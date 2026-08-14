import threading
import time

import schedule

from agent.logger import agent_logger
from agent.api_client import APIClient
from agent.utils import load_config

from agent.modules.process_monitor import ProcessMonitor
from agent.modules.service_monitor import ServiceMonitor
from agent.modules.eventlog_monitor import EventLogMonitor
from agent.modules.cpu_monitor import CPUMonitor
from agent.modules.memory_monitor import MemoryMonitor
from agent.modules.disk_monitor import DiskMonitor
from agent.modules.network_monitor import NetworkMonitor
from agent.modules.ioc_engine import IOCEngine


class AgentScheduler:
    """
    Central EDR telemetry scheduler.

    Responsibilities:
        - endpoint registration
        - heartbeat
        - process telemetry
        - service telemetry
        - Windows Event Log telemetry
        - CPU / memory / disk / network health
        - network telemetry
        - IOC synchronization
        - IOC matching
        - alert delivery

    Every scheduled task is isolated so one module failure does not
    stop the complete agent.
    """

    def __init__(self):
        self.config = load_config() or {}

        self.api_client = APIClient()

        # --------------------------------------------------------------
        # MODULES
        # --------------------------------------------------------------

        self.process_monitor = ProcessMonitor()
        self.service_monitor = ServiceMonitor()
        self.event_monitor = EventLogMonitor()

        self.cpu_monitor = CPUMonitor()
        self.mem_monitor = MemoryMonitor()
        self.disk_monitor = DiskMonitor()
        self.net_monitor = NetworkMonitor()

        self.ioc_engine = IOCEngine()

        # --------------------------------------------------------------
        # SETTINGS
        # --------------------------------------------------------------

        self.intervals = self._get_intervals(
            self.config
        )

        self.module_config = (
            self.config.get(
                "modules",
                {},
            )
        )

        if not isinstance(
            self.module_config,
            dict,
        ):
            self.module_config = {}

        # --------------------------------------------------------------
        # STATE
        # --------------------------------------------------------------

        self.running = False
        self.thread = None

        self.registered = False
        self.last_registration_error = ""

        self._schedule_lock = threading.RLock()

    # ------------------------------------------------------------------
    # CONFIG
    # ------------------------------------------------------------------

    @staticmethod
    def _get_intervals(config):
        defaults = {
            "process_monitor": 5,
            "service_monitor": 10,
            "eventlog_monitor": 15,
            "system_health": 30,
            "ioc_engine": 60,
            "heartbeat": 10,
            "network_monitor": 10,
        }

        configured = config.get(
            "intervals",
            {},
        )

        if not isinstance(
            configured,
            dict,
        ):
            configured = {}

        result = {}

        for name, default in defaults.items():
            try:
                value = float(
                    configured.get(
                        name,
                        default,
                    )
                )

                if value <= 0:
                    value = default

            except (
                TypeError,
                ValueError,
            ):
                value = default

            result[name] = value

        return result

    def _module_enabled(self, name):
        return bool(
            self.module_config.get(
                name,
                True,
            )
        )

    # ------------------------------------------------------------------
    # SAFE JOB EXECUTION
    # ------------------------------------------------------------------

    def _safe_run(self, job_name, function):
        """
        Run a scheduled function without allowing its exception to
        kill the scheduler loop.
        """

        if not self.running:
            return

        try:
            function()

        except Exception as exc:
            agent_logger.error(
                f"Scheduled task '{job_name}' failed: "
                f"{exc}",
                exc_info=True,
            )

    # ------------------------------------------------------------------
    # ALERT SENDING
    # ------------------------------------------------------------------

    def _send_alert(self, alert):
        if not isinstance(
            alert,
            dict,
        ):
            return

        try:
            self.api_client.send_alert(
                alert
            )

        except Exception as exc:
            agent_logger.error(
                f"Failed to send alert: {exc}"
            )

    def _send_alerts(self, alerts):
        if not alerts:
            return

        for alert in alerts:
            self._send_alert(
                alert
            )

    # ------------------------------------------------------------------
    # PROCESS
    # ------------------------------------------------------------------

    def run_process_check(self):
        agent_logger.debug(
            "Running Process Monitor check..."
        )

        result = (
            self.process_monitor.check_processes()
        )

        if not isinstance(
            result,
            dict,
        ):
            return

        running = result.get(
            "running",
            [],
        )

        if running:
            try:
                self.api_client.send_process_telemetry(
                    running
                )
            except Exception as exc:
                agent_logger.error(
                    f"Failed to send process telemetry: "
                    f"{exc}"
                )

        # IOC matching uses the current network snapshot.
        try:
            connections = (
                self.net_monitor.get_connections()
            )

            ioc_alerts = (
                self.ioc_engine.scan_system(
                    running,
                    connections,
                )
            )

            self._send_alerts(
                ioc_alerts
            )

        except Exception as exc:
            agent_logger.error(
                f"IOC process scan failed: {exc}"
            )

        self._send_alerts(
            result.get(
                "alerts",
                [],
            )
        )

    # ------------------------------------------------------------------
    # SERVICE
    # ------------------------------------------------------------------

    def run_service_check(self):
        agent_logger.debug(
            "Running Service Monitor check..."
        )

        result = (
            self.service_monitor.check_services()
        )

        if not isinstance(
            result,
            dict,
        ):
            return

        services = result.get(
            "services",
            [],
        )

        if services:
            try:
                self.api_client.send_service_telemetry(
                    services
                )
            except Exception as exc:
                agent_logger.error(
                    f"Failed to send service telemetry: "
                    f"{exc}"
                )

        self._send_alerts(
            result.get(
                "alerts",
                [],
            )
        )

    # ------------------------------------------------------------------
    # EVENT LOG
    # ------------------------------------------------------------------

    def run_eventlog_check(self):
        agent_logger.debug(
            "Running Event Log check..."
        )

        result = (
            self.event_monitor.check_events()
        )

        if not isinstance(
            result,
            dict,
        ):
            return

        logs = result.get(
            "logs",
            [],
        )

        if logs:
            try:
                self.api_client.send_eventlog_telemetry(
                    logs
                )
            except Exception as exc:
                agent_logger.error(
                    f"Failed to send Event Log telemetry: "
                    f"{exc}"
                )

        self._send_alerts(
            result.get(
                "alerts",
                [],
            )
        )

    # ------------------------------------------------------------------
    # SYSTEM HEALTH
    # ------------------------------------------------------------------

    def run_health_check(self):
        agent_logger.debug(
            "Running System Health check..."
        )

        try:
            cpu = (
                self.cpu_monitor.get_metrics()
                or {}
            )
        except Exception as exc:
            agent_logger.error(
                f"CPU monitor failed: {exc}"
            )
            cpu = {}

        try:
            mem = (
                self.mem_monitor.get_metrics()
                or {}
            )
        except Exception as exc:
            agent_logger.error(
                f"Memory monitor failed: {exc}"
            )
            mem = {}

        try:
            disk = (
                self.disk_monitor.get_metrics()
                or {}
            )
        except Exception as exc:
            agent_logger.error(
                f"Disk monitor failed: {exc}"
            )
            disk = {}

        try:
            net = (
                self.net_monitor.get_metrics()
                or {}
            )
        except Exception as exc:
            agent_logger.error(
                f"Network health monitor failed: {exc}"
            )
            net = {}

        # --------------------------------------------------------------
        # NETWORK ALERTS
        # --------------------------------------------------------------

        try:
            net_alerts = (
                self.net_monitor
                .check_suspicious_connections()
            )

            self._send_alerts(
                net_alerts
            )

        except Exception as exc:
            agent_logger.error(
                f"Network suspicious connection check failed: "
                f"{exc}"
            )

        # --------------------------------------------------------------
        # DISK
        # --------------------------------------------------------------

        partitions = disk.get(
            "partitions",
            [],
        )

        if not isinstance(
            partitions,
            list,
        ):
            partitions = []

        primary_partition = (
            partitions[0]
            if partitions
            and isinstance(
                partitions[0],
                dict,
            )
            else {}
        )

        # --------------------------------------------------------------
        # HEALTH DATA
        # --------------------------------------------------------------

        health_data = {
            "cpu_percent": self._safe_float(
                cpu.get(
                    "cpu_percent",
                    0,
                )
            ),
            "memory_percent": self._safe_float(
                mem.get(
                    "memory_percent",
                    0,
                )
            ),
            "disk_percent": self._safe_float(
                primary_partition.get(
                    "disk_percent",
                    0,
                )
            ),
            "disk_free_bytes": self._safe_int(
                primary_partition.get(
                    "free_bytes",
                    0,
                )
            ),
            "network_upload_bytes": self._safe_int(
                net.get(
                    "upload_rate_bytes",
                    0,
                )
            ),
            "network_download_bytes": self._safe_int(
                net.get(
                    "download_rate_bytes",
                    0,
                )
            ),
            "top_cpu_processes": (
                cpu.get(
                    "top_cpu_processes",
                    [],
                )
                if isinstance(
                    cpu.get(
                        "top_cpu_processes",
                        [],
                    ),
                    list,
                )
                else []
            ),
            "top_memory_processes": (
                mem.get(
                    "top_memory_processes",
                    [],
                )
                if isinstance(
                    mem.get(
                        "top_memory_processes",
                        [],
                    ),
                    list,
                )
                else []
            ),
        }

        # --------------------------------------------------------------
        # CPU ALERT
        # --------------------------------------------------------------

        if health_data[
            "cpu_percent"
        ] > 90.0:

            self._send_alert(
                {
                    "type": "High CPU Usage Alert",
                    "severity": "high",
                    "description": (
                        "Endpoint CPU usage is "
                        f"very high: "
                        f"{health_data['cpu_percent']:.2f}%."
                    ),
                    "mitre_technique": "T1496",
                    "recommendation": (
                        "Review the top CPU-consuming "
                        "processes and determine whether "
                        "the activity is authorized."
                    ),
                    "details": {
                        "cpu_percent": (
                            health_data[
                                "cpu_percent"
                            ]
                        ),
                        "top_processes": (
                            health_data[
                                "top_cpu_processes"
                            ]
                        ),
                    },
                }
            )

        # --------------------------------------------------------------
        # MEMORY ALERT
        # --------------------------------------------------------------

        if health_data[
            "memory_percent"
        ] > 90.0:

            self._send_alert(
                {
                    "type": "High RAM Usage Alert",
                    "severity": "high",
                    "description": (
                        "Endpoint memory usage is "
                        f"very high: "
                        f"{health_data['memory_percent']:.2f}%."
                    ),
                    "mitre_technique": "T1496",
                    "recommendation": (
                        "Review the top memory-consuming "
                        "processes and investigate abnormal "
                        "resource consumption."
                    ),
                    "details": {
                        "memory_percent": (
                            health_data[
                                "memory_percent"
                            ]
                        ),
                        "top_processes": (
                            health_data[
                                "top_memory_processes"
                            ]
                        ),
                    },
                }
            )

        # --------------------------------------------------------------
        # DISK ALERT
        # --------------------------------------------------------------

        if (
            health_data["disk_percent"]
            >= 95.0
        ):
            self._send_alert(
                {
                    "type": "Critical Disk Usage Alert",
                    "severity": "high",
                    "description": (
                        "Primary disk usage is "
                        f"{health_data['disk_percent']:.2f}%."
                    ),
                    "mitre_technique": "T1496",
                    "recommendation": (
                        "Investigate abnormal disk "
                        "consumption and available storage."
                    ),
                    "details": {
                        "disk_percent": (
                            health_data[
                                "disk_percent"
                            ]
                        ),
                        "disk_free_bytes": (
                            health_data[
                                "disk_free_bytes"
                            ]
                        ),
                    },
                }
            )

        # --------------------------------------------------------------
        # SEND HEALTH
        # --------------------------------------------------------------

        try:
            self.api_client.send_system_health(
                health_data
            )
        except Exception as exc:
            agent_logger.error(
                f"Failed to send system health: {exc}"
            )

    # ------------------------------------------------------------------
    # NETWORK
    # ------------------------------------------------------------------

    def run_network_check(self):
        agent_logger.debug(
            "Running Network Monitor connections check..."
        )

        try:
            connections = (
                self.net_monitor.get_connections()
            )
        except Exception as exc:
            agent_logger.error(
                f"Network connection collection failed: "
                f"{exc}"
            )
            return

        if not connections:
            return

        try:
            self.api_client.send_network_telemetry(
                connections
            )
        except Exception as exc:
            agent_logger.error(
                f"Failed to send network telemetry: "
                f"{exc}"
            )

    # ------------------------------------------------------------------
    # HEARTBEAT
    # ------------------------------------------------------------------

    def run_heartbeat(self):
        agent_logger.debug(
            "Sending agent heartbeat..."
        )

        try:
            self.api_client.send_heartbeat()
        except Exception as exc:
            agent_logger.error(
                f"Heartbeat failed: {exc}"
            )

    # ------------------------------------------------------------------
    # IOC UPDATE
    # ------------------------------------------------------------------

    def run_ioc_update(self):
        agent_logger.info(
            "Fetching latest IOC list from server..."
        )

        try:
            active_iocs = (
                self.api_client.get_active_iocs()
            )

            self.ioc_engine.update_iocs(
                active_iocs
            )

        except Exception as exc:
            agent_logger.error(
                f"IOC update failed: {exc}"
            )

    # ------------------------------------------------------------------
    # REGISTRATION
    # ------------------------------------------------------------------

    def register_endpoint(self):
        """
        Register endpoint with backend.

        Returns True on success.
        """

        try:
            agent_logger.info(
                "Registering endpoint details "
                "with EDR backend..."
            )

            result = (
                self.api_client.register_agent()
            )

            self.registered = True
            self.last_registration_error = ""

            agent_logger.info(
                "Endpoint registration completed."
            )

            return result

        except Exception as exc:
            self.registered = False
            self.last_registration_error = str(
                exc
            )

            agent_logger.error(
                "Endpoint registration failed: "
                f"{exc}"
            )

            return None

    # ------------------------------------------------------------------
    # SCHEDULES
    # ------------------------------------------------------------------

    def setup_schedules(
        self,
        run_initial_checks=False,
    ):
        """
        Rebuild schedules.

        run_initial_checks is deliberately optional. It prevents
        configuration reloads from immediately running every expensive
        monitor again.
        """

        with self._schedule_lock:

            schedule.clear()

            # ----------------------------------------------------------
            # PROCESS
            # ----------------------------------------------------------

            if self._module_enabled(
                "process_monitor"
            ):
                schedule.every(
                    self.intervals[
                        "process_monitor"
                    ]
                ).seconds.do(
                    lambda: self._safe_run(
                        "process_monitor",
                        self.run_process_check,
                    )
                )

            # ----------------------------------------------------------
            # SERVICE
            # ----------------------------------------------------------

            if self._module_enabled(
                "service_monitor"
            ):
                schedule.every(
                    self.intervals[
                        "service_monitor"
                    ]
                ).seconds.do(
                    lambda: self._safe_run(
                        "service_monitor",
                        self.run_service_check,
                    )
                )

            # ----------------------------------------------------------
            # EVENT LOG
            # ----------------------------------------------------------

            if self._module_enabled(
                "eventlog_monitor"
            ):
                schedule.every(
                    self.intervals[
                        "eventlog_monitor"
                    ]
                ).seconds.do(
                    lambda: self._safe_run(
                        "eventlog_monitor",
                        self.run_eventlog_check,
                    )
                )

            # ----------------------------------------------------------
            # SYSTEM HEALTH
            # ----------------------------------------------------------

            if self._module_enabled(
                "system_health"
            ):
                schedule.every(
                    self.intervals[
                        "system_health"
                    ]
                ).seconds.do(
                    lambda: self._safe_run(
                        "system_health",
                        self.run_health_check,
                    )
                )

            # ----------------------------------------------------------
            # IOC UPDATE
            # ----------------------------------------------------------

            if self._module_enabled(
                "ioc_engine"
            ):
                schedule.every(
                    self.intervals[
                        "ioc_engine"
                    ]
                ).seconds.do(
                    lambda: self._safe_run(
                        "ioc_engine",
                        self.run_ioc_update,
                    )
                )

            # ----------------------------------------------------------
            # HEARTBEAT
            # ----------------------------------------------------------

            schedule.every(
                self.intervals[
                    "heartbeat"
                ]
            ).seconds.do(
                lambda: self._safe_run(
                    "heartbeat",
                    self.run_heartbeat,
                )
            )

            # ----------------------------------------------------------
            # NETWORK
            # ----------------------------------------------------------

            if self._module_enabled(
                "network_monitor"
            ):
                schedule.every(
                    self.intervals[
                        "network_monitor"
                    ]
                ).seconds.do(
                    lambda: self._safe_run(
                        "network_monitor",
                        self.run_network_check,
                    )
                )

        agent_logger.info(
            "EDR schedules configured successfully."
        )

        # --------------------------------------------------------------
        # INITIAL RUNS
        # --------------------------------------------------------------

        if run_initial_checks:

            self._safe_run(
                "heartbeat_initial",
                self.run_heartbeat,
            )

            if self._module_enabled(
                "ioc_engine"
            ):
                self._safe_run(
                    "ioc_update_initial",
                    self.run_ioc_update,
                )

            if self._module_enabled(
                "process_monitor"
            ):
                self._safe_run(
                    "process_initial",
                    self.run_process_check,
                )

            if self._module_enabled(
                "network_monitor"
            ):
                self._safe_run(
                    "network_initial",
                    self.run_network_check,
                )

            if self._module_enabled(
                "service_monitor"
            ):
                self._safe_run(
                    "service_initial",
                    self.run_service_check,
                )

            if self._module_enabled(
                "eventlog_monitor"
            ):
                self._safe_run(
                    "eventlog_initial",
                    self.run_eventlog_check,
                )

            if self._module_enabled(
                "system_health"
            ):
                self._safe_run(
                    "health_initial",
                    self.run_health_check,
                )

    # ------------------------------------------------------------------
    # START
    # ------------------------------------------------------------------

    def start(self):
        if self.running:
            agent_logger.warning(
                "EDR Agent Scheduler is already running."
            )
            return

        self.running = True

        # Registration must happen before telemetry.
        self.register_endpoint()

        # Build schedules.
        self.setup_schedules(
            run_initial_checks=True
        )

        # Start scheduler thread.
        self.thread = threading.Thread(
            target=self._scheduler_loop,
            name="EDR-Agent-Scheduler",
            daemon=True,
        )

        self.thread.start()

        agent_logger.info(
            "EDR Agent Telemetry Scheduler "
            "started successfully."
        )

    # ------------------------------------------------------------------
    # STOP
    # ------------------------------------------------------------------

    def stop(self):
        if not self.running:
            return

        agent_logger.info(
            "Stopping EDR Agent Telemetry Scheduler..."
        )

        self.running = False

        if (
            self.thread
            and self.thread.is_alive()
        ):
            self.thread.join(
                timeout=5
            )

        self.thread = None

        with self._schedule_lock:
            schedule.clear()

        agent_logger.info(
            "EDR Agent Telemetry Scheduler stopped."
        )

    # ------------------------------------------------------------------
    # LOOP
    # ------------------------------------------------------------------

    def _scheduler_loop(self):

        last_config_check = 0.0

        while self.running:

            try:
                with self._schedule_lock:
                    schedule.run_pending()

            except Exception as exc:
                agent_logger.error(
                    f"Scheduler loop error: {exc}",
                    exc_info=True,
                )

            time.sleep(1)

            # ----------------------------------------------------------
            # CONFIG RELOAD
            # ----------------------------------------------------------

            now = time.monotonic()

            # Do not read config on every single second.
            if (
                now - last_config_check
                < 5.0
            ):
                continue

            last_config_check = now

            try:
                current_config = (
                    load_config() or {}
                )

                new_intervals = (
                    self._get_intervals(
                        current_config
                    )
                )

                new_modules = (
                    current_config.get(
                        "modules",
                        {},
                    )
                )

                if not isinstance(
                    new_modules,
                    dict,
                ):
                    new_modules = {}

                if (
                    new_intervals
                    != self.intervals
                    or new_modules
                    != self.module_config
                ):
                    agent_logger.info(
                        "Configuration changed. "
                        "Reloading EDR schedules."
                    )

                    self.config = (
                        current_config
                    )

                    self.intervals = (
                        new_intervals
                    )

                    self.module_config = (
                        new_modules
                    )

                    self.setup_schedules(
                        run_initial_checks=False
                    )

            except Exception as exc:
                agent_logger.error(
                    f"Configuration reload failed: "
                    f"{exc}"
                )

    # ------------------------------------------------------------------
    # SAFE TYPE HELPERS
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_float(value):
        try:
            return float(value)
        except (
            TypeError,
            ValueError,
        ):
            return 0.0

    @staticmethod
    def _safe_int(value):
        try:
            return int(value)
        except (
            TypeError,
            ValueError,
        ):
            return 0