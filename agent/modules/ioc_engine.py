import sys
from typing import Any, Dict, Iterable, List, Optional

from agent.logger import agent_logger


IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import winreg
else:
    winreg = None


class IOCEngine:
    """
    Local IOC matching engine.

    Supported IOC types:
        hash
        file_name
        path
        command_line
        parent_process
        ip_address
        registry_key
    """

    SUPPORTED_TYPES = {
        "hash",
        "file_name",
        "path",
        "command_line",
        "parent_process",
        "ip_address",
        "registry_key",
    }

    def __init__(self):
        self.active_iocs: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # IOC CACHE
    # ------------------------------------------------------------------

    def update_iocs(self, ioc_list):
        """
        Replace the local IOC cache with a normalized list.
        """

        if not isinstance(ioc_list, list):
            agent_logger.warning(
                "IOC update ignored because server returned "
                f"unexpected data type: {type(ioc_list).__name__}"
            )
            self.active_iocs = []
            return

        normalized = []

        for raw_ioc in ioc_list:
            if not isinstance(raw_ioc, dict):
                continue

            ioc_type = str(
                raw_ioc.get("type", "")
            ).strip().lower()

            ioc_value = str(
                raw_ioc.get("value", "")
            ).strip()

            if not ioc_type or not ioc_value:
                continue

            if ioc_type not in self.SUPPORTED_TYPES:
                agent_logger.debug(
                    f"Ignoring unsupported IOC type: {ioc_type}"
                )
                continue

            item = dict(raw_ioc)

            item["type"] = ioc_type
            item["value"] = ioc_value

            normalized.append(item)

        self.active_iocs = normalized

        agent_logger.info(
            "IOC Engine cache updated: "
            f"{len(self.active_iocs)} active IOCs loaded."
        )

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_string(value, default=""):
        if value is None:
            return default

        try:
            return str(value)
        except Exception:
            return default

    @staticmethod
    def _normalize_hash(value):
        return (
            str(value or "")
            .strip()
            .lower()
        )

    @staticmethod
    def _normalize_path(value):
        return (
            str(value or "")
            .strip()
            .rstrip("\\")
            .lower()
        )

    @staticmethod
    def _normalize_ip(value):
        return (
            str(value or "")
            .strip()
            .lower()
        )

    @staticmethod
    def _normalize_name(value):
        return (
            str(value or "")
            .strip()
            .lower()
        )

    # ------------------------------------------------------------------
    # REGISTRY
    # ------------------------------------------------------------------

    def check_registry_key(self, key_path):
        """
        Check whether a Windows registry value exists.

        Supported form:

            HKEY_LOCAL_MACHINE\\Software\\...\\ValueName

        The final component is treated as the value name.
        """

        if not IS_WINDOWS or winreg is None:
            return False

        key_path = self._safe_string(
            key_path
        ).strip()

        if not key_path:
            return False

        parts = [
            part.strip()
            for part in key_path.split("\\")
            if part.strip()
        ]

        if len(parts) < 2:
            return False

        root_name = parts[0].upper()
        value_name = parts[-1]

        sub_key = "\\".join(
            parts[1:-1]
        )

        roots = {
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKLM": winreg.HKEY_LOCAL_MACHINE,

            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKCU": winreg.HKEY_CURRENT_USER,

            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
            "HKCR": winreg.HKEY_CLASSES_ROOT,

            "HKEY_USERS": winreg.HKEY_USERS,
            "HKU": winreg.HKEY_USERS,

            "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
            "HKCC": winreg.HKEY_CURRENT_CONFIG,
        }

        root_key = roots.get(root_name)

        if root_key is None:
            return False

        try:
            access = (
                winreg.KEY_READ
            )

            with winreg.OpenKey(
                root_key,
                sub_key,
                0,
                access,
            ) as key:

                winreg.QueryValueEx(
                    key,
                    value_name,
                )

            return True

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
        ):
            return False

        except Exception as exc:
            agent_logger.debug(
                f"Registry IOC check failed for "
                f"'{key_path}': {exc}"
            )
            return False

    # ------------------------------------------------------------------
    # PROCESS INDEX
    # ------------------------------------------------------------------

    @staticmethod
    def _build_process_indexes(
        process_telemetry: Iterable[Dict[str, Any]]
    ):
        """
        Build indexes to avoid repeated O(n²) parent lookups.
        """

        by_pid = {}

        for proc in process_telemetry or []:
            if not isinstance(proc, dict):
                continue

            try:
                pid = int(
                    proc.get("pid", 0)
                )
            except (
                TypeError,
                ValueError,
            ):
                continue

            if pid > 0:
                by_pid[pid] = proc

        return by_pid

    # ------------------------------------------------------------------
    # ALERT DEDUPLICATION
    # ------------------------------------------------------------------

    @staticmethod
    def _alert_key(ioc, target):
        """
        Create a stable key so the same IOC match is not emitted
        repeatedly during one scan.
        """

        ioc_id = str(
            ioc.get("id", "")
        )

        ioc_type = str(
            ioc.get("type", "")
        ).lower()

        ioc_value = str(
            ioc.get("value", "")
        ).lower()

        if isinstance(target, dict):
            pid = target.get("pid", "")
            remote_ip = target.get(
                "remote_ip",
                "",
            )
            key = target.get(
                "key",
                "",
            )

            target_id = (
                f"{pid}|{remote_ip}|{key}"
            )
        else:
            target_id = str(target)

        return (
            f"{ioc_id}|"
            f"{ioc_type}|"
            f"{ioc_value}|"
            f"{target_id}"
        )

    # ------------------------------------------------------------------
    # MAIN SCAN
    # ------------------------------------------------------------------

    def scan_system(
        self,
        process_telemetry,
        network_telemetry,
    ):
        """
        Match current process and network telemetry against active IOCs.

        Returns:
            list of alert dictionaries.
        """

        alerts = []

        if not self.active_iocs:
            return alerts

        if not isinstance(
            process_telemetry,
            list,
        ):
            process_telemetry = []

        if not isinstance(
            network_telemetry,
            list,
        ):
            network_telemetry = []

        processes_by_pid = (
            self._build_process_indexes(
                process_telemetry
            )
        )

        emitted_keys = set()

        for ioc in self.active_iocs:

            try:
                ioc_type = str(
                    ioc.get("type", "")
                ).strip().lower()

                ioc_value = str(
                    ioc.get("value", "")
                ).strip()

                if not ioc_type or not ioc_value:
                    continue

                # ------------------------------------------------------
                # HASH
                # ------------------------------------------------------

                if ioc_type == "hash":

                    target_hash = (
                        self._normalize_hash(
                            ioc_value
                        )
                    )

                    for proc in process_telemetry:

                        proc_hash = (
                            self._normalize_hash(
                                proc.get("sha256")
                            )
                        )

                        if (
                            proc_hash
                            and proc_hash == target_hash
                        ):
                            description = (
                                f"Process "
                                f"'{proc.get('name', 'Unknown')}' "
                                "matches blacklisted SHA-256."
                            )

                            self._append_alert(
                                alerts,
                                emitted_keys,
                                ioc,
                                proc,
                                description,
                            )

                # ------------------------------------------------------
                # FILE NAME
                # ------------------------------------------------------

                elif ioc_type == "file_name":

                    target_name = (
                        self._normalize_name(
                            ioc_value
                        )
                    )

                    for proc in process_telemetry:

                        process_name = (
                            self._normalize_name(
                                proc.get("name")
                            )
                        )

                        if (
                            process_name
                            and process_name == target_name
                        ):
                            description = (
                                f"Process executable "
                                f"matches blacklisted "
                                f"file name: {ioc_value}"
                            )

                            self._append_alert(
                                alerts,
                                emitted_keys,
                                ioc,
                                proc,
                                description,
                            )

                # ------------------------------------------------------
                # PATH
                # ------------------------------------------------------

                elif ioc_type == "path":

                    target_path = (
                        self._normalize_path(
                            ioc_value
                        )
                    )

                    for proc in process_telemetry:

                        process_path = (
                            self._normalize_path(
                                proc.get(
                                    "exe",
                                    proc.get(
                                        "exe_path",
                                        "",
                                    ),
                                )
                            )
                        )

                        if (
                            process_path
                            and process_path
                            == target_path
                        ):
                            description = (
                                "Process is executing "
                                f"from blacklisted path: "
                                f"{ioc_value}"
                            )

                            self._append_alert(
                                alerts,
                                emitted_keys,
                                ioc,
                                proc,
                                description,
                            )

                # ------------------------------------------------------
                # COMMAND LINE
                # ------------------------------------------------------

                elif ioc_type == "command_line":

                    target_command = (
                        ioc_value.lower()
                    )

                    for proc in process_telemetry:

                        command_line = (
                            self._safe_string(
                                proc.get(
                                    "cmdline",
                                    ""
                                )
                            ).lower()
                        )

                        if (
                            target_command
                            in command_line
                        ):
                            description = (
                                "Process command line "
                                "matches IOC value: "
                                f"'{ioc_value}'"
                            )

                            self._append_alert(
                                alerts,
                                emitted_keys,
                                ioc,
                                proc,
                                description,
                            )

                # ------------------------------------------------------
                # PARENT PROCESS
                # ------------------------------------------------------

                elif ioc_type == "parent_process":

                    target_parent = (
                        self._normalize_name(
                            ioc_value
                        )
                    )

                    for proc in process_telemetry:

                        try:
                            ppid = int(
                                proc.get(
                                    "ppid",
                                    0,
                                )
                            )
                        except (
                            TypeError,
                            ValueError,
                        ):
                            continue

                        parent = (
                            processes_by_pid.get(
                                ppid
                            )
                        )

                        parent_name = ""

                        if parent:
                            parent_name = (
                                parent.get(
                                    "name",
                                    "",
                                )
                            )

                        # ProcessMonitor already provides
                        # parent_name, so use it as fallback.
                        if not parent_name:
                            parent_name = (
                                proc.get(
                                    "parent_name",
                                    "",
                                )
                            )

                        if (
                            self._normalize_name(
                                parent_name
                            )
                            == target_parent
                        ):
                            description = (
                                f"Process "
                                f"'{proc.get('name', 'Unknown')}' "
                                "was spawned by blacklisted "
                                f"parent '{parent_name}'."
                            )

                            self._append_alert(
                                alerts,
                                emitted_keys,
                                ioc,
                                proc,
                                description,
                            )

                # ------------------------------------------------------
                # IP ADDRESS
                # ------------------------------------------------------

                elif ioc_type == "ip_address":

                    target_ip = (
                        self._normalize_ip(
                            ioc_value
                        )
                    )

                    for conn in network_telemetry:

                        if not isinstance(
                            conn,
                            dict,
                        ):
                            continue

                        remote_ip = (
                            conn.get(
                                "remote_ip",
                                conn.get(
                                    "raddr_ip",
                                    "",
                                ),
                            )
                        )

                        if (
                            self._normalize_ip(
                                remote_ip
                            )
                            == target_ip
                        ):
                            description = (
                                "Network connection "
                                "matches blacklisted "
                                f"IP address: {ioc_value}"
                            )

                            self._append_alert(
                                alerts,
                                emitted_keys,
                                ioc,
                                conn,
                                description,
                            )

                # ------------------------------------------------------
                # REGISTRY
                # ------------------------------------------------------

                elif ioc_type == "registry_key":

                    if self.check_registry_key(
                        ioc_value
                    ):
                        target = {
                            "key": ioc_value
                        }

                        description = (
                            "Blacklisted registry "
                            "persistence value found: "
                            f"{ioc_value}"
                        )

                        self._append_alert(
                            alerts,
                            emitted_keys,
                            ioc,
                            target,
                            description,
                        )

            except Exception as exc:
                agent_logger.error(
                    "IOC evaluation failed for "
                    f"IOC '{ioc}': {exc}"
                )

        return alerts

    # ------------------------------------------------------------------
    # ALERT CREATION
    # ------------------------------------------------------------------

    def _append_alert(
        self,
        alerts,
        emitted_keys,
        ioc,
        target,
        description,
    ):
        key = self._alert_key(
            ioc,
            target,
        )

        if key in emitted_keys:
            return

        emitted_keys.add(key)

        alerts.append(
            self._build_ioc_alert(
                ioc,
                target,
                description,
            )
        )

    def _build_ioc_alert(
        self,
        ioc,
        target,
        description,
    ):
        return {
            "type": "IOC Threat Signature Detected",
            "severity": "critical",
            "description": description,
            "mitre_technique": (
                ioc.get(
                    "mitre_technique",
                    "T1059",
                )
            ),
            "recommendation": (
                "Investigate the matched process, "
                "network connection, or persistence "
                "location. Apply endpoint containment "
                "according to your response policy."
            ),
            "details": {
                "ioc_id": ioc.get("id"),
                "ioc_type": ioc.get("type"),
                "ioc_value": ioc.get("value"),
                "matched_object": target,
            },
        }