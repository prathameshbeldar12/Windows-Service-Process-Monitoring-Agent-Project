import os
import sys
from datetime import datetime, timezone

import psutil

from agent.logger import agent_logger
from agent.utils import load_config, get_file_sha256


IS_WINDOWS = sys.platform == "win32"


class ProcessMonitor:
    """
    Collects process telemetry and identifies suspicious processes.

    The monitor is designed to be fault tolerant:
    - A process disappearing during collection is normal.
    - AccessDenied is normal for protected processes.
    - One problematic process must never stop the whole scan.
    """

    def __init__(self):
        self.config = load_config() or {}

        suspicious_names = self.config.get(
            "suspicious_process_names",
            [],
        )

        if not isinstance(suspicious_names, list):
            suspicious_names = []

        self.suspicious_names = {
            str(name).strip().lower()
            for name in suspicious_names
            if str(name).strip()
        }

        # PID -> process information from the previous scan.
        self.previous_processes = {}

    # ------------------------------------------------------------------
    # BASIC HELPERS
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_string(value, default=""):
        """
        Convert a value safely to a string.
        """
        if value is None:
            return default

        try:
            return str(value)
        except Exception:
            return default

    @staticmethod
    def _safe_float(value, default=0.0):
        """
        Convert a value safely to float.
        """
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _safe_int(value, default=0):
        """
        Convert a value safely to int.
        """
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    # ------------------------------------------------------------------
    # WINDOWS INTEGRITY LEVEL
    # ------------------------------------------------------------------

    def _get_integrity_level(self, pid):
        """
        Get the Windows process integrity level.

        Possible values:
            System
            High
            Medium
            Low
            Unknown

        This function is Windows-only and intentionally fails safely.
        """

        if not IS_WINDOWS:
            return "Unknown"

        process_handle = None
        token_handle = None

        try:
            import win32api
            import win32con
            import win32security

            process_handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_LIMITED_INFORMATION,
                False,
                pid,
            )

            token_handle = win32security.OpenProcessToken(
                process_handle,
                win32con.TOKEN_QUERY,
            )

            token_info = win32security.GetTokenInformation(
                token_handle,
                win32security.TokenIntegrityLevel,
            )

            if not token_info:
                return "Unknown"

            sid = token_info[0]

            sub_authority = (
                win32security.GetSidSubAuthority(
                    sid,
                    win32security.GetSidSubAuthorityCount(sid) - 1,
                )
            )

            # Windows mandatory integrity level RIDs.
            if sub_authority >= 0x7000:
                return "Untrusted"

            if sub_authority >= 0x6000:
                return "Protected"

            if sub_authority >= 0x5000:
                return "System"

            if sub_authority >= 0x4000:
                return "High"

            if sub_authority >= 0x3000:
                return "Medium"

            if sub_authority >= 0x2000:
                return "Low"

            return "Untrusted"

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
            OSError,
        ):
            return "Unknown"

        except Exception as exc:
            agent_logger.debug(
                f"Could not determine integrity level "
                f"for PID {pid}: {exc}"
            )
            return "Unknown"

        finally:
            # pywin32 handles expose Close() in normal cases.
            if token_handle is not None:
                try:
                    token_handle.Close()
                except Exception:
                    pass

            if process_handle is not None:
                try:
                    process_handle.Close()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # PUBLISHER / SIGNATURE HEURISTIC
    # ------------------------------------------------------------------

    @staticmethod
    def _get_signature_metadata(exe_path):
        """
        Return conservative publisher/signature metadata.

        NOTE:
        This does NOT perform cryptographic Authenticode validation.
        A real signature check should be implemented separately using
        Windows WinVerifyTrust / PowerShell / an appropriate library.

        Therefore this function does not falsely claim that every file
        under C:\\Windows is cryptographically signed.
        """

        if not exe_path:
            return {
                "publisher": "Unknown",
                "digital_signature": "Unknown",
            }

        normalized = os.path.normcase(
            os.path.abspath(exe_path)
        )

        windows_dir = os.path.normcase(
            os.environ.get(
                "WINDIR",
                r"C:\Windows",
            )
        )

        if normalized.startswith(
            windows_dir + os.sep
        ):
            return {
                "publisher": "Windows System Path",
                "digital_signature": "Not Verified",
            }

        return {
            "publisher": "Unknown",
            "digital_signature": "Not Verified",
        }

    # ------------------------------------------------------------------
    # PROCESS INFORMATION
    # ------------------------------------------------------------------

    def get_process_info(self, proc):
        """
        Safely collect telemetry from a psutil.Process.

        Returns:
            dict | None

        Returns None when the process has disappeared or access
        is denied.
        """

        if proc is None:
            return None

        try:
            # Fetch stable process attributes in one operation.
            pinfo = proc.as_dict(
                attrs=[
                    "pid",
                    "ppid",
                    "name",
                    "username",
                    "exe",
                    "cmdline",
                    "create_time",
                ],
                ad_value=None,
            )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            return None

        except Exception as exc:
            agent_logger.debug(
                f"Unable to read process information: {exc}"
            )
            return None

        pid = self._safe_int(
            pinfo.get("pid"),
            0,
        )

        if pid <= 0:
            return None

        # --------------------------------------------------------------
        # BASIC PROCESS FIELDS
        # --------------------------------------------------------------

        name = self._safe_string(
            pinfo.get("name"),
            "Unknown",
        )

        username = self._safe_string(
            pinfo.get("username"),
            "N/A",
        )

        exe_path = self._safe_string(
            pinfo.get("exe"),
            "",
        )

        ppid = self._safe_int(
            pinfo.get("ppid"),
            0,
        )

        # --------------------------------------------------------------
        # COMMAND LINE
        # --------------------------------------------------------------

        raw_cmdline = pinfo.get(
            "cmdline"
        )

        if isinstance(raw_cmdline, (list, tuple)):
            cmdline_parts = []

            for part in raw_cmdline:
                if part is None:
                    continue

                try:
                    cmdline_parts.append(
                        str(part)
                    )
                except Exception:
                    continue

            cmdline = " ".join(
                cmdline_parts
            )

        elif raw_cmdline is None:
            cmdline = ""

        else:
            cmdline = self._safe_string(
                raw_cmdline,
                "",
            )

        # --------------------------------------------------------------
        # CREATE TIME
        # --------------------------------------------------------------

        create_time = pinfo.get(
            "create_time"
        )

        if create_time:
            try:
                create_time_formatted = (
                    datetime.fromtimestamp(
                        float(create_time),
                        tz=timezone.utc,
                    ).isoformat()
                )
            except (
                TypeError,
                ValueError,
                OSError,
                OverflowError,
            ):
                create_time_formatted = (
                    datetime.now(
                        timezone.utc
                    ).isoformat()
                )
        else:
            create_time_formatted = (
                datetime.now(
                    timezone.utc
                ).isoformat()
            )

        # --------------------------------------------------------------
        # CPU
        # --------------------------------------------------------------

        cpu_percent = 0.0

        try:
            cpu_percent = self._safe_float(
                proc.cpu_percent(
                    interval=None
                ),
                0.0,
            )
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            pass
        except Exception as exc:
            agent_logger.debug(
                f"CPU telemetry failed for PID "
                f"{pid}: {exc}"
            )

        # --------------------------------------------------------------
        # MEMORY
        # --------------------------------------------------------------

        memory_percent = 0.0

        try:
            memory_percent = self._safe_float(
                proc.memory_percent(),
                0.0,
            )
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            pass
        except Exception as exc:
            agent_logger.debug(
                f"Memory telemetry failed for PID "
                f"{pid}: {exc}"
            )

        # --------------------------------------------------------------
        # THREAD COUNT
        # --------------------------------------------------------------

        threads_count = 0

        try:
            threads_count = self._safe_int(
                proc.num_threads(),
                0,
            )
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            pass
        except Exception as exc:
            agent_logger.debug(
                f"Thread telemetry failed for PID "
                f"{pid}: {exc}"
            )

        # --------------------------------------------------------------
        # HANDLE COUNT - WINDOWS
        # --------------------------------------------------------------

        handles_count = 0

        if IS_WINDOWS:
            try:
                handles_count = self._safe_int(
                    proc.num_handles(),
                    0,
                )
            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):
                pass
            except Exception as exc:
                agent_logger.debug(
                    f"Handle telemetry failed for PID "
                    f"{pid}: {exc}"
                )

        # --------------------------------------------------------------
        # PARENT PROCESS
        # --------------------------------------------------------------

        parent_name = "Unknown"

        if ppid > 0:
            try:
                parent = psutil.Process(ppid)

                parent_name = (
                    parent.name()
                    or "Unknown"
                )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):
                pass

            except Exception as exc:
                agent_logger.debug(
                    f"Parent lookup failed for PID "
                    f"{pid}: {exc}"
                )

        # --------------------------------------------------------------
        # INTEGRITY LEVEL
        # --------------------------------------------------------------

        integrity_level = (
            self._get_integrity_level(pid)
            if IS_WINDOWS
            else "Unknown"
        )

        # --------------------------------------------------------------
        # PUBLISHER / SIGNATURE
        # --------------------------------------------------------------

        signature_info = (
            self._get_signature_metadata(
                exe_path
            )
        )

        publisher = signature_info[
            "publisher"
        ]

        digital_signature = signature_info[
            "digital_signature"
        ]

        # --------------------------------------------------------------
        # SUSPICIOUS PROCESS DETECTION
        # --------------------------------------------------------------

        is_suspicious = False
        reasons = []

        normalized_name = name.lower()
        normalized_exe = exe_path.lower()

        # Suspicious process name.
        if normalized_name in self.suspicious_names:
            is_suspicious = True

            reasons.append(
                "Process executable name matches "
                f"the configured suspicious process list: "
                f"'{name}'"
            )

        # Temporary directory execution.
        temp_indicators = [
            r"\appdata\local\temp",
            r"\windows\temp",
          ]

        if any(
            indicator in normalized_exe
            for indicator in temp_indicators
        ):
            is_suspicious = True

            reasons.append(
                "Process is executing from a "
                f"temporary directory: '{exe_path}'"
            )
            if (
                r"\appdata\local\" in normalized_exe"
                "or" r"\appdata\roaming\" in normalized_exe"
                ):
                is_suspicious = True
                reasons.append(
                    "Process is executing from a "
                    f"user AppData directory: '{exe_path}'"
                    )

        # Script interpreters are not automatically malicious.
        # We only record them when they are explicitly suspicious
        # through the configured name list or path indicators.
        suspicious_reason = "; ".join(
            reasons
        )

        # --------------------------------------------------------------
        # SHA-256
        # --------------------------------------------------------------

        sha256 = ""

        if exe_path:
            try:
                if os.path.isfile(exe_path):
                    sha256 = (
                        get_file_sha256(
                            exe_path
                        )
                        or ""
                    )
            except (
                OSError,
                PermissionError,
            ):
                pass
            except Exception as exc:
                agent_logger.debug(
                    f"SHA-256 calculation failed for "
                    f"PID {pid}: {exc}"
                )

        # --------------------------------------------------------------
        # FINAL TELEMETRY OBJECT
        # --------------------------------------------------------------

        return {
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "parent_name": parent_name,
            "username": username,
            "exe": exe_path,
            "exe_path": exe_path,
            "cmdline": cmdline,
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "threads_count": threads_count,
            "handles_count": handles_count,
            "integrity_level": integrity_level,
            "publisher": publisher,
            "digital_signature": digital_signature,
            "sha256": sha256,
            "is_suspicious": is_suspicious,
            "suspicious_reason": suspicious_reason,
            "create_time": create_time_formatted,
        }

    # ------------------------------------------------------------------
    # PROCESS SCAN
    # ------------------------------------------------------------------

    def check_processes(self):
        """
        Scan currently running processes.

        Returns:
            {
                "running": [...],
                "new": [...],
                "terminated": [...],
                "alerts": [...]
            }
        """

        current_processes = {}
        running_telemetry = []
        alerts = []

        # --------------------------------------------------------------
        # ENUMERATE PROCESSES
        # --------------------------------------------------------------

        try:
            process_iterator = psutil.process_iter(
                attrs=[
                    "pid",
                    "ppid",
                    "name",
                    "username",
                    "exe",
                    "cmdline",
                    "create_time",
                ],
            )
        except Exception as exc:
            agent_logger.error(
                f"Unable to enumerate processes: {exc}"
            )

            return {
                "running": [],
                "new": [],
                "terminated": [],
                "alerts": [],
            }

        for proc in process_iterator:
            try:
                pinfo = self.get_process_info(
                    proc
                )

                if not pinfo:
                    continue

                pid = pinfo["pid"]

                current_processes[pid] = pinfo
                running_telemetry.append(pinfo)

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):
                # Process may disappear between enumeration
                # and collection. This is expected.
                continue

            except Exception as exc:
                agent_logger.debug(
                    f"Process collection failed: {exc}"
                )

        # --------------------------------------------------------------
        # NEW / TERMINATED PROCESSES
        # --------------------------------------------------------------

        previous_pids = set(
            self.previous_processes.keys()
        )

        current_pids = set(
            current_processes.keys()
        )

        new_pids = (
            current_pids - previous_pids
        )

        terminated_pids = (
            previous_pids - current_pids
        )

        # --------------------------------------------------------------
        # NEW PROCESS ALERTS
        # --------------------------------------------------------------

        for pid in new_pids:
            pinfo = current_processes.get(pid)

            if not pinfo:
                continue

            if pinfo.get(
                "is_suspicious",
                False,
            ):
                reason = pinfo.get(
                    "suspicious_reason",
                    "Suspicious process behavior detected.",
                )

                # Critical for temp/AppData execution.
                reason_lower = reason.lower()

                if (
                    "temporary directory"
                    in reason_lower
                    or "appdata"
                    in reason_lower
                ):
                    severity = "critical"
                else:
                    severity = "high"

                process_name = pinfo.get(
                    "name",
                    "Unknown",
                )

                process_cmdline = pinfo.get(
                    "cmdline",
                    "",
                )

                # ATT&CK mapping is only a broad classification.
                if (
                    "powershell"
                    in process_name.lower()
                    or "pwsh"
                    in process_name.lower()
                ):
                    mitre_technique = "T1059.001"

                elif (
                    process_name.lower()
                    in {
                        "cmd.exe",
                        "cmd",
                    }
                ):
                    mitre_technique = "T1059.003"

                else:
                    mitre_technique = "T1204"

                alerts.append(
                    {
                        "type": "Suspicious Process Spawned",
                        "severity": severity,
                        "description": (
                            "A suspicious process was "
                            f"detected: {process_name}. "
                            f"{reason}"
                        ),
                        "mitre_technique": (
                            mitre_technique
                        ),
                        "recommendation": (
                            "Investigate the parent process, "
                            "executable path, command line, "
                            "hash, and user context before "
                            "taking containment action."
                        ),
                        "details": pinfo,
                    }
                )

            else:
                agent_logger.debug(
                    "New process spawned: "
                    f"{pinfo.get('name', 'Unknown')} "
                    f"(PID: {pid})"
                )

        # --------------------------------------------------------------
        # TERMINATED PROCESSES
        # --------------------------------------------------------------

        terminated_processes = []

        for pid in terminated_pids:
            old_process = (
                self.previous_processes.get(
                    pid
                )
            )

            if not old_process:
                old_process = {
                    "pid": pid,
                    "name": "Unknown",
                }

            agent_logger.debug(
                "Process terminated: "
                f"{old_process.get('name', 'Unknown')} "
                f"(PID: {pid})"
            )

            terminated_processes.append(
                old_process
            )

        # --------------------------------------------------------------
        # UPDATE CACHE
        # --------------------------------------------------------------

        self.previous_processes = (
            current_processes
        )

        return {
            "running": running_telemetry,
            "new": [
                current_processes[pid]
                for pid in new_pids
                if pid in current_processes
            ],
            "terminated": terminated_processes,
            "alerts": alerts,
        }