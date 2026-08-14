import sys
import os
from agent.logger import agent_logger
from agent.utils import load_config

# Conditional win32 imports for cross-platform robustness
is_windows = sys.platform == 'win32'
if is_windows:
    import win32service
    import win32serviceutil
else:
    win32service = None
    win32serviceutil = None

class ServiceMonitor:
    def __init__(self):
        self.config = load_config()
        self.critical_services = self.config.get("critical_services", ["WinDefend", "MpsSvc", "Sysmon", "Sysmon64", "EventLog"])
        self.critical_services_lower = [s.lower() for s in self.critical_services]
        self.previous_states = {}  # service_name: status_string mapping

    def get_service_start_type_str(self, start_type):
        if not win32service:
            return "Unknown"
        mapping = {
            win32service.SERVICE_AUTO_START: "Automatic",
            win32service.SERVICE_DEMAND_START: "Manual",
            win32service.SERVICE_DISABLED: "Disabled",
            win32service.SERVICE_BOOT_START: "Boot",
            win32service.SERVICE_SYSTEM_START: "System"
        }
        return mapping.get(start_type, "Unknown")

    def get_status_str(self, status_code):
        if not win32service:
            return "Unknown"
        mapping = {
            win32service.SERVICE_STOPPED: "Stopped",
            win32service.SERVICE_START_PENDING: "Start Pending",
            win32service.SERVICE_STOP_PENDING: "Stop Pending",
            win32service.SERVICE_RUNNING: "Running",
            win32service.SERVICE_CONTINUE_PENDING: "Continue Pending",
            win32service.SERVICE_PAUSE_PENDING: "Pause Pending",
            win32service.SERVICE_PAUSED: "Paused"
        }
        return mapping.get(status_code, "Unknown")

    def check_services(self):
        """
        Gathers services, compares statuses, and alerts on changes.
        """
        services_list = []
        alerts = []

        if not is_windows:
            agent_logger.info("Service monitoring is mocked on non-Windows environment.")
            # Send sample mock services for verification
            mock_services = [
                {
                    "name": "WinDefend", 
                    "display_name": "Windows Defender Antivirus Service", 
                    "status": "Running", 
                    "start_type": "Automatic",
                    "bin_path": "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
                    "account": "LocalSystem",
                    "is_suspicious": False,
                    "suspicious_reason": ""
                },
                {
                    "name": "MpsSvc", 
                    "display_name": "Windows Defender Firewall", 
                    "status": "Running", 
                    "start_type": "Automatic",
                    "bin_path": "C:\\Windows\\system32\\svchost.exe -k LocalServiceNoNetworkFirewall",
                    "account": "NT AUTHORITY\\LocalService",
                    "is_suspicious": False,
                    "suspicious_reason": ""
                },
                {
                    "name": "Sysmon", 
                    "display_name": "System Monitor", 
                    "status": "Stopped", 
                    "start_type": "Automatic",
                    "bin_path": "C:\\Windows\\Sysmon.exe",
                    "account": "LocalSystem",
                    "is_suspicious": False,
                    "suspicious_reason": ""
                },
                {
                    "name": "SuspiciousSvc",
                    "display_name": "Diagnostic Cryptographic Service Helper",
                    "status": "Running",
                    "start_type": "Automatic",
                    "bin_path": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\crypto_miner.exe",
                    "account": "LocalSystem",
                    "is_suspicious": True,
                    "suspicious_reason": "Service binary runs from a user/temporary directory (\\temp\\)."
                }
            ]
            
            # Simulate a transition if we run multiple times
            for s in mock_services:
                name = s["name"]
                prev = self.previous_states.get(name)
                if prev and prev != s["status"]:
                    if s["name"].lower() in self.critical_services_lower and s["status"] == "Stopped":
                        alerts.append({
                            "type": "Critical Service Stopped",
                            "severity": "Critical",
                            "description": f"Critical security service '{s['name']}' has been stopped!",
                            "mitre_technique": "T1562.001",
                            "recommendation": "Investigate immediately for defense evasion tactics. Re-enable and start the service.",
                            "details": s
                        })
                # Alert on suspicious mocked service
                if s["is_suspicious"]:
                    alerts.append({
                        "type": "Suspicious Service Path",
                        "severity": "High",
                        "description": f"Service '{s['name']}' binary runs from an untrusted location: {s['bin_path']}.",
                        "mitre_technique": "T1543.003",
                        "recommendation": "Examine the service binary signature, creation time, and verify legitimacy.",
                        "details": s
                    })
                self.previous_states[name] = s["status"]
            return {"services": mock_services, "alerts": alerts}

        try:
            # Connect to service manager
            scm = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_CONNECT | win32service.SC_MANAGER_ENUMERATE_SERVICE
            )
            
            # Enum services (type WIN32 services)
            service_statuses = win32service.EnumServicesStatus(
                scm, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL
            )

            current_states = {}

            for short_name, display_name, status in service_statuses:
                status_str = self.get_status_str(status[1])
                current_states[short_name] = status_str

                # Query detailed service configuration for start type, binary path, logon account
                start_type_str = "Unknown"
                bin_path = ""
                account = ""
                is_suspicious = False
                suspicious_reason = ""
                try:
                    h_service = win32service.OpenService(
                        scm, short_name, win32service.SERVICE_QUERY_CONFIG
                    )
                    config = win32service.QueryServiceConfig(h_service)
                    start_type_str = self.get_service_start_type_str(config[1])
                    bin_path = config[3]
                    account = config[7]

                    path_lower = bin_path.lower()
                    suspicious_indicators = ["\\temp\\", "\\tmp\\", "\\users\\", "\\appdata\\", "perflogs"]
                    for indicator in suspicious_indicators:
                        if indicator in path_lower:
                            is_suspicious = True
                            suspicious_reason = f"Service binary runs from a user/temporary directory ({indicator})."
                            break

                    win32service.CloseServiceHandle(h_service)
                except Exception:
                    pass

                service_entry = {
                    "name": short_name,
                    "display_name": display_name,
                    "status": status_str,
                    "start_type": start_type_str,
                    "bin_path": bin_path,
                    "account": account,
                    "is_suspicious": is_suspicious,
                    "suspicious_reason": suspicious_reason
                }
                services_list.append(service_entry)

                # Check if state changed
                prev_state = self.previous_states.get(short_name)
                if prev_state and prev_state != status_str:
                    # Alert if a service was running and stopped
                    is_critical = short_name.lower() in self.critical_services_lower
                    if status_str == "Stopped":
                        severity = "Critical" if is_critical else "Medium"
                        description = f"Service '{short_name}' ({display_name}) transitioned from {prev_state} to Stopped."
                        alerts.append({
                            "type": "Critical Service Stopped" if is_critical else "Service Stopped",
                            "severity": severity,
                            "description": description,
                            "mitre_technique": "T1562.001" if is_critical else "T1489",
                            "recommendation": f"Check system logs to verify if service shutdown was scheduled. Restart service if required.",
                            "details": service_entry
                        })
                    else:
                        # General change event
                        agent_logger.info(f"Service '{short_name}' state change: {prev_state} -> {status_str}")

                # Alert on suspicious paths dynamically
                if is_suspicious:
                    alerts.append({
                        "type": "Suspicious Service Path",
                        "severity": "High",
                        "description": f"Service '{short_name}' binary runs from an untrusted location: {bin_path}.",
                        "mitre_technique": "T1543.003",
                        "recommendation": "Examine the service binary signature, creation time, and verify legitimacy.",
                        "details": service_entry
                    })

            win32service.CloseServiceHandle(scm)
            self.previous_states = current_states

        except Exception as e:
            agent_logger.error(f"Error checking Windows Services: {e}")

        return {
            "services": services_list,
            "alerts": alerts
        }
