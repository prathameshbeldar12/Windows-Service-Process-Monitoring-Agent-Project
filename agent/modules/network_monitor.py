import psutil
from agent.logger import agent_logger

class NetworkMonitor:
    def __init__(self):
        self.prev_sent = 0
        self.prev_recv = 0
        try:
            net_io = psutil.net_io_counters()
            self.prev_sent = net_io.bytes_sent
            self.prev_recv = net_io.bytes_recv
        except Exception:
            pass

    def get_metrics(self):
        """
        Gathers upload/download metrics and counts established network connections.
        """
        try:
            net_io = psutil.net_io_counters()
            current_sent = net_io.bytes_sent
            current_recv = net_io.bytes_recv

            # Rates since last check
            upload_bytes = current_sent - self.prev_sent if self.prev_sent > 0 else 0
            download_bytes = current_recv - self.prev_recv if self.prev_recv > 0 else 0

            # Update cached rates
            self.prev_sent = current_sent
            self.prev_recv = current_recv

            # Count active established connections
            conn_count = 0
            try:
                connections = psutil.net_connections(kind='inet')
                conn_count = len([c for c in connections if c.status == 'ESTABLISHED'])
            except Exception:
                pass

            return {
                "bytes_sent": current_sent,
                "bytes_recv": current_recv,
                "upload_rate_bytes": upload_bytes,
                "download_rate_bytes": download_bytes,
                "active_connections": conn_count
            }
        except Exception as e:
            agent_logger.error(f"Error in NetworkMonitor: {e}")
            return {
                "bytes_sent": 0,
                "bytes_recv": 0,
                "upload_rate_bytes": 0,
                "download_rate_bytes": 0,
                "active_connections": 0
            }
        
    def get_connections(self):
        connections = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                process_name = "Unknown"
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        process_name = p.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                connections.append({
                    "pid": conn.pid,
                    "process_name": process_name,
                    "local_ip": conn.laddr.ip if hasattr(conn.laddr, 'ip') else (conn.laddr[0] if conn.laddr else ""),
                    "local_port": conn.laddr.port if hasattr(conn.laddr, 'port') else (conn.laddr[1] if conn.laddr else 0),
                    "remote_ip": conn.raddr.ip if hasattr(conn.raddr, 'ip') else (conn.raddr[0] if conn.raddr else "") if conn.raddr else "",
                    "remote_port": conn.raddr.port if hasattr(conn.raddr, 'port') else (conn.raddr[1] if conn.raddr else 0) if conn.raddr else 0,
                    "status": conn.status
                })
        except Exception as e:
            agent_logger.error(f"Error collecting network connections: {e}")
        return connections

    def check_suspicious_connections(self):
        """
        Check for connections to suspicious remote ports or unexpected listening processes.
        """
        alerts = []
        try:
            connections = psutil.net_connections(kind='inet')
            suspicious_ports = {4444, 1337, 31337, 6667} # Common reverse shell/IRC ports
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip = conn.raddr.ip if hasattr(conn.raddr, 'ip') else conn.raddr[0]
                    port = conn.raddr.port if hasattr(conn.raddr, 'port') else conn.raddr[1]
                    if port in suspicious_ports:
                        alerts.append({
                            "type": "Suspicious Remote Connection Established",
                            "severity": "Critical",
                            "description": f"Network connection established to known malicious port {port} (Remote: {ip}:{port}) by PID {conn.pid}.",
                            "mitre_technique": "T1043", # Commonly Used Port
                            "recommendation": "Identify the process associated with PID and terminate immediately if unauthorized. Check firewall blocklists.",
                            "details": {
                                "pid": conn.pid,
                                "remote_ip": ip,
                                "remote_port": port,
                                "local_ip": conn.laddr.ip if hasattr(conn.laddr, 'ip') else (conn.laddr[0] if conn.laddr else ""),
                                "local_port": conn.laddr.port if hasattr(conn.laddr, 'port') else (conn.laddr[1] if conn.laddr else 0)
                            }
                        })
        except Exception as e:
            agent_logger.error(f"Error checking suspicious network connections: {e}")
        return alerts

