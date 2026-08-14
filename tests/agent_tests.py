import unittest
import os
import sys

# Append parent dir to paths to import agent modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.modules.process_monitor import ProcessMonitor
from agent.modules.service_monitor import ServiceMonitor
from agent.modules.ioc_engine import IOCEngine
from agent.modules.cpu_monitor import CPUMonitor
from agent.modules.memory_monitor import MemoryMonitor
from agent.modules.disk_monitor import DiskMonitor
from agent.modules.network_monitor import NetworkMonitor

class TestEDRAgentModules(unittest.TestCase):
    
    def test_cpu_monitor(self):
        monitor = CPUMonitor()
        metrics = monitor.get_metrics()
        self.assertIn("cpu_percent", metrics)
        self.assertIsInstance(metrics["cpu_percent"], float)
        self.assertIn("top_cpu_processes", metrics)
        self.assertIsInstance(metrics["top_cpu_processes"], list)

    def test_memory_monitor(self):
        monitor = MemoryMonitor()
        metrics = monitor.get_metrics()
        self.assertIn("memory_percent", metrics)
        self.assertIsInstance(metrics["memory_percent"], float)
        self.assertIn("total_bytes", metrics)
        self.assertIsInstance(metrics["total_bytes"], int)

    def test_disk_monitor(self):
        monitor = DiskMonitor()
        metrics = monitor.get_metrics()
        self.assertIn("partitions", metrics)
        self.assertIsInstance(metrics["partitions"], list)

    def test_network_monitor(self):
        monitor = NetworkMonitor()
        metrics = monitor.get_metrics()
        self.assertIn("bytes_sent", metrics)
        self.assertIn("bytes_recv", metrics)
        self.assertIn("active_connections", metrics)

    def test_process_monitor_suspicious(self):
        monitor = ProcessMonitor()
        # Mock process data checks
        mock_proc = type('Process', (object,), {
            'as_dict': lambda self, attrs: {
                'pid': 99999, 'ppid': 1111, 'name': 'mimikatz.exe',
                'username': 'SYSTEM', 'exe': 'C:\\temp\\mimikatz.exe',
                'cmdline': ['mimikatz.exe'], 'create_time': 1600000000
            },
            'cpu_percent': lambda self, interval: 5.0,
            'memory_percent': lambda self: 10.0
        })()
        
        info = monitor.get_process_info(mock_proc)
        self.assertIsNotNone(info)
        self.assertTrue(info['is_suspicious'])
        self.assertIn("blacklisted", info['suspicious_reason'])

    def test_service_monitor(self):
        monitor = ServiceMonitor()
        res = monitor.check_services()
        self.assertIn("services", res)
        self.assertIn("alerts", res)

    def test_ioc_engine(self):
        engine = IOCEngine()
        # Mock IOC rules
        iocs = [
            {"id": 1, "name": "Test Hash", "type": "hash", "value": "a1b2c3d4", "mitre_technique": "T1003"},
            {"id": 2, "name": "Test IP", "type": "ip_address", "value": "1.2.3.4", "mitre_technique": "T1043"}
        ]
        engine.update_iocs(iocs)
        
        # Test Process hash match
        proc_telemetry = [{"name": "evil.exe", "sha256": "a1b2c3d4", "pid": 101, "ppid": 100}]
        net_telemetry = []
        alerts = engine.scan_system(proc_telemetry, net_telemetry)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "IOC Threat Signature Detected")
        self.assertIn("a1b2c3d4", alerts[0]["description"])

        # Test IP address match
        proc_telemetry = []
        net_telemetry = [{"remote_ip": "1.2.3.4"}]
        alerts = engine.scan_system(proc_telemetry, net_telemetry)
        self.assertEqual(len(alerts), 1)
        self.assertIn("1.2.3.4", alerts[0]["description"])

if __name__ == '__main__':
    unittest.main()
