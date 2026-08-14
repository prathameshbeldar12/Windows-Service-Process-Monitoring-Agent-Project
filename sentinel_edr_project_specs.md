# Sentinel EDR - Windows Endpoint Monitoring Agent
## Project Structure
```text
sentinel_edr/
├── agent/                  # Windows Monitoring Agent (Python)
│   ├── modules/
│   │   ├── process_monitor.py
│   │   ├── service_monitor.py
│   │   ├── eventlog_monitor.py
│   │   ├── sys_health.py
│   │   └── ioc_engine.py
│   ├── config.json
│   ├── main.py             # Agent Entry Point
│   └── api_client.py       # Communicates with Backend
├── backend/                # Django REST API
│   ├── core/               # Django Project Config
│   ├── monitoring/         # Main Monitoring App
│   │   ├── models.py       # Process, Service, Alert models
│   │   ├── serializers.py
│   │   └── views.py
│   ├── api/                # API Routing
│   └── manage.py
├── frontend/               # UI Templates & Assets
├── requirements.txt
└── README.md
```

## Agent Module: process_monitor.py
```python
import psutil
import datetime

class ProcessMonitor:
    def __init__(self):
        self.suspicious_names = ['mimikatz.exe', 'psexec.exe', 'nc.exe', 'powershell.exe']

    def get_running_processes(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'cpu_percent', 'memory_info', 'create_time']):
            try:
                p_info = proc.info
                p_info['is_suspicious'] = p_info['name'].lower() in self.suspicious_names
                processes.append(p_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes
```
