import psutil
from agent.logger import agent_logger

class MemoryMonitor:
    def get_metrics(self):
        """
        Gathers memory (RAM) statistics and top RAM consuming processes.
        """
        try:
            mem = psutil.virtual_memory()
            
            top_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
                try:
                    mem_percent = proc.info['memory_percent'] or 0.0
                    if mem_percent > 0.1:
                        top_processes.append({
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "memory_percent": round(mem_percent, 2)
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Sort by memory percent descending
            top_processes = sorted(top_processes, key=lambda x: x['memory_percent'], reverse=True)[:5]

            return {
                "total_bytes": mem.total,
                "available_bytes": mem.available,
                "used_bytes": mem.used,
                "memory_percent": mem.percent,
                "top_memory_processes": top_processes
            }
        except Exception as e:
            agent_logger.error(f"Error in MemoryMonitor: {e}")
            return {"memory_percent": 0.0, "top_memory_processes": []}
