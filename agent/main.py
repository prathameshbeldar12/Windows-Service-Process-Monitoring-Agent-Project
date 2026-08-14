import sys
import os
# Prepend project root to sys.path to allow absolute imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import argparse
from agent.logger import agent_logger
from agent.scheduler import AgentScheduler

# Conditional imports for Windows Service
is_windows = sys.platform == 'win32'
if is_windows:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    
    class SentinelEDRAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "SentinelEDRAgent"
        _svc_display_name_ = "Sentinel EDR Monitoring Agent"
        _svc_description_ = "Monitors Windows system processes, services, event logs, and health metrics for SOC threat intelligence and EDR backend analysis."

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self.scheduler = AgentScheduler()

        def SvcStop(self):
            agent_logger.info("Stopping Sentinel EDR Agent Service...")
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.hWaitStop)
            self.scheduler.stop()

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
            self.main()

        def main(self):
            agent_logger.info("Sentinel EDR Windows Service starting main loop...")
            self.scheduler.start()
            # Wait infinitely until Service stop event is signaled
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
            agent_logger.info("Sentinel EDR Windows Service stopped gracefully.")
else:
    SentinelEDRAgentService = None

def run_console():
    """
    Runs the agent in the foreground console mode.
    """
    agent_logger.info("Starting Sentinel EDR Agent in console mode...")
    scheduler = AgentScheduler()
    try:
        scheduler.start()
        # Keep foreground alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent_logger.info("KeyboardInterrupt detected. Shutting down EDR agent...")
        scheduler.stop()
    except Exception as e:
        agent_logger.critical(f"Unhandled agent exception: {e}")
        scheduler.stop()

if __name__ == '__main__':
    # Parse CLI options
    parser = argparse.ArgumentParser(description="Sentinel EDR Endpoint Monitoring Agent")
    parser.add_argument("--console", action="store_true", help="Run the agent in console foreground mode")
    
    # If on Windows, we allow registering as service
    if is_windows and len(sys.argv) > 1 and sys.argv[1] not in ["--console", "-h", "--help"]:
        # Handle command-line service parameters like: install, start, stop, remove, update
        try:
            win32serviceutil.HandleCommandLine(SentinelEDRAgentService)
        except Exception as e:
            print(f"Service management error: {e}")
    else:
        # Otherwise, check console or default behavior
        args, unknown = parser.parse_known_args()
        if args.console or not is_windows:
            run_console()
        else:
            # On Windows, if launched without service args or --console, prompt options
            print("Sentinel EDR Agent usage:")
            print("  python main.py --console       -> Run agent in interactive CLI mode")
            print("  python main.py install         -> Install as Windows Service")
            print("  python main.py start           -> Start EDR Service")
            print("  python main.py stop            -> Stop EDR Service")
            print("  python main.py remove          -> Remove EDR Service")
            print("\nAttempting to default to console mode...")
            run_console()
