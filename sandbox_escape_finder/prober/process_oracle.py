import sys
import threading

CRITICAL_PROCESS_EVENTS = {
    "os.system",
    "os.exec",
    "os.spawn",
    "os.posix_spawn",
    "os.listdir",
    "subprocess.Popen",
    "pty.spawn",
    "winreg.OpenKey",
}


class ProcessAuditHookManager:
    _installed = False
    _lock = threading.Lock()
    _active_violations = {}

    @classmethod
    def install(cls):
        with cls._lock:
            if cls._installed:
                return
            
            def _audit_hook(event, args):
                thread_id = threading.get_ident()
                if thread_id in cls._active_violations:
                    if event in CRITICAL_PROCESS_EVENTS or event.startswith("os.") or event.startswith("subprocess."):
                        cls._active_violations[thread_id].append({
                            "event": event,
                            "args": [str(a) for a in args]
                        })

            sys.addaudithook(_audit_hook)
            cls._installed = True

    @classmethod
    def register_thread(cls, thread_id):
        with cls._lock:
            cls._active_violations[thread_id] = []

    @classmethod
    def unregister_thread(cls, thread_id):
        with cls._lock:
            return cls._active_violations.pop(thread_id, [])


class ProcessOracle:
    def __init__(self):
        pass
    
    def verify_impact(self, audit_events):

        for event_data in audit_events:
            event_name = event_data.get("event", "")
            args = event_data.get("args", [])

            if (
                event_name in CRITICAL_PROCESS_EVENTS 
                or "subprocess" in event_name
                or "os.system" in event_name
            ):
                return True
            
        return False