import io
import multiprocessing as mp
import os
import threading
from contextlib import redirect_stdout, redirect_stderr

from .execute import Execution
from ..analyzer import StaticAnalyzer
from .process_oracle import ProcessAuditHookManager

class HarnessWrapper:
    
    def __init__(self, workspace_dir, canary_dir, import_whitelist):
        self.workspace_dir = workspace_dir
        self.canary_dir = canary_dir
        self.import_whitelist = import_whitelist
        
    def _worker_target(self, payload_code, return_dict):
        try:
            ProcessAuditHookManager.install()
            os.chdir(self.workspace_dir)
            executor = Execution(payload_code, self.workspace_dir, self.canary_dir, self.import_whitelist)
            return_value = executor.execute_payload()
            
            return_dict["status"] = return_value.get("status")
            return_dict["error"] = return_value.get("error", None)
            return_dict["execution_data"] = return_value.get("execution_data", '')
            return_dict["audit_data"] = return_value.get("audit_data", '')
            return_dict["violations"] = return_value.get("violations", "")

        except Exception as e:
            return_dict["status"] = "BLOCKED/EXCEPTION"
            return_dict["error"] = f"Unhandled Process Exception: {str(e)}"
            return_dict["violations"] = []
            return_dict["execution_data"] = ""
            return_dict["audit_data"] = ""
            
    def run_regular_payload(self, payload):
        ProcessAuditHookManager.install()
        current_thread_id = threading.get_ident()
        ProcessAuditHookManager.register_thread(current_thread_id)
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        status = None
        runtime_execption = None
        audit_data = ''
        
        try:
    
            with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
                exec(payload)
            status = 'SUCCESS'
                    
        except Exception as e:
            runtime_execption = e
            status = 'BLOCKED'
            err_type = type(runtime_execption).__name__
            if ( err_type == 'NameError' or err_type == 'AttributeError'):
                self.runtime_violations.append({
                    "event": "invalid_access_attempt",
                    "details": str(runtime_execption)
                })
        finally:    
            audit_data = ProcessAuditHookManager.unregister_thread(current_thread_id)
                                         
        execution_data = {
            "status": status,
            "stdout": stdout_buffer.getvalue(),
            "stderr": stderr_buffer.getvalue(),
            "error": str(runtime_execption) if runtime_execption else None
        }
                
        return_dict = {
            "status": status, 
            "execution_data": str(execution_data), 
            "audit_data": audit_data,
        }
                
        return return_dict
        

    def run_isolated_payload(self, payload_code, timeout=2.0):
        manager = mp.Manager()
        return_dict = manager.dict()

        process = mp.Process(
            target=self._worker_target, 
            args=(payload_code, return_dict)
        )
        
        process.start()
        process.join(timeout=timeout)

        if process.is_alive():
            process.terminate()
            process.join()
            
            return_dict = dict(return_dict)
            if ("violations" not in return_dict):
                return_dict["violations"] = []

            return_dict["violations"].append({
                "event": "dos_attempt",
                "details": f"Execution time {timeout}sec exceeded"
            })

        if process.exitcode != 0:
            return_dict = dict(return_dict)
            if ("violations" not in return_dict):
                return_dict["violations"] = []
                            
            return_dict["violations"].append({
                "event": "process_crashed",
                "details": f"Process terminated abnormally with exit code {process.exitcode}"
            })

        if (type(return_dict) != "dict"):
            return_dict = dict(return_dict)
            
        return return_dict
    
class DynamicProber:
    
    def __init__(self, sandbox_exec, oracle, config):
        self.sandbox_exec = sandbox_exec
        self.oracle = oracle
        self.config = config
        self.report = []
    
    def run(self, payload_corpus):
        for item in payload_corpus:
            payload = item.get("payload")
            
            static_analyzer = StaticAnalyzer(self.config)
            flags = static_analyzer.scan(payload)
            
            execution_result = self.sandbox_exec(
                payload, 
                self.config.get("timeout", 2.0),
            )
                    
            if (execution_result.get("status", "") == "SUCCESS"):
                print(f'[Prober] id={item.get("id")} status=Complete') 
            else:
                print(f'[Prober] id={item.get("id")} status=Blocked')
                    
            violations = execution_result.get("violations", [])
            audit_data = execution_result.get("audit_data", "")

            if "violations" in execution_result:
                del execution_result["violations"]

            oracle_verdict = self.oracle.run(execution_result, audit_data, violations)
            
            self.report.append({
                "id": item.get("id"),
                "analyzer_findings": flags,
                "prober_report": {
                    "static_analyzer_verdict": "PASSED" if len(flags) == 0 else "FLAGGED",
                    "static_analyzer_technique": [flag.technique for flag in flags] if len(flags) > 0 else None,
                    "execution_status": "PASSED" if execution_result.get("status", "") == "SUCCESS" else "BLOCKED",
                    "execution_outcome": execution_result.get("execution_data", ""),
                    "runtime_violations": [v.get("event", "") for v in violations] if len(violations) > 0 else None,
                    "oracle_verdict": oracle_verdict
                }
            })
            
        return self.report
            
            
        
