import multiprocessing as mp
from .execute import Execution
from ..analyzer import StaticAnalyzer
from .process_oracle import ProcessAuditHookManager

class HarnessWrapper:
    
    def __init__(self, workspace_dir, canary_dir):
        self.workspace_dir = workspace_dir
        self.canary_dir = canary_dir
        
    def _worker_target(self, payload_code, return_dict):
        try:
            ProcessAuditHookManager.install()
            executor = Execution(payload_code, self.workspace_dir, self.canary_dir)
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
            
            execution_result = self.sandbox_exec(payload, self.config['timeout'])
                    
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
                "static_analyzer_verdict": "PASSED" if len(flags) == 0 else "FLAGGED",
                "static_analyzer_technique": [flag.technique for flag in flags] if len(flags) > 0 else None,
                "execution_status": "PASSED" if execution_result.get("status", "") == "SUCCESS" else "BLOCKED",
                "execution_outcome": execution_result.get("execution_data", ""),
                "runtime_violations": [v.get("event", "") for v in violations] if len(violations) > 0 else None,
                "oracle_verdict": oracle_verdict
            })
            
        return self.report
            
            
        