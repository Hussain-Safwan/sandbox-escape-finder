import os
import io
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
import threading

from RestrictedPython import compile_restricted, safe_globals, safe_builtins
from RestrictedPython.Guards import full_write_guard, safe_builtins
from RestrictedPython.PrintCollector import PrintCollector
from RestrictedPython.Eval import default_guarded_getitem

from .process_oracle import ProcessAuditHookManager

class DirectPrintCollector:
    def __init__(self, _getattr_=None):
        pass

    def _call_print(self, *args, **kwargs):
        print(*args, **kwargs)

    def __call__(self):
        return ""

class SandboxSecurityError(Exception):
    pass

class Execution:
    def __init__(self, payload, workspace_dir, canary_dir, import_whitelist):
        self.payload = payload
        self.import_whitelist = import_whitelist
        self.runtime_violations = []
        self.workspace_dir = Path(workspace_dir).resolve()
        self.canary_dir = Path(canary_dir).resolve()
        self.secret_list = {'SECRET_1': 'XYZ123', 'secret_2': 'CANARY_SECRET_KEY_998123'}
                
        self.forbidden_attrs = {
            "__subclasses__", "__globals__", "__closure__", "__builtins__", "__metaclass__", 
            "gi_frame", "cr_frame", "ag_frame", "tb_frame"
        }

    def is_safe_path(self, target):
        is_inside = False
        try:
            is_inside = Path(os.path.commonpath([self.workspace_dir, target])) == self.workspace_dir
        except ValueError:
            is_inside = False
        return is_inside
    
    def custom_getattr(self, obj, name):
        if name in self.forbidden_attrs or (name.startswith("_") and name.endswith("_")):
            self.runtime_violations.append({
                "event": "attribute_access_attempt",
                "attribute_name": name
            })
            raise SandboxSecurityError(f"[ATTRIBUTE_ERROR] Access to '{name}' is restricted.")
            
        return getattr(obj, name)

    def safe_open(self, filename, mode='r', *args, **kwargs):
        abs_target = Path(filename).resolve()
        
        self.runtime_violations.append({
            "event": "file_access_attempt",
            "requested_path": filename,
            "resolved_path": abs_target,
            "mode": mode
        })

        if self.is_safe_path(abs_target):
            return open(abs_target, mode, *args, **kwargs)

        self.runtime_violations.append({
            "event": "out_of_bounds_file_access_attempt",
            "requested_path": abs_target,
            "mode": mode
        })

        target_path = Path(abs_target)
        relative_clean_path = target_path.relative_to(target_path.anchor)
        redirected_path = os.path.join(self.canary_dir, relative_clean_path)

        if any(w in mode for w in ('w', 'a', '+')):
            os.makedirs(os.path.dirname(redirected_path), exist_ok=True)

        if 'r' in mode and not os.path.exists(redirected_path):
            os.makedirs(os.path.dirname(redirected_path), exist_ok=True)
            with open(redirected_path, 'w') as f:
                f.write("CANARY_FILE_CONTENTS")

        return open(redirected_path, mode, *args, **kwargs)


    def safe_getitem(self, obj, key):
        if isinstance(key, str) and (key.startswith('_') or key in {"eval", "exec", "open", "__import__"}):
            self.runtime_violations.append({
                "event": "key_access_attempt",
                "key_name": key
            })
            raise SandboxSecurityError(f"[KEY_ERROR] Access to key '{key}' is restricted.")
        
        return default_guarded_getitem(obj, key)
    
    def safe_import(self, name, globals=None, locals=None, fromlist=(), level=0, runtime_violations=None):
        if name not in self.import_whitelist:
            self.runtime_violations.append({
                "event": "suspicious_import",
                "module": name,
                "details": f"Payload imported restricted module: '{name}'"
            })
            raise SandboxSecurityError(f"[IMPORT_ERROR] Suspicious import attempted")
            
        return __import__(name, globals, locals, fromlist, level)


    def get_restricted_scope(self):
        restricted_globals = safe_globals.copy()
        
        restricted_builtins = safe_builtins.copy()
        for dangerous in ("eval", "exec", "__import__"):
            restricted_builtins.pop(dangerous, None)
            
        restricted_builtins['open'] = self.safe_open
        restricted_builtins['globals'] = globals
        restricted_globals["__builtins__"] = restricted_builtins
        restricted_globals["__builtins__"]["next"] = next
        restricted_globals["__builtins__"]["getattr"] = getattr
        restricted_globals["__builtins__"]["__import__"] = self.safe_import
        
        restricted_globals["_getattr_"] = self.custom_getattr
        restricted_globals["_write_"] = full_write_guard
        restricted_globals["_getiter_"] = iter
        restricted_globals['_print_'] = DirectPrintCollector
        restricted_globals['print'] = print
        restricted_globals["_getitem_"] = self.safe_getitem
        for key, value in self.secret_list.items():
            restricted_globals[key] = value
        
        return restricted_globals

    def execute_payload(self):
        self.runtime_violations.clear()
        restricted_globals = self.get_restricted_scope()
        
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        status = None
        compile_exception = None
        runtime_execption = None
        audit_data = ''
        
        current_thread_id = threading.get_ident()
        ProcessAuditHookManager.register_thread(current_thread_id)
        
        try:
            byte_code = compile_restricted(self.payload, filename="<dynamic_test>", mode="exec")
        except Exception as e:
            compile_exception = e
            self.runtime_violations.append({
                "event": type(compile_exception).__name__,
                "details": str(compile_exception)
            })
        
        try:
            with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
                exec(byte_code, restricted_globals)
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
            elif compile_exception == None:
                self.runtime_violations.append({
                    "event": "process_crashed",
                    "details": str(runtime_execption)
                })
        finally:    
            audit_data = ProcessAuditHookManager.unregister_thread(current_thread_id)
        
        caught_execption = None   
        if compile_exception:
            caught_execption = compile_exception
        elif runtime_execption:
            caught_execption = runtime_execption
                 
        execution_data = {
            "status": status,
            "stdout": stdout_buffer.getvalue(),
            "stderr": stderr_buffer.getvalue(),
            "error": str(caught_execption) if caught_execption else None
        }
        
        return_dict = {
            "status": status, 
            "execution_data": str(execution_data), 
            "audit_data": audit_data,
            "violations": self.runtime_violations
        }
        if (caught_execption):
            return_dict['error'] = str(caught_execption)
        
        return return_dict
    