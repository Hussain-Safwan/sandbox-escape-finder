import os
import io
import textwrap
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
import RestrictedPython
from RestrictedPython import compile_restricted, safe_globals, safe_builtins
from RestrictedPython.Guards import full_write_guard, safe_builtins
from RestrictedPython.PrintCollector import PrintCollector
from RestrictedPython.Eval import default_guarded_getitem
from .fileio_oracle import FileIOOracle
from .exfil_oracle import ExfilOracle

import sys

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
    def __init__(self, payload, workspace_dir, canary_dir):
        self.payload = payload
        self.runtime_violations = []
        self.workspace_dir = os.path.abspath(workspace_dir)
        self.secret_list = {'SECRET_1': 'XYZ123', 'secret_2': 'CANARY_SECRET_KEY_998123'}
        
        canary_path = os.path.abspath(canary_dir)
        if not os.path.exists(canary_path):
            os.makedirs(canary_path, exist_ok=True)
        self.canary_dir = canary_path
                
        self.forbidden_attrs = {
            "__subclasses__", "__globals__", "__closure__", 
            "__builtins__", "gi_frame", "cr_frame", "ag_frame", "tb_frame"
        }

    def custom_getattr(self, obj, name):
        if name in self.forbidden_attrs or (name.startswith("_") and name.endswith("_")):
            self.runtime_violations.append({
                "event": "attribute_access_attempt",
                "attribute_name": name
            })
            print('Blocker')
            raise SandboxSecurityError(f"[ATTRIBUTE_ERROR] Access to '{name}' is restricted.")
            
        return getattr(obj, name)

    def safe_open(self, filename, mode='r', *args, **kwargs):
        abs_target = os.path.abspath(filename)
        
        self.runtime_violations.append({
            "event": "file_access_attempt",
            "requested_path": filename,
            "resolved_path": abs_target,
            "mode": mode
        })

        if abs_target.startswith(self.workspace_dir):
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
        
        
        try:
            byte_code = compile_restricted(self.payload, filename="<dynamic_test>", mode="exec")
        except SyntaxError as e:
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
            status = 'BLOCKED/EXCEPTION'
            if compile_exception == None:
                self.runtime_violations.append({
                    "event": "process_crashed",
                    "details": str(runtime_execption)
                })
            
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
        
        return_dict = {"status": status, "execution_data": str(execution_data), "violations": self.runtime_violations}
        if (caught_execption):
            return_dict['error'] = str(caught_execption)
        
        return return_dict, self.runtime_violations
    