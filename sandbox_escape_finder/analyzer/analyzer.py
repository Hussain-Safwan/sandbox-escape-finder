import ast
import textwrap
from string import Formatter

generator_attr = {"f_locals", "f_globals", "f_builtins"}
generator_values = {"gi_frame", "cr_frame", "ag_frame", "tb_frame"}
import_blacklist = ['os', 'sys']
compression_classes = ['base64', 'zlib', 'gzip', 'bz2', 'lzma']
common_methods = {"print", "open", "input", "eval", "exec"}
reports = []

class Report():
    technique = None
    source = ''
    line = ''
    colum = ''
    confidence = 0.0

    def __repr__(self):
        return f"\n(Report: \n\ttechnique={self.technique}, \n\tsource={self.source}, \n\tlocation=(line={self.line}, colum={self.colum})\n\tconfidence={self.confidence})\n"

class ASTWrapper(ast.NodeVisitor): 

    def __init__(self, source):
        self.source = source
        self.depth = 0

    def inspect_format_access(self, node):
        if not (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
        ):
            return False

        try:
            for _, field, _, _ in Formatter().parse(node.value):
                if field is None:
                    continue
                if any(part.startswith("_") for part in field.split(".")[1:]):
                    return True
        except ValueError:
            return False 

        return False

    def inspect_builtins_restoration(self, node, access_type):
        if access_type == 'subscript':
            receiver = node.value 
            key = node.slice     
            
            if (
                isinstance(receiver, ast.Attribute)
                and receiver.attr == "__globals__"
                and isinstance(key, ast.Constant)
                and key.value == "__builtins__"
            ):
                return True
        
        elif access_type == 'method':
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "__globals__"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "__builtins__"
            ):
                return True
        
        return False
     
    def inspect_generator_intro(self, node):
        if not isinstance(node, ast.Attribute):
            return 0.0

        if (
            node.attr in generator_attr
            and isinstance(node.value, ast.Attribute)
            and node.value.attr in generator_values
        ):
            return 0.9

        if node.attr in generator_attr or node.attr in generator_values:
            return 0.5

        return 0.0
        
    def inspect_exec_eval_calls(self, node):
        argument = node.args[0]
        result = None
        
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            if ('\n' in argument.value):
                lines = [x.strip() for x in argument.value.split('\n') if x and ('import' in x)]
                import_lines = [x.replace('import', '').strip() for x in lines]
                for item in import_lines:
                    if (item in import_blacklist):
                        result = 'Exec abuse (Suspicious import)'
        
        elif isinstance(argument, ast.Call):
            function = argument.func

            if isinstance(function, ast.Name):
                pass  

            elif isinstance(function, ast.Attribute):
                pass 

                if isinstance(function.value, ast.Name):
                    result = 'Exec abuse (Compression operation)'
        
        elif isinstance(argument, ast.Name):
            print("Code supplied through variable:", argument.id)
            
        return result
    
    def generic_visit(self, node):
        details = []
        report = Report()

        if isinstance(node, ast.Name):
            details.append(f"id={node.id!r}")
        elif isinstance(node, ast.Attribute):
            details.append(f"attr={node.attr!r}")
            # Pattern 1: __subclasses__ access
            if (node.attr == '__subclasses__'):
                report.technique = 'Subclasses Traversal'
                report.confidence = 0.3
                
            # Pattern 2: Access function states through __globals__/__closures__
            if (node.attr in {"__globals__", "__closure__"}):
                report.technique = f'Function-state access ({node.attr})'
                report.confidence = 0.3
            
            # Pattern 4: Generator pattern introspection 
            introspection_score = self.inspect_generator_intro(node)
            if (introspection_score > 0.0):
                report.technique = "Generator/frame introspection"
                report.confidence = introspection_score
                
                    
        elif isinstance(node, ast.Subscript):
            # Pattern 3.1: globals __builtins__ through ["__builtins__"]
            if (self.inspect_builtins_restoration(node, 'subscript')):
                report.technique = "Builtins restoration"
                report.confidence = 0.9
                
        elif isinstance(node, ast.Call):
            # Pattern 3.2: globals __builtins__ through .get("__builtins__")
            if (self.inspect_builtins_restoration(node, 'method')):
                report.technique = "Builtins restoration"
                report.confidence = 0.9
                
            # Pattern 5: Restricted fields through string format
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and self.inspect_format_access(node.func.value)
            ):
                report.technique = 'Format-string attribute'
                report.confidence = 0.5
            
            # Pattern 6: Check for exec/eval abuse with suspicious imports and compression methods  
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in {"exec", "eval"}
                and node.args
            ):
                is_exec_abused = self.inspect_exec_eval_calls(node)
                if (is_exec_abused):
                    report.technique = is_exec_abused
                    report.confidence = 0.5
              
        # Pattern 7: Common method override      
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in common_methods:
                report.technique = "Builtin shadowing"
                report.confidence = 0.3
                                
            elif isinstance(node, ast.Constant):
                details.append(f"value={node.value!r}")

        if hasattr(node, "lineno"):
            src = f"{ast.get_source_segment(self.source, node)!r}"
            details.append(f"source={src} \nline={node.lineno}, col={node.col_offset}")
            report.source = src
            report.line = node.lineno
            report.colum = node.col_offset

        if report.technique != None:
            reports.append(report)

        suffix = " | " + ", ".join(details) if details else ""
        # print("  " * self.depth + type(node).__name__ + suffix)
        # if len(details) == 0:
        #     print('\n')
            
        self.depth += 1
        super().generic_visit(node)
        self.depth -= 1

class StaticAnalyzer:
    
    def __init__(self, config):
        self.config = config
        
    def scan(self, payload):
        tree = ast.parse(payload)
        
        ASTWrapper(payload).visit(tree)
        
        return reports
    

    

