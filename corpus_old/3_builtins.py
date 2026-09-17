recovered_builtins = exposed_helper.__globals__["__builtins__"]

recovered_builtins = exposed_helper.__globals__.get("__builtins__")

# result = recovered_builtins["len"]("hello")