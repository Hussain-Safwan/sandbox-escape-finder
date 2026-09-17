# Positive
result = helper.__globals__["__builtins__"]

# Negative
text = "__builtins__"

# Possible detection gap
g = helper.__globals__
result = g["__builtins__"]

# Edge case: no arguments
exec()