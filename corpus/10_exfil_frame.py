LEAK_CONFIG = {
    "leak_stdout": False,
    "leak_stderr": False,
    "leak_return": True,
}

def demo_generator():
    local_marker = "CANARY_SECRET_KEY_998123"
    yield "paused"
    yield local_marker

def attempt_exfiltration():
    gen = demo_generator()
    gen.__next__()  # Advance generator state using method call

    # Chained attribute access: gen.gi_frame.f_locals
    # 1. Outer ast.Attribute: .f_locals (in generator_attr)
    # 2. Inner ast.Attribute: .gi_frame (in generator_values)
    locals_dict = gen.gi_frame.f_locals
    
    # Subscript access on local variables dictionary
    stolen_value = locals_dict["local_marker"]
    
    result = {
        "generator_frame": str(gen.gi_frame),
        "stolen_marker": stolen_value
    }

    if LEAK_CONFIG["leak_stdout"]:
        print(f"[GENERATOR INTROSPECTION] {result}")

    if LEAK_CONFIG["leak_stderr"]:
        raise RuntimeError(f"Generator Frame Leaked: {result}")

    if LEAK_CONFIG["leak_return"]:
        return result

    return "NO_LEAK"