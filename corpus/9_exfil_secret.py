# Configuration to toggle which channels leak the secret during testing
LEAK_CONFIG = {
    "leak_stdout": False,
    "leak_stderr": False,
    "leak_return": True,
}

def attempt_exfiltration():
    
    secret = globals().get("SECRET_1", "CANARY_SECRET_KEY_998123")
    result = None
    
    if LEAK_CONFIG["leak_stdout"]:
        print(f"[EXFILTRATION OUTPUT] Found secret: {secret}")

    if LEAK_CONFIG["leak_stderr"]:
        raise ValueError(secret)

    if LEAK_CONFIG["leak_return"]:
        return f"LEAKED_SECRET: {secret}"
        
    return "SUCCESS_NO_LEAK"

attempt_exfiltration()