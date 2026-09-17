# Configuration to toggle which channels leak the secret during testing
import sys
LEAK_CONFIG = {
    "leak_stdout": False,
    "leak_stderr": True,
}

def attempt_exfiltration():
    
    secret = globals().get("SECRET_1", "CANARY_SECRET_KEY_998123")
    
    if LEAK_CONFIG["leak_stdout"]:
        print(f"[EXFILTRATION OUTPUT] Found secret: {secret}")

    if LEAK_CONFIG["leak_stderr"]:
        sys.stderr.write(f"Critical failure occurred: {secret}")
        
    return "SUCCESS_NO_LEAK"

attempt_exfiltration()