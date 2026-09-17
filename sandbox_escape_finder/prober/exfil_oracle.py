import re

class ExfilOracle:
    FRAME_PATTERNS = [
        r"<frame at 0x[0-9a-fA-F]+",
        r"<code object [^>]+ at 0x[0-9a-fA-F]+",
        r"<traceback object at 0x[0-9a-fA-F]+",
        
        r"\bf_back\b",
        r"\bf_locals\b",
        r"\bf_globals\b",
        r"\bgi_frame\b",
        r"\bcr_frame\b",
        r"\bag_frame\b",
        r"\btb_frame\b",
        r"sys\._getframe"
    ]
    
    def __init__(self, secret_list):
        self.secret_list = secret_list.values()
        
    def check_frame_leak(self, text):
        if not text:
            return False
        for pattern in self.FRAME_PATTERNS:
            if re.search(pattern, text):
                return True
        return False

    def verify_impact(self, execution_data):
        is_frame_leak = self.check_frame_leak(str(execution_data))
        is_secret_leak = any(secret in str(execution_data) for secret in self.secret_list)
        
        return is_secret_leak or is_frame_leak