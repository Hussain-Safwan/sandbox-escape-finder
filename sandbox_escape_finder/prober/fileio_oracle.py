import os

class FileIOOracle:
    def __init__(self, workspace_dir, canary_dir, throwaway=None):
        self.workspace_dir = os.path.abspath(workspace_dir)
        self.canary_dir = os.path.abspath(canary_dir)
        self.throwaway = throwaway
        self.initial_canary_snapshot = self._get_dir_snapshot(self.canary_dir)
        self.initial_throwaway_snapshot = self._get_dir_snapshot(self.throwaway) if self.throwaway else None
        
    def _get_dir_snapshot(self, path):
        snapshot = {}
        if not os.path.exists(path):
            return snapshot
        for root, _, files in os.walk(path):
            for f in files:
                full_path = os.path.join(root, f)
                snapshot[full_path] = os.path.getmtime(full_path)
        return snapshot

    def verify_impact(self, file_handler_violations):
        msg = "out_of_bounds_file_access"
        log_check = msg in [v.get("event") for v in file_handler_violations]

        current_canary_snapshot = self._get_dir_snapshot(self.canary_dir)
        canary_change = current_canary_snapshot != self.initial_canary_snapshot
        throwaway_change = False
        
        if self.throwaway:
            current_throaway_snapshot = self._get_dir_snapshot(self.throwaway)
            throwaway_change = current_throaway_snapshot != self.initial_throwaway_snapshot

        self.initial_canary_snapshot = current_canary_snapshot
        if self.throwaway:
            self.initial_throwaway_snapshot = current_throaway_snapshot

        return log_check or canary_change or throwaway_change
