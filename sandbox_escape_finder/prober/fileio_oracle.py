import os

class FileIOOracle:
    def __init__(self, workspace_dir, canary_dir):
        self.workspace_dir = os.path.abspath(workspace_dir)
        self.canary_dir = os.path.abspath(canary_dir)
        self.initial_canary_snapshot = self._get_dir_snapshot(self.canary_dir)

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
        oob_logged = msg in [v.get("event") for v in file_handler_violations]

        current_canary_snapshot = self._get_dir_snapshot(self.canary_dir)
        physical_disk_change = current_canary_snapshot != self.initial_canary_snapshot

        return oob_logged or physical_disk_change