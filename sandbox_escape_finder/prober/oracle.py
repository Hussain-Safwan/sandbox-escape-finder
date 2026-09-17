from .fileio_oracle import FileIOOracle
from .exfil_oracle import ExfilOracle

class Oracle:
    def __init__(self, config):
        self.workspace_dir = config.get("workspace_dir") 
        self.canary_dir = config.get("canary_dir") 
        self.secret_list = config.get("secrets") 
        
        self.exfil_oracle = ExfilOracle(self.secret_list)
        self.file_io_oracle = FileIOOracle(self.workspace_dir, self.canary_dir)
        
    def run(self, execution_data, runtime_violations):
        oracle_1_outcome = self.file_io_oracle.verify_impact(runtime_violations)
        oracle_2_outcome = self.exfil_oracle.verify_impact(execution_data)
        
        return oracle_1_outcome or oracle_2_outcome