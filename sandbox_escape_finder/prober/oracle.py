from .fileio_oracle import FileIOOracle
from .exfil_oracle import ExfilOracle
from .process_oracle import ProcessOracle
from pathlib import Path

class Oracle:
    def __init__(self, config):
        self.workspace_dir = Path(config.get("workspace_dir")).resolve()
        self.canary_dir = Path(config.get("canary_dir")).resolve()
        self.secret_list = config.get("secrets") 
        
        self.exfil_oracle = ExfilOracle(self.secret_list)
        self.file_io_oracle = FileIOOracle(self.workspace_dir, self.canary_dir)
        self.process_oracle = ProcessOracle()
        
    def run(self, execution_data, audit_data, runtime_violations):
        oracle_1_outcome = self.file_io_oracle.verify_impact(runtime_violations)
        oracle_2_outcome = self.exfil_oracle.verify_impact(execution_data)
        oracle_3_outcome = self.process_oracle.verify_impact(audit_data)
        
        return oracle_1_outcome or oracle_2_outcome or oracle_3_outcome