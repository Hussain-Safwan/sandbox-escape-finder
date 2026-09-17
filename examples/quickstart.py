import json
from pathlib import Path
import pprint

from sandbox_escape_finder import StaticAnalyzer, DynamicProber
from sandbox_escape_finder.prober import HarnessWrapper
from sandbox_escape_finder.prober.oracle import Oracle

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"

def get_payload(filename):
    source_code = ''
    with open(filename, "r") as file:
        source_code = file.read()
    
    return source_code

def build_corpus(filenames):
    corpus = []
    
    for filename in filenames:
        source_code = get_payload(filename)
        corpus.append({
            "id": Path(filename).stem, 
            "payload": source_code
        })
        
    return corpus

if __name__ == '__main__':
    config = {}

    stat = 1
    with open(CONFIG_PATH, 'r') as config_file:
        config = json.load(config_file)

    corpus_path = Path(config.get("corpus_path"))
    filenames = [str(f) for f in corpus_path.iterdir() if f.is_file()]
    corpus = build_corpus(filenames)
    
    sc = next((item for item in corpus if item.get("id") == "5_format"), None)
    
    if (stat==0):
        analyzer = StaticAnalyzer(config)
        findings = analyzer.scan(sc.get("payload"))
        
        print(findings)
    
    else:
        harness = HarnessWrapper(
            config.get("workspace_dir"),
            config.get("canary_dir")
        )
        
        oracle = Oracle(config)
        prober = DynamicProber(harness.run_isolated_payload, oracle, config)
        report = prober.run([sc])
        
        pprint.pprint(report, sort_dicts=False)