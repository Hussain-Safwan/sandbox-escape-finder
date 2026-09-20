import json
from pathlib import Path
import pprint
import random

from sandbox_escape_finder import StaticAnalyzer, DynamicProber
from sandbox_escape_finder.prober import HarnessWrapper
from sandbox_escape_finder.prober.oracle import Oracle

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"

class CorpusLoader:
    
    def __init__(self, corpus_path, seed=0):
        self.corpus = []
        self.corpus_path = corpus_path
        self.seed = seed
        self.build_corpus()

    def get_code(self, filename):
        source_code = ''
        with open(filename, "r") as file:
            source_code = file.read()
        
        return source_code

    def build_corpus(self):
        _corpus_path = Path(self.corpus_path)
        filenames = sorted(
            (f for f in _corpus_path.iterdir() if f.is_file()),
            key=lambda f: int(f.stem.split("_", 1)[0]),
        )
        random.Random(self.seed).shuffle(filenames)
              
        for filename in filenames:
            source_code = self.get_code(filename)
            self.corpus.append({
                "id": filename.stem, 
                "payload": source_code
            })
                
    def get_corpus(self):
        return self.corpus
    
    def get_payload(self, id):
        return next((item for item in self.corpus if item.get("id") == id), None)

if __name__ == '__main__':
    # set stat=0 to run StaticAnalyzer only, stat=1 for entire end-to-end pipeline
    stat = 1
    config = {}
    with open(CONFIG_PATH, 'r') as config_json:
        config = json.load(config_json)
     
    corpus_loader = CorpusLoader(
        config.get("corpus_path", ""),
        config.get("seed", 0),
    )
    corpus = corpus_loader.get_corpus()
    
    if (stat==0):
        
        # enter the payload id from the corpus below - StaticAnalyzer takes singular payloads
        sc = corpus_loader.get_payload("1_subclasses")
        analyzer = StaticAnalyzer(config)
        findings = analyzer.scan(sc.get("payload"))
        
        print(findings)
    
    else:
        harness = HarnessWrapper(
            config.get("workspace_dir"),
            config.get("canary_dir"),
            config.get("import_whitelist")
        )
        
        oracle = Oracle(config)
        prober = DynamicProber(harness.run_isolated_payload, oracle, config)
        report = prober.run(corpus)

        pprint.pprint(report, sort_dicts=False)
