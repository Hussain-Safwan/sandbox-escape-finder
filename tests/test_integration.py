from pathlib import Path
from tempfile import TemporaryDirectory

from sandbox_escape_finder import DynamicProber
from sandbox_escape_finder.prober import HarnessWrapper
from sandbox_escape_finder.prober.oracle import Oracle


def test_full_corpus_against_restricted_python():
    repository = Path(__file__).resolve().parents[1]
    corpus_files = sorted(
        (repository / "corpus").glob("*.py"),
        key=lambda path: int(path.stem.split("_", 1)[0]),
    )
    corpus = [
        {"id": path.stem, "payload": path.read_text(encoding="utf-8")}
        for path in corpus_files
    ]

    with TemporaryDirectory(dir=repository / "tests") as temp_dir:
        root = Path(temp_dir)
        workspace = root / "workspace"
        canary = root / "canary"
        workspace.mkdir()
        canary.mkdir()

        config = {
            "timeout": 0.5,
            "workspace_dir": str(workspace),
            "canary_dir": str(canary),
            "import_whitelist": [
                "math",
                "random",
                "datetime",
                "json",
                "re",
                "collections",
                "itertools",
                "functools",
                "typing",
                "string",
            ],
            "secrets": {
                "SECRET_1": "XYZ123",
                "SECRET_2": "CANARY_SECRET_KEY_998123",
            },
        }
        harness = HarnessWrapper(
            workspace,
            canary,
            config["import_whitelist"],
        )
        prober = DynamicProber(
            harness.run_isolated_payload,
            Oracle(config),
            config,
        )

        report = prober.run(corpus)

    assert len(corpus) >= 10
    assert len(report) == len(corpus)
    assert {item["id"] for item in report} == {item["id"] for item in corpus}

    static_verdicts = set()
    execution_statuses = set()
    oracle_verdicts = set()

    for item in report:
        prober_report = item["prober_report"]
        oracle_result = prober_report["oracle_verdict"]

        assert set(oracle_result["details"]) == {
            "file_io",
            "exfil_attempt",
            "process_audit",
        }
        assert all(
            isinstance(value, bool)
            for value in oracle_result["details"].values()
        )

        static_verdicts.add(prober_report["static_analyzer_verdict"])
        execution_statuses.add(prober_report["execution_status"])
        oracle_verdicts.add(oracle_result["verdict"])

    assert static_verdicts == {"PASSED", "FLAGGED"}
    assert execution_statuses == {"PASSED", "BLOCKED"}
    assert oracle_verdicts == {False, True}
