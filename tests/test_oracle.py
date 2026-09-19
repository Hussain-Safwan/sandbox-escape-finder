from pathlib import Path
from tempfile import TemporaryDirectory
import pytest

from sandbox_escape_finder.prober.oracle import Oracle
from sandbox_escape_finder.prober.prober import HarnessWrapper


@pytest.mark.parametrize(
    ("target_location", "expected_verdict"),
    [
        ("inside", False),
        ("outside", False),
    ],
    ids=["in-bounds-file-access", "out-of-bounds-file-access"],
)
def test_file_oracle(target_location, expected_verdict):
    with TemporaryDirectory(dir="tests") as temp_dir:
        root = Path(temp_dir)
        workspace = root / "workspace"
        canary = root / "canary"
        workspace.mkdir()
        canary.mkdir()

        target = (
            workspace / "output.txt"
            if target_location == "inside"
            else root / "outside.txt"
        )
        payload = (
            f"with open({str(target)!r}, 'w') as file:\n"
            "    file.write('test')"
        )
        harness = HarnessWrapper(workspace, canary, import_whitelist=[])
        oracle = Oracle(
            {
                "workspace_dir": str(workspace),
                "canary_dir": str(canary),
                "secrets": {},
            }
        )

        execution_result = harness.run_isolated_payload(payload, timeout=2.0)
        violations = execution_result.pop("violations", [])
        oracle_result = oracle.run(
            execution_result,
            execution_result.get("audit_data", []),
            violations,
        )

        assert execution_result["status"] == "SUCCESS"
        assert oracle_result["verdict"] is expected_verdict
    
def test_file_oracle_catches_broken_sandbox():
    with TemporaryDirectory(dir="tests") as temp_dir:
        root = Path(temp_dir)
        workspace = root / "workspace"
        redirect_sink = root / "redirect"
        escape_target = root / "escape_target"

        workspace.mkdir()
        redirect_sink.mkdir()
        escape_target.mkdir()

        harness = HarnessWrapper(workspace, redirect_sink, import_whitelist=[])
        oracle = Oracle(
            {
                "workspace_dir": str(workspace),
                "canary_dir": str(redirect_sink),
                "throwaway_dir": str(escape_target),
                "secrets": {},
            }
        )

        target = escape_target / "escaped.txt"
        execution_result = harness.run_regular_payload(
            f"open({str(target)!r}, 'w').write('escaped')"
        )
        oracle_result = oracle.run(
            execution_result,
            execution_result.get("audit_data", []),
            [],
        )

        assert execution_result["status"] == "SUCCESS"
        assert oracle_result["details"]["file_io"] is True
        assert oracle_result["verdict"] is True


@pytest.mark.parametrize(
    ("payload", "expected_verdict", "expected_status"),
    [
        (
            "print('safe execution')",
            False, "SUCCESS"
        ),
        (
            "import os\nos.system('echo test')",
            False, "BLOCKED"
        ),
    ],
    ids=["benign-payload", "harmful-process-payload"],
)
def test_process_oracle(payload, expected_verdict, expected_status):
    workspace = Path.cwd()
    canary = workspace / "canary"
    harness = HarnessWrapper(workspace, canary, import_whitelist=[])
    oracle = Oracle(
        {
            "workspace_dir": str(workspace),
            "canary_dir": str(canary),
            "secrets": {},
        }
    )

    execution_result = harness.run_isolated_payload(payload, timeout=2.0)
    violations = execution_result.pop("violations", [])
    oracle_result = oracle.run(
        execution_result,
        execution_result.get("audit_data", []),
        violations,
    )

    assert execution_result["status"] == expected_status
    assert oracle_result["verdict"] is expected_verdict


def test_oracle_catches_process_breach_from_regular_executor():
    harness = HarnessWrapper(".", ".", [])
    oracle = Oracle(
        {
            "workspace_dir": ".",
            "canary_dir": ".",
            "secrets": {},
        }
    )

    execution_result = harness.run_regular_payload(
        "import os\nos.system('echo pwned')"
    )
    oracle_result = oracle.run(
        execution_result,
        execution_result["audit_data"],
        [],
    )

    assert execution_result["status"] == "SUCCESS"
    assert oracle_result["verdict"] is True


@pytest.mark.parametrize(
    ("executor_type", "payload", "expected_verdict"),
    [
        ("isolated", "print(SECRET_1)", True),
        ("regular", "import sys\nprint(sys._getframe())", True),
        ("isolated", "print('ordinary output')", False),
    ],
    ids=["secret-leak", "frame-leak", "benign-output"],
)
def test_exfil_oracle(executor_type, payload, expected_verdict):
    workspace = Path.cwd()
    canary = workspace / "canary"
    harness = HarnessWrapper(workspace, canary, import_whitelist=[])
    oracle = Oracle(
        {
            "workspace_dir": str(workspace),
            "canary_dir": str(canary),
            "secrets": {"SECRET_1": "XYZ123"},
        }
    )

    if executor_type == "isolated":
        execution_result = harness.run_isolated_payload(payload, timeout=2.0)
    else:
        execution_result = harness.run_regular_payload(payload)

    violations = execution_result.pop("violations", [])
    oracle_result = oracle.run(
        execution_result,
        execution_result.get("audit_data", []),
        violations,
    )

    assert execution_result["status"] == "SUCCESS"
    assert oracle_result["details"]["exfil_attempt"] is expected_verdict
    assert oracle_result["verdict"] is expected_verdict
