import pytest

from sandbox_escape_finder.analyzer import StaticAnalyzer
from sandbox_escape_finder.analyzer import analyzer as analyzer_module


@pytest.mark.parametrize(
    ("source", "expected_flagged"),
    [
        ("result = object.__subclasses__()", True),
        ("result = object.__str__()", False),
    ],
    ids=["subclasses-traversal", "benign-attribute"],
)
def test_subclasses_detector(source, expected_flagged, monkeypatch):
    monkeypatch.setattr(analyzer_module, "reports", [])
    analyzer = StaticAnalyzer(
        {"import_whitelist": [], "workspace_dir": "."}
    )

    findings = analyzer.scan(source)
    techniques = {finding.technique for finding in findings}
    assert ("Subclasses Traversal" in techniques) is expected_flagged


@pytest.mark.parametrize(
    ("source", "expected_technique"),
    [
        (
            'result = helper.__globals__["SECRET"]',
            "Function-state access (__globals__)",
        ),
        (
            "result = helper.__closure__[0].cell_contents",
            "Function-state access (__closure__)",
        ),
        ("result = helper.__name__", None),
    ],
    ids=["globals-access", "closure-access", "benign-function-attribute"],
)
def test_function_state_detector(source, expected_technique, monkeypatch):
    monkeypatch.setattr(analyzer_module, "reports", [])
    analyzer = StaticAnalyzer(
        {"import_whitelist": [], "workspace_dir": "."}
    )

    findings = analyzer.scan(source)
    techniques = {finding.technique for finding in findings}

    if expected_technique is None:
        assert not any(
            technique.startswith("Function-state access")
            for technique in techniques
        )
    else:
        assert expected_technique in techniques


@pytest.mark.parametrize(
    ("source", "expected_flagged"),
    [
        ('builtins = helper.__globals__["__builtins__"]', True),
        ('builtins = helper.__globals__.get("__builtins__")', True),
        ('value = helper.__globals__.get("ordinary_value")', False),
    ],
    ids=["builtins-subscript", "builtins-get", "benign-globals-get"],
)
def test_builtins_restoration_detector(source, expected_flagged, monkeypatch):
    monkeypatch.setattr(analyzer_module, "reports", [])
    analyzer = StaticAnalyzer(
        {"import_whitelist": [], "workspace_dir": "."}
    )

    findings = analyzer.scan(source)
    techniques = {finding.technique for finding in findings}

    assert ("Builtins restoration" in techniques) is expected_flagged


@pytest.mark.parametrize(
    ("source", "expected_flagged"),
    [
        ('result = "{0._name}".format(person)', True),
        ('result = "{0.name}".format(person)', False),
    ],
    ids=["private-format-attribute", "public-format-attribute"],
)
def test_format_string_attribute_detector(source, expected_flagged, monkeypatch):
    monkeypatch.setattr(analyzer_module, "reports", [])
    analyzer = StaticAnalyzer(
        {"import_whitelist": [], "workspace_dir": "."}
    )

    findings = analyzer.scan(source)
    techniques = {finding.technique for finding in findings}

    assert ("Format-string attribute" in techniques) is expected_flagged


@pytest.mark.parametrize(
    ("source", "expected_technique"),
    [
        ('exec("x = 2")', "Exec/eval usage"),
        ('exec("import math")', "Exec/eval usage"),
        ('exec("import os")', "Exec/eval with import"),
        (
            "exec(base64.b64decode(payload))",
            "Exec/eval with compression"
        ),
    ],
    ids=[
        "plain-exec",
        "exec-allowed-import",
        "exec-forbidden-import",
        "exec-compressed-payload",
    ],
)
def test_exec_eval_detector(
    source,
    expected_technique,
    monkeypatch,
):
    monkeypatch.setattr(analyzer_module, "reports", [])
    analyzer = StaticAnalyzer(
        {"import_whitelist": ["math"], "workspace_dir": "."}
    )

    findings = analyzer.scan(source)
    exec_findings = [
        finding
        for finding in findings
        if finding.technique.startswith("Exec/eval")
    ]

    assert len(exec_findings) == 1
    assert exec_findings[0].technique == expected_technique


@pytest.mark.parametrize(
    ("source", "expected_flagged"),
    [
        ("def print(*args):\n    pass", True),
        ("def new_method(*args):\n    pass", False),
    ],
    ids=["builtin-method-override", "fresh-method-name"],
)
def test_builtin_shadowing_detector(source, expected_flagged, monkeypatch):
    monkeypatch.setattr(analyzer_module, "reports", [])
    analyzer = StaticAnalyzer(
        {"import_whitelist": [], "workspace_dir": "."}
    )

    findings = analyzer.scan(source)
    techniques = {finding.technique for finding in findings}

    assert ("Builtin shadowing" in techniques) is expected_flagged


@pytest.mark.parametrize(
    ("source", "expected_flagged"),
    [
        ('open("../outside.txt", "w")', True),
        ('open("output.txt", "w")', False),
    ],
    ids=["out-of-bounds-file", "in-bounds-file"],
)
def test_file_io_detector(source, expected_flagged, monkeypatch):
    monkeypatch.setattr(analyzer_module, "reports", [])
    analyzer = StaticAnalyzer(
        {"import_whitelist": [], "workspace_dir": "."}
    )

    findings = analyzer.scan(source)
    techniques = {finding.technique for finding in findings}

    assert ("file_access" in techniques) is expected_flagged


@pytest.mark.parametrize(
    ("source", "expected_flagged"),
    [
        ("import math", False),
        ("import os", True),
    ],
    ids=["allowed-import", "forbidden-import"],
)
def test_import_detector(source, expected_flagged, monkeypatch):
    monkeypatch.setattr(analyzer_module, "reports", [])
    analyzer = StaticAnalyzer(
        {"import_whitelist": ["math"], "workspace_dir": "."}
    )

    findings = analyzer.scan(source)
    suspicious_imports = [
        finding
        for finding in findings
        if finding.technique.startswith("Suspicious import")
    ]

    assert bool(suspicious_imports) is expected_flagged


@pytest.mark.parametrize(
    ("source", "expected_confidence"),
    [
        ("result = gen.gi_frame.f_locals", 0.9),
        ("result = gen.gi_frame", 0.5),
        ("result = gen.value", None),
    ],
    ids=["chained-frame-access", "standalone-frame-access", "benign-attribute"],
)
def test_frame_introspection_detector(source, expected_confidence, monkeypatch):
    monkeypatch.setattr(analyzer_module, "reports", [])
    analyzer = StaticAnalyzer(
        {"import_whitelist": [], "workspace_dir": "."}
    )

    findings = analyzer.scan(source)
    frame_findings = [
        finding
        for finding in findings
        if finding.technique == "Generator/frame introspection"
    ]

    if expected_confidence is None:
        assert frame_findings == []
    else:
        assert any(
            finding.confidence == expected_confidence
            for finding in frame_findings
        )
