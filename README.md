# Sandbox Escape Finder

Sandbox Escape Finder is a defensive testing tool for Python execution
sandboxes. It combines AST-based static analysis with isolated execution
against RestrictedPython to identify known escape techniques and determine
whether a payload produces an observable out-of-sandbox effect.

The project includes an automated oracle, a corpus of escape-attempt payloads,
and unit and integration tests for comparing static findings with dynamic
results.

## Features

- AST-based detection of common Python sandbox escape techniques
- Source locations (line and column) and confidence scores for static findings
- Isolated sandboxed payload execution against RestrictedPython
- Automatic detection of file access, data leakage, and process audit
- Configurable timeouts, import allowlists, paths, and canary secrets
- A 14-payload corpus for comparing static flags, runtime behavior, and breach detection

## Installation

Python 3.10 or later is required. From the repository root, install the
package and its dependencies:

```sh
python -m pip install -e .
```

## Quickstart

Run the included example from the repository root:

```sh
python examples/quickstart.py
```

The example loads `config.json`, runs the payload corpus in an isolated RestrictedPython
process, and prints its static-analysis, execution data, and oracle results.

## Architecture

```text
Payload → StaticAnalyzer → Isolated RestrictedPython process → Oracle → Report
```

- `StaticAnalyzer` inspects the payload's AST and reports suspicious patterns.
- `HarnessWrapper` executes the payload in a separate process with a timeout.
- `Oracle` checks for file access, data leakage, and restricted process activity.
- `DynamicProber` orchestrates the end-to-end pipeline and combines the static findings, execution status, and oracle
  verdict into one report per payload.

## Statically Detected Techniques

| Technique | AST pattern | What it detects |
|---|---|---|
| Subclasses traversal | Access to `.__subclasses__` | Attempts to enumerate loaded classes and locate powerful objects. |
| Function-state access | Access to `.__globals__` or `.__closure__` | Attempts to reach a function's global namespace or captured values. |
| Builtins restoration | `.__globals__["__builtins__"]` or `.__globals__.get("__builtins__")` | Attempts to recover restricted built-in functions. |
| Generator/frame introspection | Access to frame attributes such as `gi_frame`, `f_locals`, or `f_globals` | Attempts to inspect execution frames and recover internal state. |
| Format-string attribute access | A format field that accesses a private attribute | Attempts to traverse restricted attributes through `str.format`. |
| Exec/eval usage | Calls to `exec` or `eval`, including encoded code and imports | Attempts to execute dynamically constructed or hidden code. |
| Builtin shadowing | Function definitions named `print`, `open`, `input`, `eval`, or `exec` | Detects replacement of commonly controlled built-ins. |
| Suspicious imports | Imports outside the configured allowlist | Detects access to modules not approved by the sandbox configuration. |
| Out-of-workspace file access | `open`, `file`, or supported `Path` operations using a path outside the workspace | Detects attempts to read or write beyond the allowed directory. |

## Dynamic Isolation and Oracle Design

### Process isolation

Each payload runs in a separate process managed by `HarnessWrapper`. The parent
process waits for the configured timeout and terminates the worker if it does
not finish, preventing an infinite loop from blocking the test run.

RestrictedPython provides the execution backbone. The project adds:

- `safe_open`, which allows workspace access and redirects out-of-bounds paths
  to the canary directory
- `safe_import`, which permits only modules in the configured allowlist
- guarded printing and captured standard output and error streams
- execution status, error, runtime-violation, and audit-event capture

### File oracle

Out-of-workspace file operations are redirected to a canary location instead
of touching the requested host path. The oracle also snapshots an optional
throwaway directory before execution and checks it afterward. An out-of-bounds
file-access event or a change inside the throwaway directory is treated as a
breach.

### Exfiltration oracle

The execution result includes captured `stdout`, `stderr`, `error` objects. The oracle scans
that data for canary secrets supplied through `config.json` and for signatures
of exposed frames, code objects, tracebacks, and frame attributes. Finding a
configured secret or internal frame information is treated as a breach.

### Process audit oracle

A Python audit hook is installed in the worker process before payload
execution. The executing thread is registered immediately before restricted
execution and unregistered afterward so its audit events can be collected.
The oracle monitors operating-system, subprocess, spawn, and related critical
events. Observing one of these system-level operations is treated as a breach.

### Dynamically Detected Techniques

| Technique | Example behavior |
|---|---|
| Exfiltration attempt | Secret value exfiltration |
| Exfiltration attempt | Internal frame exfiltration |
| DoS attack | Infinite loop timeout |
| Program crash | Deliberately crashing a program |
| System-level operation | Executing system or OS commands |

Timeouts and crashes are recorded as runtime violations. The oracle's breach
verdict is based on confirmed file, exfiltration, or system-process effects.

## Configuration

The default settings are stored in `config.json`. Relative paths are resolved
from the directory where the program is run, so the examples should be started
from the repository root.

| Field | Description |
|---|---|
| `timeout` | Maximum number of seconds a payload may run before its worker process is terminated. |
| `seed` | Seed used to produce a reproducible shuffled payload order. |
| `workspace_dir` | Directory in which payloads execute and may perform allowed file operations. |
| `canary_dir` | Safe destination used when an out-of-workspace file path is redirected. |
| `throwaway_dir` | Optional directory monitored by the file oracle for unexpected changes. |
| `corpus_path` | Directory containing the payload corpus loaded by the quickstart. |
| `import_whitelist` | Modules that payloads are allowed to import. All other imports are blocked and reported. |
| `secrets` | Canary values that cause the exfiltration oracle to report a breach if they appear in captured output. |

Example:

```json
{
  "timeout": 2.0,
  "seed": 1337,
  "workspace_dir": ".",
  "canary_dir": "./canary",
  "corpus_path": "./corpus",
  "import_whitelist": ["math", "random", "json"],
  "secrets": {
    "SECRET_1": "XYZ123",
    "SECRET_2": "CANARY_SECRET_KEY_998123"
  }
}
```

## Payload Corpus

The `corpus/` directory contains 14 payloads covering escape techniques,
benign controls, and runtime-failure cases. The extensionless filename (e.g., `1_subclasses`) serves as the `Payload ID`.

| Payload ID | Category | Purpose |
|---|---|---|
| `1_subclasses` | Introspection | Attempts to enumerate classes through `__subclasses__`. |
| `2_access` | Function state | Attempts to read globals and closure contents from exposed functions. |
| `3_builtins` | Builtins restoration | Attempts to recover `__builtins__` through a function's globals. |
| `4_format` | Format-string access | Attempts to read a private attribute through `str.format`. |
| `5_exec` | Encoded execution | Attempts to decode and execute a Base64-encoded command payload. |
| `6_benign_exec` | Benign control | Uses dynamic execution to import an allowlisted module. |
| `7_builtin_shadow` | Builtin shadowing | Replaces the `print` name with a user-defined function. |
| `8_out_file_io` | File access | Attempts to write to an absolute path outside the workspace. |
| `9_workdir_file_io` | Benign control | Writes a file inside the configured workspace. |
| `10_exfil_secret` | Exfiltration | Exercises configurable secret-leak channels. |
| `11_exfil_frame` | Frame introspection | Attempts to recover a secret from a generator frame. |
| `12_timeout` | DoS | Runs an infinite loop to exercise timeout enforcement. |
| `13_crash` | Program failure | Raises an exception to exercise crash reporting. |
| `14_subprocess` | System operation | Attempts to execute an operating-system command. |

## Results Matrix

| Payload ID | Technique | Analyzer verdict | Prober verdict | Oracle verdict | Comments |
|---|---|---|---|---|---|
| `1_subclasses` | Subclasses traversal | Flagged | Blocked | False | Restricted attribute access prevented traversal. |
| `2_access` | `__globals__` / `__closure__` access | Flagged | Blocked | False | Forbidden function-state access was blocked. |
| `3_builtins` | Builtins restoration | Flagged | Blocked | False | The attempt to recover builtins was blocked. |
| `4_format` | Format-string attribute access | Flagged | Blocked | False | Private attribute access through formatting was blocked. |
| `5_exec` | Compressed payload execution | Flagged | Blocked | False | The encoded execution attempt did not run. |
| `6_benign_exec` | Harmless dynamic execution | Flagged | Blocked | False | Static analysis flagged `exec`, although the inner code was harmless. |
| `7_builtin_shadow` | Builtin shadowing | Flagged | Blocked | False | The attempt to replace `print` was blocked. |
| `8_out_file_io` | Out-of-bounds file access | Flagged | Passed (redirected) | False | The path was safely redirected to the canary directory. |
| `9_workdir_file_io` | In-bounds file access | Passed | Passed | False | File access inside the workspace was allowed. |
| `10_exfil_secret` | Secret exfiltration | Passed (FN) | Passed (FN) | True (exfiltration) | The analyzer missed the leak and execution did not contain it; the oracle detected the secret. |
| `11_exfil_frame` | Internal frame exfiltration | Flagged | Blocked | True (FP, exfiltration) | The oracle matched `gi_frame` in an error object even though it was not printed. |
| `12_timeout` | Infinite-loop DoS | Passed (FN) | Blocked | False | The analyzer missed the loop, but the timeout stopped it without a breach. |
| `13_crash` | Deliberate program crash | Passed (FN) | Blocked | False | The analyzer missed the crash, but execution contained it. |
| `14_subprocess` | System-level operation | Flagged | Blocked | False | The operating-system command was blocked before it caused a breach. |

### Static and Dynamic Comparison

**Flagged but did not escape:** 
- `1_subclasses`, `2_access`, `3_builtins`,
`4_format`, `5_exec`, `6_benign_exec`, `7_builtin_shadow`, `8_out_file_io`,
`11_exfil_frame`, and `14_subprocess`. Most are genuine escape attempts that
the HarnessWrapper executor blocked. 
- `6_benign_exec` is a conventional
static false positive because its dynamically executed code is harmless.
- `11_exfil_frame` did not escape either: its positive oracle result was caused
by the error object containing the monitored `gi_frame` keyword.

**Escaped but was not flagged:** `10_exfil_secret`. The analyzer produced no
finding and execution did not contain the secret leak, while the exfiltration
oracle correctly reported the breach. This is the confirmed static false
negative in the corpus.

## Testing

Install the development dependencies and run the complete test suite from the
repository root:

```sh
python -m pip install -e .
python -m pytest
```

Run each test file separately:

```sh
python -m pytest tests/test_analyzer.py
python -m pytest tests/test_oracle.py
python -m pytest tests/test_integration.py
```

- `test_analyzer.py` covers positive and negative cases for the AST detectors.
- `test_oracle.py` verifies the file, exfiltration, and process-audit oracles.
- `test_integration.py` runs the complete payload corpus against
  RestrictedPython.

`HarnessWrapper.run_regular_payload` acts as an intentionally broken sandbox
for oracle tests. It executes controlled test payloads without RestrictedPython
so the tests can confirm that the oracles detect a real file, secret, or process
effect. It must not be used to execute untrusted code.
