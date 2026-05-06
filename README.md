# AppSec Code Review Toolkit

> **Author:** Ronald Maboufotso · CISSP · OSWP (OSWE in progress) · Principal Security Engineer  
> **Language:** Python 3.10+  
> **Targets:** Python · Java  
> **Tests:** 26 passing · 0 failing  

A white-box static analysis tool for identifying OWASP Top 10 vulnerability patterns in Python and Java codebases. Built using Python's `ast` module for semantic analysis — not grep. Designed to mirror the manual code review methodology taught in OffSec's WEB-300 (OSWE) course.

---

## Why AST-Based, Not Grep-Based

Most simple SAST tools match regex patterns against raw text. This produces high false-positive rates because context is lost. This toolkit uses Python's built-in `ast` module to parse source into an Abstract Syntax Tree before analysis, enabling:

- **Semantic understanding** — distinguishes `cursor.execute("SELECT...", (id,))` (safe) from `cursor.execute(f"SELECT...{id}")` (vulnerable)
- **False positive suppression** — `password = "changeme"` is a placeholder and skipped; `password = "Sup3rS3cr3t!"` is flagged
- **Call chain awareness** — detects `yaml.load()` without `SafeLoader` argument, not just any call to `yaml.load`

Java analysis uses regex against source text (a full Java AST requires external libraries), but with patterns tight enough to minimize noise.

---

## Rules Implemented

| Rule ID | Title | Lang | Severity | OWASP | CWE |
|---------|-------|------|----------|-------|-----|
| `PY-A03-001` | SQL Injection via String Formatting | Python | 🔴 Critical | A03 | CWE-89 |
| `PY-A03-002` | Command Injection via `subprocess shell=True` | Python | 🔴 Critical | A03 | CWE-78 |
| `PY-A08-001` | Insecure Deserialization (`pickle` / `yaml.load`) | Python | 🔴 Critical | A08 | CWE-502 |
| `PY-A02-001` | Hardcoded Secret / Credential | Python | 🟠 High | A02 | CWE-798 |
| `PY-A02-002` | Weak Cryptographic Algorithm (MD5, SHA-1) | Python | 🟠 High | A02 | CWE-327 |
| `PY-A01-001` | Route Missing Authentication Decorator | Python | 🟡 Medium | A01 | CWE-306 |
| `JAVA-A03-001` | SQL Injection via String Concatenation (JDBC) | Java | 🔴 Critical | A03 | CWE-89 |
| `JAVA-A05-001` | XML External Entity (XXE) Injection | Java | 🔴 Critical | A05 | CWE-611 |
| `JAVA-A02-001` | Hardcoded Secret / Credential | Java | 🟠 High | A02 | CWE-798 |
| `JAVA-A02-002` | Weak Cryptographic Algorithm | Java | 🟠 High | A02 | CWE-327 |
| `JAVA-A01-001` | Path Traversal — Unvalidated File Path | Java | 🟠 High | A01 | CWE-22 |
| `CROSS-A09-001` | Sensitive Data in Log Statement | Both | 🟡 Medium | A09 | CWE-532 |
| `CROSS-A05-001` | Debug Mode Enabled | Both | 🟡 Medium | A05 | CWE-94 |
| `CROSS-A02-003` | Use of `eval()` / `exec()` | Both | 🟠 High | A03 | CWE-95 |
| `CROSS-A05-002` | SSL/TLS Certificate Verification Disabled | Both | 🟠 High | A05 | CWE-295 |

---

## Quick Start

```bash
git clone https://github.com/YOUR_HANDLE/appsec-code-review-toolkit.git
cd appsec-code-review-toolkit

# Scan a Python project
python3 scanner/engine.py --path /path/to/project --lang python

# Scan a Java project, show only HIGH+ findings
python3 scanner/engine.py --path /path/to/project --lang java --severity HIGH

# Scan everything, export JSON report
python3 scanner/engine.py --path /path/to/project --lang all \
  --format json --output reports/scan.json

# Scan everything, export Markdown report
python3 scanner/engine.py --path /path/to/project --lang all \
  --format markdown --output reports/scan.md
```

### Demo — Scan the Included Vulnerable Samples

```bash
python3 scanner/engine.py --path tests/samples --lang all --severity LOW
```

Expected output: **33 findings** across Python and Java samples (10 Critical, 15 High, 8 Medium).

---

## Output Formats

### Console (default)
Color-coded terminal output with rule ID, OWASP category, CWE, location, code snippet, and remediation.

### JSON
Machine-readable output for integration with CI/CD pipelines, ticket systems, or dashboards:
```json
{
  "scan_metadata": {
    "target": "./myapp",
    "timestamp": "2026-05-01T14:32:00",
    "total_findings": 12,
    "summary": {"CRITICAL": 3, "HIGH": 5, "MEDIUM": 4, "LOW": 0, "INFO": 0}
  },
  "findings": [...]
}
```

### Markdown
Formatted report suitable for GitHub issues, Confluence, or Jira:
```bash
python3 scanner/engine.py --path ./myapp --format markdown --output SECURITY-REPORT.md
```

---

## CI/CD Integration

The scanner exits with code `1` if any CRITICAL or HIGH findings are present — enabling pipeline gates:

```yaml
# GitHub Actions example
- name: AppSec Code Review
  run: |
    python3 scanner/engine.py \
      --path . \
      --lang all \
      --severity HIGH \
      --format json \
      --output security-report.json
  # Pipeline fails if HIGH/CRITICAL findings exist (exit code 1)

- name: Upload security report
  uses: actions/upload-artifact@v3
  if: always()
  with:
    name: security-report
    path: security-report.json
```

---

## Running Tests

```bash
python3 tests/test_rules.py
```

```
Ran 26 tests in 0.079s
OK
```

Each rule has:
- A **detection test** — confirms the vuln pattern is caught
- A **false-positive test** — confirms the safe equivalent is not flagged

---

## Repository Structure

```
appsec-code-review-toolkit/
├── README.md
├── scanner/
│   └── engine.py           ← Core scanner (AST + regex rules, CLI, formatters)
├── tests/
│   ├── test_rules.py        ← 26 unit + integration tests
│   └── samples/
│       ├── python/
│       │   └── vulnerable_app.py   ← Intentionally vulnerable Flask app
│       └── java/
│           └── VulnerableApp.java  ← Intentionally vulnerable Java class
├── reports/                 ← Scan output directory (gitignored)
└── docs/
    └── adding-rules.md      ← Guide for extending with new rules
```

---

## OSWE Connection

This toolkit directly reflects the white-box methodology practiced in OffSec's WEB-300 course:

- **Source code decompilation** → replaced by AST parsing of Python source
- **Vulnerability chaining** — rules flag individual sinks; manual review chains them into full attack paths
- **Proof-of-concept development** → the test samples serve as PoC targets
- **Repeatable methodology** → rule IDs, OWASP categories, and CWE references match professional pentest report format

Skills demonstrated: Python AST parsing, static analysis methodology, test-driven development, OWASP Top 10 deep knowledge, CI/CD security integration.

---

## Extending with New Rules

See [`docs/adding-rules.md`](docs/adding-rules.md) for a step-by-step guide to adding new vulnerability patterns. The pattern is:

1. Subclass `PythonRule` or `JavaRule`
2. Implement `_check_ast()` or `_check_source()`
3. Return a list of `Finding` objects
4. Register in `Scanner._load_rules()`
5. Write detection + false-positive tests

---

## Roadmap

- [ ] SSRF detection (Python `requests` with variable URLs)
- [ ] Template injection (Jinja2 `render_string` with user input)
- [ ] IDOR pattern detection (direct object references in ORM queries)
- [ ] Semgrep rule export (convert findings to `.yaml` Semgrep rules)
- [ ] HTML report format with severity charts
- [ ] Pre-commit hook integration

---

*All testing performed on intentional vulnerable samples only. Never run against production systems without authorization.*
