# Adding New Rules to the Scanner

This guide shows how to extend the toolkit with new vulnerability detection rules.

---

## Rule Types

| Type | When to Use | Analysis Method |
|------|-------------|-----------------|
| `PythonRule` | Python-specific, semantic detection | AST parsing |
| `JavaRule` | Java-specific detection | Regex on source |
| `RegexRule` | Cross-language, simple pattern | Regex on source |

---

## Example: Adding a New Python Rule (SSRF)

### Step 1 — Subclass PythonRule

```python
class PY_SSRF(PythonRule):
    """Detect SSRF via requests.get/post with variable URLs."""

    def __init__(self):
        super().__init__(
            rule_id="PY-A10-001",
            title="Server-Side Request Forgery (SSRF)",
            severity=Severity.HIGH,
            owasp=OWASPCategory.A10_SSRF,
            description=(
                "requests.get/post is called with a URL that includes a variable. "
                "If the URL is user-controlled, an attacker can cause the server to "
                "make requests to internal services, cloud metadata endpoints, or "
                "other unintended targets."
            ),
            remediation=(
                "Validate URL scheme (https only), hostname against an allowlist, "
                "and block private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x). "
                "Never pass raw user input to requests.get/post."
            ),
            cwe="CWE-918",
            confidence="MEDIUM",
            languages=["python"]
        )

    HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "request"}

    def _check_ast(self, file_path, tree, lines):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute):
                if (isinstance(node.func.value, ast.Name)
                        and node.func.value.id in {"requests", "req", "session"}
                        and node.func.attr in self.HTTP_METHODS
                        and node.args
                        and not isinstance(node.args[0], ast.Constant)):
                    findings.append(self._make_finding(file_path, node, lines))
        return findings
```

### Step 2 — Register the Rule

```python
# In Scanner._load_rules(), add:
PY_SSRF(),
```

### Step 3 — Write Tests

```python
class TestPySSRF(unittest.TestCase):

    def test_detects_variable_url(self):
        code = '''
url = request.args.get("url")
response = requests.get(url)
'''
        findings = scan_snippet(code)
        self.assertTrue(has_rule(findings, "PY-A10-001"))

    def test_no_false_positive_literal_url(self):
        code = '''
response = requests.get("https://api.trusted.com/data")
'''
        findings = scan_snippet(code)
        self.assertFalse(has_rule(findings, "PY-A10-001"))
```

---

## Finding Fields Reference

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | `str` | Unique ID: `LANG-OWASP-NNN` |
| `title` | `str` | Short human-readable title |
| `severity` | `Severity` | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `owasp` | `OWASPCategory` | OWASP Top 10 2021 category |
| `file` | `str` | Absolute path to file |
| `line` | `int` | 1-indexed line number |
| `column` | `int` | 0-indexed column offset |
| `code_snippet` | `str` | The vulnerable line (stripped) |
| `description` | `str` | Why this is a vulnerability |
| `remediation` | `str` | How to fix it |
| `cwe` | `str` | CWE identifier: `CWE-NNN` |
| `confidence` | `str` | HIGH / MEDIUM / LOW |
| `language` | `str` | python / java / etc. |

---

## Rule ID Naming Convention

```
{LANG}-{OWASP_CODE}-{SEQ}

Examples:
  PY-A03-001     Python, OWASP A03 (Injection), first rule
  JAVA-A02-002   Java, OWASP A02 (Crypto), second rule
  CROSS-A09-001  Cross-language, OWASP A09 (Logging), first rule
```
