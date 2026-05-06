#!/usr/bin/env python3
"""
AppSec Code Review Toolkit — Test Suite
Validates that each rule correctly detects its target vulnerability
and does not produce false positives on clean code.
"""

import sys
import os
import tempfile
import unittest
from pathlib import Path

# Add parent dir to path so we can import scanner
sys.path.insert(0, str(Path(__file__).parent.parent))
from scanner.engine import (
    Scanner, Severity, Finding,
    PY_SQLInjection, PY_CommandInjection, PY_HardcodedSecret,
    PY_InsecureDeserialization, PY_WeakCrypto,
    JAVA_SQLInjection, JAVA_HardcodedSecret, JAVA_WeakCrypto,
    JAVA_XXE, JAVA_PathTraversal
)


def scan_snippet(code: str, lang: str = "python") -> list[Finding]:
    """Write a code snippet to a temp file and scan it."""
    ext = ".py" if lang == "python" else ".java"
    with tempfile.NamedTemporaryFile(suffix=ext, mode="w",
                                     delete=False, encoding="utf-8") as f:
        f.write(code)
        tmp_path = f.name
    scanner = Scanner(language=lang, min_severity=Severity.INFO)
    findings = scanner.scan_file(tmp_path)
    os.unlink(tmp_path)
    return findings


def has_rule(findings: list[Finding], rule_id: str) -> bool:
    return any(f.rule_id == rule_id for f in findings)


# ── Python Rule Tests ─────────────────────────────────────────────────────────

class TestPySQLInjection(unittest.TestCase):

    def test_detects_fstring_sql(self):
        code = '''
user_id = request.args.get("id")
query = f"SELECT * FROM users WHERE id = {user_id}"
cur.execute(query)
'''
        findings = scan_snippet(code)
        self.assertTrue(has_rule(findings, "PY-A03-001"),
                        "Should detect f-string SQL injection")

    def test_detects_percent_format_sql(self):
        code = '''
user_id = get_user_input()
query = "SELECT * FROM orders WHERE id = %s" % user_id
cur.execute(query)
'''
        findings = scan_snippet(code)
        self.assertTrue(has_rule(findings, "PY-A03-001"),
                        "Should detect % format SQL injection")

    def test_no_false_positive_parameterized(self):
        code = '''
user_id = request.args.get("id")
cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
'''
        findings = scan_snippet(code)
        self.assertFalse(has_rule(findings, "PY-A03-001"),
                         "Should NOT flag parameterized queries")


class TestPyCommandInjection(unittest.TestCase):

    def test_detects_shell_true_with_variable(self):
        code = '''
host = request.args.get("host")
import subprocess
subprocess.run(f"ping -c 1 {host}", shell=True)
'''
        findings = scan_snippet(code)
        self.assertTrue(has_rule(findings, "PY-A03-002"),
                        "Should detect shell=True with variable")

    def test_no_false_positive_list_form(self):
        code = '''
import subprocess
subprocess.run(["ping", "-c", "1", "8.8.8.8"], shell=False)
'''
        findings = scan_snippet(code)
        self.assertFalse(has_rule(findings, "PY-A03-002"),
                         "Should NOT flag list-based subprocess")


class TestPyHardcodedSecret(unittest.TestCase):

    def test_detects_password_assignment(self):
        code = 'DB_PASSWORD = "SuperSecret123!"'
        findings = scan_snippet(code)
        self.assertTrue(has_rule(findings, "PY-A02-001"),
                        "Should detect hardcoded password")

    def test_detects_api_key(self):
        code = 'api_key = "sk-prod-abc123xyz789abcdef"'
        findings = scan_snippet(code)
        self.assertTrue(has_rule(findings, "PY-A02-001"),
                        "Should detect hardcoded API key")

    def test_no_false_positive_env_var(self):
        code = 'password = os.environ.get("DB_PASSWORD")'
        findings = scan_snippet(code)
        self.assertFalse(has_rule(findings, "PY-A02-001"),
                         "Should NOT flag env var lookup")

    def test_no_false_positive_placeholder(self):
        code = 'password = "changeme"'
        findings = scan_snippet(code)
        self.assertFalse(has_rule(findings, "PY-A02-001"),
                         "Should NOT flag obvious placeholder")


class TestPyWeakCrypto(unittest.TestCase):

    def test_detects_md5(self):
        code = '''
import hashlib
digest = hashlib.md5(data.encode()).hexdigest()
'''
        findings = scan_snippet(code)
        self.assertTrue(has_rule(findings, "PY-A02-002"),
                        "Should detect MD5 usage")

    def test_detects_sha1(self):
        code = '''
import hashlib
h = hashlib.sha1(token.encode()).hexdigest()
'''
        findings = scan_snippet(code)
        self.assertTrue(has_rule(findings, "PY-A02-002"),
                        "Should detect SHA-1 usage")

    def test_no_false_positive_sha256(self):
        code = '''
import hashlib
h = hashlib.sha256(data.encode()).hexdigest()
'''
        findings = scan_snippet(code)
        self.assertFalse(has_rule(findings, "PY-A02-002"),
                         "Should NOT flag SHA-256")


class TestPyDeserialization(unittest.TestCase):

    def test_detects_pickle_loads(self):
        code = '''
import pickle
data = request.get_data()
obj = pickle.loads(data)
'''
        findings = scan_snippet(code)
        self.assertTrue(has_rule(findings, "PY-A08-001"),
                        "Should detect pickle.loads")

    def test_detects_unsafe_yaml_load(self):
        code = '''
import yaml
config = yaml.load(user_data)
'''
        findings = scan_snippet(code)
        self.assertTrue(has_rule(findings, "PY-A08-001"),
                        "Should detect yaml.load without SafeLoader")

    def test_no_false_positive_safe_yaml(self):
        code = '''
import yaml
config = yaml.safe_load(user_data)
'''
        findings = scan_snippet(code)
        self.assertFalse(has_rule(findings, "PY-A08-001"),
                         "Should NOT flag yaml.safe_load")


# ── Java Rule Tests ───────────────────────────────────────────────────────────

class TestJavaSQLInjection(unittest.TestCase):

    def test_detects_concatenated_query(self):
        code = '''
public ResultSet getUser(Connection conn, String userId) throws SQLException {
    return stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
}
'''
        findings = scan_snippet(code, lang="java")
        self.assertTrue(has_rule(findings, "JAVA-A03-001"),
                        "Should detect Java SQL concatenation")

    def test_no_false_positive_literal_query(self):
        code = '''
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, userId);
'''
        findings = scan_snippet(code, lang="java")
        self.assertFalse(has_rule(findings, "JAVA-A03-001"),
                         "Should NOT flag parameterized Java query")


class TestJavaWeakCrypto(unittest.TestCase):

    def test_detects_md5(self):
        code = 'MessageDigest md = MessageDigest.getInstance("MD5");'
        findings = scan_snippet(code, lang="java")
        self.assertTrue(has_rule(findings, "JAVA-A02-002"),
                        "Should detect Java MD5")

    def test_detects_sha1(self):
        code = 'MessageDigest md = MessageDigest.getInstance("SHA-1");'
        findings = scan_snippet(code, lang="java")
        self.assertTrue(has_rule(findings, "JAVA-A02-002"),
                        "Should detect Java SHA-1")

    def test_no_false_positive_sha256(self):
        code = 'MessageDigest md = MessageDigest.getInstance("SHA-256");'
        findings = scan_snippet(code, lang="java")
        self.assertFalse(has_rule(findings, "JAVA-A02-002"),
                         "Should NOT flag SHA-256")


class TestJavaXXE(unittest.TestCase):

    def test_detects_documentbuilderfactory(self):
        code = 'DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();'
        findings = scan_snippet(code, lang="java")
        self.assertTrue(has_rule(findings, "JAVA-A05-001"),
                        "Should detect unprotected DocumentBuilderFactory")


class TestJavaPathTraversal(unittest.TestCase):

    def test_detects_file_concat(self):
        code = 'File file = new File("/uploads/" + filename);'
        findings = scan_snippet(code, lang="java")
        self.assertTrue(has_rule(findings, "JAVA-A01-001"),
                        "Should detect path traversal via File concatenation")


# ── Integration Test: Full Scan of Sample Files ───────────────────────────────

class TestFullScanIntegration(unittest.TestCase):

    SAMPLES_DIR = Path(__file__).parent / "samples"

    def test_python_sample_has_findings(self):
        scanner = Scanner(language="python", min_severity=Severity.LOW)
        findings = scanner.scan_path(str(self.SAMPLES_DIR / "python"))
        self.assertGreater(len(findings), 5,
                           f"Expected 5+ findings in vulnerable Python sample, got {len(findings)}")

    def test_java_sample_has_findings(self):
        scanner = Scanner(language="java", min_severity=Severity.LOW)
        findings = scanner.scan_path(str(self.SAMPLES_DIR / "java"))
        self.assertGreater(len(findings), 3,
                           f"Expected 3+ findings in vulnerable Java sample, got {len(findings)}")

    def test_critical_findings_present(self):
        scanner = Scanner(language="all", min_severity=Severity.CRITICAL)
        findings = scanner.scan_path(str(self.SAMPLES_DIR))
        self.assertGreater(len(findings), 0,
                           "Expected at least one CRITICAL finding in samples")

    def test_severity_filter_works(self):
        scanner_all  = Scanner(language="python", min_severity=Severity.INFO)
        scanner_high = Scanner(language="python", min_severity=Severity.HIGH)
        all_f  = scanner_all.scan_path(str(self.SAMPLES_DIR / "python"))
        high_f = scanner_high.scan_path(str(self.SAMPLES_DIR / "python"))
        self.assertGreaterEqual(len(all_f), len(high_f),
                                "HIGH-filtered results should be subset of ALL results")


if __name__ == "__main__":
    # Run with verbose output
    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
