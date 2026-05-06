#!/usr/bin/env python3
"""
AppSec Code Review Toolkit — Core Scanner Engine
=================================================
Author:  Ronald Maboufotso | CISSP · OSWP · Principal Security Engineer
Purpose: White-box static analysis for Java and Python codebases.
         Detects OWASP Top 10 vulnerability patterns using AST parsing
         and signature-based matching. Mirrors OSWE white-box methodology.

Usage:
    python3 scanner/engine.py --path ./target --lang python --output report.json
    python3 scanner/engine.py --path ./target --lang java   --severity HIGH
    python3 scanner/engine.py --path ./target --lang all    --format html
"""

import ast
import os
import re
import json
import argparse
import sys
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional
from enum import Enum


# ── Severity & Category Enums ───────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    def score(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]

    def color(self) -> str:
        return {
            "CRITICAL": "\033[91m",  # Red
            "HIGH":     "\033[93m",  # Yellow
            "MEDIUM":   "\033[94m",  # Blue
            "LOW":      "\033[92m",  # Green
            "INFO":     "\033[37m",  # White
        }[self.value]


class OWASPCategory(str, Enum):
    A01_BROKEN_ACCESS    = "A01:2021 – Broken Access Control"
    A02_CRYPTO           = "A02:2021 – Cryptographic Failures"
    A03_INJECTION        = "A03:2021 – Injection"
    A04_INSECURE_DESIGN  = "A04:2021 – Insecure Design"
    A05_MISCONFIG        = "A05:2021 – Security Misconfiguration"
    A06_COMPONENTS       = "A06:2021 – Vulnerable & Outdated Components"
    A07_AUTH             = "A07:2021 – Identification & Authentication Failures"
    A08_INTEGRITY        = "A08:2021 – Software & Data Integrity Failures"
    A09_LOGGING          = "A09:2021 – Security Logging & Monitoring Failures"
    A10_SSRF             = "A10:2021 – Server-Side Request Forgery"


# ── Finding Data Model ───────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id:       str
    title:         str
    severity:      Severity
    owasp:         OWASPCategory
    file:          str
    line:          int
    column:        int
    code_snippet:  str
    description:   str
    remediation:   str
    cwe:           str
    confidence:    str   # HIGH / MEDIUM / LOW
    language:      str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["owasp"]    = self.owasp.value
        return d


# ── Rule Base Class ──────────────────────────────────────────────────────────

@dataclass
class Rule:
    rule_id:     str
    title:       str
    severity:    Severity
    owasp:       OWASPCategory
    description: str
    remediation: str
    cwe:         str
    confidence:  str = "MEDIUM"
    languages:   list = field(default_factory=lambda: ["python", "java"])

    def check(self, file_path: str, source: str, lines: list[str]) -> list[Finding]:
        raise NotImplementedError


# ══════════════════════════════════════════════════════════════════════════════
# PYTHON RULES — AST-based analysis
# ══════════════════════════════════════════════════════════════════════════════

class PythonRule(Rule):
    """Base class for Python AST rules."""

    def check(self, file_path: str, source: str, lines: list[str]) -> list[Finding]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        return self._check_ast(file_path, tree, lines)

    def _check_ast(self, file_path, tree, lines) -> list[Finding]:
        return []

    def _make_finding(self, file_path, node, lines) -> Finding:
        line_idx = node.lineno - 1
        snippet = lines[line_idx].strip() if 0 <= line_idx < len(lines) else ""
        return Finding(
            rule_id=self.rule_id, title=self.title,
            severity=self.severity, owasp=self.owasp,
            file=file_path, line=node.lineno,
            column=getattr(node, "col_offset", 0),
            code_snippet=snippet,
            description=self.description, remediation=self.remediation,
            cwe=self.cwe, confidence=self.confidence, language="python"
        )


class PY_SQLInjection(PythonRule):
    """Detect string-formatted SQL queries — classic SQLi pattern."""

    def __init__(self):
        super().__init__(
            rule_id="PY-A03-001",
            title="SQL Injection via String Formatting",
            severity=Severity.CRITICAL,
            owasp=OWASPCategory.A03_INJECTION,
            description=(
                "SQL query is constructed by concatenating or formatting user-controlled "
                "input directly into the query string. An attacker can manipulate the query "
                "to bypass authentication, exfiltrate data, or execute arbitrary SQL."
            ),
            remediation=(
                "Use parameterized queries (prepared statements) exclusively. "
                "Example: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)) "
                "Never use str.format(), f-strings, or % formatting to build SQL."
            ),
            cwe="CWE-89",
            confidence="HIGH",
            languages=["python"]
        )

    def _check_ast(self, file_path, tree, lines):
        findings = []
        SQL_KEYWORDS = re.compile(
            r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION|EXEC)\b',
            re.IGNORECASE
        )

        for node in ast.walk(tree):
            # Detect f-strings containing SQL keywords
            if isinstance(node, ast.JoinedStr):
                src = ast.unparse(node)
                if SQL_KEYWORDS.search(src):
                    findings.append(self._make_finding(file_path, node, lines))

            # Detect % formatting: "SELECT ... %s" % variable (NOT parameterized)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                    if SQL_KEYWORDS.search(node.left.value):
                        # Ensure right side is a variable, not just a literal
                        if not isinstance(node.right, ast.Constant):
                            findings.append(self._make_finding(file_path, node, lines))

            # Detect .format() on SQL strings
            elif isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Attribute)
                        and node.func.attr == "format"
                        and isinstance(node.func.value, ast.Constant)
                        and isinstance(node.func.value.value, str)
                        and SQL_KEYWORDS.search(node.func.value.value)):
                    findings.append(self._make_finding(file_path, node, lines))

        return findings


class PY_CommandInjection(PythonRule):
    """Detect shell=True subprocess calls with variable input."""

    def __init__(self):
        super().__init__(
            rule_id="PY-A03-002",
            title="Command Injection via subprocess shell=True",
            severity=Severity.CRITICAL,
            owasp=OWASPCategory.A03_INJECTION,
            description=(
                "subprocess.run/call/Popen is called with shell=True and a non-literal "
                "command string. If any part of the command is user-controlled, an attacker "
                "can inject arbitrary OS commands (e.g., via semicolon, pipe, backtick)."
            ),
            remediation=(
                "Pass commands as a list, never as a string: "
                "subprocess.run(['ls', '-la', user_dir], shell=False). "
                "If shell=True is required, sanitize input with shlex.quote()."
            ),
            cwe="CWE-78",
            confidence="HIGH",
            languages=["python"]
        )

    DANGEROUS_FUNCS = {"run", "call", "check_output", "Popen", "check_call"}

    def _check_ast(self, file_path, tree, lines):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            func_name = None
            if isinstance(func, ast.Attribute):
                func_name = func.attr
            elif isinstance(func, ast.Name):
                func_name = func.id

            if func_name not in self.DANGEROUS_FUNCS:
                continue

            # Check if shell=True keyword argument is present
            has_shell_true = any(
                isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                and kw.arg == "shell"
                for kw in node.keywords
            )

            if not has_shell_true:
                continue

            # Check if the command arg is non-literal (variable / f-string)
            if node.args:
                cmd_arg = node.args[0]
                if not isinstance(cmd_arg, ast.Constant):
                    findings.append(self._make_finding(file_path, node, lines))

        return findings


class PY_HardcodedSecret(PythonRule):
    """Detect hardcoded passwords, API keys, and secrets."""

    def __init__(self):
        super().__init__(
            rule_id="PY-A02-001",
            title="Hardcoded Secret / Credential",
            severity=Severity.HIGH,
            owasp=OWASPCategory.A02_CRYPTO,
            description=(
                "A credential, API key, password, or secret appears to be hardcoded as a "
                "string literal. Hardcoded secrets are exposed in source code repositories, "
                "compiled binaries, and any system with read access to the file."
            ),
            remediation=(
                "Load secrets from environment variables (os.environ.get) or a secrets "
                "manager (HashiCorp Vault, AWS Secrets Manager). "
                "Add secret patterns to .gitignore and pre-commit hooks. "
                "Rotate any exposed credentials immediately."
            ),
            cwe="CWE-798",
            confidence="MEDIUM",
            languages=["python"]
        )

    SECRET_NAMES = re.compile(
        r'(password|passwd|pwd|secret|api_key|apikey|token|auth_token'
        r'|private_key|access_key|secret_key|client_secret|db_pass'
        r'|database_password|smtp_password)',
        re.IGNORECASE
    )
    PLACEHOLDER_VALUES = re.compile(
        r'^(your[_\-]?.*|changeme|placeholder|xxxx+|todo|replace|example|test|dummy|none|null|empty)$',
        re.IGNORECASE
    )

    def _check_ast(self, file_path, tree, lines):
        findings = []
        for node in ast.walk(tree):
            # Assignment: password = "actual_secret"
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and self.SECRET_NAMES.search(target.id):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            val = node.value.value
                            # Skip empty strings and obvious placeholders
                            if val and len(val) > 3 and not self.PLACEHOLDER_VALUES.match(val):
                                findings.append(self._make_finding(file_path, node, lines))

            # Dict literal: {"password": "actual_secret"}
            elif isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if (isinstance(key, ast.Constant)
                            and isinstance(key.value, str)
                            and self.SECRET_NAMES.search(key.value)
                            and isinstance(value, ast.Constant)
                            and isinstance(value.value, str)
                            and value.value
                            and len(value.value) > 3
                            and not self.PLACEHOLDER_VALUES.match(value.value)):
                        findings.append(self._make_finding(file_path, node, lines))

        return findings


class PY_InsecureDeserialization(PythonRule):
    """Detect unsafe pickle/yaml deserialization of untrusted data."""

    def __init__(self):
        super().__init__(
            rule_id="PY-A08-001",
            title="Insecure Deserialization (pickle / yaml.load)",
            severity=Severity.CRITICAL,
            owasp=OWASPCategory.A08_INTEGRITY,
            description=(
                "pickle.loads() or yaml.load() without Loader=yaml.SafeLoader deserializes "
                "arbitrary Python objects. If any part of the input is attacker-controlled, "
                "this allows remote code execution with no further preconditions."
            ),
            remediation=(
                "Never deserialize untrusted data with pickle. Use JSON or MessagePack instead. "
                "For YAML: yaml.safe_load(data) instead of yaml.load(data). "
                "If pickle is required for internal use only, validate HMAC signatures before deserializing."
            ),
            cwe="CWE-502",
            confidence="HIGH",
            languages=["python"]
        )

    DANGEROUS = {("pickle", "loads"), ("pickle", "load"),
                 ("_pickle", "loads"), ("cPickle", "loads")}

    def _check_ast(self, file_path, tree, lines):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute):
                attr  = node.func.attr
                # pickle.loads
                if isinstance(node.func.value, ast.Name):
                    module = node.func.value.id
                    if (module, attr) in self.DANGEROUS:
                        findings.append(self._make_finding(file_path, node, lines))
                # yaml.load without SafeLoader
                if (isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "yaml"
                        and attr == "load"):
                    has_safe_loader = any(
                        (isinstance(kw.value, ast.Attribute)
                         and kw.value.attr == "SafeLoader")
                        or
                        (isinstance(kw.value, ast.Name)
                         and "Safe" in kw.value.id)
                        for kw in node.keywords
                    )
                    if not has_safe_loader:
                        findings.append(self._make_finding(file_path, node, lines))
        return findings


class PY_WeakCrypto(PythonRule):
    """Detect use of broken cryptographic algorithms."""

    def __init__(self):
        super().__init__(
            rule_id="PY-A02-002",
            title="Weak or Broken Cryptographic Algorithm",
            severity=Severity.HIGH,
            owasp=OWASPCategory.A02_CRYPTO,
            description=(
                "Use of MD5 or SHA-1 for security-sensitive operations (password hashing, "
                "integrity verification, signatures). Both are cryptographically broken and "
                "vulnerable to collision attacks."
            ),
            remediation=(
                "Use SHA-256 or SHA-3 for integrity. "
                "Use bcrypt, scrypt, or Argon2 for password hashing — never MD5/SHA-1. "
                "Use AES-256-GCM for symmetric encryption."
            ),
            cwe="CWE-327",
            confidence="HIGH",
            languages=["python"]
        )

    WEAK_ALGOS = {"md5", "sha1", "sha", "MD5", "SHA1"}

    def _check_ast(self, file_path, tree, lines):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute):
                # hashlib.md5() / hashlib.sha1()
                if (isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "hashlib"
                        and node.func.attr in self.WEAK_ALGOS):
                    findings.append(self._make_finding(file_path, node, lines))
                # hashlib.new("md5")
                elif (isinstance(node.func.value, ast.Name)
                      and node.func.value.id == "hashlib"
                      and node.func.attr == "new"
                      and node.args
                      and isinstance(node.args[0], ast.Constant)
                      and node.args[0].value.lower() in {"md5", "sha1", "sha"}):
                    findings.append(self._make_finding(file_path, node, lines))
        return findings


class PY_MissingAuthDecorator(PythonRule):
    """Detect Flask/FastAPI routes missing authentication decorators."""

    def __init__(self):
        super().__init__(
            rule_id="PY-A01-001",
            title="Route Potentially Missing Authentication",
            severity=Severity.MEDIUM,
            owasp=OWASPCategory.A01_BROKEN_ACCESS,
            description=(
                "A Flask or FastAPI route function does not have a recognizable "
                "authentication decorator (@login_required, @jwt_required, @requires_auth, "
                "Depends(get_current_user)). If this route handles sensitive data or "
                "mutations, it may be accessible without authentication."
            ),
            remediation=(
                "Apply an authentication decorator to every route that accesses "
                "user data, performs mutations, or reaches privileged functionality. "
                "Use @login_required (Flask-Login), @jwt_required (Flask-JWT), "
                "or Depends(get_current_user) (FastAPI)."
            ),
            cwe="CWE-306",
            confidence="LOW",
            languages=["python"]
        )

    ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch"}
    AUTH_DECORATORS  = {
        "login_required", "jwt_required", "jwt_optional",
        "requires_auth", "token_required", "auth_required",
        "permission_required", "staff_member_required"
    }
    SAFE_PATHS = re.compile(
        r'/(login|logout|register|signup|health|ping|status|static|favicon)',
        re.IGNORECASE
    )

    def _check_ast(self, file_path, tree, lines):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue

            decorator_names = set()
            route_path = None

            for dec in node.decorator_list:
                if isinstance(dec, ast.Call):
                    if isinstance(dec.func, ast.Attribute):
                        decorator_names.add(dec.func.attr)
                        if dec.func.attr in self.ROUTE_DECORATORS and dec.args:
                            if isinstance(dec.args[0], ast.Constant):
                                route_path = dec.args[0].value
                    elif isinstance(dec.func, ast.Name):
                        decorator_names.add(dec.func.id)
                elif isinstance(dec, ast.Attribute):
                    decorator_names.add(dec.attr)
                elif isinstance(dec, ast.Name):
                    decorator_names.add(dec.id)

            is_route = bool(decorator_names & self.ROUTE_DECORATORS)
            has_auth  = bool(decorator_names & self.AUTH_DECORATORS)

            if is_route and not has_auth:
                if route_path and self.SAFE_PATHS.search(route_path):
                    continue
                findings.append(self._make_finding(file_path, node, lines))

        return findings


# ══════════════════════════════════════════════════════════════════════════════
# JAVA RULES — Regex-based (AST requires external lib)
# ══════════════════════════════════════════════════════════════════════════════

class JavaRule(Rule):
    """Base class for Java regex-based rules."""

    def check(self, file_path: str, source: str, lines: list[str]) -> list[Finding]:
        return self._check_source(file_path, source, lines)

    def _check_source(self, file_path, source, lines) -> list[Finding]:
        return []

    def _make_finding(self, file_path, line_num, lines, col=0) -> Finding:
        line_idx = line_num - 1
        snippet = lines[line_idx].strip() if 0 <= line_idx < len(lines) else ""
        return Finding(
            rule_id=self.rule_id, title=self.title,
            severity=self.severity, owasp=self.owasp,
            file=file_path, line=line_num, column=col,
            code_snippet=snippet,
            description=self.description, remediation=self.remediation,
            cwe=self.cwe, confidence=self.confidence, language="java"
        )


class JAVA_SQLInjection(JavaRule):
    """Detect string concatenation into JDBC queries."""

    def __init__(self):
        super().__init__(
            rule_id="JAVA-A03-001",
            title="SQL Injection via String Concatenation (JDBC)",
            severity=Severity.CRITICAL,
            owasp=OWASPCategory.A03_INJECTION,
            description=(
                "A JDBC query is constructed by concatenating string variables. "
                "If any variable contains user input, this is exploitable for SQL injection."
            ),
            remediation=(
                "Use PreparedStatement with parameter binding: "
                "PreparedStatement ps = conn.prepareStatement('SELECT * FROM users WHERE id = ?'); "
                "ps.setString(1, userId); "
                "Never concatenate user input into SQL strings."
            ),
            cwe="CWE-89",
            confidence="HIGH",
            languages=["java"]
        )

    PATTERN = re.compile(
        r'(executeQuery|executeUpdate|execute|prepareStatement)\s*\(\s*'
        r'"[^"]*"\s*\+',
        re.MULTILINE
    )

    def _check_source(self, file_path, source, lines):
        findings = []
        for match in self.PATTERN.finditer(source):
            line_num = source[:match.start()].count("\n") + 1
            findings.append(self._make_finding(file_path, line_num, lines, match.start()))
        return findings


class JAVA_HardcodedSecret(JavaRule):
    """Detect hardcoded credentials in Java source."""

    def __init__(self):
        super().__init__(
            rule_id="JAVA-A02-001",
            title="Hardcoded Secret / Credential",
            severity=Severity.HIGH,
            owasp=OWASPCategory.A02_CRYPTO,
            description=(
                "A password, API key, or secret is assigned as a string literal. "
                "This will be committed to source control and visible to anyone with repo access."
            ),
            remediation=(
                "Use environment variables or a secrets manager. "
                "String password = System.getenv('DB_PASSWORD'); "
                "Use Spring's @Value annotation with external config."
            ),
            cwe="CWE-798",
            confidence="MEDIUM",
            languages=["java"]
        )

    PATTERN = re.compile(
        r'(String\s+)?(password|passwd|secret|apiKey|api_key|token|privateKey|clientSecret)'
        r'\s*=\s*"([^"]{4,})"',
        re.IGNORECASE
    )
    PLACEHOLDER = re.compile(
        r'^(your.*|changeme|placeholder|xxxx+|todo|replace|example|test|dummy)$',
        re.IGNORECASE
    )

    def _check_source(self, file_path, source, lines):
        findings = []
        for match in self.PATTERN.finditer(source):
            secret_value = match.group(3)
            if not self.PLACEHOLDER.match(secret_value):
                line_num = source[:match.start()].count("\n") + 1
                findings.append(self._make_finding(file_path, line_num, lines))
        return findings


class JAVA_WeakCrypto(JavaRule):
    """Detect MD5/SHA-1/DES usage in Java."""

    def __init__(self):
        super().__init__(
            rule_id="JAVA-A02-002",
            title="Weak Cryptographic Algorithm",
            severity=Severity.HIGH,
            owasp=OWASPCategory.A02_CRYPTO,
            description=(
                "MD5, SHA-1, or DES are cryptographically broken and should not be used "
                "for any security-sensitive operation."
            ),
            remediation=(
                "MessageDigest.getInstance('SHA-256') for hashing. "
                "Use BCrypt or Argon2 for passwords. "
                "Use AES/GCM/NoPadding for symmetric encryption."
            ),
            cwe="CWE-327",
            confidence="HIGH",
            languages=["java"]
        )

    PATTERN = re.compile(
        r'getInstance\s*\(\s*"(MD5|SHA-?1|DES|RC4|RC2|Blowfish)"',
        re.IGNORECASE
    )

    def _check_source(self, file_path, source, lines):
        findings = []
        for match in self.PATTERN.finditer(source):
            line_num = source[:match.start()].count("\n") + 1
            findings.append(self._make_finding(file_path, line_num, lines))
        return findings


class JAVA_XXE(JavaRule):
    """Detect XML parsers not protected against XXE."""

    def __init__(self):
        super().__init__(
            rule_id="JAVA-A05-001",
            title="XML External Entity (XXE) Injection",
            severity=Severity.CRITICAL,
            owasp=OWASPCategory.A05_MISCONFIG,
            description=(
                "An XML parser is instantiated without disabling external entity processing. "
                "An attacker can submit a crafted XML payload to read local files "
                "(/etc/passwd), perform SSRF, or cause DoS via billion-laughs attacks."
            ),
            remediation=(
                "Disable external entities on every XML parser: "
                "factory.setFeature('http://xml.org/sax/features/external-general-entities', false); "
                "factory.setFeature('http://xml.org/sax/features/external-parameter-entities', false); "
                "factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true);"
            ),
            cwe="CWE-611",
            confidence="MEDIUM",
            languages=["java"]
        )

    PATTERN = re.compile(
        r'(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)'
        r'\.newInstance\s*\(\s*\)',
        re.MULTILINE
    )

    def _check_source(self, file_path, source, lines):
        findings = []
        for match in self.PATTERN.finditer(source):
            line_num = source[:match.start()].count("\n") + 1
            findings.append(self._make_finding(file_path, line_num, lines))
        return findings


class JAVA_PathTraversal(JavaRule):
    """Detect unvalidated file path construction."""

    def __init__(self):
        super().__init__(
            rule_id="JAVA-A01-001",
            title="Path Traversal — Unvalidated File Path",
            severity=Severity.HIGH,
            owasp=OWASPCategory.A01_BROKEN_ACCESS,
            description=(
                "A File or Path object is constructed using a variable (likely user input) "
                "without path canonicalization or prefix validation. "
                "An attacker can use ../ sequences to escape the intended directory."
            ),
            remediation=(
                "Canonicalize and validate the path: "
                "Path resolved = Paths.get(BASE_DIR).resolve(userInput).normalize(); "
                "if (!resolved.startsWith(BASE_DIR)) throw new SecurityException(); "
                "Use an allowlist of permitted filenames where possible."
            ),
            cwe="CWE-22",
            confidence="MEDIUM",
            languages=["java"]
        )

    PATTERN = re.compile(
        r'new\s+File\s*\([^)]*\+[^)]*\)|'
        r'Paths\.get\s*\([^)]*\+[^)]*\)',
        re.MULTILINE
    )

    def _check_source(self, file_path, source, lines):
        findings = []
        for match in self.PATTERN.finditer(source):
            line_num = source[:match.start()].count("\n") + 1
            findings.append(self._make_finding(file_path, line_num, lines))
        return findings


# ══════════════════════════════════════════════════════════════════════════════
# CROSS-LANGUAGE REGEX RULES (Python + Java)
# ══════════════════════════════════════════════════════════════════════════════

class RegexRule(Rule):
    """Regex-based rule that applies to source text of any language."""

    def __init__(self, rule_id, title, severity, owasp, description,
                 remediation, cwe, pattern: str, confidence="MEDIUM",
                 languages=None, flags=re.MULTILINE | re.IGNORECASE):
        super().__init__(rule_id, title, severity, owasp, description,
                         remediation, cwe, confidence,
                         languages or ["python", "java"])
        self.pattern = re.compile(pattern, flags)

    def check(self, file_path: str, source: str, lines: list[str]) -> list[Finding]:
        findings = []
        for match in self.pattern.finditer(source):
            line_num = source[:match.start()].count("\n") + 1
            line_idx = line_num - 1
            snippet = lines[line_idx].strip() if 0 <= line_idx < len(lines) else ""
            findings.append(Finding(
                rule_id=self.rule_id, title=self.title,
                severity=self.severity, owasp=self.owasp,
                file=file_path, line=line_num, column=match.start(),
                code_snippet=snippet,
                description=self.description, remediation=self.remediation,
                cwe=self.cwe, confidence=self.confidence,
                language=Path(file_path).suffix.lstrip(".")
            ))
        return findings


def build_regex_rules() -> list[Rule]:
    return [
        RegexRule(
            "CROSS-A09-001",
            "Sensitive Data in Log Statement",
            Severity.MEDIUM,
            OWASPCategory.A09_LOGGING,
            "A log statement appears to include password, token, or secret variable names. "
            "Logging credentials creates exposure in log files, SIEM systems, and log aggregators.",
            "Strip sensitive fields before logging. Use structured logging with field redaction. "
            "Never log request bodies from authentication endpoints.",
            "CWE-532",
            r'(log|logger|logging|print)\s*[\.(].*(password|secret|token|api_key|passwd|credential)',
            confidence="MEDIUM"
        ),
        RegexRule(
            "CROSS-A05-001",
            "Debug Mode Enabled in Production Code",
            Severity.MEDIUM,
            OWASPCategory.A05_MISCONFIG,
            "DEBUG=True or debug=True found in source. Running with debug mode enabled in "
            "production exposes stack traces, internal paths, and sometimes interactive consoles.",
            "Set DEBUG=False in production. Use environment variables to control debug flags. "
            "Never commit production config with debug enabled.",
            "CWE-94",
            r'DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True',
            confidence="HIGH"
        ),
        RegexRule(
            "CROSS-A02-003",
            "Use of eval() or exec() — Code Injection Risk",
            Severity.HIGH,
            OWASPCategory.A03_INJECTION,
            "eval() or exec() executes arbitrary code from a string. If any part of the input "
            "is user-controlled, this is a direct code injection vulnerability.",
            "Eliminate eval/exec entirely. If dynamic execution is required, use a strict "
            "allowlist of permitted operations. Consider ast.literal_eval() for safe data parsing.",
            "CWE-95",
            r'\beval\s*\(|\bexec\s*\(',
            confidence="MEDIUM"
        ),
        RegexRule(
            "CROSS-A05-002",
            "SSL/TLS Certificate Verification Disabled",
            Severity.HIGH,
            OWASPCategory.A05_MISCONFIG,
            "SSL certificate verification is explicitly disabled (verify=False, "
            "VERIFY_SSL=False, checkHostName=false). This makes HTTPS connections "
            "vulnerable to man-in-the-middle attacks.",
            "Always verify TLS certificates. Remove verify=False. "
            "If using self-signed certs in development, add the CA bundle path instead.",
            "CWE-295",
            r'verify\s*=\s*False|VERIFY_SSL\s*=\s*False|checkHostName\s*=\s*false'
            r'|setHostnameVerifier\s*\(\s*ALLOW_ALL',
            confidence="HIGH"
        ),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# SCANNER ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class Scanner:

    EXTENSIONS = {
        "python": [".py"],
        "java":   [".java"],
        "all":    [".py", ".java"]
    }

    def __init__(self, language: str = "all",
                 min_severity: Severity = Severity.LOW,
                 exclude_dirs: list[str] = None):
        self.language     = language
        self.min_severity = min_severity
        self.exclude_dirs = set(exclude_dirs or ["venv", ".venv", "node_modules",
                                                  ".git", "__pycache__", "build",
                                                  "dist", "target"])
        self.rules = self._load_rules()

    def _load_rules(self) -> list[Rule]:
        all_rules: list[Rule] = [
            PY_SQLInjection(), PY_CommandInjection(),
            PY_HardcodedSecret(), PY_InsecureDeserialization(),
            PY_WeakCrypto(), PY_MissingAuthDecorator(),
            JAVA_SQLInjection(), JAVA_HardcodedSecret(),
            JAVA_WeakCrypto(), JAVA_XXE(), JAVA_PathTraversal(),
            *build_regex_rules()
        ]
        lang = self.language.lower()
        if lang == "all":
            return all_rules
        return [r for r in all_rules if lang in r.languages]

    def _should_scan(self, file_path: Path) -> bool:
        exts = self.EXTENSIONS.get(self.language, self.EXTENSIONS["all"])
        if file_path.suffix not in exts:
            return False
        for part in file_path.parts:
            if part in self.exclude_dirs:
                return False
        return True

    def scan_file(self, file_path: str) -> list[Finding]:
        p = Path(file_path)
        if not self._should_scan(p):
            return []
        try:
            source = p.read_text(encoding="utf-8", errors="ignore")
        except (IOError, OSError):
            return []
        lines = source.splitlines()
        findings = []
        for rule in self.rules:
            lang = p.suffix.lstrip(".")
            if lang == "py":   lang = "python"
            if lang not in rule.languages and "all" not in rule.languages:
                continue
            try:
                results = rule.check(str(file_path), source, lines)
                findings.extend(results)
            except Exception:
                pass
        return [f for f in findings if f.severity.score() >= self.min_severity.score()]

    def scan_path(self, target: str) -> list[Finding]:
        p = Path(target)
        all_findings = []
        if p.is_file():
            all_findings = self.scan_file(str(p))
        elif p.is_dir():
            for file_path in sorted(p.rglob("*")):
                if file_path.is_file():
                    all_findings.extend(self.scan_file(str(file_path)))
        return sorted(all_findings, key=lambda f: (-f.severity.score(), f.file, f.line))


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT FORMATTERS
# ══════════════════════════════════════════════════════════════════════════════

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"


def format_console(findings: list[Finding], path: str, elapsed: float):
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    print(f"\n{BOLD}{'─'*70}{RESET}")
    print(f"{BOLD}  AppSec Code Review Toolkit — Scan Results{RESET}")
    print(f"{'─'*70}")
    print(f"  Target:   {path}")
    print(f"  Scanned:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ({elapsed:.2f}s)")
    print(f"  Findings: {len(findings)}")
    print(f"{'─'*70}\n")

    if not findings:
        print(f"  {BOLD}✅  No findings above threshold.{RESET}\n")
        return

    for f in findings:
        color = f.severity.color()
        rel_file = f.file
        print(f"  {color}{BOLD}[{f.severity.value}]{RESET}  {BOLD}{f.title}{RESET}")
        print(f"  {DIM}Rule:{RESET} {f.rule_id}  {DIM}CWE:{RESET} {f.cwe}  {DIM}OWASP:{RESET} {f.owasp.value}")
        print(f"  {DIM}Location:{RESET} {CYAN}{rel_file}:{f.line}{RESET}")
        print(f"  {DIM}Snippet:{RESET}  {f.code_snippet}")
        print(f"  {DIM}Fix:{RESET}      {f.remediation[:100]}{'...' if len(f.remediation)>100 else ''}")
        print()

    print(f"{'─'*70}")
    print(f"  {BOLD}Summary{RESET}")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if counts[sev]:
            color = sev.color()
            print(f"    {color}{sev.value:8}{RESET}  {counts[sev]}")
    print(f"{'─'*70}\n")


def format_json(findings: list[Finding], path: str, elapsed: float) -> str:
    return json.dumps({
        "scan_metadata": {
            "target": path,
            "timestamp": datetime.now().isoformat(),
            "elapsed_seconds": round(elapsed, 3),
            "total_findings": len(findings),
            "summary": {s.value: sum(1 for f in findings if f.severity == s)
                        for s in Severity}
        },
        "findings": [f.to_dict() for f in findings]
    }, indent=2)


def format_markdown(findings: list[Finding], path: str, elapsed: float) -> str:
    lines = [
        "# AppSec Code Review Report",
        f"\n**Target:** `{path}`  ",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Total Findings:** {len(findings)}  \n",
        "## Summary\n",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = sum(1 for f in findings if f.severity == sev)
        if count:
            lines.append(f"| {sev.value} | {count} |")

    lines.append("\n## Findings\n")
    for i, f in enumerate(findings, 1):
        lines += [
            f"### Finding {i}: {f.title}",
            f"\n| Field | Value |",
            f"|-------|-------|",
            f"| **Rule ID** | `{f.rule_id}` |",
            f"| **Severity** | {f.severity.value} |",
            f"| **OWASP** | {f.owasp.value} |",
            f"| **CWE** | [{f.cwe}](https://cwe.mitre.org/data/definitions/{f.cwe.replace('CWE-','')}.html) |",
            f"| **File** | `{f.file}:{f.line}` |",
            f"| **Confidence** | {f.confidence} |",
            f"\n**Code Snippet:**",
            f"```{f.language}",
            f"{f.code_snippet}",
            "```",
            f"\n**Description:** {f.description}",
            f"\n**Remediation:** {f.remediation}\n",
            "---\n"
        ]
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="AppSec Code Review Toolkit — White-box vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --path ./myapp --lang python
  %(prog)s --path ./myapp --lang java --severity HIGH
  %(prog)s --path ./myapp --lang all --format json --output report.json
  %(prog)s --path ./myapp --lang all --format markdown --output report.md
        """
    )
    parser.add_argument("--path",     required=True, help="File or directory to scan")
    parser.add_argument("--lang",     default="all",
                        choices=["python", "java", "all"],
                        help="Language to scan (default: all)")
    parser.add_argument("--severity", default="LOW",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to report (default: LOW)")
    parser.add_argument("--format",   default="console",
                        choices=["console", "json", "markdown"],
                        help="Output format (default: console)")
    parser.add_argument("--output",   help="Write output to file")
    parser.add_argument("--exclude",  nargs="*", default=[],
                        help="Directory names to exclude from scan")

    args = parser.parse_args()

    import time
    start = time.time()

    scanner = Scanner(
        language=args.lang,
        min_severity=Severity(args.severity),
        exclude_dirs=args.exclude or []
    )

    findings = scanner.scan_path(args.path)
    elapsed = time.time() - start

    if args.format == "console":
        format_console(findings, args.path, elapsed)
        output_text = None
    elif args.format == "json":
        output_text = format_json(findings, args.path, elapsed)
    elif args.format == "markdown":
        output_text = format_markdown(findings, args.path, elapsed)
    else:
        output_text = None

    if output_text:
        if args.output:
            Path(args.output).write_text(output_text)
            print(f"Report written to: {args.output}")
        else:
            print(output_text)

    # Exit code: 1 if critical/high findings exist (useful in CI pipelines)
    has_high = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()
