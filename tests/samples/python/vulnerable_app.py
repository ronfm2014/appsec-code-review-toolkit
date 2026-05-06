"""
Intentionally Vulnerable Python Application — Scanner Test Target
=================================================================
This file contains deliberate vulnerabilities to validate scanner detection.
DO NOT deploy this code. FOR TESTING ONLY.
"""

import hashlib
import subprocess
import pickle
import sqlite3
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── Hardcoded Secrets (PY-A02-001) ──────────────────────────────────────────
DB_PASSWORD   = "SuperSecret123!"           # VULN: hardcoded password
API_KEY       = "sk-prod-abc123xyz789"      # VULN: hardcoded API key
SECRET_KEY    = "my-flask-secret"           # VULN: hardcoded flask secret
app.config["SECRET_KEY"] = SECRET_KEY

# ── Broken Crypto (PY-A02-002) ──────────────────────────────────────────────
def hash_password_insecure(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()   # VULN: MD5

def verify_token_insecure(token: str) -> str:
    return hashlib.sha1(token.encode()).hexdigest()     # VULN: SHA-1


# ── SQL Injection (PY-A03-001) ───────────────────────────────────────────────
@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur  = conn.cursor()

    # VULN: f-string SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cur.execute(query)

    # VULN: % format SQL injection
    query2 = "SELECT * FROM orders WHERE user_id = %s" % user_id
    cur.execute(query2)

    # VULN: .format() SQL injection
    query3 = "SELECT email FROM users WHERE name = '{}'".format(user_id)
    cur.execute(query3)

    return jsonify(cur.fetchall())


# ── Command Injection (PY-A03-002) ──────────────────────────────────────────
@app.route("/ping")
def ping_host():
    host = request.args.get("host")

    # VULN: shell=True with variable
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()


# ── Insecure Deserialization (PY-A08-001) ────────────────────────────────────
@app.route("/load", methods=["POST"])
def load_data():
    data = request.get_data()

    # VULN: pickle.loads on untrusted data
    obj = pickle.loads(data)

    # VULN: yaml.load without SafeLoader
    config = yaml.load(data, Loader=yaml.FullLoader)

    return jsonify({"status": "loaded"})


# ── Missing Authentication (PY-A01-001) ──────────────────────────────────────
@app.route("/admin/users", methods=["GET"])        # VULN: no auth decorator
def admin_list_users():
    return jsonify({"users": ["admin", "user1", "user2"]})


@app.route("/admin/delete", methods=["DELETE"])    # VULN: no auth decorator
def admin_delete_user():
    user_id = request.args.get("id")
    return jsonify({"deleted": user_id})


# ── Debug Mode (CROSS-A05-001) ───────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")   # VULN: debug=True in production code


# ── Logging Sensitive Data (CROSS-A09-001) ───────────────────────────────────
import logging
logger = logging.getLogger(__name__)

def authenticate(username, password):
    logger.info(f"Login attempt: user={username} password={password}")  # VULN: logs password
    return username == "admin"


# ── eval() usage (CROSS-A02-003) ─────────────────────────────────────────────
@app.route("/calculate")
def calculate():
    expression = request.args.get("expr")
    result = eval(expression)   # VULN: eval of user input
    return jsonify({"result": result})


# ── SSL Verification Disabled (CROSS-A05-002) ────────────────────────────────
import requests as req

def fetch_external(url):
    response = req.get(url, verify=False)   # VULN: no SSL verification
    return response.json()
