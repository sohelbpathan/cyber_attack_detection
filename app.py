import csv
import io
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta
from urllib.parse import unquote
from functools import wraps

from flask import (
    Flask, Response, abort, flash, redirect, render_template,
    request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=64 * 1024,  # 64 KB request limit
)
DB = os.environ.get("CYBER_DB", "cyber.db")


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        input_text TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        scanned_at TEXT NOT NULL,
        risk_score INTEGER NOT NULL DEFAULT 0,
        anomaly_score INTEGER NOT NULL DEFAULT 0,
        indicators TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'manual'
    );
    """)
    # Safe, additive migration for databases created by the original project.
    existing = {r["name"] for r in con.execute("PRAGMA table_info(scans)")}
    for name, definition in {
        "risk_score": "INTEGER NOT NULL DEFAULT 0",
        "anomaly_score": "INTEGER NOT NULL DEFAULT 0",
        "indicators": "TEXT NOT NULL DEFAULT ''",
        "source": "TEXT NOT NULL DEFAULT 'manual'",
    }.items():
        if name not in existing:
            con.execute(f"ALTER TABLE scans ADD COLUMN {name} {definition}")

    # Create the demo account only for a new installation. Change it before use.
    if not con.execute("SELECT 1 FROM users WHERE username = ?", ("admin",)).fetchone():
        con.execute(
            "INSERT INTO users(username, password) VALUES (?, ?)",
            ("admin", generate_password_hash(os.environ.get("CYBER_ADMIN_PASSWORD", "ChangeMe123!"))),
        )
    con.commit()
    con.close()


RULES = [
    {
        "name": "SQL Injection",
        "severity": "High",
        "weight": 35,
        "pattern": re.compile(
            r"""(?:\bunion\s+(?:all\s+)?select\b|\bselect\b.{0,80}\bfrom\b|"""
            r"""\bor\s+['"]?\w*['"]?\s*=\s*['"]?\w+|"""
            r"""(?:--|/\*|\*/)|\bdrop\s+table\b|\binsert\s+into\b|\bupdate\b.{0,60}\bset\b)""",
            re.I,
        ),
        "reason": "SQL syntax or a common injection expression was found.",
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "severity": "High",
        "weight": 30,
        "pattern": re.compile(
            r"""(?:<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=|"""
            r"""<\s*iframe\b|<\s*svg\b.{0,100}\bonload\s*=)""",
            re.I,
        ),
        "reason": "A script-capable HTML/JavaScript pattern was found.",
    },
    {
        "name": "Path Traversal",
        "severity": "Medium",
        "weight": 25,
        "pattern": re.compile(r"""(?:\.\.[/\\]|%2e%2e(?:%2f|%5c)|/etc/passwd|\\windows\\win\.ini)""", re.I),
        "reason": "A parent-directory traversal sequence or sensitive path was found.",
    },
    {
        "name": "Command Injection",
        "severity": "Critical",
        "weight": 40,
        "pattern": re.compile(
            r"""(?:;\s*(?:cat|ls|rm|wget|curl|whoami|ping)\b|"""
            r"""\|\s*(?:cat|ls|rm|whoami)\b|`[^`]{1,100}`|\$\([^)]{1,100}\))""",
            re.I,
        ),
        "reason": "A shell command separator or command-substitution pattern was found.",
    },
    {
        "name": "Suspicious Login Activity",
        "severity": "Medium",
        "weight": 20,
        "pattern": re.compile(r"""(?:failed\s+login|multiple\s+login|brute\s*force|invalid\s+password|authentication\s+failure)""", re.I),
        "reason": "Text associated with failed or repeated authentication was found.",
    },
    {
        "name": "Server-Side Request Forgery (SSRF) Indicator",
        "severity": "High",
        "weight": 25,
        "pattern": re.compile(r"""(?:https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])|169\.254\.169\.254)""", re.I),
        "reason": "A URL points to a loopback or cloud metadata address; context is required.",
    },
    {
        "name": "Suspicious File/Script Upload",
        "severity": "Medium",
        "weight": 20,
        "pattern": re.compile(r"""(?:\.(?:php[0-9]?|jsp|aspx|sh|exe)\b.{0,40}(?:upload|multipart)|multipart.{0,100}\.(?:php|jsp|aspx|sh|exe)\b)""", re.I),
        "reason": "A potentially executable upload pattern was found.",
    },
    {
        "name": "Credential / Secret Exposure Indicator",
        "severity": "Medium",
        "weight": 15,
        "pattern": re.compile(r"""(?:\bpassword\s*=\s*['"][^'"]{4,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|api[_-]?key\s*[:=]\s*\S{8,})""", re.I),
        "reason": "The input may contain a hard-coded secret or credential.",
    },
]


def analyze_text(raw_text):
    """Analyze a manually supplied URL/request/log. This is heuristic, not a WAF."""
    decoded = raw_text
    # Decode up to two times to expose common URL-encoded indicators.
    for _ in range(2):
        newer = unquote(decoded)
        if newer == decoded:
            break
        decoded = newer

    matches = []
    score = 0
    for rule in RULES:
        if rule["pattern"].search(raw_text) or rule["pattern"].search(decoded):
            matches.append(rule)
            score += rule["weight"]

    # Heuristic anomaly signals for manual text only; not statistical/ML anomaly detection.
    anomaly_reasons = []
    anomaly_score = 0
    if len(raw_text) > 4000:
        anomaly_score += 25
        anomaly_reasons.append("Unusually long input")
    elif len(raw_text) > 1500:
        anomaly_score += 15
        anomaly_reasons.append("Long input")
    if raw_text.count("%") >= 8:
        anomaly_score += 15
        anomaly_reasons.append("High URL-encoding density")
    if len(re.findall(r"[;|`$]", decoded)) >= 5:
        anomaly_score += 20
        anomaly_reasons.append("Many command-like separators")
    if len(re.findall(r"<\s*[a-z!/]", decoded, re.I)) >= 5:
        anomaly_score += 15
        anomaly_reasons.append("Many HTML-like tags")
    if len(matches) >= 2:
        anomaly_score += 20
        anomaly_reasons.append("Multiple attack indicators")
    anomaly_score = min(100, anomaly_score)
    risk_score = min(100, score)

    if matches:
        # Display all matched types; severity follows the highest-priority matched rule.
        order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        severity = max((m["severity"] for m in matches), key=lambda x: order[x])
        attack_type = ", ".join(m["name"] for m in matches)
        reasons = [m["reason"] for m in matches]
    else:
        severity = "Low"
        attack_type = "No known attack pattern"
        reasons = ["No configured rule matched. This does not prove the input is safe."]

    if anomaly_reasons:
        reasons.extend("Anomaly heuristic: " + x for x in anomaly_reasons)

    return {
        "attack_type": attack_type,
        "severity": severity,
        "risk_score": risk_score,
        "anomaly_score": anomaly_score,
        "indicators": reasons,
        "matched_rules": [m["name"] for m in matches],
        "is_suspicious": bool(matches) or anomaly_score >= 40,
    }


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("_csrf_token", "")
        expected = session.get("_csrf_token", "")
        if not sent or not expected or not secrets.compare_digest(sent, expected):
            abort(400, description="Invalid or missing CSRF token. Refresh the page and try again.")


@app.context_processor
def inject_csrf():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["_csrf_token"]}


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        con = db()
        user = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        con.close()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user"] = user["username"]
            session["_csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    result = None
    if request.method == "POST":
        text = request.form.get("payload", "").strip()
        if not text:
            flash("Enter a URL, request, log, or text to scan.", "error")
        elif len(text) > 12000:
            flash("Input is too long. Limit scans to 12,000 characters.", "error")
        else:
            analysis = analyze_text(text)
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            con = db()
            con.execute(
                """INSERT INTO scans
                (input_text, attack_type, severity, scanned_at, risk_score, anomaly_score, indicators, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (text, analysis["attack_type"], analysis["severity"], now,
                 analysis["risk_score"], analysis["anomaly_score"],
                 " | ".join(analysis["indicators"]), "manual"),
            )
            con.commit()
            scan_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
            con.close()
            analysis["id"] = scan_id
            analysis["scanned_at"] = now
            analysis["input_text"] = text
            result = analysis

    con = db()
    scans = con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 25").fetchall()
    total = con.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
    suspicious = con.execute(
        "SELECT COUNT(*) AS n FROM scans WHERE severity != 'Low' OR anomaly_score >= 40"
    ).fetchone()["n"]
    critical = con.execute("SELECT COUNT(*) AS n FROM scans WHERE severity = 'Critical'").fetchone()["n"]
    avg_risk = con.execute("SELECT COALESCE(ROUND(AVG(risk_score)), 0) AS n FROM scans").fetchone()["n"]
    by_attack = con.execute(
        """SELECT attack_type, COUNT(*) AS count FROM scans
           GROUP BY attack_type ORDER BY count DESC LIMIT 8"""
    ).fetchall()
    by_severity = con.execute(
        """SELECT severity, COUNT(*) AS count FROM scans
           GROUP BY severity"""
    ).fetchall()
    daily_rows = con.execute(
        """SELECT substr(scanned_at, 1, 10) AS day, COUNT(*) AS total,
                  SUM(CASE WHEN severity != 'Low' OR anomaly_score >= 40 THEN 1 ELSE 0 END) AS suspicious
           FROM scans GROUP BY day ORDER BY day DESC LIMIT 7"""
    ).fetchall()
    con.close()

    # Chart.js receives only values from database aggregates, not raw user input.
    daily = [dict(r) for r in reversed(daily_rows)]
    attack_labels = [r["attack_type"] for r in by_attack]
    attack_values = [r["count"] for r in by_attack]
    severity_map = {r["severity"]: r["count"] for r in by_severity}
    severity_labels = ["Low", "Medium", "High", "Critical"]
    severity_values = [severity_map.get(s, 0) for s in severity_labels]

    return render_template(
        "dashboard.html", result=result, scans=scans, total=total,
        suspicious=suspicious, critical=critical, avg_risk=avg_risk,
        attack_labels=attack_labels, attack_values=attack_values,
        severity_labels=severity_labels, severity_values=severity_values,
        daily=daily,
    )


@app.route("/export.csv")
@login_required
def export_csv():
    con = db()
    rows = con.execute(
        """SELECT id, input_text, attack_type, severity, risk_score,
                  anomaly_score, indicators, source, scanned_at
           FROM scans ORDER BY id DESC"""
    ).fetchall()
    con.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Input", "Detection", "Severity", "Risk Score",
                     "Heuristic Anomaly Score", "Reasons", "Source", "Scanned At"])
    for row in rows:
        writer.writerow([row[k] for k in row.keys()])
    return Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=cyber_scan_report.csv"},
    )


@app.route("/delete/<int:scan_id>", methods=["POST"])
@login_required
def delete_scan(scan_id):
    con = db()
    con.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    con.commit()
    con.close()
    flash("Scan record deleted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "Bad request")), 400


if __name__ == "__main__":
    init_db()
    # debug mode is intentionally off by default.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
