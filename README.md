# Cyber Attack Detection — upgraded educational Flask project

## Features
- Flask login and session handling, hashed passwords, CSRF tokens on POST forms
- Existing SQLite database is retained; new columns are added with an additive migration
- Multi-rule text inspection for SQL injection, XSS, path traversal, command injection, suspicious login activity, SSRF indicators, risky upload patterns, and possible exposed secrets
- Explainable rule risk score (0–100) and separate **heuristic** anomaly score (0–100)
- Dashboard cards, attack-category bar chart, severity doughnut chart, daily activity line chart
- Search/filter recent scan history, POST-only deletion, CSV export
- Responsive dark UI

## Run on Windows (PowerShell)
1. Extract this ZIP.
2. Open a terminal in the extracted project directory.
3. Create and activate a virtual environment:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   If PowerShell blocks activation, run `.\.venv\Scripts\python.exe -m pip install -r requirements.txt` and use that interpreter directly.
4. Install dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```
5. (Recommended for a new database) Set a custom secret and admin password **before first run**:
   ```powershell
   $env:FLASK_SECRET_KEY = "replace-with-a-long-random-secret"
   $env:CYBER_ADMIN_PASSWORD = "replace-with-a-strong-password"
   ```
   For an existing `cyber.db`, the existing admin password is not changed by this setting. Use the existing password or reset it separately.
6. Start:
   ```powershell
   python app.py
   ```
7. Open `http://127.0.0.1:5000/` in Chrome.

## Login
For a brand-new database only, the initial account is:
- Username: `admin`
- Password: `ChangeMe123!`

Set `CYBER_ADMIN_PASSWORD` before the first run to replace the initial demo password. This is a local educational demo; do not expose it publicly with demo credentials.

## Folder structure
```text
cyber_attack_detection_upgraded/
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   └── error.html
└── static/
    └── style.css
```

## Detection scope and limitations
- This app analyzes only the URL/request/log text that a user submits in the form. It does not execute the submitted input.
- The rules and scores are educational heuristics. They can produce false positives and false negatives; a "Low" result is not proof of safety.
- The anomaly score uses simple text characteristics (length, encoding density, separators, HTML-like tags, and multiple matched rules). It is **not** a trained ML model and is not a statistical baseline of network behavior.
- Chart.js is loaded from a CDN, so the graphs require internet access in the browser. The scan and storage backend work locally without Chart.js.
- This project does not capture live packets, monitor server traffic, block requests, or provide a production WAF/SIEM. Live network monitoring would require an authorized telemetry source and a separate ingestion pipeline.
- The built-in user table is a minimal demo login. For a public deployment, add user management, password reset, rate limiting, audit logging, a persistent secret key, HTTPS, backups, and security review.
- Use only systems and sample data you are authorized to test.
