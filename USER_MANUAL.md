# WebGuard Scanner — User Manual & Reference 🛡️

WebGuard Scanner is an automated website security auditing platform designed to run security assessments on target web hosts. It scans for configuration errors, missing HTTP headers, insecure cookies, exposed sensitive files, directory listings, and active Reflected XSS or SQL Injection syntax vulnerabilities.

---

## 🚀 Getting Started

### 1. Prerequisites
Ensure you have Python 3.8+ installed. Check your dependencies in [requirements.txt](file:///c:/WebGuardScanner/requirements.txt):
*   `fastapi`
*   `uvicorn`
*   `requests`
*   `reportlab` (for PDF reports)

To install dependencies:
```bash
pip install -r requirements.txt
```

### 2. Configuration (`.env`)
You can configure the application using the [.env](file:///c:/WebGuardScanner/.env) file located in the root directory:
*   `ALLOW_PRIVATE_IPS`: Set to `True` to allow scanning local target addresses (e.g. `127.0.0.1`, `localhost`).
*   `DB_PATH`: SQLite database file path (defaults to `webguard.db`).
*   `MAX_CONCURRENT_SCANS`: Restricts the number of parallel scans in the backend threadpool.
*   `REQUEST_TIMEOUT`: Timeout for target connection requests in seconds.

---

## 🛠️ Testing Locally (Mock Target Server)

To test the scanner without auditing external targets, a local mock server with built-in vulnerabilities is provided in [run_test_server.py](file:///c:/WebGuardScanner/run_test_server.py).

1.  **Launch the Mock Vulnerable Server**:
    ```bash
    python run_test_server.py
    ```
    This spins up a target at `http://127.0.0.1:9999` exposing an insecure `.env` file, directory indexes on `/uploads/`, and weak cookie headers.

2.  **Launch the Scanner Application**:
    ```bash
    uvicorn main:app --reload
    ```
    Open your browser to `http://localhost:8000/dashboard`.

3.  **Perform a Scan**:
    *   Set `ALLOW_PRIVATE_IPS=True` in `.env`.
    *   Enter `http://127.0.0.1:9999` in the Dashboard target input.
    *   Select **Full Audit** and click **Run Scan**.

---

## 📊 Scanning Profiles

The tool supports four audit scopes:
1.  **Full Audit**: Executes all validation, headers, SSL, cookie, robots.txt, backup exposure, and active probing scans.
2.  **Fast Scan**: Bypasses the directory and backup checks to deliver results in seconds.
3.  **SSL Only**: Exclusively audits SSL/TLS certificate chains, protocols, and cipher suites.
4.  **Headers Only**: Checks HTTP response headers and cookie security attributes.

---

## 🛡️ Audited Vulnerabilities

*   **SSRF Protection**: Prevents scanning local loopback and private subnets (unless bypassed for testing).
*   **Security Headers**: Checks HSTS, CSP (including unsafe-inline/eval), X-Frame-Options, Referrer-Policy, and CORS wildcard credentials.
*   **SSL/TLS**: Audits validity periods, self-signed signatures, weak ciphers, and deprecated versions (TLS 1.0/1.1).
*   **Cookie Security**: Checks for HttpOnly, Secure, SameSite, and sensitive data leakage in cookie values.
*   **Active Probing**: Non-intrusively detects Reflected XSS and SQL Injection errors on query parameters.
*   **Sensitive Exposures**: Checks for exposed `.env` files, `.git` configs, `docker-compose.yml`, and backup file arrays (`.zip`, `.sql`).

---

## 📑 Generating Reports

*   **PDF Report**: Click the "PDF Report" button on the dashboard to download an executive-level ReportLab PDF including severity graphs and remediation guidelines.
*   **Raw JSON**: Export findings in standard JSON format using the "Raw JSON" button.
