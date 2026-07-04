# WebGuard Scanner 🛡️

WebGuard Scanner is an automated, enterprise-grade website vulnerability assessment platform built with Python, FastAPI, and Bootstrap 5. It performs parallel, multi-threaded security audits across several key attack surfaces to identify misconfigurations, weak headers, SSL flaws, and sensitive file exposures in seconds.

## 🚀 Key Features

* **SSL/TLS Security Analysis**: Deep inspection of certificates, cipher suites, supported TLS versions, and expiry tracking.
* **HTTP Security Headers Audit**: Validates over 30+ headers including CSP, HSTS, CORS, and XSS protection.
* **Cookie Security Inspector**: Checks flags (`HttpOnly`, `Secure`, `SameSite`) to prevent session hijacking.
* **Sensitive File Exposure Detection**: Discovers misplaced files (e.g., `.env`, `.git/config`, backup archives, `.htaccess`).
* **Interactive Dashboard**: Modern glassmorphism UI supporting light and dark modes, live scan progress terminal logs, and system health status tracking.
* **PDF Reports**: Generates professional, executive-ready PDF report sheets detailing severity breakdown and remediation guidance.

## 🛠️ Technology Stack

* **Backend**: Python 3, FastAPI, SQLite
* **Frontend**: HTML5, Vanilla CSS (Design Tokens, Custom Theme Variables), Bootstrap 5, Chart.js
* **PDF Engine**: ReportLab (HTML-escaped structural formatting)
