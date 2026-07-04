"""
WebGuard Sensitive Exposure Detection Module
=============================================
Implements checks for:
- Sensitive File Discovery (.env, .git/config, swagger.json etc.)
- Directory Listing Detection
- Backup File Detection (.bak, .zip, .sql etc.)
Includes soft-404 detection and content validation to reduce false positives.
"""

import re
import requests
from urllib.parse import urlparse, urlunparse

# ---------------------------------------------------------------------------
# Constants & Lists
# ---------------------------------------------------------------------------

SENSITIVE_FILES_DB = [
    {
        "path": "/.env",
        "check": "Exposed .env File",
        "severity": "High",
        "status": "FAIL",
        "description": "An exposed .env file was discovered. This file typically contains sensitive configuration details like database credentials, API keys, and environment secrets.",
        "recommendation": "Remove the .env file from the web-accessible directory. Move configuration variables to the host environment variables, or restrict access to hidden files in the web server config.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body", r"<div"],
            "patterns": [r"^[A-Z0-9_]+\s*=", r"DB_", r"API_", r"KEY", r"SECRET", r"PASSWORD"]
        }
    },
    {
        "path": "/.env.local",
        "check": "Exposed .env.local File",
        "severity": "High",
        "status": "FAIL",
        "description": "An exposed .env.local file was discovered containing local development environment secrets.",
        "recommendation": "Remove it from the web-accessible directory.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body", r"<div"],
            "patterns": [r"^[A-Z0-9_]+\s*=", r"DB_", r"API_", r"KEY", r"SECRET"]
        }
    },
    {
        "path": "/.env.production",
        "check": "Exposed .env.production File",
        "severity": "High",
        "status": "FAIL",
        "description": "An exposed production .env file was discovered, presenting a critical risk of data leak.",
        "recommendation": "Remove the production environment file from the web root immediately.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body", r"<div"],
            "patterns": [r"^[A-Z0-9_]+\s*=", r"DB_", r"API_", r"KEY", r"SECRET"]
        }
    },
    {
        "path": "/.env.development",
        "check": "Exposed .env.development File",
        "severity": "High",
        "status": "FAIL",
        "description": "An exposed development configuration file was found.",
        "recommendation": "Delete the file or move it out of the public folder.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body", r"<div"],
            "patterns": [r"^[A-Z0-9_]+\s*=", r"DB_", r"API_", r"KEY", r"SECRET"]
        }
    },
    {
        "path": "/.env.staging",
        "check": "Exposed .env.staging File",
        "severity": "High",
        "status": "FAIL",
        "description": "An exposed staging configuration file was found.",
        "recommendation": "Remove the file from the web directory.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body", r"<div"],
            "patterns": [r"^[A-Z0-9_]+\s*=", r"DB_", r"API_", r"KEY", r"SECRET"]
        }
    },
    {
        "path": "/.git/config",
        "check": "Exposed Git Repository Configuration",
        "severity": "High",
        "status": "FAIL",
        "description": "The Git repository configuration file (.git/config) is accessible. This discloses source control metadata, repository URLs, and branch details.",
        "recommendation": "Restrict access to the .git directory in your web server configuration (e.g., Apache, Nginx, or IIS), or delete version control files from the production web root.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"\[core\]", r"\[remote", r"repositoryformatversion"]
        }
    },
    {
        "path": "/.git/HEAD",
        "check": "Exposed Git Repository Metadata",
        "severity": "High",
        "status": "FAIL",
        "description": "The Git metadata file (.git/HEAD) is publicly accessible, indicating that the entire .git repository folder may be exposed.",
        "recommendation": "Disable public access to the .git directory or remove it completely from the web server root.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"ref:\s*refs/", r"^[0-9a-f]{40}$"]
        }
    },
    {
        "path": "/.git/logs/HEAD",
        "check": "Exposed Git Commit Logs",
        "severity": "Medium",
        "status": "WARN",
        "description": "Git commit logs are publicly readable, leaking developer email addresses, usernames, and branch histories.",
        "recommendation": "Restrict access to all hidden .git folders.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"00000000000000000", r"commit\s*:", r"clone\s*:"]
        }
    },
    {
        "path": "/docker-compose.yml",
        "check": "Exposed Docker Compose Configuration",
        "severity": "High",
        "status": "FAIL",
        "description": "A docker-compose configuration file was found. This discloses the structure of service containers, link names, volume pathways, and potentially hardcoded environment secrets.",
        "recommendation": "Remove docker-compose configurations from the public folder.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"version\s*:", r"services\s*:", r"image\s*:", r"environment\s*:"]
        }
    },
    {
        "path": "/Dockerfile",
        "check": "Exposed Dockerfile",
        "severity": "Medium",
        "status": "WARN",
        "description": "An exposed Dockerfile was found, leaking software build setups, internal directory paths, and commands.",
        "recommendation": "Remove the Dockerfile from the web-accessible directory.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"FROM\s+[a-zA-Z0-9]", r"RUN\s+", r"EXPOSE\s+", r"WORKDIR\s+"]
        }
    },
    {
        "path": "/.npmrc",
        "check": "Exposed npm Configuration",
        "severity": "High",
        "status": "FAIL",
        "description": "An exposed .npmrc configuration file was discovered. This file may contain access tokens for private npm registries, exposing proprietary libraries.",
        "recommendation": "Remove .npmrc from public directories.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"registry\s*=", r"_authToken\s*=", r"always-auth\s*="]
        }
    },
    {
        "path": "/wp-config.php",
        "check": "Exposed WordPress Configuration Source",
        "severity": "High",
        "status": "FAIL",
        "description": "WordPress database configuration (wp-config.php) is exposed. This reveals MySQL usernames, passwords, database names, and authorization salt keys.",
        "recommendation": "Move wp-config.php one directory above the web root, or restrict read access to it.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"DB_NAME", r"DB_USER", r"DB_PASSWORD", r"SECURE_AUTH_KEY", r"wp-settings\.php"]
        }
    },
    {
        "path": "/configuration.php",
        "check": "Exposed Joomla Configuration Source",
        "severity": "High",
        "status": "FAIL",
        "description": "Joomla configuration settings (configuration.php) are exposed, leaking site-level secrets and passwords.",
        "recommendation": "Restrict read access to the Joomla configuration script.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"class\s+JConfig", r"public\s+\$host", r"public\s+\$password"]
        }
    },
    {
        "path": "/swagger.json",
        "check": "Exposed Swagger/OpenAPI API Schema",
        "severity": "Medium",
        "status": "WARN",
        "description": "An exposed Swagger JSON API schema was detected. This reveals API endpoints, parameter requirements, and schema structure, assisting attackers in API mapping.",
        "recommendation": "Restrict access to API documentation in production environments or place it behind authentication.",
        "heuristics": {
            "patterns": [r'"swagger"\s*:', r'"openapi"\s*:', r'"paths"\s*:', r'"info"\s*:'],
            "is_json": True
        }
    },
    {
        "path": "/openapi.json",
        "check": "Exposed OpenAPI API Schema",
        "severity": "Medium",
        "status": "WARN",
        "description": "An exposed OpenAPI JSON schema was detected. This reveals backend API architecture and endpoints.",
        "recommendation": "Restrict access to the OpenAPI schema behind authentication or disable it in production.",
        "heuristics": {
            "patterns": [r'"openapi"\s*:', r'"paths"\s*:', r'"info"\s*:'],
            "is_json": True
        }
    },
    {
        "path": "/swagger.yaml",
        "check": "Exposed Swagger/OpenAPI API Schema (YAML)",
        "severity": "Medium",
        "status": "WARN",
        "description": "An exposed Swagger YAML schema was detected.",
        "recommendation": "Ensure API schemas are not publicly accessible in production.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"swagger\s*:", r"openapi\s*:", r"paths\s*:", r"info\s*:"]
        }
    },
    {
        "path": "/openapi.yaml",
        "check": "Exposed OpenAPI API Schema (YAML)",
        "severity": "Medium",
        "status": "WARN",
        "description": "An exposed OpenAPI YAML schema was detected.",
        "recommendation": "Protect the schema file behind access control.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"openapi\s*:", r"paths\s*:", r"info\s*:"]
        }
    },
    {
        "path": "/composer.json",
        "check": "Exposed PHP Dependency Configuration",
        "severity": "Low",
        "status": "WARN",
        "description": "The PHP dependency configuration (composer.json) is accessible. This discloses installed packages and version numbers, helping attackers identify outdated libraries.",
        "recommendation": "Ensure composer.json is not served in the web root or disable public access to it.",
        "heuristics": {
            "patterns": [r'"require"\s*:', r'"require-dev"\s*:', r'"name"\s*:'],
            "is_json": True
        }
    },
    {
        "path": "/package.json",
        "check": "Exposed Node.js Dependency Configuration",
        "severity": "Low",
        "status": "WARN",
        "description": "The Node.js dependency configuration (package.json) is accessible. This discloses client-side or server-side libraries and versions.",
        "recommendation": "Restrict access to package.json in your web server configuration.",
        "heuristics": {
            "patterns": [r'"dependencies"\s*:', r'"devDependencies"\s*:', r'"name"\s*:'],
            "is_json": True
        }
    },
    {
        "path": "/.htaccess",
        "check": "Exposed Apache .htaccess Configuration",
        "severity": "Medium",
        "status": "WARN",
        "description": "Apache's distributed configuration file (.htaccess) is readable. This reveals rewrite rules, directory permissions, and server controls.",
        "recommendation": "Ensure AllowOverride is configured correctly in Apache global configuration, or restrict file access.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"RewriteEngine", r"RewriteRule", r"AuthType", r"Require", r"FilesMatch"]
        }
    },
    {
        "path": "/.htpasswd",
        "check": "Exposed Apache Password File (.htpasswd)",
        "severity": "High",
        "status": "FAIL",
        "description": "An exposed Apache basic authentication password file (.htpasswd) was found. This exposes usernames and password hashes to offline brute-forcing.",
        "recommendation": "Move the .htpasswd file outside the web document root and restrict server permissions.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"^[a-zA-Z0-9_-]+:\$[0-9a-zA-Z./\$]+", r"^[a-zA-Z0-9_-]+:[A-Za-z0-9./]{13}"]
        }
    },
    {
        "path": "/web.config",
        "check": "Exposed IIS Web Configuration",
        "severity": "Medium",
        "status": "WARN",
        "description": "An IIS web.config file was discovered. This contains application configuration rules and database connections.",
        "recommendation": "Disable direct downloading of .config files in IIS configuration.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"<configuration>", r"<system\.webServer>", r"<rules>"]
        }
    },
    {
        "path": "/sftp-config.json",
        "check": "Exposed SFTP Configuration",
        "severity": "High",
        "status": "FAIL",
        "description": "An exposed sftp-config.json file (Sublime SFTP) was found, revealing connection credentials and credentials.",
        "recommendation": "Delete the file immediately from the server root.",
        "heuristics": {
            "patterns": [r'"type"\s*:\s*"sftp"', r'"host"\s*:', r'"user"\s*:', r'"password"\s*:'],
            "is_json": True
        }
    },
    {
        "path": "/.vscode/settings.json",
        "check": "Exposed VS Code Configuration",
        "severity": "Low",
        "status": "WARN",
        "description": "VS Code workspace configurations are readable.",
        "recommendation": "Block access to the .vscode directory.",
        "heuristics": {
            "patterns": [r"git\.", r"python\.", r"editor\."],
            "is_json": True
        }
    }
]

DIRECTORY_LISTING_PATHS = [
    "/",
    "/uploads/",
    "/backups/",
    "/backup/",
    "/images/",
    "/assets/",
    "/static/",
    "/css/",
    "/js/",
    "/files/",
    "/documents/",
    "/media/",
    "/downloads/",
    "/database/",
    "/db/",
    "/logs/",
    "/log/",
    "/private/",
    "/admin/",
    "/src/",
    "/app/"
]

DIRECTORY_SIGNATURES = [
    r"<title>\s*Index of\s+/.*</title>",
    r"<h1>\s*Index of\s+/.*</h1>",
    r"Parent Directory",
    r"alt=\"\[DIR\]\"",
    r"Directory Listing For",
    r"<a href=\"\?C=N;O=D\">Name</a>",
    r"Last modified</a>",
    r"Size</a>",
    r"Description</a>"
]

BACKUP_FILES_DB = [
    # Database Dumps / Archives
    {
        "path": "/backup.sql",
        "check": "Exposed Database Backup (backup.sql)",
        "severity": "High",
        "status": "FAIL",
        "description": "A database backup file (backup.sql) is accessible. This discloses structure and content of database tables, which may include user data or admin records.",
        "recommendation": "Remove backup files from the web root directory immediately.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"CREATE TABLE", r"INSERT INTO", r"DROP TABLE", r"-- Host:", r"-- Database:"]
        }
    },
    {
        "path": "/db.sql",
        "check": "Exposed Database Backup (db.sql)",
        "severity": "High",
        "status": "FAIL",
        "description": "A database backup file (db.sql) is accessible. This discloses table schemas and data records.",
        "recommendation": "Remove backup files from the web root directory immediately.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"CREATE TABLE", r"INSERT INTO", r"DROP TABLE", r"-- Host:", r"-- Database:"]
        }
    },
    {
        "path": "/dump.sql",
        "check": "Exposed Database Backup (dump.sql)",
        "severity": "High",
        "status": "FAIL",
        "description": "A database backup file (dump.sql) is accessible. This discloses schemas and database records.",
        "recommendation": "Remove backup files from the web root directory immediately.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"CREATE TABLE", r"INSERT INTO", r"DROP TABLE", r"-- Host:", r"-- Database:"]
        }
    },
    {
        "path": "/schema.sql",
        "check": "Exposed Database Schema Backup (schema.sql)",
        "severity": "High",
        "status": "FAIL",
        "description": "A database schema file (schema.sql) is accessible.",
        "recommendation": "Remove backup files from the web root.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"CREATE TABLE", r"INSERT INTO", r"DROP TABLE", r"-- Host:", r"-- Database:"]
        }
    },
    {
        "path": "/mysql.sql",
        "check": "Exposed Database Backup (mysql.sql)",
        "severity": "High",
        "status": "FAIL",
        "description": "MySQL database backup file is exposed.",
        "recommendation": "Remove backup files from the web root.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"CREATE TABLE", r"INSERT INTO", r"DROP TABLE", r"-- Host:", r"-- Database:"]
        }
    },
    {
        "path": "/database.sql",
        "check": "Exposed Database Backup (database.sql)",
        "severity": "High",
        "status": "FAIL",
        "description": "A database backup file (database.sql) is accessible.",
        "recommendation": "Remove backup files from the web root.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"CREATE TABLE", r"INSERT INTO", r"DROP TABLE", r"-- Host:", r"-- Database:"]
        }
    },
    {
        "path": "/data.sql",
        "check": "Exposed Data Backup (data.sql)",
        "severity": "High",
        "status": "FAIL",
        "description": "An exposed SQL file containing database records (data.sql) was found.",
        "recommendation": "Remove backup files from the web root.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"CREATE TABLE", r"INSERT INTO", r"DROP TABLE", r"-- Host:", r"-- Database:"]
        }
    },
    # Common Source File Backups
    {
        "path": "/index.php.bak",
        "check": "Exposed PHP Script Backup (.bak)",
        "severity": "Medium",
        "status": "WARN",
        "description": "An exposed backup of index.php (index.php.bak) was found. Backup files are not parsed by the script interpreter, letting attackers download raw PHP source code.",
        "recommendation": "Delete the backup file, or configure your web server to deny requests to files ending in .bak.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"<\?php", r"echo", r"require", r"include", r"header"]
        }
    },
    {
        "path": "/config.php.bak",
        "check": "Exposed PHP Script Backup (.bak)",
        "severity": "High",
        "status": "FAIL",
        "description": "An exposed backup of config.php (config.php.bak) was found. This discloses PHP source code, often containing database logins, salt keys, and configuration secrets.",
        "recommendation": "Remove all config script backups from the web root immediately.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"<\?php", r"define\s*\(", r"DB_", r"password", r"conn"]
        }
    },
    {
        "path": "/config.php.old",
        "check": "Exposed PHP Script Backup (.old)",
        "severity": "High",
        "status": "FAIL",
        "description": "An exposed backup of config.php (config.php.old) was found. This discloses raw configuration secrets.",
        "recommendation": "Remove the script backup from the web root.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"<\?php", r"define\s*\(", r"DB_", r"password", r"conn"]
        }
    },
    {
        "path": "/index.html.bak",
        "check": "Exposed HTML File Backup (.bak)",
        "severity": "Low",
        "status": "WARN",
        "description": "An exposed backup of index.html (index.html.bak) was found. It may contain commented-out development code, comments, or older designs.",
        "recommendation": "Remove the backup file from the web directory.",
        "heuristics": {
            "patterns": [r"<html", r"<body", r"<!DOCTYPE html>"]
        }
    },
    {
        "path": "/main.py.bak",
        "check": "Exposed Python Script Backup (.bak)",
        "severity": "Medium",
        "status": "WARN",
        "description": "An exposed Python file backup (main.py.bak) was found.",
        "recommendation": "Remove python backup files from public web directories.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"import\s+", r"def\s+", r"class\s+"]
        }
    },
    {
        "path": "/app.py.bak",
        "check": "Exposed Python Script Backup (.bak)",
        "severity": "Medium",
        "status": "WARN",
        "description": "An exposed backup of app.py (app.py.bak) was found.",
        "recommendation": "Remove it from public folders.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"import\s+", r"def\s+", r"class\s+"]
        }
    },
    {
        "path": "/app.py.old",
        "check": "Exposed Python Script Backup (.old)",
        "severity": "Medium",
        "status": "WARN",
        "description": "An old version of app.py was found.",
        "recommendation": "Remove old python files.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"import\s+", r"def\s+", r"class\s+"]
        }
    },
    {
        "path": "/main.py.old",
        "check": "Exposed Python Script Backup (.old)",
        "severity": "Medium",
        "status": "WARN",
        "description": "An old version of main.py was found.",
        "recommendation": "Remove old python files.",
        "heuristics": {
            "not_patterns": [r"<html", r"<body"],
            "patterns": [r"import\s+", r"def\s+", r"class\s+"]
        }
    },
    # Site Archive Backups (Checked by headers, size or content)
    {
        "path": "/backup.zip",
        "check": "Exposed Site Archive Backup (backup.zip)",
        "severity": "High",
        "status": "FAIL",
        "description": "A compressed backup of the website files (backup.zip) was discovered. This allows downloading the source code or assets of the entire web application.",
        "recommendation": "Delete the zip archive or move it outside of the public web-accessible directory.",
        "heuristics": {
            "is_binary": True,
            "binary_signatures": [b"PK\x03\x04"]  # ZIP file magic bytes
        }
    },
    {
        "path": "/archive.zip",
        "check": "Exposed Site Archive Backup (archive.zip)",
        "severity": "High",
        "status": "FAIL",
        "description": "A compressed website archive (archive.zip) was discovered, potentially revealing the entire directory structure and source files.",
        "recommendation": "Delete or secure the zip archive.",
        "heuristics": {
            "is_binary": True,
            "binary_signatures": [b"PK\x03\x04"]
        }
    },
    {
        "path": "/project.zip",
        "check": "Exposed Site Archive Backup (project.zip)",
        "severity": "High",
        "status": "FAIL",
        "description": "A project backup archive (project.zip) was discovered, which may contain sensitive source files.",
        "recommendation": "Remove the zip archive from public directories.",
        "heuristics": {
            "is_binary": True,
            "binary_signatures": [b"PK\x03\x04"]
        }
    },
    {
        "path": "/site.zip",
        "check": "Exposed Site Archive Backup (site.zip)",
        "severity": "High",
        "status": "FAIL",
        "description": "A site archive (site.zip) was found.",
        "recommendation": "Remove it from public directories.",
        "heuristics": {
            "is_binary": True,
            "binary_signatures": [b"PK\x03\x04"]
        }
    },
    {
        "path": "/www.zip",
        "check": "Exposed Site Archive Backup (www.zip)",
        "severity": "High",
        "status": "FAIL",
        "description": "A compressed zip of www contents (www.zip) was found.",
        "recommendation": "Secure or delete the archive.",
        "heuristics": {
            "is_binary": True,
            "binary_signatures": [b"PK\x03\x04"]
        }
    },
    {
        "path": "/public.zip",
        "check": "Exposed Site Archive Backup (public.zip)",
        "severity": "High",
        "status": "FAIL",
        "description": "A public folder zip backup was found.",
        "recommendation": "Delete the archive file.",
        "heuristics": {
            "is_binary": True,
            "binary_signatures": [b"PK\x03\x04"]
        }
    },
    {
        "path": "/www.tar.gz",
        "check": "Exposed Site Tarball (www.tar.gz)",
        "severity": "High",
        "status": "FAIL",
        "description": "A compressed archive (www.tar.gz) was found.",
        "recommendation": "Remove it from public folders.",
        "heuristics": {
            "is_binary": True,
            "binary_signatures": [b"\x1f\x8b\x08"]  # Gzip magic bytes
        }
    },
    {
        "path": "/backup.tar.gz",
        "check": "Exposed Site Tarball (backup.tar.gz)",
        "severity": "High",
        "status": "FAIL",
        "description": "A compressed tarball backup (backup.tar.gz) was found.",
        "recommendation": "Remove it from the web directories.",
        "heuristics": {
            "is_binary": True,
            "binary_signatures": [b"\x1f\x8b\x08"]
        }
    },
    {
        "path": "/project.tar.gz",
        "check": "Exposed Site Tarball (project.tar.gz)",
        "severity": "High",
        "status": "FAIL",
        "description": "A compressed project tarball backup (project.tar.gz) was found.",
        "recommendation": "Secure or delete the archive.",
        "heuristics": {
            "is_binary": True,
            "binary_signatures": [b"\x1f\x8b\x08"]
        }
    },
    {
        "path": "/archive.tar.gz",
        "check": "Exposed Site Tarball (archive.tar.gz)",
        "severity": "High",
        "status": "FAIL",
        "description": "An exposed archive tarball (archive.tar.gz) was found.",
        "recommendation": "Remove it from public directories.",
        "heuristics": {
            "is_binary": True,
            "binary_signatures": [b"\x1f\x8b\x08"]
        }
    }
]

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _make_finding(check, status, severity, description, recommendation=""):
    finding = {
        "check": check,
        "status": status,
        "severity": severity,
        "description": description,
    }
    if recommendation:
        finding["recommendation"] = recommendation
    return finding

def _clean_base_url(url):
    """Normalize the URL by stripping trailing slash and parameters."""
    parsed = urlparse(url)
    clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))
    return clean_url

def _verify_content(response, heuristics):
    """Verify response content to determine if it is a real file or a soft-404."""
    if not heuristics:
        return True

    text = response.text
    content_bytes = response.content

    # 1. Binary checks
    if heuristics.get("is_binary", False):
        signatures = heuristics.get("binary_signatures", [])
        for sig in signatures:
            if content_bytes.startswith(sig):
                return True
        return False

    # 2. Negative patterns (soft-404 indicators like HTML structure in non-HTML requests)
    not_patterns = heuristics.get("not_patterns", [])
    for pattern in not_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return False

    # 3. Positive patterns (valid contents in the file)
    patterns = heuristics.get("patterns", [])
    if patterns:
        matched = False
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matched = True
                break
        if not matched:
            return False

    # 4. JSON Validation check
    if heuristics.get("is_json", False):
        try:
            import json
            json.loads(text)
            return True
        except ValueError:
            return False

    return True

# ---------------------------------------------------------------------------
# Scanning Functions
# ---------------------------------------------------------------------------

def check_sensitive_files(base_url, timeout=5):
    """
    Check for exposed sensitive configuration, metadata, and schema files.
    """
    findings = []
    headers = {"User-Agent": "WebGuardScanner/1.0"}
    clean_base = _clean_base_url(base_url)

    for item in SENSITIVE_FILES_DB:
        target_url = f"{clean_base}{item['path']}"
        try:
            response = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=False)
            
            # Exposure is confirmed if:
            # - Status code is 200 and matches content heuristics
            # - Status code is 403/401 (proves existence, but access denied is less severe - still worth warning)
            if response.status_code == 200:
                if _verify_content(response, item.get("heuristics")):
                    findings.append(_make_finding(
                        check=item["check"],
                        status=item["status"],
                        severity=item["severity"],
                        description=item["description"],
                        recommendation=item["recommendation"]
                    ))
            elif response.status_code in [403, 401]:
                # If access is denied, we can log a warning, but not a full fail
                findings.append(_make_finding(
                    check=f"Restricted {item['check']}",
                    status="WARN",
                    severity="Low",
                    description=f"The file path '{item['path']}' was detected but returned HTTP {response.status_code} (Access Denied). The file exists, but access is blocked.",
                    recommendation="No action needed, but verify that the access controls remain strictly in place."
                ))
        except requests.exceptions.RequestException:
            pass

    return findings

def check_directory_listing(base_url, timeout=5):
    """
    Check common directory paths for directory index/listing exposure.
    """
    findings = []
    headers = {"User-Agent": "WebGuardScanner/1.0"}
    clean_base = _clean_base_url(base_url)

    for path in DIRECTORY_LISTING_PATHS:
        # Avoid double slashes or missing slashes
        target_url = f"{clean_base}{path}" if path.startswith("/") else f"{clean_base}/{path}"
        try:
            response = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=True)
            
            if response.status_code == 200:
                html_content = response.text
                
                # Check for directory listing signatures
                for signature in DIRECTORY_SIGNATURES:
                    if re.search(signature, html_content, re.IGNORECASE):
                        findings.append(_make_finding(
                            check="Directory Listing Enabled",
                            status="FAIL",
                            severity="High",
                            description=f"Directory listing is enabled on path '{path}'. This exposes the directory's contents, allowing attackers to browse and download files.",
                            recommendation="Configure your web server to disable directory indexing (e.g., 'Options -Indexes' in Apache, or 'autoindex off;' in Nginx)."
                        ))
                        break
        except requests.exceptions.RequestException:
            pass

    return findings

def check_backup_files(base_url, timeout=5):
    """
    Check for exposed backup files and archives.
    """
    findings = []
    headers = {"User-Agent": "WebGuardScanner/1.0"}
    clean_base = _clean_base_url(base_url)

    for item in BACKUP_FILES_DB:
        target_url = f"{clean_base}{item['path']}"
        try:
            response = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=False)
            
            if response.status_code == 200:
                if _verify_content(response, item.get("heuristics")):
                    findings.append(_make_finding(
                        check=item["check"],
                        status=item["status"],
                        severity=item["severity"],
                        description=item["description"],
                        recommendation=item["recommendation"]
                    ))
            elif response.status_code in [403, 401]:
                findings.append(_make_finding(
                    check=f"Restricted {item['check']}",
                    status="WARN",
                    severity="Low",
                    description=f"The backup file '{item['path']}' was detected but returned HTTP {response.status_code} (Access Denied). The file exists, but access is blocked.",
                    recommendation="Verify that the access controls remain in place and consider moving backups out of the web root entirely."
                ))
        except requests.exceptions.RequestException:
            pass

    return findings

# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_sensitive_exposure(url):
    """
    Orchestrates the sensitive exposure detection module: files, directories, and backups.
    """
    all_findings = []
    
    # 1. Run all checks
    file_findings = check_sensitive_files(url)
    dir_findings = check_directory_listing(url)
    backup_findings = check_backup_files(url)

    all_findings.extend(file_findings)
    all_findings.extend(dir_findings)
    all_findings.extend(backup_findings)

    # 2. Count severities
    severity_counts = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    for finding in all_findings:
        sev = finding["severity"].lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "status": "Success",
        "url": url,
        "total_findings": len(all_findings),
        "severity_counts": severity_counts,
        "findings": all_findings
    }
