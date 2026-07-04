"""
WebGuard Information Gathering Module
=======================================
Implements robots.txt analysis, HTTP Method Enumeration, and Server Headers Info Disclosure detection.
"""

import re
import requests
from urllib.parse import urlparse, urlunparse

# Constants
SENSITIVE_ROBOTS_PATTERNS = [
    # --- Administrative & Management Panels ---
    r"/admin", r"/wp-admin", r"/administrator", r"/cpanel", r"/controlpanel",
    r"/console", r"/phpmyadmin", r"/pgadmin", r"/webmin", r"/manager", r"/dashboard",
    r"/whm", r"/directadmin", r"/plex", r"/kibana", r"/grafana", r"/portainer",
    r"/solr", r"/jenkins", r"/nagios", r"/zabbix", r"/consul", r"/eureka",
    r"/activemq", r"/rabbitmq", r"/celery", r"/sidekiq", r"/moodle", r"/drupal",
    r"/joomla", r"/typo3", r"/ghost", r"/october", r"/concrete5", r"/modx",
    
    # --- Authentication & User Credentials ---
    r"/login", r"/signin", r"/signup", r"/register", r"/logout", r"/auth", 
    r"/session", r"/account", r"/profile", r"/user", r"/passwords?", r"/credentials?",
    r"/reset-password", r"/forgot-password", r"/change-password", r"/keyring", r"/otp",
    r"/oauth", r"/sso", r"/identity", r"/mfa", r"/verification", r"/signup-success",
    
    # --- Configuration & Environment Disclosures ---
    r"/config", r"/settings", r"/setup", r"/install", r"/update", r"/upgrade",
    r"/conf", r"/properties", r"/env", r"/settings\.py", r"/web\.xml", r"/htaccess",
    r"/web\.config", r"/php\.ini", r"/composer\.json", r"/package\.json", r"/package-lock\.json",
    r"/yarn\.lock", r"/docker-compose\.yml", r"/dockerfile", r"/makefile", r"/pom\.xml",
    r"/kubernetes", r"/k8s", r"/helm", r"/deploy", r"/manifest", r"/server-status",
    
    # --- Version Control Systems & Pipelines ---
    r"/git", r"/svn", r"/cvs", r"/mercurial", r"/hg", r"/github", r"/gitlab", r"/bitbucket",
    r"/travis", r"/circleci", r"/gitlab-ci", r"/actions", r"/pipelines?", r"/builds?",
    
    # --- Database Interfaces & Backups ---
    r"/db", r"/database", r"/sql", r"/backup", r"/dumps?", r"/sql-dump", r"/migrate",
    r"/mysql", r"/postgres", r"/mongodb", r"/redis", r"/sqlite", r"/couchdb", r"/cassandra",
    r"/oracle", r"/mssql", r"/phppgadmin", r"/adminer", r"/dbadmin", r"/dump_files",
    r"/bak", r"/backup_files", r"/backup-", r"/db_", r"/schema",
    
    # --- System Files, Logs & Debugging ---
    r"/logs?", r"/error_log", r"/access_log", r"/tmp", r"/temp", r"/cache", r"/bin", r"/cgi-bin",
    r"/debug", r"/trace", r"/monitoring", r"/metrics", r"/stats", r"/telemetry", r"/status",
    r"/diagnostics", r"/sys", r"/system", r"/etc", r"/var", r"/usr", r"/home", r"/root",
    
    # --- Sensitive Files & Hidden Directories ---
    r"/private", r"/secret", r"/hidden", r"/confidential", r"/secure", r"/internal",
    r"/restricted", r"/personal", r"/uploads?", r"/downloads?", r"/archives?", r"/exports?",
    r"/imports?", r"/backups?", r"/attachments?", r"/documents?", r"/reports?", r"/invoices?",
    r"/receipts?", r"/statements?", r"/payments?", r"/billing", r"/contracts?",
    
    # --- Webmail & Communications ---
    r"/webmail", r"/roundcube", r"/squirrelmail", r"/mail", r"/email", r"/mailbox", r"/inbox",
    r"/smtp", r"/pop3", r"/imap", r"/exchange", r"/outlook", r"/owa", r"/zimbra",
    
    # --- API Endpoints & Interfaces ---
    r"/api", r"/v1", r"/v2", r"/v3", r"/rest", r"/graphql", r"/soap", r"/rpc", r"/xmlrpc",
    r"/endpoints?", r"/controllers?", r"/services?", r"/handlers?", r"/methods?", r"/actions?"
]

HTTP_METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"]

INFO_LEAK_HEADERS = {
    "Server": "Server Version Disclosure",
    "X-Powered-By": "Technology Disclosure (X-Powered-By)",
    "X-AspNet-Version": "Technology Disclosure (X-AspNet-Version)",
    "X-AspNetMvc-Version": "Technology Disclosure (X-AspNetMvc-Version)",
    "X-Generator": "Technology Disclosure (X-Generator)",
    "X-Drupal-Cache": "Technology Disclosure (X-Drupal-Cache)",
    "X-Powered-By-Plesk": "Technology Disclosure (X-Powered-By-Plesk)",
    "X-Powered-CMS": "Technology Disclosure (X-Powered-CMS)",
    "X-CMS": "Technology Disclosure (X-CMS)",
    "X-Version": "Technology Disclosure (X-Version)",
    "X-Build": "Technology Disclosure (X-Build)",
    "X-App-Version": "Technology Disclosure (X-App-Version)",
    "X-Redirect-By": "Technology Disclosure (X-Redirect-By)",
    "X-SourceMap": "Technology Disclosure (X-SourceMap)",
    "SourceMap": "Technology Disclosure (SourceMap)",
    "Via": "Technology Disclosure (Via)",
    "X-Varnish": "Technology Disclosure (X-Varnish)",
    "X-Cache": "Technology Disclosure (X-Cache)",
    "X-Cache-Lookup": "Technology Disclosure (X-Cache-Lookup)",
    "X-Pingback": "Technology Disclosure (X-Pingback)"
}

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


def analyze_robots_txt(url):
    """
    Fetch and analyze robots.txt to identify disallowed sensitive paths.
    """
    result = {
        "present": False,
        "disallowed_paths": [],
        "findings": []
    }

    parsed = urlparse(url)
    robots_url = urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))

    try:
        response = requests.get(robots_url, timeout=10, headers={"User-Agent": "WebGuardScanner/1.0"})
        if response.status_code == 200:
            result["present"] = True
            lines = response.text.splitlines()
            disallowed = []
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    key, val = line.split(":", 1)
                    if key.strip().lower() == "disallow":
                        path = val.strip()
                        if path:
                            disallowed.append(path)
            
            result["disallowed_paths"] = disallowed
            
            # Look for sensitive disallowed directories
            flagged_paths = []
            for path in disallowed:
                for pattern in SENSITIVE_ROBOTS_PATTERNS:
                    if re.search(pattern, path, re.IGNORECASE):
                        flagged_paths.append(path)
                        break
            
            if flagged_paths:
                result["findings"].append(_make_finding(
                    check="Robots.txt Sensitive Disallows",
                    status="WARN",
                    severity="Low",
                    description=(
                        f"Sensitive directories/files are listed as disallowed in robots.txt: "
                        f"{', '.join(flagged_paths)}. While this tells search engines not to "
                        f"index these paths, it publicly discloses their existence to attackers."
                    ),
                    recommendation="Remove sensitive administrative or private paths from robots.txt. Enforce authentication on these endpoints directly instead."
                ))
        else:
            result["findings"].append(_make_finding(
                check="Robots.txt Presence",
                status="INFO",
                severity="Info",
                description="robots.txt is missing on the server. While not a security vulnerability, robots.txt helps manage crawler access.",
                recommendation="Create a robots.txt file to guide search engine crawlers."
            ))
            
    except requests.exceptions.RequestException as e:
        result["findings"].append(_make_finding(
            check="Robots.txt Fetch",
            status="INFO",
            severity="Info",
            description=f"Could not check robots.txt: {str(e)}"
        ))

    return result


def enumerate_http_methods(url):
    """
    Test which HTTP methods are supported by the server and check for TRACE or unauthenticated write methods.
    """
    result = {
        "supported_methods": [],
        "findings": []
    }

    # 1. Query OPTIONS first for the Allow header
    allow_header_methods = set()
    try:
        options_response = requests.options(url, timeout=5, headers={"User-Agent": "WebGuardScanner/1.0"})
        allow_header = options_response.headers.get("Allow", "") or options_response.headers.get("Public", "")
        if allow_header:
            allow_header_methods = {m.strip().upper() for m in allow_header.split(",") if m.strip()}
    except requests.exceptions.RequestException:
        pass

    # 2. Actively probe methods to confirm support
    supported = []
    for method in HTTP_METHODS_TO_TEST:
        try:
            # For TRACE, we send a custom header to check for echoing
            headers = {"User-Agent": "WebGuardScanner/1.0"}
            if method == "TRACE":
                headers["X-WebGuard-Trace"] = "TraceActiveToken"

            response = requests.request(method, url, headers=headers, timeout=5, allow_redirects=False)
            
            # If status code is not 405 (Method Not Allowed) and not 501 (Not Implemented)
            if response.status_code not in [405, 501]:
                supported.append(method)
                
                # Check for active TRACE echoing
                if method == "TRACE" and "TraceActiveToken" in response.text:
                    result["findings"].append(_make_finding(
                        check="TRACE Method Enabled",
                        status="FAIL",
                        severity="Medium",
                        description=(
                            "The TRACE HTTP method is enabled on the server. TRACE requests echo back "
                            "the received request headers, which can facilitate Cross-Site Tracking (XST) "
                            "attacks to bypass HttpOnly cookie flags and steal sensitive session tokens."
                        ),
                        recommendation="Disable the TRACE method in your server configuration (e.g., 'TraceEnable Off' in Apache, or request filtering rules in IIS)."
                    ))
                
                # Check for unsafe PUT/DELETE without authentication
                if method in ["PUT", "DELETE"] and response.status_code in [200, 201, 204]:
                    result["findings"].append(_make_finding(
                        check="Unauthenticated write methods (PUT/DELETE)",
                        status="FAIL",
                        severity="High",
                        description=(
                            f"HTTP method {method} responded with status code {response.status_code} "
                            "without credentials. This could allow unauthorized modification or deletion of server files."
                        ),
                        recommendation="Disable PUT/DELETE methods, or restrict them behind strong authentication."
                    ))

        except requests.exceptions.RequestException:
            # If the OPTIONS Allow header reported it, keep it as fallback
            if method in allow_header_methods:
                supported.append(method)

    # Clean up and combine
    all_supported = list(set(supported).union(allow_header_methods))
    result["supported_methods"] = sorted(all_supported)

    # General warning if TRACE is in Allow header but probe timed out/blocked
    if "TRACE" in result["supported_methods"] and not any(f["check"] == "TRACE Method Enabled" for f in result["findings"]):
        result["findings"].append(_make_finding(
            check="TRACE Method Enabled",
            status="FAIL",
            severity="Medium",
            description="The TRACE HTTP method is listed as supported by the server. This may allow Cross-Site Tracking (XST) attacks.",
            recommendation="Configure your web server to disable the TRACE method."
        ))

    # General warning if PUT/DELETE are enabled but didn't trigger unauth write directly
    if ("PUT" in result["supported_methods"] or "DELETE" in result["supported_methods"]) and not any("PUT/DELETE" in f["check"] for f in result["findings"]):
        result["findings"].append(_make_finding(
            check="WebDAV / Advanced Methods Enabled",
            status="WARN",
            severity="Low",
            description=(
                f"Advanced HTTP methods ({', '.join([m for m in ['PUT', 'DELETE'] if m in result['supported_methods']])}) "
                "are enabled on this server. If improperly secured, these methods can expose the server to files modification."
            ),
            recommendation="Verify that PUT/DELETE methods are restricted to authorized users only, or disable WebDAV if not in use."
        ))

    return result


def check_server_headers(headers):
    """
    Analyze response headers to identify version or software disclosures.
    """
    findings = []
    
    for header, check_name in INFO_LEAK_HEADERS.items():
        value = headers.get(header, "")
        if value:
            # Check if Server header contains version numbers (revealing specific release)
            if header == "Server":
                if re.search(r"\d+\.\d+", value):
                    findings.append(_make_finding(
                        check=check_name,
                        status="WARN",
                        severity="Low",
                        description=(
                            f"The Server header discloses specific software and version details: "
                            f"'{value}'. This information helps attackers locate and exploit known vulnerabilities."
                        ),
                        recommendation="Remove version information or disable/genericize the Server header entirely in server settings."
                    ))
            else:
                findings.append(_make_finding(
                    check=check_name,
                    status="WARN",
                    severity="Low",
                    description=(
                        f"Response header '{header}' reveals underlying technology details: '{value}'. "
                        "Footprinting this framework details aids attackers in targeting specific weaknesses."
                    ),
                    recommendation=f"Remove or disable the '{header}' header in the application/server configuration."
                ))
                
    return findings


def run_info_gathering(url):
    """
    Orchestrates the information gathering module: robots.txt, HTTP methods, and header disclosure.
    """
    all_findings = []
    
    # 1. Fetch target headers to check disclosures
    server_disclosure = []
    try:
        response = requests.head(url, timeout=10, headers={"User-Agent": "WebGuardScanner/1.0"}, allow_redirects=True)
        headers = response.headers
        server_disclosure = check_server_headers(headers)
        all_findings.extend(server_disclosure)
    except requests.exceptions.RequestException:
        headers = {}

    # 2. Analyze robots.txt
    robots_res = analyze_robots_txt(url)
    all_findings.extend(robots_res["findings"])

    # 3. Enumerate HTTP methods
    methods_res = enumerate_http_methods(url)
    all_findings.extend(methods_res["findings"])

    # 4. Calculate severity counts
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
        "robots_txt": {
            "present": robots_res["present"],
            "disallowed_paths": robots_res["disallowed_paths"]
        },
        "http_methods": {
            "supported": methods_res["supported_methods"]
        },
        "findings": all_findings
    }