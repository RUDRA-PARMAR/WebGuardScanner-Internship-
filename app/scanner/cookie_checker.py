"""
WebGuard Cookie Security Analyzer
==================================
Cookie security analysis with comprehensive checks.
Parses raw Set-Cookie headers for accurate attribute detection.
"""

import re
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Known session / auth cookie name patterns (case-insensitive)
SESSION_COOKIE_PATTERNS = [
    r"sess",
    r"session",
    r"sid",
    r"token",
    r"auth",
    r"login",
    r"jwt",
    r"access",
    r"refresh",
    r"csrf",
    r"xsrf",
    r"ssid",
    r"connect\.sid",
]

# Known framework session cookie names
FRAMEWORK_SESSION_COOKIES = {
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
    "aspsessionid",
    "cfid",
    "cftoken",
    "laravel_session",
    "ci_session",
    "rack.session",
    "_session_id",
    "connect.sid",
    "express.sid",
    "wp-settings",
    "wordpress_logged_in",
    "django_session",
    "flask_session",
}

# Patterns that suggest sensitive data in cookie values
SENSITIVE_VALUE_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "jwt": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "base64_long": r"^[A-Za-z0-9+/]{40,}={0,2}$",
    "uuid": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "hex_token": r"^[0-9a-fA-F]{32,}$",
    "api_key_pattern": r"(?:key|api|secret|password)[=:].+",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
    "phone_number": r"\b\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b",
}

# Maximum recommended cookie expiry
MAX_EXPIRY_DAYS = 365


# ---------------------------------------------------------------------------
# Set-Cookie Header Parser
# ---------------------------------------------------------------------------

def parse_set_cookie_header(header_value):
    """
    Parse a single Set-Cookie header string into a structured dict.
    """
    cookie = {
        "name": "",
        "value": "",
        "domain": "",
        "path": "",
        "secure": False,
        "httponly": False,
        "samesite": "",
        "partitioned": False,
        "max_age": None,
        "expires": "",
        "raw": header_value,
    }

    parts = header_value.split(";")

    # First part is name=value
    if parts:
        name_value = parts[0].strip()
        if "=" in name_value:
            eq_index = name_value.index("=")
            cookie["name"] = name_value[:eq_index].strip()
            cookie["value"] = name_value[eq_index + 1:].strip()
        else:
            cookie["name"] = name_value

    # Parse remaining attributes
    for part in parts[1:]:
        part = part.strip()
        lower_part = part.lower()

        if lower_part == "secure":
            cookie["secure"] = True

        elif lower_part == "httponly":
            cookie["httponly"] = True

        elif lower_part == "partitioned":
            cookie["partitioned"] = True

        elif lower_part.startswith("samesite="):
            cookie["samesite"] = part.split("=", 1)[1].strip()

        elif lower_part.startswith("domain="):
            cookie["domain"] = part.split("=", 1)[1].strip()

        elif lower_part.startswith("path="):
            cookie["path"] = part.split("=", 1)[1].strip()

        elif lower_part.startswith("max-age="):
            try:
                cookie["max_age"] = int(part.split("=", 1)[1].strip())
            except ValueError:
                cookie["max_age"] = None

        elif lower_part.startswith("expires="):
            cookie["expires"] = part.split("=", 1)[1].strip()

    return cookie


def split_combined_set_cookie(header_value):
    """Splits a combined Set-Cookie header value safely, respecting expires dates."""
    if not header_value:
        return []
    cookies = []
    current = []
    parts = header_value.split(",")
    for part in parts:
        part = part.strip()
        # Check if part is part of a date (e.g. ends with GMT/UTC or has no = sign)
        if current and (any(part.lower().endswith(tz) for tz in ["gmt", "utc"]) or not "=" in part):
            current.append(part)
        else:
            if current:
                cookies.append(", ".join(current))
            current = [part]
    if current:
        cookies.append(", ".join(current))
    return cookies


def extract_cookies_from_response(response):
    """
    Extract all cookies by parsing raw Set-Cookie headers from the response.
    Falls back to response.cookies if no Set-Cookie headers are present.
    """
    cookies = []

    # Get all Set-Cookie headers (case-insensitive)
    set_cookie_headers = response.raw.headers.getlist("Set-Cookie") if hasattr(
        response.raw.headers, "getlist"
    ) else []

    # Fallback: try response.headers for single Set-Cookie
    if not set_cookie_headers:
        if hasattr(response.raw, "_fp") or hasattr(response.raw, "headers"):
            try:
                if hasattr(response.raw.headers, "items"):
                    set_cookie_headers = [
                        v for k, v in response.raw.headers.items()
                        if k.lower() == "set-cookie"
                    ]
            except Exception:
                pass

    # Parse each Set-Cookie header
    for header in set_cookie_headers:
        individual_headers = split_combined_set_cookie(header)
        for ind_header in individual_headers:
            parsed = parse_set_cookie_header(ind_header)
            if parsed["name"]:
                cookies.append(parsed)

    # If we still have no cookies from headers, build from response.cookies
    if not cookies and response.cookies:
        for cookie in response.cookies:
            cookies.append({
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain or "",
                "path": cookie.path or "",
                "secure": cookie.secure,
                "httponly": False,  # Cannot reliably detect from requests.cookies
                "samesite": "",
                "partitioned": False,
                "max_age": None,
                "expires": (
                    datetime.fromtimestamp(cookie.expires, tz=timezone.utc).strftime(
                        "%a, %d %b %Y %H:%M:%S GMT"
                    )
                    if cookie.expires else ""
                ),
                "raw": "",
            })

    return cookies


# ---------------------------------------------------------------------------
# Helper Utilities
# ---------------------------------------------------------------------------

def _is_session_cookie(name):
    """Check if a cookie name suggests it's a session or auth cookie."""
    lower = name.lower()

    if lower in FRAMEWORK_SESSION_COOKIES:
        return True

    for pattern in SESSION_COOKIE_PATTERNS:
        if re.search(pattern, lower):
            return True

    return False


def _make_finding(check, status, severity, description, recommendation=""):
    """Create a standardized finding dict."""
    finding = {
        "check": check,
        "status": status,
        "severity": severity,
        "description": description,
    }
    if recommendation:
        finding["recommendation"] = recommendation
    return finding


# ---------------------------------------------------------------------------
# Security Checks
# ---------------------------------------------------------------------------

def check_secure_flag(cookie):
    """
    Secure Flag — cookies without it can be transmitted over unencrypted HTTP,
    allowing interception via man-in-the-middle attacks.
    """
    findings = []

    if not cookie["secure"]:
        findings.append(_make_finding(
            check="Secure Flag",
            status="FAIL",
            severity="High",
            description=(
                f"Cookie '{cookie['name']}' is missing the Secure flag. "
                "It can be transmitted over unencrypted HTTP connections, "
                "exposing it to interception via man-in-the-middle attacks."
            ),
            recommendation=(
                "Add the 'Secure' attribute to this cookie. "
                "Example: Set-Cookie: name=value; Secure"
            ),
        ))

    return findings


def check_httponly_flag(cookie):
    """
    HttpOnly Flag — cookies without it can be accessed by client-side JavaScript,
    making them vulnerable to theft via XSS attacks.
    """
    findings = []

    if not cookie["httponly"]:
        severity = "High" if _is_session_cookie(cookie["name"]) else "Medium"

        findings.append(_make_finding(
            check="HttpOnly Flag",
            status="FAIL",
            severity=severity,
            description=(
                f"Cookie '{cookie['name']}' is missing the HttpOnly flag. "
                "Client-side JavaScript can access this cookie, making it "
                "vulnerable to theft via Cross-Site Scripting (XSS) attacks."
            ),
            recommendation=(
                "Add the 'HttpOnly' attribute to prevent JavaScript access. "
                "Example: Set-Cookie: name=value; HttpOnly"
            ),
        ))

    return findings


def check_samesite_attribute(cookie):
    """
    SameSite Attribute — controls cross-site request behavior,
    critical for CSRF protection.
    """
    findings = []
    samesite = cookie["samesite"].lower() if cookie["samesite"] else ""

    if samesite == "none":
        # SameSite=None without Secure is rejected by browsers
        if not cookie["secure"]:
            findings.append(_make_finding(
                check="SameSite Attribute",
                status="FAIL",
                severity="Critical",
                description=(
                    f"Cookie '{cookie['name']}' has SameSite=None without the "
                    "Secure flag. Modern browsers will REJECT this cookie entirely. "
                    "SameSite=None requires the Secure attribute."
                ),
                recommendation=(
                    "Add the 'Secure' attribute alongside SameSite=None, or change "
                    "to SameSite=Lax if cross-site access is not needed."
                ),
            ))
        else:
            findings.append(_make_finding(
                check="SameSite Attribute",
                status="WARN",
                severity="Medium",
                description=(
                    f"Cookie '{cookie['name']}' has SameSite=None, allowing it to "
                    "be sent with cross-site requests. This may expose the cookie to "
                    "CSRF attacks and cross-site tracking."
                ),
                recommendation=(
                    "Use SameSite=Lax (recommended default) or SameSite=Strict "
                    "unless cross-site access is explicitly required."
                ),
            ))

    elif not samesite:
        severity = "Medium" if _is_session_cookie(cookie["name"]) else "Low"

        findings.append(_make_finding(
            check="SameSite Attribute",
            status="WARN",
            severity=severity,
            description=(
                f"Cookie '{cookie['name']}' is missing the SameSite attribute. "
                "Modern browsers default to Lax, but older browsers default to "
                "None, which allows cross-site request usage."
            ),
            recommendation=(
                "Explicitly set SameSite=Lax (recommended) or SameSite=Strict. "
                "Example: Set-Cookie: name=value; SameSite=Lax"
            ),
        ))

    return findings


def check_cookie_prefixes(cookie):
    """
    Cookie Prefixes (__Host- and __Secure-) — enforce browser-level security
    constraints that prevent insecure origins from setting or overwriting cookies.
    """
    findings = []
    name = cookie["name"]

    # Validate __Host- prefix requirements
    if name.startswith("__Host-"):
        issues = []

        if not cookie["secure"]:
            issues.append("missing Secure flag")
        if cookie["path"] != "/":
            issues.append(f"Path is '{cookie['path']}' instead of '/'")
        if cookie["domain"]:
            issues.append(f"Domain is set to '{cookie['domain']}' (must be omitted)")

        if issues:
            findings.append(_make_finding(
                check="Cookie Prefix (__Host-)",
                status="FAIL",
                severity="High",
                description=(
                    f"Cookie '{name}' uses the __Host- prefix but violates its "
                    f"requirements: {'; '.join(issues)}. Browsers will REJECT this "
                    "cookie."
                ),
                recommendation=(
                    "__Host- cookies MUST have: Secure flag, Path=/, and NO Domain "
                    "attribute. Fix the listed violations."
                ),
            ))

    # Validate __Secure- prefix requirements
    elif name.startswith("__Secure-"):
        if not cookie["secure"]:
            findings.append(_make_finding(
                check="Cookie Prefix (__Secure-)",
                status="FAIL",
                severity="High",
                description=(
                    f"Cookie '{name}' uses the __Secure- prefix but is missing the "
                    "Secure flag. Browsers will REJECT this cookie."
                ),
                recommendation=(
                    "__Secure- cookies MUST have the Secure attribute."
                ),
            ))

    # Recommend prefixes for session/auth cookies without them
    elif _is_session_cookie(name):
        findings.append(_make_finding(
            check="Cookie Prefix Recommendation",
            status="WARN",
            severity="Medium",
            description=(
                f"Cookie '{name}' appears to be a session/auth cookie but does "
                "not use a security prefix. Using __Host- prefix provides the "
                "strongest protection against subdomain attacks and cookie injection."
            ),
            recommendation=(
                "Rename to '__Host-" + name + "' with Secure, Path=/, and no "
                "Domain attribute. Alternatively, use '__Secure-' prefix with the "
                "Secure attribute."
            ),
        ))

    return findings


def check_partitioned_chips(cookie):
    """
    CHIPS / Partitioned Attribute — cookies with SameSite=None should use the
    Partitioned attribute to prevent cross-site tracking.
    """
    findings = []
    samesite = cookie["samesite"].lower() if cookie["samesite"] else ""

    if samesite == "none" and not cookie["partitioned"]:
        findings.append(_make_finding(
            check="Partitioned (CHIPS)",
            status="WARN",
            severity="Medium",
            description=(
                f"Cookie '{cookie['name']}' has SameSite=None but lacks the "
                "Partitioned attribute. Without CHIPS, this cookie can be used "
                "for cross-site tracking across different top-level sites."
            ),
            recommendation=(
                "Add the 'Partitioned' attribute to enable CHIPS. This creates "
                "a separate cookie jar per top-level site, preventing tracking. "
                "Example: Set-Cookie: name=value; SameSite=None; Secure; Partitioned"
            ),
        ))

    return findings


def check_domain_scope(cookie):
    """
    Domain Scope — overly broad Domain attributes allow subdomains to access
    the cookie, increasing the attack surface.
    """
    findings = []
    domain = cookie["domain"]

    if domain:
        # Leading dot means all subdomains can access
        if domain.startswith("."):
            severity = "Medium" if _is_session_cookie(cookie["name"]) else "Low"

            findings.append(_make_finding(
                check="Domain Scope",
                status="WARN",
                severity=severity,
                description=(
                    f"Cookie '{cookie['name']}' has Domain='{domain}', making it "
                    "accessible to all subdomains. A compromised subdomain could "
                    "read or overwrite this cookie."
                ),
                recommendation=(
                    "Omit the Domain attribute to restrict the cookie to the exact "
                    "host that set it. If subdomain access is required, ensure all "
                    "subdomains are trusted and secured."
                ),
            ))

        # Check for overly broad TLD-like domains
        parts = domain.lstrip(".").split(".")
        if len(parts) <= 2 and domain.lstrip(".") != "localhost":
            findings.append(_make_finding(
                check="Domain Scope",
                status="WARN",
                severity="Medium",
                description=(
                    f"Cookie '{cookie['name']}' is scoped to the broad domain "
                    f"'{domain}'. This exposes it to all services hosted under "
                    "this domain."
                ),
                recommendation=(
                    "Scope cookies to the most specific subdomain possible, or "
                    "omit the Domain attribute entirely."
                ),
            ))

    return findings


def check_expiry(cookie):
    """
    Expiry / Max-Age — excessively long cookie lifetimes increase the window
    for session theft.
    """
    findings = []
    max_age = cookie["max_age"]
    expires = cookie["expires"]

    has_expiry = max_age is not None or expires

    if not has_expiry:
        return findings

    days_to_expiry = None

    if max_age is not None:
        days_to_expiry = max_age / 86400  # seconds to days

        if max_age <= 0:
            # Cookie is being deleted — that's fine
            return findings

    elif expires:
        # Try parsing common Expires date formats
        for fmt in [
            "%a, %d %b %Y %H:%M:%S GMT",
            "%a, %d-%b-%Y %H:%M:%S GMT",
            "%a %b %d %H:%M:%S %Y",
        ]:
            try:
                expiry_date = datetime.strptime(expires, fmt).replace(
                    tzinfo=timezone.utc
                )
                days_to_expiry = (
                    expiry_date - datetime.now(timezone.utc)
                ).days
                break
            except ValueError:
                continue

    if days_to_expiry is not None and days_to_expiry > MAX_EXPIRY_DAYS:
        severity = "Medium" if _is_session_cookie(cookie["name"]) else "Low"

        findings.append(_make_finding(
            check="Cookie Expiry",
            status="WARN",
            severity=severity,
            description=(
                f"Cookie '{cookie['name']}' has an expiry of "
                f"~{int(days_to_expiry)} days ({int(days_to_expiry / 365)} "
                "years). Excessively long cookie lifetimes increase the window "
                "for stolen session attacks."
            ),
            recommendation=(
                f"Reduce cookie lifetime to {MAX_EXPIRY_DAYS} days or less. "
                "For session cookies, consider using Max-Age=86400 (1 day) or "
                "shorter depending on security requirements."
            ),
        ))

    return findings


def check_sensitive_data(cookie):
    """
    Sensitive Data in Cookie Values — cookie values containing PII, JWTs,
    or other sensitive data are at risk of exposure through browser storage,
    logs, and HTTP headers.
    """
    findings = []
    value = cookie["value"]

    if not value:
        return findings

    for pattern_name, pattern in SENSITIVE_VALUE_PATTERNS.items():
        if re.search(pattern, value, re.IGNORECASE):
            # Don't flag short hex strings that are just session IDs
            if pattern_name == "hex_token" and len(value) < 32:
                continue

            # Don't flag UUIDs that are just session identifiers
            if pattern_name == "uuid" and _is_session_cookie(cookie["name"]):
                continue

            severity_map = {
                "email": "High",
                "jwt": "High",
                "api_key_pattern": "Critical",
                "credit_card": "Critical",
                "phone_number": "High",
                "base64_long": "Medium",
                "uuid": "Low",
                "hex_token": "Low",
            }

            findings.append(_make_finding(
                check="Sensitive Data in Value",
                status="FAIL",
                severity=severity_map.get(pattern_name, "Medium"),
                description=(
                    f"Cookie '{cookie['name']}' value appears to contain "
                    f"sensitive data (pattern: {pattern_name}). Sensitive "
                    "information in cookies is exposed in HTTP headers, browser "
                    "storage, and potentially server logs."
                ),
                recommendation=(
                    "Do not store sensitive data directly in cookies. Use server-"
                    "side sessions with an opaque session identifier, or encrypt "
                    "cookie values using authenticated encryption (AES-GCM)."
                ),
            ))
            break  # One finding per cookie for sensitive data

    return findings


def check_session_fixation(cookie):
    """
    Session Fixation Risk — session cookies without __Host- prefix and with
    a broad Domain are susceptible to subdomain-based session fixation attacks.
    """
    findings = []

    if not _is_session_cookie(cookie["name"]):
        return findings

    name = cookie["name"]

    # Session fixation risk: broad domain + no host prefix
    has_host_prefix = name.startswith("__Host-")
    has_broad_domain = bool(cookie["domain"])

    if not has_host_prefix and has_broad_domain:
        findings.append(_make_finding(
            check="Session Fixation Risk",
            status="WARN",
            severity="Medium",
            description=(
                f"Cookie '{name}' appears to be a session cookie with "
                f"Domain='{cookie['domain']}' and no __Host- prefix. A compromised "
                "subdomain could set or overwrite this cookie to perform session "
                "fixation attacks."
            ),
            recommendation=(
                "Use the __Host- prefix (which enforces no Domain attribute and "
                "Secure flag) to prevent subdomain-based session fixation. "
                "Example: __Host-session=value; Secure; Path=/"
            ),
        ))

    # Also flag if session cookie lacks both Secure and HttpOnly
    if not cookie["secure"] and not cookie["httponly"]:
        findings.append(_make_finding(
            check="Session Fixation Risk",
            status="FAIL",
            severity="High",
            description=(
                f"Session cookie '{name}' is missing BOTH Secure and HttpOnly "
                "flags. This makes it highly vulnerable to interception (MitM) "
                "and theft (XSS)."
            ),
            recommendation=(
                "Session cookies MUST have both Secure and HttpOnly attributes. "
                "Example: Set-Cookie: session=value; Secure; HttpOnly; SameSite=Lax"
            ),
        ))

    return findings


def check_deprecated_patterns(cookie):
    """
    Deprecated / Dangerous Patterns — flag cookies using known-insecure
    framework defaults or patterns.
    """
    findings = []
    name = cookie["name"].lower()

    # Check for known framework session cookies without proper security
    if name in FRAMEWORK_SESSION_COOKIES:
        issues = []

        if not cookie["secure"]:
            issues.append("Secure")
        if not cookie["httponly"]:
            issues.append("HttpOnly")
        if not cookie["samesite"]:
            issues.append("SameSite")

        if issues:
            framework_hints = {
                "phpsessid": "PHP",
                "jsessionid": "Java/Tomcat",
                "asp.net_sessionid": "ASP.NET",
                "aspsessionid": "Classic ASP",
                "laravel_session": "Laravel",
                "ci_session": "CodeIgniter",
                "django_session": "Django",
                "flask_session": "Flask",
                "connect.sid": "Express.js",
                "express.sid": "Express.js",
                "rack.session": "Ruby/Rack",
                "wordpress_logged_in": "WordPress",
            }

            framework = framework_hints.get(name, "Unknown framework")

            findings.append(_make_finding(
                check="Framework Session Cookie",
                status="FAIL",
                severity="Medium",
                description=(
                    f"Cookie '{cookie['name']}' is a known {framework} session "
                    f"cookie missing: {', '.join(issues)}. Default framework "
                    "session cookies often lack proper security attributes."
                ),
                recommendation=(
                    f"Configure {framework} to set session cookies with Secure, "
                    "HttpOnly, and SameSite=Lax attributes. Refer to the framework's "
                    "session security documentation."
                ),
            ))

    return findings


# ---------------------------------------------------------------------------
# Main Analysis Function
# ---------------------------------------------------------------------------

def analyze_cookies(url):
    """
    Perform cookie security analysis on the target URL.

    Runs security checks against all cookies returned by the target
    and returns a structured report with findings and per-cookie breakdowns.
    """
    try:
        response = requests.get(url, timeout=15, allow_redirects=True)
    except requests.exceptions.Timeout:
        return {
            "status": "Error",
            "error": "Connection timed out after 15 seconds.",
            "url": url,
        }
    except requests.exceptions.ConnectionError:
        return {
            "status": "Error",
            "error": "Failed to connect to the target URL.",
            "url": url,
        }
    except requests.exceptions.RequestException as e:
        return {
            "status": "Error",
            "error": f"Request failed: {str(e)}",
            "url": url,
        }

    # Extract cookies from Set-Cookie headers
    cookies = extract_cookies_from_response(response)

    if not cookies:
        return {
            "status": "Success",
            "url": url,
            "total_cookies": 0,
            "message": "No cookies were set by this URL.",
            "cookies": [],
        }

    # Run all security checks on each cookie
    all_findings = []
    cookie_reports = []

    for cookie in cookies:
        cookie_findings = []

        # Secure flag
        cookie_findings.extend(check_secure_flag(cookie))

        # HttpOnly flag
        cookie_findings.extend(check_httponly_flag(cookie))

        # SameSite attribute
        cookie_findings.extend(check_samesite_attribute(cookie))

        # Cookie prefixes
        cookie_findings.extend(check_cookie_prefixes(cookie))

        # Partitioned / CHIPS
        cookie_findings.extend(check_partitioned_chips(cookie))

        # Domain scope
        cookie_findings.extend(check_domain_scope(cookie))

        # Expiry / Max-Age
        cookie_findings.extend(check_expiry(cookie))

        # Sensitive data in values
        cookie_findings.extend(check_sensitive_data(cookie))

        # Session fixation risk
        cookie_findings.extend(check_session_fixation(cookie))

        # Deprecated / dangerous patterns
        cookie_findings.extend(check_deprecated_patterns(cookie))

        all_findings.extend(cookie_findings)

        # Build per-cookie report
        cookie_reports.append({
            "name": cookie["name"],
            "domain": cookie["domain"] or "(host-only)",
            "path": cookie["path"] or "/",
            "secure": cookie["secure"],
            "httponly": cookie["httponly"],
            "samesite": cookie["samesite"] or "(not set)",
            "partitioned": cookie["partitioned"],
            "has_expiry": bool(cookie["max_age"] is not None or cookie["expires"]),
            "findings": cookie_findings,
        })

    # Calculate severity counts
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
        "total_cookies": len(cookies),
        "total_findings": len(all_findings),
        "severity_counts": severity_counts,
        "cookies": cookie_reports,
    }
