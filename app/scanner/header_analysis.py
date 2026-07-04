"""
WebGuard Security Headers Analyzer
=====================================
Checks HTTP response headers for security misconfigurations.
"""

import re
import requests


# Headers that leak server/technology information
INFO_LEAK_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
]


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


def _check_hsts(headers):
    findings = []
    hsts = headers.get("Strict-Transport-Security", "")

    if not hsts:
        findings.append(_make_finding(
            check="Strict-Transport-Security",
            status="FAIL",
            severity="High",
            description=(
                "HSTS header is missing. Without it, users can be tricked into "
                "using HTTP, enabling SSL stripping attacks."
            ),
            recommendation=(
                "Add: Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains; preload"
            ),
        ))
        return findings

    max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
    if not max_age_match:
        findings.append(_make_finding(
            check="HSTS max-age",
            status="FAIL",
            severity="High",
            description="HSTS header is present but missing max-age directive.",
            recommendation="Add max-age directive: max-age=31536000",
        ))
    else:
        max_age = int(max_age_match.group(1))
        if max_age < 31536000:
            findings.append(_make_finding(
                check="HSTS max-age",
                status="WARN",
                severity="Medium",
                description=(
                    f"HSTS max-age is {max_age} seconds ({max_age // 86400} days). "
                    "Minimum recommended is 31536000 (1 year)."
                ),
                recommendation="Increase max-age to at least 31536000.",
            ))

    if "includesubdomains" not in hsts.lower():
        findings.append(_make_finding(
            check="HSTS includeSubDomains",
            status="WARN",
            severity="Medium",
            description=(
                "HSTS does not include 'includeSubDomains'. "
                "Subdomains can still be accessed over plain HTTP."
            ),
            recommendation="Add 'includeSubDomains' to the HSTS header.",
        ))

    if "preload" not in hsts.lower():
        findings.append(_make_finding(
            check="HSTS Preload",
            status="INFO",
            severity="Low",
            description=(
                "HSTS header does not include 'preload'. The site "
                "is not eligible for browser HSTS preload lists."
            ),
            recommendation=(
                "Add 'preload' to the HSTS header and submit to "
                "hstspreload.org for inclusion in browser preload lists."
            ),
        ))

    return findings


def _check_csp(headers):
    findings = []
    csp = headers.get("Content-Security-Policy", "")

    if not csp:
        findings.append(_make_finding(
            check="Content-Security-Policy",
            status="FAIL",
            severity="High",
            description=(
                "CSP header is missing. Without it, the site has no defense "
                "against XSS, data injection, and other code injection attacks."
            ),
            recommendation=(
                "Add a Content-Security-Policy header. Start with: "
                "default-src 'self'; script-src 'self'; style-src 'self'"
            ),
        ))
        return findings

    csp_lower = csp.lower()

    if "unsafe-inline" in csp_lower:
        findings.append(_make_finding(
            check="CSP unsafe-inline",
            status="FAIL",
            severity="High",
            description=(
                "CSP contains 'unsafe-inline'. This allows inline <script> tags "
                "and event handlers, effectively disabling XSS protection."
            ),
            recommendation=(
                "Remove 'unsafe-inline' and use nonce-based or hash-based CSP. "
                "Example: script-src 'nonce-{random}'"
            ),
        ))

    if "unsafe-eval" in csp_lower:
        findings.append(_make_finding(
            check="CSP unsafe-eval",
            status="FAIL",
            severity="High",
            description=(
                "CSP contains 'unsafe-eval'. This allows eval(), Function(), "
                "and similar dynamic code execution, enabling XSS attacks."
            ),
            recommendation="Remove 'unsafe-eval' from the CSP.",
        ))

    if re.search(r"(?:^|[\s;])\*(?:\s|;|$)", csp):
        findings.append(_make_finding(
            check="CSP wildcard source",
            status="FAIL",
            severity="High",
            description=(
                "CSP contains a wildcard '*' source, allowing resources from "
                "any origin. This effectively disables CSP protection."
            ),
            recommendation="Replace '*' with specific trusted origins.",
        ))

    if "data:" in csp_lower:
        findings.append(_make_finding(
            check="CSP data: URI",
            status="WARN",
            severity="Medium",
            description=(
                "CSP allows 'data:' URIs. Attackers can use data: URIs to "
                "inject content and bypass CSP restrictions."
            ),
            recommendation="Remove 'data:' from script-src and object-src directives.",
        ))

    if "http:" in csp_lower:
        findings.append(_make_finding(
            check="CSP insecure source",
            status="WARN",
            severity="Medium",
            description=(
                "CSP allows resources over plain HTTP. This enables "
                "man-in-the-middle injection of malicious resources."
            ),
            recommendation="Use only HTTPS sources in CSP directives.",
        ))

    if "default-src" not in csp_lower:
        findings.append(_make_finding(
            check="CSP default-src",
            status="WARN",
            severity="Medium",
            description=(
                "CSP is missing 'default-src' directive. Without a fallback, "
                "unspecified resource types have no restrictions."
            ),
            recommendation="Add default-src 'self' as a baseline.",
        ))

    if "script-src" not in csp_lower and "default-src" not in csp_lower:
        findings.append(_make_finding(
            check="CSP script-src",
            status="WARN",
            severity="High",
            description=(
                "CSP has neither 'script-src' nor 'default-src'. "
                "Script loading is unrestricted."
            ),
            recommendation="Add script-src 'self' to restrict script origins.",
        ))

    return findings


def _check_x_frame_options(headers):
    findings = []
    xfo = headers.get("X-Frame-Options", "")

    if not xfo:
        csp = headers.get("Content-Security-Policy", "").lower()
        if "frame-ancestors" not in csp:
            findings.append(_make_finding(
                check="X-Frame-Options",
                status="FAIL",
                severity="Medium",
                description=(
                    "Neither X-Frame-Options nor CSP frame-ancestors is set. "
                    "The site can be embedded in iframes on any origin, enabling "
                    "clickjacking attacks."
                ),
                recommendation=(
                    "Add X-Frame-Options: DENY (or SAMEORIGIN), or use "
                    "CSP frame-ancestors 'self'."
                ),
            ))
        return findings

    xfo_upper = xfo.strip().upper()
    if xfo_upper not in ("DENY", "SAMEORIGIN") and not xfo_upper.startswith("ALLOW-FROM"):
        findings.append(_make_finding(
            check="X-Frame-Options",
            status="WARN",
            severity="Medium",
            description=(
                f"X-Frame-Options has invalid value '{xfo}'. "
                "Valid values are DENY, SAMEORIGIN, or ALLOW-FROM uri."
            ),
            recommendation="Set X-Frame-Options to DENY or SAMEORIGIN.",
        ))

    if xfo_upper.startswith("ALLOW-FROM"):
        findings.append(_make_finding(
            check="X-Frame-Options ALLOW-FROM",
            status="WARN",
            severity="Medium",
            description=(
                "X-Frame-Options uses ALLOW-FROM which is deprecated and not "
                "supported by modern browsers. Use CSP frame-ancestors instead."
            ),
            recommendation="Replace with: Content-Security-Policy: frame-ancestors 'self' https://trusted.com",
        ))

    return findings


def _check_content_type_options(headers):
    findings = []
    value = headers.get("X-Content-Type-Options", "")

    if not value:
        findings.append(_make_finding(
            check="X-Content-Type-Options",
            status="FAIL",
            severity="Medium",
            description=(
                "X-Content-Type-Options header is missing. Browsers may "
                "MIME-sniff responses, allowing attackers to disguise "
                "executable content as innocent file types."
            ),
            recommendation="Add: X-Content-Type-Options: nosniff",
        ))
    elif value.strip().lower() != "nosniff":
        findings.append(_make_finding(
            check="X-Content-Type-Options",
            status="FAIL",
            severity="Medium",
            description=(
                f"X-Content-Type-Options has invalid value '{value}'. "
                "The only valid value is 'nosniff'."
            ),
            recommendation="Set X-Content-Type-Options to 'nosniff'.",
        ))

    return findings


def _check_referrer_policy(headers):
    findings = []
    policy = headers.get("Referrer-Policy", "")

    if not policy:
        findings.append(_make_finding(
            check="Referrer-Policy",
            status="WARN",
            severity="Medium",
            description=(
                "Referrer-Policy header is missing. The full URL (including "
                "query parameters with sensitive data like tokens or session IDs) "
                "may be sent to third-party sites via the Referer header."
            ),
            recommendation=(
                "Add: Referrer-Policy: strict-origin-when-cross-origin "
                "(recommended) or no-referrer."
            ),
        ))
        return findings

    unsafe_policies = {"unsafe-url", "no-referrer-when-downgrade"}
    if policy.strip().lower() in unsafe_policies:
        findings.append(_make_finding(
            check="Referrer-Policy",
            status="WARN",
            severity="Medium",
            description=(
                f"Referrer-Policy is set to '{policy}'. This sends the full URL "
                "(including path and query) to third-party sites, potentially "
                "leaking sensitive information."
            ),
            recommendation=(
                "Use 'strict-origin-when-cross-origin' or 'no-referrer' instead."
            ),
        ))

    return findings


def _check_permissions_policy(headers):
    findings = []
    policy = headers.get("Permissions-Policy", "") or headers.get("Feature-Policy", "")

    if not policy:
        findings.append(_make_finding(
            check="Permissions-Policy",
            status="WARN",
            severity="Medium",
            description=(
                "Permissions-Policy header is missing. The page can access "
                "browser features like camera, microphone, and geolocation "
                "without restriction, and third-party iframes may also use them."
            ),
            recommendation=(
                "Add: Permissions-Policy: camera=(), microphone=(), "
                "geolocation=(), payment=()"
            ),
        ))

    return findings


def _check_coop(headers):
    findings = []
    coop = headers.get("Cross-Origin-Opener-Policy", "")

    if not coop:
        findings.append(_make_finding(
            check="Cross-Origin-Opener-Policy",
            status="WARN",
            severity="Medium",
            description=(
                "COOP header is missing. Without it, other windows opened from "
                "this site can retain a reference to it, potentially enabling "
                "Spectre-class side-channel attacks."
            ),
            recommendation="Add: Cross-Origin-Opener-Policy: same-origin",
        ))

    return findings


def _check_info_leak_headers(headers):
    findings = []

    for header_name in INFO_LEAK_HEADERS:
        value = headers.get(header_name, "")
        if value:
            if re.search(r"\d+\.\d+", value) or header_name in (
                "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
                "X-Generator", "X-Drupal-Cache"
            ):
                findings.append(_make_finding(
                    check=f"Information Leak ({header_name})",
                    status="WARN",
                    severity="Low",
                    description=(
                        f"Header '{header_name}: {value}' reveals server/technology "
                        "information. Attackers can use this to identify known "
                        "vulnerabilities for the specific software version."
                    ),
                    recommendation=(
                        f"Remove or suppress the '{header_name}' header in the "
                        "server configuration."
                    ),
                ))

    return findings


# ---------------------------------------------------------------------------
# Main Analysis Function
# ---------------------------------------------------------------------------

def full_header_scan(url):
    try:
        response = requests.get(
            url,
            timeout=15,
            allow_redirects=True,
            headers={"User-Agent": "WebGuardScanner/1.0"},
        )
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

    headers = response.headers
    all_findings = []

    all_findings.extend(_check_hsts(headers))
    all_findings.extend(_check_csp(headers))
    all_findings.extend(_check_x_frame_options(headers))
    all_findings.extend(_check_content_type_options(headers))
    all_findings.extend(_check_referrer_policy(headers))
    all_findings.extend(_check_permissions_policy(headers))
    all_findings.extend(_check_coop(headers))
    all_findings.extend(_check_info_leak_headers(headers))

    severity_counts = {
        "critical": 0, "high": 0, "medium": 0, "low": 0,
    }
    for f in all_findings:
        sev = f["severity"].lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "status": "Success",
        "url": url,
        "total_findings": len(all_findings),
        "severity_counts": severity_counts,
        "findings": all_findings,
    }