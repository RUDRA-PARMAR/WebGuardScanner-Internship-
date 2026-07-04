"""
WebGuard SSL/TLS Security Analyzer
====================================
SSL/TLS analysis: certificate validation, protocol version checks,
cipher suite assessment, hostname verification, and vulnerability detection.
"""

import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INSECURE_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

WEAK_CIPHER_INDICATORS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "RC2", "IDEA", "SEED",
]

EXPIRY_CRITICAL = 0
EXPIRY_HIGH = 30
EXPIRY_MEDIUM = 90

CONNECTION_TIMEOUT = 10


# ---------------------------------------------------------------------------
# TLS Connection
# ---------------------------------------------------------------------------

def _get_hostname_port(url):
    parsed = urlparse(url)
    return parsed.hostname, parsed.port or 443


def _connect_tls(hostname, port, context=None):
    if context is None:
        context = ssl.create_default_context()

    with socket.create_connection((hostname, port), timeout=CONNECTION_TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            cipher_info = ssock.cipher()
            tls_version = ssock.version()
            return cert, cipher_info, tls_version


# ---------------------------------------------------------------------------
# Certificate Security Checks
# ---------------------------------------------------------------------------

def _check_expiry(cert):
    findings = []

    not_after = cert.get("notAfter", "")
    not_before = cert.get("notBefore", "")

    if not not_after:
        findings.append({
            "check": "Certificate Expiry",
            "status": "FAIL",
            "severity": "Critical",
            "description": "Certificate has no expiration date field.",
        })
        return findings, None

    try:
        expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        start_date = (
            datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            if not_before else None
        )
    except ValueError:
        findings.append({
            "check": "Certificate Expiry",
            "status": "FAIL",
            "severity": "High",
            "description": f"Could not parse certificate dates. notAfter='{not_after}'.",
        })
        return findings, None

    now = datetime.now(timezone.utc)
    days_remaining = (expiry_date - now).days

    if start_date and now < start_date:
        findings.append({
            "check": "Certificate Validity",
            "status": "FAIL",
            "severity": "Critical",
            "description": (
                f"Certificate is not yet valid. It becomes valid on "
                f"{start_date.strftime('%Y-%m-%d')}."
            ),
        })

    if days_remaining < EXPIRY_CRITICAL:
        findings.append({
            "check": "Certificate Expiry",
            "status": "FAIL",
            "severity": "Critical",
            "description": (
                f"Certificate EXPIRED {abs(days_remaining)} days ago "
                f"(expired {expiry_date.strftime('%Y-%m-%d')}). "
                "Browsers will display security warnings and may block access."
            ),
        })
    elif days_remaining < EXPIRY_HIGH:
        findings.append({
            "check": "Certificate Expiry",
            "status": "WARN",
            "severity": "High",
            "description": (
                f"Certificate expires in {days_remaining} days "
                f"({expiry_date.strftime('%Y-%m-%d')}). Renew immediately."
            ),
        })
    elif days_remaining < EXPIRY_MEDIUM:
        findings.append({
            "check": "Certificate Expiry",
            "status": "WARN",
            "severity": "Medium",
            "description": (
                f"Certificate expires in {days_remaining} days "
                f"({expiry_date.strftime('%Y-%m-%d')}). Plan renewal soon."
            ),
        })

    if start_date:
        total_validity = (expiry_date - start_date).days
        if total_validity > 398:
            findings.append({
                "check": "Certificate Validity Period",
                "status": "WARN",
                "severity": "Medium",
                "description": (
                    f"Certificate validity period is {total_validity} days. "
                    "CA/Browser Forum limits public certificates to 398 days. "
                    "This may indicate a misconfigured or non-public CA."
                ),
            })

    return findings, days_remaining


def _check_self_signed(cert):
    findings = []

    if cert.get("subject") == cert.get("issuer"):
        findings.append({
            "check": "Self-Signed Certificate",
            "status": "FAIL",
            "severity": "Critical",
            "description": (
                "Certificate is self-signed (subject == issuer). "
                "Browsers will not trust this certificate. It provides no "
                "third-party identity verification and is vulnerable to "
                "man-in-the-middle attacks."
            ),
            "recommendation": (
                "Obtain a certificate from a trusted Certificate Authority. "
                "Free options include Let's Encrypt."
            ),
        })

    return findings


def _check_hostname_match(cert, hostname):
    findings = []

    san_entries = []
    for san_type, san_value in cert.get("subjectAltName", ()):
        if san_type.lower() == "dns":
            san_entries.append(san_value.lower())

    cn = ""
    for rdn in cert.get("subject", ()):
        for attr_type, attr_value in rdn:
            if attr_type == "commonName":
                cn = attr_value.lower()

    target = hostname.lower()
    matched = False
    all_names = san_entries if san_entries else ([cn] if cn else [])

    for name in all_names:
        if name == target:
            matched = True
            break
        if name.startswith("*."):
            wildcard_base = name[2:]
            if target.endswith(wildcard_base) and target.count(".") == name.count("."):
                matched = True
                break

    if not matched:
        findings.append({
            "check": "Hostname Mismatch",
            "status": "FAIL",
            "severity": "Critical",
            "description": (
                f"Certificate does not cover hostname '{hostname}'. "
                f"Certificate names: {', '.join(all_names) or 'none found'}. "
                "Browsers will reject this connection."
            ),
        })

    if not san_entries and cn:
        findings.append({
            "check": "Subject Alternative Name",
            "status": "WARN",
            "severity": "Medium",
            "description": (
                "Certificate uses only Common Name (CN) without Subject Alternative "
                "Names (SAN). Modern browsers require SAN for hostname validation. "
                "CN-only certificates are deprecated."
            ),
        })

    return findings


# ---------------------------------------------------------------------------
# Protocol & Cipher Security Checks
# ---------------------------------------------------------------------------

def _check_tls_version(tls_version):
    findings = []

    if not tls_version or tls_version == "Unknown":
        findings.append({
            "check": "TLS Version",
            "status": "FAIL",
            "severity": "High",
            "description": "Could not determine the TLS protocol version.",
        })
        return findings

    if tls_version in INSECURE_PROTOCOLS:
        findings.append({
            "check": "TLS Version",
            "status": "FAIL",
            "severity": "Critical",
            "description": (
                f"Server negotiated {tls_version}, which is deprecated and "
                "has known vulnerabilities (POODLE, BEAST, etc.). "
                "All major browsers have dropped support for this protocol."
            ),
            "recommendation": "Upgrade to TLS 1.2 or TLS 1.3.",
        })

    return findings


def _check_deprecated_protocol_support(hostname, port):
    """Actively probe whether server still accepts TLS 1.0 or 1.1."""
    findings = []

    deprecated_versions = [
        ("TLSv1", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ]

    for version_name, version_const in deprecated_versions:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version_const
            ctx.maximum_version = version_const

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    findings.append({
                        "check": "Deprecated Protocol",
                        "status": "FAIL",
                        "severity": "High",
                        "description": (
                            f"Server accepts connections using {version_name}. "
                            "This protocol has known vulnerabilities and should "
                            "be disabled."
                        ),
                        "recommendation": (
                            f"Disable {version_name} in the server's TLS configuration. "
                            "Only allow TLS 1.2 and TLS 1.3."
                        ),
                    })
        except (ssl.SSLError, socket.error, OSError):
            pass
        except Exception:
            pass

    return findings


def _check_cipher_suite(cipher_info):
    findings = []

    if not cipher_info:
        findings.append({
            "check": "Cipher Suite",
            "status": "FAIL",
            "severity": "High",
            "description": "Could not determine the negotiated cipher suite.",
        })
        return findings

    cipher_name, protocol, key_bits = cipher_info

    cipher_upper = cipher_name.upper()
    for weak in WEAK_CIPHER_INDICATORS:
        if weak.upper() in cipher_upper:
            findings.append({
                "check": "Weak Cipher",
                "status": "FAIL",
                "severity": "Critical",
                "description": (
                    f"Cipher suite '{cipher_name}' uses weak/broken algorithm "
                    f"'{weak}'. This is vulnerable to known attacks."
                ),
                "recommendation": (
                    "Configure the server to use only strong cipher suites. "
                    "Prefer AES-GCM and ChaCha20-Poly1305 ciphers."
                ),
            })
            break

    if key_bits and key_bits < 128:
        findings.append({
            "check": "Cipher Key Length",
            "status": "FAIL",
            "severity": "High",
            "description": (
                f"Cipher suite '{cipher_name}' uses only {key_bits}-bit "
                "encryption. Minimum 128-bit is required for adequate security."
            ),
        })

    if not any(fs in cipher_name.upper() for fs in ["ECDHE", "DHE", "ECDH"]):
        findings.append({
            "check": "Forward Secrecy",
            "status": "WARN",
            "severity": "Medium",
            "description": (
                f"Cipher suite '{cipher_name}' does not provide forward secrecy. "
                "If the server's private key is compromised, all past traffic "
                "can be decrypted."
            ),
            "recommendation": (
                "Prefer ECDHE or DHE key exchange cipher suites for "
                "perfect forward secrecy."
            ),
        })

    return findings


def _check_wildcard_scope(cert):
    """Flag overly broad wildcard certificates."""
    findings = []

    for san_type, san_value in cert.get("subjectAltName", ()):
        if san_type.lower() == "dns" and san_value.startswith("*."):
            domain_part = san_value[2:]
            if domain_part.count(".") == 0:
                findings.append({
                    "check": "Wildcard Scope",
                    "status": "WARN",
                    "severity": "Medium",
                    "description": (
                        f"Certificate has an extremely broad wildcard: '{san_value}'. "
                        "This could cover unintended subdomains."
                    ),
                })

    return findings


# ---------------------------------------------------------------------------
# Main Analysis Function
# ---------------------------------------------------------------------------

def ssl_analysis(url):
    """
    Perform SSL/TLS security analysis on the target URL.
    """
    hostname, port = _get_hostname_port(url)

    if not hostname:
        return {
            "status": "Error",
            "error": "Could not extract hostname from URL.",
            "url": url,
        }

    all_findings = []

    # ---- Establish TLS connection ----
    try:
        cert, cipher_info, tls_version = _connect_tls(hostname, port)
    except ssl.SSLCertVerificationError as e:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            cert, cipher_info, tls_version = _connect_tls(hostname, port, ctx)

            all_findings.append({
                "check": "Certificate Verification",
                "status": "FAIL",
                "severity": "Critical",
                "description": (
                    f"Certificate failed verification: {str(e)}. "
                    "Browsers will display security warnings."
                ),
            })
        except Exception as inner_e:
            return {
                "status": "Error",
                "error": f"SSL connection failed: {str(inner_e)}",
                "url": url,
            }
    except ssl.SSLError as e:
        return {
            "status": "Error",
            "error": f"SSL/TLS error: {str(e)}",
            "url": url,
            "findings": [{
                "check": "SSL Connection",
                "status": "FAIL",
                "severity": "Critical",
                "description": f"Cannot establish SSL/TLS connection: {str(e)}",
            }],
        }
    except socket.timeout:
        return {
            "status": "Error",
            "error": f"Connection timed out after {CONNECTION_TIMEOUT} seconds.",
            "url": url,
        }
    except ConnectionRefusedError:
        return {
            "status": "Error",
            "error": f"Connection refused on port {port}.",
            "url": url,
        }
    except Exception as e:
        return {
            "status": "Error",
            "error": f"Connection failed: {str(e)}",
            "url": url,
        }

    # ---- Run security checks ----
    expiry_findings, days_remaining = _check_expiry(cert)
    all_findings.extend(expiry_findings)
    all_findings.extend(_check_self_signed(cert))
    all_findings.extend(_check_hostname_match(cert, hostname))
    all_findings.extend(_check_tls_version(tls_version))
    all_findings.extend(_check_deprecated_protocol_support(hostname, port))
    all_findings.extend(_check_cipher_suite(cipher_info))
    all_findings.extend(_check_wildcard_scope(cert))

    # ---- Severity counts ----
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
        "hostname": hostname,
        "tls_version": tls_version,
        "cipher_suite": cipher_info[0] if cipher_info else "",
        "days_remaining": days_remaining,
        "self_signed": cert.get("subject") == cert.get("issuer"),
        "severity_counts": severity_counts,
        "findings": all_findings,
    }