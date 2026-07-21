"""
WebGuard URL Validation & Reachability Analyzer
=================================================
URL validation with SSRF protection, DNS analysis,
redirect chain tracking, and transport security checks.
"""

import re
import socket
import ipaddress
import time
import os
import requests
from urllib.parse import urlparse, urlunparse



# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Private / reserved IP ranges that must be blocked (SSRF protection)
BLOCKED_IP_NETWORKS = [
    # IPv4 private ranges
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),

    # IPv4 loopback
    ipaddress.ip_network("127.0.0.0/8"),

    # IPv4 link-local
    ipaddress.ip_network("169.254.0.0/16"),

    # IPv4 CGNAT (Carrier-Grade NAT)
    ipaddress.ip_network("100.64.0.0/10"),

    # IPv4 reserved / special-use
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast

    # IPv6 private / reserved
    ipaddress.ip_network("::1/128"),             # Loopback
    ipaddress.ip_network("fc00::/7"),            # Unique Local
    ipaddress.ip_network("fe80::/10"),           # Link-Local
    ipaddress.ip_network("::ffff:0:0/96"),       # IPv4-mapped IPv6
]

# Cloud metadata endpoints (common SSRF targets)
CLOUD_METADATA_IPS = {
    "169.254.169.254",   # AWS, GCP, Azure
    "metadata.google.internal",
    "100.100.100.200",   # Alibaba Cloud
    "169.254.170.2",     # AWS ECS task metadata
}

# Allowed schemes
ALLOWED_SCHEMES = {"http", "https"}

# Allowed ports (None means default 80/443)
ALLOWED_PORTS = {None, 80, 443, 8080, 8443}

# Maximum redirects to follow
MAX_REDIRECTS = 10

# Request timeout in seconds
REQUEST_TIMEOUT = 15

# Domain validation regex (RFC 1123 compliant)
DOMAIN_REGEX = re.compile(
    r"^(?!-)"                      # Cannot start with hyphen
    r"(?:[a-zA-Z0-9-]{1,63}\.)*"   # Subdomain labels
    r"[a-zA-Z]{2,63}$"             # TLD must be letters only
)

# IP address pattern (to detect direct IP usage)
IPV4_PATTERN = re.compile(
    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
)


# ---------------------------------------------------------------------------
# URL Validation
# ---------------------------------------------------------------------------

def validate_url(url):
    
    result = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "components": {},
    }

    if not url or not isinstance(url, str):
        result["valid"] = False
        result["errors"].append("URL is empty or not a string.")
        return result

    # Strip whitespace
    url = url.strip()

    # Check for whitespace within URL
    if re.search(r"\s", url):
        result["valid"] = False
        result["errors"].append("URL contains whitespace characters.")
        return result

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception:
        result["valid"] = False
        result["errors"].append("URL could not be parsed.")
        return result

    # Validate scheme
    if not parsed.scheme:
        result["valid"] = False
        result["errors"].append(
            "URL is missing a scheme. Use 'https://' or 'http://'."
        )
        return result

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        result["valid"] = False
        result["errors"].append(
            f"Scheme '{parsed.scheme}' is not allowed. "
            "Only 'http' and 'https' are supported."
        )
        return result

    # Validate hostname
    hostname = parsed.hostname
    if not hostname:
        result["valid"] = False
        result["errors"].append("URL is missing a hostname.")
        return result

    # Check for credentials in URL (security risk)
    if parsed.username or parsed.password:
        result["warnings"].append(
            "URL contains embedded credentials. This is a security risk "
            "as credentials may be logged or leaked via Referer headers."
        )

    # Validate port
    port = parsed.port
    if port is not None:
        if port < 1 or port > 65535:
            result["valid"] = False
            result["errors"].append(
                f"Port {port} is outside the valid range (1-65535)."
            )
            return result

        if port not in ALLOWED_PORTS:
            result["warnings"].append(
                f"Non-standard port {port} detected. Common web ports "
                "are 80, 443, 8080, and 8443."
            )

    # Validate domain format
    is_ip = IPV4_PATTERN.match(hostname)

    if is_ip:
        # Direct IP address usage — may bypass DNS-based security controls
        result["warnings"].append(
            "URL uses a direct IP address instead of a domain name. "
            "This may bypass DNS-based security controls."
        )
    else:
        # Validate domain name format
        ascii_hostname = hostname.lower()
        if not DOMAIN_REGEX.match(ascii_hostname):
            if "." not in ascii_hostname:
                result["valid"] = False
                result["errors"].append(
                    f"Hostname '{hostname}' is not a valid domain name. "
                    "A domain must contain at least one dot (e.g., example.com)."
                )
                return result

    # Check for fragment-only URLs
    if not parsed.netloc:
        result["valid"] = False
        result["errors"].append("URL has no network location (host).")
        return result

    # Store parsed components
    result["components"] = {
        "scheme": parsed.scheme,
        "hostname": hostname,
        "port": port,
        "path": parsed.path or "/",
        "query": parsed.query or "",
        "is_https": parsed.scheme.lower() == "https",
        "is_ip_address": bool(is_ip),
    }

    return result


# ---------------------------------------------------------------------------
# SSRF Protection
# ---------------------------------------------------------------------------

def check_ssrf(hostname):
    """
    Resolve hostname and check if it points to a private/reserved IP.
    Prevents Server-Side Request Forgery (SSRF) attacks.

    """
    result = {
        "safe": True,
        "resolved_ips": [],
        "findings": [],
    }

    # Check against known cloud metadata hostnames
    if hostname.lower() in CLOUD_METADATA_IPS:
        result["safe"] = False
        result["findings"].append({
            "check": "SSRF Protection",
            "status": "BLOCKED",
            "severity": "Critical",
            "description": (
                f"Hostname '{hostname}' is a known cloud metadata endpoint. "
                "Accessing it could expose sensitive cloud credentials and "
                "instance metadata."
            ),
        })
        return result

    # Resolve hostname to IP addresses
    try:
        addr_infos = socket.getaddrinfo(
            hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        resolved_ips = list(set(
            addr_info[4][0] for addr_info in addr_infos
        ))
        result["resolved_ips"] = resolved_ips

    except socket.gaierror:
        result["findings"].append({
            "check": "DNS Resolution",
            "status": "FAIL",
            "severity": "High",
            "description": (
                f"DNS resolution failed for '{hostname}'. The domain may not "
                "exist or DNS servers are unreachable."
            ),
        })
        return result

    except Exception as e:
        result["findings"].append({
            "check": "DNS Resolution",
            "status": "FAIL",
            "severity": "Medium",
            "description": f"DNS resolution error: {str(e)}",
        })
        return result

    # Check each resolved IP against blocked ranges
    allow_private = os.getenv("ALLOW_PRIVATE_IPS", "False").lower() in ("true", "1", "yes")
    if not allow_private:
        for ip_str in resolved_ips:
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue

            # Check cloud metadata IPs
            if ip_str in CLOUD_METADATA_IPS:
                result["safe"] = False
                result["findings"].append({
                    "check": "SSRF Protection",
                    "status": "BLOCKED",
                    "severity": "Critical",
                    "description": (
                        f"'{hostname}' resolves to cloud metadata IP {ip_str}. "
                        "This is a potential DNS rebinding attack to access "
                        "cloud instance metadata."
                    ),
                })
                continue

            # Check against blocked networks
            for network in BLOCKED_IP_NETWORKS:
                if ip in network:
                    result["safe"] = False
                    result["findings"].append({
                        "check": "SSRF Protection",
                        "status": "BLOCKED",
                        "severity": "Critical",
                        "description": (
                            f"'{hostname}' resolves to private/reserved IP "
                            f"{ip_str} (in {network}). Scanning internal "
                            "network addresses is blocked."
                        ),
                    })
                    break

    return result


# ---------------------------------------------------------------------------
# DNS Analysis
# ---------------------------------------------------------------------------

def analyze_dns(hostname):
    """
    Perform DNS analysis on the hostname.

    """
    result = {
        "resolved": False,
        "ipv4_addresses": [],
        "ipv6_addresses": [],
        "resolution_time_ms": 0,
        "findings": [],
    }

    start = time.time()

    try:
        # Resolve IPv4
        try:
            ipv4_infos = socket.getaddrinfo(
                hostname, None, socket.AF_INET, socket.SOCK_STREAM
            )
            result["ipv4_addresses"] = list(set(
                info[4][0] for info in ipv4_infos
            ))
        except socket.gaierror:
            pass

        # Resolve IPv6
        try:
            ipv6_infos = socket.getaddrinfo(
                hostname, None, socket.AF_INET6, socket.SOCK_STREAM
            )
            result["ipv6_addresses"] = list(set(
                info[4][0] for info in ipv6_infos
            ))
        except socket.gaierror:
            pass

        elapsed = (time.time() - start) * 1000
        result["resolution_time_ms"] = round(elapsed, 2)

        if result["ipv4_addresses"] or result["ipv6_addresses"]:
            result["resolved"] = True
        else:
            result["findings"].append({
                "check": "DNS Resolution",
                "status": "FAIL",
                "severity": "High",
                "description": (
                    f"No DNS records found for '{hostname}'. The domain "
                    "may not exist or DNS propagation is pending."
                ),
            })

    except Exception as e:
        result["findings"].append({
            "check": "DNS Resolution",
            "status": "FAIL",
            "severity": "High",
            "description": f"DNS analysis failed: {str(e)}",
        })

    return result


# ---------------------------------------------------------------------------
# Redirect Chain Analysis
# ---------------------------------------------------------------------------

def analyze_redirect_chain(url):
    """
    Follow and analyze the full redirect chain.
    Detects insecure redirects, loops, and excessive chains.

    """
    result = {
        "chain": [],
        "total_redirects": 0,
        "final_url": url,
        "findings": [],
    }

    try:
        # Send request without following redirects
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            headers={"User-Agent": "WebGuardScanner/1.0"},
        )

        visited = [url]
        chain = [{
            "url": url,
            "status_code": response.status_code,
            "is_https": url.startswith("https://"),
        }]

        redirect_count = 0

        while response.is_redirect and redirect_count < MAX_REDIRECTS:
            redirect_url = response.headers.get("Location", "")

            if not redirect_url:
                break

            # Handle relative redirects
            if redirect_url.startswith("/"):
                parsed_current = urlparse(visited[-1])
                redirect_url = urlunparse((
                    parsed_current.scheme,
                    parsed_current.netloc,
                    redirect_url, "", "", "",
                ))

            # Detect redirect loops
            if redirect_url in visited:
                result["findings"].append({
                    "check": "Redirect Loop",
                    "status": "FAIL",
                    "severity": "High",
                    "description": (
                        f"Redirect loop detected: '{redirect_url}' was "
                        f"already visited at step {visited.index(redirect_url) + 1}."
                    ),
                })
                break

            visited.append(redirect_url)
            redirect_count += 1

            try:
                response = requests.get(
                    redirect_url,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=False,
                    headers={"User-Agent": "WebGuardScanner/1.0"},
                )

                chain.append({
                    "url": redirect_url,
                    "status_code": response.status_code,
                    "is_https": redirect_url.startswith("https://"),
                })

            except requests.exceptions.RequestException:
                chain.append({
                    "url": redirect_url,
                    "status_code": None,
                    "is_https": redirect_url.startswith("https://"),
                    "error": "Failed to follow redirect",
                })
                break

        result["chain"] = chain
        result["total_redirects"] = redirect_count
        result["final_url"] = visited[-1]

        # Check for excessive redirects (potential misconfiguration / DoS)
        if redirect_count >= MAX_REDIRECTS:
            result["findings"].append({
                "check": "Excessive Redirects",
                "status": "WARN",
                "severity": "Medium",
                "description": (
                    f"Redirect chain reached the maximum of {MAX_REDIRECTS} "
                    "hops. This may indicate a misconfiguration."
                ),
            })

        # Check for HTTPS downgrade in redirect chain (critical security issue)
        for i in range(len(chain) - 1):
            if chain[i]["is_https"] and not chain[i + 1]["is_https"]:
                result["findings"].append({
                    "check": "HTTPS Downgrade",
                    "status": "FAIL",
                    "severity": "Critical",
                    "description": (
                        f"Redirect from HTTPS to HTTP detected at step "
                        f"{i + 1}: '{chain[i]['url']}' → '{chain[i + 1]['url']}'. "
                        "This exposes traffic to interception."
                    ),
                })

    except requests.exceptions.Timeout:
        result["findings"].append({
            "check": "Redirect Analysis",
            "status": "FAIL",
            "severity": "High",
            "description": "Request timed out during redirect analysis.",
        })
    except requests.exceptions.RequestException as e:
        result["findings"].append({
            "check": "Redirect Analysis",
            "status": "FAIL",
            "severity": "Medium",
            "description": f"Redirect analysis failed: {str(e)}",
        })

    return result


# ---------------------------------------------------------------------------
# Transport Security Checks
# ---------------------------------------------------------------------------

def check_transport_security(url):
    """
    Check transport-layer security: HTTPS enforcement.
    """
    result = {
        "is_https": url.startswith("https://"),
        "findings": [],
    }

    # Check if site uses HTTPS
    if not result["is_https"]:
        result["findings"].append({
            "check": "HTTPS",
            "status": "FAIL",
            "severity": "High",
            "description": (
                "Site is accessed over plain HTTP. All traffic, including "
                "cookies, credentials, and content, can be intercepted "
                "by attackers."
            ),
            "recommendation": (
                "Serve all content over HTTPS. Obtain a TLS certificate "
                "(e.g., from Let's Encrypt) and redirect all HTTP traffic "
                "to HTTPS."
            ),
        })

    return result


# ---------------------------------------------------------------------------
# Reachability Check
# ---------------------------------------------------------------------------

def check_reachability(url):
    """
    Check if the website is reachable and inspect security-relevant
    response properties.
    """
    result = {
        "reachable": False,
        "status_code": None,
        "response_time_ms": None,
        "server": "",
        "findings": [],
    }

    try:
        start = time.time()

        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "WebGuardScanner/1.0"},
        )

        elapsed = (time.time() - start) * 1000

        result["reachable"] = True
        result["status_code"] = response.status_code
        result["response_time_ms"] = round(elapsed, 2)
        result["server"] = response.headers.get("Server", "")

        # Status code findings
        if response.status_code >= 500:
            result["findings"].append({
                "check": "HTTP Status",
                "status": "FAIL",
                "severity": "High",
                "description": (
                    f"Server returned {response.status_code}. "
                    "This indicates a server-side error."
                ),
            })
        elif response.status_code == 403:
            result["findings"].append({
                "check": "HTTP Status",
                "status": "WARN",
                "severity": "Medium",
                "description": (
                    "Server returned 403 Forbidden. Access is denied, "
                    "possibly due to IP blocking or authentication requirements."
                ),
            })
        elif response.status_code == 401:
            result["findings"].append({
                "check": "HTTP Status",
                "status": "INFO",
                "severity": "Info",
                "description": (
                    "Server returned 401 Unauthorized. Authentication "
                    "is required to access this resource."
                ),
            })

    except requests.exceptions.Timeout:
        result["findings"].append({
            "check": "Reachability",
            "status": "FAIL",
            "severity": "High",
            "description": (
                f"Connection timed out after {REQUEST_TIMEOUT} seconds. "
                "The server may be down or blocking requests."
            ),
        })

    except requests.exceptions.SSLError as e:
        result["findings"].append({
            "check": "SSL/TLS",
            "status": "FAIL",
            "severity": "Critical",
            "description": (
                f"SSL/TLS connection failed: {str(e)}. The server's "
                "certificate may be invalid, expired, or misconfigured."
            ),
        })

    except requests.exceptions.ConnectionError:
        result["findings"].append({
            "check": "Reachability",
            "status": "FAIL",
            "severity": "High",
            "description": (
                "Connection refused or failed. The server may be down, "
                "the port may be closed, or a firewall is blocking access."
            ),
        })

    except requests.exceptions.TooManyRedirects:
        result["findings"].append({
            "check": "Redirects",
            "status": "FAIL",
            "severity": "High",
            "description": (
                "Too many redirects. The server is stuck in a redirect "
                "loop."
            ),
        })

    except requests.exceptions.RequestException as e:
        result["findings"].append({
            "check": "Reachability",
            "status": "FAIL",
            "severity": "Medium",
            "description": f"Request failed: {str(e)}",
        })

    return result


def audit_dns_security(hostname):
    findings = []
    # Skip for direct IPs or local addresses
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) or hostname.lower() in ["localhost", "127.0.0.1"]:
        return findings

    headers = {"Accept": "application/json"}
    
    # 1. Check SPF (TXT records on base hostname)
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={hostname}&type=TXT"
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            answers = data.get("Answer", [])
            has_spf = False
            for ans in answers:
                txt_data = ans.get("data", "")
                if "v=spf1" in txt_data.lower():
                    has_spf = True
                    # Validate SPF configuration
                    if "~all" in txt_data.lower() or "?all" in txt_data.lower():
                        findings.append({
                            "check": "Weak SPF Policy",
                            "status": "WARN",
                            "severity": "Low",
                            "description": f"SPF record '{txt_data}' uses a softfail (~all) or neutral (?all) directive. This permits spoofed emails to pass validation in some spam filters.",
                            "recommendation": "Change the SPF mechanism to hardfail (-all) if appropriate for your mail delivery setup."
                        })
                    break
            if not has_spf:
                findings.append({
                    "check": "Missing SPF Record",
                    "status": "FAIL",
                    "severity": "Medium",
                    "description": f"No Sender Policy Framework (SPF) record was found for '{hostname}'. Attackers can easily send spoofed emails pretending to originate from this domain.",
                    "recommendation": "Configure an SPF TXT record (e.g., 'v=spf1 include:_spf.google.com -all') to authorize specific mail servers."
                })
    except Exception:
        pass

    # 2. Check DMARC (TXT records on _dmarc.hostname)
    try:
        url = f"https://cloudflare-dns.com/dns-query?name=_dmarc.{hostname}&type=TXT"
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            answers = data.get("Answer", [])
            has_dmarc = False
            for ans in answers:
                txt_data = ans.get("data", "")
                if "v=dmarc1" in txt_data.lower():
                    has_dmarc = True
                    # Check policy
                    if "p=none" in txt_data.lower():
                        findings.append({
                            "check": "Weak DMARC Policy",
                            "status": "WARN",
                            "severity": "Low",
                            "description": f"DMARC record '{txt_data}' uses policy 'p=none' (monitoring only). While helpful for testing, it does not instruct receiver servers to block spoofed emails.",
                            "recommendation": "Upgrade DMARC policy from p=none to p=quarantine or p=reject to enforce email authentication."
                        })
                    break
            if not has_dmarc:
                findings.append({
                    "check": "Missing DMARC Record",
                    "status": "FAIL",
                    "severity": "Medium",
                    "description": f"Domain-based Message Authentication, Reporting, and Conformance (DMARC) record is missing for '{hostname}'.",
                    "recommendation": "Publish a DMARC TXT record under '_dmarc.{hostname}' to specify how receivers should handle unauthorized mail."
                })
    except Exception:
        pass

    # 3. Check Subdomain Takeover (CNAME records)
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={hostname}&type=CNAME"
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            answers = data.get("Answer", [])
            for ans in answers:
                cname_target = ans.get("data", "").lower().rstrip(".")
                
                # Check known vulnerable SaaS patterns
                takeover_targets = {
                    "github.io": "GitHub Pages",
                    "herokuapp.com": "Heroku",
                    "s3.amazonaws.com": "AWS S3 Bucket",
                    "myshopify.com": "Shopify Store",
                    "azurewebsites.net": "Azure App Service",
                }
                
                for pattern, saas_name in takeover_targets.items():
                    if pattern in cname_target:
                        # Probe if the target returns a 404/Not Found indicating the SaaS app is deleted but CNAME points to it
                        try:
                            probe_res = requests.get(f"http://{hostname}", timeout=5)
                            # Signatures of deleted SaaS targets
                            signatures = [
                                "There isn't a GitHub Pages site here",
                                "NoSuchBucket",
                                "herokucdn.com/error-pages/no-such-app",
                                "Sorry, this shop is currently unavailable",
                                "404 Not Found"
                            ]
                            if any(sig in probe_res.text for sig in signatures) or probe_res.status_code == 404:
                                findings.append({
                                    "check": f"Subdomain Takeover Opportunity ({saas_name})",
                                    "status": "FAIL",
                                    "severity": "Critical",
                                    "description": f"The domain CNAME points to '{cname_target}' ({saas_name}), but the target service returned a 404/Not Found error. An attacker could register this project on {saas_name} and hijack the subdomain.",
                                    "recommendation": f"Remove the CNAME record in your DNS settings, or claim the resource on the {saas_name} platform."
                                })
                        except Exception:
                            pass
    except Exception:
        pass

    # 4. Check DNSSEC
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={hostname}&type=DS"
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            answers = data.get("Answer", [])
            if not answers:
                findings.append({
                    "check": "Missing DNSSEC Security",
                    "status": "INFO",
                    "severity": "Info",
                    "description": f"DNSSEC is not configured for '{hostname}'. Without DNSSEC, the domain is vulnerable to DNS cache poisoning/spoofing attacks.",
                    "recommendation": "Enable DNSSEC validation at your domain registrar and DNS hosting provider."
                })
    except Exception:
        pass

    return findings


def simulate_dns_rebinding(hostname):
    """
    Query the DNS of the hostname 5 times rapidly.
    Detect if the IPs switch between private and public ranges, or if the TTL is low.
    """
    findings = []
    # Skip for direct IPs or local addresses
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) or hostname.lower() in ["localhost", "127.0.0.1"]:
        return findings

    resolutions = []
    for _ in range(5):
        try:
            addr_infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
            ips = set(info[4][0] for info in addr_infos)
            resolutions.append(ips)
        except Exception:
            resolutions.append(set())
        time.sleep(0.05) # 50ms interval

    # 1. Check for IP Rotation (DNS Rebinding)
    non_empty = [r for r in resolutions if r]
    if len(non_empty) >= 2:
        first_set = non_empty[0]
        rebinding_detected = False
        for next_set in non_empty[1:]:
            if next_set != first_set:
                rebinding_detected = True
                break
        
        if rebinding_detected:
            findings.append({
                "check": "DNS Rebinding Vulnerability (IP Rotation)",
                "status": "FAIL",
                "severity": "Critical",
                "description": f"The domain '{hostname}' resolved to different IP sets across rapid subsequent requests: {[list(x) for x in non_empty]}. This is a high-risk indicator of a DNS Rebinding attack pattern designed to bypass SSRF protections.",
                "recommendation": "Configure static DNS records or enforce DNS resolution caching at the gateway layer."
            })

    # 2. Check for Low TTL via DoH query
    try:
        headers = {"Accept": "application/json"}
        url = f"https://cloudflare-dns.com/dns-query?name={hostname}&type=A"
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            answers = data.get("Answer", [])
            for ans in answers:
                ttl = ans.get("TTL", 300)
                if ttl < 5:
                    findings.append({
                        "check": "DNS Rebinding Vulnerability (Low TTL)",
                        "status": "WARN",
                        "severity": "Medium",
                        "description": f"The domain '{hostname}' publishes an extremely low DNS TTL ({ttl} seconds). Low TTLs are commonly used in DNS rebinding payloads to force browsers to re-resolve hostnames immediately.",
                        "recommendation": "Increase the DNS record TTL to at least 60 seconds unless dynamic IP load balancing is strictly required."
                    })
                    break
    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# Main Analysis Function
# ---------------------------------------------------------------------------

def check_website(url):
    """
    Perform comprehensive URL validation and reachability analysis.

    Includes:
      - URL format validation
      - SSRF protection (blocks private/reserved IPs)
      - DNS resolution analysis
      - Redirect chain tracking
      - Transport security checks (HTTPS, HSTS)
      - Reachability and security-relevant response inspection

    Args:
        url: Target URL to analyze (must include scheme).

    Returns:
        dict with structured analysis report.
    """
    # ---- Step 1: URL Validation ----
    validation = validate_url(url)

    if not validation["valid"]:
        return {
            "status": "Invalid",
            "url": url,
            "valid": False,
            "errors": validation["errors"],
        }

    components = validation["components"]
    hostname = components["hostname"]
    all_findings = []

    # Add any validation warnings as findings
    for warning in validation.get("warnings", []):
        all_findings.append({
            "check": "URL Validation",
            "status": "WARN",
            "severity": "Medium",
            "description": warning,
        })

    # ---- Step 2: SSRF Protection ----
    ssrf_result = check_ssrf(hostname)

    if not ssrf_result["safe"]:
        return {
            "status": "Blocked",
            "url": url,
            "valid": True,
            "blocked": True,
            "reason": "SSRF protection: target resolves to a private or reserved IP address.",
            "findings": ssrf_result["findings"],
        }

    all_findings.extend(ssrf_result["findings"])

    # ---- Step 3: DNS Analysis ----
    dns_result = analyze_dns(hostname)
    all_findings.extend(dns_result["findings"])

    # ---- Step 3.5: DNS Security Audits (SPF, DMARC, DNSSEC, Takeover) ----
    dnssec_findings = audit_dns_security(hostname)
    all_findings.extend(dnssec_findings)

    # ---- Step 3.6: DNS Rebinding Protection Simulation ----
    rebinding_findings = simulate_dns_rebinding(hostname)
    all_findings.extend(rebinding_findings)


    if not dns_result["resolved"]:
        return {
            "status": "DNS Failure",
            "url": url,
            "valid": True,
            "reachable": False,
            "dns": dns_result,
            "findings": all_findings,
        }

    # ---- Step 4: Reachability Check ----
    reachability = check_reachability(url)
    all_findings.extend(reachability["findings"])

    # ---- Step 5: Redirect Chain Analysis ----
    redirect_result = analyze_redirect_chain(url)
    all_findings.extend(redirect_result["findings"])

    # ---- Step 6: Transport Security ----
    transport = check_transport_security(
        redirect_result["final_url"] if redirect_result["final_url"] else url
    )
    all_findings.extend(transport["findings"])

    # ---- Build Response ----
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
        "valid": True,
        "reachable": reachability["reachable"],
        "severity_counts": severity_counts,
        "url_components": components,
        "dns": {
            "resolved": dns_result["resolved"],
            "ipv4": dns_result["ipv4_addresses"],
            "ipv6": dns_result["ipv6_addresses"],
            "resolution_time_ms": dns_result["resolution_time_ms"],
            "ip_address": dns_result["ipv4_addresses"][0] if dns_result["ipv4_addresses"] else (dns_result["ipv6_addresses"][0] if dns_result["ipv6_addresses"] else "N/A"),
        },
        "reachability": {
            "status_code": reachability["status_code"],
            "response_time_ms": reachability["response_time_ms"],
            "server": reachability["server"],
        },
        "redirects": {
            "total": redirect_result["total_redirects"],
            "final_url": redirect_result["final_url"],
            "chain": redirect_result["chain"],
        },
        "transport_security": {
            "is_https": transport["is_https"],
        },
        "findings": all_findings,
    }