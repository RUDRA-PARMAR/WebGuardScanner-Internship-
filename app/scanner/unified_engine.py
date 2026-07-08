"""
WebGuard Unified Scanning Engine
=================================
Orchestrates URL validation, reachability analysis, header analysis,
SSL/TLS assessment, cookie security check, information gathering,
and sensitive exposure discovery into a single unified security report.
"""

import logging
from urllib.parse import urlparse

from app.scanner.validation_reachable import check_website
from app.scanner.header_analysis import full_header_scan
from app.scanner.ssl_analysis import ssl_analysis
from app.scanner.cookie_checker import analyze_cookies
from app.scanner.info_gathering import run_info_gathering
from app.scanner.sensitive_exposure import run_sensitive_exposure

logger = logging.getLogger("WebGuardUnifiedEngine")

def run_full_scan(url):
    """
    Perform a complete security scan of the target URL by executing all modules.
    
    Args:
        url (str): The target website URL.
        
    Returns:
        dict: A comprehensive scan report with consolidated findings.
    """
    # ---- Step 1: URL Validation, SSRF Protection, and Reachability ----
    logger.info(f"Starting base reachability and safety checks for: {url}")
    base_check = check_website(url)
    
    # If the URL validation failed, SSRF blocked it, or the site is completely unreachable,
    # we return early as other modules will fail or be blocked.
    if base_check.get("status") in ["Invalid", "Blocked", "DNS Failure"]:
        return base_check

    # If not reachable, return the base check directly
    if not base_check.get("reachable", False):
        return {
            "status": "Unreachable",
            "url": url,
            "reachable": False,
            "findings": base_check.get("findings", []),
            "severity_counts": base_check.get("severity_counts", {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
            }),
            "base_check": base_check
        }

    all_findings = []
    # Add findings from the base reachability checks
    all_findings.extend(base_check.get("findings", []))

    # Initialize sub-module outputs
    header_res = None
    ssl_res = None
    cookie_res = None
    info_res = None
    sensitive_res = None

    # Determine if SSL analysis is applicable (initial scheme is HTTPS, or final resolved URL after redirects is HTTPS)
    final_url = base_check.get("redirects", {}).get("final_url") or url
    is_https = urlparse(url).scheme.lower() == "https" or urlparse(final_url).scheme.lower() == "https"

    # ---- Step 2: Run Header Analysis ----
    try:
        header_res = full_header_scan(url)
        if header_res.get("status") == "Success":
            all_findings.extend(header_res.get("findings", []))
    except Exception as e:
        logger.error(f"Header scan failed: {e}")
        all_findings.append({
            "check": "Header Scan Error",
            "status": "ERROR",
            "severity": "Low",
            "description": f"Failed to complete header scan: {str(e)}"
        })

    # ---- Step 3: Run SSL/TLS Analysis (if HTTPS) ----
    if is_https:
        try:
            target_ssl_url = final_url if urlparse(final_url).scheme.lower() == "https" else url
            ssl_res = ssl_analysis(target_ssl_url)
            if ssl_res.get("status") == "Success":
                all_findings.extend(ssl_res.get("findings", []))
            elif ssl_res.get("status") == "Error" and "findings" in ssl_res:
                all_findings.extend(ssl_res.get("findings", []))
        except Exception as e:
            logger.error(f"SSL scan failed: {e}")
            all_findings.append({
                "check": "SSL Scan Error",
                "status": "ERROR",
                "severity": "Low",
                "description": f"Failed to complete SSL scan: {str(e)}"
            })

    # ---- Step 4: Run Cookie Checker ----
    try:
        cookie_res = analyze_cookies(url)
        if cookie_res.get("status") == "Success":
            all_findings.extend(cookie_res.get("findings", []))
    except Exception as e:
        logger.error(f"Cookie scan failed: {e}")
        all_findings.append({
            "check": "Cookie Scan Error",
            "status": "ERROR",
            "severity": "Low",
            "description": f"Failed to complete cookie security analysis: {str(e)}"
        })

    # ---- Step 5: Run Info Gathering (robots.txt, HTTP methods) ----
    try:
        info_res = run_info_gathering(url)
        if info_res.get("status") == "Success":
            all_findings.extend(info_res.get("findings", []))
    except Exception as e:
        logger.error(f"Info gathering scan failed: {e}")
        all_findings.append({
            "check": "Info Gathering Scan Error",
            "status": "ERROR",
            "severity": "Low",
            "description": f"Failed to complete info gathering scan: {str(e)}"
        })

    # ---- Step 6: Run Sensitive Exposure Detection (Week 4) ----
    try:
        sensitive_res = run_sensitive_exposure(url)
        if sensitive_res.get("status") == "Success":
            all_findings.extend(sensitive_res.get("findings", []))
    except Exception as e:
        logger.error(f"Sensitive exposure scan failed: {e}")
        all_findings.append({
            "check": "Sensitive Exposure Scan Error",
            "status": "ERROR",
            "severity": "Low",
            "description": f"Failed to complete sensitive exposure scan: {str(e)}"
        })

    # ---- Step 7: Consolidate Severities ----
    severity_counts = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    
    # Deduplicate findings by unique signature (check + description + severity)
    unique_findings = []
    seen_findings = set()
    
    for f in all_findings:
        signature = (f.get("check"), f.get("description"), f.get("severity"))
        if signature not in seen_findings:
            seen_findings.add(signature)
            unique_findings.append(f)
            
            # Count severity
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

    # ---- Step 8: Build Unified Report ----
    return {
        "status": "Success",
        "url": url,
        "reachable": True,
        "total_findings": len(unique_findings),
        "severity_counts": severity_counts,
        "target_details": {
            "dns": base_check.get("dns"),
            "url_components": base_check.get("url_components"),
            "reachability": base_check.get("reachability"),
            "redirects": base_check.get("redirects"),
            "transport_security": base_check.get("transport_security")
        },
        "ssl_tls": {
            "version": ssl_res.get("tls_version") if ssl_res else None,
            "cipher_suite": ssl_res.get("cipher_suite") if ssl_res else None,
            "days_remaining": ssl_res.get("days_remaining") if ssl_res else None,
            "self_signed": ssl_res.get("self_signed") if ssl_res else None
        } if (is_https and ssl_res and ssl_res.get("status") == "Success") else None,
        "robots_txt": info_res.get("robots_txt") if (info_res and info_res.get("status") == "Success") else None,
        "http_methods": info_res.get("http_methods") if (info_res and info_res.get("status") == "Success") else None,
        "findings": unique_findings
    }
