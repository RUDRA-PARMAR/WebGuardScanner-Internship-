"""
WebGuard Unified Scanning Engine
=================================
Orchestrates URL validation, reachability analysis, header analysis,
SSL/TLS assessment, cookie security check, information gathering,
sensitive exposure discovery, and active vulnerability probing into a single unified report.
"""

import logging
from urllib.parse import urlparse

from app.scanner.validation_reachable import check_website
from app.scanner.header_analysis import full_header_scan
from app.scanner.ssl_analysis import ssl_analysis
from app.scanner.cookie_checker import analyze_cookies
from app.scanner.info_gathering import run_info_gathering
from app.scanner.sensitive_exposure import run_sensitive_exposure
from app.scanner.virtual_patching import generate_virtual_patches
from app.scanner.script_integrity import run_script_integrity_scan
from app.scanner.supply_chain import run_supply_chain_scan
from app.database import get_latest_report_for_url

logger = logging.getLogger("WebGuardUnifiedEngine")

def run_full_scan(url, profile="full"):
    """
    Perform a complete security scan of the target URL by executing all modules.
    
    Args:
        url (str): The target website URL.
        profile (str): The scan profile ("full", "fast", "ssl", or "headers").
        
    Returns:
        dict: A comprehensive scan report with consolidated findings.
    """
    # ---- Step 1: URL Validation, SSRF Protection, and Reachability ----
    logger.info(f"Starting base reachability and safety checks for: {url} (Profile: {profile})")
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
    active_findings = []

    # Determine if SSL analysis is applicable (initial scheme is HTTPS, or final resolved URL after redirects is HTTPS)
    final_url = base_check.get("redirects", {}).get("final_url") or url
    is_https = urlparse(url).scheme.lower() == "https" or urlparse(final_url).scheme.lower() == "https"

    # Profile logic settings
    run_headers = profile in ["full", "fast", "headers"]
    run_ssl = is_https and profile in ["full", "fast", "ssl"]
    run_cookies = profile in ["full", "fast", "headers"]
    run_info = profile in ["full", "fast"]
    run_sensitive = profile in ["full"]
    run_active = profile in ["full"]

    # ---- Pre-fetch Shared HTML for HTML-dependent modules ----
    shared_html = None
    if profile in ["full", "fast"]:
        try:
            import requests
            headers = {"User-Agent": "WebGuardScanner/1.0"}
            resp = requests.get(final_url, headers=headers, timeout=10)
            if resp.status_code == 200:
                shared_html = resp.text
        except Exception as e:
            logger.warning(f"Could not pre-fetch shared HTML for {final_url}: {e}")

    # ---- Step 2 to 6.7: Parallel Sub-Module Execution ----
    from concurrent.futures import ThreadPoolExecutor, as_completed

    supply_chain_components = []
    futures = {}

    with ThreadPoolExecutor(max_workers=8) as executor:
        if run_headers:
            futures[executor.submit(full_header_scan, final_url)] = "header"
        if run_ssl:
            target_ssl_url = final_url if urlparse(final_url).scheme.lower() == "https" else url
            futures[executor.submit(ssl_analysis, target_ssl_url)] = "ssl"
        if run_cookies:
            futures[executor.submit(analyze_cookies, final_url)] = "cookie"
        if run_info:
            futures[executor.submit(run_info_gathering, final_url)] = "info"
        if run_sensitive:
            futures[executor.submit(run_sensitive_exposure, final_url)] = "sensitive"
        if profile == "full":
            prev_report = get_latest_report_for_url(url)
            futures[executor.submit(run_script_integrity_scan, final_url, html_content=shared_html, previous_scan_report=prev_report)] = "script"
            futures[executor.submit(run_supply_chain_scan, final_url, html_content=shared_html)] = "supply_chain"

        for future in as_completed(futures):
            mod_name = futures[future]
            try:
                res = future.result()
                if res and isinstance(res, dict):
                    if res.get("status") == "Success":
                        all_findings.extend(res.get("findings", []))
                        if mod_name == "header":
                            header_res = res
                        elif mod_name == "ssl":
                            ssl_res = res
                        elif mod_name == "cookie":
                            cookie_res = res
                        elif mod_name == "info":
                            info_res = res
                        elif mod_name == "sensitive":
                            sensitive_res = res
                        elif mod_name == "supply_chain":
                            supply_chain_components = res.get("components", [])
                    elif res.get("status") == "Error" and "findings" in res:
                        all_findings.extend(res.get("findings", []))
            except Exception as e:
                logger.error(f"{mod_name} scan failed: {e}")
                all_findings.append({
                    "check": f"{mod_name.capitalize()} Scan Error",
                    "status": "ERROR",
                    "severity": "Low",
                    "description": f"Failed to complete {mod_name} scan: {str(e)}"
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

    # ---- Step 7.5: Generate Virtual Patches ----
    patches = generate_virtual_patches(unique_findings)

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
        "findings": unique_findings,
        "virtual_patches": patches,
        "supply_chain_components": supply_chain_components
    }
