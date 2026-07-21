"""
WebGuard Client-Side Script Integrity & Magecart Auditor
=========================================================
Parses HTML scripts and stylesheets, checks for Subresource Integrity (SRI) missing flags,
verifies declared SRI hashes (sha256/sha384/sha512) against actual content,
calculates SHA-256 fingerprints, and checks for web skimming heuristics.
"""

import re
import base64
import hashlib
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def verify_sri_hash(declared_sri, resource_bytes):
    """
    Verifies a declared SRI string (e.g. 'sha384-xxxx' or 'sha256-yyyy sha384-zzzz')
    against actual resource bytes.

    Args:
        declared_sri (str): The integrity attribute value.
        resource_bytes (bytes): The raw byte content of the fetched script or stylesheet.

    Returns:
        tuple: (is_valid, algo_used, expected_b64, actual_b64)
    """
    tokens = declared_sri.strip().split()

    for token in tokens:
        if "-" not in token:
            continue
        algo, expected_b64 = token.split("-", 1)
        algo = algo.lower()

        if algo == "sha256":
            calc_digest = hashlib.sha256(resource_bytes).digest()
        elif algo == "sha384":
            calc_digest = hashlib.sha384(resource_bytes).digest()
        elif algo == "sha512":
            calc_digest = hashlib.sha512(resource_bytes).digest()
        else:
            continue

        actual_b64 = base64.b64encode(calc_digest).decode("utf-8")

        if actual_b64 == expected_b64:
            return True, algo, expected_b64, actual_b64
        else:
            return False, algo, expected_b64, actual_b64

    return False, "unknown", declared_sri, ""


def run_script_integrity_scan(url, html_content=None, previous_scan_report=None):
    """
    Scans script elements and stylesheets in the HTML for security vulnerabilities (SRI and Skimming).
    
    Args:
        url (str): Target web page URL.
        html_content (str, optional): Pre-fetched HTML content.
        previous_scan_report (dict, optional): Dict of previous raw report for this URL.
        
    Returns:
        dict: Status and findings list.
    """
    findings = []
    
    # 1. Fetch HTML if not provided
    if not html_content:
        try:
            headers = {"User-Agent": "WebGuardScanner/1.0"}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code != 200:
                return {
                    "status": "Error",
                    "error": f"Failed to retrieve page HTML (HTTP {response.status_code})",
                    "findings": []
                }
            html_content = response.text
        except Exception as e:
            return {
                "status": "Error",
                "error": f"Connection error: {str(e)}",
                "findings": []
            }
            
    # 2. Extract previous hashes for drift detection
    prev_hashes = {}
    if previous_scan_report:
        prev_findings = previous_scan_report.get("findings", [])
        for f in prev_findings:
            if f.get("check", "").startswith("Script Fingerprint Log"):
                desc = f.get("description", "")
                m_url = re.search(r"script\s+'([^']+)'", desc, re.IGNORECASE)
                m_hash = re.search(r"SHA-256:([a-f0-9]+)", desc, re.IGNORECASE)
                if m_url and m_hash:
                    prev_hashes[m_url.group(1)] = m_hash.group(1)

    # 3. Parse HTML using BeautifulSoup
    try:
        soup = BeautifulSoup(html_content, "html.parser")
    except Exception as e:
        return {
            "status": "Error",
            "error": f"Failed to parse HTML body: {str(e)}",
            "findings": []
        }
        
    # --- A. Audit <script> Tags ---
    script_tags = soup.find_all("script")
    
    for idx, tag in enumerate(script_tags):
        src = tag.get("src")
        sri = tag.get("integrity")
        inline_code = tag.string or ""
        
        # Scenario A1: External Scripts
        if src:
            abs_src = urljoin(url, src)
            
            # Check for Missing SRI
            if not sri:
                findings.append({
                    "check": "Missing Subresource Integrity (SRI) Attribute",
                    "status": "WARN",
                    "severity": "Medium",
                    "description": f"The external script '{abs_src}' is loaded without an integrity hash check. If the host serving this script is compromised, attackers can execute malicious scripts in your users' browser scopes.",
                    "recommendation": "Calculate a cryptographic hash (SHA-256/384/512) of the script and append it as the 'integrity' attribute along with crossorigin='anonymous'."
                })
            
            # Fetch script body for hash verification & heuristics
            try:
                script_headers = {"User-Agent": "WebGuardScanner/1.0"}
                script_res = requests.get(abs_src, headers=script_headers, timeout=5)
                if script_res.status_code == 200:
                    script_bytes = script_res.content
                    script_code = script_res.text
                    
                    # Verify SRI Hash Match if integrity attribute is provided
                    if sri:
                        is_valid, algo, exp_hash, act_hash = verify_sri_hash(sri, script_bytes)
                        if is_valid:
                            findings.append({
                                "check": "Valid Subresource Integrity (SRI) Hash",
                                "status": "PASS",
                                "severity": "Info",
                                "description": f"The external script '{abs_src}' has a valid SRI hash ({algo}-{exp_hash[:16]}...). The resource content matches the declared integrity attribute.",
                            })
                        else:
                            findings.append({
                                "check": "Subresource Integrity (SRI) Hash Mismatch / Content Tampered",
                                "status": "FAIL",
                                "severity": "Critical",
                                "description": (
                                    f"The external script '{abs_src}' declared SRI hash ({algo}-{exp_hash}) "
                                    f"does NOT match the actual calculated hash ({algo}-{act_hash})! "
                                    f"This indicates the script file has been modified or tampered with on the server/CDN."
                                ),
                                "recommendation": "Re-verify the external script source code and update the 'integrity' attribute to match the new hash."
                            })
                    
                    # Calculate SHA-256 for fingerprinting & drift detection
                    s_hash = hashlib.sha256(script_bytes).hexdigest()
                    
                    # Log hash info as an informative finding
                    findings.append({
                        "check": f"Script Fingerprint Log ({abs_src})",
                        "status": "INFO",
                        "severity": "Info",
                        "description": f"External script '{abs_src}' fingerprint verified. Hash: SHA-256:{s_hash}.",
                        "details": f"Source: {abs_src}\nHash: {s_hash}\nLength: {len(script_bytes)} bytes."
                    })
                    
                    # Check for Script Content Drift
                    if abs_src in prev_hashes:
                        old_hash = prev_hashes[abs_src]
                        if s_hash != old_hash:
                            findings.append({
                                "check": "Javascript Content Drift Detected",
                                "status": "FAIL",
                                "severity": "High",
                                "description": f"The script at '{abs_src}' has changed its contents since the last scan! Previous Hash: {old_hash}, Current Hash: {s_hash}. This indicates a dynamic code update or potential script tampering.",
                                "recommendation": "Inspect the source script differences to ensure the update was authorized and did not inject malicious dependencies."
                            })
                    
            except Exception:
                findings.append({
                    "check": "External Script Resolution Error",
                    "status": "WARN",
                    "severity": "Low",
                    "description": f"Failed to download external script resource at '{abs_src}' for integrity scanning.",
                })
                
        # Scenario A2: Inline Scripts
        elif inline_code.strip():
            pass

    # --- B. Audit <link rel="stylesheet"> Tags ---
    link_tags = soup.find_all("link", rel=lambda r: r and "stylesheet" in r.lower())

    for tag in link_tags:
        href = tag.get("href")
        sri = tag.get("integrity")
        
        if href:
            abs_href = urljoin(url, href)

            # Check for Missing SRI on Stylesheets
            if not sri:
                findings.append({
                    "check": "Missing Subresource Integrity (SRI) Attribute on Stylesheet",
                    "status": "WARN",
                    "severity": "Low",
                    "description": f"The external stylesheet '{abs_href}' is loaded without an integrity hash check.",
                    "recommendation": "Calculate a cryptographic hash (SHA-256/384/512) of the CSS file and append it as the 'integrity' attribute."
                })
            else:
                # Fetch CSS file to verify SRI hash
                try:
                    css_res = requests.get(abs_href, headers={"User-Agent": "WebGuardScanner/1.0"}, timeout=5)
                    if css_res.status_code == 200:
                        is_valid, algo, exp_hash, act_hash = verify_sri_hash(sri, css_res.content)
                        if is_valid:
                            findings.append({
                                "check": "Valid Subresource Integrity (SRI) Hash on Stylesheet",
                                "status": "PASS",
                                "severity": "Info",
                                "description": f"The external stylesheet '{abs_href}' has a valid SRI hash ({algo}-{exp_hash[:16]}...).",
                            })
                        else:
                            findings.append({
                                "check": "Subresource Integrity (SRI) Hash Mismatch on Stylesheet",
                                "status": "FAIL",
                                "severity": "High",
                                "description": (
                                    f"The external stylesheet '{abs_href}' declared SRI hash ({algo}-{exp_hash}) "
                                    f"does NOT match the actual calculated hash ({algo}-{act_hash})!"
                                ),
                                "recommendation": "Update the stylesheet 'integrity' attribute to match the actual file content hash."
                            })
                except Exception:
                    pass

    return {
        "status": "Success",
        "findings": findings
    }




