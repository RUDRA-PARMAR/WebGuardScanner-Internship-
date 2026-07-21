"""
WebGuard Automated Virtual Patching (AVP) Engine
================================================
Generates copy-pasteable server mitigation rules (Nginx, Apache, Cloudflare WAF)
based on scan findings to patch vulnerabilities at the infrastructure layer.
"""

import re

def generate_virtual_patches(findings):
    """
    Generate tailored virtual patching configuration rules for Nginx, Apache, and Cloudflare WAF
    based on the scan findings.
    
    Args:
        findings (list): List of finding dicts from the scanner engine.
        
    Returns:
        dict: Mitigations formatted for various server types.
    """
    patches = {
        "nginx": [],
        "apache": [],
        "cloudflare": []
    }
    
    missing_hsts = False
    missing_csp = False
    missing_xframe = False
    missing_xcontent = False
    missing_referrer = False
    insecure_cors = False
    insecure_cookies = []

    for f in findings:
        check_name = f.get("check", "")
        if "HSTS" in check_name:
            missing_hsts = True
        elif "Content Security Policy" in check_name or "CSP" in check_name:
            missing_csp = True
        elif "X-Frame-Options" in check_name:
            missing_xframe = True
        elif "X-Content-Type-Options" in check_name:
            missing_xcontent = True
        elif "Referrer-Policy" in check_name:
            missing_referrer = True
        elif "CORS" in check_name:
            insecure_cors = True
        elif "Cookie" in check_name:
            desc = f.get("description", "")
            m = re.search(r"cookie\s+'([^']+)'", desc, re.IGNORECASE)
            if m:
                insecure_cookies.append(m.group(1))
            else:
                insecure_cookies.append("*")

    # 1. HSTS
    if missing_hsts:
        patches["nginx"].append('add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;')
        patches["apache"].append('Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"')
        patches["cloudflare"].append('Transform Rule -> Response Header: Set "Strict-Transport-Security" to "max-age=31536000; includeSubDomains; preload"')

    # 2. CSP
    if missing_csp:
        patches["nginx"].append('add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\'; frame-ancestors \'none\';" always;')
        patches["apache"].append('Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\'; frame-ancestors \'none\';"')
        patches["cloudflare"].append('Transform Rule -> Response Header: Set "Content-Security-Policy" to "default-src \'self\'; script-src \'self\'; style-src \'self\';"')

    # 3. X-Frame-Options
    if missing_xframe:
        patches["nginx"].append('add_header X-Frame-Options "DENY" always;')
        patches["apache"].append('Header always set X-Frame-Options "DENY"')
        patches["cloudflare"].append('Transform Rule -> Response Header: Set "X-Frame-Options" to "DENY"')

    # 4. X-Content-Type-Options
    if missing_xcontent:
        patches["nginx"].append('add_header X-Content-Type-Options "nosniff" always;')
        patches["apache"].append('Header always set X-Content-Type-Options "nosniff"')
        patches["cloudflare"].append('Transform Rule -> Response Header: Set "X-Content-Type-Options" to "nosniff"')

    # 5. Referrer-Policy
    if missing_referrer:
        patches["nginx"].append('add_header Referrer-Policy "strict-origin-when-cross-origin" always;')
        patches["apache"].append('Header always set Referrer-Policy "strict-origin-when-cross-origin"')
        patches["cloudflare"].append('Transform Rule -> Response Header: Set "Referrer-Policy" to "strict-origin-when-cross-origin"')

    # 6. CORS Wildcard fix
    if insecure_cors:
        patches["nginx"].append(
            '# Secure CORS rule (Verify Origin whitelist before allowing credentials)\n'
            'if ($http_origin ~* (https?://(trusted\\.domain\\.com|another\\.trusted\\.com))) {\n'
            '    add_header Access-Control-Allow-Origin $http_origin always;\n'
            '    add_header Access-Control-Allow-Credentials "true" always;\n'
            '}'
        )
        patches["apache"].append(
            '# Secure CORS Rule\n'
            'SetEnvIf Origin "https?://(trusted\\.domain\\.com|another\\.trusted\\.com)$" AllowedOrigin=$0\n'
            'Header always set Access-Control-Allow-Origin %{AllowedOrigin}e env=AllowedOrigin\n'
            'Header always set Access-Control-Allow-Credentials "true" env=AllowedOrigin'
        )
        patches["cloudflare"].append('WAF Custom Rules -> Block requests with Origin headers matching wildcards when Authorization cookies are present.')

    # 7. Cookie security attributes
    if insecure_cookies:
        cookies_str = "|".join(insecure_cookies) if "*" not in insecure_cookies else ".*"
        patches["nginx"].append(
            f'# Secure Cookie attributes for ({cookies_str})\n'
            'proxy_cookie_path / "/; HttpOnly; Secure; SameSite=Strict";'
        )
        patches["apache"].append(
            f'# Secure Cookie attributes for ({cookies_str})\n'
            'Header edit Set-Cookie "^(.*)$" "$1; HttpOnly; Secure; SameSite=Strict"'
        )
        patches["cloudflare"].append('WAF Managed Rules -> Enable "OWASP Cookie Security" protection rule triggers.')

    # Fallback if no issues found
    if not any(patches.values()):
        patches["nginx"].append("# All assessed security headers conform to strict infrastructure policies.")
        patches["apache"].append("# All assessed security headers conform to strict infrastructure policies.")
        patches["cloudflare"].append("# All assessed security headers conform to strict infrastructure policies.")

    return {
        "status": "Success",
        "nginx": "\n".join(patches["nginx"]),
        "apache": "\n".join(patches["apache"]),
        "cloudflare": "\n".join(patches["cloudflare"])
    }
