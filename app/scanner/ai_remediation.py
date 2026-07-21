"""
WebGuard AI Remediation Agent
=============================
Integrates with the Gemini API (primary) and Blackbox AI API (fallback/alternative)
to explain vulnerabilities identified during scans and generate custom fixes.
"""

import os
import json
import threading
import requests
from app.database import get_scan_detail

# Global in-memory cache for AI responses
AI_CACHE = {}
AI_CACHE_LOCK = threading.Lock()

def get_gemini_remediation(scan_id, user_prompt=None):
    """
    Retrieves the report details, builds a system context prompt, 
    and queries Gemini (or Blackbox AI fallback) for security remediation guides.
    
    Args:
        scan_id (int): Scan ID from the database history.
        user_prompt (str, optional): User's specific question.
        
    Returns:
        dict: The markdown explanation response.
    """
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    blackbox_key = os.getenv("BLACKBOX_API_KEY", "").strip()

    if not gemini_key and not blackbox_key:
        return {
            "status": "Configuration Required",
            "response": (
                "### AI API Key Missing 🔑\n\n"
                "To enable the AI Copilot Remediation Agent, configure `GEMINI_API_KEY` or `BLACKBOX_API_KEY` in your `.env` file.\n\n"
                "1. Open your `.env` file in the workspace root.\n"
                "2. Add your key: `GEMINI_API_KEY=...` or `BLACKBOX_API_KEY=...`\n"
                "3. Restart the server and run scans to chat with the security copilot!"
            )
        }

    # Fetch report
    report = get_scan_detail(scan_id)
    if not report:
        return {
            "status": "Error",
            "response": f"Scan ID {scan_id} not found in database history."
        }

    findings = report.get("findings", [])
    url = report.get("url", "Unknown Target")
    metrics = report.get("severity_counts", {})
    
    # Format simplified findings list for LLM context
    simplified_findings = []
    for idx, f in enumerate(findings):
        simplified_findings.append(
            f"{idx + 1}. [{f.get('severity', 'INFO')}] {f.get('check')}\n"
            f"   Description: {f.get('description')}\n"
            f"   Recommendation: {f.get('recommendation', 'N/A')}\n"
        )
    findings_context = "\n".join(simplified_findings)
 
    # Check if the user prompt is a simple greeting or general conversation
    is_greeting = False
    if user_prompt:
        clean_prompt = user_prompt.strip().lower().strip("?!.")
        greetings = {
            "hi", "hello", "hey", "yo", "greetings", "hola", "who are you", 
            "what is this", "help", "good morning", "good afternoon", "good evening",
            "start", "restart", "welcome"
        }
        if clean_prompt in greetings or len(clean_prompt) < 3:
            is_greeting = True

    if is_greeting:
        system_instruction = (
            "You are Antigravity-Security-Copilot, a friendly and professional security assistant Bot. "
            "The user is greeting you or asking for help. "
            "Your task is to introduce yourself, state that you are ready to assist with the security scan for "
            f"target '{url}' (which has {len(findings)} findings, security score: {report.get('security_score', 0)}/100), "
            "and invite the user to ask about specific findings, vulnerability details, or custom remediation patches. "
            "DO NOT list the individual findings, analyze them, or write any code/remediation blocks in this response. "
            "Keep your greeting short, welcoming, and helpful."
        )
        user_content = f"User greeting: {user_prompt}"
    else:
        # Build system instructions and query for actual analysis
        system_instruction = (
            "You are Antigravity-Security-Copilot, an expert AI Web Security Engineer pair-programming with the user. "
            "Your task is to analyze the security findings from WebGuard Scanner and provide tailored, clear, and actionable remediation steps.\n\n"
            "Here are the details of the target website assessment:\n"
            f"- Target Website: {url}\n"
            f"- Risk Rating: {report.get('risk_rating', 'Unknown')}\n"
            f"- Security Score: {report.get('security_score', 0)}/100\n"
            f"- Severity Summary: {metrics}\n"
            f"- Detected Vulnerabilities:\n{findings_context}\n\n"
            "Provide professional code remedies, infrastructure configurations (Nginx, Apache, Node, PHP, Python), "
            "and explain the impact of these findings. "
            "Be concise, technical, and prioritize security best practices."
        )
        if user_prompt:
            user_content = f"User Question: {user_prompt}"
        else:
            user_content = "Analyze the findings above and provide a comprehensive executive summary of the top critical/high issues and how to remediate them."

    errors = []

    # Scenario A: If Gemini key is available, attempt Gemini request
    if gemini_key:
        url_endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": system_instruction},
                        {"text": user_content}
                    ]
                }
            ]
        }
        headers = {"Content-Type": "application/json"}
        
        try:
            response = requests.post(url_endpoint, json=payload, headers=headers, timeout=12)
            if response.status_code == 200:
                data = response.json()
                candidates = data.get("candidates", [])
                if candidates:
                    text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                    if text_content:
                        res = {
                            "status": "Success",
                            "response": text_content
                        }
                        with AI_CACHE_LOCK:
                            AI_CACHE[cache_key] = res
                        return res
                errors.append(f"Gemini API: Response parsed as empty candidate list.")
            else:
                # Capture API details
                err_text = response.text[:200]
                try:
                    err_json = response.json()
                    err_text = err_json.get("error", {}).get("message", err_text)
                except Exception:
                    pass
                errors.append(f"Gemini API returned HTTP {response.status_code}: {err_text}")
        except Exception as e:
            errors.append(f"Gemini Connection Error: {str(e)}")

    # Scenario B: Try Blackbox fallback/alternative
    if blackbox_key:
        success, result_or_err = query_blackbox_api(system_instruction, user_content, blackbox_key)
        if success:
            res = {
                "status": "Success",
                "response": result_or_err
            }
            with AI_CACHE_LOCK:
                AI_CACHE[cache_key] = res
            return res
        else:
            errors.append(f"Blackbox AI API: {result_or_err}")

    # Build detailed debug error response so the user knows exactly why keys are failing
    err_summary = "\n\n".join([f"- {err}" for err in errors])
    
    return {
        "status": "Error",
        "response": (
            "### AI Connection Error ⚠️\n\n"
            "Failed to reach both Gemini and Blackbox AI APIs. Please review the responses below to verify your API credentials:\n\n"
            f"{err_summary}\n\n"
            "**Tips to resolve:**\n"
            "1. Verify that your `GEMINI_API_KEY` starts with `AIzaSy` (copied from Google AI Studio API Keys).\n"
            "2. Verify that your `BLACKBOX_API_KEY` is active and correct.\n"
            "3. Try switching off VPN connections that might trigger automated anti-bot rate-limiting blocks."
        )
    }

def query_blackbox_api(system_instruction, user_content, blackbox_key):
    """
    Helper function to query Blackbox AI chat completions API.
    Returns:
        tuple (bool, str): (Success status, text response or error string)
    """
    url = "https://api.blackbox.ai/chat/completions"
    headers = {
        "Authorization": f"Bearer {blackbox_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "blackboxai/meta/llama-3.1-8b",  # Valid Llama 3.1 8B model on Blackbox API
        "messages": [
            {"role": "user", "content": f"{system_instruction}\n\n{user_content}"}
        ],
        "max_tokens": 1024
    }
    try:
        res = requests.post(url, json=payload, headers=headers, timeout=15)
        if res.status_code == 200:
            data = res.json()
            choices = data.get("choices", [])
            if choices:
                content = choices[0].get("message", {}).get("content", "")
                if content:
                    return True, content
            return False, "Received empty choices response."
        else:
            return False, f"Returned HTTP {res.status_code}: {res.text[:200]}"
    except Exception as e:
        return False, f"Connection error: {str(e)}"

def generate_ai_patch(scan_id, finding_check, tech_stack):
    """
    Queries Gemini/Blackbox AI to generate a precise remediation patch (code diff/config snippet)
    for a specific scan finding, tailored to a target tech stack (nginx, apache, cloudflare, python, node, php).
    """
    cache_key = f"patch_{scan_id}_{finding_check}_{tech_stack}"
    with AI_CACHE_LOCK:
        if cache_key in AI_CACHE:
            return AI_CACHE[cache_key]
    # 1. Fetch report details
    report = get_scan_detail(scan_id)
    if not report:
        return {"status": "Error", "response": f"Scan ID {scan_id} not found."}
    
    findings = report.get("findings", [])
    finding = None
    for f in findings:
        if f.get("check") == finding_check:
            finding = f
            break
            
    if not finding:
        return {"status": "Error", "response": f"Finding with check '{finding_check}' not found in scan report."}
        
    target_url = report.get("url", "Unknown Target")
    
    # 2. Get API Keys
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    blackbox_key = os.getenv("BLACKBOX_API_KEY", "").strip()
    
    if not gemini_key and not blackbox_key:
        return {
            "status": "Configuration Required",
            "response": "### AI API Key Missing 🔑\n\nTo generate AI Remediation Patches, please configure `GEMINI_API_KEY` or `BLACKBOX_API_KEY` in your `.env` file."
        }
        
    # 3. Construct LLM prompt
    system_instruction = (
        "You are Antigravity-Security-Copilot, an expert AI Web Security Engineer and Remediation Author. "
        f"Your task is to generate precise fix instructions (code snippets, configuration changes, or code diffs) "
        f"for a specific vulnerability identified during a scan of target: {target_url}.\n\n"
        "Vulnerability details:\n"
        f"- Finding Check Name: {finding.get('check', 'Unknown Check')}\n"
        f"- Severity: {finding.get('severity', 'Info')}\n"
        f"- Description: {finding.get('description', 'No description')}\n"
        f"- Recommendation: {finding.get('recommendation', 'N/A')}\n\n"
        f"Generate a remediation guide tailored specifically for the technology stack: {tech_stack.upper()}.\n"
        "Your response MUST contain:\n"
        "1. A brief explanation of why this finding is a risk.\n"
        "2. Copy-pasteable server config lines or code blocks to fix the issue.\n"
        "3. A markdown code block containing a precise diff (using 'diff' language highlighting) or a clear 'Vulnerable' vs 'Secured' side-by-side snippet showing exactly what to remove/add to apply the patch.\n\n"
        "Be extremely technical, concise, and ensure the configuration/code is secure and production-ready. Focus ONLY on this specific finding."
    )
    
    user_content = f"Generate the remediation patch and code/config diff for {finding.get('check')} on stack {tech_stack}."
    
    errors = []
    
    # Try Gemini
    if gemini_key:
        url_endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": system_instruction},
                        {"text": user_content}
                    ]
                }
            ]
        }
        headers = {"Content-Type": "application/json"}
        try:
            response = requests.post(url_endpoint, json=payload, headers=headers, timeout=12)
            if response.status_code == 200:
                data = response.json()
                candidates = data.get("candidates", [])
                if candidates:
                    text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                    if text_content:
                        res = {"status": "Success", "response": text_content}
                        with AI_CACHE_LOCK:
                            AI_CACHE[cache_key] = res
                        return res
                errors.append("Gemini API: Response parsed as empty candidate list.")
            else:
                errors.append(f"Gemini API returned HTTP {response.status_code}: {response.text[:200]}")
        except Exception as e:
            errors.append(f"Gemini Connection Error: {str(e)}")
            
    # Try Blackbox Fallback
    if blackbox_key:
        success, result_or_err = query_blackbox_api(system_instruction, user_content, blackbox_key)
        if success:
            res = {"status": "Success", "response": result_or_err}
            with AI_CACHE_LOCK:
                AI_CACHE[cache_key] = res
            return res
        else:
            errors.append(f"Blackbox AI API: {result_or_err}")
            
    err_summary = "\n\n".join([f"- {err}" for err in errors])
    return {
        "status": "Error",
        "response": f"Failed to reach both Gemini and Blackbox AI APIs:\n\n{err_summary}"
    }

def generate_consolidated_ai_patch(scan_id, tech_stack):
    """
    Consolidates all scan findings for the target and asks the LLM to output a single,
    complete configuration file or patch script to address all issues at once.
    """
    cache_key = f"consolidated_{scan_id}_{tech_stack}"
    with AI_CACHE_LOCK:
        if cache_key in AI_CACHE:
            return AI_CACHE[cache_key]
    # 1. Fetch report details
    report = get_scan_detail(scan_id)
    if not report:
        return {"status": "Error", "response": f"Scan ID {scan_id} not found."}
        
    findings = report.get("findings", [])
    if not findings:
        return {"status": "Success", "response": "No findings detected. No consolidated patch is required!"}
        
    target_url = report.get("url", "Unknown Target")
    
    # Format simplified findings list
    simplified_findings = []
    for idx, f in enumerate(findings):
        simplified_findings.append(
            f"{idx + 1}. [{f.get('severity', 'INFO')}] {f.get('check')}\n"
            f"   Description: {f.get('description')}\n"
        )
    findings_context = "\n".join(simplified_findings)
    
    # 2. Get API Keys
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    blackbox_key = os.getenv("BLACKBOX_API_KEY", "").strip()
    
    if not gemini_key and not blackbox_key:
        return {
            "status": "Configuration Required",
            "response": "### AI API Key Missing 🔑\n\nTo generate AI Remediation Patches, please configure `GEMINI_API_KEY` or `BLACKBOX_API_KEY` in your `.env` file."
        }
        
    # 3. Construct LLM prompt
    system_instruction = (
        "You are Antigravity-Security-Copilot, an expert AI Web Security Engineer and Remediation Author.\n\n"
        f"The user has run a security scan on target website: {target_url}\n"
        "Here are all detected vulnerabilities:\n"
        f"{findings_context}\n\n"
        f"Your task is to generate a SINGLE, CONSOLIDATED security configuration file or patch script tailored for the technology stack: {tech_stack.upper()} that resolves all of these findings at once.\n\n"
        "Depending on the tech stack requested, please output:\n"
        "- For Nginx: A complete, copy-pasteable server block configuration (or list of directives) enclosing HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, secure cookie directives, and secure CORS blocks.\n"
        "- For Apache: A complete, copy-pasteable `.htaccess` or virtual host configuration containing all relevant Header set/edit rules and CORS blocks.\n"
        "- For Cloudflare WAF: A consolidated list of Custom Rules and Transformation Rules to implement in Cloudflare to mitigate these headers/cookies issues.\n"
        "- For Python: A complete security middleware or configuration wrapper (e.g. using `Secure` library or manual header/cookie setters for Flask/FastAPI) that enforces all these controls.\n"
        "- For Node.js: A complete Express security middleware configuration (e.g., configuring `helmet` and custom middlewares) resolving all these findings.\n"
        "- For PHP: A complete, single `security_headers.php` file containing `header()` calls and cookie configurations that should be prepended/included in PHP scripts.\n\n"
        "Your response MUST contain:\n"
        "1. A high-level explanation of how this consolidated configuration protects the application.\n"
        "2. The complete, copy-pasteable configuration file or script code block with comments detailing which parts address which finding.\n"
        "3. Step-by-step instructions on where to place the file and how to reload the server/application to apply the changes.\n\n"
        "Be technical, clear, and prioritize security best practices."
    )
    
    user_content = f"Generate the consolidated security patch for target {target_url} on stack {tech_stack}."
    
    errors = []
    
    # Try Gemini
    if gemini_key:
        url_endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": system_instruction},
                        {"text": user_content}
                    ]
                }
            ]
        }
        headers = {"Content-Type": "application/json"}
        try:
            response = requests.post(url_endpoint, json=payload, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                candidates = data.get("candidates", [])
                if candidates:
                    text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                    if text_content:
                        res = {"status": "Success", "response": text_content}
                        with AI_CACHE_LOCK:
                            AI_CACHE[cache_key] = res
                        return res
                errors.append("Gemini API: Response parsed as empty candidate list.")
            else:
                errors.append(f"Gemini API returned HTTP {response.status_code}: {response.text[:200]}")
        except Exception as e:
            errors.append(f"Gemini Connection Error: {str(e)}")
            
    # Try Blackbox Fallback
    if blackbox_key:
        success, result_or_err = query_blackbox_api(system_instruction, user_content, blackbox_key)
        if success:
            res = {"status": "Success", "response": result_or_err}
            with AI_CACHE_LOCK:
                AI_CACHE[cache_key] = res
            return res
        else:
            errors.append(f"Blackbox AI API: {result_or_err}")
            
    err_summary = "\n\n".join([f"- {err}" for err in errors])
    return {
        "status": "Error",
        "response": f"Failed to reach both Gemini and Blackbox AI APIs:\n\n{err_summary}"
    }

