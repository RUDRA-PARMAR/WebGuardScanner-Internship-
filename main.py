import os  # reload-trigger-secure

# Load .env file if it exists
if os.path.exists(".env"):
    with open(".env", "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                k = key.strip()
                os.environ[k] = val.strip().strip('"').strip("'")


import json
from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse
from app.scanner.validation_reachable import check_website
from app.scanner.header_analysis import full_header_scan
from app.scanner.ssl_analysis import ssl_analysis
from app.scanner.cookie_checker import analyze_cookies
from app.scanner.info_gathering import run_info_gathering
from app.scanner.sensitive_exposure import run_sensitive_exposure
from app.scanner.unified_engine import run_full_scan

from app.scanner.pdf_generator import generate_pdf_report
from app.database import init_db, save_scan, get_history, get_scan_detail
from app.scanner.script_integrity import run_script_integrity_scan
from app.scanner.supply_chain import run_supply_chain_scan
from app.scanner.ai_remediation import get_gemini_remediation

from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.mount("/static", StaticFiles(directory="app/static"), name="static")

import threading
max_scans = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
scan_semaphore = threading.Semaphore(max_scans)

@app.on_event("startup")
def startup_event():
    init_db()

@app.get("/", response_class=HTMLResponse)
def home():
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "templates", "index.html")
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error loading homepage: {str(e)}</h3>", status_code=500)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "templates", "dashboard.html")
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error loading dashboard: {str(e)}</h3>", status_code=500)

@app.get("/scan")
def scan(url:str):
   try:
      return check_website(url)
   except Exception as e:
      return {
         "status": "Error",
         "error": f"Scan failed: {str(e)}",
         "url": url
      }

@app.get("/headers")
def header_scan(url:str):
   return full_header_scan(url)

@app.get("/ssl")
def ssl_scan(url:str):
   return ssl_analysis(url)

@app.get("/cookies")
def cookie_scan(url:str):
   try:
      return analyze_cookies(url)
   except Exception as e:
      return {
         "status": "Error",
         "error": f"Cookie analysis failed: {str(e)}",
         "url": url
      }

@app.get("/info")
def info_scan(url:str):
   try:
      return run_info_gathering(url)
   except Exception as e:
      return {
         "status": "Error",
         "error": f"Information gathering failed: {str(e)}",
         "url": url
      }

@app.get("/sensitive_exposure")
def sensitive_exposure_scan(url:str):
   try:
      return run_sensitive_exposure(url)
   except Exception as e:
      return {
         "status": "Error",
         "error": f"Sensitive exposure analysis failed: {str(e)}",
         "url": url
      }

@app.get("/full_scan")
def full_scan(url: str):
    return api_run_scan(url, profile="full")

# --- Primary Unified Scanning API ---

@app.api_route("/api/scan", methods=["GET", "POST"])
def api_run_scan(url: str, profile: str = "full"):
    try:
        with scan_semaphore:
            report = run_full_scan(url, profile=profile)
        
        # Save all scans (even failed/blocked ones) to database so they appear in history!
        scan_id = save_scan(url, report)
        report["id"] = scan_id
        
        # Add security score and risk rating into response as well
        report["security_score"] = report.get("security_score", 100)
        report["risk_rating"] = report.get("risk_rating", "Safe")
        
        return report
    except Exception as e:
        return {
            "status": "Error",
            "error": f"API Scan failed: {str(e)}",
            "url": url
        }

@app.get("/api/history")
def api_history():
    try:
        return get_history()
    except Exception as e:
        return {"status": "Error", "error": f"Failed to retrieve history: {str(e)}"}

@app.get("/api/scan/scripts")
def api_scan_scripts(url: str):
    try:
        from app.database import get_latest_report_for_url
        prev_report = get_latest_report_for_url(url)
        return run_script_integrity_scan(url, previous_scan_report=prev_report)
    except Exception as e:
        return {"status": "Error", "error": f"Script integrity scan failed: {str(e)}"}

@app.get("/api/scan/supply_chain")
def api_supply_chain(url: str):
    try:
        return run_supply_chain_scan(url)
    except Exception as e:
        return {"status": "Error", "error": f"Supply-chain scan failed: {str(e)}"}

@app.get("/api/scan/{scan_id}")
def api_scan_detail(scan_id: int):
    try:
        report = get_scan_detail(scan_id)
        if report:
            report["id"] = scan_id
            return report
        return {"status": "Error", "error": "Scan report not found"}
    except Exception as e:
        return {"status": "Error", "error": f"Failed to retrieve scan detail: {str(e)}"}

@app.get("/api/scan/{scan_id}/pdf")
def api_scan_pdf(scan_id: int):
    try:
        report = get_scan_detail(scan_id)
        if not report:
            return {"status": "Error", "error": "Scan report not found"}
        
        pdf_bytes = generate_pdf_report(report)
        headers = {
            'Content-Disposition': f'attachment; filename="webguard_report_{scan_id}.pdf"'
        }
        return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)
    except Exception as e:
        return {"status": "Error", "error": f"Failed to generate PDF: {str(e)}"}

@app.get("/api/scan/{scan_id}/json")
def api_scan_json(scan_id: int):
    try:
        report = get_scan_detail(scan_id)
        if not report:
            return {"status": "Error", "error": "Scan report not found"}
            
        headers = {
            'Content-Disposition': f'attachment; filename="webguard_report_{scan_id}.json"'
        }
        return Response(content=json.dumps(report, indent=2), media_type="application/json", headers=headers)
    except Exception as e:
        return {"status": "Error", "error": f"Failed to export JSON: {str(e)}"}



@app.post("/api/scan/remediate")
def api_remediate(scan_id: int, user_prompt: str = None):
    try:
        return get_gemini_remediation(scan_id, user_prompt)
    except Exception as e:
        return {"status": "Error", "error": f"Remediation query failed: {str(e)}"}

@app.post("/api/scan/remediate/generate_patch")
def api_generate_patch(scan_id: int, finding_check: str, tech: str):
    try:
        from app.scanner.ai_remediation import generate_ai_patch
        return generate_ai_patch(scan_id, finding_check, tech)
    except Exception as e:
        return {"status": "Error", "error": f"Failed to generate patch: {str(e)}"}

@app.post("/api/scan/remediate/consolidated_patch")
def api_consolidated_patch(scan_id: int, tech: str):
    try:
        from app.scanner.ai_remediation import generate_consolidated_ai_patch
        return generate_consolidated_ai_patch(scan_id, tech)
    except Exception as e:
        return {"status": "Error", "error": f"Failed to generate consolidated patch: {str(e)}"}

@app.delete("/api/scan/{scan_id}")
def api_delete_scan(scan_id: int):
    try:
        from app.database import delete_scan, get_scan_detail
        report = get_scan_detail(scan_id)
        if not report:
            return {"status": "Error", "error": "Scan report not found"}
        delete_scan(scan_id)
        return {"status": "Success", "message": f"Scan {scan_id} deleted successfully"}
    except Exception as e:
        return {"status": "Error", "error": f"Failed to delete scan: {str(e)}"}