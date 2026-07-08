import os
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

# Week 5 Imports
from app.database import init_db, save_scan, get_history, get_scan_detail
from app.scanner.pdf_generator import generate_pdf_report

from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.mount("/static", StaticFiles(directory="app/static"), name="static")

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
def full_scan(url:str):
   try:
      return run_full_scan(url)
   except Exception as e:
      return {
         "status": "Error",
         "error": f"Unified scan failed: {str(e)}",
         "url": url
      }

# --- Week 5 API Endpoints ---

@app.post("/api/scan")
def api_run_scan(url: str):
    try:
        report = run_full_scan(url)
        # Check if the scan itself returned an early exit status
        if report.get("status") in ["Invalid", "Blocked", "DNS Failure"] or not report.get("reachable", False):
            return report
        
        # Save valid scans to the history database
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
            
        if "security_score" in report:
            report.pop("security_score")
            
        headers = {
            'Content-Disposition': f'attachment; filename="webguard_report_{scan_id}.json"'
        }
        return Response(content=json.dumps(report, indent=2), media_type="application/json", headers=headers)
    except Exception as e:
        return {"status": "Error", "error": f"Failed to export JSON: {str(e)}"}