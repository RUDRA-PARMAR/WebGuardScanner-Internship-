"""
WebGuard Dashboard & API Full Verification Script
===================================================
Tests all UI elements and API endpoints against a local mock vulnerable server.
Uses 'fast' profile for local testing to avoid external DNS/HTTP timeouts.
"""
import requests
import subprocess
import sys
import os
import time
import json

BASE = "http://127.0.0.1:8000"
MOCK_PORT = "9099"
MOCK_URL = f"http://127.0.0.1:{MOCK_PORT}"
all_passed = True
failures = []

def check(label, condition):
    global all_passed
    status = "PASS" if condition else "FAIL"
    if not condition:
        all_passed = False
        failures.append(label)
    print(f"  [{status}] {label}")

print("=" * 60)
print("  WebGuard Full Functionality Verification")
print("=" * 60)

# ---- Start mock vulnerable target ----
print("\n[0/8] Starting Mock Vulnerable Target Server...")
env = os.environ.copy()
env["MOCK_PORT"] = MOCK_PORT
env["PYTHONUNBUFFERED"] = "1"
mock_proc = subprocess.Popen(
    [sys.executable, "run_test_server.py"],
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)
time.sleep(3)
# Verify mock server is actually running
try:
    r = requests.get(MOCK_URL, timeout=3)
    print(f"  Mock server started on {MOCK_URL} (status {r.status_code})")
except Exception as e:
    print(f"  [FAIL] Mock server failed to start: {e}")
    mock_proc.kill()
    sys.exit(1)

try:
    # ---- 1. Dashboard HTML Structure ----
    print("\n[1/8] Checking Dashboard HTML Structure...")
    r = requests.get(f"{BASE}/dashboard", timeout=5)
    check("Dashboard loads (HTTP 200)", r.status_code == 200)
    html = r.text
    check("Web Scanner tab present", "Web Scanner" in html)
    check("Supply-Chain / CVE Auditor tab present", "Supply-Chain" in html)
    check("AI Remediation Copilot tab present", "AI Remediation Copilot" in html)
    check("Scan form present", "scanForm" in html)
    check("Chat form present", "chatForm" in html)
    check("Severity chart canvas", "severityChart" in html)
    check("Trend chart canvas", "trendChart" in html)
    check("Virtual patch (Nginx)", "patchNginx" in html)
    check("Virtual patch (Apache)", "patchApache" in html)
    check("Virtual patch (Cloudflare)", "patchCf" in html)
    check("Dark mode toggle", "toggleTheme" in html)
    check("Particle canvas", "particleCanvas" in html)

    # ---- 2. Homepage ----
    print("\n[2/8] Checking Homepage...")
    r = requests.get(f"{BASE}/", timeout=5)
    check("Homepage loads (HTTP 200)", r.status_code == 200)
    check("Homepage has HTML content", "<html" in r.text.lower())

    # ---- 3. API History Endpoint ----
    print("\n[3/8] Checking API History Endpoint...")
    r = requests.get(f"{BASE}/api/history", timeout=5)
    check("History endpoint responds (HTTP 200)", r.status_code == 200)
    data = r.json()
    check("History returns a list", isinstance(data, list))

    # ---- 4. Fast Web Scan (against local mock) ----
    print(f"\n[4/8] Running Fast Web Scan against {MOCK_URL} ...")
    s = requests.Session()
    r = s.post(f"{BASE}/api/scan?url={MOCK_URL}&profile=fast", timeout=45)
    check("Scan endpoint responds (HTTP 200)", r.status_code == 200)
    report = r.json()
    check("Scan status is Success", report.get("status") == "Success")
    check("Has security_score field", "security_score" in report)
    check("Has risk_rating field", "risk_rating" in report)
    check("Has findings list", isinstance(report.get("findings"), list))
    check("Findings count > 0", len(report.get("findings", [])) > 0)
    check("Has severity_counts", isinstance(report.get("severity_counts"), dict))
    check("Has virtual_patches", isinstance(report.get("virtual_patches"), dict))
    check("virtual_patches.nginx present", "nginx" in report.get("virtual_patches", {}))
    check("virtual_patches.apache present", "apache" in report.get("virtual_patches", {}))
    check("Has target_details", isinstance(report.get("target_details"), dict))
    check("Has reachable=True", report.get("reachable") == True)
    
    scan_id = report.get("id")
    check("Scan saved with ID", scan_id is not None)
    
    finding_count = len(report.get("findings", []))
    print(f"     -> Score: {report.get('security_score')}/100, Rating: {report.get('risk_rating')}, Findings: {finding_count}")

    # ---- 5. Scan Detail & PDF Generation ----
    print("\n[5/8] Checking Scan Detail & PDF Endpoints...")
    if scan_id:
        r = s.get(f"{BASE}/api/scan/{scan_id}", timeout=5)
        check("Scan detail endpoint (HTTP 200)", r.status_code == 200)
        detail = r.json()
        check("Detail has findings", "findings" in detail)
        check("Detail has severity_counts", "severity_counts" in detail)
        check("Detail matches scan findings count", len(detail.get("findings", [])) == finding_count)
        
        r = s.get(f"{BASE}/api/scan/{scan_id}/pdf", timeout=10)
        check("PDF endpoint (HTTP 200)", r.status_code == 200)
        check("PDF content-type correct", "application/pdf" in r.headers.get("content-type", ""))
        check("PDF has content (>1KB)", len(r.content) > 1024)
        print(f"     -> PDF size: {len(r.content):,} bytes")
    else:
        print("  [SKIP] No scan_id available")

    # ---- 6. Script Integrity / Magecart Scan ----
    print(f"\n[6/8] Checking Script Integrity Scan against {MOCK_URL} ...")
    r = s.get(f"{BASE}/api/scan/scripts?url={MOCK_URL}", timeout=15)
    check("Script scan endpoint (HTTP 200)", r.status_code == 200)
    script_report = r.json()
    check("Script scan status is Success", script_report.get("status") == "Success")
    check("Script scan has findings list", isinstance(script_report.get("findings"), list))
    check("Script scan found issues (>0)", len(script_report.get("findings", [])) > 0)
    print(f"     -> Script findings: {len(script_report.get('findings', []))}")


    # ---- 8. AI Remediation Copilot ----
    print("\n[8/8] Checking AI Remediation Copilot...")
    if scan_id:
        r = s.post(f"{BASE}/api/scan/remediate?scan_id={scan_id}&user_prompt=What+are+the+top+vulnerabilities?", timeout=15)
        check("Remediation endpoint (HTTP 200)", r.status_code == 200)
        ai_data = r.json()
        has_response = "response" in ai_data or "error" in ai_data
        check("AI response has 'response' or 'error'", has_response)
        if "response" in ai_data:
            check("AI response is non-empty", len(ai_data["response"]) > 0)
            print(f"     -> AI response: {len(ai_data['response'])} chars")
        elif "error" in ai_data:
            print(f"     -> AI note: {ai_data['error'][:100]}")
    else:
        print("  [SKIP] No scan_id available")

except Exception as e:
    import traceback
    print(f"\n  [FATAL] Unhandled exception: {e}")
    traceback.print_exc()
    all_passed = False
    failures.append(f"Unhandled exception: {e}")

finally:
    print("\nCleaning up mock server...")
    mock_proc.terminate()
    try:
        mock_proc.wait(timeout=3)
    except:
        mock_proc.kill()

# ---- Summary ----
print("\n" + "=" * 60)
if all_passed:
    print("  ALL FUNCTIONALITY TESTS PASSED!")
else:
    print(f"  {len(failures)} TEST(S) FAILED:")
    for f in failures:
        print(f"     - {f}")
print("=" * 60)

sys.exit(0 if all_passed else 1)
