"""
WebGuard Scanner End-to-End Integration Tests
============================================
Launches the mock target server and scanner app in subprocesses, 
calls all REST API endpoints, and validates the scanned outputs.
"""

import time
import subprocess
import requests
import sys
import os

def run_integration_test():
    print("====================================================")
    print("   WebGuard E2E Integration Test Suite Starting     ")
    print("====================================================")
    
    # 1. Start mock vulnerable target server on port 9999
    # 1. Start mock vulnerable target server on port 9099
    print("[1/5] Launching Mock Vulnerable target server on port 9099...")
    target_env = os.environ.copy()
    target_env["MOCK_PORT"] = "9099"
    target_env["PYTHONUNBUFFERED"] = "1"
    target_env["TESTING"] = "True"
    target_process = subprocess.Popen(
        [sys.executable, "run_test_server.py"],
        env=target_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # 2. Start primary FastAPI scanner application on port 8088
    print("[2/5] Launching Scanner Backend application on port 8088...")
    env = os.environ.copy()
    env["ALLOW_PRIVATE_IPS"] = "True"
    env["GEMINI_API_KEY"] = "mock_key"
    env["BLACKBOX_API_KEY"] = "mock_key"
    env["PYTHONUNBUFFERED"] = "1"
    env["TESTING"] = "True"
    
    scanner_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--port", "8088"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for servers to initialize
    time.sleep(4)
    
    success = True
    try:
        # 3. Test Web Scan Endpoint
        print("[3/5] Testing POST /api/scan endpoint (with 60s timeout)...")
        scan_url = "http://127.0.0.1:8088/api/scan?url=http://127.0.0.1:9099&profile=full"
        res = requests.post(scan_url, timeout=60)
        if res.status_code == 200:
            report = res.json()
            print(f"      - Web Scan Result Status: {report.get('status')}")
            print(f"      - Security Score: {report.get('security_score')}/100")
            print(f"      - Risk Rating: {report.get('risk_rating')}")
            print(f"      - Findings Count: {len(report.get('findings', []))}")
            
            # Verify virtual patches generated
            v_patches = report.get("virtual_patches", {})
            if "nginx" in v_patches and "apache" in v_patches:
                print("      - Virtual Patches: Success")
            else:
                print("      - Virtual Patches: Failed")
                success = False
        else:
            print(f"      - Web Scan API Failed with HTTP {res.status_code}: {res.text}")
            success = False

            
        # 5. Test Script Integrity check endpoint
        print("[5/5] Testing GET /api/scan/scripts endpoint (with 45s timeout)...")
        scripts_url = "http://127.0.0.1:8088/api/scan/scripts?url=http://127.0.0.1:9099"
        res_scripts = requests.get(scripts_url, timeout=45)
        if res_scripts.status_code == 200:
            scripts_report = res_scripts.json()
            print(f"      - Script Auditor Status: {scripts_report.get('status')}")
            print(f"      - Script Findings: {len(scripts_report.get('findings', []))}")
        else:
            print(f"      - Script Auditor Failed with HTTP {res_scripts.status_code}: {res_scripts.text}")
            success = False
            
    except Exception as e:
        print(f"   [ERROR] E2E Request failed: {str(e)}")
        success = False
    finally:
        # Shut down servers cleanly
        print("Cleaning up background server processes...")
        target_process.terminate()
        scanner_process.terminate()
        try:
            target_out, target_err = target_process.communicate(timeout=2)
            print("--- Target Server Logs ---")
            print(target_out.decode("utf-8", errors="ignore"))
            if target_err:
                print(target_err.decode("utf-8", errors="ignore"))
        except Exception:
            pass
            
        try:
            scanner_out, scanner_err = scanner_process.communicate(timeout=2)
            print("--- Scanner Server Logs ---")
            print(scanner_out.decode("utf-8", errors="ignore"))
            if scanner_err:
                print(scanner_err.decode("utf-8", errors="ignore"))
        except Exception:
            pass
        
    if success:
        print("\n====================================================")
        print("   INTEGRATION TESTS PASSED: ALL FUNCTIONALITY OK   ")
        print("====================================================")
        sys.exit(0)
    else:
        print("\n====================================================")
        print("   INTEGRATION TESTS FAILED                         ")
        print("====================================================")
        sys.exit(1)

if __name__ == "__main__":
    run_integration_test()
