"""
WebGuard AI Patching verification script
=========================================
Queries the SQLite database for the last scan, calls /api/scan/remediate/generate_patch
and /api/scan/remediate/consolidated_patch endpoints, and prints the AI response.
"""
import sys
import os
import json
import requests
import subprocess
import time

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Load .env file
if os.path.exists(".env"):
    with open(".env", "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                k = key.strip()
                os.environ[k] = val.strip().strip('"').strip("'")

from app.database import init_db, get_history, get_scan_detail

# 1. Start the Scanner Backend in a background process
print("[*] Launching Scanner Backend application on port 8089...")
env = os.environ.copy()
env["ALLOW_PRIVATE_IPS"] = "True"
env["PYTHONUNBUFFERED"] = "1"
env["TESTING"] = "True"

scanner_process = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "main:app", "--port", "8089"],
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

# Wait for server to initialize
time.sleep(4)

try:
    # Initialize database
    init_db()

    # Get history to find a scan ID
    history = get_history()
    if not history:
        print("[-] No scan history found. Running a mock scan to populate history...")
        # Start mock vulnerable target server on port 9099 to run a scan
        target_process = subprocess.Popen(
            [sys.executable, "run_test_server.py"],
            env={"MOCK_PORT": "9099", "TESTING": "True"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(3)
        try:
            # Perform a fast scan to get a scan ID
            scan_url = "http://127.0.0.1:8089/api/scan?url=http://127.0.0.1:9099&profile=fast"
            res = requests.post(scan_url, timeout=30)
            if res.status_code == 200:
                history = get_history()
            else:
                print(f"[-] Mock scan failed to run: {res.text}")
        finally:
            target_process.terminate()
            target_process.wait()

    if not history:
        print("[-] Error: Still no scan history found. Cannot proceed with AI patch tests.")
        sys.exit(1)

    latest_scan = history[0]
    scan_id = latest_scan["id"]
    target_url = latest_scan["url"]
    print(f"[+] Found latest Scan ID: {scan_id} for target: {target_url}")

    # Fetch first finding's check name
    report_detail = get_scan_detail(scan_id)
    findings = report_detail.get("findings", [])
    if not findings:
        print("[-] Error: No findings in latest scan report. Cannot test generate_patch.")
        sys.exit(1)
    finding_check = findings[0]["check"]
    print(f"[+] Using finding check name for testing: '{finding_check}'")

    # Set output encoding to UTF-8 for console printing
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    # Test 1: Individual Finding Nginx Patch
    print("\n[*] Testing POST /api/scan/remediate/generate_patch for NGINX...")
    res = requests.post(f"http://127.0.0.1:8089/api/scan/remediate/generate_patch?scan_id={scan_id}&finding_check={requests.utils.quote(finding_check)}&tech=nginx")
    print(f"Status Code: {res.status_code}")
    if res.status_code == 200:
        data = res.json()
        print(f"Response Status: {data.get('status')}")
        print("--- Response Snippet (First 300 chars) ---")
        print(data.get("response", "")[:300])
        print("------------------------------------------")
    else:
        print(f"Failed: {res.text}")

    # Test 2: Individual Finding Python Patch
    print("\n[*] Testing POST /api/scan/remediate/generate_patch for Python...")
    res = requests.post(f"http://127.0.0.1:8089/api/scan/remediate/generate_patch?scan_id={scan_id}&finding_check={requests.utils.quote(finding_check)}&tech=python")
    print(f"Status Code: {res.status_code}")
    if res.status_code == 200:
        data = res.json()
        print(f"Response Status: {data.get('status')}")
        print("--- Response Snippet (First 300 chars) ---")
        print(data.get("response", "")[:300])
        print("------------------------------------------")
    else:
        print(f"Failed: {res.text}")

    # Test 3: Consolidated Nginx Patch
    print("\n[*] Testing POST /api/scan/remediate/consolidated_patch for Nginx...")
    res = requests.post(f"http://127.0.0.1:8089/api/scan/remediate/consolidated_patch?scan_id={scan_id}&tech=nginx")
    print(f"Status Code: {res.status_code}")
    if res.status_code == 200:
        data = res.json()
        print(f"Response Status: {data.get('status')}")
        print("--- Response Snippet (First 300 chars) ---")
        print(data.get("response", "")[:300])
        print("------------------------------------------")
    else:
        print(f"Failed: {res.text}")

finally:
    print("\nCleaning up background server processes...")
    scanner_process.terminate()
    scanner_process.wait()
