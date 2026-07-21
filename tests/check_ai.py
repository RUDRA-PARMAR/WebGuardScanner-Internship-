"""
WebGuard AI Remediation Copilot Direct Checker
===============================================
Queries the database for the last scan, calls get_gemini_remediation,
and prints the AI agent's response to check functionality.
"""
import sys
import os
import json

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

from app.database import init_db, get_history
from app.scanner.ai_remediation import get_gemini_remediation

print("=" * 60)
print("  WebGuard AI Functionality Self-Check")
print("=" * 60)

# Initialize database
init_db()

# Get history to find a scan ID
history = get_history()
if not history:
    print("[-] No scan history found. Please run tests/verify_dashboard.py first to create a scan.")
    sys.exit(1)

# Find the latest successful scan ID
latest_scan = history[0]
scan_id = latest_scan["id"]
target_url = latest_scan["url"]
print(f"[+] Found latest Scan ID: {scan_id} for target: {target_url}")

# Run AI Remediation with a greeting
print("[*] Testing AI Copilot with greeting 'hi'...")
result_greet = get_gemini_remediation(scan_id, user_prompt="hi")

import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

print(f"Status: {result_greet.get('status')}")
print("-" * 60)
print(result_greet.get("response"))
print("-" * 60)

# Run AI Remediation with a specific request
print("\n[*] Testing AI Copilot with specific query 'Explain the top vulnerability'...")
result_query = get_gemini_remediation(scan_id, user_prompt="Explain the top vulnerability and Nginx fix.")
print(f"Status: {result_query.get('status')}")
print("-" * 60)
print(result_query.get("response"))
print("-" * 60)

if result_greet.get("status") == "Success" and result_query.get("status") == "Success":
    print("✅ AI FUNCTIONALITY VERIFIED successfully for both greetings and queries!")
else:
    print("❌ AI FUNCTIONALITY FAILED! See details above.")
