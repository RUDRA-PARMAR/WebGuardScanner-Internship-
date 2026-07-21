"""
WebGuard Scanner Unit Tests
===========================
Tests core scanner components including URL validation, SSRF filters, CORS auditing, 
Set-Cookie header split parsing, and unified engine features using unittest.
"""

import unittest
from unittest.mock import MagicMock, patch
import os
import sys
import json

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.scanner.validation_reachable import validate_url, check_ssrf, simulate_dns_rebinding
from app.scanner.header_analysis import _check_cors
from app.scanner.cookie_checker import split_combined_set_cookie
from app.scanner.virtual_patching import generate_virtual_patches
from app.scanner.script_integrity import run_script_integrity_scan
from app.scanner.ai_remediation import get_gemini_remediation

class TestWebGuardScanner(unittest.TestCase):

    # 1. URL Validation Tests
    def test_url_validation_success(self):
        res = validate_url("https://example.com/path?query=1")
        self.assertTrue(res["valid"])
        self.assertEqual(res["components"]["scheme"], "https")
        self.assertEqual(res["components"]["hostname"], "example.com")

    def test_url_validation_missing_scheme(self):
        res = validate_url("example.com")
        self.assertFalse(res["valid"])
        self.assertIn("missing a scheme", res["errors"][0])

    def test_url_validation_invalid_scheme(self):
        res = validate_url("ftp://example.com")
        self.assertFalse(res["valid"])
        self.assertIn("not allowed", res["errors"][0])

    # 2. SSRF Protection Tests
    def test_ssrf_blocked_localhost(self):
        # Allow private IPs is disabled by default
        with patch("os.getenv", return_value="False"):
            res = check_ssrf("127.0.0.1")
            self.assertFalse(res["safe"])
            self.assertTrue(any(f["check"] == "SSRF Protection" for f in res["findings"]))

    def test_ssrf_allowed_localhost_if_configured(self):
        # Allow private IPs is enabled via environment variable
        with patch("os.getenv", return_value="True"):
            res = check_ssrf("127.0.0.1")
            self.assertTrue(res["safe"])
            self.assertEqual(len(res["findings"]), 0)

    # 3. CORS Header Auditing Tests
    def test_cors_wildcard_with_credentials(self):
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        }
        findings = _check_cors(headers)
        self.assertEqual(len(findings), 1)
        self.assertIn("Wildcard with Credentials", findings[0]["check"])
        self.assertEqual(findings[0]["severity"], "High")

    def test_cors_null_with_credentials(self):
        headers = {
            "Access-Control-Allow-Origin": "null",
            "Access-Control-Allow-Credentials": "true"
        }
        findings = _check_cors(headers)
        self.assertEqual(len(findings), 1)
        self.assertIn("Null Origin with Credentials", findings[0]["check"])
        self.assertEqual(findings[0]["severity"], "High")

    def test_cors_safe(self):
        headers = {
            "Access-Control-Allow-Origin": "https://trusted.com",
            "Access-Control-Allow-Credentials": "true"
        }
        findings = _check_cors(headers)
        self.assertEqual(len(findings), 0)

    # 4. Cookie Parsing comma split bug
    def test_split_combined_set_cookie(self):
        combined = "c1=v1; expires=Mon, 12-Jul-2026 12:00:00 GMT, c2=v2; Path=/"
        split = split_combined_set_cookie(combined)
        self.assertEqual(len(split), 2)
        self.assertEqual(split[0], "c1=v1; expires=Mon, 12-Jul-2026 12:00:00 GMT")
        self.assertEqual(split[1], "c2=v2; Path=/")



    # 6. Virtual Patching Generation Tests
    def test_generate_virtual_patches(self):
        findings = [
            {"check": "Missing HSTS Header", "severity": "Medium", "description": "HSTS header is missing"},
            {"check": "Insecure CORS Configuration", "severity": "High", "description": "Wildcard origin with credentials allowed"}
        ]
        patches = generate_virtual_patches(findings)
        self.assertEqual(patches["status"], "Success")
        self.assertIn("Strict-Transport-Security", patches["nginx"])
        self.assertIn("Access-Control-Allow-Origin", patches["nginx"])
        self.assertIn("Strict-Transport-Security", patches["apache"])

    # 7. DNS Rebinding Simulator Tests
    @patch("requests.get")
    def test_dns_rebinding_low_ttl(self, mock_get):
        # Mock a low TTL return from Cloudflare DoH API
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Answer": [{"name": "lowttl.com", "type": 1, "TTL": 3, "data": "1.1.1.1"}]
        }
        mock_get.return_value = mock_resp
        
        findings = simulate_dns_rebinding("lowttl.com")
        self.assertTrue(any("Low TTL" in f["check"] for f in findings))

    # 8. Magecart & Script Integrity Tests
    @patch("requests.get")
    def test_script_integrity_sri_check(self, mock_get):
        # Mock HTML containing external script lacking SRI attribute
        html = '<html><body><script src="https://cdn.com/lib.js"></script></body></html>'
        
        # Mock request to fetch script itself
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "console.log('loaded');"
        mock_get.return_value = mock_resp
        
        res = run_script_integrity_scan("https://example.com", html_content=html)
        self.assertEqual(res["status"], "Success")
        self.assertTrue(any("Missing Subresource Integrity" in f["check"] for f in res["findings"]))

    @patch("requests.get")
    def test_script_integrity_sri_hash_verification(self, mock_get):
        import base64
        import hashlib
        script_content = b"console.log('hello world');"
        calc_digest = hashlib.sha384(script_content).digest()
        calc_b64 = base64.b64encode(calc_digest).decode("utf-8")
        
        # Valid SRI HTML
        html_valid = f'<html><body><script src="https://cdn.com/lib.js" integrity="sha384-{calc_b64}"></script></body></html>'
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = script_content
        mock_resp.text = script_content.decode("utf-8")
        mock_get.return_value = mock_resp
        
        res_valid = run_script_integrity_scan("https://example.com", html_content=html_valid)
        self.assertTrue(any("Valid Subresource Integrity" in f["check"] for f in res_valid["findings"]))

        # Mismatched SRI HTML
        html_tampered = '<html><body><script src="https://cdn.com/lib.js" integrity="sha384-INVALIDHASH12345"></script></body></html>'
        res_tampered = run_script_integrity_scan("https://example.com", html_content=html_tampered)
        self.assertTrue(any("Hash Mismatch" in f["check"] for f in res_tampered["findings"]))

    # 10. AI Remediation Config Validation
    def test_ai_remediation_agent_config(self):
        # Verify AI agent flags missing API key gracefully
        with patch("os.getenv", return_value=""):
            res = get_gemini_remediation(1)
            self.assertEqual(res["status"], "Configuration Required")
            self.assertIn("AI API Key Missing", res["response"])

    # 11. Database Deletion Test
    def test_database_delete_scan(self):
        from app.database import init_db, save_scan, get_scan_detail, delete_scan
        import tempfile
        import os
        # Set DB_PATH to a temp file
        fd, temp_db_path = tempfile.mkstemp()
        os.close(fd)
        try:
            with patch("app.database.DB_PATH", temp_db_path):
                init_db()
                report = {
                    "url": "http://example.com",
                    "reachable": True,
                    "total_findings": 0,
                    "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                }
                scan_id = save_scan("http://example.com", report)
                self.assertIsNotNone(scan_id)
                # Check detail exists
                detail = get_scan_detail(scan_id)
                self.assertIsNotNone(detail)
                # Delete it
                delete_scan(scan_id)
                # Check detail is gone
                self.assertIsNone(get_scan_detail(scan_id))
        finally:
            if os.path.exists(temp_db_path):
                os.remove(temp_db_path)

if __name__ == "__main__":
    unittest.main()

