"""
FactoryShield: CAD & Engineering Decoy Web Portal (Port 8088)
Simulates cad-srv01.jim.corp - Engineering Network
"""
from flask import Flask, request, jsonify, render_template_string, send_file
import threading
import os
from pathlib import Path
from datetime import datetime

from factoryshield.config import CANARY_FILES_DIR
from factoryshield.engine.detector import detector_engine

cad_app = Flask("cad_web_trap")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>JIM — Engineering CAD Vault & Technical Repository</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }
        .container { max-width: 900px; margin: 0 auto; background: #1e293b; padding: 2rem; border-radius: 12px; border: 1px solid #334155; }
        .header { border-bottom: 2px solid #38bdf8; padding-bottom: 1rem; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center; }
        h1 { margin: 0; color: #38bdf8; font-size: 1.5rem; }
        .badge { background: #dc2626; color: #fff; padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.8rem; font-weight: bold; }
        .file-list { list-style: none; padding: 0; }
        .file-item { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; background: #0f172a; margin-bottom: 0.5rem; border-radius: 6px; border: 1px solid #334155; }
        .file-link { color: #38bdf8; text-decoration: none; font-weight: bold; }
        .file-link:hover { text-decoration: underline; }
        .meta { color: #94a3b8; font-size: 0.85rem; }
        .login-box { margin-top: 2rem; background: #0f172a; padding: 1.5rem; border-radius: 8px; border: 1px solid #475569; }
        input[type="text"], input[type="password"] { width: 100%; padding: 0.6rem; margin: 0.5rem 0; background: #1e293b; border: 1px solid #475569; color: #fff; border-radius: 4px; box-sizing: border-box; }
        button { background: #0284c7; color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 6px; cursor: pointer; font-weight: bold; }
        button:hover { background: #0369a1; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>Jordan Industrial Manufacturing (JIM)</h1>
                <p class="meta">Server: cad-srv01.jim.corp | Subnet: 192.168.20.0/24 (Engineering Network)</p>
            </div>
            <span class="badge">INTERNAL USE ONLY</span>
        </div>

        <p>Welcome to the JIM Engineering CAD Vault. Authorized personnel only. All access is logged to Security SOC.</p>

        <h3>Proprietary CAD Blueprints & Specifications</h3>
        <ul class="file-list">
            <li class="file-item">
                <div>
                    <a class="file-link" href="/vault/Turbine_Rotor_Gen4_Confidential_Blueprints.dwg">Turbine_Rotor_Gen4_Confidential_Blueprints.dwg</a>
                    <div class="meta">Classification: Confidential Industrial IP | Size: 4.2 MB</div>
                </div>
                <a href="/vault/Turbine_Rotor_Gen4_Confidential_Blueprints.dwg"><button>Download</button></a>
            </li>
            <li class="file-item">
                <div>
                    <a class="file-link" href="/vault/Hydraulic_Press_Bypass_Safety_Specification.pdf">Hydraulic_Press_Bypass_Safety_Specification.pdf</a>
                    <div class="meta">Classification: Restricted Safety Interlock Specs | Size: 1.1 MB</div>
                </div>
                <a href="/vault/Hydraulic_Press_Bypass_Safety_Specification.pdf"><button>Download</button></a>
            </li>
            <li class="file-item">
                <div>
                    <a class="file-link" href="/vault/internal_services_conf.json">internal_services_conf.json</a>
                    <div class="meta">Classification: Internal API Service Configuration | Size: 24 KB</div>
                </div>
                <a href="/vault/internal_services_conf.json"><button>Download</button></a>
            </li>
        </ul>

        <div class="login-box">
            <h3>CAD Vault Authentication</h3>
            <form action="/login" method="POST">
                <label>Corporate Username / Service Account:</label>
                <input type="text" name="username" placeholder="e.g. t.haddad or svc_eng_backup" required>
                <label>Password:</label>
                <input type="password" name="password" required>
                <button type="submit">Sign In to Repository</button>
            </form>
        </div>
    </div>
</body>
</html>
"""

@cad_app.route("/")
def home():
    return render_template_string(HTML_TEMPLATE)

@cad_app.route("/robots.txt")
def robots():
    content = (
        "User-agent: *\n"
        "Disallow: /vault/Turbine_Rotor_Gen4_Confidential_Blueprints.dwg\n"
        "Disallow: /vault/Hydraulic_Press_Bypass_Safety_Specification.pdf\n"
        "Disallow: /vault/internal_services_conf.json\n"
        "Disallow: /api/production/export\n"
    )
    return content, 200, {"Content-Type": "text/plain"}

@cad_app.route("/vault/<filename>")
def download_vault_file(filename):
    client_ip = request.remote_addr or "192.168.10.99"
    # Report Canary Touch to FactoryShield Engine
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "username": "external_recon_actor",
        "source_host": client_ip,
        "target_host": "cad-srv01.jim.corp",
        "resource": f"cad/vault/{filename}",
        "action": "export",
        "status": "SUCCESS"
    }
    detector_engine.process_scenario_events([event], session_id=f"WEBTRAP-EXFIL-{filename[:6]}")

    file_path = CANARY_FILES_DIR / filename
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return f"File '{filename}' downloaded (Audit token recorded).", 200

@cad_app.route("/login", methods=["POST"])
def login_trap():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    client_ip = request.remote_addr or "192.168.10.99"

    # Report auth attempt with captured credentials to FactoryShield Engine
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "username": username,
        "password_captured": password,
        "source_host": client_ip,
        "target_host": "cad-srv01.jim.corp",
        "service_name": "CAD Web Portal (Port 8088)",
        "resource": "cad/vault/auth",
        "action": "auth_login_attempt",
        "status": "DENIED",
        "details": f"Captured Credentials -> Username: '{username}', Password: '{password}'"
    }
    incident = detector_engine.process_scenario_events([event], session_id=f"WEBTRAP-AUTH-{username}")

    return f"""
    <div style="font-family: sans-serif; background: #0f172a; color: #f87171; padding: 2rem; text-align: center;">
        <h2>Access Denied: Authentication Failed</h2>
        <p>Security Audit ID: {incident['incident_id']} has been dispatched to JIM Security SOC.</p>
        <p><a href="/" style="color: #38bdf8;">Return to CAD Portal</a></p>
    </div>
    """, 403

def run_cad_web_trap(host="0.0.0.0", port=8088):
    cad_app.run(host=host, port=port, debug=False, use_reloader=False)

def start_cad_web_trap_thread(host="0.0.0.0", port=8088):
    t = threading.Thread(target=run_cad_web_trap, args=(host, port), daemon=True, name="CADWebTrap")
    t.start()
    return t
