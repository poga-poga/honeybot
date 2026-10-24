"""
FactoryShield: Industrial CAD Archive Services
Port 21: Pure RFC 959 FTP Honeypot Server (for Terminal 'ftp localhost' and FTP clients)
Port 2121: Industrial CAD Archive Web Gateway (for Web Browsers 'http://localhost:2121')
"""
import socket
import threading
from datetime import datetime
from flask import Flask, render_template_string, request, send_file
import os

from factoryshield.config import CANARY_FILES_DIR
from factoryshield.engine.detector import detector_engine

# ---------------------------------------------------------
# 1. Port 2121: CAD Archive Web Gateway (Flask App for Browsers)
# ---------------------------------------------------------
ftp_web_app = Flask("ftp_web_2121")

FTP_WEB_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>JIM Industrial CAD Archive — Web Gateway (Port 2121)</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }
        .box { max-width: 920px; margin: 0 auto; background: #1e293b; padding: 2.2rem; border-radius: 12px; border: 1px solid #334155; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        .hdr { border-bottom: 2px solid #a855f7; padding-bottom: 1rem; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center; }
        h1 { margin: 0; color: #c084fc; font-size: 1.45rem; }
        .badge { background: #7e22ce; color: #fff; padding: 0.25rem 0.7rem; border-radius: 6px; font-size: 0.8rem; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }
        th, td { padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid #334155; }
        th { background: #0f172a; color: #94a3b8; font-weight: 600; }
        a { color: #38bdf8; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
        .auth-form { margin-top: 2rem; background: #0f172a; padding: 1.5rem; border-radius: 8px; border: 1px solid #475569; }
        input { padding: 0.6rem; margin: 0.5rem 0 1rem 0; width: 100%; box-sizing: border-box; background: #1e293b; border: 1px solid #475569; color: #fff; border-radius: 4px; }
        button { background: #9333ea; color: white; border: none; padding: 0.6rem 1.4rem; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 0.95rem; }
        button:hover { background: #7e22ce; }
        .meta-tag { font-size: 0.75rem; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: bold; }
        .tag-canary { background: rgba(239, 68, 68, 0.15); color: #f87171; }
    </style>
</head>
<body>
    <div class="box">
        <div class="hdr">
            <div>
                <h1>JIM Industrial CAD Archive (Web Gateway)</h1>
                <small style="color: #94a3b8;">Host: cad-repo01.jim.corp | Service: Web CAD Explorer (Port 2121)</small>
            </div>
            <span class="badge">CAD BACKUP REPOSITORY</span>
        </div>

        <p>Active Repository Path: <code>/vault/blueprints/industrial_prototypes/</code></p>

        <table>
            <thead>
                <tr>
                    <th>Asset Name</th>
                    <th>Classification</th>
                    <th>File Size</th>
                    <th>Permissions</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>📄 <strong>Turbine_Rotor_Gen4_Confidential_Blueprints.dwg</strong></td>
                    <td><span class="meta-tag tag-canary">Confidential IP (Canary)</span></td>
                    <td>4.2 MB</td>
                    <td>-rw-r-----</td>
                    <td><a href="/download/Turbine_Rotor_Gen4_Confidential_Blueprints.dwg"><button style="padding: 0.3rem 0.8rem; font-size: 0.8rem;">Download</button></a></td>
                </tr>
                <tr>
                    <td>📄 <strong>Hydraulic_Press_Bypass_Safety_Specification.pdf</strong></td>
                    <td><span class="meta-tag tag-canary">Safety Override (Canary)</span></td>
                    <td>1.1 MB</td>
                    <td>-rw-r-----</td>
                    <td><a href="/download/Hydraulic_Press_Bypass_Safety_Specification.pdf"><button style="padding: 0.3rem 0.8rem; font-size: 0.8rem;">Download</button></a></td>
                </tr>
                <tr>
                    <td>📄 <strong>internal_services_conf.json</strong></td>
                    <td><span class="meta-tag" style="background: rgba(245, 158, 11, 0.15); color: #fde68a;">API Key Canary</span></td>
                    <td>24 KB</td>
                    <td>-r--------</td>
                    <td><a href="/download/internal_services_conf.json"><button style="padding: 0.3rem 0.8rem; font-size: 0.8rem;">Download</button></a></td>
                </tr>
            </tbody>
        </table>

        <div class="auth-form">
            <h4 style="margin-top: 0; color: #c084fc;">Archive Gateway Authentication</h4>
            <form action="/login" method="POST">
                <label>Archive Operator / Service Account:</label>
                <input type="text" name="username" placeholder="e.g. svc_eng_backup or contractor" required>
                <label>Password:</label>
                <input type="password" name="password" required>
                <button type="submit">Authenticate to Archive</button>
            </form>
        </div>
    </div>
</body>
</html>
"""

@ftp_web_app.route("/")
def ftp_web_home():
    client_ip = request.remote_addr or "127.0.0.1"
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "username": "ftp_web_visitor",
        "source_host": client_ip,
        "target_host": "cad-repo01.jim.corp",
        "service_name": "CAD Archive Web (Port 2121)",
        "resource": "cad/repo/explorer",
        "action": "view_repo",
        "status": "SUCCESS"
    }
    detector_engine.process_scenario_events([event], session_id=f"FTPWEB-{client_ip}")
    return render_template_string(FTP_WEB_TEMPLATE)

@ftp_web_app.route("/download/<filename>")
def ftp_web_download(filename):
    client_ip = request.remote_addr or "127.0.0.1"
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "username": "ftp_web_exfil",
        "source_host": client_ip,
        "target_host": "cad-repo01.jim.corp",
        "service_name": "CAD Archive Web (Port 2121)",
        "resource": f"cad/vault/{filename}",
        "action": "export",
        "status": "SUCCESS"
    }
    detector_engine.process_scenario_events([event], session_id=f"FTPWEB-EXFIL-{filename[:6]}")

    file_path = CANARY_FILES_DIR / filename
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return f"Canary file '{filename}' download triggered and audit token dispatched.", 200

@ftp_web_app.route("/login", methods=["POST"])
def ftp_web_login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    client_ip = request.remote_addr or "127.0.0.1"

    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "username": username,
        "password_captured": password,
        "source_host": client_ip,
        "target_host": "cad-repo01.jim.corp",
        "service_name": "CAD Archive Web (Port 2121)",
        "resource": f"ftp/auth/{username}",
        "action": "auth_ftp_web",
        "status": "DENIED",
        "details": f"Captured Credentials -> Username: '{username}', Password: '{password}'"
    }
    incident = detector_engine.process_scenario_events([event], session_id=f"FTPWEB-AUTH-{username}")

    return f"""
    <div style="font-family: sans-serif; background: #0f172a; color: #f87171; padding: 2.5rem; text-align: center;">
        <h2>Archive Access Denied</h2>
        <p>Security Audit ID: <strong>{incident['incident_id']}</strong> logged to FactoryShield SOC.</p>
        <p>Captured Credentials: User <strong>{username}</strong> | Password: <strong>{password}</strong></p>
        <p><a href="/" style="color: #c084fc;">Return to Archive Gateway</a></p>
    </div>
    """, 403


# ---------------------------------------------------------
# 2. Port 21: Pure RFC 959 Native FTP Server (for Terminal)
# ---------------------------------------------------------
class PureFTPServer:
    def __init__(self, host="0.0.0.0", port=21):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None

    def start(self):
        self.running = True
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            print(f"[+] Native FTP Server listening on {self.host}:{self.port} (Terminal: ftp localhost)")
        except Exception as e:
            print(f"[-] Could not bind Native FTP to port {self.port}: {e}")
            return

        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True)
                t.start()
            except Exception:
                break

    def _handle_client(self, client_sock, client_addr):
        client_ip = client_addr[0]
        try:
            # Send RFC 959 banner immediately
            client_sock.sendall(b"220 Jordan Industrial Manufacturing (JIM) Secure CAD Archive Ready.\r\n")
            current_user = "anonymous"

            while True:
                client_sock.settimeout(60.0)
                data = client_sock.recv(2048)
                if not data:
                    break

                raw_line = data.decode("utf-8", errors="ignore").strip()
                if not raw_line:
                    continue

                parts = raw_line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1].strip() if len(parts) > 1 else ""

                if cmd == "USER":
                    current_user = arg
                    client_sock.sendall(f"331 User name '{current_user}' okay, need password.\r\n".encode())
                elif cmd == "PASS":
                    event = {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "username": current_user,
                        "password_captured": arg,
                        "source_host": client_ip,
                        "target_host": "cad-repo01.jim.corp",
                        "service_name": "FTP Terminal Trap (Port 21)",
                        "resource": f"ftp/auth/{current_user}",
                        "action": "ftp_login",
                        "status": "SUCCESS" if current_user in ["t.haddad", "r.qasim"] else "DENIED",
                        "details": f"Captured FTP Credentials -> Username: '{current_user}', Password: '{arg}'"
                    }
                    detector_engine.process_scenario_events([event], session_id=f"FTP-AUTH-{current_user}")
                    client_sock.sendall(b"230 User logged in, welcome to JIM CAD Vault.\r\n")
                elif cmd in ["PWD", "XPWD"]:
                    client_sock.sendall(b'257 "/vault/blueprints" is current directory.\r\n')
                elif cmd == "TYPE":
                    client_sock.sendall(b"200 Type set to I.\r\n")
                elif cmd in ["SYST", "FEAT"]:
                    client_sock.sendall(b"215 UNIX Type: L8 (JIM Industrial)\r\n")
                elif cmd in ["PASV", "EPSV"]:
                    client_sock.sendall(b"227 Entering Passive Mode (127,0,0,1,8,73).\r\n")
                elif cmd in ["PORT", "EPRT"]:
                    client_sock.sendall(b"200 PORT command successful.\r\n")
                elif cmd in ["LIST", "NLST"]:
                    listing = (
                        "-rw-r----- 1 engineering engineering  4404019 Oct 19 12:00 Turbine_Rotor_Gen4_Confidential_Blueprints.dwg\r\n"
                        "-rw-r----- 1 engineering engineering  1153433 Oct 19 12:00 Hydraulic_Press_Bypass_Safety_Specification.pdf\r\n"
                        "-r-------- 1 it          it             24576 Oct 19 12:00 internal_services_conf.json\r\n"
                    )
                    client_sock.sendall(b"150 Opening data connection for file list.\r\n")
                    client_sock.sendall(listing.encode())
                    client_sock.sendall(b"226 Transfer complete.\r\n")
                elif cmd == "RETR":
                    event = {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "username": current_user,
                        "source_host": client_ip,
                        "target_host": "cad-repo01.jim.corp",
                        "service_name": "FTP Terminal Trap (Port 21)",
                        "resource": f"cad/vault/{arg}",
                        "action": "export",
                        "status": "SUCCESS"
                    }
                    detector_engine.process_scenario_events([event], session_id=f"FTP-RETR-{arg}")
                    client_sock.sendall(b"150 Opening binary mode data connection.\r\n")
                    client_sock.sendall(b"[CANARY_CAD_DWG_BINARY_MOCK_JIM_2026]\r\n")
                    client_sock.sendall(b"226 Transfer complete. Exfiltration flagged.\r\n")
                elif cmd == "QUIT":
                    client_sock.sendall(b"221 Goodbye from JIM CAD Archive.\r\n")
                    break
                else:
                    client_sock.sendall(b"500 Command unrecognized.\r\n")
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass


def start_ftp_trap_thread(ports=None, host="0.0.0.0"):
    # 1. Start Native FTP on Port 21
    ftp_server = PureFTPServer(host=host, port=21)
    t_ftp = threading.Thread(target=ftp_server.start, daemon=True, name="NativeFTP21")
    t_ftp.start()

    # 2. Start Web CAD Archive on Port 2121
    t_web = threading.Thread(target=lambda: ftp_web_app.run(host=host, port=2121, debug=False, use_reloader=False), daemon=True, name="FTPWeb2121")
    t_web.start()

    return ftp_server
