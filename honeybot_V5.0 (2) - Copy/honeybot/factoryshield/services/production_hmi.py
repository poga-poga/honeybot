"""
FactoryShield: Production HMI & Manufacturing Line Dashboard (Port 8080)
Simulates hmi-prod01.jim.corp - Production Simulation Network (Purdue Level 2/3)
"""
from flask import Flask, render_template_string, request, jsonify
import threading
from datetime import datetime
from factoryshield.engine.detector import detector_engine

hmi_app = Flask("production_hmi_8080")

HMI_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>JIM — Production HMI & Factory Supervisory Control</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b1120; color: #f8fafc; margin: 0; padding: 2rem; }
        .hmi-container { max-width: 1000px; margin: 0 auto; background: #1e293b; border-radius: 14px; border: 1px solid #334155; box-shadow: 0 10px 30px rgba(0,0,0,0.6); overflow: hidden; }
        .hmi-top { background: linear-gradient(90deg, #0f172a, #1e293b); padding: 1.5rem 2rem; border-bottom: 3px solid #10b981; display: flex; justify-content: space-between; align-items: center; }
        .hmi-top h1 { margin: 0; color: #10b981; font-size: 1.5rem; display: flex; align-items: center; gap: 0.5rem; }
        .hmi-badge { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; padding: 0.3rem 0.8rem; border-radius: 20px; font-size: 0.8rem; font-weight: bold; }
        .content { padding: 2rem; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .stat-box { background: #0f172a; padding: 1.25rem; border-radius: 10px; border: 1px solid #334155; }
        .stat-box small { color: #94a3b8; font-size: 0.8rem; display: block; margin-bottom: 0.4rem; }
        .stat-box strong { font-size: 1.8rem; color: #38bdf8; font-family: monospace; }
        .lines-table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }
        .lines-table th, .lines-table td { padding: 1rem; text-align: left; border-bottom: 1px solid #334155; }
        .lines-table th { background: #0f172a; color: #94a3b8; font-weight: 600; }
        .tag-ok { color: #34d399; font-weight: bold; }
        .tag-maint { color: #fbbf24; font-weight: bold; }
        .tag-canary { color: #f87171; font-weight: bold; background: rgba(239, 68, 68, 0.15); padding: 0.2rem 0.6rem; border-radius: 6px; }
        .btn-ctrl { background: #0284c7; color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .btn-ctrl:hover { background: #0369a1; }
        .btn-canary-trip { background: #dc2626; color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .btn-canary-trip:hover { background: #b91c1c; }
        .login-section { margin-top: 2rem; background: #0f172a; padding: 1.5rem; border-radius: 10px; border: 1px solid #334155; }
        input { width: 100%; padding: 0.6rem; margin: 0.5rem 0 1rem 0; background: #1e293b; border: 1px solid #475569; color: #fff; border-radius: 6px; box-sizing: border-box; }
        button.btn-login { background: #10b981; color: #fff; border: none; padding: 0.6rem 1.5rem; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 0.95rem; }
        button.btn-login:hover { background: #059669; }
    </style>
</head>
<body>
    <div class="hmi-container">
        <div class="hmi-top">
            <div>
                <h1>⚙️ JIM Plant Supervisory HMI (Port 8080)</h1>
                <small style="color: #94a3b8;">Host: hmi-prod01.jim.corp | Network: Production Simulation (192.168.30.0/24)</small>
            </div>
            <span class="hmi-badge">● SCADA ONLINE</span>
        </div>

        <div class="content">
            <div class="stats-grid">
                <div class="stat-box">
                    <small>Daily Production Yield</small>
                    <strong>4,350 Units</strong>
                </div>
                <div class="stat-box">
                    <small>Operational Line Efficiency</small>
                    <strong style="color: #34d399;">94.8 %</strong>
                </div>
                <div class="stat-box">
                    <small>Active Line Controllers</small>
                    <strong>4 / 5</strong>
                </div>
                <div class="stat-box">
                    <small>Connected SCADA PLC</small>
                    <strong style="color: #a78bfa;">192.168.30.80</strong>
                </div>
            </div>

            <h3>Active Assembly & Manufacturing Lines</h3>
            <table class="lines-table">
                <thead>
                    <tr>
                        <th>Line ID</th>
                        <th>Manufacturing Section</th>
                        <th>Target Capacity</th>
                        <th>Operating Status</th>
                        <th>Supervisory Action</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>LINE-01</strong></td>
                        <td>CNC Milling & Machining</td>
                        <td>1,200 parts/day</td>
                        <td><span class="tag-ok">● RUNNING</span></td>
                        <td><button class="btn-ctrl" onclick="actLine('LINE-01')">View Line Telemetry</button></td>
                    </tr>
                    <tr>
                        <td><strong>LINE-02</strong></td>
                        <td>Robotic Spot Welding</td>
                        <td>850 parts/day</td>
                        <td><span class="tag-ok">● RUNNING</span></td>
                        <td><button class="btn-ctrl" onclick="actLine('LINE-02')">View Line Telemetry</button></td>
                    </tr>
                    <tr>
                        <td><strong>LINE-03</strong></td>
                        <td>Powder Coating & Heat Treatment</td>
                        <td>600 parts/day</td>
                        <td><span class="tag-maint">● SCHEDULED MAINTENANCE</span></td>
                        <td><button class="btn-ctrl" onclick="actLine('LINE-03')">View Line Telemetry</button></td>
                    </tr>
                    <tr>
                        <td><strong>LINE-04</strong></td>
                        <td>Heavy Stamping Hydraulic Press</td>
                        <td>2,200 parts/day</td>
                        <td><span class="tag-ok">● RUNNING</span></td>
                        <td><button class="btn-ctrl" onclick="actLine('LINE-04')">View Line Telemetry</button></td>
                    </tr>
                    <tr style="background: rgba(220, 38, 38, 0.08);">
                        <td><strong style="color: #f87171;">LINE-07</strong></td>
                        <td>Prototype Titanium Black Project (Decoy)</td>
                        <td>10 parts/day</td>
                        <td><span class="tag-canary">⚠ HONEYTOKEN CANARY LINE</span></td>
                        <td><button class="btn-canary-trip" onclick="tripCanary()">Trip Line-07 Interlock</button></td>
                    </tr>
                </tbody>
            </table>

            <div id="hmi-msg" style="margin-top: 1rem; font-family: monospace; font-size: 0.9rem;"></div>

            <div class="login-section">
                <h4 style="margin-top: 0; color: #10b981;">Plant Supervisor Authorization (RBAC)</h4>
                <form action="/login" method="POST">
                    <label>Supervisor / Operator Account:</label>
                    <input type="text" name="username" placeholder="e.g. o.alali (Plant Supervisor) or l.najjar (HR)" required>
                    <label>Password:</label>
                    <input type="password" name="password" required>
                    <button type="submit" class="btn-login">Authenticate on HMI</button>
                </form>
            </div>
        </div>
    </div>

    <script>
        function actLine(line) {
            fetch('/api/line/telemetry?line=' + line)
                .then(r => r.json())
                .then(data => {
                    document.getElementById('hmi-msg').innerHTML = '<span style="color: #38bdf8;">[TELEMETRY] ' + data.line + ': ' + data.status + ' | RPM: 1800 | Temp: 65C</span>';
                });
        }
        function tripCanary() {
            fetch('/api/line/trip-canary')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('hmi-msg').innerHTML = '<span style="color: #f87171; font-weight: bold;">[CANARY ALERT] ' + data.message + '</span>';
                });
        }
    </script>
</body>
</html>
"""

@hmi_app.route("/")
def hmi_home():
    client_ip = request.remote_addr or "127.0.0.1"
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "username": "hmi_operator_visitor",
        "source_host": client_ip,
        "target_host": "hmi-prod01.jim.corp",
        "resource": "production/hmi/dashboard",
        "action": "view_hmi",
        "status": "SUCCESS"
    }
    detector_engine.process_scenario_events([event], session_id=f"HMI-VIEW-{client_ip}")
    return render_template_string(HMI_HTML_TEMPLATE)

@hmi_app.route("/api/line/telemetry")
def api_line_telemetry():
    line = request.args.get("line", "LINE-01")
    return jsonify({
        "line": line,
        "status": "OPERATIONAL",
        "output_rate": "98%",
        "controller": "plc-sim01.jim.corp"
    })

@hmi_app.route("/api/line/trip-canary")
def api_trip_canary():
    client_ip = request.remote_addr or "127.0.0.1"
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "username": "unauthorized_operator",
        "source_host": client_ip,
        "target_host": "hmi-prod01.jim.corp",
        "resource": "production/lines/LINE-07-BLACK-PROJECT",
        "action": "emergency_trip_canary",
        "status": "TRIGGERED",
        "details": "Operator triggered canary shutdown on non-existent Line-07"
    }
    incident = detector_engine.process_scenario_events([event], session_id="HMI-CANARY-TRIP")
    return jsonify({
        "status": "INCIDENT_TRIGGERED",
        "message": f"Canary Honeytoken LINE-07 triggered! Incident {incident['incident_id']} logged with risk score {incident['score']}/100.",
        "incident_id": incident["incident_id"]
    })

@hmi_app.route("/login", methods=["POST"])
def hmi_login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    client_ip = request.remote_addr or "127.0.0.1"

    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "username": username,
        "password_captured": password,
        "source_host": client_ip,
        "target_host": "hmi-prod01.jim.corp",
        "service_name": "Production HMI (Port 8080)",
        "resource": "production/hmi/auth",
        "action": "auth_hmi_login",
        "status": "SUCCESS" if username in ["o.alali", "k.masri"] else "DENIED",
        "details": f"Captured HMI Credentials -> Username: '{username}', Password: '{password}'"
    }
    incident = detector_engine.process_scenario_events([event], session_id=f"HMI-AUTH-{username}")

    return f"""
    <div style="font-family: sans-serif; background: #0f172a; color: #fff; padding: 2.5rem; text-align: center;">
        <h2>HMI Authentication: {'Authorized' if incident['score'] < 30 else 'Policy Violation Logged'}</h2>
        <p>User: <strong>{username}</strong> | Risk Score: <strong>{incident['score']}/100 ({incident['severity']})</strong></p>
        <p><a href="/" style="color: #10b981;">Return to HMI Dashboard</a></p>
    </div>
    """

def run_hmi_app(host="0.0.0.0", port=8080):
    hmi_app.run(host=host, port=port, debug=False, use_reloader=False)

def start_hmi_thread(host="0.0.0.0", port=8080):
    t = threading.Thread(target=run_hmi_app, args=(host, port), daemon=True, name="ProductionHMI8080")
    t.start()
    return t
