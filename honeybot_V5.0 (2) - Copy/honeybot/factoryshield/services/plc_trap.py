"""
FactoryShield: Simulated Industrial PLC / Siemens S7 Diagnostic Web Portal (Port 5020)
Simulates plc-sim01.jim.corp - Production Simulation Network
"""
from flask import Flask, render_template_string, request, jsonify
import threading
from datetime import datetime
from factoryshield.engine.detector import detector_engine

plc_app = Flask("plc_trap_5020")

PLC_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SIMATIC S7-1500 — Industrial PLC Diagnostics | JIM</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a202c; color: #edf2f7; margin: 0; padding: 2rem; }
        .plc-chassis { max-width: 950px; margin: 0 auto; background: #2d3748; border-radius: 12px; border: 2px solid #4a5568; box-shadow: 0 10px 25px rgba(0,0,0,0.5); overflow: hidden; }
        .plc-header { background: #1a365d; padding: 1.25rem 2rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 3px solid #3182ce; }
        .plc-header h1 { margin: 0; font-size: 1.4rem; color: #63b3ed; }
        .status-pill { background: #38a169; color: white; padding: 0.3rem 0.8rem; border-radius: 20px; font-weight: bold; font-size: 0.85rem; display: flex; align-items: center; gap: 0.5rem; }
        .status-dot { width: 10px; height: 10px; background: #fff; border-radius: 50%; }
        .plc-body { padding: 2rem; }
        .telemetry-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .telemetry-card { background: #1a202c; padding: 1.25rem; border-radius: 8px; border: 1px solid #4a5568; }
        .telemetry-card small { color: #a0aec0; display: block; font-size: 0.8rem; }
        .telemetry-card strong { font-size: 1.5rem; color: #63b3ed; font-family: monospace; }
        .table-wrap { background: #1a202c; border-radius: 8px; border: 1px solid #4a5568; overflow: hidden; margin-bottom: 2rem; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
        th, td { padding: 0.9rem 1.2rem; border-bottom: 1px solid #2d3748; }
        th { background: #2b6cb0; color: white; font-weight: 600; }
        .canary-line { background: rgba(229, 62, 62, 0.15); border-left: 4px solid #e53e3e; }
        .btn-action { background: #e53e3e; color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .btn-action:hover { background: #c53030; }
        .btn-poll { background: #3182ce; color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .btn-poll:hover { background: #2b6cb0; }
    </style>
</head>
<body>
    <div class="plc-chassis">
        <div class="plc-header">
            <div>
                <h1>SIMATIC S7-1500 / Industrial Controller Gateway</h1>
                <small style="color: #cbd5e0;">Device: plc-sim01.jim.corp | Firmware: v4.2.1-JIM-PROD | Subnet: 192.168.30.0/24</small>
            </div>
            <div class="status-pill">
                <span class="status-dot"></span>
                <span>PLC RUNNING</span>
            </div>
        </div>

        <div class="plc-body">
            <h3>Active Industrial Holding Registers (Modbus TCP 5020 Telemetry)</h3>
            <div class="telemetry-grid">
                <div class="telemetry-card">
                    <small>Spindle RPM (Reg 40001)</small>
                    <strong>1,800 RPM</strong>
                </div>
                <div class="telemetry-card">
                    <small>Hydraulic Pressure (Reg 40002)</small>
                    <strong>45.2 Bar</strong>
                </div>
                <div class="telemetry-card">
                    <small>Coolant Temperature (Reg 40003)</small>
                    <strong>68.4 °C</strong>
                </div>
                <div class="telemetry-card">
                    <small>PLC CPU Load</small>
                    <strong>14.2 %</strong>
                </div>
            </div>

            <h3>Production Line Controller Status</h3>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Line Identifier</th>
                            <th>Operation Type</th>
                            <th>Status</th>
                            <th>Diagnostic Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>LINE-01</strong></td>
                            <td>CNC Milling Machine Line A</td>
                            <td><span style="color: #48bb78; font-weight: bold;">● OPERATIONAL</span></td>
                            <td><button class="btn-poll" onclick="pollTelemetry('LINE-01')">Read Modbus Data</button></td>
                        </tr>
                        <tr>
                            <td><strong>LINE-02</strong></td>
                            <td>Automated Robotic Welding</td>
                            <td><span style="color: #48bb78; font-weight: bold;">● OPERATIONAL</span></td>
                            <td><button class="btn-poll" onclick="pollTelemetry('LINE-02')">Read Modbus Data</button></td>
                        </tr>
                        <tr>
                            <td><strong>LINE-03</strong></td>
                            <td>Powder Coating & Finishing</td>
                            <td><span style="color: #ecc94b; font-weight: bold;">● MAINTENANCE</span></td>
                            <td><button class="btn-poll" onclick="pollTelemetry('LINE-03')">Read Modbus Data</button></td>
                        </tr>
                        <tr class="canary-line">
                            <td><strong style="color: #fc8181;">LINE-07-BLACK-PROJECT [DECOY]</strong></td>
                            <td>Prototype Titanium Alloy Forging</td>
                            <td><span style="color: #fc8181; font-weight: bold;">⚠ RESTRICTED HONEYTOKEN</span></td>
                            <td><button class="btn-action" onclick="pollCanary('LINE-07')">Force Modbus Override</button></td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div style="background: #1a202c; padding: 1.25rem; border-radius: 8px; border: 1px solid #4a5568;">
                <h4 style="margin-top: 0; color: #63b3ed;">Modbus / TCP Telemetry Probe</h4>
                <p style="font-size: 0.85rem; color: #a0aec0;">Clicking either button will submit a simulated Modbus packet to the controller and log the telemetry probe directly to FactoryShield SOC.</p>
                <div id="status-msg" style="margin-top: 0.5rem; font-family: monospace; color: #48bb78;"></div>
            </div>
        </div>
    </div>

    <script>
        function pollTelemetry(line) {
            fetch('/api/modbus/read?line=' + line)
                .then(r => r.json())
                .then(data => {
                    document.getElementById('status-msg').innerText = 'Modbus 0x03 Response received: ' + JSON.stringify(data);
                });
        }

        function pollCanary(line) {
            fetch('/api/modbus/override?line=' + line)
                .then(r => r.json())
                .then(data => {
                    document.getElementById('status-msg').innerHTML = '<span style="color: #fc8181;">⚠ ALERT: ' + data.message + '</span>';
                });
        }
    </script>
</body>
</html>
"""

@plc_app.route("/")
def plc_dashboard():
    client_ip = request.remote_addr or "127.0.0.1"
    # Report PLC Web Diagnostic reconnaissance to FactoryShield
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "username": "ot_recon_actor",
        "source_host": client_ip,
        "target_host": "plc-sim01.jim.corp",
        "resource": "ot/plc/diagnostics_portal",
        "action": "http_hmi_recon",
        "status": "SUCCESS"
    }
    detector_engine.process_scenario_events([event], session_id=f"PLC-RECON-{client_ip}")
    return render_template_string(PLC_HTML_TEMPLATE)

@plc_app.route("/api/modbus/read")
def api_modbus_read():
    line = request.args.get("line", "LINE-01")
    client_ip = request.remote_addr or "127.0.0.1"

    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "username": "ot_operator_probe",
        "source_host": client_ip,
        "target_host": "plc-sim01.jim.corp",
        "resource": f"ot/plc/{line}/registers",
        "action": "modbus_func_03",
        "status": "SUCCESS"
    }
    detector_engine.process_scenario_events([event], session_id=f"MODBUS-POLL-{line}")

    return jsonify({
        "controller": "SIMATIC S7-1500 (plc-sim01.jim.corp)",
        "line": line,
        "holding_registers": [1800, 452, 684, 102],
        "status": "OPERATIONAL"
    })

@plc_app.route("/api/modbus/override")
def api_modbus_override():
    line = request.args.get("line", "LINE-07")
    client_ip = request.remote_addr or "127.0.0.1"

    # Triggers Canary Rule R1 (Database/OT Canary LINE-07)
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "username": "malicious_ot_actor",
        "source_host": client_ip,
        "target_host": "plc-sim01.jim.corp",
        "resource": "ot/plc/LINE-07-BLACK-PROJECT/registers",
        "action": "modbus_func_16_write",
        "status": "SUCCESS",
        "details": "Canary Honeytoken Line-07 register write override attempt"
    }
    incident = detector_engine.process_scenario_events([event], session_id=f"PLC-OVERRIDE-CANARY")

    return jsonify({
        "status": "TRIGGERED",
        "message": f"Canary Token Activated! Security Incident {incident['incident_id']} generated with risk score {incident['score']}/100.",
        "incident_id": incident["incident_id"],
        "severity": incident["severity"]
    })

def run_plc_trap_app(host="0.0.0.0", port=5020):
    plc_app.run(host=host, port=port, debug=False, use_reloader=False)

def start_plc_trap_thread(host="0.0.0.0", port=5020):
    t = threading.Thread(target=run_plc_trap_app, args=(host, port), daemon=True, name="PLCTrapApp")
    t.start()
    return t
