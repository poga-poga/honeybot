"""
FactoryShield Web Forensics & Security Dashboard
Flask Application for the Isolated Security Monitoring Network
"""
from flask import Flask, render_template, jsonify, request
import os
import json
from pathlib import Path

from factoryshield.config import (
    COMPANY_NAME_EN, COMPANY_NAME_AR, NETWORKS, SCORING, SEVERITY_LEVELS
)
from factoryshield.enterprise.company import get_all_hosts, DEPARTMENTS
from factoryshield.enterprise.rbac import USERS_DIRECTORY
from factoryshield.honeytokens.manager import honeytoken_mgr
from factoryshield.engine.detector import detector_engine
from factoryshield.simulator.scenario_runner import (
    build_data_exfiltration_scenario,
    build_privilege_abuse_scenario,
    build_lateral_movement_scenario,
    build_normal_activity_scenario
)
from factoryshield.simulator.benchmark_100 import benchmark_runner

template_dir = Path(__file__).resolve().parent / "templates"
static_dir = Path(__file__).resolve().parent / "static"

app = Flask(
    __name__,
    template_folder=str(template_dir),
    static_folder=str(static_dir)
)

# Seed an initial incident on startup so the dashboard is immediately vivid
def seed_initial_demo():
    if not detector_engine.incidents_history:
        # Run 1 exfiltration and 1 privilege abuse scenario
        exfil_events = build_data_exfiltration_scenario("r.qasim")
        detector_engine.process_scenario_events(exfil_events, session_id="DEMO-EXFIL-001")
        
        priv_events = build_privilege_abuse_scenario("l.najjar")
        detector_engine.process_scenario_events(priv_events, session_id="DEMO-PRIV-002")

seed_initial_demo()

@app.route("/")
def index():
    return render_template(
        "index.html",
        company_en=COMPANY_NAME_EN,
        company_ar=COMPANY_NAME_AR
    )

@app.route("/api/stats")
def api_stats():
    incidents = detector_engine.incidents_history
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for inc in incidents:
        sev = inc.get("severity", "Low")
        if sev in sev_counts:
            sev_counts[sev] += 1

    return jsonify({
        "total_incidents": len(incidents),
        "active_decoys": len(honeytoken_mgr.list_all()),
        "monitored_hosts": len(get_all_hosts()),
        "departments_count": len(DEPARTMENTS),
        "severity_distribution": sev_counts,
        "latest_score": incidents[0]["score"] if incidents else 0
    })

@app.route("/api/topology")
def api_topology():
    return jsonify({
        "networks": NETWORKS,
        "departments": {
            k: {
                "name_en": v.name_en,
                "name_ar": v.name_ar,
                "classification": v.data_classification,
                "workstations": v.workstations,
                "servers": v.servers
            }
            for k, v in DEPARTMENTS.items()
        }
    })

@app.route("/api/honeytokens")
def api_honeytokens():
    tokens = honeytoken_mgr.list_all()
    return jsonify([
        {
            "token_id": t.token_id,
            "type": t.token_type,
            "identifier": t.identifier,
            "location": t.asset_location,
            "desc_ar": t.description_ar,
            "desc_en": t.description_en,
            "classification": t.classification
        }
        for t in tokens
    ])

def redact_sensitive_fields(value):
    """Return API-safe data without raw passwords or credential secrets."""
    if isinstance(value, dict):
        return {
            key: redact_sensitive_fields(item)
            for key, item in value.items()
            if key.lower() not in {"password", "captured_password", "credential_value", "secret"}
        }
    if isinstance(value, list):
        return [redact_sensitive_fields(item) for item in value]
    return value


@app.route("/api/credentials")
def api_credentials():
    creds = []
    for inc in detector_engine.incidents_history:
        if inc.get("captured_password"):
            creds.append({
                "incident_id": inc["incident_id"],
                "timestamp": inc["timestamp"],
                "username": inc["actor"],
                                "service": inc.get("service_name", "Decoy Trap"),
                "source_host": inc.get("source_workstation", "Unknown"),
                "severity": inc.get("severity", "Medium"),
                "severity_ar": inc.get("severity_ar", "متوسط")
            })
    return jsonify([redact_sensitive_fields(cred) for cred in creds])

@app.route("/api/incidents")
def api_incidents():
    return jsonify(redact_sensitive_fields(detector_engine.incidents_history))

@app.route("/api/incidents/<incident_id>")
def api_incident_detail(incident_id):
    for inc in detector_engine.incidents_history:
        if inc["incident_id"] == incident_id:
            return jsonify(redact_sensitive_fields(inc))
    return jsonify({"error": "Incident not found"}), 404

@app.route("/api/simulate/<scenario_type>", methods=["POST"])
def api_simulate_scenario(scenario_type):
    scenario_type = scenario_type.lower()
    session_id = f"SIM-{scenario_type.upper()}-{os.urandom(3).hex().upper()}"

    if scenario_type == "exfiltration":
        events = build_data_exfiltration_scenario("r.qasim")
    elif scenario_type == "privilege_abuse":
        events = build_privilege_abuse_scenario("l.najjar")
    elif scenario_type == "lateral_movement":
        events = build_lateral_movement_scenario("a.barakat")
    elif scenario_type == "normal":
        events = build_normal_activity_scenario("Engineering")
    else:
        return jsonify({"error": f"Unknown scenario type: {scenario_type}"}), 400

    result = detector_engine.process_scenario_events(events, session_id=session_id)
    return jsonify({
        "scenario": scenario_type,
        "session_id": session_id,
        "result": result
    })

@app.route("/api/benchmark/run", methods=["POST", "GET"])
def api_run_benchmark():
    report = benchmark_runner.evaluate_benchmark()
    return jsonify(report)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
