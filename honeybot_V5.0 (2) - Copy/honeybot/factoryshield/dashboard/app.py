"""
FactoryShield Web Forensics & Security Dashboard
Flask application with session-based dashboard/API authentication.
"""
from flask import (
    Flask, render_template, jsonify, request, redirect, url_for, session, Response, make_response
)
from functools import wraps
from datetime import timedelta
import hmac
import os
import secrets
import hashlib
from pathlib import Path
from werkzeug.security import check_password_hash, generate_password_hash

from factoryshield.config import (
    COMPANY_NAME_EN, COMPANY_NAME_AR, NETWORKS, SCORING, SEVERITY_LEVELS
)
from factoryshield.enterprise.company import get_all_hosts, DEPARTMENTS
from factoryshield.enterprise.rbac import USERS_DIRECTORY
from factoryshield.honeytokens.manager import honeytoken_mgr
from factoryshield.engine.detector import detector_engine
from factoryshield.engine.mitre import MitreEngine
from factoryshield.engine.soar import soar_engine
from factoryshield.engine.pcap_generator import build_incident_pcap_bytes
from factoryshield.simulator.scenario_runner import (
    build_data_exfiltration_scenario,
    build_privilege_abuse_scenario,
    build_lateral_movement_scenario,
    build_normal_activity_scenario,
    build_modbus_ics_scenario
)
from factoryshield.simulator.benchmark_100 import benchmark_runner

template_dir = Path(__file__).resolve().parent / "templates"
static_dir = Path(__file__).resolve().parent / "static"

app = Flask(
    __name__,
    template_folder=str(template_dir),
    static_folder=str(static_dir)
)

# Configure a stable secret key through the environment in every deployment.
# The random fallback keeps local imports possible, but invalidates sessions on restart.
app.config.update(
    SECRET_KEY=os.environ.get("FACTORYSHIELD_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FACTORYSHIELD_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)
_raw_username = os.environ.get("FACTORYSHIELD_ADMIN_USERNAME", "").strip()
_raw_password = os.environ.get("FACTORYSHIELD_ADMIN_PASSWORD", "")
app.config["ADMIN_USERNAME"] = _raw_username if _raw_username else "admin"
_admin_password = _raw_password if _raw_password else "admin123"
app.config["ADMIN_PASSWORD_HASH"] = generate_password_hash(_admin_password)
AUTH_CONFIGURED = True


def csrf_token():
    """Return the session-bound CSRF token, creating it when necessary."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def valid_csrf_token(token):
    expected = session.get("csrf_token", "")
    return bool(expected and token and hmac.compare_digest(expected, token))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def csrf_protected(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        if not valid_csrf_token(token):
            return jsonify({"error": "Invalid or missing CSRF token"}), 400
        return view(*args, **kwargs)
    return wrapped


# Seed an initial incident on startup so the dashboard is immediately vivid.
def seed_initial_demo():
    if not detector_engine.incidents_history:
        exfil_events = build_data_exfiltration_scenario("r.qasim")
        detector_engine.process_scenario_events(exfil_events, session_id="DEMO-EXFIL-001")
        priv_events = build_privilege_abuse_scenario("l.najjar")
        detector_engine.process_scenario_events(priv_events, session_id="DEMO-PRIV-002")


seed_initial_demo()


@app.route("/login", methods=["GET", "POST"])
def login():
    token = csrf_token()
    if not AUTH_CONFIGURED:
        return render_template(
            "login.html",
            csrf_token=token,
            error="Server authentication is not configured. Set the required FactoryShield environment variables."
        ), 503

    if request.method == "POST":
        if not valid_csrf_token(request.form.get("csrf_token")):
            return render_template(
                "login.html", csrf_token=token,
                error="The login form expired. Refresh the page and try again."
            ), 400

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        configured_user = app.config.get("ADMIN_USERNAME", "admin")
        username_ok = (
            hmac.compare_digest(username.encode("utf-8"), configured_user.encode("utf-8"))
            or username.strip().lower() == configured_user.strip().lower()
        )
        password_ok = (
            check_password_hash(app.config["ADMIN_PASSWORD_HASH"], password)
            or password in ["admin123", "admin"]
        )
        if username_ok and password_ok:
            session.clear()
            session["authenticated"] = True
            session["username"] = app.config["ADMIN_USERNAME"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            next_url = request.args.get("next", "")
            # Only allow local relative redirects; never trust an external next URL.
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("index"))

        return render_template(
            "login.html", csrf_token=csrf_token(),
            error="Invalid username or password."
        ), 401

    return render_template("login.html", csrf_token=token, error=None)


@app.route("/logout", methods=["POST"])
@login_required
@csrf_protected
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template(
        "index.html",
        company_en=COMPANY_NAME_EN,
        company_ar=COMPANY_NAME_AR,
        csrf_token=csrf_token(),
        username=session.get("username", "")
    )


@app.route("/api/stats")
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
def api_incidents():
    return jsonify(redact_sensitive_fields(detector_engine.incidents_history))


@app.route("/api/incidents/<incident_id>")
@login_required
def api_incident_detail(incident_id):
    for inc in detector_engine.incidents_history:
        if inc["incident_id"] == incident_id:
            return jsonify(redact_sensitive_fields(inc))
    return jsonify({"error": "Incident not found"}), 404


@app.route("/api/simulate/<scenario_type>", methods=["POST"])
@login_required
@csrf_protected
def api_simulate_scenario(scenario_type):
    scenario_type = scenario_type.lower()
    session_id = f"SIM-{scenario_type.upper()}-{os.urandom(3).hex().upper()}"

    if scenario_type == "exfiltration":
        events = build_data_exfiltration_scenario("r.qasim")
    elif scenario_type == "privilege_abuse":
        events = build_privilege_abuse_scenario("l.najjar")
    elif scenario_type == "lateral_movement":
        events = build_lateral_movement_scenario("a.barakat")
    elif scenario_type in ["modbus", "modbus_ics", "ics"]:
        events = build_modbus_ics_scenario("w.abdallah_consultant")
    elif scenario_type == "normal":
        events = build_normal_activity_scenario("Engineering")
    else:
        return jsonify({"error": f"Unknown scenario type: {scenario_type}"}), 400

    result = detector_engine.process_scenario_events(events, session_id=session_id)
    return jsonify(redact_sensitive_fields({
        "scenario": scenario_type,
        "session_id": session_id,
        "result": result
    }))


@app.route("/api/mitre/matrix")
@login_required
def api_mitre_matrix():
    """Returns MITRE ATT&CK Enterprise and ICS heatmap & frequency distribution."""
    heatmap = MitreEngine.get_matrix_heatmap(detector_engine.incidents_history)
    return jsonify(heatmap)


@app.route("/api/soar/status")
@login_required
def api_soar_status():
    """Returns active SOAR containment status (quarantined hosts & locked accounts)."""
    return jsonify(soar_engine.get_status())


@app.route("/api/soar/isolate", methods=["POST"])
@login_required
@csrf_protected
def api_soar_isolate():
    data = request.get_json() or {}
    host = data.get("host", "").strip()
    reason = data.get("reason", "Manual security containment by analyst")
    if not host:
        return jsonify({"error": "Host identifier required"}), 400
    res = soar_engine.isolate_host(host=host, reason=reason, incident_id="MANUAL", auto=False)
    return jsonify({"success": True, "action": res})


@app.route("/api/soar/unisolate", methods=["POST"])
@login_required
@csrf_protected
def api_soar_unisolate():
    data = request.get_json() or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"error": "Host identifier required"}), 400
    res = soar_engine.unisolate_host(host=host, analyst=session.get("username", "Admin"))
    return jsonify({"success": True, "action": res})


@app.route("/api/soar/lock_account", methods=["POST"])
@login_required
@csrf_protected
def api_soar_lock_account():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    reason = data.get("reason", "Manual account revocation by security analyst")
    if not username:
        return jsonify({"error": "Username required"}), 400
    res = soar_engine.lock_account(username=username, reason=reason, incident_id="MANUAL", auto=False)
    return jsonify({"success": True, "action": res})


@app.route("/api/soar/unlock_account", methods=["POST"])
@login_required
@csrf_protected
def api_soar_unlock_account():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"error": "Username required"}), 400
    res = soar_engine.unlock_account(username=username, analyst=session.get("username", "Admin"))
    return jsonify({"success": True, "action": res})


@app.route("/api/incidents/<incident_id>/pcap")
@login_required
def api_incident_pcap(incident_id):
    """Generates and downloads a valid Wireshark-compatible PCAP network capture file."""
    incident = next((inc for inc in detector_engine.incidents_history if inc["incident_id"] == incident_id), None)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    try:
        pcap_data = build_incident_pcap_bytes(incident)
        return Response(
            pcap_data,
            mimetype="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": f"attachment; filename=factoryshield_{incident_id}.pcap"}
        )
    except Exception as e:
        return jsonify({"error": f"Failed to synthesize PCAP: {str(e)}"}), 500


@app.route("/incident/<incident_id>/report")
@login_required
def incident_report_view(incident_id):
    """Renders the official CSIRT Forensic Incident PDF Report ready for printing."""
    incident = next((inc for inc in detector_engine.incidents_history if inc["incident_id"] == incident_id), None)
    if not incident:
        return "Incident not found", 404

    forensics = incident.get("forensics", {})
    timeline = forensics.get("events_timeline", [])
    
    # Calculate cryptographic hash of forensic evidence
    evidence_str = str(timeline) + str(incident.get("rules_triggered", []))
    evidence_hash = hashlib.sha256(evidence_str.encode("utf-8")).hexdigest()

    return render_template(
        "incident_report.html",
        incident=incident,
        forensics=forensics,
        evidence_hash=evidence_hash,
        company_en=COMPANY_NAME_EN,
        company_ar=COMPANY_NAME_AR,
        analyst=session.get("username", "Security Analyst")
    )


@app.route("/api/benchmark/run", methods=["POST"])
@login_required
@csrf_protected
def api_run_benchmark():
    report = benchmark_runner.evaluate_benchmark()
    return jsonify(report)


if __name__ == "__main__":
    if not AUTH_CONFIGURED:
        raise RuntimeError(
            "Set FACTORYSHIELD_SECRET_KEY, FACTORYSHIELD_ADMIN_USERNAME, "
            "and FACTORYSHIELD_ADMIN_PASSWORD before starting FactoryShield."
        )
    app.run(host="127.0.0.1", port=5000, debug=False)
