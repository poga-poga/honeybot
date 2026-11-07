"""
FactoryShield Web Forensics & Security Dashboard
Flask application with session-based dashboard/API authentication.
"""
from flask import (
    Flask, render_template, jsonify, request, redirect, url_for, session
)
from functools import wraps
from datetime import timedelta
import hmac
import os
import secrets
from pathlib import Path
from werkzeug.security import check_password_hash, generate_password_hash

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

# Configure a stable secret key through the environment in every deployment.
# The random fallback keeps local imports possible, but invalidates sessions on restart.
app.config.update(
    SECRET_KEY=os.environ.get("FACTORYSHIELD_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FACTORYSHIELD_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)
app.config["ADMIN_USERNAME"] = os.environ.get("FACTORYSHIELD_ADMIN_USERNAME", "").strip()
_admin_password = os.environ.get("FACTORYSHIELD_ADMIN_PASSWORD", "")
app.config["ADMIN_PASSWORD_HASH"] = (
    generate_password_hash(_admin_password) if _admin_password else None
)
AUTH_CONFIGURED = bool(
    os.environ.get("FACTORYSHIELD_SECRET_KEY")
    and app.config["ADMIN_USERNAME"]
    and app.config["ADMIN_PASSWORD_HASH"]
)


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
        username_ok = hmac.compare_digest(
            username.encode("utf-8"),
            app.config["ADMIN_USERNAME"].encode("utf-8")
        )
        password_ok = check_password_hash(app.config["ADMIN_PASSWORD_HASH"], password)
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
