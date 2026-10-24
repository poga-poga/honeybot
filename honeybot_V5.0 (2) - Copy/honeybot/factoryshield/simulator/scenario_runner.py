"""
Attack & Enterprise Activity Scenarios
Jordan Industrial Manufacturing (JIM)
"""
from typing import List, Dict, Any
from datetime import datetime, timedelta
import random

def create_event(
    username: str,
    source_host: str,
    target_host: str,
    resource: str,
    action: str = "read",
    status: str = "SUCCESS",
    query: str = "",
    api_key: str = "",
    offset_seconds: int = 0
) -> Dict[str, Any]:
    timestamp = (datetime.utcnow() + timedelta(seconds=offset_seconds)).isoformat() + "Z"
    return {
        "timestamp": timestamp,
        "username": username,
        "source_host": source_host,
        "target_host": target_host,
        "resource": resource,
        "action": action,
        "status": status,
        "query": query,
        "api_key": api_key
    }

# Specific Threat Scenarios
def build_data_exfiltration_scenario(username: str = "r.qasim") -> List[Dict[str, Any]]:
    """
    Scenario A: Data Exfiltration
    User accesses CAD repository, opens Canary Blueprint, then triggers synthetic archive export.
    """
    return [
        create_event(username, "WS-ENG-01", "cad-srv01.jim.corp", "cad/models/gearbox_v2.dwg", "read", offset_seconds=0),
        create_event(username, "WS-ENG-01", "cad-srv01.jim.corp", "cad/blueprints/Turbine_Rotor_Gen4_Confidential_Blueprints.dwg", "read", offset_seconds=10),
        create_event(username, "WS-ENG-01", "cad-srv01.jim.corp", "cad/export/synthetic_archive.zip", "export", offset_seconds=25),
    ]

def build_privilege_abuse_scenario(username: str = "l.najjar") -> List[Dict[str, Any]]:
    """
    Scenario B: Privilege Abuse
    HR employee attempts to access Engineering CAD server and Production Database.
    """
    return [
        create_event(username, "WS-HR-01", "cad-srv01.jim.corp", "cad/models/turbine_assembly.dwg", "read", status="DENIED", offset_seconds=0),
        create_event(username, "WS-HR-01", "db-prod01.jim.corp", "production/db/secret_rnd_formulations", "query", status="DENIED", offset_seconds=15),
    ]

def build_lateral_movement_scenario(username: str = "a.barakat") -> List[Dict[str, Any]]:
    """
    Scenario C: Lateral Movement
    Multi-host progression: Workstation (Office) -> CAD Server (Engineering) -> Production Database & PLC (Production).
    """
    return [
        create_event(username, "WS-IT-01", "WS-IT-01", "it/admin/login", "auth", offset_seconds=0),
        create_event(username, "WS-IT-01", "cad-srv01.jim.corp", "cad/repo/ssh_session", "connect", offset_seconds=10),
        create_event(username, "cad-srv01.jim.corp", "db-prod01.jim.corp", "production/db/internal_query", "query", offset_seconds=25),
        create_event(username, "db-prod01.jim.corp", "plc-sim01.jim.corp", "ot/plc/hold_registers", "modbus_read", offset_seconds=40),
    ]

def build_normal_activity_scenario(dept: str = "Engineering") -> List[Dict[str, Any]]:
    """
    Normal legitimate business operation aligned with employee's RBAC role.
    """
    if dept == "Engineering":
        return [
            create_event("t.haddad", "WS-ENG-01", "cad-srv01.jim.corp", "cad/models/chassis_bracket.dwg", "read", offset_seconds=0),
            create_event("t.haddad", "WS-ENG-01", "cad-srv01.jim.corp", "cad/specs/material_tolerances.pdf", "read", offset_seconds=12),
        ]
    elif dept == "Production":
        return [
            create_event("o.alali", "WS-PROD-01", "db-prod01.jim.corp", "production/schedules/daily_run", "query", query="SELECT * FROM production_lines", offset_seconds=0),
            create_event("o.alali", "WS-PROD-01", "hmi-prod01.jim.corp", "production/hmi/dashboard", "read", offset_seconds=15),
        ]
    elif dept == "HR":
        return [
            create_event("l.najjar", "WS-HR-01", "WS-HR-01", "hr/employees/directory", "read", offset_seconds=0),
            create_event("l.najjar", "WS-HR-01", "WS-HR-01", "hr/payroll/september_records", "read", offset_seconds=20),
        ]
    else:
        return [
            create_event("m.khalil", "WS-MGMT-01", "WS-MGMT-01", "reports/executive/q3_summary", "read", offset_seconds=0),
        ]
