"""
Role-Based Access Control (RBAC) & Identity Model
Jordan Industrial Manufacturing (JIM)
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class EnterpriseUser:
    username: str
    full_name: str
    department: str
    role: str
    allowed_resources: Set[str]
    default_workstation: str
    is_canary: bool = False

# Realistic Enterprise Employees Directory (All synthetic data)
USERS_DIRECTORY: Dict[str, EnterpriseUser] = {
    # Management
    "m.khalil": EnterpriseUser(
        username="m.khalil",
        full_name="Mahmoud Khalil",
        department="Management",
        role="Chief Executive Officer",
        allowed_resources={"reports/executive", "reports/financial", "mgmt/dashboard"},
        default_workstation="WS-MGMT-01"
    ),
    "s.mansour": EnterpriseUser(
        username="s.mansour",
        full_name="Sami Mansour",
        department="Management",
        role="Operations Director",
        allowed_resources={"reports/executive", "reports/operations", "mgmt/dashboard"},
        default_workstation="WS-MGMT-01"
    ),
    # Engineering
    "t.haddad": EnterpriseUser(
        username="t.haddad",
        full_name="Tareq Haddad",
        department="Engineering",
        role="Lead Mechanical Engineer",
        allowed_resources={"cad/models", "cad/specs", "cad/blueprints", "engineering/repo"},
        default_workstation="WS-ENG-01"
    ),
    "r.qasim": EnterpriseUser(
        username="r.qasim",
        full_name="Rania Qasim",
        department="Engineering",
        role="CAD Design Engineer",
        allowed_resources={"cad/models", "cad/specs", "engineering/repo"},
        default_workstation="WS-ENG-01"
    ),
    # Production
    "o.alali": EnterpriseUser(
        username="o.alali",
        full_name="Omar Al-Ali",
        department="Production",
        role="Plant Operations Supervisor",
        allowed_resources={"production/db", "production/schedules", "production/hmi", "ot/telemetry"},
        default_workstation="WS-PROD-01"
    ),
    "k.masri": EnterpriseUser(
        username="k.masri",
        full_name="Khaled Al-Masri",
        department="Production",
        role="Assembly Line Operator",
        allowed_resources={"production/schedules", "production/hmi"},
        default_workstation="WS-PROD-01"
    ),
    # HR
    "l.najjar": EnterpriseUser(
        username="l.najjar",
        full_name="Layla Al-Najjar",
        department="HR",
        role="Senior HR Specialist",
        allowed_resources={"hr/employees", "hr/payroll", "hr/portal"},
        default_workstation="WS-HR-01"
    ),
    "d.khatib": EnterpriseUser(
        username="d.khatib",
        full_name="Dana Al-Khatib",
        department="HR",
        role="Payroll & Benefits Officer",
        allowed_resources={"hr/payroll", "hr/portal"},
        default_workstation="WS-HR-01"
    ),
    # IT
    "a.barakat": EnterpriseUser(
        username="a.barakat",
        full_name="Ahmad Barakat",
        department="IT",
        role="Senior Systems Administrator",
        allowed_resources={"it/admin", "it/servers", "it/network", "mgmt/dashboard"},
        default_workstation="WS-IT-01"
    ),
    # CANARY ACCOUNTS (Decoys - Should NEVER perform normal business activity)
    "svc_eng_backup": EnterpriseUser(
        username="svc_eng_backup",
        full_name="CAD Backup Service Account",
        department="Engineering",
        role="Automated Backup Daemon (Decoy)",
        allowed_resources=set(),
        default_workstation="UNKNOWN",
        is_canary=True
    ),
    "w.abdallah_consultant": EnterpriseUser(
        username="w.abdallah_consultant",
        full_name="Waleed Abdallah (External Consultant)",
        department="External",
        role="Inactive Third-Party Auditor (Decoy)",
        allowed_resources=set(),
        default_workstation="UNKNOWN",
        is_canary=True
    )
}

def get_user(username: str) -> Optional[EnterpriseUser]:
    return USERS_DIRECTORY.get(username.lower())

def evaluate_access(username: str, resource: str, operation: str = "read") -> Tuple[bool, str]:
    """
    Evaluates whether a user has legitimate access to a target resource.
    Returns: (is_allowed, reason)
    """
    user = get_user(username)
    if not user:
        return False, f"Unknown account: '{username}' does not exist in JIM directory."
    
    if user.is_canary:
        return False, f"Canary account triggered: '{username}' is a decoy account and has no legitimate access rights."

    # Normalize resource prefix
    resource_clean = resource.strip("/").lower()
    for allowed in user.allowed_resources:
        if resource_clean.startswith(allowed.lower()) or allowed.lower() in resource_clean:
            return True, f"Authorized: User '{username}' ({user.role} - {user.department}) is permitted to access '{resource}'."

    return False, f"Policy Violation: User '{username}' in department '{user.department}' attempted unauthorized access to '{resource}'."
