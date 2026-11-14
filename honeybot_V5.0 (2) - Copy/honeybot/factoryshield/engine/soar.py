"""
FactoryShield: Automated SOAR & Active Defense Containment Engine
Implements zero-trust automated containment, host isolation, account revocation,
and incident webhook notifications for critical enterprise threats.
"""
import os
import json
import uuid
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

class SOAREngine:
    def __init__(self):
        # Active isolation and account lock states
        self.isolated_hosts: Dict[str, Dict[str, Any]] = {}
        self.locked_accounts: Dict[str, Dict[str, Any]] = {}
        self.action_logs: List[Dict[str, Any]] = []
        self.webhook_url: Optional[str] = os.environ.get("FACTORYSHIELD_WEBHOOK_URL", None)

    def is_host_isolated(self, host: str) -> bool:
        return host in self.isolated_hosts

    def is_account_locked(self, username: str) -> bool:
        return username in self.locked_accounts

    def isolate_host(self, host: str, reason: str, incident_id: str, auto: bool = False) -> Dict[str, Any]:
        """
        Isolates a host from enterprise network communication via simulated firewall quarantine.
        """
        action_id = f"ACT-ISO-{uuid.uuid4().hex[:6].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat() + "Z"
        entry = {
            "action_id": action_id,
            "action_type": "HOST_ISOLATION",
            "target": host,
            "target_type": "Host / Workstation",
            "reason": reason,
            "incident_id": incident_id,
            "timestamp": timestamp,
            "status": "ISOLATED",
            "policy": "Drop all ingress/egress except Forensics SOC",
            "executed_by": "Automated SOAR Engine" if auto else "Security Analyst"
        }
        self.isolated_hosts[host] = entry
        self.action_logs.insert(0, entry)
        return entry

    def unisolate_host(self, host: str, analyst: str = "Admin") -> Dict[str, Any]:
        """
        Restores network connectivity for a previously isolated host.
        """
        if host in self.isolated_hosts:
            del self.isolated_hosts[host]
        action_id = f"ACT-RESTORE-{uuid.uuid4().hex[:6].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat() + "Z"
        entry = {
            "action_id": action_id,
            "action_type": "HOST_RESTORED",
            "target": host,
            "target_type": "Host / Workstation",
            "reason": "Security Analyst released quarantine after forensic investigation",
            "incident_id": "MANUAL",
            "timestamp": timestamp,
            "status": "ACTIVE",
            "policy": "Normal network routing re-established",
            "executed_by": f"Analyst ({analyst})"
        }
        self.action_logs.insert(0, entry)
        return entry

    def lock_account(self, username: str, reason: str, incident_id: str, auto: bool = False) -> Dict[str, Any]:
        """
        Revokes user tokens and disables domain/RBAC account immediately.
        """
        action_id = f"ACT-LOCK-{uuid.uuid4().hex[:6].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat() + "Z"
        entry = {
            "action_id": action_id,
            "action_type": "ACCOUNT_REVOCATION",
            "target": username,
            "target_type": "User Account / Identity",
            "reason": reason,
            "incident_id": incident_id,
            "timestamp": timestamp,
            "status": "LOCKED",
            "policy": "IAM/AD session tokens invalidated; login prohibited",
            "executed_by": "Automated SOAR Engine" if auto else "Security Analyst"
        }
        self.locked_accounts[username] = entry
        self.action_logs.insert(0, entry)
        return entry

    def unlock_account(self, username: str, analyst: str = "Admin") -> Dict[str, Any]:
        """
        Restores account credentials and access rights.
        """
        if username in self.locked_accounts:
            del self.locked_accounts[username]
        action_id = f"ACT-UNLOCK-{uuid.uuid4().hex[:6].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat() + "Z"
        entry = {
            "action_id": action_id,
            "action_type": "ACCOUNT_UNLOCKED",
            "target": username,
            "target_type": "User Account / Identity",
            "reason": "Identity verified and access restored by analyst",
            "incident_id": "MANUAL",
            "timestamp": timestamp,
            "status": "ACTIVE",
            "policy": "Standard RBAC permissions restored",
            "executed_by": f"Analyst ({analyst})"
        }
        self.action_logs.insert(0, entry)
        return entry

    def evaluate_and_contain(self, incident: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Automated Incident Response Policy:
        If severity is Critical (score >= 80), automatically execute:
        1. Quarantine the source workstation
        2. Revoke the actor's session and account
        3. Dispatch SOC webhook alert
        """
        score = incident.get("score", 0)
        incident_id = incident.get("incident_id", "UNKNOWN")
        actor = incident.get("actor", "anonymous")
        source_host = incident.get("source_workstation", "Unknown")
        actions_taken = []

        if score >= 80:
            # 1. Isolate host
            if source_host and source_host != "Unknown" and source_host not in self.isolated_hosts:
                iso = self.isolate_host(
                    host=source_host,
                    reason=f"Automated containment triggered by Critical incident {incident_id} (Score {score}/100)",
                    incident_id=incident_id,
                    auto=True
                )
                actions_taken.append(iso)

            # 2. Lock account
            if actor and actor != "anonymous" and actor not in self.locked_accounts:
                lock = self.lock_account(
                    username=actor,
                    reason=f"Account revoked due to unauthorized high-risk operations flagged in {incident_id}",
                    incident_id=incident_id,
                    auto=True
                )
                actions_taken.append(lock)

            # 3. Dispatch Webhook Alert
            self.dispatch_webhook(incident, actions_taken)

        return actions_taken

    def dispatch_webhook(self, incident: Dict[str, Any], actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Dispatches real-time incident alert to configured SOC Webhook (Slack, Discord, Telegram, or internal SIEM).
        """
        actions_desc = ", ".join([f"{a['action_type']}: {a['target']}" for a in actions]) or "Under Analyst Review"
        payload = {
            "alert": "CRITICAL_SECURITY_INCIDENT",
            "source": "FactoryShield Cyber Deception SOAR",
            "incident_id": incident.get("incident_id"),
            "score": incident.get("score"),
            "severity": incident.get("severity"),
            "actor": incident.get("actor"),
            "workstation": incident.get("source_workstation"),
            "rules_triggered": incident.get("rules_triggered", []),
            "containment_actions": actions_desc,
            "timestamp": incident.get("timestamp"),
            "dashboard_url": f"http://localhost:5000"
        }

        # If a real webhook URL is provided, send HTTP POST
        webhook_status = "Simulated / Logged"
        if self.webhook_url:
            try:
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    self.webhook_url,
                    data=data,
                    headers={"Content-Type": "application/json", "User-Agent": "FactoryShield-SOAR/1.0"}
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    webhook_status = f"Dispatched HTTP {resp.status}"
            except Exception as e:
                webhook_status = f"Webhook error: {str(e)}"

        log_entry = {
            "action_id": f"ACT-NOTIF-{uuid.uuid4().hex[:6].upper()}",
            "action_type": "SOC_ALERT_DISPATCHED",
            "target": "SOC SIEM / Webhook Channel",
            "target_type": "Alert Notification",
            "reason": f"Dispatched real-time alert for {incident.get('incident_id')} with actions: {actions_desc}",
            "incident_id": incident.get("incident_id"),
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "status": webhook_status,
            "policy": "Instant notification broadcast to Incident Response Team",
            "executed_by": "SOAR Notification Dispatcher"
        }
        self.action_logs.insert(0, log_entry)
        return log_entry

    def get_status(self) -> Dict[str, Any]:
        return {
            "isolated_hosts": list(self.isolated_hosts.values()),
            "locked_accounts": list(self.locked_accounts.values()),
            "total_isolated_hosts": len(self.isolated_hosts),
            "total_locked_accounts": len(self.locked_accounts),
            "action_logs": self.action_logs[:50]
        }

# Global SOAR instance
soar_engine = SOAREngine()
