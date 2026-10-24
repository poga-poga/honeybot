"""
FactoryShield Context-Aware Deterministic Correlation Engine
Implements Multi-Layer Deception, RBAC Policy Verification, and Lateral Movement Tracking.
"""
import uuid
import time
from typing import List, Dict, Any, Optional
from datetime import datetime

from factoryshield.enterprise.rbac import evaluate_access, get_user
from factoryshield.enterprise.company import get_host_by_name, get_host_by_ip
from factoryshield.honeytokens.manager import honeytoken_mgr
from factoryshield.engine.rules import RuleEvaluationResult, RULES_METADATA
from factoryshield.engine.scoring import ScoringEngine
from factoryshield.engine.explainability import ExplainabilityEngine

class FactoryShieldDetector:
    def __init__(self):
        self.active_sessions: Dict[str, List[Dict[str, Any]]] = {}
        self.incidents_history: List[Dict[str, Any]] = []

    def process_scenario_events(self, events: List[Dict[str, Any]], session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Processes a full correlated timeline of events for an entity/session.
        Evaluates R1 - R5 and generates an explainable verdict.
        """
        start_time = time.perf_counter()
        session_id = session_id or f"sess-{uuid.uuid4().hex[:8]}"
        incident_id = f"FS-INC-{int(time.time())}-{uuid.uuid4().hex[:4].upper()}"

        if not events:
            return {
                "incident_id": incident_id,
                "alert_generated": False,
                "score": 0,
                "severity": "Low",
                "rules_triggered": [],
                "explanation": "No events provided in sequence."
            }

        # Context Extraction
        primary_username = events[0].get("username", "anonymous")
        user_obj = get_user(primary_username)
        user_dept = user_obj.department if user_obj else "Unknown"
        initial_host = events[0].get("source_host", "Unknown")

        triggered_rules: List[RuleEvaluationResult] = []
        mitre_tactics = set()

        # State tracking across timeline
        hosts_traversed = []
        departments_touched = set()
        canaries_hit = []
        privilege_violations = []
        exfiltration_indicators = []

        # Analyze each event
        for ev in events:
            src_host = ev.get("source_host", "")
            tgt_host = ev.get("target_host", "")
            resource = ev.get("resource", "")
            action = ev.get("action", "")
            query = ev.get("query", "")
            api_key = ev.get("api_key", "")
            username = ev.get("username", primary_username)

            if src_host and src_host not in hosts_traversed:
                hosts_traversed.append(src_host)
            if tgt_host and tgt_host not in hosts_traversed:
                hosts_traversed.append(tgt_host)

            # Check target host department
            host_info = get_host_by_name(tgt_host) or get_host_by_ip(tgt_host)
            if host_info and host_info.department:
                departments_touched.add(host_info.department)

            # 1. Evaluate Canary / Decoy
            token_hit = honeytoken_mgr.inspect_event_for_honeytoken(
                resource=resource,
                query=query,
                username=username,
                api_key=api_key
            )
            if token_hit:
                canaries_hit.append({
                    "token_id": token_hit.token_id,
                    "token_type": token_hit.token_type,
                    "identifier": token_hit.identifier,
                    "resource": resource,
                    "event": ev
                })

            # 2. Evaluate RBAC Policy
            if resource:
                is_allowed, reason = evaluate_access(username, resource, action)
                if not is_allowed:
                    privilege_violations.append({
                        "username": username,
                        "resource": resource,
                        "action": action,
                        "reason": reason
                    })

            # 3. Evaluate Exfiltration action
            if action in ["export", "dump", "download_archive", "exfiltrate"] or "export" in resource.lower():
                exfiltration_indicators.append(ev)

        # Apply Rule Logic
        # R1: Decoy / Honeytoken Access
        if canaries_hit:
            meta = RULES_METADATA["R1"]
            first_canary = canaries_hit[0]
            triggered_rules.append(RuleEvaluationResult(
                rule_id="R1",
                rule_name_en=meta["name_en"],
                rule_name_ar=meta["name_ar"],
                triggered=True,
                points=meta["points"],
                explanation_en=f"Accessed decoy {first_canary['token_type']}: '{first_canary['identifier']}'.",
                explanation_ar=f"تم رصد الوصول إلى مورد خادع ({first_canary['token_type']}): '{first_canary['identifier']}'.",
                evidence={"canaries_touched": [c["identifier"] for c in canaries_hit]}
            ))
            mitre_tactics.add("T1078 - Valid Accounts / Decoys")

        # R2: Privilege Policy Violation
        if privilege_violations:
            meta = RULES_METADATA["R2"]
            first_viol = privilege_violations[0]
            triggered_rules.append(RuleEvaluationResult(
                rule_id="R2",
                rule_name_en=meta["name_en"],
                rule_name_ar=meta["name_ar"],
                triggered=True,
                points=meta["points"],
                explanation_en=f"Unauthorized access by '{first_viol['username']}' to '{first_viol['resource']}'. {first_viol['reason']}",
                explanation_ar=f"محاولة وصول غير مصرح بها من '{first_viol['username']}' للمورد '{first_viol['resource']}'. {first_viol['reason']}",
                evidence={"violations_count": len(privilege_violations), "details": privilege_violations[0]}
            ))
            mitre_tactics.add("T1078.004 - Privilege Escalation & Abuse")

        # R3: Cross-Department Anomalous Sequence
        if len(departments_touched) >= 2:
            meta = RULES_METADATA["R3"]
            depts_list = list(departments_touched)
            triggered_rules.append(RuleEvaluationResult(
                rule_id="R3",
                rule_name_en=meta["name_en"],
                rule_name_ar=meta["name_ar"],
                triggered=True,
                points=meta["points"],
                explanation_en=f"Cross-department sequential activity across: {', '.join(depts_list)}.",
                explanation_ar=f"رصد نشاط متسلسل عبر أقسام مؤسسية متعددة: {', '.join(depts_list)}.",
                evidence={"departments": depts_list}
            ))
            mitre_tactics.add("T1087 - Account & Permission Discovery")

        # R4: Data Exfiltration Indicator
        if exfiltration_indicators and (canaries_hit or privilege_violations):
            meta = RULES_METADATA["R4"]
            triggered_rules.append(RuleEvaluationResult(
                rule_id="R4",
                rule_name_en=meta["name_en"],
                rule_name_ar=meta["name_ar"],
                triggered=True,
                points=meta["points"],
                explanation_en=f"Sensitive/Decoy data touched followed by data staging/export: {len(exfiltration_indicators)} export event(s).",
                explanation_ar=f"الوصول لبيانات حساسة أو خادعة متبوعاً بمحاولة تصدير أو نقل بيانات اصطناعية ({len(exfiltration_indicators)} حدث تصدير).",
                evidence={"exfil_events": len(exfiltration_indicators)}
            ))
            mitre_tactics.add("T1048 - Exfiltration Over Alternative Protocol")

        # R5: Lateral Movement Progression
        # Occurs when sequence involves an authentic pivot chain: a target host becomes the source host for subsequent hops
        previous_targets = set()
        pivots = []
        for ev in events:
            src = ev.get("source_host", "")
            tgt = ev.get("target_host", "")
            if src in previous_targets and src != initial_host and src != tgt:
                pivots.append(f"{src} -> {tgt}")
            if tgt:
                previous_targets.add(tgt)

        if pivots:
            meta = RULES_METADATA["R5"]
            pivot_path = " | ".join(pivots)
            triggered_rules.append(RuleEvaluationResult(
                rule_id="R5",
                rule_name_en=meta["name_en"],
                rule_name_ar=meta["name_ar"],
                triggered=True,
                points=meta["points"],
                explanation_en=f"Lateral movement pivot chain detected: {pivot_path}.",
                explanation_ar=f"رصد مسار انتقال متسلسل بين أجهزة متعددة عبر نقطة وسيطة (Pivot Chain): {pivot_path}.",
                evidence={"pivots": pivots, "pivot_path": pivot_path}
            ))
            mitre_tactics.add("T1021 - Remote Services / Lateral Movement")

        # Scoring & Classification
        score_info = ScoringEngine.calculate_incident_score(triggered_rules)
        alert_generated = len(triggered_rules) > 0  # Alert is generated if any deterministic rule R1-R5 triggered

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)

        forensic_report = ExplainabilityEngine.generate_incident_explanation(
            incident_id=incident_id,
            session_id=session_id,
            username=primary_username,
            user_dept=user_dept,
            source_host=initial_host,
            score_info=score_info,
            triggered_rules=triggered_rules,
            events_timeline=events,
            mitre_tactics=list(mitre_tactics)
        )

        captured_passwords = [ev.get("password_captured") for ev in events if ev.get("password_captured")]
        captured_password = captured_passwords[0] if captured_passwords else None
        service_name = events[0].get("service_name") or ("CAD Web Portal (8088)" if "cad" in events[0].get("target_host", "") else "Enterprise Host")

        incident_entry = {
            "incident_id": incident_id,
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "alert_generated": alert_generated,
            "score": score_info["score"],
            "severity": score_info["severity_level"],
            "severity_ar": score_info["severity_level_ar"],
            "severity_color": score_info["severity_color"],
            "rules_triggered": [r.rule_id for r in triggered_rules],
            "rules_details": [r.__dict__ for r in triggered_rules],
            "actor": primary_username,
            "captured_password": captured_password,
            "service_name": service_name,
            "department": user_dept,
            "source_workstation": initial_host,
            "hosts_traversed": hosts_traversed,
            "detection_time_ms": elapsed_ms,
            "forensics": forensic_report
        }

        if alert_generated:
            self.incidents_history.insert(0, incident_entry)

        return incident_entry

# Global detector instance
detector_engine = FactoryShieldDetector()
