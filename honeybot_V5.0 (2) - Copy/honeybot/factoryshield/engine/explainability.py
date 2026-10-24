"""
Forensic Explainability & Audit Engine
Produces verifiable, transparent, and interpretable incident reports.
"""
from typing import List, Dict, Any
from datetime import datetime

class ExplainabilityEngine:
    @staticmethod
    def generate_incident_explanation(
        incident_id: str,
        session_id: str,
        username: str,
        user_dept: str,
        source_host: str,
        score_info: Dict[str, Any],
        triggered_rules: List[Any],
        events_timeline: List[Dict[str, Any]],
        mitre_tactics: List[str]
    ) -> Dict[str, Any]:
        """
        Builds an explainable forensic justification breakdown for security analysts.
        """
        rule_breakdowns = []
        for r in triggered_rules:
            rule_breakdowns.append({
                "rule_id": r.rule_id,
                "name_en": r.rule_name_en,
                "name_ar": r.rule_name_ar,
                "points_contributed": r.points,
                "explanation_en": r.explanation_en,
                "explanation_ar": r.explanation_ar,
                "evidence": r.evidence
            })

        # Generate summary synthesis in both English and Arabic
        points_str = " + ".join([f"{r.rule_id}({r.points}pts)" for r in triggered_rules])
        
        ar_summary = (
            f"تم تصنيف الحادث بمستوى [{score_info['severity_level_ar']}] بمجموع {score_info['score']}/100 نقطة ({points_str}). "
            f"الحساب المعني '{username}' (قسم: {user_dept}) بدأ النشاط من محطة '{source_host}'. "
            f"استند القرار الأمني إلى مطابقة {len(triggered_rules)} قواعد حتمية واضحة ومسار تسلسل زمني من {len(events_timeline)} أحداث مرصودة."
        )

        en_summary = (
            f"Incident classified as [{score_info['severity_level']}] with score {score_info['score']}/100 ({points_str}). "
            f"Actor '{username}' (Dept: {user_dept}) initiated activity from '{source_host}'. "
            f"Verdict verified via {len(triggered_rules)} deterministic rules correlated across a {len(events_timeline)}-event forensic timeline."
        )

        return {
            "incident_id": incident_id,
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "actor": {
                "username": username,
                "department": user_dept,
                "source_workstation": source_host,
            },
            "verdict": {
                "score": score_info["score"],
                "severity": score_info["severity_level"],
                "severity_ar": score_info["severity_level_ar"],
                "color": score_info["severity_color"]
            },
            "mitre_att_ck": mitre_tactics,
            "synthesis_ar": ar_summary,
            "synthesis_en": en_summary,
            "rule_contributions": rule_breakdowns,
            "events_timeline": events_timeline
        }
