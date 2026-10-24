"""
Baseline Detection Engine (Isolated Single-Event Evaluation)
Used as an Academic Comparative Baseline against FactoryShield.
Evaluates individual events in isolation without cross-host correlation,
without RBAC context, and without multi-step temporal tracking.
"""
from typing import Dict, Any, List

class BaselineEngine:
    def __init__(self):
        # Naive keyword lists commonly found in isolated SIEM alerts
        self.suspicious_keywords = ["secret", "bypass", "override", "backup", "dump", "export", "cad"]

    def evaluate_isolated_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inspects an isolated single event without context or correlation.
        """
        raw_text = f"{event.get('resource', '')} {event.get('action', '')} {event.get('query', '')} {event.get('details', '')}".lower()
        matched_keywords = [kw for kw in self.suspicious_keywords if kw in raw_text]

        # Naive condition 1: Any simple keyword match triggers an alert
        is_alert = len(matched_keywords) > 0

        # Naive condition 2: Any failed auth or error triggers alert
        if event.get("status") in ["DENIED", "FAILED", "403"]:
            is_alert = True

        return {
            "engine": "Baseline (Isolated Rules)",
            "alert_generated": is_alert,
            "matched_keywords": matched_keywords,
            "reason": f"Isolated keyword/status trigger: {matched_keywords}" if is_alert else "No isolated pattern",
            "score": 50 if is_alert else 0
        }

    def evaluate_scenario(self, scenario_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluates a complete sequence of events using isolated rules.
        If ANY isolated event flagged an alert, baseline generates an alert.
        """
        alerts = []
        for ev in scenario_events:
            res = self.evaluate_isolated_event(ev)
            if res["alert_generated"]:
                alerts.append(res)

        return {
            "engine": "Baseline (Isolated Events)",
            "alert_generated": len(alerts) > 0,
            "alerts_count": len(alerts),
            "alerts": alerts
        }
