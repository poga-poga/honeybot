"""
Scoring and Threat Severity Classification
FactoryShield Deterministic Engine
"""
from typing import List, Dict, Any
from factoryshield.config import get_severity
from factoryshield.engine.rules import RuleEvaluationResult

class ScoringEngine:
    @staticmethod
    def calculate_incident_score(rules_triggered: List[RuleEvaluationResult]) -> Dict[str, Any]:
        """
        Calculates the cumulative deterministic score (0 - 100) based on triggered rules.
        """
        raw_score = sum(r.points for r in rules_triggered if r.triggered)
        clamped_score = min(100, max(0, raw_score))
        severity = get_severity(clamped_score)

        return {
            "score": clamped_score,
            "raw_score": raw_score,
            "severity_level": severity["name"],
            "severity_level_ar": severity["name_ar"],
            "severity_color": severity["color"],
            "rules_count": len(rules_triggered),
            "triggered_rule_ids": [r.rule_id for r in rules_triggered if r.triggered]
        }
