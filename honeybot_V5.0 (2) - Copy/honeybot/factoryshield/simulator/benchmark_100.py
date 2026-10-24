"""
Academic Evaluation Benchmark Suite (100 Scenarios)
Compares Baseline (Isolated Single-Event Rules) vs. FactoryShield (Context-Aware Multi-Layer Honeypot)
"""
import time
import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Tuple
from pathlib import Path

from factoryshield.simulator.scenario_runner import (
    create_event,
    build_data_exfiltration_scenario,
    build_privilege_abuse_scenario,
    build_lateral_movement_scenario,
    build_normal_activity_scenario
)
from factoryshield.engine.baseline_engine import BaselineEngine
from factoryshield.engine.detector import FactoryShieldDetector

@dataclass
class ScenarioTestItem:
    scenario_id: str
    scenario_type: str  # Normal, Privilege Abuse, Decoy Access, Exfiltration, Lateral Movement
    is_malicious: bool
    description_ar: str
    description_en: str
    events: List[Dict[str, Any]]

class BenchmarkSuite:
    def __init__(self):
        self.baseline = BaselineEngine()
        self.factoryshield = FactoryShieldDetector()

    def generate_100_scenarios(self) -> List[ScenarioTestItem]:
        scenarios: List[ScenarioTestItem] = []
        idx = 1

        # 1. Normal Authorized Activities (40 scenarios) -> is_malicious = False
        depts = ["Engineering", "Production", "HR", "Management"]
        for i in range(40):
            d = depts[i % len(depts)]
            scenarios.append(ScenarioTestItem(
                scenario_id=f"SCEN-NORM-{idx:03d}",
                scenario_type="Normal Authorized Activity",
                is_malicious=False,
                description_ar=f"نشاط اعتيادي مصرح به لموظف في قسم {d}",
                description_en=f"Normal authorized activity for {d} personnel",
                events=build_normal_activity_scenario(d)
            ))
            idx += 1

        # 2. Privilege Abuse Scenarios (20 scenarios) -> is_malicious = True
        users_viol = [
            ("l.najjar", "cad/models/sensitive_part.dwg", "cad-srv01.jim.corp", "HR employee accessing Engineering CAD"),
            ("d.khatib", "production/db/secret_run", "db-prod01.jim.corp", "Payroll officer querying Production DB"),
            ("k.masri", "hr/payroll/salaries.xlsx", "WS-HR-01", "Line operator attempting to read HR payroll"),
            ("r.qasim", "reports/executive/board_minutes", "WS-MGMT-01", "CAD designer attempting to read Board Minutes"),
        ]
        for i in range(20):
            u, res, target, desc = users_viol[i % len(users_viol)]
            evs = [
                create_event(u, "WS-HR-01", target, res, "read", status="DENIED", offset_seconds=0),
                create_event(u, "WS-HR-01", target, res, "read", status="DENIED", offset_seconds=5)
            ]
            scenarios.append(ScenarioTestItem(
                scenario_id=f"SCEN-PRIV-{idx:03d}",
                scenario_type="Privilege Abuse",
                is_malicious=True,
                description_ar=f"محاولة موظف الوصول لمورد خارج قسمه ({u} -> {res})",
                description_en=desc,
                events=evs
            ))
            idx += 1

        # 3. Decoy / Honeytoken Access Scenarios (15 scenarios) -> is_malicious = True
        canaries_test = [
            ("r.qasim", "WS-ENG-01", "cad-srv01.jim.corp", "cad/vault/Turbine_Rotor_Gen4_Confidential_Blueprints.dwg", "File Canary CAD"),
            ("o.alali", "WS-PROD-01", "cad-repo01.jim.corp", "docs/safety/Hydraulic_Press_Bypass_Safety_Specification.pdf", "File Canary Spec"),
            ("a.barakat", "WS-IT-01", "db-prod01.jim.corp", "production/db/secret_rnd_formulations", "Database Canary Table"),
            ("svc_eng_backup", "WS-ENG-01", "cad-srv01.jim.corp", "cad/backup/session", "Account Canary"),
            ("w.abdallah_consultant", "WS-EXT-01", "WS-IT-01", "remote/login", "Account Canary"),
        ]
        for i in range(15):
            u, src, tgt, res, desc = canaries_test[i % len(canaries_test)]
            evs = [
                create_event(u, src, tgt, res, "access", status="SUCCESS", offset_seconds=0)
            ]
            scenarios.append(ScenarioTestItem(
                scenario_id=f"SCEN-DECOY-{idx:03d}",
                scenario_type="Decoy Resource Access",
                is_malicious=True,
                description_ar=f"الوصول إلى مورد خادع ({desc})",
                description_en=f"Accessing canary honeytoken ({desc})",
                events=evs
            ))
            idx += 1

        # 4. Data Exfiltration Scenarios (15 scenarios) -> is_malicious = True
        for i in range(15):
            u = "r.qasim" if i % 2 == 0 else "t.haddad"
            scenarios.append(ScenarioTestItem(
                scenario_id=f"SCEN-EXFIL-{idx:03d}",
                scenario_type="Data Exfiltration",
                is_malicious=True,
                description_ar=f"محاكاة تسريب ملفات وتصاميم هندسية عبر تصدير بيانات اصطناعية",
                description_en="Simulated exfiltration of CAD blueprints with bulk export",
                events=build_data_exfiltration_scenario(u)
            ))
            idx += 1

        # 5. Lateral Movement Scenarios (10 scenarios) -> is_malicious = True
        for i in range(10):
            scenarios.append(ScenarioTestItem(
                scenario_id=f"SCEN-LATERAL-{idx:03d}",
                scenario_type="Lateral Movement",
                is_malicious=True,
                description_ar="تسلسل انتقال متعدد القفزات بين محطة عمل وخادم ملفات وخادم إنتاج",
                description_en="Multi-hop pivot from workstation to file server to OT/production",
                events=build_lateral_movement_scenario()
            ))
            idx += 1

        return scenarios

    def evaluate_benchmark(self) -> Dict[str, Any]:
        """
        Executes the full 100 scenarios across both Baseline and FactoryShield engines,
        and computes academic performance metrics.
        """
        scenarios = self.generate_100_scenarios()

        baseline_results = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "times": []}
        factoryshield_results = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "times": []}

        detailed_runs = []

        for item in scenarios:
            is_mal = item.is_malicious

            # 1. Test Baseline
            t0 = time.perf_counter()
            b_res = self.baseline.evaluate_scenario(item.events)
            b_time_ms = (time.perf_counter() - t0) * 1000
            baseline_results["times"].append(b_time_ms)
            b_alert = b_res["alert_generated"]

            if is_mal and b_alert:
                baseline_results["TP"] += 1
            elif not is_mal and b_alert:
                baseline_results["FP"] += 1
            elif not is_mal and not b_alert:
                baseline_results["TN"] += 1
            elif is_mal and not b_alert:
                baseline_results["FN"] += 1

            # 2. Test FactoryShield
            t1 = time.perf_counter()
            fs_res = self.factoryshield.process_scenario_events(item.events, session_id=item.scenario_id)
            fs_time_ms = (time.perf_counter() - t1) * 1000
            factoryshield_results["times"].append(fs_time_ms)
            fs_alert = fs_res["alert_generated"]

            if is_mal and fs_alert:
                factoryshield_results["TP"] += 1
            elif not is_mal and fs_alert:
                factoryshield_results["FP"] += 1
            elif not is_mal and not fs_alert:
                factoryshield_results["TN"] += 1
            elif is_mal and not fs_alert:
                factoryshield_results["FN"] += 1

            detailed_runs.append({
                "scenario_id": item.scenario_id,
                "type": item.scenario_type,
                "is_malicious": is_mal,
                "baseline_alert": b_alert,
                "factoryshield_alert": fs_alert,
                "factoryshield_score": fs_res["score"],
                "factoryshield_severity": fs_res["severity"],
                "rules_triggered": fs_res["rules_triggered"]
            })

        def calc_metrics(res: Dict[str, Any]) -> Dict[str, Any]:
            tp, fp, tn, fn = res["TP"], res["FP"], res["TN"], res["FN"]
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            avg_time = sum(res["times"]) / len(res["times"]) if res["times"] else 0.0

            return {
                "TP": tp,
                "FP": fp,
                "TN": tn,
                "FN": fn,
                "precision": round(precision * 100, 2),
                "recall": round(recall * 100, 2),
                "f1_score": round(f1 * 100, 2),
                "false_positive_rate": round(fpr * 100, 2),
                "avg_detection_time_ms": round(avg_time, 3),
            }

        baseline_metrics = calc_metrics(baseline_results)
        fs_metrics = calc_metrics(factoryshield_results)

        report = {
            "total_scenarios": len(scenarios),
            "distribution": {
                "normal_authorized": 40,
                "privilege_abuse": 20,
                "decoy_access": 15,
                "data_exfiltration": 15,
                "lateral_movement": 10
            },
            "comparison": {
                "baseline_isolated": baseline_metrics,
                "factoryshield_correlated": fs_metrics,
            },
            "detailed_runs": detailed_runs[:25]  # Preview subset
        }

        return report

# Global benchmark runner instance
benchmark_runner = BenchmarkSuite()
