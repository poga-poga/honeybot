"""
FactoryShield: Scenario Simulator CLI
Allows command-line triggering of threat scenarios:
- exfiltration: Data exfiltration with CAD canary
- privilege: Privilege abuse across departments
- lateral: Lateral movement pivot sequence
- normal: Normal authorized operation
"""
import sys
import json
from factoryshield.engine.detector import detector_engine
from factoryshield.simulator.scenario_runner import (
    build_data_exfiltration_scenario,
    build_privilege_abuse_scenario,
    build_lateral_movement_scenario,
    build_normal_activity_scenario
)

def run_cli_scenario(scen_type: str):
    scen_type = scen_type.lower()
    print(f"\n[*] Executing scenario: [{scen_type}]...")

    if scen_type == "exfiltration":
        events = build_data_exfiltration_scenario("r.qasim")
    elif scen_type in ["privilege", "privilege_abuse"]:
        events = build_privilege_abuse_scenario("l.najjar")
    elif scen_type in ["lateral", "lateral_movement"]:
        events = build_lateral_movement_scenario("a.barakat")
    elif scen_type in ["normal", "authorized"]:
        events = build_normal_activity_scenario("Engineering")
    else:
        print(f"[-] Unknown scenario '{scen_type}'. Choose: exfiltration, privilege, lateral, normal")
        return

    result = detector_engine.process_scenario_events(events, session_id=f"CLI-{scen_type.upper()}")

    print("\n" + "="*70)
    print(f"Incident ID     : {result['incident_id']}")
    print(f"Alert Generated : {result['alert_generated']}")
    print(f"Risk Score      : {result['score']}/100")
    print(f"Severity Level  : {result['severity']} ({result['severity_ar']})")
    print(f"Actor           : {result['actor']} (Dept: {result['department']})")
    print(f"Rules Triggered : {result['rules_triggered']}")
    print(f"Detection Time  : {result['detection_time_ms']} ms")
    print(f"\nForensic Synthesis:")
    print(f"AR: {result['forensics']['synthesis_ar']}")
    print(f"EN: {result['forensics']['synthesis_en']}")
    print("="*70 + "\n")

if __name__ == "__main__":
    choice = sys.argv[1] if len(sys.argv) > 1 else "exfiltration"
    run_cli_scenario(choice)
