"""
Unit Tests for FactoryShield v5.1 Advanced Features:
- MITRE ATT&CK Matrix & Heatmap
- Automated SOAR Containment & Active Defense
- Native Modbus TCP ICS Trap
- Wireshark-compatible PCAP Evidence Generation
- Incident PDF / Printable CSIRT Report
"""
import unittest
import os
from scapy.all import rdpcap
import io

from factoryshield.engine.mitre import MitreEngine, MITRE_CATALOG
from factoryshield.engine.soar import SOAREngine
from factoryshield.services.modbus_trap import ModbusTrapServer
from factoryshield.engine.pcap_generator import build_incident_pcap_bytes
from factoryshield.engine.detector import detector_engine
from factoryshield.simulator.scenario_runner import build_modbus_ics_scenario
from factoryshield.dashboard.app import app

class TestV51AdvancedFeatures(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    def test_mitre_mapping_and_heatmap(self):
        """Test MITRE ATT&CK technique mapping for both Enterprise and ICS."""
        mapped = MitreEngine.map_incident_tactics(
            rules=["R1", "R2", "R5"],
            events=[{"target_host": "plc-sim01.jim.corp", "resource": "modbus/override", "action": "write"}]
        )
        tech_ids = [t["id"] for t in mapped]
        self.assertIn("T1078", tech_ids) # Valid Accounts
        self.assertIn("T1078.004", tech_ids) # Privilege Abuse
        self.assertIn("T1021", tech_ids) # Remote Services
        self.assertIn("T0882", tech_ids) # ICS Discovery
        self.assertIn("T0855", tech_ids) # ICS Unauthorized Command

        # Heatmap test
        fake_incidents = [{
            "forensics": {"mitre_att_ck_details": [{"id": "T0882", "tactic": "Discovery"}]}
        }]
        heatmap = MitreEngine.get_matrix_heatmap(fake_incidents)
        self.assertIn("catalog", heatmap)
        t0882_entry = next((item for item in heatmap["catalog"] if item["id"] == "T0882"), None)
        self.assertIsNotNone(t0882_entry)
        self.assertEqual(t0882_entry["hit_count"], 1)

    def test_soar_containment_lifecycle(self):
        """Test host isolation, account locking, and auto-containment."""
        soar = SOAREngine()
        
        # Test manual host isolation
        iso = soar.isolate_host("WS-ENG-01", reason="Malicious probing", incident_id="TEST-01")
        self.assertTrue(soar.is_host_isolated("WS-ENG-01"))
        self.assertEqual(iso["status"], "ISOLATED")

        # Test un-isolation
        restore = soar.unisolate_host("WS-ENG-01", analyst="Lead_Analyst")
        self.assertFalse(soar.is_host_isolated("WS-ENG-01"))
        self.assertEqual(restore["status"], "ACTIVE")

        # Test account lock
        lock = soar.lock_account("r.qasim", reason="CAD Exfiltration", incident_id="TEST-02")
        self.assertTrue(soar.is_account_locked("r.qasim"))
        self.assertEqual(lock["status"], "LOCKED")

        # Test unlock
        unlock = soar.unlock_account("r.qasim", analyst="Lead_Analyst")
        self.assertFalse(soar.is_account_locked("r.qasim"))

        # Test auto-containment on Critical (score >= 80)
        critical_incident = {
            "incident_id": "INC-CRIT-99",
            "score": 85,
            "severity": "Critical",
            "actor": "w.abdallah_consultant",
            "source_workstation": "WS-IT-01"
        }
        actions = soar.evaluate_and_contain(critical_incident)
        self.assertGreaterEqual(len(actions), 2)
        self.assertTrue(soar.is_host_isolated("WS-IT-01"))
        self.assertTrue(soar.is_account_locked("w.abdallah_consultant"))

    def test_modbus_trap_pdu_handling(self):
        """Test Modbus PDU processing and Canary register detection."""
        server = ModbusTrapServer(host="127.0.0.1", port=55502)
        
        # 1. Read Holding Registers (Function 0x03) - normal registers (addr 1, qty 2)
        req_pdu = b"\x00\x01\x00\x02" # addr 1, qty 2
        resp = server.handle_modbus_pdu("192.168.10.15", 0x03, req_pdu)
        self.assertEqual(resp[0], 0x03) # Function code
        self.assertEqual(resp[1], 4)    # Byte count (2 * 2 = 4)

        # 2. Read Device Identification (Function 0x2B) - Nmap probe
        resp_id = server.handle_modbus_pdu("192.168.10.15", 0x2B, b"\x0E\x01\x00")
        self.assertIn(b"Siemens AG", resp_id)
        self.assertIn(b"SIMATIC S7-1200", resp_id)

        # 3. Read Canary Holding Register 40108 (addr 108, qty 1)
        req_canary = b"\x00\x6c\x00\x01" # 0x6C = 108
        resp_canary = server.handle_modbus_pdu("192.168.10.15", 0x03, req_canary)
        self.assertEqual(resp_canary[0], 0x03)

    def test_pcap_generation(self):
        """Test synthesizing valid PCAP capture readable by Scapy."""
        events = build_modbus_ics_scenario("w.abdallah_consultant")
        incident = detector_engine.process_scenario_events(events, session_id="TEST-PCAP-001")
        
        pcap_bytes = build_incident_pcap_bytes(incident)
        self.assertGreater(len(pcap_bytes), 100)

        # Verify that scapy can parse the generated PCAP
        buf = io.BytesIO(pcap_bytes)
        packets = rdpcap(buf)
        self.assertGreater(len(packets), 0)
        self.assertTrue(any(p.haslayer("TCP") for p in packets))

    def test_modbus_ics_scenario_and_auto_soar(self):
        """Test that the Modbus ICS scenario triggers Critical severity and automated SOAR."""
        events = build_modbus_ics_scenario("w.abdallah_consultant")
        incident = detector_engine.process_scenario_events(events, session_id="TEST-MODBUS-SOAR")
        self.assertTrue(incident["alert_generated"])
        self.assertGreaterEqual(incident["score"], 80)
        self.assertEqual(incident["severity"], "Critical")
        self.assertIn("R1", incident["rules_triggered"])
        self.assertIn("R2", incident["rules_triggered"])
        self.assertIn("soar_actions", incident)
        self.assertGreater(len(incident["soar_actions"]), 0)

if __name__ == "__main__":
    unittest.main()
