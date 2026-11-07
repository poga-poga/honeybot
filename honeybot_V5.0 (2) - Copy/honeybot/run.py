"""
FactoryShield: Multi-Layer Industrial Enterprise Honeypot
Unified Launcher for Monitoring Dashboard and Network Traps
Jordan Industrial Manufacturing (JIM)
"""
import sys
import time
from factoryshield.config import COMPANY_NAME_EN, COMPANY_NAME_AR, NETWORKS
from factoryshield.dashboard.app import app, AUTH_CONFIGURED
from factoryshield.honeytokens.manager import honeytoken_mgr
from factoryshield.enterprise.company import get_all_hosts
from factoryshield.services.cad_web_trap import start_cad_web_trap_thread
from factoryshield.services.ssh_trap import start_ssh_trap_thread
from factoryshield.services.ftp_trap import start_ftp_trap_thread
from factoryshield.services.plc_trap import start_plc_trap_thread
from factoryshield.services.production_hmi import start_hmi_thread

def print_banner():
    banner = r"""
========================================================================================
   ____           _                   ____  _     _      _     _ 
  |  _ \         | |                 / ___|| |   (_)    | |   | |
  | |_) | ___  __| | ___ ___  _   _  \___ \| |__  _  ___| | __| |
  |  _ < / _ \/ _` |/ __/ _ \| | | |  ___) | '_ \| |/ _ \ |/ _` |
  |_| \_\  __/ (_| | (_| (_) | |_| | |____/|_| |_|_|\___/_|\__,_|
========================================================================================
   Jordan Industrial Manufacturing (JIM)
   شركة الأردن للتصنيع الصناعي (JIM)
   Multi-Layer Industrial Deception & Explainable Forensics Platform
========================================================================================
    """
    print(banner)
    print(f"[*] Initializing Jordan Industrial Manufacturing (JIM) Environment...")
    print(f"[+] Active Honeytokens: {len(honeytoken_mgr.list_all())} registered (File, DB, Account, API Canaries)")
    print(f"[+] Enterprise Monitored Assets: {len(get_all_hosts())} hosts across 4 network tiers:")
    for key, net in NETWORKS.items():
        print(f"    - {net['name']:<35} [{net['subnet']}] : {len(net['hosts'])} hosts")
    
    print("\n[+] Launching Network Decoy Trap Services:")
    print("    - Port 8080: Production HMI Dashboard (SCADA)    (http://localhost:8080)")
    print("    - Port 8088: CAD Web Vault & Blueprint Traps     (http://localhost:8088)")
    print("    - Port 5020: Siemens S7 PLC Diagnostic Portal    (http://localhost:5020)")
    print("    - Port 21/2121: CAD Archive FTP Honeypot Trap    (ftp://localhost / :2121)")
    print("    - Port 2222: SSH Decoy Gateway & Auth Trap       (ssh -p 2222 localhost)")

    print("\n[+] Isolated Security Monitoring Network (Forensics SOC):")
    print("    - Port 5000: FactoryShield Dashboard & Forensics  (http://localhost:5000)")
    print("========================================================================================\n")

if __name__ == "__main__":
    if not AUTH_CONFIGURED:
        raise RuntimeError(
            "Set FACTORYSHIELD_SECRET_KEY, FACTORYSHIELD_ADMIN_USERNAME, "
            "and FACTORYSHIELD_ADMIN_PASSWORD before starting FactoryShield. "
            "See SECURITY_SETUP.md."
        )

    print_banner()

    # Start Decoy Trap Services in background daemon threads
    start_hmi_thread(host="0.0.0.0", port=8080)
    start_cad_web_trap_thread(host="0.0.0.0", port=8088)
    start_plc_trap_thread(host="0.0.0.0", port=5020)
    start_ftp_trap_thread(ports=[21, 2121], host="0.0.0.0")
    start_ssh_trap_thread(host="0.0.0.0", port=2222)

    # Start main SOC Dashboard (blocking)
    app.run(host="127.0.0.1", port=5000, debug=False)
