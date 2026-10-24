"""
Synthetic Industrial Data & Canaries Generator
Jordan Industrial Manufacturing (JIM)
"""
import sqlite3
import json
from pathlib import Path
from typing import Dict, Any
from factoryshield.config import CANARY_FILES_DIR, DATABASE_DIR

DB_PATH = DATABASE_DIR / "production_jim.db"

def init_synthetic_database() -> str:
    """
    Initializes a realistic production database containing normal industrial tables
    and seeded with Database Canary records and tables.
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Normal production lines
    cur.execute("""
    CREATE TABLE IF NOT EXISTS production_lines (
        line_id TEXT PRIMARY KEY,
        line_name TEXT,
        department TEXT,
        status TEXT,
        target_capacity_per_day INTEGER
    )
    """)

    # Normal production batches
    cur.execute("""
    CREATE TABLE IF NOT EXISTS production_batches (
        batch_id TEXT PRIMARY KEY,
        line_id TEXT,
        product_code TEXT,
        quantity INTEGER,
        inspector TEXT,
        is_canary INTEGER DEFAULT 0
    )
    """)

    # CANARY TABLE: Honeytoken table designed to detect unauthorized DB reconnaissance
    cur.execute("""
    CREATE TABLE IF NOT EXISTS secret_rnd_formulations (
        formulation_id TEXT PRIMARY KEY,
        codename TEXT,
        alloy_composition TEXT,
        classification TEXT,
        is_canary INTEGER DEFAULT 1
    )
    """)

    # Seed Normal Data
    normal_lines = [
        ("LINE-01", "CNC Milling Line A", "Machining", "OPERATIONAL", 1200),
        ("LINE-02", "Automated Robotic Welding", "Assembly", "OPERATIONAL", 850),
        ("LINE-03", "Powder Coating & Finishing", "Finishing", "MAINTENANCE", 600),
        ("LINE-04", "Heavy Stamping Press", "Fabrication", "OPERATIONAL", 2200),
    ]
    cur.executemany("INSERT OR REPLACE INTO production_lines VALUES (?, ?, ?, ?, ?)", normal_lines)

    normal_batches = [
        ("BATCH-1001", "LINE-01", "GEAR-BOX-M8", 300, "o.alali", 0),
        ("BATCH-1002", "LINE-02", "BRACKET-ARM-A3", 500, "k.masri", 0),
        ("BATCH-1003", "LINE-04", "CHASSIS-PLATE-T2", 150, "k.masri", 0),
        # DATABASE CANARY ROW: Line-07 does NOT exist in real company operations!
        ("BATCH-7709-TITANIUM-SECRET", "LINE-07-BLACK-PROJECT", "PROTOTYPE-DRONE-CHASSIS-77", 10, "svc_eng_backup", 1)
    ]
    cur.executemany("INSERT OR REPLACE INTO production_batches VALUES (?, ?, ?, ?, ?, ?)", normal_batches)

    # Seed CANARY TABLE
    canary_formulations = [
        ("FORM-X99", "AeroAlloy-Titanium-Ultra", "Ti-6Al-4V + 1.2% Scandium Nano-Coating", "TOP-SECRET-DECOY", 1),
        ("FORM-X100", "ThermalBypass-Shield", "Carbon-Ceramic Matrix Type 4", "RESTRICTED-DECOY", 1),
    ]
    cur.executemany("INSERT OR REPLACE INTO secret_rnd_formulations VALUES (?, ?, ?, ?, ?)", canary_formulations)

    conn.commit()
    conn.close()
    return str(DB_PATH)

def generate_canary_files() -> Dict[str, str]:
    """
    Creates decoy CAD designs, engineering specifications, and system configuration files.
    """
    files_created = {}

    # 1. File Canary: CAD Drawing Decoy
    cad_file = CANARY_FILES_DIR / "Turbine_Rotor_Gen4_Confidential_Blueprints.dwg"
    cad_content = (
        "=== JIM ENGINEERING PROPRIETARY BLUEPRINT ===\n"
        "Project: High-Pressure Turbine Rotor Generation 4\n"
        "Author: Tareq Haddad (Lead Mechanical Engineer)\n"
        "Classification: CONFIDENTIAL INDUSTRIAL IP\n"
        "Status: Prototype Testing Stage 3\n"
        "[CANARY_TOKEN: CANARY_FILE_CAD_ROTOR_GEN4_9921b]\n"
        "WARNING: Unauthorized access, copying, or export will be logged and reported to JIM Security SOC.\n"
    )
    with open(cad_file, "w", encoding="utf-8") as f:
        f.write(cad_content)
    files_created["file_canary_cad"] = str(cad_file)

    # 2. File Canary: Hydraulic Safety Bypass
    spec_file = CANARY_FILES_DIR / "Hydraulic_Press_Bypass_Safety_Specification.pdf"
    spec_content = (
        "%PDF-1.4 Mock CAD Specification\n"
        "Title: Hydraulic Press Emergency Interlock Bypass Guidelines\n"
        "Classification: RESTRICTED SAFETY PROCEDURES\n"
        "[CANARY_TOKEN: CANARY_FILE_HYDRAULIC_BYPASS_4410a]\n"
    )
    with open(spec_file, "w", encoding="utf-8") as f:
        f.write(spec_content)
    files_created["file_canary_spec"] = str(spec_file)

    # 3. API Canary: Decoy Config File with fake internal credentials
    config_file = CANARY_FILES_DIR / "internal_services_conf.json"
    config_data = {
        "enterprise": "Jordan Industrial Manufacturing (JIM)",
        "internal_cad_vault": "https://cad-srv01.jim.corp:8443/vault",
        "ot_production_gateway": "192.168.30.80:502",
        "api_service_keys": {
            "comment": "Internal service authentication token - DO NOT SHARE",
            "active_key": "JIM-CANARY-APIKEY-4f9a0c1e8b2d-PROD-VAULT",
            "client_id": "svc_eng_backup"
        }
    }
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=4)
    files_created["api_canary_config"] = str(config_file)

    return files_created
