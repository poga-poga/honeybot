"""
FactoryShield: Configuration and Constants
Jordan Industrial Manufacturing (JIM) Virtual Enterprise
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CANARY_FILES_DIR = BASE_DIR / "honeytokens" / "decoys" / "files"
DATABASE_DIR = BASE_DIR / "honeytokens" / "decoys" / "database"

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CANARY_FILES_DIR, exist_ok=True)
os.makedirs(DATABASE_DIR, exist_ok=True)

COMPANY_NAME_EN = "Jordan Industrial Manufacturing (JIM)"
COMPANY_NAME_AR = "شركة الأردن للتصنيع الصناعي (JIM)"

# Networks and Purdue Model IP mapping
NETWORKS = {
    "office": {
        "name": "Office Network",
        "subnet": "192.168.10.0/24",
        "desc": "أجهزة الموظفين والإدارة والموارد البشرية",
        "hosts": {
            "WS-MGMT-01": {"ip": "192.168.10.11", "dept": "Management", "owner": "m.khalil"},
            "WS-ENG-01": {"ip": "192.168.10.21", "dept": "Engineering", "owner": "t.haddad"},
            "WS-PROD-01": {"ip": "192.168.10.31", "dept": "Production", "owner": "o.alali"},
            "WS-HR-01": {"ip": "192.168.10.41", "dept": "HR", "owner": "l.najjar"},
            "WS-IT-01": {"ip": "192.168.10.51", "dept": "IT", "owner": "a.barakat"},
        }
    },
    "engineering": {
        "name": "Engineering Network",
        "subnet": "192.168.20.0/24",
        "desc": "خادم التصاميم الهندسية ومستودع ملفات CAD",
        "hosts": {
            "cad-srv01.jim.corp": {"ip": "192.168.20.15", "type": "CAD File Server", "dept": "Engineering"},
            "cad-repo01.jim.corp": {"ip": "192.168.20.16", "type": "Decoy CAD Repository", "dept": "Engineering"},
        }
    },
    "production": {
        "name": "Production Simulation Network",
        "subnet": "192.168.30.0/24",
        "desc": "خادم محاكاة الإنتاج وقاعدة البيانات وخدمات OT الصناعية",
        "hosts": {
            "db-prod01.jim.corp": {"ip": "192.168.30.50", "type": "Production Database (PostgreSQL/SQLite)", "dept": "Production"},
            "plc-sim01.jim.corp": {"ip": "192.168.30.80", "type": "Simulated PLC / OT Modbus Service", "dept": "Production"},
            "hmi-prod01.jim.corp": {"ip": "192.168.30.90", "type": "Production HMI Dashboard", "dept": "Production"},
        }
    },
    "security": {
        "name": "Isolated Security Monitoring Network",
        "subnet": "192.168.99.0/24",
        "desc": "شبكة المراقبة الأمنية ومحرك الكشف والتحليل الجنائي",
        "hosts": {
            "sec-mon01.jim.corp": {"ip": "192.168.99.10", "type": "FactoryShield Engine & Dashboard", "dept": "Security"},
        }
    }
}

# Detection Engine Scoring Rules
SCORING = {
    "DECOY_CANARY_HIT": 40,        # الوصول إلى مورد خادع
    "PRIVILEGE_VIOLATION": 20,     # محاولة وصول مرفوضة خارج الصلاحية
    "LATERAL_MOVEMENT": 20,        # ظهور تسلسل أحداث عبر أكثر من جهاز
    "EXFILTRATION_ACTIVITY": 20,   # عملية تصدير بيانات اصطناعية مرتبطة بالحادث
    "CROSS_DEPT_ANOMALY": 15,      # الوصول المتتابع إلى موارد في أقسام مختلفة
}

SEVERITY_LEVELS = [
    {"name": "Low", "name_ar": "منخفض", "min": 0, "max": 29, "color": "#10b981"},
    {"name": "Medium", "name_ar": "متوسط", "min": 30, "max": 59, "color": "#f59e0b"},
    {"name": "High", "name_ar": "مرتفع", "min": 60, "max": 79, "color": "#f97316"},
    {"name": "Critical", "name_ar": "حرج", "min": 80, "max": 100, "color": "#ef4444"},
]

def get_severity(score: int):
    clamped = max(0, min(100, score))
    for s in SEVERITY_LEVELS:
        if s["min"] <= clamped <= s["max"]:
            return s
    return SEVERITY_LEVELS[-1]
