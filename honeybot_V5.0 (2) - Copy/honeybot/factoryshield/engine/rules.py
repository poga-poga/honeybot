"""
Deterministic Explainable Detection Rules (R1 - R5)
FactoryShield Multi-Layer Honeypot Engine
"""
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class RuleEvaluationResult:
    rule_id: str
    rule_name_en: str
    rule_name_ar: str
    triggered: bool
    points: int
    explanation_en: str
    explanation_ar: str
    evidence: Dict[str, Any]

# Rule Definitions
RULES_METADATA = {
    "R1": {
        "name_en": "Decoy / Honeytoken Access",
        "name_ar": "الوصول إلى مورد خادع (Canary Trigger)",
        "points": 40,
        "desc_en": "A user or process touched or interacted with a registered Canary resource.",
        "desc_ar": "محاولة وصول أو تفاعل مع ملف أو سجل قاعدة بيانات أو حساب خادع."
    },
    "R2": {
        "name_en": "Privilege Policy Violation",
        "name_ar": "إساءة استخدام الصلاحيات (Privilege Abuse)",
        "points": 20,
        "desc_en": "An employee attempted to access resources outside their departmental RBAC rights.",
        "desc_ar": "محاولة موظف الوصول لمورد تقني أو هندسي أو إنتاجي يقع خارج صلاحيات قسمه."
    },
    "R3": {
        "name_en": "Cross-Department Anomalous Sequence",
        "name_ar": "الوصول المتتابع عبر أقسام متعددة (Cross-Department)",
        "points": 15,
        "desc_en": "Rapid sequential access across multiple distinct corporate departmental resources.",
        "desc_ar": "تسلسل نشاط وصول سريع بين موارد تتبع لأقسام مختلفة دون سياق إداري مصرح."
    },
    "R4": {
        "name_en": "Data Exfiltration Indicator",
        "name_ar": "مؤشر اشتباه تسريب البيانات (Data Exfiltration)",
        "points": 20,
        "desc_en": "Access to confidential engineering assets followed by synthetic data export or staging.",
        "desc_ar": "الوصول لملفات هندسية/إنتاجية حساسة أو Canary متبوعاً بعملية تصدير بيانات اصطناعية."
    },
    "R5": {
        "name_en": "Lateral Movement Progression",
        "name_ar": "الانتقال المتسلسل بين الأجهزة (Lateral Movement)",
        "points": 20,
        "desc_en": "Sequential session progression traversing from an initial workstation across enterprise servers.",
        "desc_ar": "تسلسل أحداث وصول وانتقال يمتد من محطة عمل أولية إلى خوادم وسيطة ثم خدمات الإنتاج."
    }
}
