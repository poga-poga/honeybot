"""
Honeytoken & Decoy Manager
Manages File Canaries, Database Canaries, Account Canaries, and API Canaries
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from factoryshield.enterprise.synthetic_data import init_synthetic_database, generate_canary_files

@dataclass
class Honeytoken:
    token_id: str
    token_type: str  # File Canary, Database Canary, Account Canary, API Canary
    identifier: str
    asset_location: str
    description_ar: str
    description_en: str
    classification: str

class HoneytokenManager:
    def __init__(self):
        # Initialize synthetic files & DB
        init_synthetic_database()
        generate_canary_files()
        
        self.tokens: Dict[str, Honeytoken] = {
            # File Canaries
            "FILE_CANARY_CAD_01": Honeytoken(
                token_id="FILE_CANARY_CAD_01",
                token_type="File Canary",
                identifier="Turbine_Rotor_Gen4_Confidential_Blueprints.dwg",
                asset_location="cad-srv01.jim.corp:/vault/blueprints/",
                description_ar="ملف تصميم هندسي وهمي (مخطط توربين سري) لا يحتاج أي موظف لفتحه",
                description_en="Decoy CAD turbine blueprint file canary",
                classification="Proprietary IP"
            ),
            "FILE_CANARY_SPEC_02": Honeytoken(
                token_id="FILE_CANARY_SPEC_02",
                token_type="File Canary",
                identifier="Hydraulic_Press_Bypass_Safety_Specification.pdf",
                asset_location="cad-repo01.jim.corp:/docs/safety/",
                description_ar="مواصفات سلامة وهمية لتجاوز أقفال المكابس الهيدروليكية",
                description_en="Decoy emergency safety interlock bypass document",
                classification="Safety Critical"
            ),
            # Database Canaries
            "DB_CANARY_TABLE_01": Honeytoken(
                token_id="DB_CANARY_TABLE_01",
                token_type="Database Canary",
                identifier="secret_rnd_formulations",
                asset_location="db-prod01.jim.corp:production_jim.db",
                description_ar="جدول سري وهمي لتراكيب السبائك في قاعدة بيانات الإنتاج",
                description_en="Decoy R&D formulations database table",
                classification="R&D Confidential"
            ),
            "DB_CANARY_ROW_02": Honeytoken(
                token_id="DB_CANARY_ROW_02",
                token_type="Database Canary",
                identifier="LINE-07-BLACK-PROJECT",
                asset_location="db-prod01.jim.corp:production_batches",
                description_ar="سجل إنتاج وهمي لخط تصنيع غير موجود فعلياً (Line-07)",
                description_en="Decoy production batch record referencing non-existent line",
                classification="Operational Deception"
            ),
            # Account Canaries
            "ACC_CANARY_SVC_01": Honeytoken(
                token_id="ACC_CANARY_SVC_01",
                token_type="Account Canary",
                identifier="svc_eng_backup",
                asset_location="Active Directory / IAM Service Accounts",
                description_ar="حساب خدمة نسخ احتياطي تجريبي غير مستخدم في العمليات الطبيعية",
                description_en="Decoy automated backup service account",
                classification="Deceptive Credential"
            ),
            "ACC_CANARY_EXT_02": Honeytoken(
                token_id="ACC_CANARY_EXT_02",
                token_type="Account Canary",
                identifier="w.abdallah_consultant",
                asset_location="Enterprise Domain Accounts",
                description_ar="حساب مقاول خارجي غير نشط، مرصود لأي محاولة تسجيل دخول",
                description_en="Decoy inactive third-party auditor account",
                classification="Deceptive Credential"
            ),
            # API Canary
            "API_CANARY_KEY_01": Honeytoken(
                token_id="API_CANARY_KEY_01",
                token_type="API Canary",
                identifier="JIM-CANARY-APIKEY-4f9a0c1e8b2d-PROD-VAULT",
                asset_location="cad-srv01.jim.corp:/etc/internal_services_conf.json",
                description_ar="مفتاح API خادع داخل ملف إعدادات داخلي غير صالح للوصول الحقيقي",
                description_en="Decoy API token embedded in fake application config",
                classification="API Key Deception"
            ),
        }

    def inspect_event_for_honeytoken(self, resource: str, query: str = "", username: str = "", api_key: str = "") -> Optional[Honeytoken]:
        """
        Inspects an event's attributes to check if any Honeytoken was touched.
        """
        # Check Account Canary
        if username:
            for token in self.tokens.values():
                if token.token_type == "Account Canary" and token.identifier.lower() == username.lower():
                    return token

        # Check API Canary
        if api_key:
            for token in self.tokens.values():
                if token.token_type == "API Canary" and token.identifier in api_key:
                    return token

        # Check File Canary in resource path
        if resource:
            for token in self.tokens.values():
                if token.token_type == "File Canary" and token.identifier.lower() in resource.lower():
                    return token

        # Check Database Canary in SQL query or resource target
        combined_text = f"{resource} {query}".lower()
        for token in self.tokens.values():
            if token.token_type == "Database Canary" and token.identifier.lower() in combined_text:
                return token

        return None

    def list_all(self) -> List[Honeytoken]:
        return list(self.tokens.values())

# Global singleton
honeytoken_mgr = HoneytokenManager()
