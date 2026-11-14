"""
FactoryShield: MITRE ATT&CK Framework Mapping Engine
Comprehensive Enterprise & ICS Matrix mapping for industrial cyber deception.
"""
from typing import Dict, List, Any, Optional

# Official MITRE ATT&CK Catalog (Enterprise & ICS)
MITRE_CATALOG: Dict[str, Dict[str, Any]] = {
    # ICS Tactics & Techniques
    "T0882": {
        "id": "T0882",
        "name": "Internet Connection Discovery",
        "name_ar": "استكشاف اتصالات الإنترنت والأجهزة الصناعية",
        "tactic": "Discovery",
        "tactic_ar": "الاستكشاف (Discovery)",
        "matrix": "ICS",
        "description": "Adversaries may attempt to discover internet and internal connections to ICS/SCADA controllers and services.",
        "remediation": "Enforce strict network segmentation between IT and OT tiers per ISA/IEC 62443."
    },
    "T0855": {
        "id": "T0855",
        "name": "Unauthorized Command Message",
        "name_ar": "إرسال أوامر تحكم صناعية غير مصرح بها",
        "tactic": "Impair Process Control",
        "tactic_ar": "تعطيل التحكم بالعمليات الصناعية",
        "matrix": "ICS",
        "description": "Adversaries may send unauthorized commands over industrial protocols (Modbus, S7comm) to alter process states.",
        "remediation": "Deploy deep packet inspection (DPI) firewalls and disable unauthenticated PLC write functions."
    },
    "T0812": {
        "id": "T0812",
        "name": "Default Credentials",
        "name_ar": "استخدام كلمات المرور الافتراضية للأنظمة الصناعية",
        "tactic": "Initial Access",
        "tactic_ar": "الوصول الأولي",
        "matrix": "ICS",
        "description": "Adversaries may exploit factory default passwords on HMI, PLC, and gateway controllers.",
        "remediation": "Change all vendor factory credentials before commissioning OT equipment."
    },
    "T0843": {
        "id": "T0843",
        "name": "Program Download / Modify Controller",
        "name_ar": "تعديل برامج وحدات التحكم المنطقية (PLC)",
        "tactic": "Impair Process Control",
        "tactic_ar": "تعطيل التحكم بالعمليات الصناعية",
        "matrix": "ICS",
        "description": "Adversaries may attempt to overwrite logic or memory registers of controllers running critical manufacturing lines.",
        "remediation": "Engage hardware physical key-switches to RUN-ONLY mode to prevent remote program modification."
    },
    "T0866": {
        "id": "T0866",
        "name": "Exploitation of Remote Services (ICS)",
        "name_ar": "استغلال الخدمات عن بعد في البيئة الصناعية",
        "tactic": "Lateral Movement",
        "tactic_ar": "الانتقال الجانبي",
        "matrix": "ICS",
        "description": "Adversaries may exploit vulnerabilities in remote services to pivot into supervisory and control networks.",
        "remediation": "Implement jump hosts with multi-factor authentication (MFA) between IT and OT zones."
    },

    # Enterprise Tactics & Techniques
    "T1083": {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "name_ar": "استكشاف الملفات والأدلة الحساسة",
        "tactic": "Discovery",
        "tactic_ar": "الاستكشاف (Discovery)",
        "matrix": "Enterprise",
        "description": "Adversaries enumerate files and directories looking for confidential blueprints or credentials.",
        "remediation": "Audit file system access and deploy decoy canary documents in shared file repositories."
    },
    "T1005": {
        "id": "T1005",
        "name": "Data from Local System",
        "name_ar": "جمع البيانات من الأنظمة المحلية",
        "tactic": "Collection",
        "tactic_ar": "جمع البيانات (Collection)",
        "matrix": "Enterprise",
        "description": "Adversaries search local file repositories and databases to stage sensitive operational IP.",
        "remediation": "Implement Data Loss Prevention (DLP) agents and encrypt intellectual property at rest."
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "name_ar": "استخدام حسابات صالحة أو خادعة",
        "tactic": "Defense Evasion",
        "tactic_ar": "تجاوز الدفاعات",
        "matrix": "Enterprise",
        "description": "Adversaries obtain and abuse existing credentials to access domain systems without triggering brute force alarms.",
        "remediation": "Deploy honeytoken accounts with zero legitimate enterprise operational use."
    },
    "T1078.004": {
        "id": "T1078.004",
        "name": "Privilege Abuse (Enterprise Accounts)",
        "name_ar": "إساءة استخدام صلاحيات الحسابات المؤسسية",
        "tactic": "Privilege Escalation",
        "tactic_ar": "تصعيد الصلاحيات",
        "matrix": "Enterprise",
        "description": "Employees or compromised accounts access resources outside their designated business role.",
        "remediation": "Enforce strict Role-Based Access Control (RBAC) and least privilege principles."
    },
    "T1087": {
        "id": "T1087",
        "name": "Account & Permission Discovery",
        "name_ar": "استكشاف الحسابات والأقسام المؤسسية",
        "tactic": "Discovery",
        "tactic_ar": "الاستكشاف (Discovery)",
        "matrix": "Enterprise",
        "description": "Adversaries enumerate domain users, service accounts, and departmental groups.",
        "remediation": "Monitor LDAP/Active Directory queries for suspicious cross-departmental user enumeration."
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services / Lateral Movement",
        "name_ar": "الانتقال الجانبي عبر الخدمات عن بعد",
        "tactic": "Lateral Movement",
        "tactic_ar": "الانتقال الجانبي (Lateral Movement)",
        "matrix": "Enterprise",
        "description": "Adversaries log into remote services (SSH, RDP, SMB) to pivot across enterprise workstations and servers.",
        "remediation": "Block workstation-to-workstation communication with host-based firewalls."
    },
    "T1048": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "name_ar": "تسريب البيانات عبر بروتوكولات بديلة",
        "tactic": "Exfiltration",
        "tactic_ar": "تسريب البيانات (Exfiltration)",
        "matrix": "Enterprise",
        "description": "Adversaries steal sensitive data by exfiltrating it over FTP, HTTP, or external cloud relays.",
        "remediation": "Inspect outbound traffic, restrict egress ports, and implement canary data watermarking."
    },
    "T1552": {
        "id": "T1552",
        "name": "Unsecured Credentials",
        "name_ar": "البحث عن بيانات الاعتماد غير المحمية",
        "tactic": "Credential Access",
        "tactic_ar": "الوصول لبيانات الاعتماد",
        "matrix": "Enterprise",
        "description": "Adversaries search files, scripts, and configs for plaintext API keys and passwords.",
        "remediation": "Store secrets in secure hardware security modules (HSM) or secrets vaults."
    }
}

class MitreEngine:
    @staticmethod
    def get_catalog() -> Dict[str, Dict[str, Any]]:
        return MITRE_CATALOG

    @staticmethod
    def get_technique(tech_id: str) -> Optional[Dict[str, Any]]:
        # Handle prefixes like "T1078 - Valid Accounts"
        clean_id = tech_id.split(" ")[0].split("-")[0].strip()
        return MITRE_CATALOG.get(clean_id)

    @staticmethod
    def map_incident_tactics(rules: List[str], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Maps triggered rules and event indicators to formal MITRE ATT&CK techniques.
        """
        mapped_ids = set()

        # Rule-based mapping
        if "R1" in rules:
            mapped_ids.add("T1078")
            mapped_ids.add("T1083")
        if "R2" in rules:
            mapped_ids.add("T1078.004")
        if "R3" in rules:
            mapped_ids.add("T1087")
        if "R4" in rules:
            mapped_ids.add("T1048")
            mapped_ids.add("T1005")
        if "R5" in rules:
            mapped_ids.add("T1021")

        # Event-based inspection for ICS / Specific Traps
        for ev in events:
            res = str(ev.get("resource", "")).lower()
            tgt = str(ev.get("target_host", "")).lower()
            act = str(ev.get("action", "")).lower()

            if "plc" in tgt or "modbus" in res or "s7" in res:
                mapped_ids.add("T0882")  # ICS Discovery
                if "write" in act or "override" in res or "coil" in res:
                    mapped_ids.add("T0855")  # Unauthorized Command
                    mapped_ids.add("T0843")  # Modify Controller
            if "hmi" in tgt or "hmi" in res:
                mapped_ids.add("T0812")  # Default Credentials / HMI
            if "api" in res or ev.get("api_key"):
                mapped_ids.add("T1552")  # Unsecured Credentials

        result = []
        for tid in sorted(mapped_ids):
            tech = MITRE_CATALOG.get(tid)
            if tech:
                result.append(tech)
            else:
                result.append({
                    "id": tid,
                    "name": tid,
                    "name_ar": tid,
                    "tactic": "General",
                    "tactic_ar": "عام",
                    "matrix": "Enterprise",
                    "description": "ATT&CK Technique",
                    "remediation": "Apply defense-in-depth principles."
                })
        return result

    @staticmethod
    def get_matrix_heatmap(incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Computes frequency and activation status for each MITRE technique across all incidents.
        """
        technique_hits = {k: 0 for k in MITRE_CATALOG.keys()}
        tactics_summary: Dict[str, int] = {}

        for inc in incidents:
            forensics = inc.get("forensics", {})
            attck_list = forensics.get("mitre_att_ck_details") or []
            for item in attck_list:
                tid = item.get("id")
                if tid in technique_hits:
                    technique_hits[tid] += 1
                    tactic = item.get("tactic", "Other")
                    tactics_summary[tactic] = tactics_summary.get(tactic, 0) + 1

        catalog_with_counts = []
        for tid, data in MITRE_CATALOG.items():
            count = technique_hits.get(tid, 0)
            catalog_with_counts.append({
                **data,
                "hit_count": count,
                "active": count > 0,
                "intensity": "high" if count >= 3 else ("medium" if count > 0 else "inactive")
            })

        return {
            "catalog": catalog_with_counts,
            "tactics_summary": tactics_summary,
            "total_mapped_incidents": len(incidents)
        }
