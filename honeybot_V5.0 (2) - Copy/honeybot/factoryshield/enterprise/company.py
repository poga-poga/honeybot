"""
Jordan Industrial Manufacturing (JIM) Enterprise Model
Virtual Enterprise Architecture & Asset Inventory
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from factoryshield.config import NETWORKS

@dataclass
class EnterpriseHost:
    hostname: str
    ip: str
    network: str
    host_type: str
    department: str
    assigned_user: Optional[str] = None
    services: List[str] = field(default_factory=list)

@dataclass
class Department:
    code: str
    name_en: str
    name_ar: str
    description: str
    data_classification: str
    workstations: List[str]
    servers: List[str]

DEPARTMENTS: Dict[str, Department] = {
    "Management": Department(
        code="MGMT",
        name_en="Management",
        name_ar="الإدارة",
        description="إدارة الشركة والتقارير التنفيذية الداخلية",
        data_classification="Confidential / Executive",
        workstations=["WS-MGMT-01"],
        servers=[]
    ),
    "Engineering": Department(
        code="ENG",
        name_en="Engineering",
        name_ar="الهندسة",
        description="تصميم المنتجات، مخططات CAD، ومواصفات القطع الميكانيكية",
        data_classification="Proprietary IP / Secret",
        workstations=["WS-ENG-01"],
        servers=["cad-srv01.jim.corp", "cad-repo01.jim.corp"]
    ),
    "Production": Department(
        code="PROD",
        name_en="Production",
        name_ar="الإنتاج",
        description="متابعة التصنيع، جداول خطوط الإنتاج، والتحكم الصناعي",
        data_classification="Internal / Operational",
        workstations=["WS-PROD-01"],
        servers=["db-prod01.jim.corp", "plc-sim01.jim.corp", "hmi-prod01.jim.corp"]
    ),
    "HR": Department(
        code="HR",
        name_en="Human Resources",
        name_ar="الموارد البشرية",
        description="إدارة الموظفين، الرواتب، وسجلات الكادر الوظيفي",
        data_classification="Restricted PII",
        workstations=["WS-HR-01"],
        servers=[]
    ),
    "IT": Department(
        code="IT",
        name_en="Information Technology",
        name_ar="تقنية المعلومات",
        description="إدارة الأنظمة، الخوادم، والشبكات والبنية التحتية",
        data_classification="Administrative / Infrastructure",
        workstations=["WS-IT-01"],
        servers=[]
    )
}

def get_all_hosts() -> List[EnterpriseHost]:
    hosts = []
    for net_key, net_val in NETWORKS.items():
        for hostname, host_info in net_val.get("hosts", {}).items():
            hosts.append(EnterpriseHost(
                hostname=hostname,
                ip=host_info["ip"],
                network=net_key,
                host_type=host_info.get("type", "Workstation"),
                department=host_info.get("dept", "Unknown"),
                assigned_user=host_info.get("owner", None)
            ))
    return hosts

def get_host_by_name(hostname: str) -> Optional[EnterpriseHost]:
    for host in get_all_hosts():
        if host.hostname.lower() == hostname.lower():
            return host
    return None

def get_host_by_ip(ip: str) -> Optional[EnterpriseHost]:
    for host in get_all_hosts():
        if host.ip == ip:
            return host
    return None
