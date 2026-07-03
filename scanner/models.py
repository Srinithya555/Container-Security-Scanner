from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = 40
    HIGH = 20
    MEDIUM = 10
    LOW = 5
    INFO = 1


@dataclass
class Finding:
    resource_type: str  # "dockerfile" | "k8s_pod_spec"
    resource_id: str
    rule_id: str
    severity: Severity
    title: str
    description: str
    remediation: str
