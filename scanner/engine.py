from scanner.dockerfile_parser import parse_dockerfile
from scanner.k8s_parser import parse_k8s_manifests
from scanner.rules.dockerfile_rules import run_dockerfile_rules
from scanner.rules.k8s_rules import run_k8s_rules


def scan_dockerfile_text(text: str, resource_id: str = "Dockerfile") -> list:
    dockerfile = parse_dockerfile(text)
    return run_dockerfile_rules(dockerfile, resource_id)


def scan_dockerfile_file(path: str) -> list:
    with open(path) as f:
        return scan_dockerfile_text(f.read(), resource_id=path)


def scan_k8s_yaml_text(text: str) -> list:
    manifests = parse_k8s_manifests(text)
    findings = []
    for manifest in manifests:
        findings.extend(run_k8s_rules(manifest))
    return findings


def scan_k8s_yaml_file(path: str) -> list:
    with open(path) as f:
        return scan_k8s_yaml_text(f.read())


def compute_risk_score(findings: list, cap: int = 100) -> int:
    return min(sum(f.severity.value for f in findings), cap)
