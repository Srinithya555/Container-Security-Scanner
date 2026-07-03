from scanner.engine import compute_risk_score
from scanner.models import Severity

SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[91m", Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m", Severity.LOW: "\033[94m", Severity.INFO: "\033[90m",
}
RESET = "\033[0m"


def print_text_report(findings: list, title: str = "CONTAINER SECURITY SCAN REPORT") -> None:
    score = compute_risk_score(findings)
    print("=" * 72)
    print(title)
    print("=" * 72)
    print(f"\nRisk score: {score}/100  ({len(findings)} findings)\n")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        items = [f for f in findings if f.severity == sev]
        if not items:
            continue
        color = SEVERITY_COLOR.get(sev, "")
        print(f"{color}--- {sev.name} ({len(items)}) ---{RESET}")
        for f in items:
            print(f"  [{f.rule_id}] {f.resource_id}")
            print(f"      {f.title}")
            print(f"      {f.description}")
            print(f"      Fix: {f.remediation}\n")
