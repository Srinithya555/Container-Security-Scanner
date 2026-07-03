#!/usr/bin/env python3
"""
Usage:
    python scripts/scan_cli.py --dockerfile path/to/Dockerfile
    python scripts/scan_cli.py --k8s path/to/deployment.yaml
    python scripts/scan_cli.py --dockerfile Dockerfile --k8s deployment.yaml --fail-on HIGH
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.engine import scan_dockerfile_file, scan_k8s_yaml_file, compute_risk_score
from scanner.report import print_text_report
from scanner.models import Severity


def main():
    parser = argparse.ArgumentParser(description="Scan Dockerfiles and Kubernetes manifests for security issues.")
    parser.add_argument("--dockerfile", help="Path to a Dockerfile")
    parser.add_argument("--k8s", help="Path to a Kubernetes manifest YAML file")
    parser.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], default="HIGH")
    args = parser.parse_args()

    if not args.dockerfile and not args.k8s:
        parser.error("Provide at least one of --dockerfile or --k8s")

    all_findings = []
    if args.dockerfile:
        findings = scan_dockerfile_file(args.dockerfile)
        print_text_report(findings, title=f"DOCKERFILE SCAN: {args.dockerfile}")
        all_findings.extend(findings)

    if args.k8s:
        findings = scan_k8s_yaml_file(args.k8s)
        print_text_report(findings, title=f"KUBERNETES MANIFEST SCAN: {args.k8s}")
        all_findings.extend(findings)

    threshold = Severity[args.fail_on].value
    should_fail = any(f.severity.value >= threshold for f in all_findings)
    sys.exit(1 if should_fail else 0)


if __name__ == "__main__":
    main()
