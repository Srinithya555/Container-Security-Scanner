"""
Kubernetes pod spec security rules, operating on the normalized
{"kind", "name", "namespace", "pod_spec"} dicts from k8s_parser.py.
"""
from scanner.models import Finding, Severity


def _containers(pod_spec: dict) -> list:
    return (pod_spec.get("containers") or []) + (pod_spec.get("initContainers") or [])


def check_privileged_container(manifest: dict) -> list:
    findings = []
    for c in _containers(manifest["pod_spec"]):
        sc = c.get("securityContext", {}) or {}
        if sc.get("privileged") is True:
            findings.append(Finding(
                resource_type="k8s_pod_spec", resource_id=f"{manifest['kind']}/{manifest['name']}",
                rule_id="K8S-001", severity=Severity.CRITICAL,
                title=f"Container '{c.get('name', '?')}' runs privileged",
                description="privileged: true gives the container nearly all capabilities of "
                             "the host — effectively no container isolation. A compromise of "
                             "this container is close to a host compromise.",
                remediation="Remove privileged: true. If specific capabilities are needed, "
                             "add only those specific capabilities instead.",
            ))
    return findings


def check_host_namespace_sharing(manifest: dict) -> list:
    findings = []
    spec = manifest["pod_spec"]
    for field_name, label in [("hostNetwork", "host network"), ("hostPID", "host PID namespace"),
                                ("hostIPC", "host IPC namespace")]:
        if spec.get(field_name) is True:
            findings.append(Finding(
                resource_type="k8s_pod_spec", resource_id=f"{manifest['kind']}/{manifest['name']}",
                rule_id="K8S-002", severity=Severity.HIGH,
                title=f"Pod shares the {label} with the host",
                description=f"{field_name}: true removes namespace isolation between this "
                             f"pod and the host — it can see/interact with host-level "
                             f"{'network interfaces' if 'Network' in field_name else 'processes' if 'PID' in field_name else 'IPC resources'}.",
                remediation=f"Remove {field_name}: true unless there's a specific, "
                             "documented operational reason (e.g. a network monitoring "
                             "daemonset) that requires it.",
            ))
    return findings


def check_missing_run_as_non_root(manifest: dict) -> list:
    findings = []
    pod_level_non_root = manifest["pod_spec"].get("securityContext", {}).get("runAsNonRoot")
    for c in _containers(manifest["pod_spec"]):
        container_sc = c.get("securityContext", {}) or {}
        effective = container_sc.get("runAsNonRoot", pod_level_non_root)
        if effective is not True:
            findings.append(Finding(
                resource_type="k8s_pod_spec", resource_id=f"{manifest['kind']}/{manifest['name']}",
                rule_id="K8S-003", severity=Severity.MEDIUM,
                title=f"Container '{c.get('name', '?')}' does not enforce runAsNonRoot",
                description="Neither the pod nor this container sets securityContext."
                             "runAsNonRoot: true, so it may run as root depending on the "
                             "image's own default user.",
                remediation="Set securityContext.runAsNonRoot: true at the pod or container level.",
            ))
    return findings


def check_allow_privilege_escalation(manifest: dict) -> list:
    findings = []
    for c in _containers(manifest["pod_spec"]):
        sc = c.get("securityContext", {}) or {}
        if sc.get("allowPrivilegeEscalation") is not False:
            findings.append(Finding(
                resource_type="k8s_pod_spec", resource_id=f"{manifest['kind']}/{manifest['name']}",
                rule_id="K8S-004", severity=Severity.MEDIUM,
                title=f"Container '{c.get('name', '?')}' does not explicitly disable privilege escalation",
                description="allowPrivilegeEscalation defaults to true if not explicitly set "
                             "to false, permitting a process to gain more privileges than its "
                             "parent (e.g. via setuid binaries).",
                remediation="Set securityContext.allowPrivilegeEscalation: false.",
            ))
    return findings


def check_hostpath_volume(manifest: dict) -> list:
    findings = []
    for volume in manifest["pod_spec"].get("volumes", []) or []:
        if "hostPath" in volume:
            path = volume["hostPath"].get("path", "?")
            findings.append(Finding(
                resource_type="k8s_pod_spec", resource_id=f"{manifest['kind']}/{manifest['name']}",
                rule_id="K8S-005", severity=Severity.HIGH,
                title=f"hostPath volume mounts host directory '{path}'",
                description="hostPath volumes give the pod direct access to a path on the "
                             "underlying node's filesystem — a common container-escape vector, "
                             "especially if the mounted path includes sensitive locations "
                             "like /var/run/docker.sock or /etc.",
                remediation="Avoid hostPath where possible; use a properly scoped "
                             "PersistentVolume/PersistentVolumeClaim instead.",
            ))
    return findings


def check_missing_resource_limits(manifest: dict) -> list:
    findings = []
    for c in _containers(manifest["pod_spec"]):
        resources = c.get("resources", {}) or {}
        if "limits" not in resources:
            findings.append(Finding(
                resource_type="k8s_pod_spec", resource_id=f"{manifest['kind']}/{manifest['name']}",
                rule_id="K8S-006", severity=Severity.LOW,
                title=f"Container '{c.get('name', '?')}' has no resource limits",
                description="Without CPU/memory limits, a single misbehaving or compromised "
                             "container (e.g. running a cryptominer, or hitting a memory leak) "
                             "can starve other workloads on the same node.",
                remediation="Set resources.limits.cpu and resources.limits.memory.",
            ))
    return findings


def check_image_tag_latest(manifest: dict) -> list:
    findings = []
    for c in _containers(manifest["pod_spec"]):
        image = c.get("image", "")
        if ":" not in image.split("/")[-1] or image.endswith(":latest"):
            findings.append(Finding(
                resource_type="k8s_pod_spec", resource_id=f"{manifest['kind']}/{manifest['name']}",
                rule_id="K8S-007", severity=Severity.MEDIUM,
                title=f"Container '{c.get('name', '?')}' uses image '{image}' (latest/untagged)",
                description="Same issue as the Dockerfile FROM check: an untagged or "
                             "':latest' image reference means the exact deployed content can "
                             "silently change between pod restarts/reschedules.",
                remediation="Pin to a specific, immutable image tag or digest.",
            ))
    return findings


ALL_K8S_RULES = [
    check_privileged_container,
    check_host_namespace_sharing,
    check_missing_run_as_non_root,
    check_allow_privilege_escalation,
    check_hostpath_volume,
    check_missing_resource_limits,
    check_image_tag_latest,
]


def run_k8s_rules(manifest: dict) -> list:
    findings = []
    for rule in ALL_K8S_RULES:
        findings.extend(rule(manifest))
    return findings
