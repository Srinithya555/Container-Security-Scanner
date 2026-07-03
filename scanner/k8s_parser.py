"""
Parses Kubernetes manifest YAML (which commonly contains multiple
documents separated by `---` in one file — e.g. a Deployment plus its
Service in the same manifest). Extracts pod specs from whichever
resource kind contains one (Pod, Deployment, StatefulSet, DaemonSet,
Job, CronJob all nest a pod spec at different YAML paths).
"""
import yaml

_POD_SPEC_PATHS = {
    "Pod": lambda doc: doc.get("spec"),
    "Deployment": lambda doc: doc.get("spec", {}).get("template", {}).get("spec"),
    "StatefulSet": lambda doc: doc.get("spec", {}).get("template", {}).get("spec"),
    "DaemonSet": lambda doc: doc.get("spec", {}).get("template", {}).get("spec"),
    "Job": lambda doc: doc.get("spec", {}).get("template", {}).get("spec"),
    "CronJob": lambda doc: doc.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec"),
}


def parse_k8s_manifests(yaml_text: str) -> list:
    """
    Returns a list of dicts: {"kind": str, "name": str, "namespace": str,
    "pod_spec": dict} — one per document that contains a pod spec.
    Documents of kinds without a pod spec (Service, ConfigMap, etc.) are
    skipped, since the security rules in this project only inspect
    workload pod specs.
    """
    results = []
    for doc in yaml.safe_load_all(yaml_text):
        if not doc or not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "")
        extractor = _POD_SPEC_PATHS.get(kind)
        if extractor is None:
            continue
        pod_spec = extractor(doc)
        if pod_spec is None:
            continue
        metadata = doc.get("metadata", {}) or {}
        results.append({
            "kind": kind,
            "name": metadata.get("name", "unnamed"),
            "namespace": metadata.get("namespace", "default"),
            "pod_spec": pod_spec,
        })
    return results
