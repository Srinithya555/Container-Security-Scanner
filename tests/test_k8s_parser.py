import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.k8s_parser import parse_k8s_manifests


class TestK8sParser:
    def test_parses_pod_directly(self):
        yaml_text = """
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
  - name: c1
    image: nginx
"""
        results = parse_k8s_manifests(yaml_text)
        assert len(results) == 1
        assert results[0]["kind"] == "Pod"
        assert results[0]["pod_spec"]["containers"][0]["name"] == "c1"

    def test_parses_deployment_nested_pod_spec(self):
        yaml_text = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
spec:
  template:
    spec:
      containers:
      - name: c1
        image: nginx
"""
        results = parse_k8s_manifests(yaml_text)
        assert len(results) == 1
        assert results[0]["kind"] == "Deployment"
        assert "containers" in results[0]["pod_spec"]

    def test_skips_resources_without_pod_spec(self):
        yaml_text = """
apiVersion: v1
kind: Service
metadata:
  name: my-svc
spec:
  type: ClusterIP
"""
        assert parse_k8s_manifests(yaml_text) == []

    def test_multi_document_yaml_parses_all_relevant_docs(self):
        yaml_text = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app1
spec:
  template:
    spec:
      containers: [{name: c1, image: nginx}]
---
apiVersion: v1
kind: Service
metadata:
  name: svc1
---
apiVersion: v1
kind: Pod
metadata:
  name: pod1
spec:
  containers: [{name: c2, image: busybox}]
"""
        results = parse_k8s_manifests(yaml_text)
        assert len(results) == 2  # Deployment + Pod, Service skipped
        kinds = {r["kind"] for r in results}
        assert kinds == {"Deployment", "Pod"}

    def test_defaults_namespace_to_default(self):
        yaml_text = """
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers: [{name: c1, image: nginx}]
"""
        results = parse_k8s_manifests(yaml_text)
        assert results[0]["namespace"] == "default"

    def test_empty_yaml_returns_empty_list(self):
        assert parse_k8s_manifests("") == []

    def test_cronjob_nested_path(self):
        yaml_text = """
apiVersion: batch/v1
kind: CronJob
metadata:
  name: my-cronjob
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers: [{name: c1, image: nginx}]
"""
        results = parse_k8s_manifests(yaml_text)
        assert len(results) == 1
        assert results[0]["pod_spec"]["containers"][0]["name"] == "c1"
