import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.rules.k8s_rules import (
    check_privileged_container, check_host_namespace_sharing, check_missing_run_as_non_root,
    check_allow_privilege_escalation, check_hostpath_volume, check_missing_resource_limits,
    check_image_tag_latest,
)


def make_manifest(pod_spec, kind="Deployment", name="test"):
    return {"kind": kind, "name": name, "namespace": "default", "pod_spec": pod_spec}


class TestPrivileged:
    def test_flags_privileged_container(self):
        m = make_manifest({"containers": [{"name": "c1", "securityContext": {"privileged": True}}]})
        assert len(check_privileged_container(m)) == 1

    def test_does_not_flag_non_privileged(self):
        m = make_manifest({"containers": [{"name": "c1", "securityContext": {"privileged": False}}]})
        assert check_privileged_container(m) == []

    def test_does_not_flag_missing_security_context(self):
        m = make_manifest({"containers": [{"name": "c1"}]})
        assert check_privileged_container(m) == []


class TestHostNamespaces:
    def test_flags_host_network(self):
        m = make_manifest({"hostNetwork": True, "containers": []})
        findings = check_host_namespace_sharing(m)
        assert len(findings) == 1
        assert "network" in findings[0].title

    def test_flags_all_three_host_namespaces_independently(self):
        m = make_manifest({"hostNetwork": True, "hostPID": True, "hostIPC": True, "containers": []})
        assert len(check_host_namespace_sharing(m)) == 3

    def test_does_not_flag_when_absent(self):
        m = make_manifest({"containers": []})
        assert check_host_namespace_sharing(m) == []


class TestRunAsNonRoot:
    def test_flags_when_neither_pod_nor_container_sets_it(self):
        m = make_manifest({"containers": [{"name": "c1"}]})
        assert len(check_missing_run_as_non_root(m)) == 1

    def test_pod_level_setting_satisfies_check(self):
        m = make_manifest({"securityContext": {"runAsNonRoot": True}, "containers": [{"name": "c1"}]})
        assert check_missing_run_as_non_root(m) == []

    def test_container_level_overrides_pod_level(self):
        """Container explicitly setting False should still be flagged even
        if the pod sets True — container-level is more specific and wins."""
        m = make_manifest({
            "securityContext": {"runAsNonRoot": True},
            "containers": [{"name": "c1", "securityContext": {"runAsNonRoot": False}}],
        })
        assert len(check_missing_run_as_non_root(m)) == 1


class TestAllowPrivilegeEscalation:
    def test_flags_when_not_explicitly_false(self):
        m = make_manifest({"containers": [{"name": "c1"}]})
        assert len(check_allow_privilege_escalation(m)) == 1

    def test_does_not_flag_when_explicitly_false(self):
        m = make_manifest({"containers": [{"name": "c1", "securityContext": {"allowPrivilegeEscalation": False}}]})
        assert check_allow_privilege_escalation(m) == []


class TestHostPathVolume:
    def test_flags_hostpath_volume(self):
        m = make_manifest({"containers": [], "volumes": [{"name": "v1", "hostPath": {"path": "/etc"}}]})
        assert len(check_hostpath_volume(m)) == 1

    def test_does_not_flag_other_volume_types(self):
        m = make_manifest({"containers": [], "volumes": [{"name": "v1", "emptyDir": {}}]})
        assert check_hostpath_volume(m) == []

    def test_no_volumes_does_not_crash(self):
        m = make_manifest({"containers": []})
        assert check_hostpath_volume(m) == []


class TestResourceLimits:
    def test_flags_missing_limits(self):
        m = make_manifest({"containers": [{"name": "c1", "resources": {}}]})
        assert len(check_missing_resource_limits(m)) == 1

    def test_does_not_flag_when_limits_present(self):
        m = make_manifest({"containers": [{"name": "c1", "resources": {"limits": {"cpu": "500m"}}}]})
        assert check_missing_resource_limits(m) == []

    def test_missing_resources_key_entirely_flagged(self):
        m = make_manifest({"containers": [{"name": "c1"}]})
        assert len(check_missing_resource_limits(m)) == 1


class TestImageTagLatest:
    def test_flags_latest_tag(self):
        m = make_manifest({"containers": [{"name": "c1", "image": "nginx:latest"}]})
        assert len(check_image_tag_latest(m)) == 1

    def test_flags_untagged_image(self):
        m = make_manifest({"containers": [{"name": "c1", "image": "nginx"}]})
        assert len(check_image_tag_latest(m)) == 1

    def test_does_not_flag_pinned_tag(self):
        m = make_manifest({"containers": [{"name": "c1", "image": "nginx:1.25.3"}]})
        assert check_image_tag_latest(m) == []

    def test_handles_registry_with_port_correctly(self):
        """A private registry hostname with a port (registry.example.com:5000/app)
        must not be confused with an image tag — the check should split on the
        LAST path segment before looking for a colon."""
        m = make_manifest({"containers": [{"name": "c1", "image": "registry.example.com:5000/app:2.1.0"}]})
        assert check_image_tag_latest(m) == []
