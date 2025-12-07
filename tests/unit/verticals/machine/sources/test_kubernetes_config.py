"""
Tests for Kubernetes config secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.kubernetes_config import KubernetesConfigSource


class TestKubernetesConfigSource:
    """Tests for KubernetesConfigSource."""

    def test_source_type(self):
        """
        GIVEN a KubernetesConfigSource
        WHEN accessing source_type
        THEN it returns KUBERNETES_CONFIG
        """
        source = KubernetesConfigSource()
        assert source.source_type == SourceType.KUBERNETES_CONFIG

    def test_gather_with_token(self, tmp_path: Path):
        """
        GIVEN a kubeconfig with user token
        WHEN gathering secrets
        THEN yields the token
        """
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        # Using simple YAML that works without PyYAML parser
        config_content = """apiVersion: v1
kind: Config
users:
- name: test-user
  user:
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0
"""
        (kube_dir / "config").write_text(config_content)

        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        # Should find the token
        assert len(secrets) >= 1
        assert any("eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9" in s.value for s in secrets)
        assert all(
            s.metadata.source_type == SourceType.KUBERNETES_CONFIG for s in secrets
        )

    def test_gather_with_password(self, tmp_path: Path):
        """
        GIVEN a kubeconfig with user password
        WHEN gathering secrets
        THEN yields the password
        """
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        config_content = """apiVersion: v1
users:
- name: basic-user
  user:
    password: supersecretpassword
"""
        (kube_dir / "config").write_text(config_content)

        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) >= 1
        assert any(s.value == "supersecretpassword" for s in secrets)

    def test_gather_with_client_key_data(self, tmp_path: Path):
        """
        GIVEN a kubeconfig with client key data
        WHEN gathering secrets
        THEN yields the client key data
        """
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        # Base64-encoded key data (example)
        key_data = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQo="
        config_content = f"""apiVersion: v1
users:
- name: cert-user
  user:
    client-key-data: {key_data}
"""
        (kube_dir / "config").write_text(config_content)

        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) >= 1
        assert any(key_data in s.value for s in secrets)

    def test_gather_no_kubeconfig(self, tmp_path: Path):
        """
        GIVEN no kubeconfig file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_kubeconfig(self, tmp_path: Path):
        """
        GIVEN an empty kubeconfig file
        WHEN gathering secrets
        THEN yields nothing
        """
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        (kube_dir / "config").write_text("")

        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_kubeconfig_without_users(self, tmp_path: Path):
        """
        GIVEN a kubeconfig without users section
        WHEN gathering secrets
        THEN yields nothing
        """
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        config_content = """apiVersion: v1
kind: Config
clusters:
- name: my-cluster
  cluster:
    server: https://kubernetes.example.com
"""
        (kube_dir / "config").write_text(config_content)

        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
