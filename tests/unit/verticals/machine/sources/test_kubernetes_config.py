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

    def test_gather_with_auth_provider_tokens(self, tmp_path: Path):
        """
        GIVEN a kubeconfig with auth-provider config (GKE/EKS style)
        WHEN gathering secrets
        THEN yields access-token and id-token
        """
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        config_content = """apiVersion: v1
users:
- name: gke-user
  user:
    auth-provider:
      name: gcp
      config:
        access-token: ya29.a0AfH6SMBxxxxxxxxxxxxxxxx
        id-token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.xxxxx
"""
        (kube_dir / "config").write_text(config_content)

        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        secret_names = {s.metadata.secret_name for s in secrets}
        assert "users/gke-user/auth-provider/access-token" in secret_names
        assert "users/gke-user/auth-provider/id-token" in secret_names

    def test_gather_invalid_users_type(self, tmp_path: Path):
        """
        GIVEN a kubeconfig where users is not a list
        WHEN gathering secrets
        THEN yields nothing (handles gracefully)
        """
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        config_content = """apiVersion: v1
users: not_a_list
"""
        (kube_dir / "config").write_text(config_content)

        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_invalid_user_entry_type(self, tmp_path: Path):
        """
        GIVEN a kubeconfig where user entry is not a dict
        WHEN gathering secrets
        THEN skips that entry
        """
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        config_content = """apiVersion: v1
users:
- "not_a_dict"
- name: valid-user
  user:
    token: valid_token_12345
"""
        (kube_dir / "config").write_text(config_content)

        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        # Should find the valid token, skip the invalid entry
        assert len(secrets) >= 1
        assert any("valid_token_12345" in s.value for s in secrets)

    def test_gather_invalid_user_config_type(self, tmp_path: Path):
        """
        GIVEN a kubeconfig where user.user is not a dict
        WHEN gathering secrets
        THEN skips that user
        """
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        config_content = """apiVersion: v1
users:
- name: invalid-config-user
  user: "not_a_dict"
"""
        (kube_dir / "config").write_text(config_content)

        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_without_yaml_fallback(self, tmp_path: Path, monkeypatch):
        """
        GIVEN PyYAML is not installed
        WHEN gathering secrets from kubeconfig
        THEN uses regex fallback to extract tokens
        """
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        config_content = """apiVersion: v1
users:
- name: test-user
  user:
    token: fallback_token_12345
    password: fallback_pass_67890
"""
        (kube_dir / "config").write_text(config_content)

        # Mock yaml import to raise ImportError
        original_import = __builtins__["__import__"]

        def mock_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("No module named 'yaml'")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", mock_import)

        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        # Fallback should still find secrets via regex
        assert len(secrets) >= 1
        values = {s.value for s in secrets}
        assert "fallback_token_12345" in values or "fallback_pass_67890" in values

    def test_gather_yaml_parse_error(self, tmp_path: Path):
        """
        GIVEN a kubeconfig with invalid YAML
        WHEN gathering secrets
        THEN yields nothing (handles gracefully)
        """
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        config_content = """apiVersion: v1
users:
  - this: is: invalid: yaml: syntax
    [broken
"""
        (kube_dir / "config").write_text(config_content)

        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        # Should handle parse error gracefully
        assert len(secrets) == 0

    def test_gather_not_dict_root(self, tmp_path: Path):
        """
        GIVEN a kubeconfig that parses to non-dict (e.g., just a string)
        WHEN gathering secrets
        THEN yields nothing
        """
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        # YAML that parses to a string, not a dict
        config_content = "just a string, not yaml dict"
        (kube_dir / "config").write_text(config_content)

        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_extract_without_yaml_quoted_values(self, tmp_path: Path, monkeypatch):
        """
        GIVEN PyYAML is not installed and config has quoted values
        WHEN gathering secrets
        THEN removes quotes from extracted values
        """
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        config_content = """apiVersion: v1
users:
- name: test-user
  user:
    token: "quoted_token_value"
    password: 'single_quoted_pass'
"""
        (kube_dir / "config").write_text(config_content)

        # Mock yaml import to raise ImportError
        original_import = __builtins__["__import__"]

        def mock_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("No module named 'yaml'")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", mock_import)

        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        # Values should have quotes stripped
        values = {s.value for s in secrets}
        assert "quoted_token_value" in values or "single_quoted_pass" in values
        # Quotes should be removed
        assert '"quoted_token_value"' not in values

    def test_extract_without_yaml_empty_values(self, tmp_path: Path, monkeypatch):
        """
        GIVEN PyYAML is not installed and config has empty quoted values
        WHEN gathering secrets
        THEN skips empty values
        """
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        config_content = """apiVersion: v1
users:
- name: test-user
  user:
    token: ""
    password: ''
"""
        (kube_dir / "config").write_text(config_content)

        # Mock yaml import to raise ImportError
        original_import = __builtins__["__import__"]

        def mock_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("No module named 'yaml'")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", mock_import)

        source = KubernetesConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        # Empty values should be skipped
        assert len(secrets) == 0
