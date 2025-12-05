"""
Tests for environment variable secret source.
"""

import os
from unittest.mock import patch

import pytest

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.environment import (
    EXCLUDED_ENV_KEYS,
    EnvironmentSecretSource,
)


class TestEnvironmentSecretSource:
    """Tests for EnvironmentSecretSource."""

    def test_source_type(self):
        """
        GIVEN an EnvironmentSecretSource
        WHEN accessing source_type
        THEN it returns ENVIRONMENT_VAR
        """
        source = EnvironmentSecretSource()
        assert source.source_type == SourceType.ENVIRONMENT_VAR

    def test_gather_returns_env_vars(self):
        """
        GIVEN environment variables set
        WHEN gathering secrets
        THEN yields secrets with correct values and metadata
        """
        test_env = {
            "MY_SECRET_KEY": "secret_value_123",
            "API_TOKEN": "token_abc",
        }

        with patch.dict(os.environ, test_env, clear=True):
            source = EnvironmentSecretSource()
            secrets = list(source.gather())

        assert len(secrets) == 2
        secret_names = {s.metadata.secret_name for s in secrets}
        assert secret_names == {"MY_SECRET_KEY", "API_TOKEN"}

        for secret in secrets:
            assert secret.metadata.source_type == SourceType.ENVIRONMENT_VAR
            assert secret.metadata.source_path == "environment"

    def test_gather_excludes_common_vars(self):
        """
        GIVEN environment with common non-secret variables
        WHEN gathering secrets
        THEN excludes PATH, HOME, USER, etc.
        """
        test_env = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/home/user",
            "USER": "testuser",
            "SHELL": "/bin/bash",
            "MY_ACTUAL_SECRET": "real_secret",
        }

        with patch.dict(os.environ, test_env, clear=True):
            source = EnvironmentSecretSource()
            secrets = list(source.gather())

        secret_names = {s.metadata.secret_name for s in secrets}
        assert "MY_ACTUAL_SECRET" in secret_names
        assert "PATH" not in secret_names
        assert "HOME" not in secret_names
        assert "USER" not in secret_names
        assert "SHELL" not in secret_names

    def test_gather_empty_environment(self):
        """
        GIVEN an empty environment
        WHEN gathering secrets
        THEN yields nothing
        """
        with patch.dict(os.environ, {}, clear=True):
            source = EnvironmentSecretSource()
            secrets = list(source.gather())

        assert len(secrets) == 0

    @pytest.mark.parametrize("excluded_key", list(EXCLUDED_ENV_KEYS)[:5])
    def test_excluded_keys_are_filtered(self, excluded_key):
        """
        GIVEN an environment with an excluded key
        WHEN gathering secrets
        THEN that key is not included
        """
        test_env = {
            excluded_key: "some_value",
            "KEEP_THIS_SECRET": "secret",
        }

        with patch.dict(os.environ, test_env, clear=True):
            source = EnvironmentSecretSource()
            secrets = list(source.gather())

        secret_names = {s.metadata.secret_name for s in secrets}
        assert excluded_key not in secret_names
        assert "KEEP_THIS_SECRET" in secret_names
