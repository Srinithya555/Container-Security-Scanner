import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.dockerfile_parser import parse_dockerfile
from scanner.rules.dockerfile_rules import (
    check_missing_user, check_latest_tag, check_add_instead_of_copy,
    check_secrets_in_env_or_arg, check_missing_healthcheck,
)


class TestMissingUser:
    def test_flags_missing_user(self):
        df = parse_dockerfile("FROM node:18\nCMD [\"node\"]\n")
        assert len(check_missing_user(df, "Dockerfile")) == 1

    def test_does_not_flag_when_user_present(self):
        df = parse_dockerfile("FROM node:18\nUSER appuser\n")
        assert check_missing_user(df, "Dockerfile") == []

    def test_checks_only_final_stage_user(self):
        """A USER in an early build stage doesn't count for the final image."""
        df = parse_dockerfile("FROM node:18 AS builder\nUSER builduser\nFROM node:18\nCMD [\"node\"]\n")
        assert len(check_missing_user(df, "Dockerfile")) == 1


class TestLatestTag:
    def test_flags_explicit_latest(self):
        df = parse_dockerfile("FROM node:latest\n")
        assert len(check_latest_tag(df, "Dockerfile")) == 1

    def test_flags_missing_tag(self):
        df = parse_dockerfile("FROM node\n")
        assert len(check_latest_tag(df, "Dockerfile")) == 1

    def test_does_not_flag_pinned_version(self):
        df = parse_dockerfile("FROM node:18.20.4\n")
        assert check_latest_tag(df, "Dockerfile") == []

    def test_handles_multi_stage_alias_suffix(self):
        df = parse_dockerfile("FROM node:18.20.4 AS builder\n")
        assert check_latest_tag(df, "Dockerfile") == []


class TestAddVsCopy:
    def test_flags_local_add(self):
        df = parse_dockerfile("FROM node:18\nADD ./app.tar.gz /app\n")
        assert len(check_add_instead_of_copy(df, "Dockerfile")) == 1

    def test_does_not_flag_remote_url_add(self):
        """ADD's one legitimate use case — fetching a remote URL — shouldn't be flagged."""
        df = parse_dockerfile("FROM node:18\nADD https://example.com/file.tar.gz /app\n")
        assert check_add_instead_of_copy(df, "Dockerfile") == []


class TestSecretsInEnvArg:
    def test_flags_password_in_env(self):
        df = parse_dockerfile("FROM node:18\nENV DB_PASSWORD=hunter2\n")
        assert len(check_secrets_in_env_or_arg(df, "Dockerfile")) == 1

    def test_flags_secret_in_arg(self):
        df = parse_dockerfile("FROM node:18\nARG API_SECRET=abc123\n")
        assert len(check_secrets_in_env_or_arg(df, "Dockerfile")) == 1

    def test_does_not_flag_non_secret_env(self):
        df = parse_dockerfile("FROM node:18\nENV NODE_ENV=production\n")
        assert check_secrets_in_env_or_arg(df, "Dockerfile") == []


class TestMissingHealthcheck:
    def test_flags_missing_healthcheck(self):
        df = parse_dockerfile("FROM node:18\nCMD [\"node\"]\n")
        assert len(check_missing_healthcheck(df, "Dockerfile")) == 1

    def test_does_not_flag_when_present(self):
        df = parse_dockerfile("FROM node:18\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n")
        assert check_missing_healthcheck(df, "Dockerfile") == []
