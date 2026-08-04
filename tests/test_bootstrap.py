"""Offline checks for configuration and repository boundaries."""

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_urllib3_config_matches_bootstrap_contract() -> None:
    config_path = PROJECT_ROOT / "configs" / "urllib3.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    assert config["package"] == {
        "name": "urllib3",
        "ecosystem": "PyPI",
        "purl": "pkg:pypi/urllib3",
        "repository": "urllib3/urllib3",
        "version_scheme": "pep440",
    }
    assert config["sources"] == {
        "pypi": True,
        "github_releases": True,
        "github_tags": True,
        "changelog": True,
        "github_advisories": True,
        "osv": True,
        "nvd": "optional",
        "patches": True,
        "regression_tests": True,
    }
    assert config["repository"] == {
        "default_branch": "main",
        "changelog_candidates": ["CHANGES.rst", "CHANGELOG.md", "HISTORY.rst"],
        "security_policy_candidates": ["SECURITY.md", ".github/SECURITY.md"],
    }
    assert config["output"] == {
        "directory": "data",
        "deterministic": True,
        "include_raw": True,
        "include_kb_documents": True,
    }
    assert config["crawl"] == {
        "timeout_seconds": 30,
        "max_retries": 4,
        "cache_enabled": True,
        "respect_rate_limits": True,
        "max_response_bytes": 10_485_760,
        "initial_backoff_seconds": 1.0,
        "max_retry_delay_seconds": 60.0,
    }


def test_environment_template_contains_names_without_values() -> None:
    assignments = {
        line.split("=", maxsplit=1)[0]: line.split("=", maxsplit=1)[1]
        for line in (PROJECT_ROOT / ".env.example")
        .read_text(encoding="utf-8")
        .splitlines()
        if line and not line.startswith("#")
    }

    assert assignments == {"GITHUB_TOKEN": "", "NVD_API_KEY": ""}


def test_planned_repository_boundaries_exist() -> None:
    expected_directories = (
        "crawler/clients",
        "crawler/extractors",
        "crawler/normalizers",
        "crawler/resolvers",
        "crawler/validators",
        "crawler/exporters",
        "crawler/utils",
        "schemas",
        "tests/fixtures",
        "tests/fixtures/pipeline",
        "data/raw",
        "data/normalized",
        "data/kb",
    )

    for relative_path in expected_directories:
        assert (PROJECT_ROOT / relative_path).is_dir()


def test_pipeline_fixture_bundle_exists() -> None:
    fixture_root = PROJECT_ROOT / "tests" / "fixtures" / "pipeline"
    required = (
        "pypi_project.json",
        "osv_query.json",
        "github_tags.json",
        "github_releases.json",
        "changelog.rst",
        "commits/c3d4e5f6789012345678901234567890abcdef12.json",
    )
    for relative in required:
        assert (fixture_root / relative).is_file()
