# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every plugin that sends data off the host is the operator's to configure, not a client's.

A plugin that sends the repository's content, its findings or its dependency list off
the host does so with the operator's credentials, network and trust. An MCP client's
runtime overrides must not configure, enable or disable one, or change what it sends or
where, whatever a profile's ``denied_paths`` says. So each such plugin's whole section
is in ``ALWAYS_DENIED_PATHS`` (``**`` also matches the section itself). A workspace
scan's ``scanners`` and ``excluded_scanners`` arguments, which are not overrides, can
still leave a scanner out of a run, never add one.

This file classifies every scanner, reporter and converter the plugin packages ship.
A new plugin, or a plugin that starts to declare a network, fails here until it is
classified: off the host (and denied), or local, with what it does instead.
"""

from __future__ import annotations

import importlib
import pkgutil
import typing
from typing import Dict, List, Tuple

import pytest
from pydantic import BaseModel

import automated_security_helper.plugin_modules as plugin_packages
from automated_security_helper.config.ash_config import (
    ALWAYS_DENIED_PATHS,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    check_runtime_ops,
)

Plugin = Tuple[str, str]  # (config section, plugin name)

#: What each plugin sends off the host, and where in its code.
OFF_HOST: Dict[Plugin, str] = {
    ("scanners", "snyk-code"): (
        "the source, uploaded for analysis by `snyk code test` "
        "(snyk_code_scanner.py:76)"
    ),
    ("scanners", "npm-audit"): (
        "each package's dependency list, to the registry's advisory service, by "
        "`npm/pnpm/yarn audit` (npm_audit_scanner.py:1309, :1338)"
    ),
    ("scanners", "semgrep"): (
        "usage metrics about the run, to the Semgrep server: `--metrics auto` online "
        "by default and `on` when the option says so (_grep_scanner_base.py:79, "
        ":270; semgrep_scanner.py:60)"
    ),
    ("scanners", "opengrep"): (
        "the same usage metrics, with an opengrep older than 1.7.0, set by its "
        "`metrics` option (opengrep_scanner.py:69, :277)"
    ),
    ("scanners", "trivy-repo"): (
        "dependency identifiers, in the API requests trivy makes to identify "
        "dependencies, unless `--offline-scan` is passed, which is only offline "
        "(trivy_repo_scanner.py:328); and usage data to Aqua when "
        "`disable_telemetry` is false (trivy_repo_scanner.py:140, :294)"
    ),
    ("scanners", "detect-secrets"): (
        "each candidate secret, to the service that issued it, when the "
        "verification filter is configured (detect_secrets_scanner.py:245-268)"
    ),
    ("reporters", "s3"): "the results, to an S3 bucket (s3_reporter.py:230, :305)",
    ("reporters", "aws-security-hub"): (
        "requests to Security Hub and STS with the operator's credentials "
        "(security_hub_reporter.py:122-128)"
    ),
    ("reporters", "cloudwatch-logs"): (
        "the results, to a CloudWatch Logs group (cloudwatch_logs_reporter.py:209, "
        ":284)"
    ),
    ("reporters", "bedrock-summary-reporter"): (
        "findings, to a Bedrock model for a summary "
        "(bedrock_summary_reporter.py:1254; bedrock_pipeline.py:137)"
    ),
}

#: Plugins that send nothing off the host, and what network they use, if any.
LOCAL: Dict[Plugin, str] = {
    ("scanners", "bandit"): "reads the files",
    ("scanners", "cdk-nag"): "evaluates the templates in a local child",
    ("scanners", "cfn-nag"): "reads the templates",
    ("scanners", "checkov"): (
        "fetches its policies online (checkov_scanner.py:224); sends nothing "
        "about the repository"
    ),
    ("scanners", "grype"): (
        "fetches its vulnerability database online (grype_scanner.py:102, :149); "
        "matches locally"
    ),
    ("scanners", "syft"): (
        "checks for updates online (syft_scanner.py:71); catalogs locally"
    ),
    ("scanners", "ferret-scan"): "reads the files (ferret_scanner.py:412, :548)",
    ("reporters", "csv"): "writes a file",
    ("reporters", "cyclonedx"): "writes a file",
    ("reporters", "flat-json"): "writes a file",
    ("reporters", "github-ghas"): "writes a file; a pipeline step may upload it",
    ("reporters", "gitlab-cyclonedx"): "writes a file",
    ("reporters", "gitlab-sast"): "writes a file",
    ("reporters", "html"): "writes a file",
    ("reporters", "junitxml"): "writes a file",
    ("reporters", "markdown"): "writes a file",
    ("reporters", "ocsf"): "writes a file",
    ("reporters", "sarif"): "writes a file",
    ("reporters", "spdx"): "writes a file",
    ("reporters", "text"): "writes a file",
    ("reporters", "unused-suppressions"): "writes a file",
    ("reporters", "yaml"): "writes a file",
    ("converters", "archive"): "extracts archives in the work directory",
    ("converters", "jupyter"): (
        "converts notebooks with nbconvert, which it installs from the package "
        "index when missing"
    ),
}

#: Local plugins that still declare a network, for what they fetch (see LOCAL).
FETCH_ONLY = {("scanners", "grype")}

_KINDS = {
    "ASH_SCANNERS": "scanners",
    "ASH_REPORTERS": "reporters",
    "ASH_CONVERTERS": "converters",
}


def _config_name(plugin_class) -> str:
    annotation = plugin_class.model_fields["config"].annotation
    for candidate in (annotation, *typing.get_args(annotation)):
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            return candidate().name
    raise AssertionError(f"{plugin_class.__name__} has no config model")


def _shipped_plugins() -> Dict[Plugin, type]:
    """Every plugin each package under plugin_modules declares."""
    found: Dict[Plugin, type] = {}
    for package in pkgutil.iter_modules(plugin_packages.__path__):
        if not package.ispkg:
            continue
        module = importlib.import_module(f"{plugin_packages.__name__}.{package.name}")
        for attribute, section in _KINDS.items():
            for plugin_class in getattr(module, attribute, None) or []:
                found[(section, _config_name(plugin_class))] = plugin_class
    return found


def test_the_inventory_finds_the_plugin_packages():
    """Control: the walk reaches every package, built-in and add-on."""
    names = {name for _, name in _shipped_plugins()}
    assert {"bandit", "snyk-code", "trivy-repo", "ferret-scan", "s3"} <= names


def test_every_shipped_plugin_is_classified():
    shipped = set(_shipped_plugins())
    assert not set(OFF_HOST) & set(LOCAL)
    unclassified = sorted(shipped - set(OFF_HOST) - set(LOCAL))
    assert unclassified == [], (
        f"classify each as OFF_HOST (and deny it) or LOCAL: {unclassified}"
    )
    assert sorted(set(OFF_HOST) | set(LOCAL)) == sorted(shipped), "stale entries"


def test_a_local_plugin_that_declares_a_network_says_what_it_fetches():
    for plugin, plugin_class in _shipped_plugins().items():
        requirements = getattr(plugin_class, "sandbox_requirements", None)
        if plugin in LOCAL and getattr(requirements, "network", False) is True:
            assert plugin in FETCH_ONLY, plugin


def test_every_off_host_plugin_is_always_denied():
    missing = [
        f"/{section}/{name}/**"
        for section, name in sorted(OFF_HOST)
        if f"/{section}/{name}/**" not in ALWAYS_DENIED_PATHS
    ]
    assert missing == [], missing


@pytest.mark.parametrize("plugin", sorted(OFF_HOST), ids=lambda p: "/".join(p))
def test_no_profile_lets_a_client_configure_an_off_host_plugin(plugin):
    section, name = plugin
    policy = RuntimeOverridesConfig(
        enabled=True, allowed_paths=["/**"], denied_paths=[]
    )

    for path, value in (
        (f"/{section}/{name}", {"enabled": True, "options": {}}),
        (f"/{section}/{name}/enabled", False),
        (f"/{section}/{name}/options/anything", "else"),
    ):
        with pytest.raises(RuntimePatchDeniedError):
            check_runtime_ops(
                [{"op": "add", "path": path, "value": value}], allowlist=policy
            )


def test_control_a_local_plugin_stays_tunable():
    policy = RuntimeOverridesConfig(
        enabled=True, allowed_paths=["/**"], denied_paths=[]
    )

    ops: List[dict] = [
        {
            "op": "replace",
            "path": "/scanners/bandit/options/severity_threshold",
            "value": "HIGH",
        }
    ]
    check_runtime_ops(ops, allowlist=policy)
