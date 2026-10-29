# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every reader of the chain a scan loads takes what the scan's own load takes.

The scan loads the ASH_CONFIG chain with the repository's confinement and the
operator's ownership. Three other surfaces read the same chain: config
validate's ASH_CONFIG check (``config_validator``), MCP ``get_config``'s
pre-check of a named file, and MCP ``get_config``'s search read when the
searched directory has no config file. Each must load with the same
confinement and ownership, or it refuses, with exit 3, a chain the scan
itself takes: a repository file writing a case-variant twin of the operator's
reporter section makes the operator's deep patch ambiguous to an
ownership-less fold.

The last cell pins the ownership compare's join rule: deep_merge joins an
incoming key onto an existing key that is its uniform "-"/"_" swap, so the
operator's write can end up standing under the repository's spelling, and the
compare has to read that key as carrying the operator's write.

Premises raise RuntimeError, so only the behavior under test fails a cell.
"""

import pytest
import yaml

from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
)
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

_REFUSED = (ASHConfigSourceError, ASHConfigValidationError)


def _write(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _section(key, enabled, region):
    return {key: {"enabled": enabled, "options": {"aws_region": region}}}


_PATCH = {
    "op": "replace",
    "path": "/reporters/AWS_Security_Hub/options/aws_region",
    "value": "us-west-2",
}


def _env_chain(tmp_path, monkeypatch, twin):
    """ASH_CONFIG names an operator root outside the checkout. It extends the
    operator's own section file and, with *twin*, a repository file writing a
    case-variant twin; it patches under a third spelling."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    own = _write(
        tmp_path / "ops" / "own.yaml",
        {"reporters": _section("aws-security-hub", True, "us-east-1")},
    )
    bases = [own]
    if twin:
        bases.append(
            _write(
                src / ".ash" / "twin.yaml",
                {"reporters": _section("AwsSecurityHub", False, "repo-r0")},
            )
        )
    root = _write(
        tmp_path / "env-root.yaml",
        {
            "project_name": "env",
            "extends": [b.as_posix() for b in bases],
            "patch": [_PATCH],
        },
    )
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    return src


def _checked(src):
    return _write(src / ".ash" / ".ash.yaml", {"project_name": "checked"})


def _scan_takes_it(src, checked):
    try:
        resolve_config(config_path=checked, source_dir=src)
    except _REFUSED as error:
        raise RuntimeError(
            "the scan's own load refuses, so the cell shows nothing: "
            + type(error).__name__
        )


def _validator_errors(tmp_path, monkeypatch, twin):
    from automated_security_helper.config.config_validator import ConfigValidator

    src = _env_chain(tmp_path, monkeypatch, twin=twin)
    checked = _checked(src)
    _scan_takes_it(src, checked)
    return ConfigValidator.check_config_file(checked, source_dir=src).errors


def test_config_validate_s_ash_config_check_takes_the_chain_the_scan_takes(
    tmp_path, monkeypatch
):
    errors = _validator_errors(tmp_path, monkeypatch, twin=True)
    assert errors == [], [e[:160] for e in errors]


def test_control_without_the_twin_validate_reports_nothing(tmp_path, monkeypatch):
    errors = _validator_errors(tmp_path, monkeypatch, twin=False)
    assert errors == [], [e[:160] for e in errors]


def _get_config_answer(tmp_path, monkeypatch, twin):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    src = _env_chain(tmp_path, monkeypatch, twin=twin)
    checked = _checked(src)
    _scan_takes_it(src, checked)
    return mcp_get_config(config_path=str(checked))


def test_mcp_get_config_s_pre_check_takes_the_chain_the_scan_takes(
    tmp_path, monkeypatch
):
    answer = _get_config_answer(tmp_path, monkeypatch, twin=True)
    assert answer.get("project_name") == "checked", {
        k: str(v)[:120] for k, v in answer.items()
    }


def test_control_without_the_twin_get_config_answers(tmp_path, monkeypatch):
    answer = _get_config_answer(tmp_path, monkeypatch, twin=False)
    assert answer.get("project_name") == "checked", {
        k: str(v)[:120] for k, v in answer.items()
    }


@pytest.mark.parametrize("twin", [True, False], ids=["twin", "no-twin"])
def test_mcp_get_config_s_search_read_takes_the_chain_the_scan_takes(
    tmp_path, monkeypatch, twin
):
    """With no config file in the searched directory, get_config loads the
    ASH_CONFIG chain itself. Beside a repository twin it must answer what the
    scan's own load of that directory answers."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    src = _env_chain(tmp_path, monkeypatch, twin=twin)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    try:
        resolve_config(source_dir=src)
    except _REFUSED as error:
        raise RuntimeError(
            "the scan's own load refuses, so the cell shows nothing: "
            + type(error).__name__
        )
    answer = mcp_get_config(search_dir=str(src))
    assert answer.get("project_name") == "env", {
        k: str(v)[:160] for k, v in answer.items()
    }


def test_an_operator_key_joined_under_the_repository_s_swap_spelling_is_owned(
    tmp_path, monkeypatch
):
    """The repository file comes first and spells the section as the whole
    "-"/"_" swap of the operator's, so deep_merge joins the operator's write
    under the repository's spelling. The ownership compare's swap arm is what
    still finds that key owned, so the operator's patch lands and the reporter
    runs it."""
    from automated_security_helper.config.operator_only_options import (
        _reporter_section_of,
        reporter_section,
    )
    from automated_security_helper.config.plugin_section_names import (
        folded_section_name,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = _write(
        checkout / ".ash" / ".ash.yaml",
        {
            "project_name": "repository",
            "reporters": _section("aws_security_hub", False, "repo-r0"),
        },
    )
    own = _write(
        tmp_path / "own.yaml",
        {"reporters": _section("aws-security-hub", True, "us-east-1")},
    )
    root = _write(
        tmp_path / "operator.yaml",
        {
            "extends": [repository.as_posix(), own.as_posix()],
            "patch": [
                {
                    "op": "replace",
                    "path": "/reporters/AwsSecurityHub/options/aws_region",
                    "value": "us-west-2",
                }
            ],
        },
    )
    config = resolve_config(config_path=root, source_dir=checkout)
    reporters = config.model_dump().get("reporters") or {}
    hub_fold = folded_section_name("aws-security-hub")
    hubs = sorted(
        key
        for key in reporters
        if isinstance(key, str) and folded_section_name(key) == hub_fold
    )
    if hubs != ["aws_security_hub"]:
        raise RuntimeError(
            "deep_merge did not join the operator's write under the "
            "repository's spelling: " + str(hubs)
        )
    key = plugin_config_key(SecurityHubReporter)
    shown = _reporter_section_of(config, key)
    ran = reporter_section(config, SecurityHubReporter)

    def _plain(section):
        if section is None:
            return {}
        if hasattr(section, "model_dump"):
            return section.model_dump()
        return dict(section)

    ran_options = _plain(ran).get("options") or {}
    assert (ran_options.get("aws_region"), _plain(ran).get("enabled")) == (
        "us-west-2",
        True,
    ), (_plain(shown), _plain(ran))
