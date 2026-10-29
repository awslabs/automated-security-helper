# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reporters that send findings off the host come from a file outside every checkout.

An operator file in a git checkout other than the scanned one grants nothing
(``sandbox_grants``), and the reporters that send findings off the host with the
host's credentials are held to the same rule: whether one runs and where it
sends comes from ``--config-overrides`` or a file outside every checkout. Two
routes reach that rule, and each says so in one warning that names the file and
ends with the remedy every confinement warning ends with:

* the file is the workspace's trusted config (``trusted_config_path``), which the
  project's own config is resolved against; the resolved configuration never held
  its reporters, so nothing said they were dropped;
* the file is the selected ``--config`` or the file ``ASH_CONFIG`` names, whose
  reporters reach ``reporter_section`` as the repository's, and the warning there
  blamed "the scanned repository" and a config file "outside the tree".

A workspace overlay in another checkout is accepted and layered, as it is today:
its fields are final, and what it grants is what any file in another checkout
grants, nothing. The overlay cells pin that one answer (they read the same before
and after) so the refusal check and the trusted-base check cannot drift apart.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.config.operator_only_options import (
    record_operator_reporters,
    reporter_section,
)
from automated_security_helper.config.resolve_config import (
    check_operator_config,
    resolve_config,
)
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

#: The sentence a warning explains the drop of a file outside the scanned trees with.
OUTSIDE_SENTENCE = (
    "the file is inside the scanned tree or a git checkout, or an MCP client "
    "delivered it, so someone other than the operator may have written it"
)

#: The old claim, false for a file in another checkout.
STALE_CLAIM = "the scanned repository could write the file"

S3_SECTION = (
    "reporters:\n"
    "  s3:\n"
    "    enabled: true\n"
    "    options:\n"
    "      bucket_name: operator-bucket\n"
)


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _repository(tmp_path: Path, config: str) -> Path:
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    _write(repository / ".ash" / ".ash.yaml", config)
    return repository


def _warnings(caplog: pytest.LogCaptureFixture, start: str) -> List[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING and record.getMessage().startswith(start)
    ]


def _enabled(config: AshConfig, reporter: str) -> object:
    section = config.get_plugin_config(plugin_type="reporter", plugin_name=reporter)
    return (section or {}).get("enabled")


def test_the_trusted_file_in_another_checkout_loses_its_off_host_reporter_with_a_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    repository = _repository(tmp_path, "project_name: repo\n")
    mark_git_checkout(tmp_path / "ops")
    trusted = _write(tmp_path / "ops" / "ash.yaml", S3_SECTION)

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=repository, trusted_config_path=trusted)

    assert _enabled(config, "s3") is not True
    named = _warnings(caplog, "Ignoring reporters.s3 from ")
    assert len(named) == 1, caplog.text
    assert "/ops/ash.yaml" in named[0], named[0]
    assert OUTSIDE_SENTENCE in named[0], named[0]
    assert "findings off the host" in named[0], named[0]
    assert named[0].endswith(KEEP_A_SETTING), named[0]
    assert STALE_CLAIM not in named[0], named[0]


def test_control_the_trusted_file_outside_every_checkout_keeps_its_reporter_without_a_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    repository = _repository(tmp_path, "project_name: repo\n")
    trusted = _write(tmp_path / "plain" / "ash.yaml", S3_SECTION)

    with caplog.at_level(logging.WARNING):
        resolve_config(source_dir=repository, trusted_config_path=trusted)

    assert not _warnings(caplog, "Ignoring reporters.s3"), caplog.text


def test_the_trusted_file_in_another_checkout_names_only_the_off_host_sections(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A reporter that writes only local files keeps being the file's to set;
    the warning names the one that sends findings off the host and no other."""
    repository = _repository(tmp_path, "project_name: repo\n")
    mark_git_checkout(tmp_path / "ops")
    trusted = _write(
        tmp_path / "ops" / "ash.yaml",
        S3_SECTION + "  html:\n    enabled: false\n",
    )

    with caplog.at_level(logging.WARNING):
        resolve_config(source_dir=repository, trusted_config_path=trusted)

    [warning] = _warnings(caplog, "Ignoring reporters.")
    assert warning.startswith("Ignoring reporters.s3 from "), warning
    assert "reporters.html" not in warning, warning


def test_reporter_section_names_the_file_and_makes_no_false_claim(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The reporter's own warning, driven through the record the load makes of
    the files that are not the operator's. The record carries no membership
    here, which is the shape of an older caller: the sentence is the one every
    other voice gives for a file outside the trees."""
    from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
        SecurityHubReporter,
    )

    config = AshConfig.model_validate(
        {
            "reporters": {
                "aws-security-hub": {
                    "enabled": True,
                    "options": {"aws_profile": "ops-profile"},
                }
            }
        }
    )
    ops_file = tmp_path / "ops" / "ash.yaml"
    record_operator_reporters(config, AshConfig(), [ops_file])

    with caplog.at_level(logging.WARNING):
        reporter_section(config, SecurityHubReporter)

    [warning] = _warnings(caplog, "Ignoring reporters.aws-security-hub from ")
    assert "/ops/ash.yaml" in warning, warning
    assert STALE_CLAIM not in warning, warning
    assert "outside the tree" not in warning, warning
    assert "findings off the host" in warning, warning
    assert warning.endswith(KEEP_A_SETTING), warning


def test_the_load_records_why_the_file_is_not_the_operators(tmp_path: Path) -> None:
    """A selected --config in another checkout: the configuration carries the
    sentence the settle warning gives, so the reporter's warning says the same."""
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    mark_git_checkout(tmp_path / "ops")
    selected = _write(tmp_path / "ops" / "ash.yaml", S3_SECTION)

    config = resolve_config(config_path=selected, source_dir=repository)

    assert OUTSIDE_SENTENCE in (config._repository_config_membership or "")


def test_a_section_the_operators_own_file_writes_is_named_when_its_chain_is_dropped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """``trusted_base_config`` drops the WHOLE trusted chain when any file of it
    sits in a checkout: the operator's own file, outside every checkout, writes
    the S3 section and extends a base kept in an ops checkout. The section is
    lost with the chain, so the warning names it, with the file that wrote it
    and the file that put the chain under the rule."""
    repository = _repository(tmp_path, "project_name: repo\n")
    mark_git_checkout(tmp_path / "ops")
    _write(tmp_path / "ops" / "base.yaml", "project_name: base\n")
    trusted = _write(
        tmp_path / "ash.yaml", "extends:\n  - ops/base.yaml\n" + S3_SECTION
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=repository, trusted_config_path=trusted)

    assert _enabled(config, "s3") is not True
    [warning] = _warnings(caplog, "Ignoring reporters.s3 from ")
    assert "/ash.yaml" in warning, warning
    assert "/ops/base.yaml" in warning, warning
    assert OUTSIDE_SENTENCE in warning, warning
    assert warning.endswith(KEEP_A_SETTING), warning


def test_the_operators_own_file_is_not_put_under_the_membership_sentence(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The membership sentence is true of the base in the checkout and false of
    the operator's own file outside every checkout. The warning says it of the
    base alone, and names the operator's file in a clause of its own."""
    repository = _repository(tmp_path, "project_name: repo\n")
    mark_git_checkout(tmp_path / "ops")
    _write(tmp_path / "ops" / "base.yaml", "project_name: base\n")
    trusted = _write(
        tmp_path / "ash.yaml", "extends:\n  - ops/base.yaml\n" + S3_SECTION
    )

    with caplog.at_level(logging.WARNING):
        resolve_config(source_dir=repository, trusted_config_path=trusted)

    [warning] = _warnings(caplog, "Ignoring reporters.s3 from ")
    before, found, after = warning.partition(OUTSIDE_SENTENCE)
    assert found, warning
    subject = before.rsplit(": ", 1)[-1]
    assert "/ops/base.yaml" in subject, warning
    assert "/ash.yaml" not in subject, warning
    assert "/ash.yaml" in after, warning
    assert warning.endswith(KEEP_A_SETTING), warning


def test_control_a_trusted_chain_wholly_outside_every_checkout_warns_of_nothing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    repository = _repository(tmp_path, "project_name: repo\n")
    _write(tmp_path / "plain" / "base.yaml", "project_name: base\n")
    trusted = _write(
        tmp_path / "plain" / "ash.yaml", "extends:\n  - base.yaml\n" + S3_SECTION
    )

    with caplog.at_level(logging.WARNING):
        resolve_config(source_dir=repository, trusted_config_path=trusted)

    assert not _warnings(caplog, "Ignoring reporters."), caplog.text


def test_the_dropped_section_warning_claims_no_scanned_tree_on_a_load_without_one(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A root given but declared not scanned: the sentence names the checkout
    and the delivered file, and no scanned tree."""
    repository = _repository(tmp_path, "project_name: repo\n")
    mark_git_checkout(tmp_path / "ops")
    trusted = _write(tmp_path / "ops" / "ash.yaml", S3_SECTION)

    with caplog.at_level(logging.WARNING):
        resolve_config(
            source_dir=repository,
            scanned_root=repository,
            trusted_config_path=trusted,
            no_scanned_tree=True,
        )

    [warning] = _warnings(caplog, "Ignoring reporters.s3 from ")
    assert "the file is inside a git checkout, or an MCP client delivered it" in warning
    assert "scanned tree" not in warning, warning


def test_the_dropped_section_warning_of_a_rootless_load_claims_no_scanned_tree(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """No tree is known at all (the working directory is gone): the warning is
    built from the load's wording flag, as the sandbox and settle warnings are."""
    from automated_security_helper.config.resolve_config import (
        _load_operator_config,
        _warn_dropped_operator_reporters,
    )

    mark_git_checkout(tmp_path / "ops")
    trusted = _write(tmp_path / "ops" / "ash.yaml", S3_SECTION)
    operator = _load_operator_config(trusted, None, None)

    with caplog.at_level(logging.WARNING):
        _warn_dropped_operator_reporters(
            operator, [], [], given_root_membership=False, rootless_wording=True
        )

    [warning] = _warnings(caplog, "Ignoring reporters.s3 from ")
    assert "the file is inside a git checkout, or an MCP client delivered it" in warning
    assert "scanned tree" not in warning, warning


def test_reporter_section_claims_no_scanned_tree_on_a_load_without_one(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The membership the record carries comes from the load's wording flags,
    so the reporter's own warning never claims a tree the load does not have."""
    from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
        SecurityHubReporter,
    )

    config = AshConfig.model_validate(
        {
            "reporters": {
                "aws-security-hub": {
                    "enabled": True,
                    "options": {"aws_profile": "ops-profile"},
                }
            }
        }
    )
    ops_file = tmp_path / "ops" / "ash.yaml"
    record_operator_reporters(config, AshConfig(), [ops_file], rootless_wording=True)

    with caplog.at_level(logging.WARNING):
        reporter_section(config, SecurityHubReporter)

    [warning] = _warnings(caplog, "Ignoring reporters.aws-security-hub from ")
    assert "the file is inside a git checkout, or an MCP client delivered it" in warning
    assert "scanned tree" not in warning, warning


def test_an_overlay_in_another_checkout_is_accepted_and_grants_nothing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Workspace mode passes the operator's --config as the overlay and as the
    trusted config. In another checkout it is not refused (the refusal judges
    the scanned trees and delivery), and the trusted-base check agrees about
    what it is: a file whose fields are final but which grants nothing. The one
    warning names it, with the sentence for a file outside the trees."""
    repository = _repository(tmp_path, "fail_on_findings: false\n")
    mark_git_checkout(tmp_path / "ops")
    overlay = _write(
        tmp_path / "ops" / "ash.yaml",
        "fail_on_findings: true\nsandbox:\n  extra_read_paths:\n    - /opt/ops-grant\n",
    )

    check_operator_config(overlay, repository)
    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=repository / ".ash" / ".ash.yaml",
            source_dir=repository,
            scanned_root=repository,
            trusted_config_path=overlay,
            overlay_config_path=overlay,
        )

    assert config.fail_on_findings is True
    assert config.sandbox.extra_read_paths == []
    [warning] = _warnings(caplog, "Ignoring sandbox.extra_read_paths")
    assert "/ops/ash.yaml" in warning, warning
    assert OUTSIDE_SENTENCE in warning, warning
