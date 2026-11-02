# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""With the working directory deleted, every checkout write stays untrusted.

resolve_config with no scanned_root, no source_dir and the working directory
deleted (the no-root branch). A named checkout file, a chain whose middle file
sits in a checkout, and an ASH_CONFIG checkout file each plant an off-host
reporter section, two operator-only reporter options, detect-secrets' output
limit and two sandbox grants. Under the fail-closed reading every checkout
file is the repository's, so none of those writes may apply -- the in-tree
membership that drives the confine steps (off-host section and sandbox grants
included) runs on the any-checkout rule instead of an empty tree list
returning early. Each deleted-cwd scenario has a live-cwd control confining
the same files, so a cell here can only fail by the two paths diverging.
"""

import logging
import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.operator_only_options import reporter_section
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.config.sandbox_grants import scanned_trees
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
)
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

# The rule the module-location checks below cite, quoted once from the trust
# model's ``ash_plugin_modules`` row (docs/content/concepts/trust-model.md, the
# "What each tier may set" table). The docstrings name this constant instead
# of a line number, which moves with every edit of that page.
_CHECKOUT_RULE = (
    "Only ASH's own plugin modules and modules installed outside every git "
    "checkout and the scanned directory. A third-party package in a virtual "
    "environment inside a checkout counts as inside it."
)


def test_the_quoted_checkout_rule_is_the_trust_models_own_sentence():
    """The docstrings below quote the rule rather than cite a line number, and a
    copied sentence goes stale as silently as a number moves, so the page is
    read: the sentence is still there, in the ``ash_plugin_modules`` row."""
    page = (
        Path(__file__).resolve().parents[3]
        / "docs"
        / "content"
        / "concepts"
        / "trust-model.md"
    )

    assert _CHECKOUT_RULE in page.read_text(encoding="utf-8"), page


def test_no_scan_root_is_no_scanned_tree():
    """The premise the no-root branch rests on, measured: scanned_trees(None)
    answers no tree at all, never a default such as the process's cwd."""
    assert scanned_trees(None) == []


def test_a_none_root_leaves_only_the_client_supplied_arm(tmp_path):
    """in_scanned_tree with a None scan root cannot see any checkout: it
    answers False for a path inside one, since scanned_trees(None) is no tree
    and only the client-supplied arm remains. The any-checkout arm that
    closes this for no-root loads lives in refusal_reason, pinned below."""
    from automated_security_helper.config.path_trust import in_scanned_tree

    checkout = tmp_path / "arm-checkout"
    mark_git_checkout(checkout)
    inside = checkout / "somefile.py"
    inside.write_text("VALUE = 1\n", encoding="utf-8")

    assert in_scanned_tree(inside, None) is False


def test_a_config_named_through_a_checkout_symlink_is_confined_with_no_cwd(
    tmp_path, monkeypatch
):
    """A config NAMED by a link that sits in a checkout but resolves outside
    every checkout: the checkout chose where the link points, so under the
    no-tree membership the resolved file is the repository's (the reached
    arm) and its writes are confined, exactly as files_inside judges a named
    entry with a live tree."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "base.yaml"
    target.write_text("project_name: linked\n" + _PLANTED, encoding="utf-8")
    checkout = tmp_path / "link-checkout"
    mark_git_checkout(checkout)
    link = checkout / "link.yaml"
    # The cwd deletion (and its win32 skip) comes BEFORE the symlink: Windows
    # without symlink privilege raises OSError here, which must be the skip's
    # problem to prevent, not a failure before the skip is reached.
    _delete_cwd(tmp_path, monkeypatch)
    link.symlink_to(target)

    config = resolve_config(config_path=link)

    assert config.project_name == "linked"
    assert not _APPLIED["offhost-enabled"](config), _section(config)
    assert not _APPLIED["sandbox-network"](config), config.sandbox.network_scanners


def _delete_cwd(tmp_path, monkeypatch):
    # os.rmdir of the process's working directory is PermissionError on
    # Windows, so every deleted-cwd cell skips there through this one
    # helper, as the operator-limit file's deleted-cwd cells skip.
    if sys.platform == "win32":
        pytest.skip("the working directory cannot be removed on Windows")
    launched = tmp_path / "launched-here"
    launched.mkdir()
    monkeypatch.chdir(launched)
    os.rmdir(launched)
    with pytest.raises(FileNotFoundError):
        Path.cwd()


def _section(config):
    return reporter_section(config, SecurityHubReporter) or {}


def _options(config):
    return _section(config).get("options") or {}


def _limit(config):
    section = (
        config.get_plugin_config(plugin_type="scanner", plugin_name="detect-secrets")
        or {}
    )
    return (section.get("options") or {}).get("max_worker_output_mib")


_PLANTED = (
    "reporters:\n"
    "  aws-security-hub:\n"
    "    enabled: true\n"
    "    options:\n"
    "      aws_region: repo-region\n"
    "      findings_scope: repo-scope\n"
    "      archive_resolved_findings: true\n"
    "scanners:\n"
    "  detect-secrets:\n"
    "    options:\n"
    "      max_worker_output_mib: 1024\n"
    "sandbox:\n"
    "  network_scanners:\n"
    "    - bandit\n"
    "  extra_read_paths:\n"
    "    - /repo-read\n"
)

#: Each place: whether the planted checkout write applied in *config*.
_APPLIED = {
    "offhost-enabled": lambda c: _section(c).get("enabled") is True,
    "offhost-region": lambda c: _options(c).get("aws_region") == "repo-region",
    "operator-only-scope": lambda c: _options(c).get("findings_scope") == "repo-scope",
    "operator-only-archive": lambda c: (
        _options(c).get("archive_resolved_findings") is True
    ),
    "scanner-limit": lambda c: _limit(c) == 1024,
    "sandbox-network": lambda c: c.sandbox.network_scanners == ["bandit"],
    "sandbox-read-path": lambda c: "/repo-read" in list(c.sandbox.extra_read_paths),
}


def _named_checkout_file(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "named-checkout"
    mark_git_checkout(checkout)
    named = checkout / ".ash" / ".ash.yaml"
    named.parent.mkdir(parents=True, exist_ok=True)
    named.write_text("project_name: named\n" + _PLANTED, encoding="utf-8")
    return checkout, named


@pytest.mark.parametrize("place", list(_APPLIED))
def test_a_named_checkout_file_writes_nothing_trusted_with_no_cwd(
    tmp_path, monkeypatch, place
):
    _checkout, named = _named_checkout_file(tmp_path, monkeypatch)
    _delete_cwd(tmp_path, monkeypatch)
    config = resolve_config(config_path=named)
    assert config.project_name == "named"
    assert not _APPLIED[place](config), place


@pytest.mark.parametrize("place", list(_APPLIED))
def test_control_a_live_cwd_inside_the_checkout_confines_the_named_file(
    tmp_path, monkeypatch, place
):
    checkout, named = _named_checkout_file(tmp_path, monkeypatch)
    monkeypatch.chdir(checkout)
    config = resolve_config(config_path=named)
    assert config.project_name == "named"
    assert not _APPLIED[place](config), place


def _chain_through_a_checkout(tmp_path, monkeypatch):
    """operator.yaml (outside every checkout) extends checkout/.ash/.ash.yaml,
    which extends outside/base.yaml (outside every checkout) holding the
    planted writes: the base is reached THROUGH a repository file."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    outside = tmp_path / "outside"
    outside.mkdir()
    base = outside / "base.yaml"
    base.write_text("project_name: base\n" + _PLANTED, encoding="utf-8")
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    middle = checkout / ".ash" / ".ash.yaml"
    middle.parent.mkdir(parents=True, exist_ok=True)
    middle.write_text(f"extends: {base.as_posix()}\n", encoding="utf-8")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"project_name: operator\nextends: {middle.as_posix()}\n", encoding="utf-8"
    )
    return checkout, operator


@pytest.mark.parametrize("place", list(_APPLIED))
def test_a_base_reached_through_a_checkout_file_writes_nothing_trusted_with_no_cwd(
    tmp_path, monkeypatch, place
):
    _checkout, operator = _chain_through_a_checkout(tmp_path, monkeypatch)
    _delete_cwd(tmp_path, monkeypatch)
    config = resolve_config(config_path=operator)
    assert config.project_name == "operator"
    assert not _APPLIED[place](config), place


@pytest.mark.parametrize("place", list(_APPLIED))
def test_control_with_a_source_dir_the_base_reached_through_the_checkout_is_confined(
    tmp_path, monkeypatch, place
):
    checkout, operator = _chain_through_a_checkout(tmp_path, monkeypatch)
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.chdir(plain)
    config = resolve_config(config_path=operator, source_dir=checkout)
    assert config.project_name == "operator"
    assert not _APPLIED[place](config), place


def _ash_config_checkout_file(tmp_path, monkeypatch):
    checkout = tmp_path / "env-checkout"
    mark_git_checkout(checkout)
    env_cfg = checkout / ".ash" / ".ash.yaml"
    env_cfg.parent.mkdir(parents=True, exist_ok=True)
    env_cfg.write_text("project_name: env\n" + _PLANTED, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(env_cfg))
    return checkout


@pytest.mark.parametrize("place", list(_APPLIED))
def test_an_ash_config_checkout_file_writes_nothing_trusted_with_no_cwd(
    tmp_path, monkeypatch, place
):
    _ash_config_checkout_file(tmp_path, monkeypatch)
    _delete_cwd(tmp_path, monkeypatch)
    config = resolve_config()
    assert config.project_name == "env"
    assert not _APPLIED[place](config), place


@pytest.mark.parametrize("place", list(_APPLIED))
def test_control_a_live_cwd_inside_the_ash_config_checkout_confines_it(
    tmp_path, monkeypatch, place
):
    checkout = _ash_config_checkout_file(tmp_path, monkeypatch)
    monkeypatch.chdir(checkout)
    config = resolve_config()
    assert config.project_name == "env"
    assert not _APPLIED[place](config), place


def test_the_no_tree_settle_warnings_speak_the_checkout_rule(
    tmp_path, monkeypatch, caplog
):
    """With no working directory and only ASH_CONFIG set, the settle warnings
    explain the drop by the rule that made it: the file is in a checkout read
    as the scanned tree -- there is no scanned tree for the old wording to
    point at. The same keying the plugin-module drop warning carries."""
    _ash_config_checkout_file(tmp_path, monkeypatch)
    _delete_cwd(tmp_path, monkeypatch)

    with caplog.at_level(logging.WARNING):
        resolve_config()

    # The warnings that explain their drop by the membership sentence: the
    # operator-only settle warnings (the scanner option, the reporter options)
    # and the sandbox grants warning. The reporter destination warning is left
    # out: it states the same rule in its own words ("inside a git checkout or
    # the scanned tree, or was delivered by an MCP client") and names other
    # places (aws_region, enabled).
    membership_voices = (
        "sandbox.",
        "max_worker_output_mib",
        "findings_scope",
        "archive_resolved_findings",
    )
    ignoring = [
        message
        for message in (record.getMessage() for record in caplog.records)
        if "Ignoring" in message and any(word in message for word in membership_voices)
    ]
    assert len(ignoring) >= 3, ignoring
    assert all("in a checkout" in line for line in ignoring), ignoring
    assert not [line for line in ignoring if "is inside the scanned tree" in line], (
        ignoring
    )


def test_each_no_tree_place_is_warned_exactly_once(tmp_path, monkeypatch, caplog):
    """The dedup pin: in the no-config no-tree shape the settle step is the one
    voice, so each left-out option place appears in exactly one warning -- the
    fail-closed ASH_CONFIG warning stays quiet where the settle step speaks,
    and a regression that lets both fire names a place twice."""
    _ash_config_checkout_file(tmp_path, monkeypatch)
    _delete_cwd(tmp_path, monkeypatch)

    with caplog.at_level(logging.WARNING):
        resolve_config()

    messages = [record.getMessage() for record in caplog.records]
    for place in ("max_worker_output_mib", "findings_scope"):
        naming = [line for line in messages if place in line]
        assert len(naming) == 1, (place, naming)


def test_the_selected_config_path_warns_fail_closed_exactly_once(
    tmp_path, monkeypatch, caplog
):
    """The fail-closed voice's one live path: a selected config whose own
    chain settles the trust, beside an ASH_CONFIG checkout file read
    fail-closed. Exactly one fail-closed warning, and its wording names the
    rule (no scanned tree; the chain's files in a checkout), never a place
    the settle step would also name -- the settle step speaks only for the
    selected chain here."""
    _ash_config_checkout_file(tmp_path, monkeypatch)
    named = tmp_path / "operator.yaml"
    named.write_text("project_name: named\n", encoding="utf-8")
    _delete_cwd(tmp_path, monkeypatch)

    with caplog.at_level(logging.WARNING):
        resolve_config(config_path=named)

    fail_closed = [
        record.getMessage()
        for record in caplog.records
        if "read fail-closed" in record.getMessage()
    ]
    assert len(fail_closed) == 1, fail_closed
    assert "With no scanned tree" in fail_closed[0], fail_closed
    assert "in a checkout" in fail_closed[0], fail_closed


def test_the_no_config_path_emits_no_fail_closed_warning(tmp_path, monkeypatch, caplog):
    """The deduped path: with no selected config the settle step is the one
    voice, so the fail-closed warning never fires -- its places would repeat
    what the settle warnings already name (the exactly-once cell above pins
    the per-place count)."""
    _ash_config_checkout_file(tmp_path, monkeypatch)
    _delete_cwd(tmp_path, monkeypatch)

    with caplog.at_level(logging.WARNING):
        resolve_config()

    fail_closed = [
        record.getMessage()
        for record in caplog.records
        if "read fail-closed" in record.getMessage()
    ]
    assert fail_closed == [], fail_closed


def test_an_outside_ash_config_file_warns_nothing_with_no_cwd(
    tmp_path, monkeypatch, caplog
):
    """An ASH_CONFIG file outside every checkout is the operator's own under
    the no-tree rules: nothing is left out, so neither the fail-closed voice
    nor the settle step says anything, and its writes apply."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    outside = tmp_path / "outside"
    outside.mkdir()
    env_cfg = outside / "ash.yaml"
    env_cfg.write_text("project_name: env\n" + _PLANTED, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(env_cfg))
    _delete_cwd(tmp_path, monkeypatch)

    with caplog.at_level(logging.WARNING):
        config = resolve_config()

    assert config.project_name == "env"
    assert _APPLIED["scanner-limit"](config), _limit(config)
    noisy = [
        record.getMessage()
        for record in caplog.records
        if "read fail-closed" in record.getMessage()
        or "Ignoring" in record.getMessage()
    ]
    assert noisy == [], noisy


def test_the_left_out_selected_chain_limit_is_warned_with_no_cwd(
    tmp_path, monkeypatch, caplog
):
    """An operator file outside every checkout whose base in a checkout writes
    the limit, cwd deleted: the base's 1024 is left out, and the leaving-out
    is said, never silent -- the selected chain warns through the same settle
    step a live tree uses, since the fail-closed membership keeps its files
    in the confinement instead of returning before it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    base = checkout / ".ash" / ".ash.yaml"
    base.parent.mkdir(parents=True, exist_ok=True)
    base.write_text(
        "project_name: base\nscanners:\n  detect-secrets:\n    options:\n"
        "      max_worker_output_mib: 1024\n",
        encoding="utf-8",
    )
    named = tmp_path / "operator.yaml"
    named.write_text(f"extends: {base.as_posix()}\n", encoding="utf-8")
    _delete_cwd(tmp_path, monkeypatch)
    with caplog.at_level(logging.DEBUG):
        config = resolve_config(config_path=named)
    # Premise: the value was left out.
    assert _limit(config) == 256, _limit(config)
    said = [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING
        and "max_worker_output_mib" in record.getMessage()
    ]
    assert said, [record.getMessage() for record in caplog.records]


def test_a_client_module_inside_a_checkout_on_sys_path_is_refused_with_no_cwd(
    tmp_path,
    monkeypatch,
):
    """The fail-open the drop rule left: a checkout still on sys.path (an
    editable install of the very repository whose deleted working directory
    was the scan's) holds an importable module; a client-supplied config
    naming it must not get it imported just because no tree says whose
    checkout it is. The load refuses, naming the gone working directory."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "editable-checkout"
    mark_git_checkout(checkout)
    module = checkout / "zz_checkout_mod.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(checkout))
    upload = tmp_path / "upload" / "config.yaml"
    upload.parent.mkdir()
    upload.write_text(
        "project_name: upload\nash_plugin_modules:\n  - zz_checkout_mod\n",
        encoding="utf-8",
    )
    _delete_cwd(tmp_path, monkeypatch)

    with pytest.raises(ASHConfigSourceError) as caught:
        resolve_config(
            config_path=str(upload), untrusted_config=True, fallback_to_default=False
        )
    text = str(caught.value)
    assert "working directory" in text and "zz_checkout_mod" in text, text


def test_a_named_checkout_file_s_checkout_importable_module_drops_with_no_cwd(
    tmp_path, monkeypatch, caplog
):
    """The file-anchored variant of the refusal above: a checkout's own config
    (named with --config, not client content) lists a module importable from
    that same checkout, still on sys.path, with the working directory
    deleted. A live scan of the checkout refuses the module as in-tree; the
    no-tree load must judge it by the any-checkout rule and drop it the same
    way, never keep it because no tree says whose checkout it is."""
    import logging

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "editable-checkout"
    mark_git_checkout(checkout)
    module = checkout / "zz_checkout_mod_ash_plugins.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(checkout))
    named = checkout / ".ash" / ".ash.yaml"
    named.parent.mkdir(parents=True, exist_ok=True)
    named.write_text(
        "project_name: named\nash_plugin_modules:\n  - zz_checkout_mod_ash_plugins\n",
        encoding="utf-8",
    )
    _delete_cwd(tmp_path, monkeypatch)

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=named)

    assert "zz_checkout_mod_ash_plugins" not in (config.ash_plugin_modules or []), (
        config.ash_plugin_modules
    )
    ignoring = [
        record.getMessage()
        for record in caplog.records
        if "Ignoring ash_plugin_modules" in record.getMessage()
    ]
    assert ignoring, [record.getMessage() for record in caplog.records]
    # The warning explains the drop by the rule that made it: with no
    # working directory the file is judged by its checkout, so the
    # scanned-tree wording would contradict the drop it explains. The exact
    # phrase, not a bare "checkout" -- the file's own PATH contains that word
    # here, so the loose check would pass whatever the wording said.
    assert all(
        "is read as the scanned tree" in line and "only installed modules" in line
        for line in ignoring
    ), ignoring
    assert not [line for line in ignoring if "is inside the scanned tree" in line], (
        ignoring
    )


def test_an_ash_config_checkout_file_is_no_trusted_base_with_no_cwd(
    tmp_path, monkeypatch
):
    """The chain branch's half of the ASH_CONFIG rule: with a selected config
    and the working directory deleted, the trusted base the sandbox grants
    come from must be the plain defaults, never the checkout ASH_CONFIG
    file's own writes -- a scan of that checkout uses AshConfig(), and the
    no-tree load may not grant more."""
    checkout = tmp_path / "env-checkout"
    mark_git_checkout(checkout)
    env_cfg = checkout / ".ash" / ".ash.yaml"
    env_cfg.parent.mkdir(parents=True, exist_ok=True)
    env_cfg.write_text("project_name: env\n" + _PLANTED, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(env_cfg))
    named = tmp_path / "operator.yaml"
    named.write_text("project_name: named\n", encoding="utf-8")
    _delete_cwd(tmp_path, monkeypatch)

    config = resolve_config(config_path=named)

    assert config.project_name == "named"
    assert config.sandbox.network_scanners != ["bandit"], (
        config.sandbox.network_scanners
    )
    assert "/repo-read" not in list(config.sandbox.extra_read_paths), (
        config.sandbox.extra_read_paths
    )
    assert not _APPLIED["offhost-enabled"](config), _section(config)


def _profile_and_named_checkout_config(tmp_path, monkeypatch, profile_dir):
    """A selected checkout config plus an operator profile holding a sandbox
    grant, with the profile's file under *profile_dir*."""
    _checkout, named = _named_checkout_file(tmp_path, monkeypatch)
    profile = profile_dir / "operator-profile.yaml"
    profile.parent.mkdir(parents=True, exist_ok=True)
    profile.write_text(
        "project_name: profile\nsandbox:\n  extra_read_paths:\n    - /profile-read\n",
        encoding="utf-8",
    )
    return named, profile


def test_an_operator_profile_inside_a_checkout_is_no_trusted_base_with_no_cwd(
    tmp_path, monkeypatch
):
    """trusted_base_config's half of the any-checkout rule: with the working
    directory deleted, an operator profile (``trusted_config_path``) whose
    file sits inside a checkout is judged the repository's -- the same
    fail-closed membership the chain reads use -- so its sandbox grants never
    become the trusted base a checkout config's confinement grants from."""
    checkout = tmp_path / "profile-checkout"
    mark_git_checkout(checkout)
    named, profile = _profile_and_named_checkout_config(tmp_path, monkeypatch, checkout)
    _delete_cwd(tmp_path, monkeypatch)

    config = resolve_config(config_path=named, trusted_config_path=profile)

    assert config.project_name == "named"
    assert "/profile-read" not in list(config.sandbox.extra_read_paths), (
        config.sandbox.extra_read_paths
    )


def test_control_an_outside_operator_profile_is_the_trusted_base_with_no_cwd(
    tmp_path, monkeypatch
):
    """The contrast that keeps the cell above observable: the same profile
    outside every checkout IS the trusted base, so its grant applies."""
    outside = tmp_path / "profile-outside"
    named, profile = _profile_and_named_checkout_config(tmp_path, monkeypatch, outside)
    _delete_cwd(tmp_path, monkeypatch)

    config = resolve_config(config_path=named, trusted_config_path=profile)

    assert config.project_name == "named"
    assert "/profile-read" in list(config.sandbox.extra_read_paths), (
        config.sandbox.extra_read_paths
    )


def test_the_uncarried_trusted_base_read_judges_a_file_in_another_checkout_as_a_scan_does(
    tmp_path, monkeypatch
):
    """trusted_base_config's uncarried read (the container floor's shape:
    no default_config passed) confines the ASH_CONFIG chain with the scan's
    settings (``scan_repository_settings``): the scanned trees and every
    other checkout. An ASH_CONFIG file in its own checkout outside the
    scanned tree is therefore not the operator's, and the operator-only
    option it writes is left out as the file is read, as the scan leaves it
    out. A read that judged by the scanned trees alone would keep the option
    (4096) in the trusted base. ``default_in_tree`` is false: ASH_CONFIG's
    file sits outside the scanned tree."""
    from automated_security_helper.config.resolve_config import trusted_base_config

    source = tmp_path / "scanned"
    mark_git_checkout(source)
    elsewhere = tmp_path / "operator-checkout"
    mark_git_checkout(elsewhere)
    named = elsewhere / "cfg.yaml"
    named.write_text(
        "project_name: outside\n"
        "scanners:\n  detect-secrets:\n    options:\n"
        "      max_worker_output_mib: 4096\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(named))
    monkeypatch.chdir(tmp_path)

    base = trusted_base_config(
        None,
        scanned_trees(source),
        default_in_tree=False,
        any_checkout=False,
        merged_fallback=False,
    )

    assert base.scanners.detect_secrets.options.max_worker_output_mib == 256


def _mode_chain_with_a_twin(tmp_path, with_twin=True):
    """An ASH_CONFIG chain whose operator root sets the sandbox mode and
    patches its own section case-variant, beside a twin a base in the
    scanned checkout wrote (or no twin, for the control)."""
    source = tmp_path / "scanned"
    mark_git_checkout(source)
    extends = []
    own = tmp_path / "own.yaml"
    own.write_text(
        "reporters:\n  aws-security-hub:\n    enabled: true\n"
        "    options:\n      aws_region: us-east-1\n",
        encoding="utf-8",
    )
    extends.append(own)
    if with_twin:
        twin = source / "cfg" / "twin.yaml"
        twin.parent.mkdir(parents=True)
        twin.write_text(
            "reporters:\n  AwsSecurityHub:\n    enabled: false\n",
            encoding="utf-8",
        )
        extends.append(twin)
    root = tmp_path / "ash.yaml"
    root.write_text(
        'sandbox:\n  mode: "firejail"\n'
        "extends:\n"
        + "".join(f"  - {base.as_posix()}\n" for base in extends)
        + "patch:\n"
        "  - op: replace\n"
        "    path: /reporters/AWS_Security_Hub/options/aws_region\n"
        "    value: us-west-2\n",
        encoding="utf-8",
    )
    return source, root


def test_the_uncarried_mode_read_folds_with_the_scans_ownership(tmp_path, monkeypatch):
    """The sandbox-mode floor read with nothing carried (no operator config,
    the trusted base already the defaults) loads the ASH_CONFIG chain with
    the ownership the scan's own load applies: the operator root's
    case-variant patch folds onto the operator's own section beside the twin
    a base in the scanned checkout wrote, and the mode read answers the
    chain's mode. A read without the ownership finds the fold ambiguous and
    refuses a chain the local scan takes, so the floor it feeds reported no
    sandbox where the local scan applies one."""
    from automated_security_helper.config.resolve_config import trusted_base_config

    source, root = _mode_chain_with_a_twin(tmp_path)
    monkeypatch.setenv("ASH_CONFIG", str(root))

    base = trusted_base_config(
        None, scanned_trees(source), default_in_tree=True, merged_fallback=False
    )

    assert base.sandbox.mode == "firejail"


def test_control_the_uncarried_mode_read_without_the_twin(tmp_path, monkeypatch):
    """The same chain with no twin beside the patch: the mode read answers
    either way, so the cell above measures the twin's effect alone."""
    from automated_security_helper.config.resolve_config import trusted_base_config

    source, root = _mode_chain_with_a_twin(tmp_path, with_twin=False)
    monkeypatch.setenv("ASH_CONFIG", str(root))

    base = trusted_base_config(
        None, scanned_trees(source), default_in_tree=True, merged_fallback=False
    )

    assert base.sandbox.mode == "firejail"


def test_control_a_live_cwd_drops_the_same_checkout_module(tmp_path, monkeypatch):
    """The live-cwd control for the cell above: scanning the checkout itself
    refuses the same entry as in-tree, and the refusal names the file as the
    client's. The client config rules judge a module against the given root
    and run first, so the load ends in the refusal and the confinement never
    reaches its drop. The deleted-cwd client path refuses the same upload one
    step later, at the confinement, and would refuse even an entry importable
    outside every checkout, because with no tree there is nothing to judge a
    keep by; that is the intended fail-closed cost of validating client content
    with the working directory gone, not a parity target."""
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "editable-checkout"
    mark_git_checkout(checkout)
    module = checkout / "zz_checkout_mod.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(checkout))
    upload = tmp_path / "upload" / "config.yaml"
    upload.parent.mkdir()
    upload.write_text(
        "project_name: upload\nash_plugin_modules:\n  - zz_checkout_mod\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(checkout)

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(
            config_path=str(upload),
            untrusted_config=True,
            fallback_to_default=False,
            source_dir=checkout,
        )

    message = str(refused.value)
    assert f"{upload.name} came from an MCP client" in message, message
    assert "ash_plugin_modules" in message, message
    assert "'zz_checkout_mod' (it resolves inside the scanned tree)" in message, message
    assert "is in a checkout" not in message, message


def test_a_client_config_keeps_an_ash_own_module_with_no_cwd(tmp_path, monkeypatch):
    """The client refusal's one exemption: a module whose every spec location
    sits inside the running automated_security_helper package is ASH's own
    code, already running, so refusing it protects nothing. Client content
    naming one with the working directory deleted still loads, with the
    module kept."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    own_module = "automated_security_helper.plugin_modules.ash_builtin"
    upload = tmp_path / "upload" / "config.yaml"
    upload.parent.mkdir()
    upload.write_text(
        f"project_name: upload\nash_plugin_modules:\n  - {own_module}\n",
        encoding="utf-8",
    )
    _delete_cwd(tmp_path, monkeypatch)

    config = resolve_config(
        config_path=str(upload), untrusted_config=True, fallback_to_default=False
    )

    assert config.project_name == "upload"
    assert own_module in (config.ash_plugin_modules or []), config.ash_plugin_modules


def test_a_vanished_client_path_leaves_the_operator_chain_the_operator_s(
    tmp_path, monkeypatch
):
    """untrusted_config describes the FILE the client supplied; when that file
    vanished and the fallback answered, no client content was loaded, so the
    ASH_CONFIG chain is judged by the operator's fail-closed rules -- the
    load ANSWERS, with the checkout file's module entry left out by the
    fail-closed read -- never by the client blanket, which refused the whole
    load for an entry the operator set. The module the fail-closed read drops
    lives in a checkout the TEST made, so the cell holds wherever the
    interpreter and its site-packages live; that is the no-tree read's ruled
    direction, the same one the operator-only cells above pin."""
    checkout = tmp_path / "env-checkout"
    mark_git_checkout(checkout)
    module = checkout / "zz_vanish_mod_ash_plugins.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(checkout))
    env_cfg = checkout / ".ash" / ".ash.yaml"
    env_cfg.parent.mkdir(parents=True, exist_ok=True)
    env_cfg.write_text(
        "project_name: env\nash_plugin_modules:\n  - zz_vanish_mod_ash_plugins\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(env_cfg))
    _delete_cwd(tmp_path, monkeypatch)

    config = resolve_config(
        config_path=str(tmp_path / "nope" / "missing.yaml"),
        untrusted_config=True,
        fallback_to_default=True,
    )

    assert config.project_name == "env"
    assert "zz_vanish_mod_ash_plugins" not in (config.ash_plugin_modules or []), (
        config.ash_plugin_modules
    )


def test_the_any_checkout_arm_judges_a_location_by_its_checkout(tmp_path, monkeypatch):
    """refusal_reason's any-checkout arm, directly: the same name resolves
    inside a checkout, and only the arm turns that location into a refusal --
    without it the None root leaves the client-supplied test alone, which
    cannot see the checkout."""
    from automated_security_helper.config.plugin_module_trust import refusal_reason

    checkout = tmp_path / "arm-checkout"
    mark_git_checkout(checkout)
    module = checkout / "zz_arm_mod.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(checkout))

    with_arm = refusal_reason("zz_arm_mod", None, any_checkout=True)
    without_arm = refusal_reason("zz_arm_mod", None, any_checkout=False)

    assert with_arm is not None and "checkout" in with_arm, with_arm
    assert without_arm is None, without_arm


def _get_config_construction(config_path):
    from automated_security_helper.config.config_sources import (
        default_confinement_root,
    )

    return resolve_config(
        config_path=config_path,
        source_dir=default_confinement_root(config_path),
        scanned_root=None,
        untrusted_config=True,
        no_scanned_tree=True,
        fallback_to_default=False,
    )


def _foreign_checkout_module(tmp_path, monkeypatch, name):
    foreign = tmp_path / "foreign-checkout"
    mark_git_checkout(foreign)
    (foreign / f"{name}.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(foreign))
    return foreign


def _checkout_refusal(checkout, name):
    """The entry a scan of a tree gives a module installed in a git checkout
    other than the scanned one: the module's file, then the checkout that
    holds it. The rule is the trust model's ``ash_plugin_modules`` row
    (``_CHECKOUT_RULE``)."""
    module_file = checkout / f"{name}.py"
    return (
        f"'{name}' (it is at {module_file.as_posix()}, and it is inside the git "
        f"checkout at {checkout.absolute().as_posix()})"
    )


def _module_outside_every_checkout(tmp_path, monkeypatch, name):
    """A stand-in module installed under tmp_path, where no ``.git`` sits at or
    above it, and put on sys.path. A cell that needs a module outside every
    checkout cannot use one the interpreter installed, because the test
    environment's virtualenv may sit inside a checkout. So the stand-in's
    location is asserted first, and an environment that cannot give one fails
    the cell instead of skipping it."""
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    site = tmp_path / "site-outside"
    site.mkdir()
    module = site / f"{name}.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(site))
    assert not in_any_checkout(module), (
        f"{module} is inside a git checkout, so this venue cannot give a location "
        "outside every checkout; run with --basetemp outside one"
    )
    return module


def test_a_foreign_checkout_module_is_refused_with_a_given_root(tmp_path, monkeypatch):
    """The rooted judgment's direction, as a scan would have it: get_config's
    construction (a root given, no scanned tree) judges an upload's module
    entries as a scan of that root would. A scan of a tree refuses a module
    installed in any git checkout, not only one inside the scanned tree, so an
    upload naming a module importable from a checkout OUTSIDE the upload's
    root is refused, and the refusal names the module and the checkout that
    holds it. That is the trust model's ``ash_plugin_modules`` row
    (``_CHECKOUT_RULE``: a package in a virtual environment inside a checkout
    counts as inside it). The control below keeps a module outside every
    checkout."""
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    foreign = _foreign_checkout_module(
        tmp_path, monkeypatch, "zz9_foreign_mod_ash_plugins"
    )
    upload = tmp_path / "upload" / "config.yaml"
    upload.parent.mkdir()
    upload.write_text(
        "project_name: upload\nash_plugin_modules:\n  - zz9_foreign_mod_ash_plugins\n",
        encoding="utf-8",
    )
    _delete_cwd(tmp_path, monkeypatch)

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        _get_config_construction(upload)

    message = str(refused.value)
    refusal = _checkout_refusal(foreign, "zz9_foreign_mod_ash_plugins")
    assert f"{upload.name} came from an MCP client" in message, message
    assert "ash_plugin_modules" in message, message
    assert refusal in message, message


def test_control_a_module_outside_every_checkout_is_kept_with_a_given_root(
    tmp_path, monkeypatch
):
    """The contrast that keeps the refusal cell above observable: the same
    construction and upload shape, naming a module installed outside every git
    checkout, is not refused, and the module is kept. The scan's rule refuses a
    location inside a checkout (``_CHECKOUT_RULE``), not an installed module as
    such. The module is named inside the plugin namespace, so the confinement
    judges where it resolves: the confinement keeps a name outside the
    namespace whatever its location, so only an in-namespace name makes this
    pair (the refusal above and this control) a test of the location
    judgment."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    name = "zz9_outside_ctrl_mod_ash_plugins"
    _module_outside_every_checkout(tmp_path, monkeypatch, name)
    upload = tmp_path / "upload" / "config.yaml"
    upload.parent.mkdir()
    upload.write_text(
        f"project_name: upload\nash_plugin_modules:\n  - {name}\n", encoding="utf-8"
    )
    _delete_cwd(tmp_path, monkeypatch)

    config = _get_config_construction(upload)

    assert name in (config.ash_plugin_modules or []), config.ash_plugin_modules


def test_control_with_no_root_the_same_upload_is_refused(tmp_path, monkeypatch):
    """The no-root half: the same upload with no root at all refuses the load,
    naming the gone working directory."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    _foreign_checkout_module(tmp_path, monkeypatch, "zz9_foreign_mod")
    upload = tmp_path / "upload" / "config.yaml"
    upload.parent.mkdir()
    upload.write_text(
        "project_name: upload\nash_plugin_modules:\n  - zz9_foreign_mod\n",
        encoding="utf-8",
    )
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    _delete_cwd(tmp_path, monkeypatch)
    with pytest.raises(ASHConfigSourceError) as caught:
        resolve_config(config_path=upload, untrusted_config=True)
    assert "working directory is gone" in str(caught.value), str(caught.value)


def test_a_rooted_drop_is_worded_by_the_rule_that_made_it(tmp_path, monkeypatch):
    """A rooted load words each refusal by the rule that made it: a client
    upload's in-root module by the tree rule, and a module installed in a
    checkout outside the root by the checkout rule, naming the module's file
    and the checkout that holds it. A scan of a tree refuses both (the trust
    model's ``ash_plugin_modules`` row, ``_CHECKOUT_RULE``). The refusal never
    uses 'every checkout', the sentence of a load with no root, which would
    claim a rule the given root does not apply."""
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    foreign = _foreign_checkout_module(tmp_path, monkeypatch, "zz9_foreign_mod")
    delivered = tmp_path / "delivered"
    mark_git_checkout(delivered)
    (delivered / "zz9_in_tree_mod.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(delivered))
    upload = delivered / ".ash" / ".ash.yaml"
    upload.parent.mkdir(parents=True, exist_ok=True)
    upload.write_text(
        "project_name: delivered\nash_plugin_modules:\n"
        "  - zz9_in_tree_mod\n  - zz9_foreign_mod\n",
        encoding="utf-8",
    )
    _delete_cwd(tmp_path, monkeypatch)

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        _get_config_construction(upload)

    message = str(refused.value)
    assert f"{upload.name} came from an MCP client" in message, message
    assert "ash_plugin_modules" in message, message
    # The in-root module is refused by the given root's tree rule; the module
    # importable from a checkout outside the root is named beside it, with the
    # checkout that holds it.
    assert "'zz9_in_tree_mod' (it resolves inside the scanned tree)" in message, message
    assert _checkout_refusal(foreign, "zz9_foreign_mod") in message, message
    assert "every checkout" not in message, message


def test_an_installed_module_outside_every_checkout_is_kept_on_the_fallback(
    tmp_path, monkeypatch
):
    """The vanished client path under the operator's rules, kept side: the
    ASH_CONFIG checkout file names a module the test installs OUTSIDE every
    checkout; the load answers and keeps it, as a live scan would -- wherever
    the interpreter's own site-packages live. The file names a second module
    that sits inside the same checkout, which the any-checkout rule drops, so
    the cell keeps the one by its location and cannot pass on a load that
    keeps every name. Both are named inside the plugin namespace: the
    confinement keeps a name outside it whatever its location."""
    checkout = tmp_path / "env-checkout"
    mark_git_checkout(checkout)
    (checkout / "zz9_inside_mod_ash_plugins.py").write_text(
        "VALUE = 1\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(checkout))
    env_cfg = checkout / ".ash" / ".ash.yaml"
    env_cfg.parent.mkdir(parents=True, exist_ok=True)
    env_cfg.write_text(
        "project_name: env\nash_plugin_modules:\n"
        "  - zz9_outside_mod_ash_plugins\n  - zz9_inside_mod_ash_plugins\n",
        encoding="utf-8",
    )
    site = tmp_path / "site"
    site.mkdir()
    (site / "zz9_outside_mod_ash_plugins.py").write_text(
        "VALUE = 1\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.setenv("ASH_CONFIG", str(env_cfg))
    _delete_cwd(tmp_path, monkeypatch)

    config = resolve_config(
        config_path=str(tmp_path / "nope" / "missing.yaml"),
        untrusted_config=True,
        fallback_to_default=True,
    )

    kept = config.ash_plugin_modules or []
    assert config.project_name == "env"
    assert "zz9_outside_mod_ash_plugins" in kept, kept
    assert "zz9_inside_mod_ash_plugins" not in kept, kept


def test_a_given_root_judges_client_modules_as_a_scan_of_it_would(
    tmp_path, monkeypatch
):
    """A caller that declares no scanned tree but GIVES a root (the MCP
    get_config construction passes the delivered file's confinement root)
    keeps the plain tree judgment for client modules: an entry importable
    from inside the delivered tree is refused as in-tree, naming the file as
    the client's, and a module installed outside the root and outside every
    git checkout is not named. The client config rules run first and judge the
    module against the given root, as the confinement does for a scan of it;
    the whole-load refusal that names the gone working directory is only for
    client content with no root at all, which the client-refusal cells above
    pin. A scan of a tree also refuses a module installed in a git checkout, a
    virtualenv inside one included (``_CHECKOUT_RULE``), so the installed
    module here is a stand-in placed where no checkout holds it, and the check
    holds wherever the interpreter's own virtualenv lives."""
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    outside = "zz_outside_mod_ash_plugins"
    _module_outside_every_checkout(tmp_path, monkeypatch, outside)
    delivered = tmp_path / "delivered"
    mark_git_checkout(delivered)
    module = delivered / "zz_delivered_mod.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(delivered))
    upload = delivered / ".ash" / ".ash.yaml"
    upload.parent.mkdir(parents=True, exist_ok=True)
    upload.write_text(
        "project_name: delivered\nash_plugin_modules:\n"
        f"  - zz_delivered_mod\n  - {outside}\n",
        encoding="utf-8",
    )
    _delete_cwd(tmp_path, monkeypatch)

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(
            config_path=upload,
            source_dir=delivered,
            untrusted_config=True,
            no_scanned_tree=True,
            fallback_to_default=False,
        )

    message = str(refused.value)
    assert f"{upload.name} came from an MCP client" in message, message
    assert "ash_plugin_modules" in message, message
    # Three checks: the in-root module is named with the scanned-tree reason;
    # the module installed outside the root and outside every checkout is not
    # named; and the text never says 'every checkout', the wording of a load
    # with no root.
    assert "'zz_delivered_mod' (it resolves inside the scanned tree)" in message, (
        message
    )
    assert f"'{outside}'" not in message, message
    assert "every checkout" not in message, message


def test_a_caller_known_no_tree_drop_speaks_the_checkout_rule_beside_trees(
    tmp_path, monkeypatch, caplog
):
    """The caller-known no-tree route with a live source directory: the MCP
    get_config tool passes the flag when ITS working directory is gone while
    still passing source_dir, so trees are resolved from source_dir and can
    be non-empty. The in-tree membership still adds any checkout's chain
    files (that is what the flag means to the build), so a drop of a foreign
    checkout's operator-only write must be explained by the checkout rule --
    the scanned-tree wording would claim a tree membership the file does not
    have. The wording flag follows the membership that built in_tree, never
    whether trees happen to exist."""
    from automated_security_helper.config.ash_config import AshConfig

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "scanned"
    mark_git_checkout(source)
    foreign = tmp_path / "foreign"
    mark_git_checkout(foreign)
    base = foreign / "base.yaml"
    base.write_text(
        "scanners:\n  detect-secrets:\n    options:\n"
        "      max_worker_output_mib: 4096\n",
        encoding="utf-8",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text("extends:\n  - " + base.as_posix() + "\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=operator,
            source_dir=source,
            scanned_root=None,
            no_scanned_tree=True,
        )

    # Premise: the any-checkout membership confined the foreign write.
    default = AshConfig().scanners.detect_secrets.options.max_worker_output_mib
    assert config.scanners.detect_secrets.options.max_worker_output_mib == default
    ignoring = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring")
        and "max_worker_output_mib" in record.getMessage()
    ]
    assert ignoring, caplog.text
    assert all("the file is in a checkout" in line for line in ignoring), ignoring
    assert not any("inside the scanned tree" in line for line in ignoring), ignoring


def test_resolve_config_loads_the_default_chain_config_once(tmp_path, monkeypatch):
    """One get_default_config call per resolve: the trusted base is built
    from the carried config of the same read the membership judgments and
    the fail-closed warning used. A second read (the base, and its
    sandbox-mode floor) could see an ASH_CONFIG chain file changed between
    the reads, so the base would not be the configuration those judgments
    described."""
    from automated_security_helper.config import (
        resolve_config as resolve_config_module,
    )

    env_file = tmp_path / "ops" / "ash-config.yaml"
    env_file.parent.mkdir()
    env_file.write_text("project_name: from-env\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(env_file))
    plain = tmp_path / "plain"
    plain.mkdir()
    named = plain / "config.yaml"
    named.write_text("project_name: named\n", encoding="utf-8")
    monkeypatch.chdir(plain)

    calls = []
    real = resolve_config_module.get_default_config

    def counted(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    # Both bindings: the from-import copy the module-global calls go
    # through, and the defining module's attribute a reintroduced
    # call-time import would bind. Each route wraps the one real function
    # once, so a call increments once whichever door it takes.
    from automated_security_helper.config import default_config

    monkeypatch.setattr(resolve_config_module, "get_default_config", counted)
    monkeypatch.setattr(default_config, "get_default_config", counted)

    config = resolve_config(config_path=named)

    assert config.project_name == "named"
    assert len(calls) == 1, len(calls)


def test_a_client_supplied_drop_names_the_content_not_a_checkout(tmp_path, monkeypatch):
    """A client upload outside every checkout, loaded with no working
    directory, that asks for more sandbox access than the server gives is
    refused, and the refusal names the file as the client's. Either location
    wording would be false here -- the upload is in no checkout and no tree is
    scanned -- and the checkout wording would claim a repository wrote what
    the client did. The client config rules run on every resolution, so a
    plain call that marks the upload untrusted reaches the refusal even with
    no root to judge it against; the confinement would otherwise have dropped
    the grant with a warning."""
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    upload = tmp_path / "upload" / "config.yaml"
    upload.parent.mkdir()
    upload.write_text(
        "project_name: upload\nsandbox:\n  extra_read_paths:\n    - /client-read\n",
        encoding="utf-8",
    )
    _delete_cwd(tmp_path, monkeypatch)

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(
            config_path=str(upload), untrusted_config=True, fallback_to_default=False
        )

    message = str(refused.value)
    assert f"{upload.name} came from an MCP client" in message, message
    assert "sandbox.extra_read_paths" in message, message
    assert "/client-read" in message, message
    assert not (
        "is in a checkout" in message or "inside the scanned tree" in message
    ), message


def test_a_confined_client_upload_with_no_working_directory_speaks_the_client_voice(
    tmp_path, monkeypatch, caplog
):
    """What a client upload only restricts is not refused, with no working
    directory any more than under a live root: it loads, its network_scanners
    list kept as a limit, and the confinement warning explains the drop by the
    client sentence. This is the client-voice check the refused grant above
    used to carry. The upload is in no checkout and no tree is scanned, so
    either location wording would be false for it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    upload = tmp_path / "upload" / "config.yaml"
    upload.parent.mkdir()
    upload.write_text("sandbox:\n  network_scanners: []\n", encoding="utf-8")
    _delete_cwd(tmp_path, monkeypatch)

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=str(upload), untrusted_config=True, fallback_to_default=False
        )

    # Premise: the empty list was confined to a limit, not applied as a grant.
    assert config.sandbox.network_limit == []
    ignoring = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring")
        and "sandbox.network_scanners" in record.getMessage()
    ]
    assert ignoring, caplog.text
    assert all(
        "the file's content is the session client's" in line for line in ignoring
    ), ignoring
    assert not any(
        "is in a checkout" in line or "inside the scanned tree" in line
        for line in ignoring
    ), ignoring


@pytest.mark.parametrize("where", ["outside-the-tree", "inside-the-tree"])
def test_a_client_upload_under_a_live_root_is_named_as_the_clients(
    tmp_path, monkeypatch, where
):
    """A client upload under a LIVE root that asks for more sandbox access
    than the server gives is refused, and the refusal names the file as the
    client's: the content is the session client's wherever the file lies,
    outside the tree or inside it, so either location wording could be false
    for it. The client config rules run on every resolution, so a plain call
    that marks the upload untrusted reaches the refusal; the confinement
    would otherwise have dropped the grant with a warning."""
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "scanned"
    mark_git_checkout(source)
    upload = (
        source / "upload.yaml" if where == "inside-the-tree" else tmp_path / "up.yaml"
    )
    upload.write_text(
        "project_name: upload\nsandbox:\n  extra_read_paths:\n    - /zz-live-read\n",
        encoding="utf-8",
    )

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(
            config_path=str(upload),
            source_dir=source,
            untrusted_config=True,
            fallback_to_default=False,
        )

    message = str(refused.value)
    assert f"{upload.name} came from an MCP client" in message, message
    assert "sandbox.extra_read_paths" in message, message
    assert "/zz-live-read" in message, message
    assert not (
        "is in a checkout" in message or "inside the scanned tree" in message
    ), message


@pytest.mark.parametrize("where", ["outside-the-tree", "inside-the-tree"])
def test_a_confined_client_upload_under_a_live_root_speaks_the_client_voice(
    tmp_path, monkeypatch, caplog, where
):
    """What a client upload only restricts is not refused: it scans, its
    network_scanners list kept as a limit, and the confinement warning
    explains the drop by the client sentence. The sentence does not depend on
    the no-tree flag or on where the file lies -- the content is the session
    client's wherever it sits, and either location wording could be false for
    it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "scanned"
    mark_git_checkout(source)
    upload = (
        source / "upload.yaml" if where == "inside-the-tree" else tmp_path / "up.yaml"
    )
    upload.write_text("sandbox:\n  network_scanners: []\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=str(upload),
            source_dir=source,
            untrusted_config=True,
            fallback_to_default=False,
        )

    # Premise: the empty list was confined to a limit, not applied as a grant.
    assert config.sandbox.network_limit == []
    ignoring = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring")
        and "sandbox.network_scanners" in record.getMessage()
    ]
    assert ignoring, caplog.text
    assert all(
        "the file's content is the session client's" in line for line in ignoring
    ), ignoring
    assert not any(
        "is in a checkout" in line or "the file is inside the scanned tree" in line
        for line in ignoring
    ), ignoring


def test_a_client_supplied_module_drop_names_the_content_not_a_location(
    tmp_path, monkeypatch
):
    """The module sibling of the sandbox refusal cell above: a client-supplied
    config that names a module the server's config does not load, and that
    resolves inside the given root, is refused, and the refusal names the file
    as the client's. Either location wording could be false for an uploaded
    file, so the refusal claims no checkout for it. The client config rules
    judge the module against the given root as the confinement does and run
    first, so the load ends in this refusal."""
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "scanned"
    mark_git_checkout(source)
    module = source / "zz_client_mod.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(source))
    upload = tmp_path / "upload" / "config.yaml"
    upload.parent.mkdir()
    upload.write_text(
        "project_name: upload\nash_plugin_modules:\n  - zz_client_mod\n",
        encoding="utf-8",
    )

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(
            config_path=str(upload),
            source_dir=source,
            no_scanned_tree=True,
            untrusted_config=True,
            fallback_to_default=False,
        )

    message = str(refused.value)
    assert f"{upload.name} came from an MCP client" in message, message
    assert "ash_plugin_modules" in message, message
    assert "'zz_client_mod'" in message, message
    assert "is in a checkout" not in message, message


def test_a_registered_uploads_module_drop_still_speaks_the_client_voice(
    tmp_path, monkeypatch
):
    """The cell above uploads from an unregistered tmp_path, a state a real
    MCP session cannot reach: in production, config_is_client_supplied is
    True for every file the client delivered, so in_scanned_tree reads the
    whole chain as the scanned party's. This variant pins the
    production-reachable state by making config_is_client_supplied answer
    True: the module is still refused, and the refusal still names the file
    as the client's and the module it adds, with no checkout claim."""
    from automated_security_helper.cli.mcp import sandbox as mcp_sandbox
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "scanned"
    mark_git_checkout(source)
    module = source / "zz_registered_mod.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(source))
    upload = tmp_path / "upload" / "config.yaml"
    upload.parent.mkdir()
    upload.write_text(
        "project_name: upload\nash_plugin_modules:\n  - zz_registered_mod\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(mcp_sandbox, "config_is_client_supplied", lambda path: True)

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(
            config_path=str(upload),
            source_dir=source,
            no_scanned_tree=True,
            untrusted_config=True,
            fallback_to_default=False,
        )

    message = str(refused.value)
    assert f"{upload.name} came from an MCP client" in message, message
    assert "ash_plugin_modules" in message, message
    assert "'zz_registered_mod'" in message, message
    assert "is in a checkout" not in message, message


def test_a_rooted_no_tree_module_drop_says_both_halves(tmp_path, monkeypatch, caplog):
    """The caller-known no-tree route with a live source directory, module
    half: the config FILE sits in a foreign checkout (in the confinement by
    the any-checkout membership), while its module entries are judged against
    the GIVEN root, as a scan of that root would. The drop warning says both
    halves -- claiming the file sits inside the scanned tree would be false,
    and claiming the any-checkout module judgment would be false too."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "scanned"
    mark_git_checkout(source)
    module = source / "zz_root_tree_mod_ash_plugins.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(source))
    foreign = tmp_path / "foreign"
    mark_git_checkout(foreign)
    named = foreign / "config.yaml"
    named.write_text(
        "project_name: named\nash_plugin_modules:\n  - zz_root_tree_mod_ash_plugins\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=str(named),
            source_dir=source,
            scanned_root=None,
            no_scanned_tree=True,
        )

    # Premise: the root-based judgment refused the root-tree module.
    assert "zz_root_tree_mod_ash_plugins" not in list(config.ash_plugin_modules)
    ignoring = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring ash_plugin_modules")
    ]
    assert ignoring, caplog.text
    assert all(
        "which with no scanned tree is read as the repository's" in line
        and "judged against the given root" in line
        for line in ignoring
    ), ignoring
    # The per-entry reason agrees with the sentence: these files sit outside
    # the root's trees, so no part of the line may claim the scanned tree,
    # the parenthetical reason included.
    assert all("the given root's trees" in line for line in ignoring), ignoring
    assert not any(
        "inside the scanned tree" in line or "outside every checkout" in line
        for line in ignoring
    ), ignoring


def test_a_rooted_no_tree_checkout_drop_speaks_one_membership_everywhere(
    tmp_path, monkeypatch, caplog
):
    """Every voice of one load speaks one membership for one file. The
    caller-known no-tree route with a live source directory and the config in
    a FOREIGN checkout: the module line says the file's checkout is read as
    the repository's -- the load declared that no scanned tree exists to read
    it as -- and the sandbox and settle lines explain the same file's drops,
    so they say the same sentence. "Read as the scanned tree" there would
    claim the tree the caller said does not exist, two lines from the module
    line that denies it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "scanned"
    mark_git_checkout(source)
    module = source / "zz_voices_mod_ash_plugins.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(source))
    foreign = tmp_path / "foreign"
    mark_git_checkout(foreign)
    named = foreign / "config.yaml"
    named.write_text(
        "project_name: named\n"
        "sandbox:\n  extra_read_paths:\n    - /zz-voices-read\n"
        "ash_plugin_modules:\n  - zz_voices_mod_ash_plugins\n"
        "scanners:\n  detect-secrets:\n    options:\n"
        "      max_worker_output_mib: 4096\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=str(named),
            source_dir=source,
            scanned_root=None,
            no_scanned_tree=True,
        )

    # Premises: all three confinements fired on the foreign checkout's file.
    assert "/zz-voices-read" not in [
        str(p) for p in config.sandbox.extra_read_paths or []
    ]
    assert "zz_voices_mod_ash_plugins" not in list(config.ash_plugin_modules)
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring")
    ]
    module_lines = [line for line in lines if "ash_plugin_modules" in line]
    other_lines = [line for line in lines if "ash_plugin_modules" not in line]
    assert module_lines and other_lines, lines
    assert all(
        "which with no scanned tree is read as the repository's" in line
        for line in lines
    ), lines
    assert not any("read as the scanned tree" in line for line in lines), lines


def test_a_file_in_no_checkout_is_never_said_to_be_in_one(
    tmp_path, monkeypatch, caplog
):
    """The checkout wording follows the rule that put the files under the
    confinement: a config at a plain non-checkout root is files_inside's own
    (a non-checkout root is its own tree), so under a caller-known no-tree
    load every voice speaks the given root -- the load declared no scanned
    tree, so "inside the scanned tree" would claim a tree the caller said
    does not exist, for the sandbox and settle lines as much as for the
    module line, whose judgment tail stays its own. The any-checkout arm
    said "the file is in a checkout" for a file in no checkout at all."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    plain = tmp_path / "plain"
    plain.mkdir()
    module = plain / "zz_plain_mod_ash_plugins.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(plain))
    named = plain / ".ash" / ".ash.yaml"
    named.parent.mkdir(parents=True)
    named.write_text(
        "project_name: plain\n"
        "sandbox:\n  extra_read_paths:\n    - /zz-plain-read\n"
        "ash_plugin_modules:\n  - zz_plain_mod_ash_plugins\n"
        "scanners:\n  detect-secrets:\n    options:\n"
        "      max_worker_output_mib: 4096\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=str(named),
            source_dir=plain,
            scanned_root=None,
            no_scanned_tree=True,
        )

    # Premises: the grant and the module were confined.
    assert "/zz-plain-read" not in [
        str(p) for p in config.sandbox.extra_read_paths or []
    ]
    assert "zz_plain_mod_ash_plugins" not in list(config.ash_plugin_modules)
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring")
    ]
    assert lines, caplog.text
    assert not any("is in a checkout" in line for line in lines), lines
    module_lines = [line for line in lines if "ash_plugin_modules" in line]
    other_lines = [line for line in lines if "ash_plugin_modules" not in line]
    assert module_lines and other_lines, lines
    assert all(
        "the file is inside the given root's trees" in line
        and "scanned tree" not in line
        for line in other_lines
    ), other_lines
    assert all(
        "the given root's trees" in line and "scanned tree" not in line
        for line in module_lines
    ), module_lines


def test_a_mixed_membership_line_names_each_files_own(caplog):
    """A warning line covering files of BOTH memberships (some put under the
    confinement by files_inside, some by the any-checkout rule) says each
    file's own membership: one sentence claiming "the file is in a checkout"
    would name a location the in-tree file does not have. Pinned at the
    warning level beside the load-level cells below: a chain's extends bases
    must stay inside one confinement root, and every file inside a root that
    is its own tree is files_inside's (nested checkouts included), so only
    the out-of-root operator shape those cells drive produces the mixed line;
    the flag also keeps a direct caller that holds both groups honest."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.sandbox_grants import (
        confine_sandbox_grants,
        confinement_membership,
    )

    mixed = confinement_membership(checkout_membership=True, mixed=True)
    assert "each file is the repository's" in mixed, mixed
    assert "the file is in a checkout" not in mixed, mixed

    resolved = AshConfig()
    resolved.sandbox.extra_read_paths = ["/zz-mixed-read"]
    with caplog.at_level(logging.WARNING):
        confine_sandbox_grants(
            resolved.sandbox,
            AshConfig().sandbox,
            [Path("/zz-root/cfg.yaml"), Path("/zz-elsewhere/base.yaml")],
            checkout_membership=True,
            mixed_membership=True,
            given_root_membership=False,
            undecided_membership=False,
        )
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring")
    ]
    assert lines, caplog.text
    assert all("each file is the repository's" in line for line in lines), lines
    assert not any("the file is in a checkout" in line for line in lines), lines


def test_the_membership_flags_bind_only_by_keyword():
    """The first membership flag's meaning changed when it was renamed from
    the old no-scanned-tree parameter, so a positional call written against
    the old meaning must fail with a TypeError instead of binding silently
    to the new one. The signatures say keyword-only; these calls are what
    pin it, so dropping the ``*`` turns them red."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.sandbox_grants import (
        confine_sandbox_grants,
        confinement_membership,
    )

    # Every required flag the signature could complain about is satisfied (by
    # the sole positional word, were the star dropped, or by keyword), and the
    # match pins the TypeError to the positional refusal: a missing-flags
    # TypeError would otherwise keep these green with the star gone.
    with pytest.raises(
        TypeError, match=r"takes (from \d+ to )?\d+ positional argument"
    ):
        confinement_membership(True)

    with pytest.raises(
        TypeError, match=r"takes (from \d+ to )?\d+ positional argument"
    ):
        confine_sandbox_grants(
            AshConfig().sandbox,
            AshConfig().sandbox,
            [Path("/zz-root/cfg.yaml")],
            frozenset(),
            True,
            mixed_membership=False,
            given_root_membership=False,
            undecided_membership=False,
        )


def test_a_mixed_membership_module_line_with_a_root_needs_the_given_root_flag():
    """With a root given, the load judges against that root, so the mixed
    flag alone no longer passes the wording check: the mixed head without the
    given-root flag does not speak the given root, and the sentence would put
    that head beside the given-root judgment tail. The check is eager -- it
    runs on every call that declares no scanned tree -- so the refusal fires
    at call time, before any module is judged. resolve_config cannot state
    this set: with a root given its trees are non-empty, so it states the
    given-root flag; only a direct caller meets the refusal."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        confine_plugin_modules,
    )

    resolved = AshConfig()
    resolved.ash_plugin_modules = ["zz_mixed_gate_mod_ash_plugins"]
    with pytest.raises(TypeError, match="do not speak the given root"):
        confine_plugin_modules(
            resolved,
            AshConfig(),
            [],
            Path("/zz-root"),
            [Path("/zz-root/cfg.yaml"), Path("/zz-elsewhere/base.yaml")],
            frozenset(),
            no_scanned_tree=True,
            checkout_membership=False,
            mixed_membership=True,
            given_root_membership=False,
            undecided_membership=False,
        )


def test_a_mixed_membership_module_line_with_a_root_speaks_the_given_roots_trees(
    caplog,
):
    """The green sibling of the refusal cell above: the same mixed line with
    the given-root flag stated, as resolve_config states it for every load
    whose trees are known, carries the full given-root mixed head beside the
    given-root judgment tail."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        confine_plugin_modules,
    )

    resolved = AshConfig()
    resolved.ash_plugin_modules = ["zz_mixed_gate_mod_ash_plugins"]
    with caplog.at_level(logging.WARNING):
        confine_plugin_modules(
            resolved,
            AshConfig(),
            [],
            Path("/zz-root"),
            [Path("/zz-root/cfg.yaml"), Path("/zz-elsewhere/base.yaml")],
            frozenset(),
            no_scanned_tree=True,
            checkout_membership=False,
            mixed_membership=True,
            given_root_membership=True,
            undecided_membership=False,
        )
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring ash_plugin_modules")
    ]
    assert lines, caplog.text
    assert all(
        "each file is the repository's -- inside the given root's trees, "
        "or in a checkout, which with no scanned tree is read as the "
        "repository's --"
        in line
        and "judged against the given root" in line
        for line in lines
    ), lines
    assert not any("inside the scanned tree" in line for line in lines), lines


def test_a_stated_given_root_build_speaks_the_given_root(caplog):
    """A caller that declares no scanned tree and gives a root judges against
    that root, and states the given-root wording flag that goes with it
    (resolve_config computes it from the trees); the module warning speaks
    that root. The module voice honors the flags as stated, as the sandbox
    and settle voices do, so the stated flag is what makes the sentence the
    given-root one."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        confine_plugin_modules,
    )

    resolved = AshConfig()
    resolved.ash_plugin_modules = ["zz_default_root_mod_ash_plugins"]
    with caplog.at_level(logging.WARNING):
        confine_plugin_modules(
            resolved,
            AshConfig(),
            [],
            Path("/zz-root"),
            [Path("/zz-root/cfg.yaml")],
            frozenset(),
            no_scanned_tree=True,
            checkout_membership=False,
            mixed_membership=False,
            given_root_membership=True,
            undecided_membership=False,
        )
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring ash_plugin_modules")
    ]
    assert lines, caplog.text
    assert all(
        "the file is inside the given root's trees" in line
        and "judged against the given root" in line
        for line in lines
    ), lines
    assert not any("inside the scanned tree" in line for line in lines), lines


def test_a_stated_checkout_build_with_a_given_root_speaks_the_repositorys(caplog):
    """A caller that declares no scanned tree, gives a root, and states the
    warned files as the any-checkout rule's also states the given-root flag
    (the load has trees), so the checkout head takes its no-scanned-tree arm
    ("read as the repository's"), the one that agrees with the given-root
    judgment tail. The sibling cell above states no checkout flag, so this
    one is what holds the checkout head over a given root."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        confine_plugin_modules,
    )

    resolved = AshConfig()
    resolved.ash_plugin_modules = ["zz_checkout_root_mod_ash_plugins"]
    with caplog.at_level(logging.WARNING):
        confine_plugin_modules(
            resolved,
            AshConfig(),
            [],
            Path("/zz-root"),
            [Path("/zz-elsewhere/checkout/cfg.yaml")],
            frozenset(),
            no_scanned_tree=True,
            checkout_membership=True,
            mixed_membership=False,
            given_root_membership=True,
            undecided_membership=False,
        )
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring ash_plugin_modules")
    ]
    assert lines, caplog.text
    assert all(
        "which with no scanned tree is read as the repository's" in line
        and "judged against the given root" in line
        for line in lines
    ), lines
    assert not any(
        "read as the scanned tree" in line or "with no working directory" in line
        for line in lines
    ), lines


def test_a_rootless_checkout_build_speaks_the_checkout_head(caplog):
    """A caller that declares no scanned tree and gives NO root judges by the
    any-checkout rule, and states the checkout wording flag that goes with
    it: the head is the checkout reading and the tail the every-checkout
    judgment. The rule that makes a rootless load state that flag lives in
    resolve_config (``rootless_wording``), not in this function, which
    speaks the flags as stated. The resolve_config-level cell that pins the
    rule is ``test_a_host_marked_rootless_file_is_worded_as_a_checkout``."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        confine_plugin_modules,
    )

    resolved = AshConfig()
    resolved.ash_plugin_modules = ["zz_default_rootless_mod_ash_plugins"]
    with caplog.at_level(logging.WARNING):
        confine_plugin_modules(
            resolved,
            AshConfig(),
            [],
            None,
            [Path("/zz-elsewhere/checkout/cfg.yaml")],
            frozenset(),
            no_scanned_tree=True,
            # The caller states the wording flags (they carry no defaults):
            # a rootless default build's judgment IS the any-checkout rule,
            # so its membership is the checkout one.
            checkout_membership=True,
            mixed_membership=False,
            given_root_membership=False,
            undecided_membership=False,
        )
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring ash_plugin_modules")
    ]
    assert lines, caplog.text
    assert all(
        "the file is in a checkout, which with no working directory is read "
        "as the scanned tree"
        in line
        and "outside every checkout" in line
        for line in lines
    ), lines
    assert not any("the file is inside the scanned tree" in line for line in lines), (
        lines
    )


#: Each: the stated flags and the root of a load that declared no scanned tree,
#: for a caller whose flags agree with its judgment.
_AGREEING_FLAGS = {
    "rootless-checkout": (
        None,
        {"checkout_membership": True, "mixed": False, "given_root": False},
    ),
    "rootless-known-trees": (
        None,
        {"checkout_membership": False, "mixed": False, "given_root": True},
    ),
    # A direct caller's shape: no resolve_config load states mixed without
    # the given-root flag (the rootless reading forces the mixed flag off,
    # and the undecided override reaches the mixed-undecided arm, which
    # names no tree).
    "rootless-host-marked-and-checkout": (
        None,
        {"checkout_membership": True, "mixed": True, "given_root": False},
    ),
    "given-root": (
        Path("/zz-root"),
        {"checkout_membership": False, "mixed": False, "given_root": True},
    ),
    "given-root-checkout": (
        Path("/zz-root"),
        {"checkout_membership": True, "mixed": False, "given_root": True},
    ),
    "given-root-mixed": (
        Path("/zz-root"),
        {"checkout_membership": False, "mixed": True, "given_root": True},
    ),
}


@pytest.mark.parametrize("case", sorted(_AGREEING_FLAGS))
def test_the_sandbox_and_module_warnings_speak_one_head_for_the_same_flags(
    caplog, case
):
    """Both confiners run for real with the same stated flags, and each line
    carries the location head ``membership_clause`` builds for those flags.
    A confiner that overrode a stated flag for its own voice, as the module
    warning once did for the checkout flag, turns this red: neither head is
    taken from the confiner under test."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        confine_plugin_modules,
    )
    from automated_security_helper.config.sandbox_grants import (
        confine_sandbox_grants,
        membership_clause,
    )

    root, flags = _AGREEING_FLAGS[case]
    config_file = Path("/zz-root/cfg.yaml")
    resolved = AshConfig()
    resolved.ash_plugin_modules = ["zz_one_head_mod_ash_plugins"]
    resolved.sandbox.extra_read_paths = ["/zz-one-head-read"]
    with caplog.at_level(logging.WARNING):
        confine_sandbox_grants(
            resolved.sandbox,
            AshConfig().sandbox,
            [config_file],
            frozenset(),
            checkout_membership=flags["checkout_membership"],
            mixed_membership=flags["mixed"],
            given_root_membership=flags["given_root"],
            undecided_membership=False,
        )
        confine_plugin_modules(
            resolved,
            AshConfig(),
            [],
            root,
            [config_file],
            frozenset(),
            no_scanned_tree=True,
            checkout_membership=flags["checkout_membership"],
            mixed_membership=flags["mixed"],
            given_root_membership=flags["given_root"],
            undecided_membership=False,
        )
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring")
    ]
    sandbox_lines = [line for line in lines if line.startswith("Ignoring sandbox.")]
    module_lines = [
        line for line in lines if line.startswith("Ignoring ash_plugin_modules")
    ]
    assert sandbox_lines and module_lines, caplog.text
    head = membership_clause(**flags)
    assert all(head in line for line in sandbox_lines), (head, sandbox_lines)
    assert all(head in line for line in module_lines), (head, module_lines)


def _refused_confine(**stated):
    """confine_plugin_modules with the stated wording flags, for a load that
    declared no scanned tree; the result is the call's TypeError (a bad
    argument combination, never a ValueError: every config-validation error
    is one, and a caller bug must not be reportable as an invalid config)."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        confine_plugin_modules,
    )

    root = stated.pop("root")
    resolved = AshConfig()
    resolved.ash_plugin_modules = ["zz_refused_flags_mod"]
    with pytest.raises(TypeError, match="wording flags") as caught:
        confine_plugin_modules(
            resolved,
            AshConfig(),
            [],
            root,
            [Path("/zz-elsewhere/plain/cfg.yaml")],
            frozenset(),
            no_scanned_tree=True,
            **stated,
        )
    assert not isinstance(caught.value, ValueError), type(caught.value).__mro__
    return resolved, caught.value


@pytest.mark.parametrize("root", [None, Path("/zz-root")], ids=["rootless", "root"])
def test_mismatched_wording_flags_are_refused_even_when_no_entry_is_dropped(
    caplog, root
):
    """The refusal is eager: it runs on every call that declares no scanned
    tree, not only on a call that drops an entry. A call that keeps every
    entry (every module is the trusted list's) is refused for flags that
    state no membership too, so an inconsistent set fails on the first call
    that states it and not on the first call that refuses a real module. The
    one production caller, resolve_config, states a consistent set on every
    branch, so only a direct caller meets this. Nothing is warned and the
    list is left as it was."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        confine_plugin_modules,
    )

    resolved = AshConfig()
    resolved.ash_plugin_modules = ["zz_trusted_flags_mod"]
    trusted = AshConfig()
    trusted.ash_plugin_modules = ["zz_trusted_flags_mod"]
    with caplog.at_level(logging.WARNING):
        with pytest.raises(TypeError, match="wording flags") as caught:
            confine_plugin_modules(
                resolved,
                trusted,
                [],
                root,
                [Path("/zz-elsewhere/plain/cfg.yaml")],
                frozenset(),
                no_scanned_tree=True,
                checkout_membership=False,
                mixed_membership=False,
                given_root_membership=False,
                undecided_membership=False,
            )
    assert not isinstance(caught.value, ValueError), type(caught.value).__mro__
    assert list(resolved.ash_plugin_modules) == ["zz_trusted_flags_mod"]
    assert not [r for r in caplog.records if "Ignoring" in r.getMessage()]


def test_a_rootless_build_that_states_no_membership_is_refused(caplog):
    """A load that declared no scanned tree and gave no root judges by the
    any-checkout rule, so a caller that states no flag for it (the file is not
    a checkout's, no trees are known, nothing is mixed) describes a load that
    does not exist. The only sentence the flags could give is the
    scanned-tree one, which this judgment contradicts, so the call is
    refused instead of warning with a sentence the module voice can see is
    false."""
    with caplog.at_level(logging.WARNING):
        resolved, error = _refused_confine(
            root=None,
            checkout_membership=False,
            mixed_membership=False,
            given_root_membership=False,
            undecided_membership=False,
        )
    assert "rootless" in str(error), error
    assert list(resolved.ash_plugin_modules) == ["zz_refused_flags_mod"]
    assert not [r for r in caplog.records if "Ignoring" in r.getMessage()]


@pytest.mark.parametrize(
    "stated",
    [
        {
            "checkout_membership": False,
            "mixed_membership": False,
            "given_root_membership": False,
            "undecided_membership": False,
        },
        {
            "checkout_membership": True,
            "mixed_membership": False,
            "given_root_membership": False,
            "undecided_membership": False,
        },
    ],
    ids=["no-flag", "checkout-only"],
)
def test_a_given_root_build_that_does_not_state_the_given_root_is_refused(stated):
    """A load that declared no scanned tree and gave a root judges against
    that root, so the sentence has to speak the given root: a caller whose
    flags say otherwise (no flag, or the rootless checkout head, "with no
    working directory") would pair that head with the given-root judgment, a
    sentence claiming a tree the load declared it does not have. resolve_config
    states the given-root flag whenever the trees are known."""
    resolved, error = _refused_confine(root=Path("/zz-root"), **stated)
    assert "given root" in str(error), error
    assert list(resolved.ash_plugin_modules) == ["zz_refused_flags_mod"]


def test_the_wording_flags_check_leaves_a_scan_with_a_tree_alone(caplog):
    """The refusal is for loads that declared no scanned tree. A scan that
    judges against a real tree keeps stating whatever head its flags give."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        confine_plugin_modules,
    )

    resolved = AshConfig()
    resolved.ash_plugin_modules = ["zz_scan_flags_mod_ash_plugins"]
    with caplog.at_level(logging.WARNING):
        confine_plugin_modules(
            resolved,
            AshConfig(),
            [],
            Path("/zz-root"),
            [Path("/zz-root/cfg.yaml")],
            frozenset(),
            no_scanned_tree=False,
            checkout_membership=False,
            mixed_membership=False,
            given_root_membership=False,
            undecided_membership=False,
        )
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring ash_plugin_modules")
    ]
    assert lines, caplog.text
    assert all("the file is inside the scanned tree" in line for line in lines), lines


def test_a_host_marked_rootless_file_is_worded_as_a_checkout(
    tmp_path, monkeypatch, caplog
):
    """A load with no working directory and no source directory has no trees,
    so ``files_inside`` admits only the files the host marked as the scanned
    repository's, and a mark is the host's checkout verdict
    (``in_a_checkout`` counts a marked file wherever it sits). That is the one
    rootless shape the any-checkout rule did not add, so ``checkout_membership``
    would be False for it; resolve_config's ``rootless_wording`` makes it
    True, and the sandbox, settle and module warnings all speak the checkout
    head with the same words. Deleting the rule turns all three red."""
    from automated_security_helper.config.sandbox_grants import (
        in_a_checkout,
        marked_files_repository_written,
        membership_clause,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    mounted = tmp_path / "mounted"
    mounted.mkdir()
    named = mounted / "marked-cfg.yaml"
    named.write_text("project_name: marked\n" + _MIXED_WRITES, encoding="utf-8")
    # Premise: the file is in no checkout of its own, so the mark is all
    # that makes it the repository's.
    assert not in_a_checkout(named)
    _delete_cwd(tmp_path, monkeypatch)

    with marked_files_repository_written([named]), caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=str(named))

    # Premises: its grant and module were confined.
    assert "/zz-mixed2-read" not in [
        str(p) for p in config.sandbox.extra_read_paths or []
    ]
    assert "zz_mixed2_mod_ash_plugins" not in list(config.ash_plugin_modules or [])
    head = membership_clause(checkout_membership=True, mixed=False, given_root=False)
    for voice in sorted(_MIXED_VOICES):
        lines = [
            line for line in _mixed_voice_lines(caplog, voice) if "marked-cfg" in line
        ]
        assert lines, (voice, caplog.text)
        clauses = [_membership_clause(line) for line in lines]
        assert all(clause.startswith(head) for clause in clauses), (voice, clauses)
    module_lines = [
        line for line in _mixed_voice_lines(caplog, "module") if "marked-cfg" in line
    ]
    assert all("outside every checkout" in line for line in module_lines), module_lines


def test_a_rootless_load_of_a_marked_file_speaks_the_checkout_judgment_in_every_warning(
    tmp_path, monkeypatch, caplog
):
    """The module warning gets the same wording value as the sandbox warning
    through resolve_config itself. The file is outside every checkout and the
    host marked it as the scanned repository's, so files_inside already
    counted it and the any-checkout rule added nothing: the files it added
    are none. A rootless load still speaks the checkout reading for the
    module line, as it does for the sandbox line. The direct-call cells above
    pin confine_plugin_modules; none of them goes through the value
    resolve_config computes and hands it."""
    from automated_security_helper.config.sandbox_grants import (
        confinement_membership,
        marked_files_repository_written,
        membership_clause,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "editable-checkout"
    mark_git_checkout(checkout)
    (checkout / "zz_marked_rootless_mod_ash_plugins.py").write_text(
        "VALUE = 1\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(checkout))
    plain = tmp_path / "plain"
    plain.mkdir()
    named = plain / "config.yaml"
    named.write_text(
        "project_name: marked\n"
        "sandbox:\n  extra_read_paths:\n    - /zz-marked-rootless-read\n"
        "ash_plugin_modules:\n  - zz_marked_rootless_mod_ash_plugins\n",
        encoding="utf-8",
    )
    _delete_cwd(tmp_path, monkeypatch)

    with caplog.at_level(logging.WARNING), marked_files_repository_written([named]):
        config = resolve_config(config_path=named)

    # Premises: the grant and the module were confined, by the marked file
    # alone (it sits in no checkout).
    assert "/zz-marked-rootless-read" not in [
        str(p) for p in config.sandbox.extra_read_paths or []
    ]
    assert "zz_marked_rootless_mod_ash_plugins" not in list(config.ash_plugin_modules)
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring")
    ]
    module_lines = [line for line in lines if "ash_plugin_modules" in line]
    other_lines = [line for line in lines if "ash_plugin_modules" not in line]
    assert module_lines and other_lines, lines
    head = membership_clause(checkout_membership=True, mixed=False, given_root=False)
    sandbox_sentence = confinement_membership(
        checkout_membership=True, mixed=False, given_root=False
    )
    assert sandbox_sentence.startswith(head), sandbox_sentence
    assert all(head in line for line in other_lines), (head, other_lines)
    assert all(head in line for line in module_lines), (head, module_lines)
    assert not any("is inside the scanned tree" in line for line in lines), lines


def test_a_host_marked_rootless_ash_config_file_is_worded_as_a_checkout(
    tmp_path, monkeypatch, caplog
):
    """The configless branch's half of
    ``test_a_host_marked_rootless_file_is_worded_as_a_checkout``: a load with
    no working directory, no source directory and NO selected config file
    reads its configuration from the ASH_CONFIG chain, and resolve_config
    derives ``checkout_membership`` for that branch with its own copy of the
    rule. A host-marked ASH_CONFIG file sits in no checkout of its own, so
    only the rootless reading makes the sandbox, settle and module warnings
    speak the checkout head. Dropping ``or rootless_wording`` on this branch
    alone turns all three red; the selected-chain cell cannot see it."""
    from automated_security_helper.config.sandbox_grants import (
        in_a_checkout,
        marked_files_repository_written,
        membership_clause,
    )

    mounted = tmp_path / "mounted"
    mounted.mkdir()
    named = mounted / "marked-env-cfg.yaml"
    named.write_text("project_name: marked\n" + _MIXED_WRITES, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(named))
    # Premise: the file is in no checkout of its own, so the mark is all
    # that makes it the repository's.
    assert not in_a_checkout(named)
    _delete_cwd(tmp_path, monkeypatch)

    with marked_files_repository_written([named]), caplog.at_level(logging.WARNING):
        config = resolve_config()

    # Premises: the configless branch ran and its grant and module were
    # confined.
    assert "/zz-mixed2-read" not in [
        str(p) for p in config.sandbox.extra_read_paths or []
    ]
    assert "zz_mixed2_mod_ash_plugins" not in list(config.ash_plugin_modules or [])
    head = membership_clause(checkout_membership=True, mixed=False, given_root=False)
    for voice in sorted(_MIXED_VOICES):
        lines = [
            line
            for line in _mixed_voice_lines(caplog, voice)
            if "marked-env-cfg" in line
        ]
        assert lines, (voice, caplog.text)
        clauses = [_membership_clause(line) for line in lines]
        assert all(clause.startswith(head) for clause in clauses), (voice, clauses)
    module_lines = [
        line
        for line in _mixed_voice_lines(caplog, "module")
        if "marked-env-cfg" in line
    ]
    assert all("outside every checkout" in line for line in module_lines), module_lines


@pytest.mark.parametrize("branch", ["selected-chain", "ash-config-chain"])
def test_a_rootless_line_naming_a_marked_file_and_a_checkout_base_speaks_one_head(
    tmp_path, monkeypatch, caplog, branch
):
    """A load with no working directory and no source directory has no trees.
    A host-marked file outside every checkout and a base of it inside a
    checkout land on ONE warning line: the base is the any-checkout rule's
    and the marked file is files_inside's, so the files are of both
    memberships. The rootless reading says every file is in a checkout, so
    the line must not take the mixed head, which speaks "inside the given
    root's trees" -- trees this load does not have. The whole location
    sentence is compared with the checkout head, so a line that carries the
    checkout words inside a mixed sentence still fails."""
    from automated_security_helper.config.sandbox_grants import (
        in_a_checkout,
        marked_files_repository_written,
        membership_clause,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    mounted = tmp_path / "mounted"
    mounted.mkdir()
    # A config's bases must stay inside its own directory, so the checkout
    # is nested under the marked file's directory, which is no checkout.
    foreign = mounted / "foreign"
    mark_git_checkout(foreign)
    base = foreign / "foreign-base.yaml"
    base.write_text(_MIXED_WRITES, encoding="utf-8")
    named = mounted / "marked-mixed.yaml"
    named.write_text(f"extends:\n  - {base.as_posix()}\n", encoding="utf-8")
    # Premises: one file of each membership, the marked one only by its mark.
    assert in_a_checkout(base)
    assert not in_a_checkout(named)
    if branch == "ash-config-chain":
        monkeypatch.setenv("ASH_CONFIG", str(named))
    _delete_cwd(tmp_path, monkeypatch)

    with marked_files_repository_written([named]), caplog.at_level(logging.WARNING):
        if branch == "ash-config-chain":
            config = resolve_config()
        else:
            config = resolve_config(config_path=str(named))

    # Premises: the base's grant and module were confined.
    assert "/zz-mixed2-read" not in [
        str(p) for p in config.sandbox.extra_read_paths or []
    ]
    assert "zz_mixed2_mod_ash_plugins" not in list(config.ash_plugin_modules or [])
    head = membership_clause(checkout_membership=True, mixed=False, given_root=False)
    for voice in sorted(_MIXED_VOICES):
        lines = [
            line
            for line in _mixed_voice_lines(caplog, voice)
            if "foreign-base.yaml" in line
        ]
        assert lines, (voice, caplog.text)
        # The line names both files, so it is the one mixed-shaped line.
        assert all("marked-mixed.yaml" in line for line in lines), (voice, lines)
        clauses = [_membership_clause(line) for line in lines]
        assert all(clause.startswith(head) for clause in clauses), (voice, clauses)
        assert not any(
            "given root" in clause or "each file is" in clause for clause in clauses
        ), (voice, clauses)


def test_the_confines_wording_flags_carry_no_defaults():
    """The four wording flags are stated by every caller, on all three
    warning voices. A default can only be a guess about the caller's
    membership, and the rootless guess was measured wrong: a rootless call
    that left ``checkout_membership`` at its default got the scanned-tree
    head -- one sentence claiming a tree the load declared it does not have
    -- where a rootless file is in a checkout by the any-checkout rule or by
    the host's mark. Requiring the flags makes the omission a TypeError
    instead of a wrong sentence, and feeds the sandbox, settle and module
    warnings the same values."""
    import inspect

    from automated_security_helper.config.operator_only_options import (
        confine_operator_only_options,
    )
    from automated_security_helper.config.plugin_module_trust import (
        confine_plugin_modules,
    )
    from automated_security_helper.config.sandbox_grants import (
        confine_sandbox_grants,
    )

    for confine in (
        confine_plugin_modules,
        confine_sandbox_grants,
        confine_operator_only_options,
    ):
        parameters = inspect.signature(confine).parameters
        for flag in (
            "checkout_membership",
            "mixed_membership",
            "given_root_membership",
            "undecided_membership",
        ):
            parameter = parameters[flag]
            assert parameter.kind is inspect.Parameter.KEYWORD_ONLY, (
                confine.__name__,
                flag,
                parameter.kind,
            )
            assert parameter.default is inspect.Parameter.empty, (
                confine.__name__,
                flag,
                parameter.default,
            )


def test_the_confines_wording_flags_are_keyword_only():
    """The two confinement entry points carry the same keyword-only guard as
    the membership sentence helpers: both renamed or inserted a flag in a
    positional slot, so a positional call written against an older signature
    must fail with a TypeError instead of binding a judgment or wording flag
    silently to the wrong meaning."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.operator_only_options import (
        confine_operator_only_options,
    )
    from automated_security_helper.config.plugin_module_trust import (
        confine_plugin_modules,
    )

    # As in the membership-flag cell above: the stated flags leave the
    # positional refusal as the only TypeError, so a dropped star fails here
    # instead of passing on the missing-flags TypeError.
    with pytest.raises(
        TypeError, match=r"takes (from \d+ to )?\d+ positional argument"
    ):
        confine_plugin_modules(
            AshConfig(),
            AshConfig(),
            [],
            None,
            [],
            frozenset(),
            True,
            checkout_membership=False,
            mixed_membership=False,
            given_root_membership=False,
            undecided_membership=False,
        )
    with pytest.raises(
        TypeError, match=r"takes (from \d+ to )?\d+ positional argument"
    ):
        confine_operator_only_options(
            AshConfig(),
            AshConfig(),
            [],
            [],
            None,
            frozenset(),
            None,
            True,
            checkout_membership=False,
            mixed_membership=False,
            given_root_membership=False,
            undecided_membership=False,
        )


_MIXED_WRITES = (
    "sandbox:\n  extra_read_paths:\n    - /zz-mixed2-read\n"
    "ash_plugin_modules:\n  - zz_mixed2_mod_ash_plugins\n"
    "scanners:\n  detect-secrets:\n    options:\n"
    "      max_worker_output_mib: 4096\n"
)

#: voice -> the prefix its warning starts with, and a word that selects it.
_MIXED_VOICES = {
    "sandbox": ("Ignoring sandbox.", "extra_read_paths"),
    "settle": ("Ignoring ", "max_worker_output_mib"),
    "module": ("Ignoring ash_plugin_modules", "zz_mixed2_mod_ash_plugins"),
}


def _mixed_operator_load(tmp_path, monkeypatch, caplog, bases):
    """resolve_config with a live source directory at a plain root and the
    caller's no-tree flag: the operator file OUTSIDE the root extends a base
    in the plain root, one in a foreign checkout, or both -- the one API
    shape that puts files of both memberships on one warning line (it has
    no production caller; the flag keeps it honest)."""
    from automated_security_helper.config.sandbox_grants import in_a_checkout

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "zz_mixed2_mod_ash_plugins.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(plain))
    foreign = tmp_path / "foreign"
    mark_git_checkout(foreign)
    base_files = {
        "plain": plain / "plain-base.yaml",
        "foreign": foreign / "foreign-base.yaml",
    }
    for file in base_files.values():
        file.write_text(_MIXED_WRITES, encoding="utf-8")
    # Premises: the memberships are what the shape needs.
    assert not in_a_checkout(base_files["plain"])
    assert in_a_checkout(base_files["foreign"])
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        "extends:\n" + "".join(f"  - {base_files[b].as_posix()}\n" for b in bases),
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=str(operator),
            source_dir=plain,
            scanned_root=None,
            no_scanned_tree=True,
        )
    # Premises: both writes were confined.
    assert "/zz-mixed2-read" not in [
        str(p) for p in config.sandbox.extra_read_paths or []
    ]
    assert "zz_mixed2_mod_ash_plugins" not in list(config.ash_plugin_modules or [])


def _mixed_voice_lines(caplog, voice):
    prefix, word = _MIXED_VOICES[voice]
    return [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith(prefix) and word in record.getMessage()
    ]


def _membership_clause(line):
    """The membership sentence: the text after the last named file's ': '."""
    head, sep, tail = line.rpartition(".yaml: ")
    assert sep, "no file named: " + line
    return tail.split(". Name other", 1)[0].split(". A network_scanners", 1)[0]


@pytest.mark.parametrize("voice", sorted(_MIXED_VOICES))
def test_a_line_naming_a_plain_root_file_never_says_it_is_in_a_checkout(
    tmp_path, monkeypatch, caplog, voice
):
    """The load-level mixed flag's kill: one line names a files_inside file
    (a plain non-checkout root is its own tree) beside a foreign-checkout
    base the any-checkout rule added, and claiming "in a checkout" for the
    whole line would name a location the plain file does not have."""
    _mixed_operator_load(tmp_path, monkeypatch, caplog, ["plain", "foreign"])
    lines = [
        line for line in _mixed_voice_lines(caplog, voice) if "plain-base.yaml" in line
    ]
    assert lines, "no " + voice + " line names the plain file: " + caplog.text
    assert all("foreign-base.yaml" in line for line in lines), lines
    clauses = [_membership_clause(line) for line in lines]
    assert not any("is in a checkout" in clause for clause in clauses), lines
    # The in-tree half speaks the given root's trees, never a scanned tree
    # the load declared it does not have.
    assert all("inside the given root's trees" in clause for clause in clauses), lines
    assert not any(
        "inside the scanned tree" in clause or "read as the scanned tree" in clause
        for clause in clauses
    ), lines


@pytest.mark.parametrize("voice", sorted(_MIXED_VOICES))
def test_control_a_plain_root_line_alone_keeps_the_tree_wording(
    tmp_path, monkeypatch, caplog, voice
):
    _mixed_operator_load(tmp_path, monkeypatch, caplog, ["plain"])
    lines = _mixed_voice_lines(caplog, voice)
    assert lines, caplog.text
    assert not any("is in a checkout" in _membership_clause(line) for line in lines), (
        lines
    )


@pytest.mark.parametrize("voice", sorted(_MIXED_VOICES))
def test_control_a_foreign_checkout_line_alone_says_it_is_in_a_checkout(
    tmp_path, monkeypatch, caplog, voice
):
    _mixed_operator_load(tmp_path, monkeypatch, caplog, ["foreign"])
    lines = _mixed_voice_lines(caplog, voice)
    assert lines, caplog.text
    assert all("is in a checkout" in _membership_clause(line) for line in lines), lines


def test_control_a_nested_checkouts_chain_file_keeps_one_voice(
    tmp_path, monkeypatch, caplog
):
    """The load-level control for the mixed pin above: a chain whose base
    sits in a checkout NESTED inside a plain root stays one voice, because
    everything inside the root is files_inside's (a plain root is its own
    tree), so the whole line keeps the tree wording and never claims a
    checkout. The routes that would put a file of each membership on one
    line were measured refused at the load: an extends leaving the root is
    refused by the base confinement, selected chain and ASH_CONFIG chain
    alike."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    plain = tmp_path / "plain"
    plain.mkdir()
    module = plain / "zz_mixed_mod_ash_plugins.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(plain))
    nested = plain / "vendor"
    mark_git_checkout(nested)
    base = nested / "base.yaml"
    base.write_text(
        "sandbox:\n  extra_read_paths:\n    - /zz-mixed-read\n",
        encoding="utf-8",
    )
    named = plain / ".ash" / ".ash.yaml"
    named.parent.mkdir(parents=True)
    named.write_text(
        f"extends:\n  - {base.as_posix()}\n"
        "project_name: mixed\n"
        "ash_plugin_modules:\n  - zz_mixed_mod_ash_plugins\n"
        "scanners:\n  detect-secrets:\n    options:\n"
        "      max_worker_output_mib: 4096\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=str(named),
            source_dir=plain,
            scanned_root=None,
            no_scanned_tree=True,
        )

    # Premises: both files' writes were confined.
    assert "/zz-mixed-read" not in [
        str(p) for p in config.sandbox.extra_read_paths or []
    ]
    assert "zz_mixed_mod_ash_plugins" not in list(config.ash_plugin_modules)
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring")
    ]
    assert lines, caplog.text
    assert not any("the file is in a checkout" in line for line in lines), lines
    assert not any("each file is the repository's" in line for line in lines), lines


def test_an_in_tree_files_module_drop_under_a_given_root_speaks_that_root(
    tmp_path, monkeypatch, caplog
):
    """Under a caller-known no-tree load with a root given, every module is
    judged against that root, wherever the config file sits -- so an in-tree
    file's drop line also speaks the given root, in the membership sentence
    and in the per-entry reason, and never claims a scanned tree the load
    declared it does not have."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "scanned"
    mark_git_checkout(source)
    module = source / "zz_tree_kept_mod_ash_plugins.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(source))
    named = source / ".ash" / ".ash.yaml"
    named.parent.mkdir(parents=True, exist_ok=True)
    named.write_text(
        "project_name: named\nash_plugin_modules:\n  - zz_tree_kept_mod_ash_plugins\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=str(named),
            source_dir=source,
            scanned_root=None,
            no_scanned_tree=True,
        )

    assert "zz_tree_kept_mod_ash_plugins" not in list(config.ash_plugin_modules)
    ignoring = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring ash_plugin_modules")
    ]
    assert ignoring, caplog.text
    assert all(
        "the file is inside the given root's trees" in line
        and "it resolves inside the given root's trees" in line
        for line in ignoring
    ), ignoring
    assert not any("scanned tree" in line for line in ignoring), ignoring


def test_control_a_real_scans_module_drop_keeps_the_tree_wording(
    tmp_path, monkeypatch, caplog
):
    """The scanned-tree wording is a real scan's: with a scanned tree (no
    no-tree flag), an in-tree file's drop keeps the tree membership and the
    scanned-tree reason, and never names a given root."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "scanned"
    mark_git_checkout(source)
    module = source / "zz_real_scan_mod_ash_plugins.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(source))
    named = source / ".ash" / ".ash.yaml"
    named.parent.mkdir(parents=True, exist_ok=True)
    named.write_text(
        "project_name: named\nash_plugin_modules:\n  - zz_real_scan_mod_ash_plugins\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=str(named), source_dir=source)

    assert "zz_real_scan_mod_ash_plugins" not in list(config.ash_plugin_modules)
    ignoring = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring ash_plugin_modules")
    ]
    assert ignoring, caplog.text
    assert all(
        "the file is inside the scanned tree" in line
        and "it resolves inside the scanned tree" in line
        for line in ignoring
    ), ignoring
    assert not any("given root" in line for line in ignoring), ignoring


def test_a_load_whose_trees_come_from_also_scanned_speaks_those_trees(
    tmp_path, monkeypatch, caplog
):
    """No root, no source directory, no working directory, but also_scanned
    names a repository (the shape report readers use): the files the
    confinement judges sit inside those trees, so no sandbox or settle line
    may claim a scanned tree the load never had, and the module line speaks
    the same membership. The trees decide the wording whether they came from
    a root or from also_scanned."""
    from automated_security_helper.config import (
        resolve_config as resolve_config_module,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    (repo / "zz_also_mod_ash_plugins.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(repo))
    named = repo / ".ash" / ".ash.yaml"
    named.parent.mkdir(parents=True)
    named.write_text(
        "sandbox:\n  extra_read_paths:\n    - /zz-also-read\n"
        "ash_plugin_modules:\n  - zz_also_mod_ash_plugins\n"
        "scanners:\n  detect-secrets:\n    options:\n"
        "      max_worker_output_mib: 4096\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(resolve_config_module, "working_directory", lambda: None)

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=str(named), also_scanned=[repo])

    # Premises: all three writes were confined.
    assert "/zz-also-read" not in [
        str(p) for p in config.sandbox.extra_read_paths or []
    ]
    assert "zz_also_mod_ash_plugins" not in list(config.ash_plugin_modules or [])
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring")
    ]
    assert lines, caplog.text
    assert all("the file is inside the given root's trees" in line for line in lines), (
        lines
    )
    assert not any(
        "inside the scanned tree" in line or "read as the scanned tree" in line
        for line in lines
    ), lines


_LINKED_ENV_CONFIG_TEXT = (
    "project_name: outside\n"
    "sandbox:\n  extra_read_paths:\n    - /zz-link-read\n"
    "reporters:\n  aws-security-hub:\n    enabled: true\n"
    "    options:\n      aws_region: zz-link-region\n"
)


def _linked_env_config(
    tmp_path, through_link, text=_LINKED_ENV_CONFIG_TEXT, link_at=".ash/ash.yaml"
):
    """A checkout plus an ASH_CONFIG target outside it that writes a sandbox
    grant and an off-host reporter (or the given text); named through an
    in-tree link (at the discovery name unless *link_at* says otherwise), or
    directly."""
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    target = tmp_path / "elsewhere" / "cfg.yaml"
    target.parent.mkdir()
    target.write_text(text, encoding="utf-8")
    if not through_link:
        return checkout, target
    link = checkout / link_at
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(target)
    except OSError:
        # Windows without symlink privilege raises here; the cells that take
        # the link route cannot run there, like this file's other link cells.
        pytest.skip("cannot create symlinks on this platform")
    return checkout, link


def test_an_ash_config_link_in_the_tree_names_the_repositorys_file(
    tmp_path, monkeypatch
):
    """The carried names judge the ASH_CONFIG file by the name that reached
    it as well as by where it resolves: named through a link inside the
    scanned tree, the outside target is the repository's, so its sandbox
    grant and off-host reporter stay out. Dropping Path(ASH_CONFIG) from the
    carried names survives every other cell (the verify's surviving mutant);
    this pair is its kill, with the direct-name control proving the drop is
    the LINK's doing."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
        SecurityHubReporter,
    )

    checkout, named = _linked_env_config(tmp_path, through_link=True)
    monkeypatch.setenv("ASH_CONFIG", str(named))
    config = resolve_config(source_dir=checkout)
    assert config.project_name == "outside"
    assert "/zz-link-read" not in [
        str(p) for p in config.sandbox.extra_read_paths or []
    ]
    section = reporter_section(config, SecurityHubReporter)
    plain = section if isinstance(section, dict) else {}
    assert plain.get("enabled") is not True, section
    assert (plain.get("options") or {}).get("aws_region") != "zz-link-region", section


def test_control_the_linked_target_named_directly_is_the_operators(
    tmp_path, monkeypatch
):
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
        SecurityHubReporter,
    )

    checkout, named = _linked_env_config(tmp_path, through_link=False)
    monkeypatch.setenv("ASH_CONFIG", str(named))
    config = resolve_config(source_dir=checkout)
    assert "/zz-link-read" in [str(p) for p in config.sandbox.extra_read_paths or []]
    section = reporter_section(config, SecurityHubReporter)
    plain = section if isinstance(section, dict) else {}
    assert plain.get("enabled") is True, section
    assert (plain.get("options") or {}).get("aws_region") == "zz-link-region", section


_LINKED_SCANNER_LIMIT_TEXT = (
    "project_name: outside\n"
    "scanners:\n  detect-secrets:\n    options:\n      max_worker_output_mib: 1024\n"
)


def _ignored_write_lines(caplog):
    return [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring")
        and "scanners.detect-secrets.options.max_worker_output_mib"
        in record.getMessage()
    ]


def test_a_linked_ash_configs_operator_only_write_is_recorded_as_ignored(
    tmp_path, monkeypatch, caplog
):
    """The per-file layer judges the
    ASH_CONFIG file by the name that reached it, so the operator-only scanner
    option a file reached through an in-tree link writes is stripped AND recorded, and
    the load names it as the repository's ignored write. The settled value
    alone cannot show this layer, because the resolve-level confinement keeps
    the option out on its own; the record is what only the per-file judgment
    produces. Judging the file by where it resolves instead (outside the
    tree) leaves the write unrecorded and the naming silent."""
    checkout, named = _linked_env_config(
        tmp_path, through_link=True, text=_LINKED_SCANNER_LIMIT_TEXT
    )
    monkeypatch.setenv("ASH_CONFIG", str(named))

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=checkout)

    assert config.project_name == "outside"
    assert _ignored_write_lines(caplog), caplog.text


def test_control_the_linked_target_named_directly_records_no_ignored_write(
    tmp_path, monkeypatch, caplog
):
    checkout, named = _linked_env_config(
        tmp_path, through_link=False, text=_LINKED_SCANNER_LIMIT_TEXT
    )
    monkeypatch.setenv("ASH_CONFIG", str(named))

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=checkout)

    assert config.project_name == "outside"
    assert _ignored_write_lines(caplog) == [], caplog.text


def _selected_config_in_the_tree(checkout):
    selected = checkout / "selected.yaml"
    selected.write_text("project_name: selected\n", encoding="utf-8")
    return selected


def test_a_selected_config_takes_nothing_from_an_ash_config_link_in_the_tree(
    tmp_path, monkeypatch
):
    """A config file selected inside the scanned tree gets its sandbox grants
    from the trusted base. When ASH_CONFIG is named through a link inside the
    same tree, the repository chose that file too, so its grant is not the
    trusted base and the selected config ends up with none."""
    checkout, named = _linked_env_config(tmp_path, through_link=True)
    monkeypatch.setenv("ASH_CONFIG", str(named))
    selected = _selected_config_in_the_tree(checkout)

    config = resolve_config(config_path=str(selected), source_dir=checkout)

    assert config.project_name == "selected"
    assert "/zz-link-read" not in [
        str(p) for p in config.sandbox.extra_read_paths or []
    ]


def test_control_a_selected_config_takes_the_grant_of_an_ash_config_named_directly(
    tmp_path, monkeypatch
):
    checkout, named = _linked_env_config(tmp_path, through_link=False)
    monkeypatch.setenv("ASH_CONFIG", str(named))
    selected = _selected_config_in_the_tree(checkout)

    config = resolve_config(config_path=str(selected), source_dir=checkout)

    assert config.project_name == "selected"
    assert "/zz-link-read" in [str(p) for p in config.sandbox.extra_read_paths or []]


_LINKED_BEDROCK_PATCH_TEXT = (
    "project_name: outside\n"
    "reporters:\n  bedrock-summary-reporter:\n    enabled: true\n"
    "    options:\n      aws_region: us-east-1\n"
    "      model_id: zz-link-model-written\n"
    "patch:\n"
    "  - op: replace\n"
    "    path: /reporters/bedrock-summary-reporter/options/model_id\n"
    "    value: zz-link-model-patched\n"
)


def test_a_bedrock_deep_patch_in_an_ash_config_link_in_the_tree_stays_out(
    tmp_path, monkeypatch
):
    """The off-host Bedrock section an ASH_CONFIG file reaches through a link
    inside the scanned tree, with a patch operation setting a deeply nested
    option, is the repository's: the reporter runs with the operator's
    section, not the enabled flag or the patched model."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
        BedrockSummaryReporter,
    )

    checkout, named = _linked_env_config(
        tmp_path, through_link=True, text=_LINKED_BEDROCK_PATCH_TEXT
    )
    monkeypatch.setenv("ASH_CONFIG", str(named))
    config = resolve_config(source_dir=checkout)
    assert config.project_name == "outside"
    section = reporter_section(config, BedrockSummaryReporter)
    plain = section if isinstance(section, dict) else {}
    assert plain.get("enabled") is not True, section
    assert (plain.get("options") or {}).get("model_id") != "zz-link-model-patched", (
        section
    )


def test_control_a_bedrock_deep_patch_in_an_ash_config_named_directly_applies(
    tmp_path, monkeypatch
):
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
        BedrockSummaryReporter,
    )

    checkout, named = _linked_env_config(
        tmp_path, through_link=False, text=_LINKED_BEDROCK_PATCH_TEXT
    )
    monkeypatch.setenv("ASH_CONFIG", str(named))
    config = resolve_config(source_dir=checkout)
    section = reporter_section(config, BedrockSummaryReporter)
    plain = section if isinstance(section, dict) else {}
    assert plain.get("enabled") is True, section
    assert (plain.get("options") or {}).get("model_id") == "zz-link-model-patched", (
        section
    )


_LINKED_NETWORK_TEXT = (
    "project_name: outside\nsandbox:\n  network_scanners:\n    - zz-link-net\n"
)


def test_a_sandbox_network_grant_in_an_ash_config_link_in_the_tree_stays_out(
    tmp_path, monkeypatch
):
    """A network_scanners list in the ASH_CONFIG file reached through a link
    inside the scanned tree is the repository's, so it can only remove
    network: the grant is the trusted base's (unset), and the list survives
    only as the limit."""
    checkout, named = _linked_env_config(
        tmp_path, through_link=True, text=_LINKED_NETWORK_TEXT
    )
    monkeypatch.setenv("ASH_CONFIG", str(named))
    config = resolve_config(source_dir=checkout)
    assert config.project_name == "outside"
    assert "zz-link-net" not in (config.sandbox.network_scanners or [])


def test_control_a_sandbox_network_grant_in_an_ash_config_named_directly_applies(
    tmp_path, monkeypatch
):
    checkout, named = _linked_env_config(
        tmp_path, through_link=False, text=_LINKED_NETWORK_TEXT
    )
    monkeypatch.setenv("ASH_CONFIG", str(named))
    config = resolve_config(source_dir=checkout)
    assert config.project_name == "outside"
    assert config.sandbox.network_scanners == ["zz-link-net"]


def test_an_ash_config_link_at_a_plain_name_with_no_discovered_config_stays_out(
    tmp_path, monkeypatch
):
    """Every other link cell puts the link
    at the discovery name, so the tree always has a discovered config chain.
    Here the link sits at a plain name (checkout/cfg.yaml), no config is
    discoverable and none is selected, so the load takes the no-config arm,
    which must carry the name that reached the ASH_CONFIG file just as the
    chain arm does: the outside target is the repository's, and its network
    grant stays out. The direct-name twin above shows the same text applies
    when the operator names the target itself."""
    checkout, named = _linked_env_config(
        tmp_path, through_link=True, text=_LINKED_NETWORK_TEXT, link_at="cfg.yaml"
    )
    assert not (checkout / ".ash" / "ash.yaml").exists()
    monkeypatch.setenv("ASH_CONFIG", str(named))

    config = resolve_config(source_dir=checkout)

    assert config.project_name == "outside"
    assert "zz-link-net" not in (config.sandbox.network_scanners or [])


def test_the_get_config_shapes_sandbox_drop_speaks_the_checkout_rule(
    tmp_path, monkeypatch, caplog
):
    """The sandbox half of the caller-known no-tree flag, pinned on its own:
    a foreign checkout base's grant is dropped with the checkout wording and
    never the scanned-tree claim. The flag's committed cell asserted only the
    output limit, so reverting the sandbox call's flag alone turned nothing
    red (the verify's surviving half-mutant); this cell is that kill."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "scanned"
    mark_git_checkout(source)
    foreign = tmp_path / "foreign"
    mark_git_checkout(foreign)
    base = foreign / "base.yaml"
    base.write_text(
        "sandbox:\n  extra_read_paths:\n    - /zz-foreign-read\n",
        encoding="utf-8",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(f"extends:\n  - {base.as_posix()}\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=str(operator),
            source_dir=source,
            scanned_root=None,
            no_scanned_tree=True,
        )

    assert "/zz-foreign-read" not in [
        str(p) for p in config.sandbox.extra_read_paths or []
    ]
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring")
        and "extra_read_paths" in record.getMessage()
    ]
    assert lines, caplog.text
    assert all("the file is in a checkout" in line for line in lines), lines
    assert not any("inside the scanned tree" in line for line in lines), lines


def test_a_fail_closed_chain_read_tolerates_a_misfit_the_load_accepts(
    tmp_path, monkeypatch
):
    """The no-tree readers' construction: a patch op that fits only one view
    (a remove indexing into a value a repository base holds as a scalar)
    loads under the real confine pair, so a fail-closed read of the same
    chain (``repository_settings_for_root(None)``, the construction every
    reader with no working directory uses) must tolerate the same misfit
    instead of refusing a chain the load it describes accepted. Reverting
    the fail-closed confine turns this red."""
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.config.operator_only_options import (
        repository_settings_for_root,
    )

    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    base = checkout / "cfg" / "repo-base.yaml"
    base.parent.mkdir(parents=True)
    base.write_text(
        "reporters:\n  aws-security-hub:\n    options:\n"
        "      findings_scope: zz-scalar\n",
        encoding="utf-8",
    )
    own = tmp_path / "own.yaml"
    own.write_text(
        "project_name: op\n"
        "reporters:\n  aws-security-hub:\n    enabled: true\n"
        "    options:\n      aws_region: us-east-1\n"
        "      findings_scope:\n        - a\n        - b\n",
        encoding="utf-8",
    )
    root = tmp_path / "operator.yaml"
    root.write_text(
        f"extends:\n  - {own.as_posix()}\n  - {base.as_posix()}\n"
        "patch:\n"
        "  - op: remove\n"
        "    path: /reporters/aws-security-hub/options/findings_scope/0\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(root))
    settings = repository_settings_for_root(None)
    views: list = []
    get_default_config(
        settings.confine, views=views, repository_file=settings.is_repository_file
    )
    assert views, "the load carried no views"
    chain = views[0][0]
    assert {Path(p).resolve() for p in chain} >= {
        root.resolve(),
        own.resolve(),
        base.resolve(),
    }, chain


def test_the_default_load_appends_views_exactly_when_a_chain_exists(
    tmp_path, monkeypatch
):
    """The carried-views invariant the membership judgments rest on: with
    ASH_CONFIG set to a usable file, get_default_config appends exactly one
    views tuple before its return; a name that does not load RAISES, never
    returning defaults with an empty carry -- a silent empty chain would make
    the in-tree judgment empty and let the trusted base trust an in-tree
    ASH_CONFIG file itself; unset or empty, the defaults return with nothing
    appended, since no chain exists to judge."""
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    good = tmp_path / "ops" / "cfg.yaml"
    good.parent.mkdir()
    good.write_text("project_name: from-env\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(good))
    views: list = []
    config = get_default_config(views=views)
    assert config.project_name == "from-env"
    assert len(views) == 1, views
    assert any(Path(p).resolve() == good.resolve() for p in views[0][0]), views

    missing: list = []
    monkeypatch.setenv("ASH_CONFIG", str(tmp_path / "missing.yaml"))
    with pytest.raises(ASHConfigValidationError):
        get_default_config(views=missing)
    assert missing == []

    bad = tmp_path / "bad.yaml"
    bad.write_text("{{{\n", encoding="utf-8")
    unparsed: list = []
    monkeypatch.setenv("ASH_CONFIG", str(bad))
    with pytest.raises(ASHConfigValidationError):
        get_default_config(views=unparsed)
    assert unparsed == []

    empty: list = []
    monkeypatch.setenv("ASH_CONFIG", "")
    assert get_default_config(views=empty) is not None
    assert empty == []
    unset: list = []
    monkeypatch.delenv("ASH_CONFIG")
    assert get_default_config(views=unset) is not None
    assert unset == []


def test_the_selected_branch_never_reresolves_the_default_chain(tmp_path, monkeypatch):
    """The membership judgments and the files-read listing travel OUT of the
    one confined load (the carried views and slice), so resolving a selected
    config -- here inside a checkout with no working directory and ASH_CONFIG
    naming an operator file, the shape whose judgments once resolved the chain
    twice -- never re-reads the ASH_CONFIG document. A second resolution could
    skew the chain between the judgments and re-log its warnings. The counter
    sits on the one door a re-resolution would walk through
    (``config_sources.resolve_config_document``, bound at call time), while
    the load's own confined read is bound elsewhere and does not fire it. The
    direct document read below proves the counter live before the zero is
    read. The trusted base's single-load property is the companion cell
    (test_resolve_config_loads_the_default_chain_config_once)."""
    from automated_security_helper.config import config_sources
    from automated_security_helper.config.operator_only_options import (
        repository_settings_for_root,
    )

    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    named = checkout / ".ash" / ".ash.yaml"
    named.parent.mkdir(parents=True, exist_ok=True)
    named.write_text("project_name: named\n", encoding="utf-8")
    env_file = tmp_path / "ops" / "ash-config.yaml"
    env_file.parent.mkdir()
    env_file.write_text("project_name: from-env\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(env_file))
    _delete_cwd(tmp_path, monkeypatch)

    env_reads = []
    real = config_sources.resolve_config_document

    def counted(path, *args, **kwargs):
        if Path(path).resolve() == env_file.resolve():
            env_reads.append(Path(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(config_sources, "resolve_config_document", counted)

    # The counter proves itself live first: a direct document read reaches it.
    settings = repository_settings_for_root(None)
    config_sources.resolve_config_document(
        env_file,
        confine=settings.confine,
        repository_file=settings.is_repository_file,
    )
    assert env_reads, "the counter never fired on a direct document read"
    env_reads.clear()

    files_read: list = []
    config = resolve_config(config_path=named, files_read=files_read)

    assert config.project_name == "named"
    assert env_reads == [], env_reads
    # The carried slice, not a re-resolution, supplied the listing.
    assert env_file.resolve() in {Path(p).resolve() for p in files_read}, files_read


def test_a_client_supplied_drop_speaks_one_sentence_for_either_membership():
    """A client-supplied file is confined because the session's client sent
    its content, wherever the file sits: the membership sentence is the
    client-supplied one for either value of the checkout flag, so a caller's
    choice of which membership variable to pass cannot change the warning."""
    from automated_security_helper.config.sandbox_grants import (
        confinement_membership,
    )

    by_checkout = confinement_membership(checkout_membership=True, client_supplied=True)
    by_tree = confinement_membership(checkout_membership=False, client_supplied=True)

    assert by_checkout == by_tree
    assert "session client" in by_checkout, by_checkout
