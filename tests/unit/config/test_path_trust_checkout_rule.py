# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tool config files, plugin modules and uploaded configs follow the checkout rule.

config/path_trust.py and config/plugin_module_trust.py decide whether the scanned
repository could have written a file with ``sandbox_grants.untrusted_path``, the same
rule config files are judged by: inside any git checkout, or inside the scan root.
"""

import sys
from pathlib import Path

import pytest

from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.config.path_trust import (
    honored_path,
    reset_path_refusal_warnings,
)
from automated_security_helper.config.plugin_module_trust import refusal_reason
from automated_security_helper.config.resolve_config import resolve_config
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


@pytest.fixture(autouse=True)
def _tmp_path_is_outside_every_checkout(tmp_path):
    # A basetemp inside a repository, or a home that is a checkout with TMPDIR
    # under it, would make every refusal here pass for the wrong reason.
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )


def _checkout(path: Path) -> Path:
    # A .git directory holding HEAD: the shape sandbox_grants._git_shaped counts. A
    # bare empty .git directory bounds nothing there, so every refusal below that
    # rests on a checkout would not fire (and every pass that rests on one would
    # pass for the wrong reason). The assert fails the fixture, naming itself, if
    # that shape ever stops counting.
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    mark_git_checkout(path)
    assert in_any_checkout(path), f"{path} is not a checkout to sandbox_grants"
    return path


def test_a_tool_config_in_another_checkout_is_not_passed(tmp_path):
    # Outside the scanned tree, but in a checkout: someone other than the operator
    # can push to it.
    other = _checkout(tmp_path / "rules-repo")
    rules = other / "semgrep.yml"
    rules.write_text("rules: []\n")
    target = tmp_path / "target"
    target.mkdir()
    assert honored_path(str(rules), source_dir=target, key="config") is None


@pytest.mark.parametrize("marker", ["directory", "file"])
def test_a_tool_config_in_a_neighbouring_checkout_is_not_passed(tmp_path, marker):
    # The scan root is mono/app; the file sits in mono/vendor/lib, a checkout
    # outside the scan root with no .git above mono. Only the checkout rule can
    # refuse it. A submodule or linked worktree has a .git file, not a directory.
    mono = tmp_path / "mono"
    app = mono / "app"
    app.mkdir(parents=True)
    lib = mono / "vendor" / "lib"
    lib.mkdir(parents=True)
    if marker == "directory":
        mark_git_checkout(lib)
    else:
        (lib / ".git").write_text("gitdir: ../../.git/modules/lib\n")
    rules = lib / "semgrep.yml"
    rules.write_text("rules: []\n")
    assert honored_path(str(rules), source_dir=app, key="config") is None


def test_without_the_checkout_the_neighbouring_tool_config_is_passed(tmp_path):
    mono = tmp_path / "mono"
    app = mono / "app"
    app.mkdir(parents=True)
    lib = mono / "vendor" / "lib"
    lib.mkdir(parents=True)
    rules = lib / "semgrep.yml"
    rules.write_text("rules: []\n")
    assert honored_path(str(rules), source_dir=app, key="config") == rules.resolve()


def test_a_name_outside_every_checkout_that_resolves_into_one_is_not_passed(
    tmp_path,
):
    other = _checkout(tmp_path / "rules-repo")
    (other / "semgrep.yml").write_text("rules: []\n")
    elsewhere = tmp_path / "etc"
    elsewhere.mkdir()
    link = elsewhere / "semgrep.yml"
    _link(link, other / "semgrep.yml")
    target = tmp_path / "target"
    target.mkdir()
    assert honored_path(str(link), source_dir=target, key="config") is None


def _link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")


def test_a_link_in_the_target_to_a_file_outside_is_not_passed(tmp_path):
    # The repository plants a link and so chooses which host file the tool reads.
    host = tmp_path / "host" / "semgrep.yml"
    host.parent.mkdir()
    host.write_text("rules: []\n")
    target = tmp_path / "target"
    target.mkdir()
    _link(target / ".semgrep.yml", host)
    assert (
        honored_path(str(target / ".semgrep.yml"), source_dir=target, key="config")
        is None
    )


def test_a_link_inside_another_checkout_to_a_file_outside_is_not_passed(tmp_path):
    host = tmp_path / "host" / "semgrep.yml"
    host.parent.mkdir()
    host.write_text("rules: []\n")
    other = _checkout(tmp_path / "rules-repo")
    _link(other / "semgrep.yml", host)
    target = tmp_path / "target"
    target.mkdir()
    assert (
        honored_path(str(other / "semgrep.yml"), source_dir=target, key="config")
        is None
    )


def test_a_tool_config_reached_through_a_link_inside_a_checkout_is_not_passed(
    tmp_path,
):
    # The operator names their own link, which leads to a link inside someone's
    # checkout, which leads on to a file outside: the link in between decides
    # which file the tool reads.
    rules = tmp_path / "semgrep.yml"
    rules.write_text("rules: []\n")
    other = _checkout(tmp_path / "other")
    try:
        (other / "semgrep.yml").symlink_to(rules)
        (tmp_path / "mine.yml").symlink_to(other / "semgrep.yml")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")
    target = tmp_path / "target"
    target.mkdir()
    assert (
        honored_path(str(tmp_path / "mine.yml"), source_dir=target, key="config")
        is None
    )


def test_a_tool_config_outside_every_checkout_and_the_target_is_passed(tmp_path):
    rules = tmp_path / "etc" / "semgrep.yml"
    rules.parent.mkdir()
    rules.write_text("rules: []\n")
    target = tmp_path / "target"
    target.mkdir()
    assert honored_path(str(rules), source_dir=target, key="config") == rules.resolve()


def test_a_plugin_module_in_another_checkout_is_refused(tmp_path, monkeypatch):
    other = _checkout(tmp_path / "plugins-repo")
    package = other / "acme_ash_plugin_checkoutrule"
    package.mkdir()
    (package / "__init__.py").write_text("")
    monkeypatch.syspath_prepend(str(other))
    target = tmp_path / "target"
    target.mkdir()
    try:
        reason = refusal_reason("acme_ash_plugin_checkoutrule", target)
    finally:
        sys.modules.pop("acme_ash_plugin_checkoutrule", None)
    assert reason == (
        f"it is at {package.as_posix()}, and it is inside the git checkout at "
        f"{other.absolute().as_posix()}"
    )


def test_an_installed_module_in_a_virtualenv_inside_a_checkout_is_refused(
    tmp_path, monkeypatch
):
    # A virtualenv kept inside some unrelated checkout: its packages are inside
    # that checkout, so a repository's config cannot import them.
    project = _checkout(tmp_path / "project")
    site = project / ".venv" / "lib" / "python3" / "site-packages"
    package = site / "acme_ash_plugin_venv"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    monkeypatch.syspath_prepend(str(site))
    target = tmp_path / "target"
    target.mkdir()
    try:
        reason = refusal_reason("acme_ash_plugin_venv", target)
    finally:
        sys.modules.pop("acme_ash_plugin_venv", None)
    assert reason is not None
    assert f"the git checkout at {project.absolute().as_posix()}" in reason


def test_an_uploaded_config_outside_every_checkout_cannot_grant(tmp_path):
    """Refused, naming each grant: a file a client supplied that widens the
    sandbox is refused rather than confined (client_config_policy)."""
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    upload = tmp_path / "upload" / "ash.yaml"
    upload.parent.mkdir()
    upload.write_text(
        "project_name: x\nsandbox:\n  mode: bwrap\n"
        "  network_scanners: [checkov]\n  extra_read_paths: ['/']\n"
    )
    target = tmp_path / "target"
    target.mkdir()
    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(config_path=upload, source_dir=target, untrusted_config=True)
    # The refusal gives the reason that applies: a client supplied the file.
    assert "came from an MCP client" in str(refused.value)
    assert "sandbox.network_scanners" in str(refused.value)
    assert "sandbox.extra_read_paths" in str(refused.value)


def _plugin_package(root: Path, name: str) -> None:
    package = root / name
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")


@pytest.mark.parametrize("supplied_by", ["checkout", "mcp-upload"])
def test_one_config_is_confined_by_both_rules(tmp_path, monkeypatch, supplied_by):
    # One config that asks for sandbox grants and for a plugin module the scanned
    # repository could have written. Both rules apply in the same resolution: the
    # grants come from the trusted base, and the module is not imported. The name is
    # inside the plugin namespace, so this filter is what drops it; a name outside it
    # is kept for the scan's exit-3 refusal (test_refused_plugin_modules_in_tree.py).
    target = tmp_path / "target"
    target.mkdir()
    module = f"acme_combined_{supplied_by.replace('-', '_')}_ash_plugins"
    _plugin_package(target / "plugins", module)
    monkeypatch.syspath_prepend(str(target / "plugins"))
    text = (
        "project_name: x\nsandbox:\n  mode: bwrap\n"
        "  network_scanners: [checkov]\n  extra_read_paths: ['/']\n"
        f"ash_plugin_modules: [{module}]\n"
    )
    if supplied_by == "checkout":
        config_path = _checkout(tmp_path / "ops") / "ash.yaml"
        untrusted = False
    else:
        config_path = tmp_path / "upload" / "ash.yaml"
        config_path.parent.mkdir()
        untrusted = True
    config_path.write_text(text)
    if untrusted:
        # A file a client supplied that widens the sandbox is refused rather
        # than confined (client_config_policy), before any module is imported.
        from automated_security_helper.core.exceptions import (
            ASHConfigFieldDeniedError,
        )

        with pytest.raises(ASHConfigFieldDeniedError, match="sandbox"):
            resolve_config(
                config_path=config_path, source_dir=target, untrusted_config=True
            )
        assert module not in sys.modules
        return
    try:
        config = resolve_config(
            config_path=config_path, source_dir=target, untrusted_config=untrusted
        )
    finally:
        sys.modules.pop(module, None)
    assert config.sandbox.mode == "bwrap"
    assert config.sandbox.network_scanners is None
    assert config.sandbox.extra_read_paths == []
    assert module not in config.ash_plugin_modules


# --- Who named the path ------------------------------------------------------
#
# The rule: a tool config path the operator named (--config-overrides,
# a config file outside every git checkout and the scanned directory, an
# environment variable) is honored from another checkout, such as an ops
# repository. It is refused only inside the scanned tree itself or when an MCP
# client delivered it. A path a config file inside any git checkout or the scanned
# directory names keeps the stricter rule: such a file may not grant sandbox access
# either (sandbox_grants.repository_written), so it does not name paths as the
# operator.

CHECKOV_KEY = "scanners.checkov.options.config_file"


def _ops_rules(tmp_path: Path) -> Path:
    ops = _checkout(tmp_path / "ops")
    rules = ops / "checkov.yaml"
    rules.write_text("framework: [terraform]\n")
    return rules


def _scanned_checkout(tmp_path: Path, config: str = "project_name: scanned\n") -> Path:
    target = _checkout(tmp_path / "target")
    (target / ".ash").mkdir()
    (target / ".ash" / ".ash.yaml").write_text(config)
    return target


def _honored(value, target, config, key=CHECKOV_KEY):
    # The spelling the config documents and overrides above use (``as_posix()``):
    # ``OperatorPaths.named`` matches the value the config holds as written, and a
    # Windows ``str(path)`` has backslashes, so it would name no operator option.
    spelled = value.as_posix() if isinstance(value, Path) else str(value)
    return honored_path(spelled, source_dir=target, key=key, config=config)


def _config_naming(path: Path, rules: Path) -> Path:
    path.write_text(
        f"project_name: ops\nscanners:\n  checkov:\n    options:\n"
        f"      config_file: {rules.as_posix()}\n"
    )
    return path


def test_a_config_file_in_an_ops_checkout_does_not_name_a_tool_config_in_it(tmp_path):
    rules = _ops_rules(tmp_path)
    config_file = _config_naming(rules.parent / "ash.yaml", rules)
    target = _scanned_checkout(tmp_path)
    config = resolve_config(config_path=config_file, source_dir=target)
    assert _honored(rules, target, config) is None


def test_an_operator_config_file_names_a_tool_config_in_an_ops_checkout(tmp_path):
    rules = _ops_rules(tmp_path)
    outside = tmp_path / "etc"
    outside.mkdir()
    operator = _config_naming(outside / "ash.yaml", rules)
    target = _scanned_checkout(tmp_path)
    config = resolve_config(config_path=operator, source_dir=target)
    assert _honored(rules, target, config) == rules.resolve()


def test_an_override_names_a_tool_config_in_another_checkout(tmp_path):
    rules = _ops_rules(tmp_path)
    target = _scanned_checkout(tmp_path)
    config = resolve_config(
        source_dir=target,
        config_overrides=[f"{CHECKOV_KEY}={rules.as_posix()}"],
    )
    assert _honored(rules, target, config) == rules.resolve()


def test_an_environment_variable_names_a_file_in_another_checkout(tmp_path):
    rules = _ops_rules(tmp_path)
    target = _scanned_checkout(tmp_path)
    config = resolve_config(source_dir=target)
    assert _honored(rules, target, config, key="TRIVY_IGNOREFILE") == rules.resolve()


def test_a_repository_config_still_cannot_name_a_file_in_another_checkout(
    tmp_path, caplog
):
    rules = _ops_rules(tmp_path)
    target = _scanned_checkout(
        tmp_path,
        f"project_name: scanned\nscanners:\n  checkov:\n    options:\n"
        f"      config_file: {rules.as_posix()}\n",
    )
    config = resolve_config(source_dir=target)
    caplog.set_level("WARNING")
    assert _honored(rules, target, config) is None
    messages = [r.getMessage() for r in caplog.records if "Ignoring" in r.getMessage()]
    # Two steps refuse it, each in its own warning: resolution drops the
    # repository's config_file (tool_config_trust), naming the config that set
    # it, and the path check refuses the file it names (path_trust), naming the
    # checkout that file is in. Both end with the same remedy.
    config_file = (target / ".ash" / ".ash.yaml").as_posix()
    assert len(messages) == 2, messages
    assert any(f"from {config_file}:" in message for message in messages), messages
    assert any("inside the git checkout at" in message for message in messages), (
        messages
    )
    for message in messages:
        assert message.endswith(KEEP_A_SETTING), message


def test_an_operator_named_file_inside_the_scanned_tree_is_still_refused(
    tmp_path, caplog
):
    target = _scanned_checkout(tmp_path)
    rules = target / "vendor" / "checkov.yaml"
    rules.parent.mkdir()
    rules.write_text("framework: [terraform]\n")
    config = resolve_config(
        source_dir=target, config_overrides=[f"{CHECKOV_KEY}={rules.as_posix()}"]
    )
    caplog.set_level("WARNING")
    assert _honored(rules, target, config) is None
    (message,) = [
        r.getMessage() for r in caplog.records if "Ignoring" in r.getMessage()
    ]
    assert "inside the scanned tree" in message
    assert "whoever names it" not in message


def test_the_outer_checkout_of_a_submodule_scan_root_is_the_scanned_tree(tmp_path):
    # Scanning mono/vendor/lib, a submodule: the superproject is scanned too.
    mono = _checkout(tmp_path / "mono")
    lib = mono / "vendor" / "lib"
    lib.mkdir(parents=True)
    (lib / ".git").write_text("gitdir: ../../.git/modules/lib\n")
    rules = mono / "ops" / "checkov.yaml"
    rules.parent.mkdir()
    rules.write_text("framework: [terraform]\n")
    config = resolve_config(
        source_dir=lib, config_overrides=[f"{CHECKOV_KEY}={rules.as_posix()}"]
    )
    assert _honored(rules, lib, config) is None


def test_with_a_repository_base_only_the_operator_files_own_value_counts(tmp_path):
    rules = _ops_rules(tmp_path)
    target = _scanned_checkout(tmp_path)
    (target / ".ash" / "base.yaml").write_text(
        f"project_name: scanned\nscanners:\n  checkov:\n    options:\n"
        f"      config_file: {rules.as_posix()}\n"
    )
    inherited = tmp_path / "inherits.yaml"
    inherited.write_text("project_name: op\nextends: target/.ash/base.yaml\n")
    config = resolve_config(config_path=inherited, source_dir=target)
    assert _honored(rules, target, config) is None
    own = tmp_path / "own.yaml"
    own.write_text(
        f"project_name: op\nextends: target/.ash/base.yaml\nscanners:\n  checkov:\n"
        f"    options:\n      config_file: {rules.as_posix()}\n"
    )
    config = resolve_config(config_path=own, source_dir=target)
    assert _honored(rules, target, config) == rules.resolve()


def test_an_mcp_clients_overrides_are_not_the_operators(tmp_path):
    rules = _ops_rules(tmp_path)
    target = _scanned_checkout(tmp_path)
    config = resolve_config(
        source_dir=target,
        config_overrides=[f"{CHECKOV_KEY}={rules.as_posix()}"],
        client_overrides=True,
    )
    assert _honored(rules, target, config) is None


def test_a_file_url_entry_the_operator_named_counts_by_its_file(tmp_path):
    ops = _checkout(tmp_path / "ops")
    plugin = ops / "plugin.py"
    plugin.write_text("")
    target = _scanned_checkout(tmp_path)
    key = "scanners.detect-secrets.options.scan_settings.plugins_used[].path"
    config = resolve_config(
        source_dir=target,
        config_overrides=[
            (
                "scanners.detect-secrets.options.scan_settings.plugins_used="
                f'[{{"name": "Mine", "path": "file://{plugin.as_posix()}"}}]'
            )
        ],
    )
    assert _honored(plugin, target, config, key=key) == plugin.resolve()


def test_a_value_the_operators_config_does_not_set_is_not_the_operators(tmp_path):
    # Every config file here is the operator's, but detect-secrets also checks
    # entries it read from a .secrets.baseline in the scanned tree under the same
    # key. Such an entry is not in the operator's config, so it follows the
    # stricter rule and cannot point at a file in someone's checkout.
    ops = _checkout(tmp_path / "ops")
    plugin = ops / "plugin.py"
    plugin.write_text("")
    operator = tmp_path / "ash.yaml"
    operator.write_text("project_name: op\n")
    target = _scanned_checkout(tmp_path)
    config = resolve_config(config_path=operator, source_dir=target)
    key = "scanners.detect-secrets.options.scan_settings.plugins_used[].path"
    assert _honored(plugin, target, config, key=key) is None
    assert _honored(plugin, target, config, key=CHECKOV_KEY) is None


# --- A Homebrew prefix that is itself a checkout ------------------------------
#
# On Apple Silicon, Homebrew's prefix (/opt/homebrew) is a clone of Homebrew/brew,
# so its etc/ and lib/pythonX/site-packages/ are inside a git checkout. The layout
# is simulated here, so this runs on every platform.


def _homebrew_prefix(tmp_path: Path) -> Path:
    prefix = _checkout(tmp_path / "opt" / "homebrew")
    (prefix / "Library" / "Homebrew").mkdir(parents=True)
    (prefix / "etc").mkdir()
    return prefix


def test_a_tool_config_the_operator_keeps_in_the_homebrew_prefix_is_passed(
    tmp_path,
):
    prefix = _homebrew_prefix(tmp_path)
    rules = prefix / "etc" / "checkov.yaml"
    rules.write_text("framework: [terraform]\n")
    target = _scanned_checkout(tmp_path)
    config = resolve_config(
        source_dir=target, config_overrides=[f"{CHECKOV_KEY}={rules.as_posix()}"]
    )
    assert _honored(rules, target, config) == rules.resolve()


def test_a_repository_config_cannot_name_a_file_in_the_homebrew_prefix(tmp_path):
    prefix = _homebrew_prefix(tmp_path)
    rules = prefix / "etc" / "checkov.yaml"
    rules.write_text("framework: [terraform]\n")
    target = _scanned_checkout(
        tmp_path,
        f"project_name: scanned\nscanners:\n  checkov:\n    options:\n"
        f"      config_file: {rules.as_posix()}\n",
    )
    config = resolve_config(source_dir=target)
    assert _honored(rules, target, config) is None


def test_a_module_in_the_homebrew_prefix_counts_as_inside_a_checkout(
    tmp_path, monkeypatch
):
    # Today's rule, pending a decision: a repository's config cannot import a
    # module installed under the Homebrew prefix, as for any virtualenv inside a
    # checkout. --ash-plugin-modules and an operator config are unaffected.
    prefix = _homebrew_prefix(tmp_path)
    site = prefix / "lib" / "python3.12" / "site-packages"
    package = site / "acme_ash_plugin_brew"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    monkeypatch.syspath_prepend(str(site))
    target = _scanned_checkout(tmp_path)
    try:
        reason = refusal_reason("acme_ash_plugin_brew", target)
    finally:
        sys.modules.pop("acme_ash_plugin_brew", None)
    assert reason is not None
    assert f"the git checkout at {prefix.absolute().as_posix()}" in reason


@pytest.mark.parametrize("patched", [False, True])
def test_a_session_profile_a_client_patched_is_not_the_operators(tmp_path, patched):
    # select_profile writes the operator's profile, plus any patch_ops or
    # override_yaml the client sent, into the session's config/ directory. With
    # a patch in it, a tool path it names is not the operator's.
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.config.ash_config import AshConfig

    rules = _ops_rules(tmp_path)
    profile = tmp_path / "session" / "config" / "ash.yaml"
    profile.parent.mkdir(parents=True)
    profile.write_text(
        f"project_name: profile\nscanners:\n  checkov:\n    options:\n"
        f"      config_file: {rules.as_posix()}\n"
    )
    profile_registry.bind_session_config(
        "test-patched-profile",
        config=AshConfig(),
        profile_name="test-patched-profile",
        patch_ops=[{"op": "add", "path": "/x", "value": 1}] if patched else None,
        config_path=profile.as_posix(),
    )
    try:
        target = _scanned_checkout(tmp_path)
        config = resolve_config(config_path=profile, source_dir=target)
        honored = _honored(rules, target, config)
    finally:
        with profile_registry._session_lock:
            profile_registry._session_state.pop("test-patched-profile", None)
    assert (honored is None) is patched


def test_a_section_spelled_in_another_case_is_the_same_scanners_section(tmp_path):
    """A plugin section the operator spells ``Checkov`` is read by the
    configuration as the checkov scanner's (``folded_section_name``: ASCII case
    and the ``-`` / ``_`` separators dropped), so the path it names is the
    operator's under the key the scanner asks about. The fold applies to the
    section name under a plugin segment only: a top-level key in another case
    (``Scanners``) is another key, and an option spelled with a hyphen is the
    same option as before."""
    from automated_security_helper.config.path_trust import OperatorPaths

    record = OperatorPaths(
        documents=[
            {"scanners": {"Checkov": {"options": {"config_file": "/ops/c.yaml"}}}}
        ]
    )
    assert record.named(CHECKOV_KEY, "/ops/c.yaml")
    record = OperatorPaths(
        documents=[
            {"Scanners": {"checkov": {"options": {"config_file": "/ops/c.yaml"}}}}
        ]
    )
    assert not record.named(CHECKOV_KEY, "/ops/c.yaml")
    record = OperatorPaths(
        documents=[
            {"scanners": {"checkov": {"options": {"config-file": "/ops/c.yaml"}}}}
        ]
    )
    assert record.named(CHECKOV_KEY, "/ops/c.yaml")


@pytest.mark.parametrize(
    "raw", ["/ops/c.yaml", "'/ops/c.yaml'", "/ops/c.yaml # note", "[a, b]"]
)
def test_an_override_is_recorded_as_it_is_applied(raw):
    from automated_security_helper.config.path_trust import parse_overrides
    from automated_security_helper.config.resolve_config import _parse_config_value

    assert parse_overrides([f"{CHECKOV_KEY}={raw}"]) == [
        (CHECKOV_KEY, _parse_config_value(raw))
    ]
    assert parse_overrides([f"{CHECKOV_KEY}+={raw}"])[0][0] == CHECKOV_KEY
