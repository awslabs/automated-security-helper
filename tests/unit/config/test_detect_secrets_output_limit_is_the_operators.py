# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Only the operator sets detect-secrets' worker output limit, and only to 4096.

``scanners.detect-secrets.options.max_worker_output_mib`` bounds how much of the
worker's output file ASH reads back, and reading costs about three times the
file's size in memory. The limit is taken only from --config-overrides or a config
file outside the scanned tree and every git checkout, as the reporter options in
config/operator_only_options.py are, and the operator cannot set it past 4096.
What a config file inside the tree or inside any other git checkout writes for it,
any value, is left out of the configuration before it is validated, with one
warning; what a file outside both writes is kept
(test_an_operator_file_in_another_checkout_sets_no_operator_only_option.py holds
the cells for a file in another checkout or a delivered one).
"""

import contextlib
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator, List

import pytest

from tests.utils.helpers import mark_git_checkout

OPTION = "scanners.detect-secrets.options.max_worker_output_mib"

# os.rmdir of the process's working directory is PermissionError on Windows,
# so the deleted-cwd cells cannot set their scene there.
_POSIX_ONLY_CWD_REMOVAL = pytest.mark.skipif(
    sys.platform == "win32", reason="the working directory cannot be removed on Windows"
)


def _checkout(tmp_path: Path, body: str = "") -> Path:
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    if body:
        (checkout / ".ash").mkdir()
        (checkout / ".ash" / ".ash.yaml").write_text(body, encoding="utf-8")
    return checkout


def _setting(limit: "int | str", key: str = "detect-secrets") -> str:
    return f"scanners:\n  {key}:\n    options:\n      max_worker_output_mib: {limit}\n"


_OTHER_OPTION = "scanners:\n  detect-secrets:\n    options:\n      skip_generated_lockfiles: false\n"


def _operator_names_files_under(tmp_path: Path, monkeypatch) -> None:
    """Set the test's directory aside as the operator's.

    A path named to MCP get_config is the client's unless it is in a directory
    ASH_MCP_ALLOWED_CONFIG_ROOTS names (sandbox.client_named_config_is_untrusted),
    and a client's named file is refused instead of shown. The tests that call
    get_config with a named file are about how a file the operator names is
    shown, so they set their directory aside first.
    """
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))


def _limit(config) -> int:
    return config.scanners.detect_secrets.options.max_worker_output_mib


@contextlib.contextmanager
def _warnings() -> Iterator[List[str]]:
    """ASH's warnings while the block runs, as their messages."""
    from automated_security_helper.utils.log import ASH_LOGGER

    messages: List[str] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    handler = _Collect(level=logging.WARNING)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        yield messages
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _about_the_limit(messages: List[str]) -> List[str]:
    return [message for message in messages if "max_worker_output_mib" in message]


@pytest.mark.parametrize("key", ["detect-secrets", "detect_secrets"])
def test_a_file_in_the_tree_does_not_set_the_limit(tmp_path, key):
    """The repository's own .ash/.ash.yaml raises the limit: the scan keeps
    the operator's, 256 by default, and one warning names the option, the file
    and where the operator sets it. Each spelling of the section reaches the
    scanner, so each is ignored."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(tmp_path, _setting(1024, key))

    with _warnings() as messages:
        config = resolve_config(source_dir=checkout)

    assert _limit(config) == 256
    [warning] = _about_the_limit(messages)
    assert f"Ignoring {OPTION}" in warning, warning
    assert ".ash.yaml" in warning, warning
    assert "--config-overrides" in warning, warning


def test_the_same_setting_in_a_file_outside_the_tree_is_kept(tmp_path):
    """The control: the operator's own config file, outside the scanned tree,
    sets the limit, and nothing is ignored."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(tmp_path)
    operator = tmp_path / "operator.yaml"
    operator.write_text(_setting(1024), encoding="utf-8")

    with _warnings() as messages:
        config = resolve_config(config_path=operator, source_dir=checkout)

    assert _limit(config) == 1024
    assert not _about_the_limit(messages), messages


def test_an_override_sets_the_limit_past_a_file_in_the_tree(tmp_path):
    """The control: --config-overrides is the operator's, so its value is kept
    over the one the repository's file wrote, and nothing is ignored."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(tmp_path, _setting(2048))

    with _warnings() as messages:
        config = resolve_config(
            source_dir=checkout,
            config_overrides=[f"{OPTION}=1024"],
        )

    assert _limit(config) == 1024
    assert not _about_the_limit(messages), messages


def test_a_file_in_the_tree_that_leaves_the_limit_alone_warns_nothing(tmp_path):
    """The control: the repository's file sets another of the scanner's
    options; the limit is the default, and no warning names it."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(
        tmp_path,
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        "      skip_generated_lockfiles: false\n",
    )

    with _warnings() as messages:
        config = resolve_config(source_dir=checkout)

    assert _limit(config) == 256
    assert config.scanners.detect_secrets.options.skip_generated_lockfiles is False
    assert not _about_the_limit(messages), messages


@pytest.mark.parametrize("operator_limit", [1024, 64])
def test_a_limit_only_the_operator_s_file_sets_binds_a_silent_tree(
    tmp_path, operator_limit
):
    """The trusted base is the operator's file outside the tree, which sets the
    limit, and the repository's file does not. The limit is the operator's
    whether or not the repository wrote one: a lower cap the operator set
    binds a scan whose repository says nothing, or the option would bound
    nothing. The repository's file wrote nothing to ignore, so no warning
    names it. (Re-pinned: this cell held the scan to the default, 256, when
    the repository was silent; that let a silent repository lift the
    operator's 64 back to 256.)"""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(_setting(operator_limit), encoding="utf-8")

    with _warnings() as messages:
        config = resolve_config(source_dir=checkout, trusted_config_path=operator)

    assert _limit(config) == operator_limit
    assert not _about_the_limit(messages), messages


@pytest.mark.parametrize("repository", ["leaves-it-alone", "sets-another"])
def test_an_operator_file_keeps_its_limit_over_a_repository_base(tmp_path, repository):
    """The operator's file outside the tree sets 1024 and extends the
    repository's .ash/.ash.yaml. That file either sets another of the scanner's
    options or sets the limit too; the operator's file is merged over it either
    way. The limit is the operator's, and no warning charges the repository's
    file or tells the operator to do what their file already does."""
    from automated_security_helper.config.resolve_config import resolve_config

    body = _OTHER_OPTION if repository == "leaves-it-alone" else _setting(2048)
    checkout = _checkout(tmp_path, body)
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n" + _setting(1024),
        encoding="utf-8",
    )

    with _warnings() as messages:
        config = resolve_config(config_path=operator, source_dir=checkout)

    assert _limit(config) == 1024
    assert not _about_the_limit(messages), messages


@pytest.mark.parametrize(
    "trusted", [True, False], ids=["trusted-file-1024", "no-trusted-file"]
)
def test_an_override_of_the_limit_wins_whatever_the_trusted_base_says(
    tmp_path, trusted
):
    """A `--config-overrides` of the limit applies over a silent repository,
    with and without a workspace trusted file that sets its own 1024: the
    override is the operator's last word either way."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(tmp_path, "project_name: checkout\n")
    kwargs = {}
    if trusted:
        operator = tmp_path / "operator.yaml"
        operator.write_text(_setting(1024), encoding="utf-8")
        kwargs["trusted_config_path"] = operator

    config = resolve_config(
        source_dir=checkout, config_overrides=[f"{OPTION}=64"], **kwargs
    )

    assert _limit(config) == 64


def test_a_trusted_file_s_limit_is_the_scan_s_own(tmp_path):
    """The workspace trusted file (``trusted_config_path``) is the
    operator's own configuration, so the limit it writes governs the scan:
    over a silent repository with no override, the scan runs with the
    trusted file's 1024, not the configuration's default -- the operator
    governs their own limit, as an operator ``--config`` file's does."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(_setting(1024), encoding="utf-8")

    config = resolve_config(source_dir=checkout, trusted_config_path=operator)
    plain = resolve_config(source_dir=checkout)

    assert _limit(config) == 1024
    assert _limit(plain) != 1024


@pytest.mark.parametrize("operator_file", ["workspace", "ash-config"])
def test_an_unrelated_override_charges_no_repository_file(
    tmp_path, monkeypatch, operator_file
):
    """The repository's file does not name the limit, and the operator's file
    outside the tree, the trusted base, sets 1024. An override of another
    setting changes nothing about the limit: it is the operator's 1024, and no
    warning names the repository's file. (Re-pinned with the cell above: it
    held 256 here, the default, which a silent repository should not get.)"""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(_setting(1024), encoding="utf-8")
    trusted = {}
    if operator_file == "workspace":
        trusted["trusted_config_path"] = operator
    else:
        monkeypatch.setenv("ASH_CONFIG", str(operator))

    with _warnings() as messages:
        config = resolve_config(
            source_dir=checkout,
            config_overrides=["project_name=renamed"],
            **trusted,
        )

    assert config.project_name == "renamed"
    assert _limit(config) == 1024
    assert not _about_the_limit(messages), messages


@pytest.mark.parametrize("written", ["4097", "0", "abc", "true"])
def test_a_repository_value_the_option_refuses_is_ignored_like_any_other(
    tmp_path, written
):
    """What the repository's file writes for the limit is left out before the
    file is validated, so a value the option refuses (past 4096, not positive,
    not a number) is ignored with the same warning as one it accepts, and the
    rest of the file is the scan's configuration."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(tmp_path, "project_name: checkout\n" + _setting(written))

    with _warnings() as messages:
        config = resolve_config(source_dir=checkout)

    assert config.project_name == "checkout"
    assert _limit(config) == 256
    [warning] = _about_the_limit(messages)
    assert f"Ignoring {OPTION}" in warning, warning
    assert ".ash.yaml" in warning, warning


def test_a_repository_patch_that_sets_the_limit_is_ignored(tmp_path):
    """A `patch` operation in the repository's file writes the limit after the
    file's own keys are merged: it is left out as the keys are."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(
        tmp_path,
        _OTHER_OPTION + "patch:\n"
        "  - op: add\n"
        "    path: /scanners/detect-secrets/options/max_worker_output_mib\n"
        "    value: 4097\n",
    )

    with _warnings() as messages:
        config = resolve_config(source_dir=checkout)

    assert _limit(config) == 256
    assert config.scanners.detect_secrets.options.skip_generated_lockfiles is False
    [warning] = _about_the_limit(messages)
    assert f"Ignoring {OPTION}" in warning, warning


_LIMIT_PATH = "/scanners/detect-secrets/options/max_worker_output_mib"


def _patching_its_base(tmp_path: Path, op: str, value: Any, head: str = "") -> Path:
    """A checkout whose .ash/.ash.yaml extends .ash/base.yaml, which sets the
    limit to 64, and patches the limit with one ``op``."""
    checkout = _checkout(
        tmp_path,
        head
        + "extends: base.yaml\n"
        + f"patch:\n  - op: {op}\n    path: {_LIMIT_PATH}\n"
        + ("" if value is None else f"    value: {value}\n"),
    )
    (checkout / ".ash" / "base.yaml").write_text(_setting(64), encoding="utf-8")
    return checkout


@pytest.mark.parametrize(
    "op,value,head",
    [
        ("replace", 32, ""),
        ("remove", None, ""),
        ("test", 64, ""),
        ("replace", 32, "project_name: ${ASH_TEST_PATCHING_NAME}\n"),
    ],
    ids=["replace", "remove", "test", "beside-a-read-value"],
)
def test_a_repository_patch_at_a_limit_left_out_of_its_base_still_loads(
    tmp_path, monkeypatch, op, value, head
):
    """The base's limit is left out before the extending file's patch applies,
    so the place the patch names is not in the document. The file still loads,
    as it would without the trust rules; the limit is the operator's, with the
    one warning. Beside a value the file reads from the environment, which the
    patch's operations are followed through to place, too."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.setenv("ASH_TEST_PATCHING_NAME", "named-from-the-environment")
    checkout = _patching_its_base(tmp_path, op, value, head)

    with _warnings() as messages:
        config = resolve_config(source_dir=checkout)

    assert _limit(config) == 256
    if head:
        assert config.project_name == "named-from-the-environment"
    [warning] = _about_the_limit(messages)
    assert f"Ignoring {OPTION}" in warning, warning


def test_a_test_of_a_left_out_limit_is_of_what_the_repository_s_files_wrote(
    tmp_path,
):
    """The control: a test the files' own values fail still refuses the file,
    as it would without the trust rules. The base wrote 64, the test says 32."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    checkout = _patching_its_base(tmp_path, "test", 32)

    with pytest.raises(ASHConfigSourceError, match="does not equal the value"):
        resolve_config(source_dir=checkout)


def test_a_repository_patch_tests_its_own_keys_beside_a_left_out_limit(tmp_path):
    """The extending file's own keys are merged before its patch applies, into
    what a test reads as well: its test of its own setting passes, and its
    replace of the base's left-out limit loads."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(
        tmp_path,
        _OTHER_OPTION + "extends: base.yaml\n"
        "patch:\n"
        "  - op: test\n"
        "    path: /scanners/detect-secrets/options/skip_generated_lockfiles\n"
        "    value: false\n"
        f"  - op: replace\n    path: {_LIMIT_PATH}\n    value: 32\n",
    )
    (checkout / ".ash" / "base.yaml").write_text(_setting(64), encoding="utf-8")

    config = resolve_config(source_dir=checkout)

    assert _limit(config) == 256
    assert config.scanners.detect_secrets.options.skip_generated_lockfiles is False


@pytest.mark.parametrize("op", ["replace", "add"])
def test_an_operator_patch_sets_the_limit_over_a_repository_base(tmp_path, op):
    """The operator's file outside the tree extends the repository's file,
    which sets 64, and patches the limit to 32. The repository's 64 is left out
    first, so the replace names a place the document does not hold; it sets the
    limit as the add does, and the limit is the operator's 32."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(tmp_path, _setting(64))
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        f"patch:\n  - op: {op}\n    path: {_LIMIT_PATH}\n    value: 32\n",
        encoding="utf-8",
    )

    with _warnings() as messages:
        config = resolve_config(config_path=operator, source_dir=checkout)

    assert _limit(config) == 32
    assert not _about_the_limit(messages), messages


@pytest.mark.parametrize("extends", [False, True], ids=["alone", "extending-it"])
def test_an_ash_config_file_in_the_tree_does_not_set_the_limit(
    tmp_path, monkeypatch, extends
):
    """With no config file to discover, the configuration is the file
    ASH_CONFIG names. When that file is in the tree, the limit it writes is the
    repository's like any other: the default, with one warning naming it. When
    a file outside the tree that ASH_CONFIG names sets the limit and extends one
    in the tree, the outside file's value is kept."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(tmp_path)
    in_tree = checkout / "configs" / "ash.yaml"
    in_tree.parent.mkdir()
    if extends:
        in_tree.write_text(_OTHER_OPTION, encoding="utf-8")
        named = tmp_path / "env-config.yaml"
        named.write_text(
            f"extends: {in_tree.as_posix()}\n" + _setting(1024), encoding="utf-8"
        )
    else:
        in_tree.write_text(_setting(1024), encoding="utf-8")
        named = in_tree
    monkeypatch.setenv("ASH_CONFIG", str(named))

    with _warnings() as messages:
        config = resolve_config(source_dir=checkout)

    if extends:
        assert _limit(config) == 1024
        assert not _about_the_limit(messages), messages
    else:
        assert _limit(config) == 256
        [warning] = _about_the_limit(messages)
        assert f"Ignoring {OPTION}" in warning, warning


@pytest.mark.parametrize(
    "beside",
    ["no-config-file", "beside-a-config-file", "named-without-the-defaults"],
)
def test_an_ash_config_file_in_the_tree_that_writes_a_refused_limit_still_loads(
    tmp_path, monkeypatch, beside
):
    """ASH_CONFIG names a file in the tree that writes 4097, a limit the option
    refuses. That file is the repository's, so the limit is left out as it is
    read and the file still loads, as one discovered does: with no config file
    to discover, the scan's configuration is that file's, at the default limit;
    beside the repository's .ash/.ash.yaml, which the scan uses, it is read too
    and refuses nothing, as it is for a command that names the config file and
    does not fall back to the defaults (`ash config get`)."""
    from automated_security_helper.config.resolve_config import resolve_config

    alone = beside == "no-config-file"
    checkout = _checkout(tmp_path, "" if alone else "project_name: checkout\n")
    in_tree = checkout / "configs" / "ash.yaml"
    in_tree.parent.mkdir()
    in_tree.write_text(
        "project_name: from-ash-config\n" + _setting(4097), encoding="utf-8"
    )
    monkeypatch.setenv("ASH_CONFIG", str(in_tree))

    with _warnings() as messages:
        if beside == "named-without-the-defaults":
            config = resolve_config(
                config_path=checkout / ".ash" / ".ash.yaml",
                source_dir=checkout,
                fallback_to_default=False,
            )
        else:
            config = resolve_config(source_dir=checkout)

    assert config.project_name == ("from-ash-config" if alone else "checkout")
    assert _limit(config) == 256
    if alone:
        [warning] = _about_the_limit(messages)
        assert f"Ignoring {OPTION}" in warning, warning


def test_the_limit_ash_config_s_file_wrote_is_settled_from_the_read_the_scan_used(
    tmp_path, monkeypatch
):
    """ASH_CONFIG names a file in the tree that writes 1024, and the file
    changes once the scan has read it: the limit is gone from it. The limit the
    configuration holds came from the first read, so that read is the one whose
    limit is left out: the scan keeps the operator's 256 and warns, rather than
    keeping the repository's 1024 because a second read found nothing to leave
    out."""
    from automated_security_helper.config import config_sources
    from automated_security_helper.config import resolve_config as resolve_module

    checkout = _checkout(tmp_path)
    in_tree = checkout / "configs" / "ash.yaml"
    in_tree.parent.mkdir()
    in_tree.write_text(_setting(1024), encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(in_tree))
    real = config_sources.read_config_text
    changed: List[Path] = []

    def read_then_change(path, expect=None):
        text = real(path, expect=expect)
        if not changed and Path(path).resolve() == in_tree.resolve():
            changed.append(Path(path))
            in_tree.write_text(_OTHER_OPTION, encoding="utf-8")
        return text

    monkeypatch.setattr(config_sources, "read_config_text", read_then_change)
    monkeypatch.setattr(resolve_module, "read_config_text", read_then_change)

    with _warnings() as messages:
        config = resolve_module.resolve_config(source_dir=checkout)

    # The control: the file was read once before it changed.
    assert changed
    assert _limit(config) == 256
    [warning] = _about_the_limit(messages)
    assert f"Ignoring {OPTION}" in warning, warning


@pytest.mark.parametrize("source", ["override", "operator-file"])
def test_the_operator_s_own_value_past_4096_is_refused(tmp_path, source):
    """The control: the operator's own surfaces are validated, so 4097 there
    refuses the configuration rather than being ignored."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    checkout = _checkout(tmp_path)
    if source == "override":
        call = {"source_dir": checkout, "config_overrides": [f"{OPTION}=4097"]}
    else:
        operator = tmp_path / "operator.yaml"
        operator.write_text(_setting(4097), encoding="utf-8")
        call = {"config_path": operator, "source_dir": checkout}

    with pytest.raises(ASHConfigValidationError, match="max_worker_output_mib"):
        resolve_config(**call)


@pytest.mark.parametrize("operator_value", [None, 1024])
def test_a_repository_file_that_sets_the_operator_s_own_limit_warns_nothing(
    tmp_path, operator_value
):
    """The repository's file writes exactly the limit the operator's trusted
    base has (the default 256, or the workspace file's 1024): nothing it wrote
    is changed, so nothing is reported ignored."""
    from automated_security_helper.config.resolve_config import resolve_config

    expected = 256 if operator_value is None else operator_value
    checkout = _checkout(tmp_path, _setting(expected))
    trusted = {}
    if operator_value is not None:
        operator = tmp_path / "operator.yaml"
        operator.write_text(_setting(operator_value), encoding="utf-8")
        trusted["trusted_config_path"] = operator

    with _warnings() as messages:
        config = resolve_config(source_dir=checkout, **trusted)

    assert _limit(config) == expected
    assert not _about_the_limit(messages), messages


def _at_the_limit(reference) -> bool:
    """Whether an environment reference of the configuration sits at the
    limit's place, spelled as the confinement compares places."""
    path = (*reference.path, reference.resolved) if reference.key else reference.path
    shown = tuple(
        part.replace("-", "_").lower() if isinstance(part, str) else part
        for part in path
    )
    return shown[:4] == (
        "scanners",
        "detect_secrets",
        "options",
        "max_worker_output_mib",
    )


def test_a_repository_reference_at_the_limit_leaves_no_reference_behind(
    tmp_path, monkeypatch
):
    """The repository's file writes the limit as ${VAR}. The value is left out
    with the rest of what the file wrote there, so the configuration's record of
    what its files read from the environment holds no reference at the limit:
    the limit there is the operator's, and was not read from the variable. The
    warning does not print the variable's value."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.setenv("ASH_TEST_DS_OUTPUT_LIMIT", "3071")
    checkout = _checkout(
        tmp_path, "project_name: checkout\n" + _setting("${ASH_TEST_DS_OUTPUT_LIMIT}")
    )

    with _warnings() as messages:
        config = resolve_config(source_dir=checkout)

    assert _limit(config) == 256
    [warning] = _about_the_limit(messages)
    assert "3071" not in warning, warning
    assert not [
        reference
        for reference in config._environment_references
        if _at_the_limit(reference)
    ]
    assert not [
        reference
        for reference in config._displayed_environment_references
        if _at_the_limit(reference)
    ]


def test_the_record_does_not_name_a_repository_variable_for_the_operator_s_limit(
    tmp_path, monkeypatch
):
    """The repository's file writes the limit as ${VAR}, and the variable holds
    256, the operator's limit too. The scan leaves the repository's value out,
    so its limit is the operator's 256, read from no variable: the record of
    the configuration (a results file's ash_config) holds 256, not the
    repository's ${VAR}, which a reader of the record would resolve again."""
    import json

    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_TEST_DS_OUTPUT_LIMIT", "256")
    checkout = _checkout(
        tmp_path, "project_name: checkout\n" + _setting("${ASH_TEST_DS_OUTPUT_LIMIT}")
    )

    config = resolve_config(source_dir=checkout)

    assert _limit(config) == 256
    recorded = json.loads(
        AshAggregatedResults(ash_config=config).model_dump_json(by_alias=True)
    )["ash_config"]
    options = recorded["scanners"]["detect-secrets"]["options"]
    assert options["max_worker_output_mib"] == 256, options


@pytest.mark.parametrize("kept_by", ["override", "operator-file"])
def test_a_repository_reference_at_a_kept_limit_leaves_no_reference_behind(
    tmp_path, monkeypatch, kept_by
):
    """The repository's file writes the limit as ${VAR}, which the scan leaves
    out, and the operator's own limit is kept: an override's, or that of the
    operator's --config outside the tree, which extends the repository's file.
    No reference at the limit is left in the configuration's record of what
    its files read from the environment, or in what a message or `ash config
    get` shows: the limit there is the operator's 512, read from no variable."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.setenv("ASH_TEST_DS_OUTPUT_LIMIT", "3071")
    checkout = _checkout(
        tmp_path, "project_name: checkout\n" + _setting("${ASH_TEST_DS_OUTPUT_LIMIT}")
    )
    if kept_by == "override":
        config = resolve_config(
            source_dir=checkout,
            config_overrides=[
                "scanners.detect-secrets.options.max_worker_output_mib=512"
            ],
        )
    else:
        operator = tmp_path / "operator.yaml"
        operator.write_text(
            f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
            + _setting(512),
            encoding="utf-8",
        )
        config = resolve_config(config_path=operator, source_dir=checkout)

    assert _limit(config) == 512
    assert not [
        reference
        for reference in config._environment_references
        if _at_the_limit(reference)
    ]
    assert not [
        reference
        for reference in config._displayed_environment_references
        if _at_the_limit(reference)
    ]
    assert not [
        rewrite
        for rewrite in config._written_references or []
        if rewrite.kind == "value" and rewrite.resolved == "3071"
    ]


def test_the_exit_code_fields_are_read_past_a_repository_limit_out_of_range(tmp_path):
    """The scan reads fail_on_findings from its config file as it loads it for
    the scan, so a repository file whose limit the option refuses is still the
    file those fields come from."""
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _resolve_config_fail_on_findings,
    )

    checkout = _checkout(
        tmp_path, "project_name: checkout\nfail_on_findings: false\n" + _setting(4097)
    )
    opts = ScanOptions(source_dir=checkout, output_dir=tmp_path / "out")

    assert _resolve_config_fail_on_findings(opts) is False


def test_config_validate_reports_a_repository_limit_as_the_scan_treats_it(tmp_path):
    """`ash config validate` checks a file the way a scan loads it: the
    repository's limit, out of range or not, is no error, and a warning says the
    scan ignores it."""
    from automated_security_helper.config.config_validator import ConfigValidator

    checkout = _checkout(tmp_path, "project_name: checkout\n" + _setting(4097))

    check = ConfigValidator.check_config_file(
        checkout / ".ash" / ".ash.yaml", source_dir=checkout
    )

    assert not [e for e in check.errors if "max_worker_output_mib" in e], check.errors
    assert [w for w in check.warnings if OPTION in w], check.warnings


@pytest.mark.parametrize(
    "repository, operator, overrides, warned",
    [
        # ASH_CONFIG's file, outside the tree, sets the limit the repository
        # writes: the scan keeps it and says nothing.
        (1024, 1024, [], False),
        # The repository writes the default (as `ash config init` does) and
        # ASH_CONFIG's file raises the limit: the scan warns and uses 1024.
        (256, 1024, [], True),
        # An override sets the limit: the scan keeps it and says nothing.
        (1024, None, [f"{OPTION}=512"], False),
        # The control: nothing else sets it, so the repository's 1024 is the
        # one ignored.
        (1024, None, [], True),
        # ASH_CONFIG's file is outside the tree but extends a base inside it,
        # so its chain is partly the repository's: the scan judges against the
        # defaults, not that file's 1024, and warns.
        (1024, "extends-in-tree", [], True),
    ],
    ids=[
        "operator-same",
        "operator-raises",
        "override",
        "defaults",
        "operator-chain-in-tree",
    ],
)
def test_config_validate_warns_about_the_limit_as_the_scan_does(
    tmp_path, monkeypatch, repository, operator, overrides, warned
):
    """`ash config validate` says a scan ignores the repository's limit exactly
    when the scan does: against the trusted base the scan uses (ASH_CONFIG's
    file outside the tree here, or the defaults when that file's chain reaches
    into the tree), and not where an override keeps the operator's own."""
    from automated_security_helper.config.config_validator import ConfigValidator
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(tmp_path, "project_name: checkout\n" + _setting(repository))
    if operator is None:
        monkeypatch.delenv("ASH_CONFIG", raising=False)
    elif operator == "extends-in-tree":
        base = checkout / "configs" / "base.yaml"
        base.parent.mkdir()
        base.write_text(_OTHER_OPTION, encoding="utf-8")
        named = tmp_path / "operator.yaml"
        named.write_text(
            f"extends: {base.as_posix()}\n" + _setting(1024), encoding="utf-8"
        )
        monkeypatch.setenv("ASH_CONFIG", str(named))
    else:
        named = tmp_path / "operator.yaml"
        named.write_text(_setting(operator), encoding="utf-8")
        monkeypatch.setenv("ASH_CONFIG", str(named))

    with _warnings() as messages:
        resolve_config(source_dir=checkout, config_overrides=overrides)
    check = ConfigValidator.check_config_file(
        checkout / ".ash" / ".ash.yaml",
        source_dir=checkout,
        config_overrides=overrides,
    )

    # The control: the scan warns as the case says.
    assert bool(_about_the_limit(messages)) is warned, messages
    assert bool([w for w in check.warnings if OPTION in w]) is warned, check.warnings


def test_config_validate_reads_ash_config_s_file_in_the_tree_as_the_scan_does(
    tmp_path, monkeypatch
):
    """`ash config validate` of the repository's .ash/.ash.yaml also loads the
    file ASH_CONFIG names, as a scan starts from it. That file is in the tree
    and writes 4097: a scan leaves the limit out and refuses nothing, so the
    check reports no error for it either."""
    from automated_security_helper.config.config_validator import ConfigValidator

    checkout = _checkout(tmp_path, "project_name: checkout\n")
    in_tree = checkout / "configs" / "ash.yaml"
    in_tree.parent.mkdir()
    in_tree.write_text(_setting(4097), encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(in_tree))

    check = ConfigValidator.check_config_file(
        checkout / ".ash" / ".ash.yaml", source_dir=checkout
    )

    assert not [e for e in check.errors if "max_worker_output_mib" in e], check.errors


def test_no_configuration_sets_the_limit_past_4096():
    """At 4096 MiB the read can hold about 12 GiB; past it the options model
    refuses the value. (A config file inside the tree that writes one is
    ignored, as for any value it writes: see above.)"""
    from pydantic import ValidationError

    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScannerConfigOptions,
    )

    # The control: the cap itself loads.
    assert (
        DetectSecretsScannerConfigOptions(
            max_worker_output_mib=4096
        ).max_worker_output_mib
        == 4096
    )
    with pytest.raises(ValidationError):
        DetectSecretsScannerConfigOptions(max_worker_output_mib=4097)


@pytest.mark.parametrize("value,read", [(100000, 256), (4096, 4096)])
def test_a_limit_that_skipped_validation_is_read_within_the_cap(value, read):
    """Options built without validation (model_construct) hold whatever they
    were given: the scanner reads one past the cap as the default, and the cap
    itself as written."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfigOptions,
    )

    options = DetectSecretsScannerConfigOptions.model_construct(
        max_worker_output_mib=value
    )
    stand_in = SimpleNamespace(config=SimpleNamespace(options=options))

    assert DetectSecretsScanner._worker_output_mib(stand_in) == read


@pytest.mark.parametrize(
    "writes", [None, 1024, 5000], ids=["names-no-limit", "sets-1024", "sets-5000"]
)
def test_get_config_marks_the_limit_only_where_a_checkout_s_file_writes_it(
    tmp_path, monkeypatch, writes
):
    """MCP get_config of a file in a checkout, named from outside it, marks
    the limit ignored only when the file writes one: a file that names no limit
    shows the limit the configuration holds, 256, not a value it never wrote
    shown as ignored. A value the option refuses (5000) is marked the same way:
    a scan of that checkout loads the file past it, so the tool answers with
    the marker rather than refusing the file."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config
    from tests.utils.helpers import mark_git_checkout

    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    (checkout / ".ash").mkdir()
    (checkout / ".ash" / ".ash.yaml").write_text(
        "project_name: checkout\n" + (_setting(writes) if writes else ""),
        encoding="utf-8",
    )
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    # A path named to get_config is the client's unless it is in a directory
    # ASH_MCP_ALLOWED_CONFIG_ROOTS names, and a client's file that writes the
    # limit is refused outright; this test is about how a file the operator
    # names is shown, so the test's directory is set aside as the operator's.
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))

    result = mcp_get_config(config_path=str(checkout / ".ash" / ".ash.yaml"))

    scanners = result["scanners"]
    [key] = [key for key in scanners if key in ("detect-secrets", "detect_secrets")]
    limit = scanners[key]["options"]["max_worker_output_mib"]
    if writes is None:
        assert limit == 256, limit
    else:
        assert limit == f"<operator only; ignored from this file: {writes}>", limit


def test_get_config_shows_a_checkout_s_limit_as_ignored():
    """MCP get_config shows a file in a checkout as a scan of that checkout
    applies it, so the limit that file sets is shown ignored, as the reporter
    options are. The scanner's other options are shown as they are."""
    from automated_security_helper.config.operator_only_options import (
        mark_operator_only_options,
    )

    shown = mark_operator_only_options(
        {
            "scanners": {
                "detect-secrets": {
                    "options": {
                        "max_worker_output_mib": 1024,
                        "skip_generated_lockfiles": False,
                    }
                }
            }
        }
    )

    options = shown["scanners"]["detect-secrets"]["options"]
    assert options["max_worker_output_mib"] == (
        "<operator only; ignored from this file: 1024>"
    )
    assert options["skip_generated_lockfiles"] is False


def test_a_spelling_the_model_folds_leaves_no_reference_behind(tmp_path, monkeypatch):
    """The repository's file writes the limit as ${VAR} under ``detectsecrets``,
    a spelling the configuration model reads as the scanner's section (case and
    separators dropped). The value is left out and the limit settles like any
    other spelling of it, so no reference survives into the record of what the
    files read from the environment: a surviving one would say the limit came
    from the variable while the scan uses the operator's."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_TEST_DS_OUTPUT_LIMIT", "3071")
    checkout = _checkout(
        tmp_path,
        "project_name: checkout\n"
        + _setting("${ASH_TEST_DS_OUTPUT_LIMIT}", key="detectsecrets"),
    )

    with _warnings() as messages:
        config = resolve_config(source_dir=checkout)

    # The controls: the spelling reaches the scanner (so it settles and warns),
    # and the warning prints no value. The fixture reads exactly one variable,
    # so an empty record proves the reference did not survive under the folded
    # spelling either.
    assert _limit(config) == 256
    [warning] = _about_the_limit(messages)
    assert "3071" not in warning, warning
    assert not list(config._environment_references)
    assert not list(config._displayed_environment_references)
    assert not [
        rewrite
        for rewrite in config._written_references or []
        if rewrite.resolved == "3071"
    ]


def test_the_exit_code_fields_survive_a_failing_tree_walk(tmp_path, monkeypatch):
    """_load_config_file promises None when the config cannot be loaded, the
    exit-code readers' contract: parsing failures surface later through the
    orchestrator's own validation. The checkout walk that builds the
    confinement is part of that load, so when it fails, the reader answers
    None instead of raising into the exit-code computation."""
    from automated_security_helper.config import sandbox_grants
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _resolve_config_fail_on_findings,
    )

    checkout = _checkout(tmp_path, "fail_on_findings: false\n")

    def refused(scan_root):
        raise PermissionError(13, "Permission denied", str(scan_root))

    monkeypatch.setattr(sandbox_grants, "scanned_trees", refused)
    opts = ScanOptions(source_dir=checkout, output_dir=tmp_path / "out")

    assert _resolve_config_fail_on_findings(opts) is None


@pytest.mark.parametrize("root_writes", [None, 512], ids=["base-only", "root-keeps-it"])
def test_get_config_does_not_mark_what_the_operator_s_own_chain_file_keeps(
    tmp_path, monkeypatch, root_writes
):
    """MCP get_config of an operator's file outside every checkout that extends
    a checkout's file: the limit the checkout's file writes is marked ignored,
    but where the operator's own file writes it too, a scan keeps that value,
    so the tool shows it as applied, not ignored."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config
    from tests.utils.helpers import mark_git_checkout

    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    (checkout / ".ash").mkdir()
    (checkout / ".ash" / ".ash.yaml").write_text(_setting(1024), encoding="utf-8")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        + (_setting(root_writes) if root_writes else ""),
        encoding="utf-8",
    )
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    _operator_names_files_under(tmp_path, monkeypatch)

    result = mcp_get_config(config_path=str(operator))

    scanners = result["scanners"]
    [key] = [key for key in scanners if key in ("detect-secrets", "detect_secrets")]
    limit = scanners[key]["options"]["max_worker_output_mib"]
    if root_writes is None:
        assert limit == "<operator only; ignored from this file: 1024>", limit
    else:
        assert limit == root_writes, limit


@pytest.mark.parametrize("writes", [1024, 4097], ids=["in-range", "past-the-cap"])
def test_get_config_with_no_file_shows_the_tree_s_ash_config_limit_as_ignored(
    tmp_path, monkeypatch, writes
):
    """MCP get_config with no config file answers with what a scan would use:
    ASH_CONFIG's file. When that file is inside the searched tree, the limit it
    writes is the repository's, which such a scan ignores: shown as ignored,
    whether or not the option would accept it, instead of applied or refused."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    checkout = _tree_with_ash_config_limit(tmp_path, monkeypatch, _setting(writes))

    result = mcp_get_config(search_dir=str(checkout))

    scanners = result["scanners"]
    [key] = [key for key in scanners if key in ("detect-secrets", "detect_secrets")]
    limit = scanners[key]["options"]["max_worker_output_mib"]
    assert limit == f"<operator only; ignored from this file: {writes}>", limit


def test_get_config_of_a_named_file_loads_past_the_tree_s_ash_config_limit(
    tmp_path, monkeypatch
):
    """MCP get_config of a named file also loads the file ASH_CONFIG names, as
    a scan starts from it. One inside the scanned tree writing a limit the
    option refuses is read past, as that scan reads past it, instead of
    refusing the file asked for."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    _tree_with_ash_config_limit(tmp_path, monkeypatch, _setting(4097))
    named = tmp_path / "operator.yaml"
    named.write_text("project_name: named\n", encoding="utf-8")

    result = mcp_get_config(config_path=str(named))

    assert result.get("project_name") == "named", result


_SERVER_VALUE = "server-value-read-from-the-environment"

#: Each operator-only option a checkout's file can write as ${VAR}: the
#: section text and the place the marker sits at in get_config's answer.
_ENV_OPTIONS = {
    "scope": (
        (
            "reporters:\n  aws-security-hub:\n    options:\n"
            "      findings_scope: ${ASH_TEST_MARKER_VAR}\n"
        ),
        ("reporters", "aws-security-hub", "options", "findings_scope"),
    ),
    "limit": (
        _setting("${ASH_TEST_MARKER_VAR}"),
        ("scanners", None, "options", "max_worker_output_mib"),
    ),
}


def _marker_at(result: dict, place) -> Any:
    kind, key, options, option = place
    sections = result[kind]
    if key is None:
        [key] = [k for k in sections if k in ("detect-secrets", "detect_secrets")]
    return sections[key][options][option]


@pytest.mark.parametrize("option", sorted(_ENV_OPTIONS))
@pytest.mark.parametrize("route", ["named-file", "no-file"])
def test_get_config_shows_an_environment_read_option_by_its_reference(
    tmp_path, monkeypatch, option, route
):
    """A checkout's file writes an operator-only option as ${VAR}. get_config
    shows it ignored, and shows what the file wrote as the reference,
    `<from ${VAR}>`, never the value the server's environment gave it: through
    a named file in a checkout the session does not scan, and with no file,
    ASH_CONFIG naming one inside the searched tree."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config
    from tests.utils.helpers import mark_git_checkout

    body, place = _ENV_OPTIONS[option]
    monkeypatch.setenv("ASH_TEST_MARKER_VAR", _SERVER_VALUE)
    if route == "named-file":
        checkout = tmp_path / "checkout"
        mark_git_checkout(checkout)
        (checkout / ".ash").mkdir()
        (checkout / ".ash" / ".ash.yaml").write_text(
            "project_name: checkout\n" + body, encoding="utf-8"
        )
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        _operator_names_files_under(tmp_path, monkeypatch)
        result = mcp_get_config(config_path=str(checkout / ".ash" / ".ash.yaml"))
    else:
        checkout = _tree_with_ash_config_limit(tmp_path, monkeypatch, body)
        result = mcp_get_config(search_dir=str(checkout))

    import json

    assert _SERVER_VALUE not in json.dumps(result), result
    marker = _marker_at(result, place)
    assert marker == (
        "<operator only; ignored from this file: <from ${ASH_TEST_MARKER_VAR}>>"
    ), marker


@pytest.mark.parametrize(
    "route,where",
    [
        ("named-ash-config-file", "configs/ash.yaml"),
        ("named-in-the-searched-tree", "configs/ash.yaml"),
        ("no-file", ".ash/other.yaml"),
        ("discovered", ".ash/.ash.yaml"),
        ("discovered", "ash.yaml"),
    ],
)
def test_get_config_never_answers_with_an_in_tree_file_s_read_scope(
    tmp_path, monkeypatch, route, where
):
    """A file inside the searched tree writes findings_scope as ${VAR}, and
    ASH_CONFIG names it (but for the second route, where only the call does).
    By every route get_config takes for it, the answer holds no value the
    environment gave. Where it marks the scope ignored, the marker is the
    reference. Where the file is the one a scan of the tree finds, it is
    resolved as that scan resolves it, and the scope is the one the scan
    applies."""
    import json

    from automated_security_helper.cli.mcp_tools import mcp_get_config
    from automated_security_helper.config.resolve_config import resolve_config
    from tests.utils.helpers import mark_git_checkout

    monkeypatch.setenv("ASH_TEST_MARKER_VAR", _SERVER_VALUE)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    named = checkout / where
    named.parent.mkdir(parents=True, exist_ok=True)
    named.write_text(_ENV_OPTIONS["scope"][0], encoding="utf-8")
    if route == "named-in-the-searched-tree":
        monkeypatch.delenv("ASH_CONFIG", raising=False)
    else:
        monkeypatch.setenv("ASH_CONFIG", str(named))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    _operator_names_files_under(tmp_path, monkeypatch)

    if route.startswith("named"):
        result = mcp_get_config(config_path=str(named), search_dir=str(checkout))
    else:
        result = mcp_get_config(search_dir=str(checkout))

    assert _SERVER_VALUE not in json.dumps(result), result
    options = result["reporters"]["aws-security-hub"]["options"]
    if route == "discovered":
        applied = resolve_config(source_dir=checkout).model_dump()
        expected = applied["reporters"]["aws-security-hub"]["options"].get(
            "findings_scope", "<absent>"
        )
        assert options.get("findings_scope", "<absent>") == expected, options
    elif route.startswith("named"):
        # The caller named its scan target, so the file is loaded as a scan
        # of that target loads it: the in-tree file's operator-only option is
        # left out at the load, and the answer holds no scope at all.
        assert "findings_scope" not in options, options
    else:
        assert options["findings_scope"] == (
            "<operator only; ignored from this file: <from ${ASH_TEST_MARKER_VAR}>>"
        ), options
    if route.startswith("named"):
        # Without the target, the session's stand-in is not the scan's tree:
        # the file is judged by its own confinement root, and the ignored
        # option is shown with its reference, never the value.
        control = mcp_get_config(config_path=str(named))
        assert _SERVER_VALUE not in json.dumps(control), control
        control_options = control["reporters"]["aws-security-hub"]["options"]
        assert control_options["findings_scope"] == (
            "<operator only; ignored from this file: <from ${ASH_TEST_MARKER_VAR}>>"
        ), control_options


def test_get_config_shows_a_literal_scope_as_written_beside_a_read_value(
    tmp_path, monkeypatch
):
    """A checkout's file reads project_name from ${VAR} and writes
    findings_scope as a literal that happens to be the same text. The marker
    shows the scope's literal: it is the repository's own text, and no
    reference sits at the scope. A literal that equals a value read elsewhere
    stays the literal."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config
    from tests.utils.helpers import mark_git_checkout

    monkeypatch.setenv("ASH_TEST_MARKER_VAR", "same-text")
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    (checkout / ".ash").mkdir()
    (checkout / ".ash" / ".ash.yaml").write_text(
        "project_name: ${ASH_TEST_MARKER_VAR}\n"
        "reporters:\n  aws-security-hub:\n    options:\n"
        "      findings_scope: same-text\n",
        encoding="utf-8",
    )
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    _operator_names_files_under(tmp_path, monkeypatch)

    result = mcp_get_config(config_path=str(checkout / ".ash" / ".ash.yaml"))

    marker = result["reporters"]["aws-security-hub"]["options"]["findings_scope"]
    assert marker == '<operator only; ignored from this file: "same-text">', marker


def test_get_config_shows_a_literal_written_over_a_read_value_as_the_literal(
    tmp_path, monkeypatch
):
    """A checkout's base file reads findings_scope from ${VAR}, and the
    checkout's root writes a literal over it at the same place. The chain
    settles on the literal, so the marker shows it as written: the base's
    reference sits at the place but resolved to the read value, not to the
    literal the root wrote over it."""
    import json

    from automated_security_helper.cli.mcp_tools import mcp_get_config
    from tests.utils.helpers import mark_git_checkout

    monkeypatch.setenv("ASH_TEST_MARKER_VAR", _SERVER_VALUE)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    (checkout / ".ash").mkdir()
    (checkout / ".ash" / "base.yaml").write_text(
        "reporters:\n  aws-security-hub:\n    options:\n"
        "      findings_scope: ${ASH_TEST_MARKER_VAR}\n",
        encoding="utf-8",
    )
    (checkout / ".ash" / ".ash.yaml").write_text(
        "extends: base.yaml\n"
        "project_name: checkout\n"
        "reporters:\n  aws-security-hub:\n    options:\n"
        "      findings_scope: literal-over-the-read\n",
        encoding="utf-8",
    )
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    _operator_names_files_under(tmp_path, monkeypatch)

    result = mcp_get_config(config_path=str(checkout / ".ash" / ".ash.yaml"))

    assert _SERVER_VALUE not in json.dumps(result), result
    marker = result["reporters"]["aws-security-hub"]["options"]["findings_scope"]
    assert marker == (
        '<operator only; ignored from this file: "literal-over-the-read">'
    ), marker


def test_a_chain_file_swapped_for_a_link_after_the_resolve_still_answers(
    tmp_path, monkeypatch
):
    """The checkout's base file is swapped for a symlink out of the checkout
    right after the resolution reads the chain, as a writer can between the
    read and the answer. get_config answers from that one read: the base's
    env-read option is marked by its reference, and nothing walks the live
    filesystem again to raise past the structured refusals or to read what
    the link points at now."""
    import json

    from automated_security_helper.cli.mcp_tools import mcp_get_config
    from automated_security_helper.config import resolve_config as resolve_module
    from tests.utils.helpers import mark_git_checkout

    monkeypatch.setenv("ASH_TEST_MARKER_VAR", _SERVER_VALUE)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    (checkout / ".ash").mkdir()
    base = checkout / ".ash" / "base.yaml"
    base.write_text(
        "reporters:\n  aws-security-hub:\n    options:\n"
        "      findings_scope: ${ASH_TEST_MARKER_VAR}\n",
        encoding="utf-8",
    )
    (checkout / ".ash" / ".ash.yaml").write_text(
        "extends: base.yaml\nproject_name: checkout\n", encoding="utf-8"
    )
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: swapped-in-after-the-read\n", encoding="utf-8")
    real_resolve = resolve_module.resolve_config

    def resolve_then_swap(*args, **kwargs):
        config = real_resolve(*args, **kwargs)
        base.unlink()
        base.symlink_to(outside)
        return config

    monkeypatch.setattr(resolve_module, "resolve_config", resolve_then_swap)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    _operator_names_files_under(tmp_path, monkeypatch)

    result = mcp_get_config(config_path=str(checkout / ".ash" / ".ash.yaml"))

    text = json.dumps(result)
    assert _SERVER_VALUE not in text, result
    assert "swapped-in-after-the-read" not in text, result
    marker = result["reporters"]["aws-security-hub"]["options"]["findings_scope"]
    assert marker == (
        "<operator only; ignored from this file: <from ${ASH_TEST_MARKER_VAR}>>"
    ), marker


def test_get_config_shows_an_aliased_environment_value_by_its_reference(
    tmp_path, monkeypatch
):
    """A checkout's file reads project_name from ${VAR} under a YAML anchor
    and points findings_scope at it with an alias. The scope holds the value
    the environment gave: the marker shows the reference, never the value.
    (A `patch` copy of it is refused at load: copy is not an allowed op.)"""
    import json

    from automated_security_helper.cli.mcp_tools import mcp_get_config
    from tests.utils.helpers import mark_git_checkout

    monkeypatch.setenv("ASH_TEST_MARKER_VAR", _SERVER_VALUE)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    (checkout / ".ash").mkdir()
    (checkout / ".ash" / ".ash.yaml").write_text(
        "project_name: &scope ${ASH_TEST_MARKER_VAR}\n"
        "reporters:\n  aws-security-hub:\n    options:\n      aws_region: us-west-2\n"
        "      findings_scope: *scope\n",
        encoding="utf-8",
    )
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    _operator_names_files_under(tmp_path, monkeypatch)

    result = mcp_get_config(config_path=str(checkout / ".ash" / ".ash.yaml"))

    assert _SERVER_VALUE not in json.dumps(result), result
    marker = result["reporters"]["aws-security-hub"]["options"]["findings_scope"]
    assert marker.startswith("<operator only; ignored from this file: <from "), marker


def _tree_with_ash_config_limit(tmp_path, monkeypatch, body: str) -> Path:
    """A checkout the process sits in, whose in-tree file ASH_CONFIG names
    writes *body*: the fixture for the callers that read the operator's
    default configuration next to a repository."""
    from tests.utils.helpers import mark_git_checkout

    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    named = checkout / "configs" / "ash.yaml"
    named.parent.mkdir(parents=True)
    named.write_text(body, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(named))
    monkeypatch.chdir(checkout)
    return checkout


def test_the_record_repair_reads_the_operator_s_default_past_the_tree_s_limit(
    tmp_path, monkeypatch
):
    """The record repair falls back to the operator's default configuration
    when the scan has no config file. That is ASH_CONFIG's file, loaded as the
    scan loads it: one in the scanned tree writing a limit the option refuses
    is read past, not raised out of the repair."""
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _operator_default_config,
    )

    checkout = _tree_with_ash_config_limit(tmp_path, monkeypatch, _setting(4097))
    opts = ScanOptions(source_dir=checkout, output_dir=tmp_path / "out")

    assert _limit(_operator_default_config(opts)) == 256


def test_the_scanner_inventory_loads_past_the_tree_s_limit(tmp_path, monkeypatch):
    """The scanner inventory reads the operator's default configuration for
    what is enabled. Run inside a checkout whose in-tree ASH_CONFIG file writes
    a limit the option refuses, it answers instead of raising over a value a
    scan of this checkout reads past."""
    from automated_security_helper.core.scanner_inventory import (
        list_scanner_inventory,
    )

    _tree_with_ash_config_limit(tmp_path, monkeypatch, _setting(4097))

    assert list_scanner_inventory(scanner_classes_provider=list, concurrent=False) == []


def test_the_statistics_fallback_loads_past_the_tree_s_limit(tmp_path, monkeypatch):
    """The threshold reader falls back to the operator's default configuration
    when the results' record cannot be read. Inside a checkout whose in-tree
    ASH_CONFIG file writes a limit the option refuses, the fallback still
    answers a threshold."""
    from automated_security_helper.core.scanner_statistics_calculator import (
        ScannerStatisticsCalculator,
    )

    _tree_with_ash_config_limit(tmp_path, monkeypatch, _setting(4097))

    class _Broken:
        @property
        def ash_config(self):
            raise RuntimeError("the record cannot be read")

    threshold, source = ScannerStatisticsCalculator.get_scanner_threshold_info(
        _Broken(), "bandit"
    )
    assert source == "global"


def test_the_mcp_server_s_scanner_resource_loads_past_the_tree_s_limit(
    tmp_path, monkeypatch
):
    """The MCP server's built-in-scanner resource reads the operator's default
    configuration for what is enabled. Inside a checkout whose in-tree
    ASH_CONFIG file writes a limit the option refuses, it answers the bullets
    instead of failing."""
    from automated_security_helper.cli.mcp_server import _builtin_scanner_lines

    _tree_with_ash_config_limit(tmp_path, monkeypatch, _setting(4097))

    lines = _builtin_scanner_lines()
    assert "detect-secrets" in lines


def test_the_mcp_resource_limits_load_past_the_tree_s_limit(tmp_path, monkeypatch):
    """The MCP resource limits are ASH_CONFIG's section. A file in this
    checkout that also writes a limit the option refuses does not make them
    unreadable, and the section itself is read as written: the limits are not
    operator-only options."""
    from automated_security_helper.cli.mcp_tools import _resource_limits

    _tree_with_ash_config_limit(
        tmp_path,
        monkeypatch,
        "mcp-resource-management:\n  max_concurrent_scans: 2\n" + _setting(4097),
    )

    assert _resource_limits().max_concurrent_scans == 2


@pytest.mark.parametrize(
    "reader",
    [
        "resource-limits",
        "scanner-resource",
        "scanner-inventory",
        "threshold-fallback",
        "validate",
        "get-config-of-a-named-file",
    ],
)
@_POSIX_ONLY_CWD_REMOVAL
def test_a_working_directory_deleted_after_launch_is_no_scanned_tree(
    tmp_path, monkeypatch, reader
):
    """The process's working directory is deleted while it runs, so
    Path.cwd() raises. Each reader that judged files by the trees scanned
    from it answers anyway: that directory holds no file, so no tree is
    taken from it. The threshold fallback answers in place of the error it
    handles, rather than replacing it with this one."""
    import os

    from automated_security_helper.cli import mcp_server, mcp_tools
    from automated_security_helper.config.config_validator import ConfigValidator
    from automated_security_helper.core.scanner_statistics_calculator import (
        ScannerStatisticsCalculator,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "elsewhere" / "ash.yaml"
    config.parent.mkdir()
    config.write_text("project_name: elsewhere\n", encoding="utf-8")
    launched = tmp_path / "launched-here"
    launched.mkdir()
    monkeypatch.chdir(launched)
    os.rmdir(launched)

    class _Unreadable:
        @property
        def ash_config(self):
            raise RuntimeError("the results' config is unreadable")

    if reader == "resource-limits":
        assert mcp_tools._resource_limits() is not None
    elif reader == "scanner-resource":
        assert "bandit" in mcp_server._builtin_scanner_lines()
    elif reader == "scanner-inventory":
        from automated_security_helper.core.scanner_inventory import (
            list_scanner_inventory,
        )

        assert list_scanner_inventory(list) == []
    elif reader == "threshold-fallback":
        threshold, _source = ScannerStatisticsCalculator.get_scanner_threshold_info(
            _Unreadable(), "bandit"
        )
        assert threshold in ("ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    elif reader == "validate":
        assert ConfigValidator.check_config_file(config) is not None
    else:
        result = mcp_tools.mcp_get_config(
            config_path=str(config), search_dir=str(tmp_path / "elsewhere")
        )
        assert result.get("project_name") == "elsewhere", result


@pytest.mark.parametrize(
    "reader",
    [
        "default-config-for-tree",
        "validate",
        "get-config-discovery",
    ],
)
@_POSIX_ONLY_CWD_REMOVAL
def test_a_working_directory_deleted_inside_a_checkout_stays_confined(
    tmp_path, monkeypatch, reader
):
    """The working directory, inside a checkout whose ASH_CONFIG file writes
    operator-only options, is deleted while the process runs. Each reader
    answers with those options still left out, fail-closed: a load that
    cannot tell whose tree it serves does not apply what a checkout's file
    wrote. Discovery, which searched that directory, answers the
    configuration a scan would start from instead of raising."""
    import json
    import os

    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config.config_validator import ConfigValidator
    from automated_security_helper.config.default_config import (
        default_config_for_tree,
    )
    from tests.utils.helpers import mark_git_checkout

    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    cfg = checkout / ".ash" / ".ash.yaml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(
        "project_name: checkout\n"
        + _setting(128)
        + "reporters:\n  aws-security-hub:\n    options:\n"
        "      findings_scope: repository-scope\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(cfg))
    sub = checkout / "sub"
    sub.mkdir()
    monkeypatch.chdir(sub)
    os.rmdir(sub)

    if reader == "default-config-for-tree":
        config = default_config_for_tree()
        dumped = json.dumps(config.model_dump(), default=str)
        assert "128" not in dumped, dumped[:400]
        assert "repository-scope" not in dumped, dumped[:400]
    elif reader == "validate":
        check = ConfigValidator.check_config_file(cfg)
        assert [w for w in check.warnings if OPTION in w], check.warnings
        assert [w for w in check.warnings if "findings_scope" in w], check.warnings
    else:
        result = mcp_tools.mcp_get_config()
        text = json.dumps(result, default=str)
        marker = ((result.get("reporters") or {}).get("aws-security-hub") or {}).get(
            "options"
        ) or {}
        assert "ignored from this file" in str(marker.get("findings_scope")), marker
        assert "repository-scope" not in text.replace(
            'ignored from this file: \\"repository-scope\\"', ""
        ), text[:400]


@_POSIX_ONLY_CWD_REMOVAL
def test_get_config_answers_a_named_file_past_another_checkout_s_ash_config(
    tmp_path, monkeypatch
):
    """The working directory is deleted while the server runs, ASH_CONFIG
    names a file inside one checkout that writes a refused limit, and
    get_config asks for a file inside another. The ASH_CONFIG pre-check
    fails closed and passes, so the real load does too: the refused value
    is left out there as well, and the answer is the named file's own
    settings -- never a load failure blaming the file asked for with
    another checkout's value."""
    import os

    from automated_security_helper.cli import mcp_tools
    from tests.utils.helpers import mark_git_checkout

    operator_checkout = tmp_path / "operator-checkout"
    mark_git_checkout(operator_checkout)
    env_cfg = operator_checkout / ".ash" / ".ash.yaml"
    env_cfg.parent.mkdir(parents=True, exist_ok=True)
    env_cfg.write_text("project_name: env\n" + _setting(4097), encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(env_cfg))

    named_checkout = tmp_path / "named-checkout"
    mark_git_checkout(named_checkout)
    named = named_checkout / ".ash" / ".ash.yaml"
    named.parent.mkdir(parents=True, exist_ok=True)
    named.write_text("project_name: named\n", encoding="utf-8")

    launched = tmp_path / "launched-here"
    launched.mkdir()
    monkeypatch.chdir(launched)
    os.rmdir(launched)

    result = mcp_tools.mcp_get_config(config_path=str(named))

    assert result.get("project_name") == "named", result


@_POSIX_ONLY_CWD_REMOVAL
def test_the_no_tree_reads_share_the_pre_check_s_construction(tmp_path, monkeypatch):
    """With no scanned tree, the ASH_CONFIG chain's read and the trusted
    base's confine take their settings from scan_repository_settings,
    the one construction the MCP pre-check uses (through
    repository_settings_for_root) -- not from a second, hand-built
    RepositorySettings whose tree set can drift from it. The membership the
    two shapes disagree on (files inside a source directory that is not a
    checkout) then has one answer."""
    import os

    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config import operator_only_options
    from automated_security_helper.config import resolve_config as module
    from tests.utils.helpers import mark_git_checkout

    operator_checkout = tmp_path / "operator-checkout"
    mark_git_checkout(operator_checkout)
    env_cfg = operator_checkout / ".ash" / ".ash.yaml"
    env_cfg.parent.mkdir(parents=True, exist_ok=True)
    env_cfg.write_text("project_name: env\n" + _setting(4097), encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(env_cfg))
    named_checkout = tmp_path / "named-checkout"
    mark_git_checkout(named_checkout)
    named = named_checkout / ".ash" / ".ash.yaml"
    named.parent.mkdir(parents=True, exist_ok=True)
    named.write_text("project_name: named\n", encoding="utf-8")
    launched = tmp_path / "launched-here"
    launched.mkdir()
    monkeypatch.chdir(launched)
    os.rmdir(launched)

    real = operator_only_options.scan_repository_settings
    from_resolve_config: list = []
    from_the_pre_check: list = []

    def spying_in(calls):
        def spying(trees, *args, **kwargs):
            calls.append(list(trees))
            return real(trees, *args, **kwargs)

        return spying

    monkeypatch.setattr(
        module, "scan_repository_settings", spying_in(from_resolve_config)
    )
    monkeypatch.setattr(
        operator_only_options, "scan_repository_settings", spying_in(from_the_pre_check)
    )
    result = mcp_tools.mcp_get_config(config_path=str(named))

    assert result.get("project_name") == "named", result
    # One construction, one tree set: the pre-check takes the trees of the root
    # the load reads (the named file's project directory, as no tree is
    # scanned), and every read of the load takes the same set.
    assert from_the_pre_check, from_the_pre_check
    pre_check = from_the_pre_check[0]
    assert pre_check, from_the_pre_check
    assert len(from_resolve_config) >= 2, from_resolve_config
    assert all(trees == pre_check for trees in from_resolve_config), (
        from_the_pre_check,
        from_resolve_config,
    )


def test_config_validate_of_an_operator_s_own_ash_config_file_warns_nothing(
    tmp_path, monkeypatch
):
    """`ash config validate` of the file ASH_CONFIG names, outside the tree:
    the file is the operator's, so the limit it writes is applied, not ignored,
    and no warning or error names it. (With no file of the chain inside the
    tree, nothing was recorded as the repository's, so there is nothing to
    judge against any trusted base.)"""
    from automated_security_helper.config.config_validator import ConfigValidator

    checkout = _checkout(tmp_path)
    named = tmp_path / "operator.yaml"
    named.write_text(_setting(1024), encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(named))

    check = ConfigValidator.check_config_file(named, source_dir=checkout)

    assert not [e for e in check.errors if "max_worker_output_mib" in e], check.errors
    assert not [w for w in check.warnings if OPTION in w], check.warnings


def _checkouts_either_side(tmp_path, monkeypatch, env_limit, named_text):
    """ASH_CONFIG's file in one checkout, the asked-for file in another."""
    from tests.utils.helpers import mark_git_checkout

    operator_checkout = tmp_path / "operator-checkout"
    mark_git_checkout(operator_checkout)
    env_cfg = operator_checkout / ".ash" / ".ash.yaml"
    env_cfg.parent.mkdir(parents=True, exist_ok=True)
    env_cfg.write_text("project_name: env\n" + _setting(env_limit), encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(env_cfg))
    named_checkout = tmp_path / "named-checkout"
    mark_git_checkout(named_checkout)
    named = named_checkout / ".ash" / ".ash.yaml"
    named.parent.mkdir(parents=True, exist_ok=True)
    named.write_text(named_text, encoding="utf-8")
    return named_checkout, named


def _delete_working_directory(tmp_path, monkeypatch):
    import os

    if sys.platform == "win32":
        pytest.skip("the working directory cannot be removed on Windows")
    launched = tmp_path / "launched-here"
    launched.mkdir()
    monkeypatch.chdir(launched)
    os.rmdir(launched)


def _shown_limit(shown):
    scanners = shown.get("scanners") or {}
    section = scanners.get("detect-secrets") or scanners.get("detect_secrets") or {}
    return (section.get("options") or {}).get("max_worker_output_mib")


def test_a_deleted_cwd_answers_the_default_where_ash_config_in_a_checkout_sets_it(
    tmp_path, monkeypatch
):
    """The cost of no_scanned_tree, pinned: ASH_CONFIG's file sits in a
    checkout and sets a valid limit (2048); the named file in another
    checkout writes 1024, which a scan of that checkout settles to the
    trusted base. With the working directory deleted the trusted base reads
    ASH_CONFIG fail-closed, so the answer is the default (256) -- neither
    checkout's write applies when no tree says whose they are."""
    from automated_security_helper.cli import mcp_tools

    _named_checkout, named = _checkouts_either_side(
        tmp_path, monkeypatch, 2048, "project_name: named\n" + _setting(1024)
    )
    # The operator names the file (see test_get_config_marks_the_limit_only_
    # where_a_checkout_s_file_writes_it); a client-named file writing the limit
    # would be refused outright instead of settled.
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))
    _delete_working_directory(tmp_path, monkeypatch)

    result = mcp_tools.mcp_get_config(config_path=str(named))

    assert result.get("project_name") == "named", result
    assert _shown_limit(result) == 256, result


def test_a_live_cwd_in_the_named_checkout_answers_the_ash_config_value(
    tmp_path, monkeypatch
):
    """The same files with the working directory inside the named file's
    checkout (a scan of it): the trusted base keeps ASH_CONFIG's 2048. With
    the deleted-cwd cell above, this pins that no_scanned_tree and
    any_checkout are judged from the live working directory, not forced
    either way."""
    from automated_security_helper.cli import mcp_tools

    named_checkout, named = _checkouts_either_side(
        tmp_path, monkeypatch, 2048, "project_name: named\n" + _setting(1024)
    )
    # The operator names the file, as in the deleted-cwd test above.
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))
    monkeypatch.chdir(named_checkout)

    result = mcp_tools.mcp_get_config(config_path=str(named))

    assert result.get("project_name") == "named", result
    assert _shown_limit(result) == 2048, result


def test_the_left_out_ash_config_value_is_warned(tmp_path, monkeypatch, caplog):
    """What the fail-closed read leaves out is said: with no scanned tree, one
    WARNING names each operator-only option ASH_CONFIG's file wrote that the
    load left out, by place and never by value."""
    from automated_security_helper.cli import mcp_tools

    _named_checkout, named = _checkouts_either_side(
        tmp_path, monkeypatch, 4097, "project_name: named\n"
    )
    _delete_working_directory(tmp_path, monkeypatch)

    with caplog.at_level(logging.DEBUG):
        result = mcp_tools.mcp_get_config(config_path=str(named))

    assert result.get("project_name") == "named", result
    warned = [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING
        and "max_worker_output_mib" in record.getMessage()
    ]
    assert warned, [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING
    ]
    assert not [line for line in warned if "4097" in line], warned


def test_a_live_non_checkout_cwd_reads_the_ash_config_write_as_a_scan_does(
    tmp_path, monkeypatch
):
    """With a live working directory outside every checkout, ASH_CONFIG's file
    sits in a checkout the scan does not scan and is not the operator's: the
    ASH_CONFIG pre-check leaves its 4097 out as the scan's own load does, so the
    answer is the named file's, not a load failure for a value the scan
    ignores."""
    import json

    from automated_security_helper.cli import mcp_tools

    _named_checkout, named = _checkouts_either_side(
        tmp_path, monkeypatch, 4097, "project_name: named\n"
    )
    plain = tmp_path / "plain-dir"
    plain.mkdir()
    monkeypatch.chdir(plain)

    result = mcp_tools.mcp_get_config(config_path=str(named))

    assert result.get("success") is not False, result
    assert result.get("project_name") == "named", result
    assert "named-checkout" not in json.dumps(result.get("error")), result


def _project_directory_holding_the_ash_config_file(tmp_path, monkeypatch, env_limit):
    """A project directory that is not a checkout, holding the config file a
    caller names and the file ASH_CONFIG names, which writes the limit."""
    project = tmp_path / "plain-project"
    named = project / ".ash" / ".ash.yaml"
    named.parent.mkdir(parents=True, exist_ok=True)
    named.write_text("project_name: named\n", encoding="utf-8")
    env_cfg = project / "operator.yaml"
    env_cfg.write_text("project_name: env\n" + _setting(env_limit), encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(env_cfg))
    return named


def test_get_config_leaves_out_an_ash_config_value_inside_the_named_files_project_directory(
    tmp_path, monkeypatch
):
    """The working directory is deleted while the server runs, and ASH_CONFIG
    names a file inside the named config's project directory, which is not a
    checkout. The load reads that directory as the root and leaves the file's
    refused 4097 out, so the pre-check reads it the same way: the answer is the
    named file's settings, not a load failure for a value the load ignores."""
    from automated_security_helper.cli import mcp_tools

    named = _project_directory_holding_the_ash_config_file(tmp_path, monkeypatch, 4097)
    _delete_working_directory(tmp_path, monkeypatch)

    result = mcp_tools.mcp_get_config(config_path=str(named))

    assert result.get("success") is not False, result
    assert result.get("project_name") == "named", result


def test_the_client_rules_read_ash_config_with_the_chain_settings_they_are_given(
    tmp_path, monkeypatch
):
    """The rules a delivered config is checked against come from the trusted
    default configuration, which is the file ASH_CONFIG names. Read bare, a value
    the option refuses in a file of another checkout makes the rules unreadable,
    although the scan leaves that value out; read with the settings the load of
    the same chain uses, the rules load."""
    from automated_security_helper.cli.mcp.profile_registry import (
        session_client_rules,
    )
    from automated_security_helper.config.operator_only_options import (
        repository_settings_for_root,
    )

    named_checkout, _named = _checkouts_either_side(
        tmp_path, monkeypatch, 4097, "project_name: named\n"
    )

    bare = session_client_rules(None)
    read = session_client_rules(
        None, repository=repository_settings_for_root(named_checkout)
    )

    assert bare.unreadable is not None, "control: the bare read refuses the value"
    assert read.unreadable is None, read.unreadable


def test_the_left_out_value_inside_the_given_root_is_not_said_to_be_in_a_checkout(
    tmp_path, monkeypatch, caplog
):
    """With no scanned tree but a given root, ASH_CONFIG's file inside the
    root's tree is left out because the root holds it. The warning says so, and
    does not call the file a checkout's."""
    from automated_security_helper.config.resolve_config import resolve_config

    named = _project_directory_holding_the_ash_config_file(tmp_path, monkeypatch, 4097)

    with caplog.at_level(logging.WARNING):
        resolve_config(
            config_path=named, source_dir=named.parent.parent, no_scanned_tree=True
        )

    lines = [
        record.getMessage()
        for record in caplog.records
        if "read fail-closed" in record.getMessage()
    ]
    assert len(lines) == 1, caplog.text
    assert "max_worker_output_mib" in lines[0], lines
    assert "the given root's trees" in lines[0], lines
    assert "in a checkout is left out" not in lines[0], lines


def test_validate_config_reads_ash_config_fail_closed_like_get_config(
    tmp_path, monkeypatch
):
    """The sibling MCP reader: validate_config of a named file with the
    working directory deleted. The validator's ASH_CONFIG check confines
    fail-closed like its own load (repository_settings_for_root(None)), so
    another checkout's refused 4097 is not this file's error."""
    import json

    from automated_security_helper.cli import mcp_tools

    _named_checkout, named = _checkouts_either_side(
        tmp_path, monkeypatch, 4097, "project_name: named\n"
    )
    _delete_working_directory(tmp_path, monkeypatch)

    result = mcp_tools.mcp_validate_config(config_path=str(named))

    messages = json.dumps(result.get("errors"))
    assert "max_worker_output_mib" not in messages, result
    assert result.get("valid") is True, result


def _named_file_with_a_checkout_base(tmp_path):
    """An operator file outside every checkout whose base sits inside one and
    writes the limit, an option only the operator may set."""
    from tests.utils.helpers import mark_git_checkout

    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    base = checkout / ".ash" / ".ash.yaml"
    base.parent.mkdir(parents=True, exist_ok=True)
    base.write_text("project_name: base\n" + _setting(1024), encoding="utf-8")
    named = tmp_path / "operator.yaml"
    named.write_text(f"extends: {base.as_posix()}\n", encoding="utf-8")
    return named


def test_no_scanned_tree_confines_the_selected_chain_too(tmp_path, monkeypatch):
    """A caller that knows no tree is scanned (no_scanned_tree=True) cannot
    say whose checkout a chain file sits in, so the selected config's own
    chain is confined fail-closed like the ASH_CONFIG and trusted-base
    reads: a base inside a checkout keeps project settings but its
    operator-only limit is left out."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    named = _named_file_with_a_checkout_base(tmp_path)
    plain = tmp_path / "plain-dir"
    plain.mkdir()
    monkeypatch.chdir(plain)

    config = resolve_config(config_path=named, no_scanned_tree=True)

    assert _limit(config) == 256


def test_a_deleted_cwd_confines_the_selected_chain_too(tmp_path, monkeypatch):
    """The same through the deleted-working-directory default: with no root,
    no source directory and no working directory, the load's own
    no_scanned_tree turns on, and the selected chain fails closed with it --
    not only the ASH_CONFIG and trusted-base reads."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    named = _named_file_with_a_checkout_base(tmp_path)
    _delete_working_directory(tmp_path, monkeypatch)

    config = resolve_config(config_path=named)

    assert _limit(config) == 256


def test_a_live_cwd_leaves_out_a_base_in_a_checkout_too(tmp_path, monkeypatch):
    """With a live working directory outside the base's checkout and no
    no_scanned_tree, the base is still a file in a git checkout: the
    confinement steps hold it to the trusted base (it is not the operator's
    for a sandbox grant or an archive limit), and the limit it writes is held
    to the same membership. The operator's own file that extends it writes
    nothing for the limit, so the limit is the trusted base's, 256."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    named = _named_file_with_a_checkout_base(tmp_path)
    plain = tmp_path / "plain-dir"
    plain.mkdir()
    monkeypatch.chdir(plain)

    config = resolve_config(config_path=named)

    assert _limit(config) == 256


def test_a_live_cwd_keeps_the_limit_the_operators_own_file_writes(
    tmp_path, monkeypatch
):
    """The control: the operator's file outside every checkout writes its own
    limit over the base in the checkout, and that limit is kept."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    named = _named_file_with_a_checkout_base(tmp_path)
    text = named.read_text(encoding="utf-8")
    named.write_text(text + _setting(512), encoding="utf-8")
    plain = tmp_path / "plain-dir"
    plain.mkdir()
    monkeypatch.chdir(plain)

    config = resolve_config(config_path=named)

    assert _limit(config) == 512


def _checkout_file_writing_the_off_host_section(tmp_path, monkeypatch):
    from tests.utils.helpers import mark_git_checkout

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "named-checkout"
    mark_git_checkout(checkout)
    named = checkout / ".ash" / ".ash.yaml"
    named.parent.mkdir(parents=True, exist_ok=True)
    named.write_text(
        "project_name: here\n"
        "reporters:\n  aws-security-hub:\n    enabled: true\n    options:\n"
        "      aws_region: us-east-1\n      findings_scope: repo-scope\n"
        "      archive_resolved_findings: true\n" + _setting(1024),
        encoding="utf-8",
    )
    return checkout, named


def _assert_the_checkout_file_is_confined(config):
    import json as json_module

    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
        SecurityHubReporter,
    )

    section = reporter_section(config, SecurityHubReporter)
    dumped = json_module.dumps(section, default=str)
    assert "repo-scope" not in dumped, section
    options = (section or {}).get("options") or {}
    assert options.get("archive_resolved_findings") is not True, section
    assert (section or {}).get("enabled") is not True, section
    assert _limit(config) == 256


def test_a_deleted_cwd_confines_a_named_checkout_file_whole(tmp_path, monkeypatch):
    """resolve_config with no scanned_root, no source_dir and the working
    directory deleted: the named file sits in a checkout, so the fail-closed
    reading treats it as a repository's file -- its off-host reporter section
    (enablement, destination, scope, archiving) and its operator-only limit
    do not apply, exactly as a scan of that checkout leaves them out. Before,
    the empty tree list returned early and the checkout file was taken as the
    operator's whole."""
    from automated_security_helper.config.resolve_config import resolve_config

    _checkout, named = _checkout_file_writing_the_off_host_section(
        tmp_path, monkeypatch
    )
    _delete_working_directory(tmp_path, monkeypatch)

    config = resolve_config(config_path=named)

    _assert_the_checkout_file_is_confined(config)


def test_a_live_cwd_inside_the_checkout_confines_the_same_file(tmp_path, monkeypatch):
    """The control: a scan of the checkout confines the same file the same
    way, so the deleted-cwd answer above equals the fail-closed one."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout, named = _checkout_file_writing_the_off_host_section(tmp_path, monkeypatch)
    monkeypatch.chdir(checkout)

    config = resolve_config(config_path=named)

    _assert_the_checkout_file_is_confined(config)


def test_a_deleted_cwd_with_also_scanned_trees_still_answers(tmp_path, monkeypatch):
    """ash report's call shape (also_scanned holds the results' repository)
    with the working directory deleted: the load answers with the checkout
    file confined, instead of raising TypeError out of a None root. (Before
    the deleted-cwd fix this call raised FileNotFoundError, which report's
    handlers caught; a raw TypeError they do not.)"""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout, named = _checkout_file_writing_the_off_host_section(tmp_path, monkeypatch)
    _delete_working_directory(tmp_path, monkeypatch)

    config = resolve_config(config_path=named, also_scanned=[checkout])

    _assert_the_checkout_file_is_confined(config)


def test_untrusted_content_with_no_working_directory_is_an_answer(
    tmp_path, monkeypatch
):
    """The validator module check's call shape for client content
    (untrusted_config, no source_dir, no fallback) with the working directory
    deleted: the resolve answers instead of raising TypeError out of a None
    root."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    upload = tmp_path / "upload" / "config.yaml"
    upload.parent.mkdir()
    upload.write_text("project_name: upload\n", encoding="utf-8")
    _delete_working_directory(tmp_path, monkeypatch)

    config = resolve_config(
        config_path=str(upload), untrusted_config=True, fallback_to_default=False
    )

    assert config.project_name == "upload"


def test_the_no_root_default_reads_ash_config_fail_closed(
    tmp_path, monkeypatch, caplog
):
    """The deleted-working-directory default turns no_scanned_tree on itself:
    with no config file, the configuration is ASH_CONFIG's, read fail-closed
    -- its file sits in a checkout, so its valid 2048 is left out, the
    default applies, and one warning names the place, never the value."""
    from tests.utils.helpers import mark_git_checkout

    from automated_security_helper.config.resolve_config import resolve_config

    operator_checkout = tmp_path / "operator-checkout"
    mark_git_checkout(operator_checkout)
    env_cfg = operator_checkout / ".ash" / ".ash.yaml"
    env_cfg.parent.mkdir(parents=True, exist_ok=True)
    env_cfg.write_text("project_name: env\n" + _setting(2048), encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(env_cfg))
    _delete_working_directory(tmp_path, monkeypatch)

    with caplog.at_level(logging.WARNING):
        config = resolve_config()

    assert config.project_name == "env"
    assert _limit(config) == 256
    warned = [
        record.getMessage()
        for record in caplog.records
        if "max_worker_output_mib" in record.getMessage()
    ]
    assert warned, [record.getMessage() for record in caplog.records]
    assert not [line for line in warned if "2048" in line], warned


@pytest.mark.parametrize("cwd", ["deleted", "live"])
def test_validate_config_content_judges_an_out_of_namespace_module(
    tmp_path, monkeypatch, cwd
):
    """Client content naming a module outside the plugin namespace: the
    validator's module check refuses it in the loader's words whether the
    working directory is live or deleted -- never 'could not run'."""
    import json

    from automated_security_helper.cli import mcp_tools

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    if cwd == "deleted":
        _delete_working_directory(tmp_path, monkeypatch)
    else:
        plain = tmp_path / "plain"
        plain.mkdir()
        monkeypatch.chdir(plain)

    result = mcp_tools.mcp_validate_config(
        config_content="project_name: upload\nash_plugin_modules:\n  - json\n"
    )

    messages = json.dumps(result)
    assert "could not run" not in messages, result
    assert "TypeError" not in messages, result
    assert result.get("valid") is False, result
    assert "json" in json.dumps(result.get("errors")), result


@pytest.mark.parametrize(
    "value, module_tail",
    [
        pytest.param("teamx", "teamx_findings", id="value-before-an-underscore"),
        pytest.param("qz4b", "ASH_qz4b_logs", id="value-between-underscores"),
        pytest.param("qZ4b7", "qZ4b7_findings", id="secret-looking-value"),
    ],
)
def test_a_glued_environment_value_is_hidden_on_the_mcp_and_cli_surfaces(
    tmp_path, monkeypatch, value, module_tail
):
    """The product's strict word rule on its real redacted surfaces: a value
    the chain read from the environment, glued into a module name by "_",
    is hidden in validate_config's response and in `ash config validate`'s
    output (the module-check error passes the chain-wide redaction). The
    test-report rule, which keeps such paths whole, is not the product's."""
    import json

    from typer.testing import CliRunner

    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.main import app

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_GLUED", value)
    named = tmp_path / "ash.yaml"
    named.write_text(
        "project_name: !ENV ${ASH_GLUED:demo}\n"
        "ash_plugin_modules:\n"
        f"  - automated_security_helper.plugin_modules.{module_tail}\n",
        encoding="utf-8",
    )

    result = mcp_tools.mcp_validate_config(config_path=str(named))
    assert value not in json.dumps(result, default=str), result

    cli = CliRunner().invoke(app, ["config", "validate", "--config", str(named)])
    assert value not in cli.output, cli.output


def test_redact_values_has_no_report_rule_opt_in():
    """The test-report word rule is the private entry point's alone
    (_redact_for_test_reports): redact_values has no parameter for it, so no
    call through the public entry can turn the relaxed rule on -- passing the
    old keyword fails at the call. The routes the signature cannot see (a
    product import of the private entry, a direct private-keyword call) are
    the source scan's, in the cell below."""
    import inspect

    from automated_security_helper.config import config_validator

    assert (
        "underscore_joins_words"
        not in inspect.signature(config_validator.redact_values).parameters
    )
    with pytest.raises(TypeError):
        config_validator.redact_values("text", ["value"], underscore_joins_words=True)


def test_the_report_rule_stays_out_of_product_code():
    """The signature cell above blocks the redact_values keyword; this scan
    closes the routes a signature cannot see: a product import of
    _redact_for_test_reports, or a direct _replace_values /
    _whole_word_spans call passing underscore_joins_words, both of which
    still take the keyword. Only config_validator.py, which defines them,
    may mention either name. The definer doubles as the scan's own control:
    a scanner that read nothing would pass vacuously, so the one file that
    does mention both must be seen mentioning both. The definer's own
    product sites are the AST cell's, below."""
    import automated_security_helper

    package_root = Path(automated_security_helper.__file__).resolve().parent
    tokens = ("_redact_for_test_reports", "underscore_joins_words")
    offenders = {}
    definer_hits: list = []
    for source in sorted(package_root.rglob("*.py")):
        text = source.read_text(encoding="utf-8", errors="replace")
        hits = [token for token in tokens if token in text]
        if not hits:
            continue
        relative = source.relative_to(package_root).as_posix()
        if relative == "config/config_validator.py":
            definer_hits = hits
        else:
            offenders[relative] = hits
    assert definer_hits == list(tokens), definer_hits
    assert offenders == {}, offenders


def test_the_definer_takes_the_report_rule_only_inside_its_entry_point():
    """The scan above allows every mention in the defining file, so a
    config_validator.py product site (ConfigCheck.redact, the check
    formatters) could take the report rule unseen by it. This cell reads the
    definer by AST: _redact_for_test_reports appears only as its own
    function definition, never as a Name or Attribute use; the
    underscore_joins_words keyword appears only inside that definition and
    inside _replace_values, where its forwarding to _whole_word_spans must
    pass the enclosing parameter itself, never a value of its own; every
    parameter of that name defaults to the constant False; no string
    constant equals the private name, which also covers globals()/vars()
    lookups, getattr with the whole name, and pieces the parser joins; and
    no string constant anywhere in the product package equals the keyword's
    name, which closes ** mappings however they are built -- literal, bound
    to a name, or comprehended -- and dict-driven setattr/update routes.
    Docstring mentions are longer strings, so documentation edits do not
    move it. Only a name assembled at runtime stays outside this check, as
    it stays outside any source scan."""
    import ast

    import automated_security_helper

    package_root = Path(automated_security_helper.__file__).resolve().parent
    tree = ast.parse(
        (package_root / "config" / "config_validator.py").read_text(encoding="utf-8")
    )
    uses = [
        (type(node).__name__, node.lineno)
        for node in ast.walk(tree)
        if (isinstance(node, ast.Name) and node.id == "_redact_for_test_reports")
        or (isinstance(node, ast.Attribute) and node.attr == "_redact_for_test_reports")
    ]
    assert uses == [], uses
    definitions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_redact_for_test_reports"
    ]
    assert len(definitions) == 1, [node.lineno for node in definitions]
    # The keyword's two legitimate homes; their presence is also this cell's
    # own control, since a scanner that found no keyword at all would say
    # nothing about the rule.
    allowed_spans = {
        node.name: (node.lineno, node.end_lineno)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in ("_redact_for_test_reports", "_replace_values")
    }
    assert set(allowed_spans) == {
        "_redact_for_test_reports",
        "_replace_values",
    }, allowed_spans
    keyword_nodes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.keyword) and node.arg == "underscore_joins_words"
    ]
    keyword_sites = [node.value.lineno for node in keyword_nodes]
    stray_keywords = [
        line
        for line in keyword_sites
        if not any(lo <= line <= hi for lo, hi in allowed_spans.values())
    ]
    assert stray_keywords == [], stray_keywords
    for name, (lo, hi) in allowed_spans.items():
        assert any(lo <= line <= hi for line in keyword_sites), (name, keyword_sites)
    # The forwarding site passes the enclosing parameter itself: a value of
    # its own there (True, say) would give every product message the report
    # rule, and the behavior cells alone would have to catch it.
    forwarding_lo, forwarding_hi = allowed_spans["_replace_values"]
    forwarded = [
        node
        for node in keyword_nodes
        if forwarding_lo <= node.value.lineno <= forwarding_hi
    ]
    assert forwarded and all(
        isinstance(node.value, ast.Name) and node.value.id == "underscore_joins_words"
        for node in forwarded
    ), [(node.value.lineno, ast.dump(node.value)) for node in forwarded]
    # The forwarded check reads the Name's spelling, not its binding: a
    # statement inside _replace_values that rebinds the name (an assignment,
    # a walrus, a for or with target) would hand every product message the
    # report rule while the checks above all pass. No store or delete of the
    # keyword's name may sit in that span; the parameter itself is not a
    # Name node, so the legitimate forwarding stays outside this list.
    rebinding = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == "underscore_joins_words"
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and forwarding_lo <= node.lineno <= forwarding_hi
    ]
    assert rebinding == [], rebinding
    # Every parameter of the keyword's name defaults to the constant False:
    # the rule is off unless the entry point turns it on.
    defaults = [
        (definition.lineno, default)
        for definition in ast.walk(tree)
        if isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef))
        for arg, default in [
            *zip(
                (definition.args.posonlyargs + definition.args.args)[::-1],
                definition.args.defaults[::-1],
            ),
            *(
                (arg, default)
                for arg, default in zip(
                    definition.args.kwonlyargs, definition.args.kw_defaults
                )
                if default is not None
            ),
        ]
        if arg.arg == "underscore_joins_words"
    ]
    assert defaults, "no definer takes the keyword"
    assert all(
        isinstance(default, ast.Constant) and default.value is False
        for _, default in defaults
    ), [(line, ast.dump(default)) for line, default in defaults]
    name_constants = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and node.value == "_redact_for_test_reports"
    ]
    assert name_constants == [], name_constants
    # No string constant in the whole product package equals the keyword's
    # name: that closes every mapping shape (a ** dict literal, a mapping
    # bound to a name, a comprehension) and any dict-driven call, wherever
    # it sits. The two legitimate keyword sites are keyword arguments, not
    # constants, so the tip count is zero.
    key_constants = [
        (str(path.relative_to(package_root)), node.lineno)
        for path in sorted(package_root.rglob("*.py"))
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Constant) and node.value == "underscore_joins_words"
    ]
    assert key_constants == [], key_constants


@pytest.mark.parametrize(
    "patch_lines",
    [
        pytest.param(
            "  - op: add\n"
            "    path: /scanners/Detect-Secrets/options/max_worker_output_mib\n"
            "    value: 4096\n",
            id="deep-add",
        ),
        pytest.param(
            "  - op: add\n    path: /scanners/DETECT_SECRETS\n    value:\n"
            "      options:\n        max_worker_output_mib: 4096\n",
            id="whole-section-add",
        ),
    ],
)
def test_a_repository_case_variant_patch_cannot_set_the_limit(
    tmp_path, monkeypatch, patch_lines
):
    """A repository file holding detect-secrets' section patches this
    operator-only limit under a case variant of the section name. The
    pointer fold lands the op on the held section -- never as a twin the
    exact-spelling lookup would miss -- and the limit stays the default:
    folding changes where a repository write lands, not whose write it is."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_section_names import (
        folded_section_name,
    )
    from automated_security_helper.config.resolve_config import resolve_config
    from tests.utils.helpers import mark_git_checkout

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text(
        "scanners:\n  detect-secrets:\n    options:\n"
        "      skip_generated_lockfiles: false\n"
        "patch:\n" + patch_lines,
        encoding="utf-8",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(f"extends:\n  - {repository.as_posix()}\n", encoding="utf-8")

    config = resolve_config(config_path=operator, source_dir=checkout)

    default = AshConfig().scanners.detect_secrets.options.max_worker_output_mib
    # Premise: the patch loaded onto the declared section, never as a twin.
    extras = config.scanners.__pydantic_extra__ or {}
    assert not [
        key for key in extras if folded_section_name(str(key)) == "detectsecrets"
    ], extras
    assert config.scanners.detect_secrets.options.max_worker_output_mib == default


@pytest.mark.parametrize(
    "env_value", ["AWS-Security-Hub", "AWS_Security_Hub"], ids=["dashes", "underscores"]
)
def test_the_no_tree_warning_masks_a_key_the_chain_read_from_the_environment(
    tmp_path, monkeypatch, caplog, env_value
):
    """The fail-closed warning names places, and a section key the ASH_CONFIG
    chain resolved from an environment variable IS what that variable holds:
    the place prints with the value masked, as the validator prints the same
    place strings, and the rest of the place (the option's own name) stays
    readable. Both separator spellings of the value are masked, since the
    found record folds "-" and "_" and the place can print either."""
    from tests.utils.helpers import mark_git_checkout

    from automated_security_helper.cli import mcp_tools

    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    cfg = checkout / ".ash" / ".ash.yaml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(
        "project_name: here\nreporters:\n"
        "  !ENV ${ASH_RK:aws-security-hub}:\n"
        "    options:\n      findings_scope: repo-scope\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_RK", env_value)
    monkeypatch.setenv("ASH_CONFIG", str(cfg))
    named = tmp_path / "plain" / "ash.yaml"
    named.parent.mkdir()
    named.write_text("project_name: named\n", encoding="utf-8")
    _delete_working_directory(tmp_path, monkeypatch)

    with caplog.at_level(logging.DEBUG):
        result = mcp_tools.mcp_get_config(config_path=str(named))

    assert result.get("project_name") == "named", result
    warned = [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING and "fail-closed" in record.getMessage()
    ]
    assert warned, [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING
    ]
    # Lower-cased: the found record folds key spellings, so a case-sensitive
    # compare would pass on the folded spelling with no redaction at all. The
    # masked place must show the placeholder where the key was.
    assert not [line for line in warned if "aws-security-hub" in line.lower()], warned
    assert [line for line in warned if "<value>" in line], warned
    assert [line for line in warned if "findings_scope" in line], warned


def test_the_settle_warning_masks_a_key_the_chain_read_from_the_environment(
    tmp_path, monkeypatch, caplog
):
    """The live settle warning names places, and a section key the chain
    resolved from an environment variable IS what that variable holds: the
    place prints with the value masked, as the fail-closed warning and the
    validator print the same place strings, and the option's own name stays
    readable."""
    from tests.utils.helpers import mark_git_checkout

    from automated_security_helper.config.resolve_config import resolve_config

    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    cfg = checkout / ".ash" / ".ash.yaml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(
        "project_name: here\nreporters:\n"
        "  !ENV ${ASH_RK:aws-security-hub}:\n"
        "    options:\n      findings_scope: repo-scope\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_RK", "AWS-Security-Hub")
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    with caplog.at_level(logging.WARNING):
        resolve_config(config_path=cfg, source_dir=checkout)

    warned = [
        record.getMessage()
        for record in caplog.records
        if "Ignoring" in record.getMessage() and "findings_scope" in record.getMessage()
    ]
    assert warned, [record.getMessage() for record in caplog.records]
    assert not [line for line in warned if "aws-security-hub" in line.lower()], warned
    assert [line for line in warned if "<value>" in line], warned


def test_the_settle_warning_keeps_fixed_names_beside_an_env_read_value(
    tmp_path, monkeypatch, caplog
):
    """A VALUE the chain read from the environment cannot appear in a place
    string, which is built from mapping keys alone -- so the settle warning
    redacts places against KEY reads only, and an env-read option value that
    happens to spell part of a fixed name ("aws" here, a word of the section
    name) leaves the warning's section and option names whole and readable."""
    from tests.utils.helpers import mark_git_checkout

    from automated_security_helper.config.resolve_config import resolve_config

    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    cfg = checkout / ".ash" / ".ash.yaml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(
        "project_name: here\nreporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: repo-scope\n"
        "      aws_region: !ENV ${ASH_RG:aws}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_RG", "aws")
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    with caplog.at_level(logging.WARNING):
        resolve_config(config_path=cfg, source_dir=checkout)

    warned = [
        record.getMessage()
        for record in caplog.records
        if "Ignoring" in record.getMessage() and "findings_scope" in record.getMessage()
    ]
    assert warned, [record.getMessage() for record in caplog.records]
    assert [line for line in warned if "aws-security-hub" in line], warned
    assert not [line for line in warned if "<value>-security-hub" in line], warned


_MERGED_SPELLINGS = {
    "base-dash-env-underscore": ("aws-security-hub", "aws_security_hub"),
    "base-underscore-env-dash": ("aws_security_hub", "aws-security-hub"),
}


def _value_shown(lines, spelling):
    variants = {spelling, spelling.replace("-", "_"), spelling.replace("_", "-")}
    return [line for line in lines if any(v in line for v in variants)]


def _merged_respelled_chain(tmp_path, monkeypatch, pair):
    from tests.utils.helpers import mark_git_checkout

    base_key, env_key = _MERGED_SPELLINGS[pair]
    checkout = tmp_path / "env-checkout"
    mark_git_checkout(checkout)
    base = checkout / ".ash" / "base.yaml"
    base.parent.mkdir(parents=True, exist_ok=True)
    base.write_text(
        f"reporters:\n  {base_key}:\n    options:\n      findings_scope: repo-scope\n",
        encoding="utf-8",
    )
    cfg = checkout / ".ash" / ".ash.yaml"
    cfg.write_text(
        f"project_name: here\nextends: {base.as_posix()}\nreporters:\n"
        "  !ENV ${ASH_RK:aws-security-hub}:\n"
        "    options:\n      archive_resolved_findings: true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_RK", env_key)
    monkeypatch.setenv("ASH_CONFIG", str(cfg))
    return checkout, env_key


@pytest.mark.parametrize("cwd", ["deleted", "live"])
@pytest.mark.parametrize("pair", list(_MERGED_SPELLINGS))
def test_a_merged_respelled_key_is_masked_in_every_warning(
    tmp_path, monkeypatch, caplog, pair, cwd
):
    """A base spelled one way merged under a root key read from the
    environment the other: EVERY warning line masks the key in all its
    separator spellings. The no-config shape speaks through the settle step,
    so the respellings that matter are shown_places' -- dropping them shows
    the env-read key beside the masked one."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
        SecurityHubReporter,
    )

    checkout, env_key = _merged_respelled_chain(tmp_path, monkeypatch, pair)
    if cwd == "deleted":
        _delete_working_directory(tmp_path, monkeypatch)
    else:
        monkeypatch.chdir(checkout)
    with caplog.at_level(logging.WARNING):
        config = resolve_config()
        reporter_section(config, SecurityHubReporter)
    warned = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert [line for line in warned if "findings_scope" in line], warned
    assert not _value_shown(warned, env_key), [
        line.replace(env_key, "#V#") for line in warned
    ]


@pytest.mark.parametrize("pair", list(_MERGED_SPELLINGS))
def test_a_selected_config_s_fail_closed_warning_masks_a_merged_respelled_key(
    tmp_path, monkeypatch, caplog, pair
):
    """The one shape that still reaches warn_fail_closed's "-"/"_"
    respellings: a selected config outside every checkout, the working
    directory deleted, and ASH_CONFIG's checkout chain merging a base spelled
    one way under an env-read root key the other."""
    from automated_security_helper.config.resolve_config import resolve_config

    _checkout, env_key = _merged_respelled_chain(tmp_path, monkeypatch, pair)
    named = tmp_path / "plain" / "ash.yaml"
    named.parent.mkdir()
    named.write_text("project_name: named\n", encoding="utf-8")
    _delete_working_directory(tmp_path, monkeypatch)
    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=named)
    assert config.project_name == "named"
    warned = [r.getMessage() for r in caplog.records if "fail-closed" in r.getMessage()]
    assert [line for line in warned if "findings_scope" in line], [
        r.getMessage() for r in caplog.records
    ]
    assert not _value_shown(warned, env_key), [
        line.replace(env_key, "#V#") for line in warned
    ]


def test_the_fail_closed_warning_keeps_fixed_names_beside_an_env_read_value(
    tmp_path, monkeypatch, caplog
):
    """The fail-closed voice under the same key-only rule as the settle step:
    an option VALUE the ASH_CONFIG chain read from the environment ("aws",
    spelling part of the section's own name) leaves the warning's place
    strings whole -- the two warnings share one place redaction, so neither
    can hide a fixed name the other shows."""
    from tests.utils.helpers import mark_git_checkout

    from automated_security_helper.config.resolve_config import resolve_config

    checkout = tmp_path / "env-checkout"
    mark_git_checkout(checkout)
    cfg = checkout / ".ash" / ".ash.yaml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(
        "project_name: here\nreporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: repo-scope\n"
        "      aws_region: !ENV ${ASH_RG:aws}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_RG", "aws")
    monkeypatch.setenv("ASH_CONFIG", str(cfg))
    named = tmp_path / "plain" / "ash.yaml"
    named.parent.mkdir()
    named.write_text("project_name: named\n", encoding="utf-8")
    _delete_working_directory(tmp_path, monkeypatch)

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=named)

    assert config.project_name == "named"
    warned = [r.getMessage() for r in caplog.records if "fail-closed" in r.getMessage()]
    assert [line for line in warned if "aws-security-hub" in line], warned
    assert not [line for line in warned if "<value>-security-hub" in line], warned


def test_an_untrusted_config_with_no_working_directory_refuses_its_modules(
    tmp_path, monkeypatch
):
    """A client-supplied config (untrusted_config) with the working directory
    deleted: with no tree to judge a module's location against, an installed
    module's checkout could be the very one the missing working directory
    would have named, so every entry outside the trusted list refuses the
    load, naming the gone working directory -- never a judged keep. The
    installed `yaml` rides along to pin that even an importable,
    out-of-every-tree entry is refused here."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    named = tmp_path / "ash.yaml"
    missing = "automated_security_helper.plugin_modules.zz_missing_module"
    named.write_text(
        f"project_name: client\nash_plugin_modules:\n  - {missing}\n  - yaml\n",
        encoding="utf-8",
    )
    _delete_working_directory(tmp_path, monkeypatch)

    with pytest.raises(ASHConfigSourceError) as caught:
        resolve_config(config_path=named, untrusted_config=True)
    text = str(caught.value)
    assert "working directory" in text and "ash_plugin_modules" in text, text
    assert "'yaml'" in text and "zz_missing_module" in text, text


def test_untrusted_content_with_trusted_modules_and_no_working_directory_loads(
    tmp_path, monkeypatch
):
    """The refusal above is scoped to entries OUTSIDE the trusted list: client
    content whose entries all come from the trusted base still answers with
    the working directory deleted, the trusted module kept. The override is
    the operator's own text, so it extends the trusted list the way the
    confine replays overrides onto the trusted base."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    named = tmp_path / "ash.yaml"
    named.write_text(
        "project_name: client\nash_plugin_modules:\n  - yaml\n", encoding="utf-8"
    )
    _delete_working_directory(tmp_path, monkeypatch)

    config = resolve_config(
        config_path=named,
        untrusted_config=True,
        config_overrides=['ash_plugin_modules+=["yaml"]'],
    )
    assert "yaml" in (config.ash_plugin_modules or []), config.ash_plugin_modules

    assert config.project_name == "client"


def test_the_validator_judges_an_untrusted_config_with_no_working_directory(
    tmp_path, monkeypatch
):
    """The surface the escape reached: check_config_file of an untrusted
    config with the working directory deleted reports the module entry as
    the FILE's error (valid False, naming the gone working directory), with
    no 'could not run' warning standing in for the judgement and no silent
    skip passing the file."""
    from automated_security_helper.config.config_validator import ConfigValidator

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    named = tmp_path / "ash.yaml"
    named.write_text(
        "project_name: client\nash_plugin_modules:\n"
        "  - automated_security_helper.plugin_modules.zz_missing_module\n",
        encoding="utf-8",
    )
    _delete_working_directory(tmp_path, monkeypatch)

    check = ConfigValidator.check_config_file(named, untrusted_config=True)

    named_in_errors = [
        e
        for e in check.errors
        if "ash_plugin_modules" in e and "working directory" in e
    ]
    assert named_in_errors, (check.errors, check.warnings)
    assert not [w for w in check.warnings if "could not run" in w], check.warnings


def test_discovery_with_no_working_directory_is_the_named_refusal(
    tmp_path, monkeypatch
):
    """resolve_config with no file, no source directory, no fallback and the
    working directory deleted: there is no directory to discover a config
    in, so the answer is the refusal a caller that forbids the fallback gets
    for a missing file -- not an error out of the discovery walk."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    _delete_working_directory(tmp_path, monkeypatch)

    with pytest.raises(ValueError, match="not found or provided"):
        resolve_config(fallback_to_default=False)


@pytest.mark.parametrize("modules", ["with-plugin-modules", "control-without"])
def test_validate_config_with_plugin_modules_and_no_working_directory(
    tmp_path, monkeypatch, modules
):
    """The validator's module check resolves the file again (resolve_config
    with source_dir None). With the working directory deleted that read goes
    through working_directory(), so a missing cwd is no error of the checked
    file. The control (no ash_plugin_modules, so no module check) shows the
    rest of the validator answers."""
    import json

    from automated_security_helper.cli import mcp_tools

    named = tmp_path / "plain" / "ash.yaml"
    named.parent.mkdir()
    named.write_text(
        "project_name: named\n"
        + (
            "ash_plugin_modules:\n"
            "  - automated_security_helper.plugin_modules.ash_aws_plugins\n"
            if modules == "with-plugin-modules"
            else ""
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    _delete_working_directory(tmp_path, monkeypatch)

    result = mcp_tools.mcp_validate_config(config_path=str(named))

    messages = json.dumps(result.get("errors"))
    assert "No such file" not in messages, result
    assert result.get("valid") is True, result
