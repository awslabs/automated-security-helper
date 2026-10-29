# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One pass refuses junk sandbox writes in every operator-owned file of BOTH chains.

An operator-owned file that writes a sandbox mode outside the known set tried
to set a sandbox, and a later write in the chain can bury it under a section
the merged load accepts, so the scan would run without one. The refusal used
to be decided per load path: the selected config's chain was walked when a
config file was named, the ASH_CONFIG chain only when none was, so the same
junk in the same ASH_CONFIG file was refused by ``ash scan`` and loaded by
``ash scan --config <file outside the scanned tree>``. The ASH_CONFIG file is
the base of both loads. The pass now walks the owned files of the selected
chain and of the ASH_CONFIG chain on every path.

The same pass refuses an owned file whose ``sandbox`` is written as a scalar,
through its document or its own patch, which the walk used to skip.
"""

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigFileNotFoundError,
    ASHConfigValidationError,
)
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit


def _write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _root(tmp_path, name, bases):
    """An operator root file extending *bases*, written by hand."""
    listing = "".join(f"- {base.as_posix()}\n" for base in bases)
    return _write_text(tmp_path / name, f"project_name: {name}\nextends:\n{listing}")


def _junk_chain(tmp_path, name="ash-root.yaml"):
    """A wholly operator-owned chain: a base that writes a mode outside the
    known set, then a base that buries it under bwrap."""
    junk = _write_text(tmp_path / "plain" / "junk.yaml", "sandbox:\n  mode: banana\n")
    bury = _write_text(tmp_path / "plain" / "bury.yaml", "sandbox:\n  mode: bwrap\n")
    return _root(tmp_path, name, [junk, bury])


def _outside_config(tmp_path):
    """A config file wholly outside the scanned tree that writes no sandbox."""
    return _write_text(
        tmp_path / "cli" / "cfg.yaml", "project_name: named-on-the-command-line\n"
    )


def _scanned_tree(tmp_path):
    src = tmp_path / "src"
    mark_git_checkout(src)
    return src


def _with_ash_config(monkeypatch, src, ash_config):
    monkeypatch.chdir(src)
    monkeypatch.setenv("ASH_CONFIG", str(ash_config))


def test_a_junk_write_in_the_ash_config_chain_refuses_with_a_config_outside_the_tree(
    tmp_path, monkeypatch
):
    """The red cell. ASH_CONFIG names a chain whose owned file writes junk
    and whose later owned file buries it; ``--config`` names a file wholly
    outside the scanned tree. The ASH_CONFIG file is the base of this load,
    so it refuses as it does when no ``--config`` is given."""
    src = _scanned_tree(tmp_path)
    _with_ash_config(monkeypatch, src, _junk_chain(tmp_path))
    cfg = _outside_config(tmp_path)
    with pytest.raises(ASHConfigValidationError):
        resolve_config(config_path=cfg, source_dir=src, trusted_config_path=cfg)


def test_control_the_same_ash_config_chain_refuses_with_no_config_option(
    tmp_path, monkeypatch
):
    """The path that already refused: pins that it still does."""
    src = _scanned_tree(tmp_path)
    _with_ash_config(monkeypatch, src, _junk_chain(tmp_path))
    with pytest.raises(ASHConfigValidationError):
        resolve_config(source_dir=src)


def test_control_a_junk_write_in_the_selected_chain_still_refuses(
    tmp_path, monkeypatch
):
    src = _scanned_tree(tmp_path)
    monkeypatch.chdir(src)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    selected = _junk_chain(tmp_path, name="selected.yaml")
    with pytest.raises(ASHConfigValidationError):
        resolve_config(
            config_path=selected, source_dir=src, trusted_config_path=selected
        )


def test_control_an_ash_config_chain_of_known_modes_loads_with_a_config_outside(
    tmp_path, monkeypatch
):
    """The refusal above is the junk write's, not the ASH_CONFIG file's."""
    src = _scanned_tree(tmp_path)
    first = _write_text(tmp_path / "plain" / "a.yaml", "sandbox:\n  mode: firejail\n")
    last = _write_text(tmp_path / "plain" / "b.yaml", "sandbox:\n  mode: bwrap\n")
    _with_ash_config(monkeypatch, src, _root(tmp_path, "ash-root.yaml", [first, last]))
    cfg = _outside_config(tmp_path)
    config = resolve_config(config_path=cfg, source_dir=src, trusted_config_path=cfg)
    assert config.project_name == "named-on-the-command-line"


def test_a_junk_write_in_the_ash_config_chain_refuses_when_the_named_config_is_missing(
    tmp_path, monkeypatch
):
    """A load that does not fall back to the defaults and names a config file
    that is not there resolves to no config at all, yet it still read the
    ASH_CONFIG chain as its base. The junk pass runs on every load, so the
    owned junk in that chain refuses here as it does when the file exists."""
    src = _scanned_tree(tmp_path)
    _with_ash_config(monkeypatch, src, _junk_chain(tmp_path))
    missing = tmp_path / "cli" / "not-there.yaml"
    with pytest.raises(ASHConfigValidationError):
        resolve_config(config_path=missing, source_dir=src, fallback_to_default=False)


def test_control_a_missing_named_config_is_refused_over_a_clean_chain(
    tmp_path, monkeypatch
):
    """The load shape above is real and reaches the missing-file refusal: with
    an ASH_CONFIG chain of known modes it is refused as a config file that is
    not there, and not as a junk write, so the refusal in the test above is the
    junk pass's, not the missing file's."""
    src = _scanned_tree(tmp_path)
    first = _write_text(tmp_path / "plain" / "a.yaml", "sandbox:\n  mode: firejail\n")
    last = _write_text(tmp_path / "plain" / "b.yaml", "sandbox:\n  mode: bwrap\n")
    _with_ash_config(monkeypatch, src, _root(tmp_path, "ash-root.yaml", [first, last]))
    missing = tmp_path / "cli" / "not-there.yaml"
    with pytest.raises(ASHConfigFileNotFoundError) as refused:
        resolve_config(config_path=missing, source_dir=src, fallback_to_default=False)
    message = str(refused.value)
    assert message.startswith("Configuration file not found: "), message
    assert missing.as_posix() in message, message
    # The junk pass's wording (_unknown_owned_mode_refusal) is absent, so this
    # control still tells the two chains apart.
    assert "sets a sandbox mode" not in message, message


_SCALAR_OWNED_FILES = {
    "key": "sandbox: bwrap\n",
    "patch": "patch:\n- op: add\n  path: /sandbox\n  value: bwrap\n",
}


def _scalar_chain(tmp_path, owned_text):
    """An operator root whose own base writes a scalar sandbox and whose later
    base, in the scanned checkout, writes a valid section."""
    src = _scanned_tree(tmp_path)
    owned = _write_text(tmp_path / "plain" / "scalar.yaml", owned_text)
    lower = _write_text(src / "cfg" / "lower.yaml", "sandbox:\n  mode: firejail\n")
    return src, _root(tmp_path, "ash-root.yaml", [owned, lower])


@pytest.mark.parametrize("route", ["ash_config", "config_file"])
@pytest.mark.parametrize("arm", sorted(_SCALAR_OWNED_FILES))
def test_an_owned_scalar_sandbox_buried_by_an_in_tree_section_refuses(
    tmp_path, monkeypatch, route, arm
):
    """The red cell for the non-mapping write. The operator's own file writes
    ``sandbox`` as a scalar, through its document or its own patch, and a base
    in the scanned checkout later in the chain writes a valid section, so the
    merged chain validates with the operator's write erased. The file tried to
    set a sandbox, so the load is refused the way an unknown mode is."""
    src, root = _scalar_chain(tmp_path, _SCALAR_OWNED_FILES[arm])
    monkeypatch.chdir(src)
    if route == "ash_config":
        monkeypatch.setenv("ASH_CONFIG", str(root))
        with pytest.raises(ASHConfigValidationError) as refused:
            resolve_config(source_dir=src)
    else:
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        with pytest.raises(ASHConfigValidationError) as refused:
            resolve_config(config_path=root, source_dir=src, trusted_config_path=root)
    message = str(refused.value)
    assert (tmp_path / "plain" / "scalar.yaml").as_posix() in message, message
    assert "bwrap" not in message, message


_REFUSED_OWNED_SANDBOXES = {
    "scalar": ("sandbox: bwrap\n", "bwrap"),
    "unknown_mode": ("sandbox:\n  mode: banana\n", "banana"),
}


def _env_chain(tmp_path, owned_text, via_environment):
    """An operator root whose first base is the owned file ``<sub>/mid.yaml``
    and whose later base, in the scanned checkout, writes a valid section, so
    the merged chain validates and only the owned-file walk can refuse. With
    *via_environment* the first entry is ``${ASH_OWNED_SUB}/mid.yaml`` and the
    variable holds ``sub``, so the file's path IS the variable's value;
    otherwise the entry spells the path out. Returns the scanned tree, the
    root, the owned file and ``sub``."""
    src = _scanned_tree(tmp_path)
    sub = "owned-sub-5b81"
    owned = _write_text(tmp_path / sub / "mid.yaml", owned_text)
    lower = _write_text(src / "cfg" / "lower.yaml", "sandbox:\n  mode: firejail\n")
    entry = f"${{ASH_OWNED_SUB}}/{owned.name}" if via_environment else owned.as_posix()
    root = _write_text(
        tmp_path / "ash-root.yaml",
        f"project_name: ash-root\nextends:\n- {entry}\n- {lower.as_posix()}\n",
    )
    return src, root, owned, sub


def _refusal_text(monkeypatch, src, root, route):
    monkeypatch.chdir(src)
    if route == "ash_config":
        monkeypatch.setenv("ASH_CONFIG", str(root))
        with pytest.raises(ASHConfigValidationError) as refused:
            resolve_config(source_dir=src)
    else:
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        with pytest.raises(ASHConfigValidationError) as refused:
            resolve_config(config_path=root, source_dir=src, trusted_config_path=root)
    return str(refused.value)


@pytest.mark.parametrize("route", ["ash_config", "config_file"])
@pytest.mark.parametrize("arm", sorted(_REFUSED_OWNED_SANDBOXES))
def test_an_owned_file_an_environment_value_chose_is_named_by_its_hidden_form(
    tmp_path, monkeypatch, route, arm
):
    """The operator's own base is reached through ``extends:
    ${ASH_OWNED_SUB}/mid.yaml`` and writes a sandbox the walk refuses. The
    file's path holds the variable's value, so the refusal names the file as
    the environment-value marker and prints neither the value nor the path."""
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    text, written = _REFUSED_OWNED_SANDBOXES[arm]
    src, root, owned, sub = _env_chain(tmp_path, text, via_environment=True)
    monkeypatch.setenv("ASH_OWNED_SUB", sub)
    message = _refusal_text(monkeypatch, src, root, route)
    assert ENVIRONMENT_VALUE_SHOWN in message, message
    assert sub not in message, message
    assert owned.as_posix() not in message, message
    assert written not in message, message


@pytest.mark.parametrize("route", ["ash_config", "config_file"])
@pytest.mark.parametrize("arm", sorted(_REFUSED_OWNED_SANDBOXES))
def test_control_the_same_owned_file_chosen_by_a_plain_path_is_named_by_its_path(
    tmp_path, monkeypatch, route, arm
):
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    text, written = _REFUSED_OWNED_SANDBOXES[arm]
    src, root, owned, _sub = _env_chain(tmp_path, text, via_environment=False)
    message = _refusal_text(monkeypatch, src, root, route)
    assert owned.as_posix() in message, message
    assert ENVIRONMENT_VALUE_SHOWN not in message, message
    assert written not in message, message


def test_control_an_owned_valid_section_still_loads_and_the_floor_applies(
    tmp_path, monkeypatch
):
    """The operator's own base sets firejail and a base in the scanned
    checkout after it writes off: the owned section loads and the in-tree
    write cannot turn it off."""
    src = _scanned_tree(tmp_path)
    owned = _write_text(
        tmp_path / "plain" / "mode.yaml", "sandbox:\n  mode: firejail\n"
    )
    lower = _write_text(src / "cfg" / "lower.yaml", 'sandbox:\n  mode: "off"\n')
    _with_ash_config(monkeypatch, src, _root(tmp_path, "ash-root.yaml", [owned, lower]))
    assert resolve_config(source_dir=src).sandbox.mode == "firejail"
