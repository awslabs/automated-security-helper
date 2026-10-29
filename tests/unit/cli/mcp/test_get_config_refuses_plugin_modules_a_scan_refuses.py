# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config refuses a config whose plugin modules every scan refuses.

``ash config get`` judges the ``ash_plugin_modules`` list a scan would import
(``plugin_module_trust.refuse_plugin_modules_a_scan_refuses``) and exits 3 with
the module named and the config commands' closing. get_config answered the
same file with the resolved config, as a success with neither closing, so an
agent client was shown a configuration every scan of it refuses. The scan
tool already answers ``success`` False for a refused selection, and
validate_config reports the same entries as errors; this file pins get_config
to the same agreement, in the words ``ash config get`` prints.

Both refusal arms are covered: a module outside the plugin namespace, and a
namespace module no installed package provides. The list judged is the one
an MCP scan imports, nothing more: ``ASH_PLUGIN_MODULES`` is a CLI scan
option's variable that no MCP scan reads, so it never refuses an answer
here, and the ASH_CONFIG chain is judged under the same trust confinement a
scan applies, so an in-tree chain file's unimportable entry is dropped, not
refused. The closing is the MCP surface's own -- it never says nothing was
scanned and never names ``--ash-plugin-modules`` or ``--config-overrides``,
options an MCP client does not have; it names what a client can change: the
config file, or the config content sent.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

import pytest

SESSION = "client-one"
OUTSIDE = "outside_module_r"
NOT_PROVIDED = "ash_plugins.module_no_package_provides"


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "roots" / "project"
    root.mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "roots"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    # A named file's entries are judged against the scan target run_ash_scan
    # would take: the working directory. The cells' verdicts must not depend
    # on where pytest was started (a cwd inside a checkout, or a --basetemp
    # inside the cwd, drops the entries as in-tree instead of refusing), so
    # every cell runs from a neutral directory the configs are outside of.
    neutral = tmp_path / "neutral-cwd"
    neutral.mkdir()
    monkeypatch.chdir(neutral)
    return root.resolve()


@pytest.fixture
def planted_module(root: Path, monkeypatch: pytest.MonkeyPatch):
    """An importable module on sys.path that writes a marker when imported."""
    modules = root.parent / "modules"
    modules.mkdir()
    (modules / f"{OUTSIDE}.py").write_text(
        "from pathlib import Path\n"
        "Path(__file__).with_suffix('.imported').write_text('ran')\n"
    )
    monkeypatch.delitem(sys.modules, OUTSIDE, raising=False)
    monkeypatch.syspath_prepend(str(modules))
    yield modules
    sys.modules.pop(OUTSIDE, None)


def _get_config(**kwargs: Any) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    return mcp_get_config(session_id=SESSION, **kwargs)


def _refused(response: Dict[str, Any]) -> str:
    assert response.get("success") is False, response
    assert response["exit_code"] == 3, response
    # The refusal's own category, never invalid_format: the file loaded and
    # parsed, and a format category sent a client to re-format a healthy file.
    assert response["error_category"] == "plugin_module_refused", response
    message = str(response.get("error") or "")
    assert message, response
    return message


def _closed_in_the_mcp_surfaces_words(message: str) -> None:
    # The MCP surface's own closing, never the scan's or the CLI commands':
    # get_config checked a configuration, scanned nothing, and an MCP client
    # has no --ash-plugin-modules or --config-overrides option to remove an
    # entry from.
    assert "Nothing was imported" in message, message
    assert "nothing was scanned" not in message.lower(), message
    assert "--ash-plugin-modules" not in message, message
    assert "--config-overrides" not in message, message
    assert "ASH_PLUGIN_MODULES" not in message, message


def _denied_first(response: Dict[str, Any]) -> str:
    """The answer for a file the client's own rules refuse before any module is judged.

    A config an MCP client delivered, or named outside the directories
    ``ASH_MCP_ALLOWED_CONFIG_ROOTS`` names, is resolved under the server's
    runtime-override policy, and that policy lets a client narrow
    ``ash_plugin_modules`` but never add to it. The denial answers first: the
    field is named, the answer carries ``config_field_denied`` and no exit code,
    and the plugin-module judgment is not reached for such a file.
    """
    assert response.get("success") is False, response
    assert response["error_type"] == "config_field_denied", response
    message = str(response.get("error") or "")
    assert "ash_plugin_modules" in message, message
    return message


def test_a_module_outside_the_namespace_is_refused(root: Path, planted_module: Path):
    config = root / ".ash.yaml"
    config.write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {OUTSIDE}\n",
        encoding="utf-8",
    )

    message = _refused(_get_config(config_path=str(config)))

    assert OUTSIDE in message, message
    assert "is not a plugin module ASH imports" in message, message
    _closed_in_the_mcp_surfaces_words(message)
    # The namespace kind's own remedy, not the import kind's.
    assert "Rename the package" in message, message
    assert (
        "remove the entry from the config file or the config content sent" in message
    ), message
    # Refused before any import, as the scan refuses it.
    assert OUTSIDE not in sys.modules
    assert not (planted_module / f"{OUTSIDE}.imported").exists()


def test_a_namespace_module_no_package_provides_is_refused(root: Path):
    """The file is named by path outside any directory the operator granted for
    config, so it is the client's: the entry it adds is refused by the denied-field
    policy, naming the entry as the file wrote it, before the plugin-module
    judgment (the import-kind refusal) is reached."""
    config = root / ".ash.yaml"
    config.write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {NOT_PROVIDED}\n",
        encoding="utf-8",
    )

    message = _denied_first(_get_config(config_path=str(config)))

    assert NOT_PROVIDED in message, message
    assert "it is not importable from the installed environment" in message, message
    # The plugin-module refusal's closing and remedy belong to the later judgment.
    assert "Install what the module needs" not in message, message


def test_a_discovered_in_tree_file_is_answered_as_a_scan_treats_it(root: Path):
    """The list judged is the one a scan would import. A discovered file sits
    inside the searched tree, and a scan of that tree DROPS an in-tree file's
    unimportable entries with a warning rather than refusing (resolve_config's
    trust confinement), so get_config answers the config, with the entry gone,
    exactly as the scan would run under it."""
    (root / ".ash.yaml").write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {NOT_PROVIDED}\n",
        encoding="utf-8",
    )

    response = _get_config(search_dir=str(root))

    assert response.get("success") is not False, response
    assert response["project_name"] == "demo", response
    assert response.get("ash_plugin_modules") in ([], None), response


@pytest.mark.parametrize("route", ["no-file", "named-file"])
def test_the_environment_variable_no_mcp_scan_reads_never_refuses(
    root: Path, monkeypatch: pytest.MonkeyPatch, route: str
):
    """``ASH_PLUGIN_MODULES`` is the CLI scan option's variable; the MCP
    runner starts its scans without it, so get_config judging it would refuse
    answers for configs every MCP scan of the same inputs runs under -- and
    the refusal would hand the server's own variable content to the client.
    get_config ignores it, as the MCP scan and validate_config tools do."""
    monkeypatch.setenv("ASH_PLUGIN_MODULES", NOT_PROVIDED)
    if route == "named-file":
        config = root / ".ash.yaml"
        config.write_text("project_name: demo\n", encoding="utf-8")
        response = _get_config(config_path=str(config))
    else:
        response = _get_config(search_dir=str(root))

    assert response.get("success") is not False, response
    assert "project_name" in response, response
    assert NOT_PROVIDED not in str(response), response


def test_an_in_tree_ash_config_entry_is_dropped_as_a_scan_drops_it(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """With no config file, the answer is the configuration a scan of the
    searched tree starts from: the file ASH_CONFIG names. When that file sits
    inside the searched tree, a scan reads it under plugin-module trust
    confinement and DROPS its unimportable entries with a warning rather than
    refusing. get_config answers the same configuration, with the entry gone,
    instead of refusing a config such a scan runs under."""
    operator = root / "operator-config.yaml"
    operator.write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {NOT_PROVIDED}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    response = _get_config(search_dir=str(root))

    assert response.get("success") is not False, response
    assert response.get("ash_plugin_modules") in ([], None), response


@pytest.mark.parametrize(
    "entry, remedy, other_kinds_remedy",
    [
        (NOT_PROVIDED, "install what the module needs", "rename the package"),
        (OUTSIDE, "rename the package", "install what the module needs"),
    ],
    ids=["import-kind", "namespace-kind"],
)
def test_an_out_of_tree_ash_config_entry_still_refuses(
    root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry: str,
    remedy: str,
    other_kinds_remedy: str,
):
    """The boundary control: a scan KEEPS an unimportable entry a file outside
    the scanned tree writes and refuses the run, so get_config refuses too.
    Both refusal kinds carry the no-file closing, each with its own kind's
    remedy, never the other's."""
    operator = tmp_path / "operator-config.yaml"
    operator.write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {entry}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    message = _refused(_get_config(search_dir=str(root)))

    assert entry in message, message
    lowered = message.lower()
    assert remedy in lowered, message
    assert other_kinds_remedy not in lowered, message
    _closed_in_the_mcp_surfaces_words(message)
    # The no-file answer's entries are the operator configuration's: the
    # closing says so, naming the variable ASH_CONFIG -- never its value or
    # the file's path -- and offers no remedy the client cannot apply.
    assert "ASH_CONFIG" in message, message
    assert str(operator) not in message, message
    assert operator.name not in message, message
    assert "config content sent" not in message, message


@pytest.mark.parametrize("route", ["no-file", "named-file"])
def test_raw_mode_never_judges_plugin_modules(
    root: Path, monkeypatch: pytest.MonkeyPatch, route: str
):
    """``raw`` answers a document, not a run: with a file, its contents as
    written; with none, the default configuration. Judging plugin modules
    there made the same ``raw=True`` request succeed or fail depending on
    whether a file existed -- a refused entry in the ASH_CONFIG chain failed
    only the no-file form. raw mode never judges; the resolved read keeps the
    refusal (the boundary control below this file pins it)."""
    if route == "named-file":
        config = root / ".ash.yaml"
        config.write_text(
            f"project_name: demo\nash_plugin_modules:\n  - {NOT_PROVIDED}\n",
            encoding="utf-8",
        )
        response = _get_config(config_path=str(config), raw=True)
        # As written: the entry is the document's own text, shown, not judged.
        assert response.get("ash_plugin_modules") == [NOT_PROVIDED], response
    else:
        operator = root.parent / "operator-config.yaml"
        operator.write_text(
            f"project_name: demo\nash_plugin_modules:\n  - {NOT_PROVIDED}\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        response = _get_config(search_dir=str(root), raw=True)

    assert response.get("success") is not False, response
    assert "project_name" in response, response


def test_a_client_delivered_files_dropped_entries_never_refuse(
    tmp_path: Path, root: Path
):
    """A config an MCP client delivered is restrict-only: it may narrow
    ``ash_plugin_modules`` but never add an entry the installed environment
    cannot import. The server's denied-field policy refuses that entry while the
    file is resolved, naming it as the file wrote it, so the plugin-module
    judgment, which reads the resolved list, is never reached for a delivered
    file and its refusal never answers one. The answer holds no config."""
    upload = tmp_path / "mcp-workspaces" / SESSION / "upload"
    upload.mkdir(parents=True)
    config = upload / "client-config.yaml"
    config.write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {NOT_PROVIDED}\n",
        encoding="utf-8",
    )

    response = _get_config(config_path=str(config))

    message = _denied_first(response)
    assert NOT_PROVIDED in message, message
    assert response.get("error_category") != "plugin_module_refused", response
    assert "project_name" not in response, response


def test_an_entry_the_file_also_names_gets_no_environment_remedy(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """The refusal of an entry the config file names must not offer the
    environment remedy, whether or not the server's ``ASH_PLUGIN_MODULES``
    happens to hold the same text: the variable is never part of this
    surface's judgment, and unsetting it would fix nothing. The file is the
    client's (named outside the operator's config directories), so the refusal
    is the denied-field policy's, which names the file's entry and no option or
    variable a client could use to remove it."""
    monkeypatch.setenv("ASH_PLUGIN_MODULES", NOT_PROVIDED)
    config = root / ".ash.yaml"
    config.write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {NOT_PROVIDED}\n",
        encoding="utf-8",
    )

    message = _denied_first(_get_config(config_path=str(config)))

    assert NOT_PROVIDED in message, message
    assert "ASH_PLUGIN_MODULES" not in message, message
    assert "--ash-plugin-modules" not in message, message
    assert "--config-overrides" not in message, message


def test_a_named_file_is_not_refused_for_the_operator_chains_entry(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Config sources are selected, not merged: a named file replaces the
    ASH_CONFIG chain, so a refused entry in the operator's file never rides
    into the named file's resolved list, and the answer for a healthy named
    file stays a success. The no-file answers are where the operator chain's
    entries are judged (the cells above)."""
    operator = tmp_path / "operator-config.yaml"
    operator.write_text(
        f"project_name: op\nash_plugin_modules:\n  - {NOT_PROVIDED}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    config = root / "good.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")

    response = _get_config(config_path=str(config))

    assert response.get("success") is not False, response
    assert response.get("ash_plugin_modules") in ([], None), response
    # The control: naming the operator's own file refuses through the same
    # machinery, so a merge of the two sources could not pass this cell. The
    # operator file sits outside the allowed roots, so it is first copied
    # under them to be nameable.
    named_bad = root / "operator-copy.yaml"
    named_bad.write_text(operator.read_text(encoding="utf-8"), encoding="utf-8")
    control = _get_config(config_path=str(named_bad))
    assert control.get("success") is False, control


@pytest.fixture
def kept_module(root: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """An installed plugin module OUTSIDE the searched tree, so a config entry
    reading its name from the environment is kept by the trust confinement."""
    modules = root.parent.parent / "installed-modules"
    modules.mkdir(exist_ok=True)
    (modules / "keptmod_ash_plugins.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(modules))
    monkeypatch.setenv("ASH_PLUGMOD_KEPT", "keptmod_ash_plugins")
    return "keptmod_ash_plugins"


@pytest.mark.parametrize(
    "route, dropped",
    [
        ("no-file", [NOT_PROVIDED]),
        ("no-file", [NOT_PROVIDED, "ash_plugins.second_missing_module"]),
        ("discovered", [NOT_PROVIDED]),
    ],
    ids=["no-file-one-drop", "no-file-two-drops", "discovered-one-drop"],
)
def test_a_dropped_entry_does_not_unmask_the_one_after_it(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    kept_module: str,
    route: str,
    dropped: list,
):
    """The shown list is the confined read's, and its environment markers must
    move with it: when the trust confinement drops an entry AHEAD of one read
    from the environment, a marker matched at the first read's index points
    one entry too far, and the answer shows the environment value in clear.

    The operator's chain file (the ``no-file`` routes) is the one that reads the
    environment. A file discovered in the searched tree is not the operator's: a
    remote caller's answer resolves no ``!ENV`` or ``${VAR}`` in it, so that
    route is refused as ``config_env_not_resolved`` before any entry is judged or
    dropped, and the environment value is in no key of the answer."""
    entries = "".join(f"  - {name}\n" for name in dropped)
    text = (
        "project_name: demo\n"
        f"ash_plugin_modules:\n{entries}"
        "  - !ENV ${ASH_PLUGMOD_KEPT}\n"
    )
    if route == "discovered":
        (root / ".ash.yaml").write_text(text, encoding="utf-8")
    else:
        operator_dir = root / "ops"
        operator_dir.mkdir()
        operator = operator_dir / "operator-config.yaml"
        operator.write_text(text, encoding="utf-8")
        monkeypatch.setenv("ASH_CONFIG", str(operator))

    response = _get_config(search_dir=str(root))

    import json

    assert kept_module not in json.dumps(response, default=str), response
    if route == "discovered":
        assert response.get("success") is False, response
        assert response["error_type"] == "config_env_not_resolved", response
        return
    assert response.get("success") is not False, response
    assert response.get("ash_plugin_modules") == ["<from ${ASH_PLUGMOD_KEPT}>"], (
        response
    )


def test_a_dropped_entry_does_not_corrupt_the_literal_after_it(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """The marker machinery replaces the reference's environment piece inside
    the entry at its recorded index. A dropped entry ahead of a LITERAL whose
    text shares that piece turned the literal into a half-marker; the literal
    is the file's own text and is shown as written."""
    modules = root.parent.parent / "survivor-modules"
    modules.mkdir()
    (modules / "survout_ash_plugins.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(modules))
    monkeypatch.setenv("ASH_PLUGMOD_PFX", "surv")
    operator = root / "ops-operator.yaml"
    operator.write_text(
        "project_name: demo\n"
        "ash_plugin_modules:\n"
        "  - !ENV ${ASH_PLUGMOD_PFX}in_ash_plugins\n"
        "  - survout_ash_plugins\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    response = _get_config(search_dir=str(root))

    assert response.get("success") is not False, response
    assert response.get("ash_plugin_modules") == ["survout_ash_plugins"], response


def test_control_with_no_drop_the_marker_stays_on_its_entry(
    root: Path, monkeypatch: pytest.MonkeyPatch, kept_module: str
):
    operator = root / "ops-only-env.yaml"
    operator.write_text(
        "project_name: demo\nash_plugin_modules:\n  - !ENV ${ASH_PLUGMOD_KEPT}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    response = _get_config(search_dir=str(root))

    assert response.get("success") is not False, response
    assert response.get("ash_plugin_modules") == ["<from ${ASH_PLUGMOD_KEPT}>"], (
        response
    )


@pytest.mark.parametrize("route", ["named-file", "no-file"])
def test_the_refusal_carries_its_own_error_type_not_a_load_failures(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str
):
    """The file loaded and parsed; what a scan refuses is its plugin-module
    list. Framed as a load failure, the reply said "Configuration file <path>
    cannot be loaded" under the generic MCPResourceError type, with
    file-format suggestions -- sending a client to re-format a healthy file.
    The refusal carries its own ``error_type`` a client can branch on, the
    refusal text alone as the message, and the file in the structured context
    only -- and the no-file answer carries no path at all, since its entries
    are the operator configuration's.

    The named file is one the operator granted (``root`` is in
    ``ASH_MCP_ALLOWED_CONFIG_ROOTS``): a path outside every granted directory is
    the client's, and the denied-field policy refuses its entry first."""
    if route == "named-file":
        monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(root))
        config = root / ".ash.yaml"
        config.write_text(
            f"project_name: demo\nash_plugin_modules:\n  - {NOT_PROVIDED}\n",
            encoding="utf-8",
        )
        response = _get_config(config_path=str(config))
    else:
        operator = tmp_path / "operator-config.yaml"
        operator.write_text(
            f"project_name: demo\nash_plugin_modules:\n  - {NOT_PROVIDED}\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        response = _get_config(search_dir=str(root))

    message = _refused(response)
    assert response["error_type"] == "plugin_module_refused", response
    assert "cannot be loaded" not in message, message
    context = response.get("context") or {}
    if route == "named-file":
        assert context.get("config_path") == str(config), response
    else:
        assert "config_path" not in context, response
    suggestions = response.get("suggestions")
    assert isinstance(suggestions, list) and suggestions, response
    assert "file format" not in str(suggestions), response
    context_category = (response.get("context") or {}).get("error_category")
    assert context_category == "plugin_module_refused", response


def test_control_a_config_without_plugin_modules_is_answered(root: Path):
    config = root / ".ash.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")

    response = _get_config(config_path=str(config))

    assert response.get("success") is not False, response
    assert response["project_name"] == "demo", response


def test_a_dropped_environment_entry_does_not_mislabel_the_next(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """The index shift runs in both directions. When the DROPPED entry is the
    one that read the environment, its reference matched at the old index
    lands on the surviving literal: where the dropped value's text occurs in
    the survivor (here, as its prefix), the survivor is shown with a false
    "<from ${VAR}>" marker in place of its own text -- the client is told the
    entry came from the environment when it is the file's written literal.
    The survivor stays as written, and the dropped entry's reference goes
    with it."""
    modules = root.parent.parent / "mislabel-modules"
    modules.mkdir()
    (modules / "longstay_ash_plugins.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(modules))
    # Unimportable, in the namespace, and a suffix of the survivor's text.
    monkeypatch.setenv("ASH_PLUGMOD_GONE", "stay_ash_plugins")
    operator_dir = root / "ops"
    operator_dir.mkdir()
    operator = operator_dir / "operator-config.yaml"
    operator.write_text(
        "project_name: demo\n"
        "ash_plugin_modules:\n"
        "  - !ENV ${ASH_PLUGMOD_GONE}\n"
        "  - longstay_ash_plugins\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    response = _get_config(search_dir=str(root))

    assert response.get("success") is not False, response
    assert response.get("ash_plugin_modules") == ["longstay_ash_plugins"], response
    import json

    assert "ASH_PLUGMOD_GONE" not in json.dumps(response), response


def test_a_refusals_naming_masks_an_environment_read_entry(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The refusal names an entry a config file read from the environment by
    its masked form, never the variable's value: the naming comes from the
    resolution's own references (config_module_names, through the error's
    shown_with), so a server environment value cannot ride into a client's
    reply through the refused entry's name, and the import error's own text
    is withheld for the same reason."""
    secret_name = "ash_plugins.name_the_environment_held"
    monkeypatch.setenv("ASH_PLUGMOD_BAD", secret_name)
    operator = tmp_path / "operator-config.yaml"
    operator.write_text(
        "project_name: demo\nash_plugin_modules:\n  - !ENV ${ASH_PLUGMOD_BAD}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    message = _refused(_get_config(search_dir=str(root)))

    assert secret_name not in message, message
    assert "'<value>'" in message, message
    assert "read from the environment" in message, message
    _closed_in_the_mcp_surfaces_words(message)


def test_a_named_files_refusal_masks_an_environment_read_entry(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """The named-file refusal masks like the no-file one: the two arms build
    their messages at different call sites, so the no-file cell above cannot
    pin this one. A file the operator granted (``root`` is in
    ``ASH_MCP_ALLOWED_CONFIG_ROOTS``) is resolved with its environment
    references (a file the client delivered or named outside every granted
    directory is refused before resolution, so no value exists to mask there:
    the next test pins that), and a refused entry the file read from ``${VAR}``
    is named by its masked form, never the variable's value."""
    secret_name = "ash_plugins.named_file_environment_entry"
    monkeypatch.setenv("ASH_PLUGMOD_BAD", secret_name)
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(root))
    config = root / "named-config.yaml"
    config.write_text(
        "project_name: demo\nash_plugin_modules:\n  - !ENV ${ASH_PLUGMOD_BAD}\n",
        encoding="utf-8",
    )

    message = _refused(_get_config(config_path=str(config)))

    assert secret_name not in message, message
    assert "'<value>'" in message, message
    assert "read from the environment" in message, message
    _closed_in_the_mcp_surfaces_words(message)


@pytest.mark.parametrize("route", ["named-file", "discovered"])
def test_a_file_reading_the_environment_is_refused_unless_the_operator_chose_it(
    root: Path, monkeypatch: pytest.MonkeyPatch, route: str
):
    """A remote caller's answer resolves no ``!ENV`` or ``${VAR}`` in a file the
    operator did not choose: one named outside ``ASH_MCP_ALLOWED_CONFIG_ROOTS``,
    or discovered in the searched tree. It is refused as
    ``config_env_not_resolved`` before any entry is judged, and the value the
    environment holds is in no key of the answer."""
    import json

    secret_name = "ash_plugins.entry_the_environment_held_back"
    monkeypatch.setenv("ASH_PLUGMOD_BAD", secret_name)
    config = root / ".ash.yaml"
    config.write_text(
        "project_name: demo\nash_plugin_modules:\n  - !ENV ${ASH_PLUGMOD_BAD}\n",
        encoding="utf-8",
    )

    if route == "named-file":
        response = _get_config(config_path=str(config))
    else:
        response = _get_config(search_dir=str(root))

    assert response.get("success") is False, response
    assert response["error_type"] == "config_env_not_resolved", response
    assert secret_name not in json.dumps(response, default=str), response


def test_an_unparsable_operator_chain_answers_a_load_failure_not_defaults(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The no-file answer never quietly becomes the defaults past an error:
    a chain file that cannot be parsed answers a load failure. The arm this
    pins is the FIRST read's (get_default_config raises before the confined
    second read is reached -- an unparsable chain never gets that far); the
    second read's own failure arm is pinned by the cell below through its
    one reachable entry."""
    operator = tmp_path / "operator-config.yaml"
    operator.write_text("project_name: [unclosed\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    response = _get_config(search_dir=str(root))

    assert response.get("success") is False, response
    assert response.get("exit_code") == 3, response


def test_a_confined_second_read_failure_answers_a_load_failure_not_defaults(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """The no-file branch's SECOND read -- the confined resolution that
    adopts the judged plugin-module list -- can fail where the first read
    succeeded (it re-reads the chain under the scan's plugin-module trust
    confinement). Its failure is a config the tool cannot load, exit 3,
    never the first read's defaults shown as the answer. The cell above
    cannot reach this arm: a chain the first read cannot parse fails before
    it, so this one fails the second read at its own seam, with the first
    read untouched (it loads from another module)."""
    import automated_security_helper.config.resolve_config as resolve_config_module

    from automated_security_helper.core.exceptions import ASHConfigValidationError

    real_resolve = resolve_config_module.resolve_config
    second_read_calls: list = []

    def failing_second_read(*args: Any, **kwargs: Any):
        if kwargs.get("no_discovery") and kwargs.get("config_path") is None:
            second_read_calls.append(kwargs)
            raise ASHConfigValidationError(
                "the chain failed under the scan's confinement"
            )
        return real_resolve(*args, **kwargs)

    monkeypatch.setattr(resolve_config_module, "resolve_config", failing_second_read)

    response = _get_config(search_dir=str(root))

    if not second_read_calls:
        raise RuntimeError(("premise: the second read ran", response))
    assert response.get("success") is False, response
    assert response.get("exit_code") == 3, response


def test_raw_with_no_file_answers_the_documents_plugin_modules(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """raw asks for a document: with no file, the default configuration as the
    operator chain wrote it. The confined list is the judged answer's shape,
    not the document's, so an in-tree chain file's unimportable entry stays in
    the raw answer as written. The second, confined resolution is never taken
    on the raw path: it can fail where the document read succeeded, and it
    writes module-drop warnings a document request should not."""
    operator_dir = root / "ops"
    operator_dir.mkdir()
    operator = operator_dir / "operator-config.yaml"
    operator.write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {NOT_PROVIDED}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    response = _get_config(search_dir=str(root), raw=True)

    assert response.get("success") is not False, response
    assert response.get("ash_plugin_modules") == [NOT_PROVIDED], response


def test_a_config_created_after_this_tools_discovery_is_not_read(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """The no-file answer resolves the operator chain once more, under the
    scan's plugin-module trust confinement. That second read must not run
    config discovery itself: this tool already discovered, under the
    session's gates, and found nothing. A config file that appears in the
    searched directory between the two reads would otherwise load with no
    gate, and its plugin-module list would replace the operator chain's in
    the answer."""
    modules = root.parent.parent / "between-calls-modules"
    modules.mkdir()
    (modules / "betweenmod_ash_plugins.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(modules))
    # The between-calls state: the tool's own discovery reports no file while
    # a discoverable config sits in the searched directory.
    (root / ".ash.yaml").write_text(
        "project_name: demo\nash_plugin_modules:\n  - betweenmod_ash_plugins\n",
        encoding="utf-8",
    )
    import automated_security_helper.config.resolve_config as resolve_config_module

    monkeypatch.setattr(resolve_config_module, "find_config_file", lambda **_: None)

    response = _get_config(search_dir=str(root))

    assert response.get("success") is not False, response
    import json

    assert "betweenmod_ash_plugins" not in json.dumps(response), response


@pytest.fixture
def pair_modules(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two installed plugin modules outside the searched tree, named together
    by one comma-joined environment variable."""
    modules = root.parent.parent / "pair-modules"
    modules.mkdir(exist_ok=True)
    for name in ("keeptwo_ash_plugins", "keepthree_ash_plugins"):
        (modules / f"{name}.py").write_text("", encoding="utf-8")
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(modules))
    monkeypatch.setenv("ASH_PLUGMOD_PAIR", "keeptwo_ash_plugins,keepthree_ash_plugins")
    monkeypatch.setenv("ASH_PLUGMOD_MIX", f"{NOT_PROVIDED},keeptwo_ash_plugins")


def _no_file_answer_for(
    root: Path, monkeypatch: pytest.MonkeyPatch, text: str
) -> Dict[str, Any]:
    operator_dir = root / "ops"
    operator_dir.mkdir(exist_ok=True)
    operator = operator_dir / "operator-config.yaml"
    operator.write_text(text, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    return _get_config(search_dir=str(root))


def test_a_multi_piece_entry_with_a_dropped_piece_shows_only_markers(
    root: Path, monkeypatch: pytest.MonkeyPatch, pair_modules: None
):
    """One reference can resolve to several comma-joined names. When the
    confinement drops one PIECE of it, each kept piece carries a whole-piece
    reference, so each is shown as the reference's marker and no piece's name
    rides into the answer -- the value came from the environment, whichever
    piece survived."""
    response = _no_file_answer_for(
        root,
        monkeypatch,
        "project_name: demo\nash_plugin_modules:\n  - ${ASH_PLUGMOD_MIX}\n",
    )

    assert response.get("success") is not False, response
    assert response.get("ash_plugin_modules") == ["<from ${ASH_PLUGMOD_MIX}>"], response
    import json

    assert "keeptwo_ash_plugins" not in json.dumps(response), response


def test_a_dropped_entry_before_a_multi_piece_reference_keeps_both_markers(
    root: Path, monkeypatch: pytest.MonkeyPatch, pair_modules: None
):
    """A drop AHEAD of a comma-joined reference renumbers both of its kept
    pieces at once: each gets the whole-piece marker at its new index, and
    neither piece's name shows."""
    response = _no_file_answer_for(
        root,
        monkeypatch,
        "project_name: demo\n"
        "ash_plugin_modules:\n"
        f"  - {NOT_PROVIDED}\n"
        "  - ${ASH_PLUGMOD_PAIR}\n",
    )

    assert response.get("success") is not False, response
    assert response.get("ash_plugin_modules") == [
        "<from ${ASH_PLUGMOD_PAIR}>",
        "<from ${ASH_PLUGMOD_PAIR}>",
    ], response
    import json

    dumped = json.dumps(response)
    assert "keeptwo_ash_plugins" not in dumped, response
    assert "keepthree_ash_plugins" not in dumped, response


def test_the_no_file_answer_reads_each_chain_file_once(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The no-file answer resolves the operator chain twice -- the shown
    document, then the judged splice -- over ONE set of bytes. The second step
    walks the chain holding each file to the identity it vetted, so a file the
    first step cached is read once more, and the cached read is used only if the
    file still holds the same text (``resolve_config.load_config_file_for_run``,
    ``read_once``). A chain file that changes on disk between the two steps is
    therefore refused rather than shown, and cannot put one read's marking
    record beside another read's judged list in one answer."""
    import json

    operator = tmp_path / "operator-config.yaml"
    operator.write_text(
        "project_name: demo\nash_plugin_modules: []\n", encoding="utf-8"
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    import automated_security_helper.config.resolve_config as resolve_config_module

    real_read = resolve_config_module.read_config_text
    operator_reads = {"count": 0}

    def swapping(path: Path, *args: Any, **kwargs: Any) -> str:
        if Path(path).resolve() == operator.resolve():
            operator_reads["count"] += 1
            if operator_reads["count"] > 1:
                # The racing writer: a second filesystem read sees new bytes.
                operator.write_text(
                    f"project_name: demo\nash_plugin_modules:\n  - {NOT_PROVIDED}\n",
                    encoding="utf-8",
                )
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(resolve_config_module, "read_config_text", swapping)

    response = _get_config(search_dir=str(root))

    # The first step reads the file from disk; the second reads it once more,
    # held to the identity, and finds the racing writer's bytes.
    assert operator_reads["count"] == 2, operator_reads
    assert response.get("success") is False, response
    # The writer's bytes are in no key of the answer.
    assert NOT_PROVIDED not in json.dumps(response, default=str), response


def test_a_named_files_entries_are_judged_for_the_callers_scan_target(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """A config path the client names, outside every directory the operator
    granted in ``ASH_MCP_ALLOWED_CONFIG_ROOTS``, is the client's. The entry it
    adds is refused by the denied-field policy while the file is resolved
    (``_denied_first``), so the plugin-module judgment, which is what the scan
    target changes (an entry inside the target is dropped, not refused), is not
    reached: a ``search_dir`` that holds the file does not turn the denial into
    a dropped entry, and the answer is the same with and without it."""
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    config_dir = root / "configs"
    config_dir.mkdir()
    config = config_dir / "alt.yaml"
    config.write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {NOT_PROVIDED}\n",
        encoding="utf-8",
    )

    with_target = _denied_first(
        _get_config(config_path=str(config), search_dir=str(root))
    )
    without_target = _denied_first(_get_config(config_path=str(config)))

    assert NOT_PROVIDED in with_target, with_target
    assert NOT_PROVIDED in without_target, without_target


def test_a_remote_callers_search_dir_is_gated_by_the_scan_root_policy(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A remote caller's search_dir names the directory its scan would
    target, so it goes through the scan tool's own gates in the scan tool's
    order, the root policy first: a directory outside the allowed roots
    refuses the call with the refusal a scan of the same target answers --
    scan_target_not_permitted, exit code 4 -- not the config-input gate's,
    and not some other arm's failure that happens to answer False. The
    answer says nothing about what sits outside the roots."""
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    config = root / ".ash.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")

    response = _get_config(config_path=str(config), search_dir=str(outside))

    assert response.get("success") is False, response
    assert response.get("project_name") != "demo", response
    assert response["error_type"] == "scan_target_not_permitted", response
    assert response["exit_code"] == 4, response


def test_a_refused_entry_read_from_the_environment_is_in_no_response_key(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The refused entry is a value the config read from the environment: the
    WHOLE serialized response -- message, suggestions, context, every key --
    holds no part of it. Checking the message alone left the other keys free
    to quote it."""
    import json

    canary = "zz_bld_env_entry_7351"
    monkeypatch.setenv("ASH_ZT_ENTRY", canary)
    operator = tmp_path / "operator-config.yaml"
    operator.write_text(
        "project_name: demo\nash_plugin_modules:\n  - !ENV ${ASH_ZT_ENTRY}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    response = _get_config(search_dir=str(root))

    assert response.get("success") is False, response
    whole = json.dumps(response, default=str)
    assert canary not in whole, whole
    assert response.get("error_category") == "plugin_module_refused", response
    context = response.get("context") or {}
    assert context.get("error_category") == "plugin_module_refused", response


def test_the_refusals_suggestions_are_the_categorys_defaults(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """One wording for both surfaces: the tool's refusal answers with the
    plugin-module category's own default suggestions, so a client reading
    either sees the same remedies, and the defaults entry has this caller.
    Two wordings sent a reader of the defaults to a configuration the MCP
    client may never have as a file."""
    from automated_security_helper.core.resource_management.error_handling import (
        MCPResourceError,
        PLUGIN_MODULE_REFUSED_SUGGESTIONS,
        _get_default_suggestions,
        create_error_response,
    )

    operator = tmp_path / "operator-config.yaml"
    operator.write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {NOT_PROVIDED}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    response = _get_config(search_dir=str(root))

    assert response.get("success") is False, response
    suggestions = response.get("suggestions")
    assert suggestions == list(PLUGIN_MODULE_REFUSED_SUGGESTIONS), suggestions
    assert suggestions == _get_default_suggestions("plugin_module_refused"), suggestions
    defaulted = create_error_response(
        MCPResourceError("example"), "get_config", category="plugin_module_refused"
    )
    assert defaulted.get("suggestions") == suggestions, defaulted
    # The entry's own words, not the generic fallback: dropping the entry
    # from the defaults map hands every caller the fallback instead.
    assert suggestions != _get_default_suggestions("zz-no-such-category"), suggestions
    assert "ash_plugin_modules" in suggestions[0], suggestions
