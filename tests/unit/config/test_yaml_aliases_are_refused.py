# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""YAML aliases are refused wherever ASH reads YAML that configures it.

An alias is a reference to an anchored node, so a few hundred bytes of nested
aliases stand for gigabytes once the parsed config is walked or serialized: a
scan writes its config into its results, and MCP get_config returns it. Parsing
does not expand them, so no read-size bound stops this. ASH's own YAML files use
no aliases, so every config reader refuses them at parse time and nothing past
the parse runs.

The shared loaders (``load_config_yaml`` and ``load_yaml_config``) raise the
parser's ``ComposerError`` at the first alias, "found the alias *x; ASH
configuration does not accept YAML aliases, ...", and the first group of cells
pins those words. Every reader of a config FILE reports the refusal in the
shared words of ``unparsed_config_reason``: ``<file> could not be parsed
(ComposerError at line N, column M)``. That gives the parser's type and where
it stopped, and quotes none of the file (not the alias, not a value), because
the parser's own message can quote a line of it. The reader cells pin those
words and that nothing of the file is quoted. The two readers that show a
document as written, not as a run reads it (``get_config(raw=True)`` and the
suppression save), read with ``NoRecursiveAliasLoader``, which refuses an alias
inside its own node only; their cells pin that, and that the config load of the
same file still refuses it.

One test per reader, plus a static check that every YAML load in the package
goes through the shared loaders (``load_config_yaml`` and ``load_yaml_config``),
or through the one as-written loader named below.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.config.ash_config import (
    load_config_yaml,
    load_yaml_config,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigSourceError

ALIASED = "project_name: &name repeated\nglobal_settings:\n  ignore_paths: [*name]\n"


def _chain(levels: int, width: int = 10) -> str:
    """A small alias chain: each level is `width` aliases to the level below."""
    lines = ["project_name: chain", 'l0: &l0 "x"']
    for level in range(1, levels + 1):
        refs = ", ".join(f"*l{level - 1}" for _ in range(width))
        lines.append(f"l{level}: &l{level} [{refs}]")
    return "\n".join(lines) + "\n"


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _assert_names_the_alias(text: str) -> None:
    """The shared loaders' own words, which name the alias (``load_config_yaml``
    and ``load_yaml_config`` raise the parser's error unreworded)."""
    assert "alias" in text, text
    assert "*name" in text or "*l0" in text, text


#: What every reader of a config file says of a file that uses an alias
#: (``unparsed_config_reason``): the parser's type and where it stopped.
PARSE_REFUSAL = "could not be parsed (ComposerError at line "


def _assert_refused_at_parse(text: str) -> None:
    """The refusal gives the place the parser stopped and none of the file: not
    the alias's marker, and not the value the anchor held."""
    assert PARSE_REFUSAL in text, text
    assert "*name" not in text and "*l0" not in text, text
    assert "repeated" not in text, text


class TestTheSharedLoaders:
    @pytest.mark.parametrize("loader", [load_config_yaml, load_yaml_config])
    def test_an_alias_is_refused_with_its_line(self, loader):
        with pytest.raises(yaml.YAMLError) as excinfo:
            loader(ALIASED)

        _assert_names_the_alias(str(excinfo.value))
        assert "line 3" in str(excinfo.value)

    @pytest.mark.parametrize("loader", [load_config_yaml, load_yaml_config])
    def test_a_small_alias_chain_is_refused_at_parse(self, loader):
        with pytest.raises(yaml.YAMLError, match="alias"):
            loader(_chain(4))

    @pytest.mark.parametrize("loader", [load_config_yaml, load_yaml_config])
    def test_control_an_anchor_no_alias_uses_still_parses(self, loader):
        assert loader("project_name: &name only\n") == {"project_name": "only"}

    def test_control_safe_tags_only(self):
        with pytest.raises(yaml.YAMLError):
            load_config_yaml("x: !!python/object/apply:os.getcwd []\n")


class TestEveryReaderRefusesAnAlias:
    def test_a_named_config_file(self, tmp_path):
        path = _write(tmp_path / "cfg.yaml", ALIASED)

        with pytest.raises(ASHConfigSourceError) as excinfo:
            resolve_config(config_path=path, source_dir=tmp_path)

        _assert_refused_at_parse(str(excinfo.value))

    def test_a_discovered_config_file(self, tmp_path):
        _write(tmp_path / ".ash" / ".ash.yaml", _chain(4))

        with pytest.raises(ASHConfigSourceError) as excinfo:
            resolve_config(source_dir=tmp_path)

        _assert_refused_at_parse(str(excinfo.value))

    def test_an_extends_base(self, tmp_path):
        _write(tmp_path / "base.yaml", ALIASED)
        child = _write(tmp_path / ".ash.yaml", "extends: base.yaml\n")

        with pytest.raises(ASHConfigSourceError) as excinfo:
            resolve_config(config_path=child, source_dir=tmp_path)

        _assert_refused_at_parse(str(excinfo.value))

    def test_ash_config_get_exits_3(self, tmp_path):
        from automated_security_helper.cli.config import config_app

        path = _write(tmp_path / "cfg.yaml", ALIASED)

        result = CliRunner().invoke(config_app, ["get", "--config", str(path)])

        assert result.exit_code == 3, result.output
        _assert_refused_at_parse(" ".join(result.output.split()))
        assert "Traceback" not in result.output

    def test_the_config_validator(self, tmp_path):
        from automated_security_helper.config.config_validator import ConfigValidator

        path = _write(tmp_path / "cfg.yaml", ALIASED)

        valid, errors = ConfigValidator.validate_config_file(path)

        assert valid is False
        _assert_refused_at_parse(" ".join(errors))

    def test_the_config_linter(self, tmp_path):
        from automated_security_helper.config.config_linter import ConfigLinter

        path = _write(tmp_path / "cfg.yaml", ALIASED)

        result = ConfigLinter.lint(config_path=path)

        assert result.error_count >= 1
        _assert_refused_at_parse(" ".join(str(issue) for issue in result.issues))

    def test_the_rewrite_check_of_config_update(self, tmp_path):
        """update and wizard look for extends/patch before rewriting a file."""
        from automated_security_helper.cli.config import config_app

        path = _write(tmp_path / "cfg.yaml", ALIASED)

        result = CliRunner().invoke(
            config_app, ["update", str(path), "--set", "project_name=other"]
        )

        assert result.exit_code != 0, result.output
        _assert_refused_at_parse(" ".join(result.output.split()))
        assert "Traceback" not in result.output
        assert path.read_text(encoding="utf-8") == ALIASED

    def test_saving_a_suppression_into_the_file(self, tmp_path, monkeypatch):
        """The save edits the file's text, and reads it with the as-written
        loader (``NoRecursiveAliasLoader``) to find where the entry goes, so a
        shared alias is not its refusal: the entry goes in and the alias is left
        as the file wrote it. The refusal is the config load's, and the saved
        file is still refused there, so a scan never runs on it. (An alias
        inside its own node is the save's refusal; see
        ``test_a_cyclic_yaml_config_is_refused_by_name.py``.)"""
        from automated_security_helper.config.ash_config import (
            add_suppression_to_config,
        )
        from automated_security_helper.models.core import AshSuppression

        monkeypatch.delenv("ASH_CONFIG", raising=False)
        path = _write(tmp_path / ".ash.yaml", ALIASED)

        saved = add_suppression_to_config(
            path, AshSuppression(rule_id="B101", path="x.py", reason="r")
        )

        assert saved is True
        text = path.read_text(encoding="utf-8")
        assert "ignore_paths: [*name]" in text, text
        assert "B101" in text, text
        with pytest.raises(ASHConfigSourceError) as excinfo:
            resolve_config(config_path=path, source_dir=tmp_path)
        _assert_refused_at_parse(str(excinfo.value))

    def test_an_mcp_operator_profile(self, tmp_path):
        from automated_security_helper.cli.mcp.profile_registry import (
            register_profiles,
        )

        path = _write(tmp_path / "team.yaml", ALIASED)

        with pytest.raises(ValueError, match=re.escape(PARSE_REFUSAL)) as excinfo:
            register_profiles([f"team={path}"])

        _assert_refused_at_parse(str(excinfo.value))

    def test_an_mcp_client_override(self, tmp_path):
        from automated_security_helper.cli.mcp.profile_registry import (
            clear_profile_registry,
            clear_all_session_state,
            register_profiles,
            set_profile_registry,
        )
        from automated_security_helper.cli.mcp_tools import mcp_select_profile

        profile = _write(tmp_path / "team.yaml", "project_name: team\n")
        clear_profile_registry()
        clear_all_session_state()
        try:
            set_profile_registry(register_profiles([f"team={profile}"]))
            result = mcp_select_profile("team", override_yaml=_chain(4))
        finally:
            clear_profile_registry()
            clear_all_session_state()

        assert result["success"] is False, result
        assert "alias" in result["error"]

    def test_mcp_get_config_raw(self, tmp_path, monkeypatch):
        """``raw=True`` answers the file as written, not as a run reads it, and
        parses with ``NoRecursiveAliasLoader``: a shared alias is answered with
        its value written out in each place, under the same expansion budgets
        the config chain charges (``test_get_config_raw_expansion_bound.py``),
        and an alias inside its own node is the refusal. The resolved read of
        the same file is where the alias is refused."""
        from automated_security_helper.cli.mcp_tools import mcp_get_config

        path = _write(tmp_path / ".ash.yaml", ALIASED)
        monkeypatch.chdir(tmp_path)

        result = mcp_get_config(config_path=str(path), raw=True)

        assert result == {
            "project_name": "repeated",
            "global_settings": {"ignore_paths": ["repeated"]},
        }, result
        with pytest.raises(ASHConfigSourceError) as excinfo:
            resolve_config(config_path=path, source_dir=tmp_path)
        _assert_refused_at_parse(str(excinfo.value))

    def test_a_workspace_policy_file(self, tmp_path):
        from automated_security_helper.workspace.policy import load_workspace_policy

        path = _write(tmp_path / "policy.yaml", ALIASED)

        with pytest.raises(Exception, match=re.escape(PARSE_REFUSAL)) as excinfo:
            load_workspace_policy(path)

        _assert_refused_at_parse(str(excinfo.value))

    @pytest.mark.parametrize(
        ("content", "reaches_the_check"),
        [
            pytest.param(_chain(4), False, id="aliased"),
            pytest.param("project_name: plain\n", True, id="control-no-alias"),
        ],
    )
    def test_mcp_validate_config_content_from_a_remote_client(
        self, monkeypatch, content, reaches_the_check
    ):
        """The session-policy check parses the content as the validator does.

        The validator refuses the alias; the policy check that follows it walks the
        document it parsed, so it must not parse the same text with aliases
        accepted.
        """
        from automated_security_helper.cli.mcp.profile_registry import (
            clear_profile_registry,
            clear_all_session_state,
        )
        from automated_security_helper.cli.mcp_tools import mcp_validate_config
        from automated_security_helper.config import client_config_policy

        checked = []
        real = client_config_policy.client_file_denials

        def _record(documents, *args, **kwargs):
            checked.append(dict(documents))
            return real(documents, *args, **kwargs)

        monkeypatch.setattr(client_config_policy, "client_file_denials", _record)
        clear_profile_registry()
        clear_all_session_state()
        try:
            # A real session id is a remote client's, whose content is checked.
            result = mcp_validate_config(config_content=content, session_id="client-1")
        finally:
            clear_profile_registry()
            clear_all_session_state()

        if reaches_the_check:
            assert len(checked) == 1, result
        else:
            assert result["valid"] is False, result
            _assert_refused_at_parse(json.dumps(result))
            assert checked == []

    def test_a_trivy_ignore_file_a_client_config_names(self):
        """ASH applies its entries itself, so it is parsed as ASH configuration is."""
        from automated_security_helper.config.client_scanner_exclusions import (
            parse_trivy_ignore_file,
        )

        text = (
            "misconfigurations:\n"
            "  - &entry {id: DS002, paths: [&paths [a.py, b.py]]}\n"
            "  - *entry\n"
        )

        with pytest.raises(ValueError, match="alias"):
            parse_trivy_ignore_file(text, yaml_format=True)

    def test_control_a_trivy_ignore_file_with_no_alias_still_parses(self):
        from automated_security_helper.config.client_scanner_exclusions import (
            parse_trivy_ignore_file,
        )

        text = "misconfigurations:\n  - {id: DS002, paths: [a.py]}\n"

        assert parse_trivy_ignore_file(text, yaml_format=True) == [("DS002", ("a.py",))]


# ---------------------------------------------------------------------------
# Every YAML load in the package goes through the shared loaders
# ---------------------------------------------------------------------------

PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"
LOAD_FUNCTIONS = {
    "load",
    "safe_load",
    "full_load",
    "unsafe_load",
    "load_all",
    "safe_load_all",
    "full_load_all",
    "unsafe_load_all",
}

#: YAML read with plain PyYAML on purpose, with the reason.
NOT_ASH_CONFIGURATION = {
    # Grype's own config file, in Grype's format, read for two keys. It is not
    # ASH configuration, and Grype's format allows anchors and aliases.
    "plugin_modules/ash_builtin/scanners/grype_scanner.py",
    # A .snyk policy file in the scanned tree, in Snyk's format, which allows
    # aliases. snyk-code reads it only to see whether its exclude sections list
    # anything (_excludes), which follows no alias; refusing one would count a
    # valid policy as unreadable.
    "plugin_modules/ash_snyk_plugins/snyk_code_scanner.py",
}

#: ASH configuration read with a loader of ASH's own that is not one of the two
#: shared loaders, by file and loader class. ``_KeepsEnvReferences`` reads a
#: config file the suppression save edits as text, to find where the entry goes,
#: and keeps an ``!ENV`` scalar as its own text; it refuses an alias inside its
#: own node (``NoRecursiveAliasLoader``) and nothing else, because the save
#: leaves the file's text as it was. The config load of the saved file refuses
#: every alias (``test_saving_a_suppression_into_the_file``). A direct PyYAML
#: load anywhere else in that file is still an offender.
AS_WRITTEN_LOADERS = {"config/ash_config.py": "_KeepsEnvReferences"}


def loader_names_in(source: str) -> Dict[int, str]:
    """{line: class name} for each call in ``source`` that passes ``Loader=``
    a bare class name."""
    names = {}
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg == "Loader" and isinstance(keyword.value, ast.Name):
                names[node.lineno] = keyword.value.id
    return names


def yaml_loads_in(source: str) -> List[Tuple[int, str]]:
    """(line, call) for every call to a PyYAML load function in ``source``."""
    tree = ast.parse(source)
    module_names = {"yaml"}
    function_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "yaml":
                    module_names.add(alias.asname or "yaml")
        elif isinstance(node, ast.ImportFrom) and node.module == "yaml":
            for alias in node.names:
                if alias.name in LOAD_FUNCTIONS:
                    function_names.add(alias.asname or alias.name)
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in LOAD_FUNCTIONS
            and isinstance(func.value, ast.Name)
            and func.value.id in module_names
        ):
            found.append((node.lineno, f"{func.value.id}.{func.attr}"))
        elif isinstance(func, ast.Name) and func.id in function_names:
            found.append((node.lineno, func.id))
    return found


class TestEveryYamlLoadUsesTheSharedLoaders:
    def test_no_module_calls_pyyaml_load_directly(self):
        offenders = []
        for path in sorted(PACKAGE.rglob("*.py")):
            relative = path.relative_to(PACKAGE).as_posix()
            if relative in NOT_ASH_CONFIGURATION:
                continue
            source = path.read_text(encoding="utf-8")
            as_written = AS_WRITTEN_LOADERS.get(relative)
            named = loader_names_in(source) if as_written else {}
            for line, call in yaml_loads_in(source):
                if as_written is not None and named.get(line) == as_written:
                    continue
                offenders.append(f"{relative}:{line} {call}")

        assert offenders == [], (
            "parse ASH configuration with load_config_yaml or load_yaml_config "
            "(config/ash_config.py), which refuse YAML aliases:\n"
            + "\n".join(offenders)
        )

    def test_control_the_check_finds_each_spelling(self):
        source = (
            "import yaml\nimport yaml as y\nfrom yaml import safe_load as s\n"
            "yaml.safe_load('a')\ny.load('a', Loader=None)\ns('a')\n"
        )

        assert [call for _, call in yaml_loads_in(source)] == [
            "yaml.safe_load",
            "y.load",
            "s",
        ]

    def test_control_the_exempt_reader_is_still_where_it_was(self):
        for relative in NOT_ASH_CONFIGURATION:
            assert yaml_loads_in((PACKAGE / relative).read_text(encoding="utf-8"))

    def test_control_an_as_written_load_is_told_from_a_direct_one(self):
        source = (
            "import yaml\n"
            "yaml.load('a', Loader=_KeepsEnvReferences)\n"
            "yaml.load('a', Loader=yaml.SafeLoader)\n"
            "yaml.load('a')\n"
        )

        assert loader_names_in(source) == {2: "_KeepsEnvReferences"}
        assert [line for line, _ in yaml_loads_in(source)] == [2, 3, 4]

    def test_control_the_as_written_loader_is_still_where_it_was(self):
        for relative, loader in AS_WRITTEN_LOADERS.items():
            source = (PACKAGE / relative).read_text(encoding="utf-8")
            assert loader in loader_names_in(source).values(), relative
