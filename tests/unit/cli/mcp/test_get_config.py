# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for mcp_get_config and ash://schema/config resource."""

import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.cli.mcp_tools import ENV_VALUE_PREFIX, mcp_get_config
from automated_security_helper.config.default_config import get_default_config

pytestmark = pytest.mark.unit


def _write_config(path: Path, data: dict) -> None:
    path.write_text(yaml.dump(data))


class TestGetConfigResolved:
    def test_returns_resolved_dict(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        _write_config(config_file, {"global_settings": {"severity_threshold": "HIGH"}})

        result = mcp_get_config(config_path=str(config_file))

        assert isinstance(result, dict)
        assert result["global_settings"]["severity_threshold"] == "HIGH"
        # defaults merged: scanners key should be present
        assert "scanners" in result

    def test_defaults_merged_for_non_overridden_fields(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        _write_config(
            config_file, {"global_settings": {"severity_threshold": "CRITICAL"}}
        )

        result = mcp_get_config(config_path=str(config_file))
        default = get_default_config().model_dump()

        # overridden field reflected
        assert result["global_settings"]["severity_threshold"] == "CRITICAL"
        # a non-overridden top-level field should match the default
        assert result.get("fail_on_findings") == default.get("fail_on_findings")


class TestGetConfigRaw:
    def test_raw_returns_unmerged(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        raw_data = {"global_settings": {"severity_threshold": "LOW"}}
        _write_config(config_file, raw_data)

        result = mcp_get_config(config_path=str(config_file), raw=True)

        assert result == raw_data
        # defaults NOT merged: no top-level scanners key
        assert "scanners" not in result

    @pytest.mark.parametrize("name", ["ash.toml", "ash.TOML"])
    def test_raw_reads_a_toml_file_as_toml(self, tmp_path, name):
        """The suffix in either case: `ash.TOML` was read with the YAML parser,
        which turned `a = "b"` into the string 'a = "b"'."""
        config_file = tmp_path / name
        config_file.write_text(
            'project_name = "demo"\n\n[global_settings]\nseverity_threshold = "LOW"\n',
            encoding="utf-8",
        )

        result = mcp_get_config(config_path=str(config_file), raw=True)

        assert result == {
            "project_name": "demo",
            "global_settings": {"severity_threshold": "LOW"},
        }

    def test_raw_returns_exact_file_contents(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        raw_data = {
            "global_settings": {"severity_threshold": "MEDIUM"},
            "fail_on_findings": True,
        }
        _write_config(config_file, raw_data)

        result = mcp_get_config(config_path=str(config_file), raw=True)

        assert result["global_settings"]["severity_threshold"] == "MEDIUM"
        assert result["fail_on_findings"] is True

    def test_raw_parses_a_json_file_as_json(self, tmp_path):
        """As a scan loads it. Parsed as YAML, a tab-indented file is an error and
        ``1e3`` is the string "1e3"."""
        from automated_security_helper.config.config_sources import read_config_file

        config_file = tmp_path / "ash.json"
        config_file.write_text(
            '{\n\t"project_name": "tabbed",\n\t"extra": 1e3\n}\n', encoding="utf-8"
        )

        result = mcp_get_config(config_path=str(config_file), raw=True)

        assert result == {"project_name": "tabbed", "extra": 1000.0}
        assert result == read_config_file(config_file)

    def test_raw_refuses_a_json_file_that_is_not_json(self, tmp_path):
        """YAML reads ``{"project_name": }`` as a null value; a scan refuses it."""
        config_file = tmp_path / "ash.json"
        config_file.write_text('{"project_name": }\n', encoding="utf-8")

        result = mcp_get_config(config_path=str(config_file), raw=True)

        assert result["success"] is False, result
        assert result["error_category"] == "invalid_format"
        assert "ash.json" in result["error"]


class TestGetConfigMissingFile:
    def test_missing_explicit_path_is_refused_as_not_found(self, tmp_path):
        """As `ash config get` refuses it: the defaults read as that file's."""
        result = mcp_get_config(config_path=str(tmp_path / "nonexistent.yaml"))

        assert result["success"] is False, result
        assert result["exit_code"] == 3, result
        assert result["error_category"] == "file_not_found", result

    def test_no_config_in_directory_returns_default(self, tmp_path):
        # Pass no config_path — auto-discovery in tmp_path finds nothing
        result = mcp_get_config(config_path=None, search_dir=str(tmp_path))

        default = get_default_config().model_dump()
        assert (
            result["global_settings"]["severity_threshold"]
            == default["global_settings"]["severity_threshold"]
        )


class TestGetConfigExplicitPath:
    def test_explicit_path_loads_that_file(self, tmp_path):
        config_a = tmp_path / "a.yaml"
        config_b = tmp_path / "b.yaml"
        _write_config(config_a, {"global_settings": {"severity_threshold": "LOW"}})
        _write_config(config_b, {"global_settings": {"severity_threshold": "CRITICAL"}})

        result_a = mcp_get_config(config_path=str(config_a))
        result_b = mcp_get_config(config_path=str(config_b))

        assert result_a["global_settings"]["severity_threshold"] == "LOW"
        assert result_b["global_settings"]["severity_threshold"] == "CRITICAL"

    def test_a_named_file_with_a_search_dir_loads_bases_a_scan_of_it_loads(
        self, tmp_path
    ):
        """A caller naming both the file and the directory its scan targets
        gets the file judged as that scan judges it. The scan confines the
        chain to the target when the file sits inside it, so a base above
        the config's own directory but inside the target loads there, and
        the pre-read must load it too instead of refusing on the file's own
        narrower root."""
        target = tmp_path / "proj"
        (target / "cfg").mkdir(parents=True)
        _write_config(
            target / "base.yaml",
            {"global_settings": {"severity_threshold": "LOW"}},
        )
        config = target / "cfg" / "ash.yaml"
        _write_config(config, {"extends": ["../base.yaml"]})

        result = mcp_get_config(config_path=str(config), search_dir=str(target))

        assert result["global_settings"]["severity_threshold"] == "LOW", result

    def test_control_the_same_file_without_a_target_keeps_its_own_root(self, tmp_path):
        """With no search directory, no scan target is named, so the chain
        stays confined to the file's own directory and the base above it is
        refused, as before."""
        target = tmp_path / "proj"
        (target / "cfg").mkdir(parents=True)
        _write_config(
            target / "base.yaml",
            {"global_settings": {"severity_threshold": "LOW"}},
        )
        config = target / "cfg" / "ash.yaml"
        _write_config(config, {"extends": ["../base.yaml"]})

        result = mcp_get_config(config_path=str(config))

        assert "global_settings" not in result, result
        assert result.get("error"), result


SECRET = "s3cr3t-value"
REFERENCE = "${ASH_X:fallback}"
MARKER = "<from ${ASH_X:fallback}>"


class TestGetConfigHidesEnvironmentValues:
    """get_config shows a value a config read from the environment as a marker.

    It returned the resolved config, so a `${ASH_X:fallback}` reference handed
    the server's value of ASH_X to the MCP client. The marker names the
    reference as the file writes it, and never holds the value.
    """

    @pytest.fixture(autouse=True)
    def _environment(self, monkeypatch, tmp_path):
        monkeypatch.setenv("ASH_X", SECRET)
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        monkeypatch.chdir(tmp_path)

    @staticmethod
    def _assert_hidden(result, marker=MARKER):
        text = json.dumps(result)
        assert SECRET not in text, text
        assert marker in text, text

    @pytest.mark.parametrize(
        "text",
        [
            pytest.param(f"project_name: {REFERENCE}\n", id="reference"),
            pytest.param(f"project_name: !ENV {REFERENCE}\n", id="env-tag"),
            pytest.param(
                "project_name: demo\nglobal_settings:\n  suppressions:\n"
                "    - path: src/a.py\n      rule_id: B101\n"
                f"      reason: {REFERENCE}\n",
                id="nested",
            ),
        ],
    )
    def test_the_resolved_config(self, tmp_path, text):
        config_file = tmp_path / ".ash.yaml"
        config_file.write_text(text, encoding="utf-8")

        self._assert_hidden(mcp_get_config(config_path=str(config_file)))

    def test_a_reference_without_a_default(self, tmp_path):
        """Shown as the marker where `${ASH_X}` is read, and as written where it
        is not (a reference without a default is left unresolved by some
        versions); the value either way never."""
        config_file = tmp_path / ".ash.yaml"
        config_file.write_text("project_name: ${ASH_X}\n", encoding="utf-8")

        text = json.dumps(mcp_get_config(config_path=str(config_file)))

        assert SECRET not in text, text
        assert '"<from ${ASH_X}>"' in text or '"${ASH_X}"' in text, text

    def test_a_value_read_by_a_base(self, tmp_path):
        (tmp_path / "base.yaml").write_text(
            f"project_name: {REFERENCE}\n", encoding="utf-8"
        )
        config_file = tmp_path / ".ash.yaml"
        config_file.write_text("extends: base.yaml\n", encoding="utf-8")

        self._assert_hidden(mcp_get_config(config_path=str(config_file)))

    def test_a_discovered_config(self, tmp_path):
        (tmp_path / ".ash.yaml").write_text(
            f"project_name: {REFERENCE}\n", encoding="utf-8"
        )

        self._assert_hidden(mcp_get_config(search_dir=str(tmp_path)))

    @pytest.mark.parametrize(
        "name, text, shown",
        [
            pytest.param(
                ".ashrc.toml",
                f'project_name = "{REFERENCE}"\n',
                ENV_VALUE_PREFIX + REFERENCE,
                id="toml",
            ),
            pytest.param(
                "ash.TOML",
                f'project_name = "{REFERENCE}"\n',
                ENV_VALUE_PREFIX + REFERENCE,
                id="TOML",
            ),
            pytest.param(
                "PYPROJECT.TOML",
                f'[project]\nname = "x"\n\n[tool.ash]\nproject_name = "{REFERENCE}"\n',
                ENV_VALUE_PREFIX + REFERENCE,
                id="pyproject",
            ),
            # JSON is not interpolated, so the string is a literal there.
            pytest.param(
                "ash.JSON",
                f'{{\n\t"project_name": "{REFERENCE}"\n}}\n',
                REFERENCE,
                id="JSON",
            ),
            pytest.param(
                "ash.yaml",
                f"project_name: !ENV {REFERENCE}\n",
                ENV_VALUE_PREFIX + REFERENCE,
                id="yaml",
            ),
        ],
    )
    def test_the_raw_file_is_shown_as_written(self, tmp_path, name, text, shown):
        """The raw file is the file, references unresolved: a TOML file was read
        with its references resolved, and the others with the YAML parser,
        which refuses an `!ENV` tag and a tab-indented JSON file. A value the
        loader would read from the environment is marked, as raw mode marks it
        (``ENV_VALUE_PREFIX``), so a client can tell it from a literal."""
        config_file = tmp_path / name
        config_file.write_text(text, encoding="utf-8")

        result = mcp_get_config(config_path=str(config_file), raw=True)

        assert result == {"project_name": shown}, result

    def test_the_default_config_from_ash_config(self, tmp_path, monkeypatch):
        operator = tmp_path / "operator.yaml"
        operator.write_text(f"project_name: {REFERENCE}\n", encoding="utf-8")
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        nothing_to_discover = tmp_path / "empty"
        nothing_to_discover.mkdir()

        self._assert_hidden(mcp_get_config(search_dir=str(nothing_to_discover)))

    def test_a_value_the_model_strips(self, tmp_path, monkeypatch):
        """The reference resolves to the variable's value without surrounding
        blanks; neither form is shown."""
        monkeypatch.setenv("ASH_X", f"  {SECRET}  ")
        config_file = tmp_path / ".ash.yaml"
        config_file.write_text(f"project_name: {REFERENCE}\n", encoding="utf-8")

        self._assert_hidden(mcp_get_config(config_path=str(config_file)))


def _resolve_schema_properties(schema: dict) -> dict:
    """Resolve $ref into $defs and return the properties dict."""
    ref = schema.get("$ref", "")
    if ref.startswith("#/$defs/"):
        def_name = ref.split("/")[-1]
        defn = schema.get("$defs", {}).get(def_name, {})
        return defn.get("properties", {})
    return schema.get("properties", {})


class TestSchemaResource:
    def test_schema_resource_returns_valid_json(self):
        from automated_security_helper.cli.mcp_server import _read_ash_config_schema

        content = _read_ash_config_schema()
        parsed = json.loads(content)
        # Valid JSON Schema: either top-level markers or a $ref into $defs
        assert any(
            k in parsed
            for k in ("$schema", "title", "properties", "$ref", "$defs", "type")
        )

    def test_schema_resource_contains_global_settings(self):
        from automated_security_helper.cli.mcp_server import _read_ash_config_schema

        content = _read_ash_config_schema()
        parsed = json.loads(content)
        props = _resolve_schema_properties(parsed)
        assert "global_settings" in props


def test_an_overlap_base_keeps_the_ignored_marker(tmp_path, monkeypatch):
    """A chain file BOTH the selected config and the ASH_CONFIG chain extend
    is still the selected chain's own: the tool takes the selected chain from
    the load itself (``chain_out``), so the shared checkout base keeps its
    copy in the selected chain. Reverse-engineering it from ``files_read``
    dropped a base both chains extend, the checkout guard never saw it, and
    the operator-only option it writes lost its ignored marker. The in-cell
    control proves the shape marks without the overlap before the overlap is
    added."""
    from tests.utils.helpers import mark_git_checkout

    root = tmp_path / "cfg"
    checkout = root / "vendor"
    mark_git_checkout(checkout)
    base = checkout / "base.yaml"
    base.write_text(
        "scanners:\n  detect-secrets:\n    options:\n"
        "      max_worker_output_mib: 4096\n",
        encoding="utf-8",
    )
    selected = root / "config.yaml"
    selected.write_text(
        f"project_name: op\nextends:\n  - {base.as_posix()}\n", encoding="utf-8"
    )
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    # A path named to get_config is the client's unless it is in a directory
    # ASH_MCP_ALLOWED_CONFIG_ROOTS names, and a client's chain writing the
    # limit is refused outright; this test is about the operator's selected
    # chain, so the test's directory is set aside as the operator's.
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))

    # Control: without the overlap, the checkout base's operator-only option
    # is shown as ignored.
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    control = mcp_get_config(config_path=str(selected))
    assert "operator only; ignored" in json.dumps(control, default=str), control

    env_file = root / "ash-env.yaml"
    env_file.write_text(
        f"project_name: from-env\nextends:\n  - {base.as_posix()}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(env_file))
    result = mcp_get_config(config_path=str(selected))
    assert "operator only; ignored" in json.dumps(result, default=str), result


def test_get_config_never_resolves_the_ash_config_chain_afresh(tmp_path, monkeypatch):
    """The operator-files marking uses the chain the load itself handed out,
    so the tool never resolves the ASH_CONFIG chain a second time.
    A fresh resolution could see a chain file changed since the load, leave
    it in the selected chain, and mark the answer operator-only for a file
    the load never read that way. The counter sits on the module attribute a
    fresh resolution would call; the load's own read binds elsewhere, so the
    positive control below proves the counter live rather than the premise
    riding on the load."""
    from automated_security_helper.config import config_sources
    from automated_security_helper.config.operator_only_options import (
        repository_settings_for_root,
    )

    env_file = tmp_path / "ops" / "ash-config.yaml"
    env_file.parent.mkdir()
    env_file.write_text("project_name: from-env\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(env_file))
    config_file = tmp_path / ".ash.yaml"
    _write_config(config_file, {"project_name": "named"})

    reads = []
    real = config_sources.resolve_config_document

    def counted(config_path, *args, **kwargs):
        if Path(config_path) == env_file:
            reads.append(1)
        return real(config_path, *args, **kwargs)

    monkeypatch.setattr(config_sources, "resolve_config_document", counted)

    # Positive control: a direct document read fires the counter.
    settings = repository_settings_for_root(None)
    document = config_sources.resolve_config_document(
        env_file,
        confine=settings.confine,
        repository_file=settings.is_repository_file,
    )
    assert list(document.chain) == [env_file.resolve()]
    assert reads, reads
    reads.clear()

    result = mcp_get_config(config_path=str(config_file))

    assert result["project_name"] == "named"
    assert reads == [], reads
