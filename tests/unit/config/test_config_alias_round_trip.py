"""Tests pinning that a dump/revalidate round trip preserves aliased config keys.

Three code paths take a config apart and put it back together: `ash config
update`, `apply_config_overrides`, and the MCP runtime JSON-Patch. Each dumps
without `by_alias=True`, so the scanners, reporters and converters sub-dicts come
out keyed by Python field name -- `cdk_nag`, not `cdk-nag`.

`populate_by_name` is per-model in pydantic v2 and was set only on `AshConfig`.
The three segment models declare their own `model_config` with `extra="allow"`,
so on revalidation a segment was alias-only: it did not recognize `cdk_nag` as
the `cdk-nag` field, accepted it as an extra key, and rebuilt the real field from
defaults. An operator who had disabled a scanner got it back enabled, and the
result carried both spellings at once.

None of the three paths needs an operator to ask for it. `scan
--compact-report` appends `reporters.markdown.options.compact=true` itself, so
`apply_config_overrides` runs with a non-empty override list for an operator who
passed no override flag.

Every case here is paired with an unaliased sibling -- `bandit`, which declares
no alias -- because that sibling is what separates "the alias was dropped" from
"the round trip is lossy for everything". A change that broke both would fail the
paired half.
"""

from __future__ import annotations

import yaml
from pydantic import BaseModel
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app
from automated_security_helper.config.ash_config import (
    AshConfig,
    ConverterConfigSegment,
    ReporterConfigSegment,
    RuntimeOverridesConfig,
    ScannerConfigSegment,
)
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.config.runtime_patch import apply_runtime_patch

# The override `cli/scan.py` synthesizes for `--compact-report`. Used throughout
# as the "unrelated change" so these tests exercise the argument list a real run
# produces rather than one invented for the test.
_UNRELATED_OVERRIDE = "reporters.markdown.options.compact=true"


def _config_disabling_cdk_nag() -> AshConfig:
    """A config where an aliased scanner and an unaliased one are both off."""
    return AshConfig.model_validate(
        {
            "project_name": "round-trip",
            "scanners": {
                "cdk-nag": {"enabled": False},
                "bandit": {"enabled": False},
            },
        }
    )


def _config_with_a_non_default_nag_pack() -> AshConfig:
    """The shape ASH's own `.ash/.ash.yaml` uses.

    `PCIDSS321Checks` defaults to False, so a config that sets it True is
    carrying a value only the operator could have put there.
    """
    return AshConfig.model_validate(
        {
            "project_name": "round-trip",
            "scanners": {
                "cdk-nag": {"options": {"nag_packs": {"PCIDSS321Checks": True}}},
            },
        }
    )


def _aliased_fields():
    """Every (model, field name, alias) declared under `AshConfig`."""
    seen: set[type] = set()
    found = []

    def walk(model):
        if model in seen:
            return
        seen.add(model)
        for name, field in model.model_fields.items():
            alias = field.alias or field.serialization_alias
            if isinstance(alias, str):
                found.append((model.__name__, name, alias))
            annotation = field.annotation
            for candidate in [annotation, *getattr(annotation, "__args__", ())]:
                if isinstance(candidate, type) and issubclass(candidate, BaseModel):
                    walk(candidate)

    walk(AshConfig)
    return found


class TestKeyResolutionPremise:
    """`_resolve_dict_key` compares '-' and '_' spellings instead of alias maps."""

    def test_every_alias_is_its_field_name_with_dashes(self):
        """The premise that makes the textual comparison equivalent to the aliases.

        `_apply_config_override` works on a plain dict with no model in reach, so
        it resolves a key by trying the other separator rather than by looking an
        alias up. That is only equivalent while every alias has this shape. An
        alias in any other shape -- an abbreviation, a different word -- would sit
        outside that function with nothing to say so, which is why this is
        asserted over the whole tree rather than noted in a comment.
        """
        aliased = _aliased_fields()
        assert aliased, "no aliased field found: the walk stopped finding models"
        offenders = [
            (model, name, alias)
            for model, name, alias in aliased
            if alias != name.replace("_", "-")
        ]
        assert offenders == [], (
            "alias is not its field name with '-' for '_'; _resolve_dict_key in "
            f"config/resolve_config.py does not cover it: {offenders}"
        )

    def test_the_walk_reaches_the_segment_aliases(self):
        """Paired control: the assertion above is vacuous if the walk finds nothing.

        Naming the segments' own aliases keeps a walk that silently stopped at
        `AshConfig`'s top level from passing the invariant by never looking.
        """
        found = {(name, alias) for _model, name, alias in _aliased_fields()}
        for name, alias in [
            ("cdk_nag", "cdk-nag"),
            ("detect_secrets", "detect-secrets"),
            ("github_ghas", "github-ghas"),
            ("mcp_resource_management", "mcp-resource-management"),
        ]:
            assert (name, alias) in found


class TestSegmentsAcceptBothSpellings:
    """The class-level fix, asserted on the models directly."""

    def test_the_three_segments_agree_with_ashconfig(self):
        """A parity assertion, because one segment has no aliased field today.

        `ConverterConfigSegment` declares no alias, so no value-level test can
        distinguish its setting from its absence. What can be asserted is that
        all four models resolve names the same way, which is what stops the next
        aliased field added to any segment from reintroducing this.
        """
        expected = AshConfig.model_config.get("populate_by_name")
        assert expected is True
        for segment in (
            ScannerConfigSegment,
            ReporterConfigSegment,
            ConverterConfigSegment,
        ):
            assert segment.model_config.get("populate_by_name") is True, (
                f"{segment.__name__} resolves config keys by alias only"
            )

    def test_a_hand_written_field_name_spelling_reaches_the_declared_field(self):
        """Also fixes hand-written configs that use the underscore spelling."""
        segment = ScannerConfigSegment.model_validate({"cdk_nag": {"enabled": False}})

        assert segment.cdk_nag.enabled is False
        assert "cdk_nag" not in (segment.model_extra or {})

    def test_the_alias_spelling_still_reaches_the_declared_field(self):
        """Paired control: accepting the field name must not cost the alias."""
        segment = ScannerConfigSegment.model_validate({"cdk-nag": {"enabled": False}})

        assert segment.cdk_nag.enabled is False
        assert "cdk-nag" not in (segment.model_extra or {})

    def test_a_reporter_alias_behaves_the_same_way(self):
        """Reporters carry four aliases of their own, not just scanners."""
        segment = ReporterConfigSegment.model_validate(
            {"flat_json": {"enabled": False}}
        )

        assert segment.flat_json.enabled is False

    def test_the_alias_wins_when_a_config_carries_both_spellings(self):
        """Files already corrupted by this bug carry both keys.

        Which one wins has to be a property of the model rather than of dict
        ordering, or the same file resolves differently depending on how it was
        written. pydantic checks the alias first, so the alias wins and the
        field-name spelling stays visible as an extra rather than being merged
        in silently.
        """
        alias_first = ScannerConfigSegment.model_validate(
            {"cdk-nag": {"enabled": False}, "cdk_nag": {"enabled": True}}
        )
        name_first = ScannerConfigSegment.model_validate(
            {"cdk_nag": {"enabled": True}, "cdk-nag": {"enabled": False}}
        )

        assert alias_first.cdk_nag.enabled is False
        assert name_first.cdk_nag.enabled is False
        assert (name_first.model_extra or {}).get("cdk_nag") == {"enabled": True}


class TestBareRoundTrip:
    """`model_dump()` then `model_validate()`, with nothing else involved."""

    def test_a_disabled_aliased_scanner_stays_disabled(self):
        config = _config_disabling_cdk_nag()

        result = AshConfig.model_validate(config.model_dump())

        assert result.scanners.cdk_nag.enabled is False

    def test_the_unaliased_sibling_stays_disabled_too(self):
        """Paired control: `bandit` survived the round trip all along."""
        config = _config_disabling_cdk_nag()

        result = AshConfig.model_validate(config.model_dump())

        assert result.scanners.bandit.enabled is False

    def test_a_scanner_level_severity_threshold_survives(self):
        config = AshConfig.model_validate(
            {
                "project_name": "round-trip",
                "scanners": {
                    "detect-secrets": {"options": {"severity_threshold": "LOW"}},
                    "bandit": {"options": {"severity_threshold": "LOW"}},
                },
            }
        )

        result = AshConfig.model_validate(config.model_dump())

        assert result.scanners.detect_secrets.options.severity_threshold == "LOW"
        assert result.scanners.bandit.options.severity_threshold == "LOW"

    def test_the_round_trip_leaves_no_duplicate_of_an_aliased_key(self):
        """The split brain, which is worse than the loss it comes with.

        After the round trip the aliased key held reset defaults and the
        field-name key held the operator's orphaned values, so two callers
        resolving the same scanner through `get_plugin_config` could read
        different halves of the same config.
        """
        config = _config_disabling_cdk_nag()

        result = AshConfig.model_validate(config.model_dump())
        dumped = result.model_dump(by_alias=True)

        assert "cdk-nag" in dumped["scanners"]
        assert "cdk_nag" not in dumped["scanners"]


class TestApplyConfigOverrides:
    """`apply_config_overrides`, which `--compact-report` reaches on its own."""

    def test_an_unrelated_override_does_not_re_enable_a_disabled_scanner(self):
        result = apply_config_overrides(
            _config_disabling_cdk_nag(), [_UNRELATED_OVERRIDE]
        )

        assert result.scanners.cdk_nag.enabled is False

    def test_the_unrelated_override_still_takes_effect(self):
        """Paired control: preserving the rest must not drop the override."""
        result = apply_config_overrides(
            _config_disabling_cdk_nag(), [_UNRELATED_OVERRIDE]
        )

        assert result.reporters.markdown.options.compact is True

    def test_an_unrelated_override_does_not_re_enable_the_unaliased_sibling(self):
        result = apply_config_overrides(
            _config_disabling_cdk_nag(), [_UNRELATED_OVERRIDE]
        )

        assert result.scanners.bandit.enabled is False

    def test_an_unrelated_override_preserves_a_non_default_nag_pack(self):
        """The strongest form: ASH's own config depends on this value."""
        result = apply_config_overrides(
            _config_with_a_non_default_nag_pack(), [_UNRELATED_OVERRIDE]
        )

        assert result.scanners.cdk_nag.options.nag_packs.PCIDSS321Checks is True

    def test_an_override_typed_with_the_field_name_takes_effect(self):
        """The dumped dict is keyed by field name, so this spelling must work."""
        result = apply_config_overrides(
            _config_with_a_non_default_nag_pack(), ["scanners.cdk_nag.enabled=false"]
        )

        assert result.scanners.cdk_nag.enabled is False
        assert result.scanners.cdk_nag.options.nag_packs.PCIDSS321Checks is True

    def test_an_override_typed_with_the_alias_keeps_the_rest_of_the_section(self):
        """The spelling in the operator's own file, and in this option's docs.

        `_apply_config_override`'s docstring example is a kebab-case key, and
        the config on disk spells the section `cdk-nag`. Typing that spelling
        used to add a second section beside the dumped one; the alias then won
        revalidation and every other field under it came back as a default.
        """
        result = apply_config_overrides(
            _config_with_a_non_default_nag_pack(), ["scanners.cdk-nag.enabled=false"]
        )

        assert result.scanners.cdk_nag.enabled is False
        assert result.scanners.cdk_nag.options.nag_packs.PCIDSS321Checks is True

    def test_both_spellings_resolve_to_the_same_config(self):
        alias = apply_config_overrides(
            _config_with_a_non_default_nag_pack(), ["scanners.cdk-nag.enabled=false"]
        )
        field_name = apply_config_overrides(
            _config_with_a_non_default_nag_pack(), ["scanners.cdk_nag.enabled=false"]
        )

        assert alias.model_dump(by_alias=True) == field_name.model_dump(by_alias=True)

    def test_a_section_that_is_not_a_declared_field_is_created_as_typed(self):
        """Guard on the key resolution, not a regression test.

        A plugin's config key is an extra, present under exactly one spelling.
        Resolution must only ever follow a key that already exists, so a name
        absent under both spellings is still created verbatim -- otherwise
        `scanners.not-a-loaded-scanner` and `scanners.not_a_loaded_scanner`
        would collapse into whichever the plugin did not register.
        """
        result = apply_config_overrides(
            _config_disabling_cdk_nag(), ["scanners.not-a-loaded-scanner.enabled=false"]
        )

        extra = result.scanners.model_extra or {}
        assert extra["not-a-loaded-scanner"] == {"enabled": False}
        assert "not_a_loaded_scanner" not in extra


class TestConfigUpdateCommand:
    """`ash config update`, end to end through the file on disk."""

    @staticmethod
    def _write(tmp_path, body: str):
        config_file = tmp_path / ".ash.yaml"
        config_file.write_text(body, encoding="utf-8")
        return config_file

    def test_an_unrelated_set_does_not_re_enable_a_disabled_scanner(self, tmp_path):
        config_file = self._write(
            tmp_path,
            "project_name: round-trip\nscanners:\n"
            "  cdk-nag:\n    enabled: false\n  bandit:\n    enabled: false\n",
        )

        result = CliRunner().invoke(
            config_app, ["update", str(config_file), "--set", "project_name=renamed"]
        )
        assert result.exit_code == 0, result.output

        reloaded = AshConfig.from_file(config_path=config_file)
        assert reloaded.project_name == "renamed"
        assert reloaded.scanners.cdk_nag.enabled is False
        assert reloaded.scanners.bandit.enabled is False

    def test_an_unrelated_set_preserves_a_non_default_nag_pack(self, tmp_path):
        config_file = self._write(
            tmp_path,
            "project_name: round-trip\nscanners:\n  cdk-nag:\n"
            "    options:\n      nag_packs:\n        PCIDSS321Checks: true\n",
        )

        result = CliRunner().invoke(
            config_app, ["update", str(config_file), "--set", "project_name=renamed"]
        )
        assert result.exit_code == 0, result.output

        reloaded = AshConfig.from_file(config_path=config_file)
        assert reloaded.scanners.cdk_nag.options.nag_packs.PCIDSS321Checks is True

    def test_the_written_file_carries_one_spelling_of_the_key(self, tmp_path):
        """Asserted on the file text, because the file is what the next run reads."""
        config_file = self._write(
            tmp_path,
            "project_name: round-trip\nscanners:\n  cdk-nag:\n    enabled: false\n",
        )

        result = CliRunner().invoke(
            config_app, ["update", str(config_file), "--set", "project_name=renamed"]
        )
        assert result.exit_code == 0, result.output

        written = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        assert "cdk-nag" in written["scanners"]
        assert "cdk_nag" not in written["scanners"]


class TestRuntimePatch:
    """`apply_runtime_patch`, the third dump/revalidate site."""

    def test_an_unrelated_patch_does_not_re_enable_a_disabled_scanner(self):
        allowlist = RuntimeOverridesConfig(
            enabled=True, allowed_paths=["/project_name"], denied_paths=[]
        )
        ops = [{"op": "replace", "path": "/project_name", "value": "renamed"}]

        result = apply_runtime_patch(
            _config_disabling_cdk_nag(), ops, allowlist=allowlist
        )

        assert result.project_name == "renamed"
        assert result.scanners.cdk_nag.enabled is False
        assert result.scanners.bandit.enabled is False

    def test_an_unrelated_patch_preserves_a_non_default_nag_pack(self):
        allowlist = RuntimeOverridesConfig(
            enabled=True, allowed_paths=["/project_name"], denied_paths=[]
        )
        ops = [{"op": "replace", "path": "/project_name", "value": "renamed"}]

        result = apply_runtime_patch(
            _config_with_a_non_default_nag_pack(), ops, allowlist=allowlist
        )

        assert result.scanners.cdk_nag.options.nag_packs.PCIDSS321Checks is True

    def test_the_patched_document_is_keyed_by_field_name(self):
        """Guard on why this site must keep dumping without `by_alias`.

        The shipped denylist addresses `/fail_on_findings` and
        `/global_settings/ignore_paths` -- Python field names, since that is what
        the document a patch is applied to is keyed by. Dumping this site with
        `by_alias=True` instead would leave those two pointers naming nothing,
        and the ops they exist to refuse would resolve against the aliased
        document without ever matching a denial.
        """
        document = AshConfig().model_dump(mode="python", by_alias=False)
        denied = AshConfig().global_settings.mcp.runtime_overrides.denied_paths

        top_level = [p for p in denied if p.count("/") == 1 and "*" not in p]
        assert top_level, "the shipped denylist no longer names a top-level field"
        for path in top_level:
            assert path.lstrip("/") in document, (
                f"denied path {path} resolves to nothing in the patched document"
            )
