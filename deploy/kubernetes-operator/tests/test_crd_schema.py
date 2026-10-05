"""The generated CRD: is it a structural schema, and is it the real ASH surface?

A CRD the API server rejects is caught the first time anyone applies it. The
failure this file is really guarding against is quieter: a translation that drops a
field, after which CRD pruning deletes an adopter's config silently and the scan
runs with defaults.
"""

from __future__ import annotations

import json

import pytest
import yaml

from ash_operator.crd_schema import build_config_schema
from ash_operator.generate_manifests import build_mcp_crd, build_scan_crd, render

# A miniature schema in pydantic's dialect, so the translation rules can be tested
# without depending on ASH's 83 definitions staying the shape they are today.
TOY = {
    "$defs": {
        "Inner": {
            "type": "object",
            "title": "Inner",
            "additionalProperties": False,
            "properties": {
                "name": {"type": "string", "title": "Name", "default": "x"},
                "mode": {"const": "FAST", "title": "Mode"},
                "count": {"type": "integer", "exclusiveMinimum": 0},
            },
        },
        "Recursive": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"child": {"$ref": "#/$defs/Recursive"}},
        },
        "Root": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "inner": {"anyOf": [{"$ref": "#/$defs/Inner"}, {"type": "null"}]},
                "loop": {"$ref": "#/$defs/Recursive"},
                "mixed": {
                    "anyOf": [
                        {"type": "string"},
                        {"type": "integer"},
                    ]
                },
                "same_type_union": {
                    "anyOf": [
                        {"type": "string", "minLength": 1},
                        {"type": "string", "maxLength": 4},
                    ]
                },
                "anything": {},
                "plain_map": {"type": "object", "additionalProperties": {"type": "string"}},
                "named_plus_extra": {
                    "type": "object",
                    "properties": {"known": {"type": "boolean"}},
                    "additionalProperties": {"type": "object"},
                },
                "typed_list": {"type": "array"},
            },
        },
    },
    "$ref": "#/$defs/Root",
}


def walk(node, pointer=""):
    if isinstance(node, dict):
        yield pointer, node
        for key, value in node.items():
            yield from walk(value, f"{pointer}/{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from walk(value, f"{pointer}/{i}")


@pytest.fixture(scope="module")
def toy():
    return build_config_schema(TOY)


@pytest.fixture(scope="module")
def crds():
    scan, _ = build_scan_crd()
    return [scan, build_mcp_crd()]


class TestTranslationRules:
    def test_optional_collapses_to_nullable(self, toy):
        schema, report = toy
        inner = schema["properties"]["inner"]
        assert inner["type"] == "object"
        assert inner["nullable"] is True
        assert "anyOf" not in inner
        assert report.collapsed_optionals >= 1

    def test_const_becomes_a_single_member_enum(self, toy):
        schema, report = toy
        mode = schema["properties"]["inner"]["properties"]["mode"]
        assert mode["enum"] == ["FAST"]
        assert "const" not in mode
        assert report.const_to_enum >= 1

    def test_numeric_exclusive_minimum_becomes_the_openapi_boolean_form(self, toy):
        schema, report = toy
        count = schema["properties"]["inner"]["properties"]["count"]
        assert count["minimum"] == 0
        assert count["exclusiveMinimum"] is True
        assert report.exclusive_bounds_rewritten >= 1

    def test_a_reference_cycle_becomes_a_preserve_marker(self, toy):
        schema, report = toy
        loop = schema["properties"]["loop"]["properties"]["child"]
        assert loop["x-kubernetes-preserve-unknown-fields"] is True
        assert "Recursive" in report.cycles

    def test_a_mixed_type_union_is_recorded_not_silently_dropped(self, toy):
        _schema, report = toy
        paths = [entry["path"] for entry in report.unexpressible]
        assert any("mixed" in path for path in paths)

    def test_a_same_type_union_keeps_its_constraints(self, toy):
        schema, _ = toy
        node = schema["properties"]["same_type_union"]
        assert node["type"] == "string"
        assert node["anyOf"] == [{"minLength": 1}, {"maxLength": 4}]

    def test_a_plain_map_keeps_its_value_schema(self, toy):
        schema, _ = toy
        node = schema["properties"]["plain_map"]
        assert node["additionalProperties"] == {"type": "string"}

    def test_named_properties_plus_a_catch_all_preserves_unknown_keys(self, toy):
        # Not merely dropped. CRD pruning deletes undeclared fields silently, so an
        # adopter configuring a custom plugin under a name the schema does not
        # declare would watch the API server remove it and then get a scan that ran
        # the plugin with its defaults.
        schema, _ = toy
        node = schema["properties"]["named_plus_extra"]
        assert node["properties"]["known"]["type"] == "boolean"
        assert node["x-kubernetes-preserve-unknown-fields"] is True
        assert "additionalProperties" not in node

    def test_defaults_are_dropped_everywhere(self, toy):
        schema, report = toy
        assert all("default" not in node for _, node in walk(schema))
        assert report.dropped_keywords.get("default", 0) >= 1

    def test_a_typed_array_gains_an_item_schema(self, toy):
        schema, _ = toy
        assert schema["properties"]["typed_list"]["items"] == {
            "x-kubernetes-preserve-unknown-fields": True
        }

    def test_an_untyped_node_accepts_anything_rather_than_nothing(self, toy):
        schema, _ = toy
        assert schema["properties"]["anything"]["x-kubernetes-preserve-unknown-fields"] is True


class TestStructural:
    """Rules the API server enforces, checked here so a bad CRD never ships."""

    def test_no_ref_survives(self, crds):
        for crd in crds:
            assert all("$ref" not in node for _, node in walk(crd))

    def test_no_defs_survive(self, crds):
        for crd in crds:
            assert all("$defs" not in node for _, node in walk(crd))

    def test_every_node_with_properties_or_items_declares_a_type(self, crds):
        offenders = []
        for crd in crds:
            for pointer, node in walk(crd):
                if not isinstance(node, dict):
                    continue
                if ("properties" in node or "items" in node) and "type" not in node:
                    # Skip the CRD's own non-schema structure, e.g. spec.names.
                    if "/schema/openAPIV3Schema" in pointer:
                        offenders.append(pointer)
        assert offenders == []

    def test_properties_and_additional_properties_never_coexist(self, crds):
        offenders = [
            pointer
            for crd in crds
            for pointer, node in walk(crd)
            if isinstance(node, dict) and "properties" in node and "additionalProperties" in node
        ]
        assert offenders == []

    def test_no_keyword_apiextensions_does_not_know(self, crds):
        banned = {"const", "if", "then", "else", "prefixItems", "propertyNames", "$schema"}
        offenders = [
            (pointer, key)
            for crd in crds
            for pointer, node in walk(crd)
            if isinstance(node, dict)
            for key in node
            if key in banned and "/schema/openAPIV3Schema" in pointer
        ]
        assert offenders == []

    def test_exclusive_bounds_are_booleans(self, crds):
        for crd in crds:
            for pointer, node in walk(crd):
                if not isinstance(node, dict):
                    continue
                for key in ("exclusiveMinimum", "exclusiveMaximum"):
                    if key in node and "/schema/openAPIV3Schema" in pointer:
                        assert isinstance(node[key], bool), f"{pointer}/{key}"

    def test_the_status_subresource_exists(self, crds):
        for crd in crds:
            assert crd["spec"]["versions"][0]["subresources"] == {"status": {}}


class TestSchemaSource:
    """The two sources of ``AshConfig``'s schema must not drift apart."""

    def test_the_committed_schema_matches_the_live_model(self):
        """The fallback exists so the CRD tests run without ASH installed.

        That is only safe while the committed copy still describes the model. The
        repository regenerates it from the same model and gates it, so this is a
        cross-check of that gate from the consumer's side rather than a duplicate of
        it -- and it is the positive control that lets the fallback be trusted at all.
        """
        ash_config = pytest.importorskip(
            "automated_security_helper.config.ash_config",
            reason=(
                "ASH is not importable here, so the two schema sources cannot be "
                "compared. The generator will have used the committed copy; that is "
                "a real gap in this run's coverage, not a pass."
            ),
        )
        import ash_operator.crd_schema as crd_schema
        from ash_operator.crd_schema import _COMMITTED_SCHEMA, ash_config_schema_digest

        if not _COMMITTED_SCHEMA.is_file():
            # A second, non-obvious way this arm can go missing, found while building a
            # control for the CI guard. _COMMITTED_SCHEMA is derived from
            # crd_schema.__file__ by walking up three parents, which lands on the
            # repository root only when ash_operator is imported from the checkout. Import
            # it from an installed wheel instead -- which happens the moment PYTHONPATH
            # stops putting the source tree first -- and the path resolves somewhere
            # meaningless, this test skips, and the skip has nothing to do with ASH's
            # availability. The workflow's with-ASH step fails on any skip at all, so this
            # cannot pass unnoticed there; the message has to say which of the two causes
            # it is.
            pytest.skip(
                f"no committed schema at {_COMMITTED_SCHEMA}. ash_operator was imported "
                f"from {crd_schema.__file__}; if that is inside site-packages rather than "
                f"the checkout, the path was derived from an installed copy and there is "
                f"no repository above it. Set PYTHONPATH to the operator directory."
            )
        with open(_COMMITTED_SCHEMA) as handle:
            committed = json.load(handle)
        live = ash_config.AshConfig.model_json_schema()
        assert ash_config_schema_digest(committed) == ash_config_schema_digest(live), (
            f"{_COMMITTED_SCHEMA} no longer matches AshConfig.model_json_schema(). "
            f"Regenerate it with automated_security_helper/schemas/generate_schemas.py "
            f"-- until then, a CRD generated without ASH installed describes a "
            f"different config surface from one generated with it."
        )

    def test_the_live_model_is_preferred_when_available(self):
        pytest.importorskip("automated_security_helper.config.ash_config")
        from ash_operator.crd_schema import ash_config_json_schema

        _schema, origin = ash_config_json_schema()
        assert origin == "model"

    def test_the_report_records_which_source_and_its_digest(self):
        _schema, report = build_config_schema()
        assert report.source in {"model", "committed"}
        assert len(report.source_digest) == 16
        assert report.as_report()["sourceSchemaSha256"] == report.source_digest


class TestFullExposure:
    def test_every_top_level_ash_config_field_is_present(self):
        """The requirement was full exposure, so every field is checked by name."""
        ash_config = pytest.importorskip(
            "automated_security_helper.config.ash_config",
            reason="ASH is not importable here; full-exposure cannot be verified.",
        )
        model_fields = {
            (field.alias or name) for name, field in ash_config.AshConfig.model_fields.items()
        }
        schema, _ = build_config_schema()
        exposed = set(schema["properties"])
        assert model_fields <= exposed, f"missing from the CRD: {sorted(model_fields - exposed)}"

    def test_the_hyphenated_alias_survives(self):
        # ASH spells one top-level key with a hyphen. Renaming it to camelCase would
        # mean the operator rewriting an adopter's config, and a config the operator
        # rewrites cannot be diffed against ASH's own documentation.
        schema, _ = build_config_schema()
        assert "mcp-resource-management" in schema["properties"]

    def test_the_mcp_runtime_override_allowlist_is_reachable(self):
        schema, _ = build_config_schema()
        node = schema["properties"]["global_settings"]["properties"]["mcp"]
        overrides = node["properties"]["runtime_overrides"]["properties"]
        assert {"enabled", "allowed_paths", "denied_paths", "denied_value_patterns"} <= set(
            overrides
        )

    def test_the_operator_says_which_fields_it_overrides(self):
        schema, _ = build_config_schema()
        for name in ("fail_on_findings", "fail_on_incomplete_scanners"):
            assert "IGNORED BY THE OPERATOR" in schema["properties"][name]["description"]


class TestRenderedSize:
    def test_the_crd_fits_inside_a_client_side_kubectl_apply(self):
        """Measured, because the limit is not the one people expect.

        ``kubectl apply`` stores the whole object in a
        ``kubectl.kubernetes.io/last-applied-configuration`` annotation, and
        annotations are capped at 262144 bytes in total. A CRD that exceeds it
        applies fine with ``--server-side`` and fails with plain ``apply``, so the
        number is worth pinning rather than discovering in someone's pipeline.
        """
        scan, _ = build_scan_crd()
        rendered = render(scan).encode()
        assert len(rendered) < 262144, (
            f"the generated AshScan CRD is {len(rendered)} bytes, which exceeds the "
            f"262144-byte annotation cap that plain `kubectl apply` needs. Either "
            f"shrink spec.config or document --server-side as required."
        )

    def test_the_rendered_yaml_parses_back(self):
        scan, _ = build_scan_crd()
        assert yaml.safe_load(render(scan))["kind"] == "CustomResourceDefinition"

    def test_the_translation_report_is_json_serialisable(self):
        _, report = build_scan_crd()
        json.dumps(report)
