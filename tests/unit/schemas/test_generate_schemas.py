"""Unit tests for schema generation module.

WHY THE BIJECTION TEST BELOW EXISTS
-----------------------------------
The CI schema gate regenerates the schemas and then runs
`git status --porcelain -- 'automated_security_helper/schemas/*.json'`, failing on
any output. The porcelain choice is deliberate and correct: `git diff` cannot see
a file git has never heard of, so a newly registered model's untracked `.json`
would read as clean.

What porcelain cannot see is the opposite drift. Dropping a model from the
hardcoded list at `generate_schemas.py:26` means the generator stops emitting
that schema -- and the already-committed `.json` simply stays where it is,
unmodified. Nothing is added, nothing is changed, porcelain reports nothing, and
a stale schema ships forever with no producer.

MEASURED: with `AshWorkspaceConfig` removed from the list, the generator ran
successfully, `git status --porcelain` on the schema pathspec printed nothing, and
`AshWorkspaceConfig.json` remained committed. The CI gate passed.

The one thing that did catch it was
`tests/unit/workspace/test_workspace_policy.py::test_the_generated_schema_includes_the_workspace_config`,
which asserts that name specifically. That is a membership assertion per model,
written where the model's own behaviour is tested, and it only guards the models
somebody remembered to name -- a fourth model added to the list is guarded by
nothing. The test below is the structural version: it compares the generator's
output set against the committed files as SETS, so a dropped model, an orphaned
file and an uncommitted new schema are each a failure without anyone having to
remember the name.
"""

import json
from pathlib import Path

import automated_security_helper.schemas.generate_schemas as generate_schemas_module
from automated_security_helper.schemas.generate_schemas import generate_schemas

SCHEMAS_DIR = Path(generate_schemas_module.__file__).resolve().parent


def committed_schema_names() -> set[str]:
    """The stems of the committed top-level schema files.

    Top-level only, matching the CI gate's own non-recursive
    `automated_security_helper/schemas/*.json` pathspec. The subpackages here
    (`ocsf/`, `gitlab/`, `cyclonedx_bom_1_6_schema/`) hold vendored
    datamodel-codegen output, which this generator does not produce and must not
    be compared against.
    """
    return {path.stem for path in SCHEMAS_DIR.glob("*.json")}


class TestSchemaGeneration:
    """Test cases for schema generation."""

    def test_generate_json_schema(self):
        """Test generating JSON schema for models."""
        # Test generating schema for a single model
        schema = generate_schemas("dict")
        assert isinstance(schema, dict)
        assert "AshConfig" in schema
        assert "AshAggregatedResults" in schema
        # AshWorkspaceConfig was absent from this test while the other two were
        # named, so it was the one model a drop could silently remove.
        assert "AshWorkspaceConfig" in schema

        # Check that the schema has the expected structure
        # The schema structure might be different depending on Pydantic version
        # So we just check that we have a dictionary with the expected keys
        assert isinstance(schema["AshConfig"], dict)
        assert isinstance(schema["AshAggregatedResults"], dict)
        assert isinstance(schema["AshWorkspaceConfig"], dict)


class TestSchemaInventoryIsClosed:
    """The generator's output set and the committed files must be the same set."""

    def test_the_generator_emits_something(self):
        """A positive control: an empty result would make every set test vacuous.

        `git status --porcelain` is clean both when the schemas are correct and
        when the generator emits nothing at all, because writing nothing changes
        nothing. This separates those two states.
        """
        emitted = generate_schemas("dict")
        assert emitted, "the generator produced no schemas at all"
        assert len(emitted) >= 3, (
            f"the generator emitted {len(emitted)} schema(s); three models are "
            f"registered, so this is a model silently dropped from the list"
        )

    def test_every_emitted_schema_is_substantive(self):
        """A model emitting an empty object would satisfy a names-only check."""
        for name, schema in generate_schemas("dict").items():
            assert isinstance(schema, dict), f"{name} did not produce an object"
            assert "properties" in schema or "$defs" in schema, (
                f"{name} produced a schema with neither properties nor $defs, "
                f"which describes nothing"
            )

    def test_no_committed_schema_is_orphaned(self):
        """A committed .json that no registered model produces is stale forever.

        This is the drift `git status --porcelain` structurally cannot report,
        because dropping a model leaves the file untouched rather than changed.
        """
        emitted = set(generate_schemas("dict"))
        committed = committed_schema_names()

        orphaned = sorted(committed - emitted)
        assert not orphaned, (
            f"{orphaned} are committed under automated_security_helper/schemas/ "
            f"but no model in generate_schemas.py produces them. Either the model "
            f"was dropped from the list -- in which case restore it -- or the "
            f"schema is genuinely retired and the file must be deleted. Until "
            f"then it ships to users and nothing updates it."
        )

    def test_every_emitted_schema_is_committed(self):
        """The direction porcelain does cover, asserted here too.

        Kept because it costs one line and makes this test the whole invariant
        rather than half of it; the two halves are what make it a bijection.
        """
        emitted = set(generate_schemas("dict"))
        missing = sorted(emitted - committed_schema_names())
        assert not missing, (
            f"{missing} are generated but not committed. Run "
            f"'python -m automated_security_helper.schemas.generate_schemas' and "
            f"commit the result."
        )

    def test_file_mode_writes_one_file_per_model(self, tmp_path, monkeypatch):
        """Assert the file-writing path's output COUNT, not just that it ran.

        `generate_schemas` only writes when the rendered content differs from
        what is on disk -- which is right, because an unconditional write makes
        pre-commit report every unchanged schema as modified. The cost is that a
        run which writes nothing looks exactly like a run which had nothing to
        write. Pointing the generator at an empty directory removes that
        ambiguity: every file it should produce must appear.

        The module's own `__file__` is what it derives the output directory from,
        so redirecting that is what isolates the write.
        """
        monkeypatch.setattr(
            generate_schemas_module,
            "__file__",
            str(tmp_path / "generate_schemas.py"),
        )

        expected = set(generate_schemas("dict"))
        assert generate_schemas("file") is None

        written = {path.stem for path in tmp_path.glob("*.json")}
        assert written == expected, (
            f"file mode wrote {sorted(written)} but the model list is "
            f"{sorted(expected)}"
        )

        for path in tmp_path.glob("*.json"):
            assert path.read_text(encoding="utf-8").endswith("\n")
            json.loads(path.read_text(encoding="utf-8"))
