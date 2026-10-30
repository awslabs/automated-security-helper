# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Readings of a SARIF result that ``sarif_utils`` got wrong at the edges.

A suppression object whose ``state`` is ``rejected`` or ``underReview`` has not
taken effect (SARIF 3.35.4), yet any suppression object counted as suppressed. A
message's markdown form was never masked. A percent-encoded relative URI was
matched undecoded, so no suppression applied to a file whose name holds a space.
A URI holding a NUL made ``Path.resolve`` raise out of the suppression pass. A
result whose first location names no file, or whose message is given by id alone,
broke the config-suppression pass for the whole scanner.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Kind1,
    Location,
    Message,
    Message2,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    State,
    Suppression,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import (
    _matched_path_text,
    _OutputDirExclusion,
    _result_message_text,
    apply_suppressions_to_sarif,
    get_severity_metrics_from_sarif,
    is_result_suppressed,
    mask_secrets_in_sarif,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _result(uri: str | None = "app.py", **overrides) -> Result:
    values = {
        "ruleId": "RULE-1",
        "level": "error",
        "message": Message(text="finding"),
    }
    if uri is not None:
        values["locations"] = [
            Location(
                physicalLocation=PhysicalLocation2(
                    artifactLocation=ArtifactLocation(uri=uri),
                    region=Region(startLine=3, endLine=3),
                )
            )
        ]
    values.update(overrides)
    return Result(**values)


def _report(*results: Result) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="scripted")),
                results=list(results),
            )
        ],
    )


def _context(tmp_path: Path, config: AshConfig | None = None) -> PluginContext:
    source = tmp_path / "src"
    output = source / ".ash" / "ash_output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=config or AshConfig(project_name="u28"),
    )


class TestSuppressionState:
    @pytest.mark.parametrize("state", [State.rejected, State.underReview])
    def test_a_rejected_or_reviewed_suppression_is_not_in_effect(self, state):
        result = _result(suppressions=[Suppression(kind=Kind1.inSource, state=state)])

        assert is_result_suppressed(result) is False
        counts = get_severity_metrics_from_sarif(_report(result), MagicMock())
        assert counts.suppressed == 0
        assert counts.critical == 1

    @pytest.mark.parametrize("state", [None, State.accepted])
    def test_an_accepted_or_stateless_suppression_counts(self, state):
        result = _result(suppressions=[Suppression(kind=Kind1.inSource, state=state)])

        assert is_result_suppressed(result) is True
        counts = get_severity_metrics_from_sarif(_report(result), MagicMock())
        assert counts.suppressed == 1
        assert counts.critical == 0

    @pytest.mark.parametrize(
        ("states", "suppressed"),
        [
            ([State.rejected, None], True),
            ([State.underReview, State.accepted], True),
            ([None, State.rejected], True),
            ([State.rejected, State.underReview], False),
        ],
        ids=["rejected+stateless", "review+accepted", "stateless+rejected", "none"],
    )
    def test_a_mixed_list_is_in_effect_when_any_one_suppression_is(
        self, states, suppressed
    ):
        """The rule is ANY: one suppression in effect suppresses the result
        whatever records sit beside it, and a list of rejected and under-review
        records alone does not. The pass itself builds such lists (a scanner's
        rejected record kept beside ASH's own)."""
        result = _result(
            suppressions=[Suppression(kind=Kind1.inSource, state=s) for s in states]
        )

        assert is_result_suppressed(result) is suppressed
        counts = get_severity_metrics_from_sarif(_report(result), MagicMock())
        assert counts.suppressed == (1 if suppressed else 0)
        assert counts.critical == (0 if suppressed else 1)


def test_the_markdown_form_of_a_message_is_masked_too():
    text = "Possible hardcoded password: 'hunter2'"  # pragma: allowlist secret
    result = _result(ruleId="B105", message=Message(text=text, markdown=f"**{text}**"))

    mask_secrets_in_sarif(_report(result))

    assert "hunter2" not in result.message.root.text
    assert "hunter2" not in result.message.root.markdown
    assert result.message.root.markdown.startswith("**Possible hardcoded password")


def test_a_percent_encoded_relative_uri_names_the_decoded_file():
    assert _matched_path_text("src/my%20app/a%28b%29.py", "/work/") == (
        "src/my app/a(b).py"
    )
    # A URI with a scheme and an authority is left as written.
    assert _matched_path_text("https://host/x%20y", "/work/") == "https://host/x%20y"
    # A path with no escape is unchanged.
    assert _matched_path_text("src/a.py", "/work/") == "src/a.py"


def test_a_uri_holding_a_nul_is_not_in_the_output_directory(tmp_path):
    exclusion = _OutputDirExclusion(_context(tmp_path))

    # Raised ValueError ("embedded null byte") out of resolve() before the fix.
    assert exclusion.holds("app\x00.py") is False
    assert exclusion.holds(".ash/ash_output/planted.py") is True


def test_an_id_only_message_gives_the_suppression_pass_a_title(tmp_path):
    config = AshConfig(
        project_name="u28",
        global_settings={
            "suppressions": [
                AshSuppression(rule_id="RULE-1", path="app.py", reason="known")
            ]
        },
    )
    result = _result(message=Message(Message2(id="rule.default")))

    report = apply_suppressions_to_sarif(_report(result), _context(tmp_path, config))

    # Raised ValidationError (title=None) before the fix; now the entry applies.
    assert report.runs[0].results[0].suppressions
    assert _result_message_text(result) == "Message id: rule.default"


def _transitive(root_rule: str, root_uri: str = "package-lock.json") -> Result:
    return _result(
        uri=root_uri,
        ruleId="npm-audit-transitive-left-pad",
        properties={"root_advisories": [{"rule_id": root_rule, "uri": root_uri}]},
    )


def test_a_root_reference_with_an_empty_rule_id_does_not_raise():
    """extract_root_advisories keeps such a reference but drops its empty key, so
    ref["rule_id"] raised KeyError out of the whole suppression pass."""
    from automated_security_helper.utils.sarif_utils import (
        _suppress_transitive_of_suppressed_roots,
    )

    root = _result(
        uri="package-lock.json",
        ruleId="GHSA-1",
        suppressions=[Suppression(kind=Kind1.external, justification="x")],
    )
    transitive = _transitive(root_rule="")
    report = _report(root, transitive)

    _suppress_transitive_of_suppressed_roots(report, lambda value, _is_uri: value)

    # A reference naming no rule matches nothing: the transitive finding stays.
    assert not transitive.suppressions


def test_a_transitive_suppressed_through_a_client_root_carries_the_client_mark():
    """The results show what the client's config hid; a transitive finding hidden
    only because its root was carried no mark."""
    from automated_security_helper.utils.sarif_utils import (
        _add_client_suppression,
        _suppress_transitive_of_suppressed_roots,
    )

    root = _result(uri="package-lock.json", ruleId="GHSA-1")
    _add_client_suppression(root, "(ASH, client-supplied config) hidden")
    transitive = _transitive(root_rule="GHSA-1")
    plain_root = _result(uri="other-lock.json", ruleId="GHSA-2")
    plain_root.suppressions = [Suppression(kind=Kind1.external, justification="x")]
    plain_transitive = _transitive(root_rule="GHSA-2", root_uri="other-lock.json")
    report = _report(root, transitive, plain_root, plain_transitive)

    _suppress_transitive_of_suppressed_roots(report, lambda value, _is_uri: value)

    assert transitive.suppressions
    assert transitive.suppressions[0].properties.clientSupplied is True
    assert plain_transitive.suppressions
    # Every suppression ASH attaches carries ashApplied; only the one hidden
    # through a client-supplied root carries clientSupplied as well.
    plain_properties = plain_transitive.suppressions[0].properties
    assert plain_properties.ashApplied is True
    assert "clientSupplied" not in (plain_properties.model_extra or {})


def test_the_first_location_naming_a_file_is_the_one_the_suppression_reads(tmp_path):
    config = AshConfig(
        project_name="u28",
        global_settings={
            "suppressions": [
                AshSuppression(rule_id="RULE-1", path="app.py", reason="known")
            ]
        },
    )
    result = _result()
    # A first location with no physicalLocation, as a logical location gives.
    result.locations = [Location(message=Message(text="in handler")), *result.locations]

    report = apply_suppressions_to_sarif(_report(result), _context(tmp_path, config))

    assert report.runs[0].results[0].suppressions


def test_a_first_location_given_by_index_alone_is_passed_over(tmp_path):
    """An artifactLocation may name its artifact by ``index`` alone, with no
    ``uri``; the picker took it, read ``""`` as the path and the saved entry on
    the located second location never applied."""
    config = AshConfig(
        project_name="u28",
        global_settings={
            "suppressions": [
                AshSuppression(rule_id="RULE-1", path="app.py", reason="known")
            ]
        },
    )
    result = _result()
    result.locations = [
        Location(
            physicalLocation=PhysicalLocation2(
                artifactLocation=ArtifactLocation(index=0)
            )
        ),
        *result.locations,
    ]

    report = apply_suppressions_to_sarif(_report(result), _context(tmp_path, config))

    assert report.runs[0].results[0].suppressions


def test_a_transitive_finding_keeps_the_record_its_scanner_gave_it():
    """The pass reaches a transitive result whose only suppression is a
    scanner's rejected record (not in effect) and then REPLACED its list, so
    the record was gone and the lift left nothing."""
    from automated_security_helper.utils.sarif_utils import (
        _suppress_transitive_of_suppressed_roots,
    )

    root = _result(
        uri="package-lock.json",
        ruleId="GHSA-1",
        suppressions=[Suppression(kind=Kind1.external, justification="x")],
    )
    transitive = _transitive(root_rule="GHSA-1")
    transitive.suppressions = [
        Suppression(
            kind=Kind1.external, state=State.rejected, justification="scanner record"
        )
    ]

    _suppress_transitive_of_suppressed_roots(
        _report(root, transitive), lambda value, _is_uri: value
    )

    assert len(transitive.suppressions) == 2
    assert transitive.suppressions[0].justification == "scanner record"
    assert transitive.suppressions[0].state == State.rejected
    assert transitive.suppressions[1].justification.startswith(
        "(ASH) Suppressed because every root advisory is suppressed"
    )
    assert is_result_suppressed(transitive)


def test_a_file_named_with_an_escape_is_read_as_written(tmp_path):
    """A plain-path producer wrote ``fixtures/a%2Fb.json`` for the file of that
    name; decoded, it named the missing ``fixtures/a/b.json``, so the inline read
    opened nothing and the finding id changed."""
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "a%2Fb.json").write_text("{}", encoding="utf-8")
    (tmp_path / "fixtures" / "a b.json").write_text("{}", encoding="utf-8")
    prefix = f"{tmp_path.as_posix()}/"

    # The spelling as written names a file and the decoded one does not: kept.
    assert _matched_path_text("fixtures/a%2Fb.json", prefix) == "fixtures/a%2Fb.json"
    # Only the decoded spelling names a file: decoded, as a URI reads.
    assert _matched_path_text("fixtures/a%20b.json", prefix) == "fixtures/a b.json"
    # Neither names a file: decoded, as before.
    assert _matched_path_text("fixtures/c%2Fd.json", prefix) == "fixtures/c/d.json"


def test_the_written_spelling_is_probed_only_under_the_scan_root(tmp_path):
    """The existence probe behind the as-written reading is confined to the scan
    root: a spelling that climbs out of it, or is absolute, is never probed (and
    so decodes as a URI), while one that folds back inside it is."""
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "a%2Fb.json").write_text("{}", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    root = f"{tmp_path.as_posix()}/"
    sub_root = f"{tmp_path.as_posix()}/sub/"

    # Climbing out of the root reaches the file on disk, but is not probed.
    assert (
        _matched_path_text("../fixtures/a%2Fb.json", sub_root) == "../fixtures/a/b.json"
    )
    # An absolute spelling is not probed either, wherever it points.
    assert (
        _matched_path_text(f"{root}fixtures/a%2Fb.json", root)
        == f"{root}fixtures/a/b.json"
    )
    # A spelling that folds back inside the root is probed and kept as written.
    assert _matched_path_text("fixtures/./a%2Fb.json", root) == "fixtures/a%2Fb.json"
    assert (
        _matched_path_text("sub/../fixtures/a%2Fb.json", root)
        == "sub/../fixtures/a%2Fb.json"
    )
    # A literal backslash is a separator to a Windows stat and is not folded, so
    # such a spelling is not probed even where a POSIX file of that name exists.
    # A drive-relative spelling (``C:x``) is placed by a Windows join at the
    # drive's current directory, outside the root, so it is not probed either.
    # Neither name can be made on Windows (a backslash is a separator there and
    # a colon is refused), so the files exist only on POSIX; on Windows the
    # refusal is asserted with no such file present.
    if os.name != "nt":
        (tmp_path / "fixtures" / "a\\..%2Fb.json").write_text("{}", encoding="utf-8")
        (tmp_path / "C:x%2Fb.json").write_text("{}", encoding="utf-8")
    # Decoded, never kept as written; the reading's sanitize step then treats the
    # literal backslash as a separator under a Windows scan root
    # (uri_separators.sanitized_uri_text), so the decoded text keeps the backslash
    # on POSIX and shows a slash on Windows.
    assert _matched_path_text("fixtures/a\\..%2Fb.json", root) in (
        "fixtures/a\\../b.json",
        "fixtures/a/../b.json",
    )
    assert _matched_path_text("C:x%2Fb.json", root) == "C:x/b.json"


def _suppressing(path: str) -> AshConfig:
    return AshConfig(
        project_name="u28",
        global_settings={
            "suppressions": [
                AshSuppression(rule_id="RULE-1", path=path, reason="known")
            ]
        },
    )


def test_a_result_with_only_logical_locations_does_not_stop_the_pass(tmp_path):
    """A result whose every location names no file (a logical location alone)
    has no path for a config suppression to match; the pass passes it over and
    still suppresses the located result beside it."""
    logical = _result(uri=None, locations=[Location(message=Message(text="handler"))])
    located = _result()

    report = apply_suppressions_to_sarif(
        _report(logical, located), _context(tmp_path, _suppressing("app.py"))
    )

    assert not report.runs[0].results[0].suppressions
    assert report.runs[0].results[1].suppressions


def test_a_percent_encoded_space_matches_the_decoded_suppression_path(tmp_path):
    """``my%20app/a.py`` in the SARIF names ``my app/a.py``; the config names the
    file as a person spells it."""
    report = apply_suppressions_to_sarif(
        _report(_result(uri="my%20app/a.py")),
        _context(tmp_path, _suppressing("my app/a.py")),
    )

    assert report.runs[0].results[0].suppressions


def test_a_uri_holding_an_encoded_nul_does_not_stop_the_pass(tmp_path):
    """``%00`` decodes to a NUL, which no path on disk can hold; the pass neither
    raises on it nor matches it, and the located result beside it is suppressed."""
    report = apply_suppressions_to_sarif(
        _report(_result(uri="app%00.py"), _result()),
        _context(tmp_path, _suppressing("app.py")),
    )

    assert not report.runs[0].results[0].suppressions
    assert report.runs[0].results[1].suppressions


def test_the_evaluation_budget_is_closed_when_the_pass_raises(tmp_path, monkeypatch):
    """The pass closed its EvaluationBudget on the normal return only, so an
    exception raised inside it left the budget's worker child to the garbage
    collector. The pass now owns the budget as a context manager: a pass that
    raises on its first step still closes it, exactly once."""
    from automated_security_helper.config import client_scanner_exclusions
    from automated_security_helper.utils import sarif_utils

    closed: list[bool] = []

    class RecordingBudget(client_scanner_exclusions.EvaluationBudget):
        def close(self, graceful: bool = True) -> None:
            closed.append(graceful)
            super().close(graceful)

    def planted_failure(_ignore_paths):
        raise RuntimeError("planted")

    # The pass imports the budget from its module at call time, so the module
    # attribute is what it reads; the first step of the pass is made to raise.
    monkeypatch.setattr(client_scanner_exclusions, "EvaluationBudget", RecordingBudget)
    monkeypatch.setattr(sarif_utils, "active_ignore_paths", planted_failure)

    with pytest.raises(RuntimeError, match="planted"):
        apply_suppressions_to_sarif(_report(_result()), _context(tmp_path))

    # The finalizer closes the worker, never the budget, so this list is empty
    # when the pass leaves its budget to the collector.
    assert closed == [True]
