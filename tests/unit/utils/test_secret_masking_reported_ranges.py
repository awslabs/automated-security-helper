# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The line range a secret finding covers: key blocks and resource-level findings.

A key reported on its BEGIN line runs to its END line, found in other findings'
snippets. The first masking replaced those lines with ``MASKED_LINE``, so every
later masking (each reload, ``ash merge``, the findings browser) could not find
the END line again: a private-key finding then masked to the end of the file,
and a finding known only from its BEGIN line covered that one line. The END
line was also read from any file of the same name, so another file's earlier
END line cut the range short.

The PEM block here is a shape, not a key: its body lines are derived at import
time.
"""

import hashlib
import json
import string

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import Region, SarifReport
from automated_security_helper.utils.secret_masking import (
    MASKED_LINE,
    _has_columns,
    mask_secrets_in_results,
    source_snippet_masker,
)

pytestmark = pytest.mark.unit


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


#: A PEM block as a file holds it, lines 11-14.
PEM_LINES = [
    "-----BEGIN RSA PRIVATE " + "KEY-----\n",
    _derived("ranges-body-1", 40) + "\n",
    _derived("ranges-body-2", 40) + "\n",
    "-----END RSA PRIVATE " + "KEY-----\n",
]
BEFORE_PEM = "x = 1\n"
AFTER_PEM = "y = 2\n"
FAR_LINE = "z = 3\n"


def _result(
    rule_id, uri, line, message, scanner, context=None, end=None, tags=None, column=None
):
    region = {"startLine": line, "endLine": end if end is not None else line}
    if column is not None:
        region["startColumn"] = column
    physical = {"artifactLocation": {"uri": uri}, "region": region}
    if context is not None:
        start, lines = context
        physical["contextRegion"] = {
            "startLine": start,
            "snippet": {"text": "".join(lines)},
        }
    return {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": message},
        "locations": [{"physicalLocation": physical}],
        "properties": {"scanner_name": scanner, "tags": tags or [scanner]},
    }


def _key_finding(uri="keys.py", rule_id="SECRET-PRIVATE-KEY", tags=None):
    """detect-secrets reports a private key on its BEGIN line only."""
    message = "Custom finding" if tags else "Secret of type 'Private Key' detected"
    return _result(rule_id, uri, 11, message, "detect-secrets", tags=tags)


def _neighbor(uri, line, context_start, context_lines):
    return _result(
        "B108", uri, line, "other", "bandit", context=(context_start, context_lines)
    )


def _results(*results):
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": list(results)}],
        }
    )
    return model


def _context(model, position):
    physical = model.sarif.runs[0].results[position].locations[0].physicalLocation.root
    return physical.contextRegion.snippet.text


def _region(model, position):
    return (
        model.sarif.runs[0].results[position].locations[0].physicalLocation.root.region
    )


class TestAKeyBlocksRangeOnLaterMaskings:
    def _model(self):
        return _results(
            _key_finding(),
            _neighbor("keys.py", 10, 10, [BEFORE_PEM] + PEM_LINES + [AFTER_PEM]),
            _neighbor("keys.py", 40, 40, [FAR_LINE]),
        )

    def test_the_end_line_found_is_recorded_on_the_key_finding(self):
        """The END line is kept as a property; the scanner's own region, which is
        the finding's identity across scans, is left as written."""
        model = self._model()

        mask_secrets_in_results(model)

        recorded = model.sarif.runs[0].results[0].properties.model_dump()
        assert recorded["masked_block_end"] == [14]
        assert "masked_to_end_of_file" not in recorded
        assert _region(model, 0).endLine == 11

    def test_a_second_masking_stops_at_the_end_line(self):
        """Every reload masks again; the END line is masked by then."""
        model = self._model()
        mask_secrets_in_results(model)
        once = (_context(model, 1), _context(model, 2))

        mask_secrets_in_results(model)

        assert once == (
            BEFORE_PEM + (MASKED_LINE + "\n") * 4 + AFTER_PEM,
            FAR_LINE,
        )
        assert (_context(model, 1), _context(model, 2)) == once

    def test_a_producers_own_end_line_does_not_bound_a_key_with_no_end_in_sight(
        self,
    ):
        """A producer that reports a key as lines 11-12 says nothing about where the
        block ends; with no END line in any snippet every later line is masked,
        as it was before the END line was kept on the finding. Only an END line
        an earlier masking wrote (the line then reads as masked) bounds it."""
        key = _key_finding()
        key["locations"][0]["physicalLocation"]["region"]["endLine"] = 12
        model = _results(
            key,
            _neighbor("keys.py", 10, 10, [BEFORE_PEM] + PEM_LINES[:3]),
            _neighbor("keys.py", 40, 40, [FAR_LINE]),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == BEFORE_PEM + (MASKED_LINE + "\n") * 3
        assert _context(model, 2) == MASKED_LINE + "\n"

    def _key_with_no_end_in_sight(self):
        key = _key_finding()
        key["locations"][0]["physicalLocation"]["region"]["endLine"] = 12
        return _results(
            key,
            _neighbor("keys.py", 10, 10, [BEFORE_PEM] + PEM_LINES[:3]),
            _neighbor("keys.py", 40, 40, [FAR_LINE]),
        )

    def test_a_second_masking_of_a_key_with_no_end_in_sight_runs_to_the_end(self):
        """The first masking left the line at the producer's endLine reading as a
        masked line, which alone looks like an END line an earlier masking wrote;
        the finding records that its range ran to the end of the file, so every
        reload masks the same lines and the browser shows none of the key's tail."""
        model = self._key_with_no_end_in_sight()
        mask_secrets_in_results(model)
        loaded = AshAggregatedResults.model_validate_json(model.model_dump_json())

        mask_secrets_in_results(loaded)
        mask = source_snippet_masker(loaded)
        shown = mask("keys.py", 10, "".join([BEFORE_PEM] + PEM_LINES + [AFTER_PEM]))

        assert shown == BEFORE_PEM + (MASKED_LINE + "\n") * 5
        assert _context(loaded, 2) == MASKED_LINE + "\n"
        recorded = loaded.sarif.runs[0].results[0].properties.model_dump()
        assert recorded["masked_to_end_of_file"] == [0]
        assert "masked_block_end" not in recorded

    def test_an_end_line_found_later_bounds_the_range_and_drops_the_record(self):
        """Control: a later masking whose snippets show the END line keeps it on
        the finding and the range stops there again."""
        model = self._key_with_no_end_in_sight()
        mask_secrets_in_results(model)
        key = json.loads(
            model.sarif.runs[0].results[0].model_dump_json(exclude_none=True)
        )
        later = _results(
            key,
            _neighbor("keys.py", 10, 10, [BEFORE_PEM] + PEM_LINES + [AFTER_PEM]),
            _neighbor("keys.py", 40, 40, [FAR_LINE]),
        )

        mask_secrets_in_results(later)

        assert _region(later, 0).endLine == 12
        assert _context(later, 1) == BEFORE_PEM + (MASKED_LINE + "\n") * 4 + AFTER_PEM
        assert _context(later, 2) == FAR_LINE
        recorded = later.sarif.runs[0].results[0].properties.model_dump()
        assert "masked_to_end_of_file" not in recorded
        assert recorded["masked_block_end"] == [14]

    def test_a_recorded_end_line_bounds_the_range_once_its_snippets_are_masked(
        self,
    ):
        """After the END line is recorded, a reload masks the block's lines and
        no snippet shows an END line any more: the record bounds the range, the
        lines after it stay, and the region is still the scanner's."""
        model = self._model()
        mask_secrets_in_results(model)
        loaded = AshAggregatedResults.model_validate_json(model.model_dump_json())

        mask_secrets_in_results(loaded)
        mask = source_snippet_masker(loaded)
        shown = mask("keys.py", 10, "".join([BEFORE_PEM] + PEM_LINES + [AFTER_PEM]))

        assert shown == BEFORE_PEM + (MASKED_LINE + "\n") * 4 + AFTER_PEM
        assert _context(loaded, 2) == FAR_LINE
        assert _region(loaded, 0).endLine == 11
        recorded = loaded.sarif.runs[0].results[0].properties.model_dump()
        assert recorded["masked_block_end"] == [14]

    def test_a_begin_line_finding_with_no_end_in_sight_keeps_its_range_on_reload(
        self,
    ):
        """A rule that is not a private-key rule is known to start a block only
        from the BEGIN line, which the first masking replaced; the record on the
        finding is what keeps the range to the end of the file afterwards."""
        model = _results(
            _key_finding(rule_id="CUSTOM-1", tags=["secret"]),
            _neighbor("keys.py", 10, 10, [BEFORE_PEM] + PEM_LINES[:3]),
            _neighbor("keys.py", 40, 40, [FAR_LINE]),
        )
        mask_secrets_in_results(model)
        loaded = AshAggregatedResults.model_validate_json(model.model_dump_json())

        mask_secrets_in_results(loaded)
        mask = source_snippet_masker(loaded)
        shown = mask("keys.py", 10, "".join([BEFORE_PEM] + PEM_LINES + [AFTER_PEM]))

        assert shown == BEFORE_PEM + (MASKED_LINE + "\n") * 5
        assert _context(loaded, 2) == MASKED_LINE + "\n"

    def test_the_findings_browser_masks_the_body_of_a_begin_line_finding(self):
        """A rule that is not a private-key rule is known to start a block only
        from the BEGIN line, which the first masking replaced."""
        model = _results(
            _key_finding(rule_id="CUSTOM-1", tags=["secret"]),
            _neighbor("keys.py", 10, 10, [BEFORE_PEM] + PEM_LINES + [AFTER_PEM]),
        )
        mask_secrets_in_results(model)

        mask = source_snippet_masker(model)
        shown = mask("keys.py", 10, "".join([BEFORE_PEM] + PEM_LINES + [AFTER_PEM]))

        assert shown == BEFORE_PEM + (MASKED_LINE + "\n") * 4 + AFTER_PEM

    def _begin_line_finding_alone(self):
        """No other finding's snippet shows the BEGIN line and nothing was
        recorded on the finding: a single-finding file, or results a version
        before the record was written saved."""
        return _results(_key_finding(rule_id="CUSTOM-1", tags=["secret"]))

    def test_the_findings_browser_masks_a_key_nothing_else_showed(self):
        mask = source_snippet_masker(self._begin_line_finding_alone())

        shown = mask("keys.py", 10, "".join([BEFORE_PEM] + PEM_LINES + [AFTER_PEM]))

        assert shown == BEFORE_PEM + (MASKED_LINE + "\n") * 4 + AFTER_PEM

    def test_a_text_that_shows_no_end_line_is_masked_to_its_last_line(self):
        """The END line is past what the browser read: fail closed."""
        mask = source_snippet_masker(self._begin_line_finding_alone())

        shown = mask("keys.py", 10, "".join([BEFORE_PEM] + PEM_LINES[:3]))

        assert shown == BEFORE_PEM + (MASKED_LINE + "\n") * 3

    def test_a_reported_line_that_does_not_begin_a_block_is_masked_alone(self):
        """Control: a finding on a body line, with the BEGIN line above it in the
        text, covers that line and no more."""
        finding = _result(
            "CUSTOM-2",
            "keys.py",
            12,
            "Custom finding",
            "detect-secrets",
            tags=["secret"],
        )
        mask = source_snippet_masker(_results(finding))

        shown = mask("keys.py", 10, "".join([BEFORE_PEM] + PEM_LINES + [AFTER_PEM]))

        assert shown == (
            BEFORE_PEM
            + PEM_LINES[0]
            + MASKED_LINE
            + "\n"
            + PEM_LINES[2]
            + PEM_LINES[3]
            + AFTER_PEM
        )

    def test_the_browser_reads_the_results_and_changes_nothing(self):
        model = self._begin_line_finding_alone()
        before = model.model_dump_json()

        source_snippet_masker(model)("keys.py", 10, "".join(PEM_LINES))

        assert model.model_dump_json() == before

    def test_a_producers_end_line_past_the_end_line_survives_a_reload(self):
        """The scanner reports the key as lines 11-20 and an END line shows on
        line 14. The record kept on the finding says 14, and the larger of that
        and the scanner's own end wins after a reload too: lines 15 to 20 stay
        masked."""
        key = _key_finding()
        key["locations"][0]["physicalLocation"]["region"]["endLine"] = 20
        model = _results(
            key,
            _neighbor("keys.py", 10, 10, [BEFORE_PEM] + PEM_LINES + [AFTER_PEM]),
            _neighbor("keys.py", 40, 40, [FAR_LINE]),
        )
        mask_secrets_in_results(model)
        loaded = AshAggregatedResults.model_validate_json(model.model_dump_json())

        mask_secrets_in_results(loaded)
        later = [f"l{number} = {number}\n" for number in range(15, 23)]
        shown = source_snippet_masker(loaded)(
            "keys.py", 10, "".join([BEFORE_PEM] + PEM_LINES + later)
        )

        assert shown == BEFORE_PEM + (MASKED_LINE + "\n") * 10 + "".join(later[6:])
        recorded = loaded.sarif.runs[0].results[0].properties.model_dump()
        assert recorded["masked_block_end"] == [14]

    def test_a_record_earlier_than_a_visible_end_line_does_not_cut_the_range(self):
        """A stale or foreign ``masked_block_end`` of 12 on the finding, while a
        snippet shows the END line on 14: the END line that can be read wins, and
        the finding then records it."""
        key = _key_finding()
        key["properties"]["masked_block_end"] = [12]
        model = _results(
            key,
            _neighbor("keys.py", 10, 10, [BEFORE_PEM] + PEM_LINES + [AFTER_PEM]),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == BEFORE_PEM + (MASKED_LINE + "\n") * 4 + AFTER_PEM
        recorded = model.sarif.runs[0].results[0].properties.model_dump()
        assert recorded["masked_block_end"] == [14]


class TestTheEndLineOfAnotherFileOfTheSameName:
    def test_an_earlier_end_line_in_another_file_does_not_cut_the_range(self):
        """``lib/keys.py`` and ``keys.py`` match as one file; the END line at 12
        in ``keys.py`` is not the END line of the block in ``lib/keys.py``."""
        model = _results(
            _key_finding(uri="lib/keys.py"),
            _neighbor("lib/keys.py", 10, 10, [BEFORE_PEM] + PEM_LINES + [AFTER_PEM]),
            _neighbor("keys.py", 12, 12, [PEM_LINES[3]]),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == BEFORE_PEM + (MASKED_LINE + "\n") * 4 + AFTER_PEM

    def test_the_block_is_still_masked_through_its_own_end_line(self):
        """Control: one file, one END line."""
        model = _results(
            _key_finding(),
            _neighbor("keys.py", 10, 10, [BEFORE_PEM] + PEM_LINES + [AFTER_PEM]),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == BEFORE_PEM + (MASKED_LINE + "\n") * 4 + AFTER_PEM


RESOURCE_LINES = [
    "  Database:\n",
    "    Type: AWS::RDS::DBInstance\n",
    "    Properties:\n",
    "      MasterUserPassword: placeholder-example-value\n",
]
#: What the resource block reads as once masked: a masked line keeps its indent.
RESOURCE_MASKED = "".join(
    line[: len(line) - len(line.lstrip())] + MASKED_LINE + "\n"
    for line in RESOURCE_LINES
)


class TestAResourceLevelCredentialFinding:
    """A rule about a credential written into a resource reports the resource's
    first line; the property holding the value is somewhere after it, so the
    range runs to the end of the file unless the producer gives a real end line."""

    def _credential_finding(self, end):
        return _result(
            "AwsSolutions-RDS-1",
            "template.yaml",
            3,
            "The database password must not be a plaintext string.",
            "cdk-nag",
            end=end,
        )

    def test_an_end_line_equal_to_the_start_line_does_not_bound_the_range(self):
        """cdk-nag's wrapper writes endLine == startLine. The range runs to the end
        of the file, not to the end of the resource block or of the snippet: a
        line far after the resource is masked too."""
        model = _results(
            self._credential_finding(end=3),
            _neighbor("template.yaml", 6, 3, RESOURCE_LINES),
            _neighbor("template.yaml", 40, 40, [FAR_LINE]),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == RESOURCE_MASKED
        assert _context(model, 2) == MASKED_LINE + "\n"

    @pytest.mark.parametrize("column", [None, 1])
    @pytest.mark.parametrize(
        "message",
        [
            "The database password must not be a plaintext string.",
            "Resource 'Database': the password must not be a plaintext string.",
        ],
        ids=["plain", "quotes-the-resource-name"],
    )
    def test_the_range_runs_to_the_end_whatever_else_the_finding_says(
        self, message, column
    ):
        """Where the range heuristics meet. A quoted value limits a finding to its
        own line, but only the value a hard-coded-password rule quotes after its
        label does: the logical ID a cfn-nag style message names is no value. A
        start column of 1 is a placeholder, not a span. Either one winning
        would shrink the range to line 3 and show MasterUserPassword."""
        finding = _result(
            "AwsSolutions-RDS-1",
            "template.yaml",
            3,
            message,
            "cdk-nag",
            end=3,
            column=column,
        )
        model = _results(
            finding,
            _neighbor("template.yaml", 6, 3, RESOURCE_LINES),
            _neighbor("template.yaml", 40, 40, [FAR_LINE]),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == RESOURCE_MASKED
        assert _context(model, 2) == MASKED_LINE + "\n"

    def test_a_producers_real_end_line_bounds_the_range(self):
        """Control: checkov reports the resource block's own last line."""
        model = _results(
            self._credential_finding(end=6),
            _neighbor("template.yaml", 8, 3, RESOURCE_LINES + ["Outputs: {}\n"]),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == RESOURCE_MASKED + "Outputs: {}\n"

    @pytest.mark.parametrize(
        "snippet_break", ["\f", "\v", "\x85", chr(0x2028), chr(0x2029)]
    )
    def test_a_snippet_with_an_uncounted_break_does_not_bound_the_range(
        self, snippet_break
    ):
        """A region snippet holding a break only some scanners count cannot be
        placed line by line. Counting its lines as the file's lines ended the
        range at the second line and left the properties after it unmasked; the
        range runs to the end of the file as it does with no snippet at all."""
        finding = self._credential_finding(end=3)
        region = finding["locations"][0]["physicalLocation"]["region"]
        region["snippet"] = {"text": "Database:" + snippet_break + "Type"}
        model = _results(finding, _neighbor("template.yaml", 6, 3, RESOURCE_LINES))

        mask_secrets_in_results(model)

        assert _context(model, 1) == RESOURCE_MASKED

    def test_a_snippet_with_an_uncounted_break_still_covers_its_own_lines(self):
        """Control: a finding that reports a column is not a resource, so the
        lines its snippet spans are its whole range and the lines after them
        stay as they were."""
        finding = _result(
            "AwsSolutions-RDS-1",
            "template.yaml",
            3,
            "The database password must not be a plaintext string.",
            "cdk-nag",
            end=3,
            column=10,
        )
        region = finding["locations"][0]["physicalLocation"]["region"]
        region["snippet"] = {"text": "Database:\fType"}
        model = _results(finding, _neighbor("template.yaml", 6, 3, RESOURCE_LINES))

        mask_secrets_in_results(model)

        masked = _context(model, 1)
        assert masked.startswith("  " + MASKED_LINE + "\n")
        assert masked.endswith("".join(RESOURCE_LINES[2:]))

    def test_a_finding_that_quotes_its_value_is_bounded_to_its_own_line(self):
        """bandit's hardcoded-password rule names a credential in code too, but
        it quotes the value on the line it reports, so the line itself is the
        whole range; the lines after it are not the finding's."""
        quoted = _result(
            "B105",
            "app.py",
            3,
            "Possible hardcoded password: 'placeholder-example-value'",
            "bandit",
            end=3,
        )
        model = _results(
            quoted,
            _neighbor(
                "app.py",
                5,
                3,
                [
                    "password = 'placeholder-example-value'\n",
                    "x = 1\n",
                    "y = 2\n",
                    "run()\n",
                ],
            ),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == MASKED_LINE + "\nx = 1\ny = 2\nrun()\n"
        assert _region(model, 0).endLine == 3

    def test_a_finding_that_reports_a_column_is_bounded_to_its_own_line(self):
        """semgrep's secret rules say a credential is hard-coded without quoting
        it, and report the column their match starts at: a span of the line, not
        a resource whose properties follow."""
        columned = _result(
            "generic.secrets.security.detected-generic-secret",
            "app.py",
            3,
            "A secret is hard-coded in the application. Secrets stored in source "
            "code, such as credentials, should be kept out of it.",
            "semgrep",
            end=3,
            column=10,
        )
        model = _results(
            columned,
            _neighbor(
                "app.py",
                5,
                3,
                [
                    "token = placeholder_example_value()\n",
                    "x = 1\n",
                    "y = 2\n",
                    "run()\n",
                ],
            ),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == MASKED_LINE + "\nx = 1\ny = 2\nrun()\n"
        assert _region(model, 0).endLine == 3


#: A longer PEM block as a second file holds it, lines 11-16.
LONG_PEM_LINES = [
    "-----BEGIN RSA PRIVATE " + "KEY-----\n",
    _derived("ranges-long-body-1", 40) + "\n",
    _derived("ranges-long-body-2", 40) + "\n",
    _derived("ranges-long-body-3", 40) + "\n",
    _derived("ranges-long-body-4", 40) + "\n",
    "-----END RSA PRIVATE " + "KEY-----\n",
]


class TestAKeyFindingWithTwoLocations:
    """One finding reports its key in two files whose blocks end on different lines.

    The range a masking records on the finding is one entry per primary location,
    in the order of its locations: one record per finding kept only the last
    location's end (a later masking cut the other file's block short), and the
    widest end per finding made a later masking hide more lines than the first.
    """

    def _model(self):
        key = _key_finding()
        key["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "long.py"},
                    "region": {"startLine": 11, "endLine": 11},
                }
            }
        ] + key["locations"]
        return _results(
            key,
            _neighbor("long.py", 10, 10, [BEFORE_PEM] + LONG_PEM_LINES + [AFTER_PEM]),
            _neighbor("keys.py", 10, 10, [BEFORE_PEM] + PEM_LINES + [AFTER_PEM]),
        )

    def test_both_blocks_are_masked(self):
        model = self._model()

        mask_secrets_in_results(model)

        assert _context(model, 1) == BEFORE_PEM + (MASKED_LINE + "\n") * 6 + AFTER_PEM
        assert _context(model, 2) == BEFORE_PEM + (MASKED_LINE + "\n") * 4 + AFTER_PEM

    def test_each_locations_end_line_is_recorded_on_the_finding(self):
        """The longer block, reported first, ends at 16; the shorter, reported
        second, at 14. The record holds both, in the locations' order."""
        model = self._model()

        mask_secrets_in_results(model)

        recorded = model.sarif.runs[0].results[0].properties.model_dump()
        assert recorded["masked_block_end"] == [16, 14]
        assert "masked_to_end_of_file" not in recorded

    def test_a_second_masking_masks_the_same_lines_as_the_first(self):
        """Every reload masks again; each location takes its own recorded end, so
        the shorter file's lines after its block stay as they were."""
        model = self._model()
        mask_secrets_in_results(model)
        once = (_context(model, 1), _context(model, 2))

        mask_secrets_in_results(model)

        assert once == (
            BEFORE_PEM + (MASKED_LINE + "\n") * 6 + AFTER_PEM,
            BEFORE_PEM + (MASKED_LINE + "\n") * 4 + AFTER_PEM,
        )
        assert (_context(model, 1), _context(model, 2)) == once


class TestAPlaceholderColumn:
    """A start column of 1 with no end column names no span of the line.

    npm-audit places every finding at line 1, column 1 of a package file; that
    column bounded a resource-level finding to its first line.
    """

    @pytest.mark.parametrize(
        ("region", "expected"),
        [
            (Region(startLine=1, startColumn=1), False),
            (Region(startLine=1), False),
            (Region(startLine=1, startColumn=1, endColumn=4), True),
            (Region(startLine=1, startColumn=3), True),
            (Region(startLine=1, endColumn=4), True),
        ],
    )
    def test_whether_a_region_reports_a_column(self, region, expected):
        assert _has_columns(region) is expected

    def test_a_resource_finding_at_column_one_runs_to_the_end_of_the_file(self):
        """An infrastructure finding describes a hard-coded credential without
        quoting it and reports column 1 with no end column: the later lines of
        its file are masked, as for a finding that reports no column."""
        placed_at_column_one = _result(
            "AwsSolutions-X1",
            "infra/stack.json",
            1,
            "Hard-coded credentials in configuration",
            "cdk-nag",
            end=1,
            column=1,
        )
        model = _results(
            placed_at_column_one,
            _neighbor("infra/stack.json", 40, 40, [FAR_LINE]),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == MASKED_LINE + "\n"

    def test_a_dependency_advisory_at_column_one_masks_nothing(self):
        """A dependency scanner's advisory describes the dependency's weakness,
        not a value in the manifest it is placed at: it is no secret finding, so
        neither the manifest's first line nor its later lines are masked."""
        advisory = _result(
            "ADVISORY-1",
            "pkg/package.json",
            1,
            "Hard-coded credentials in configuration",
            "npm-audit",
            end=1,
            column=1,
        )
        model = _results(
            advisory,
            _neighbor("pkg/package.json", 1, 1, ["x = 1\n"]),
            _neighbor("pkg/package.json", 40, 40, [FAR_LINE]),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == "x = 1\n"
        assert _context(model, 2) == FAR_LINE


def _results_with_rules(rules, *results):
    """A run whose tool lists ``rules``, as a scanner that writes rule metadata does."""
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "test", "rules": rules}},
                    "results": list(results),
                }
            ],
        }
    )
    return model


class TestARuleDescribedByAnAdvisoryTitle:
    """npm-audit writes one rule per advisory, described by the advisory's title.

    The title can name a hard-coded credential of the dependency; the finding's
    own message does not, so the rule's description is the only route in.
    """

    TITLE_RULE = {
        "id": "ADVISORY-1",
        "shortDescription": {"text": "Hardcoded credentials in configuration"},
    }

    def _advisory(self, scanner):
        return _result(
            "ADVISORY-1",
            "pkg/package.json",
            1,
            "Vulnerability in left-pad",
            scanner,
            end=1,
            column=1,
        )

    def test_a_dependency_advisory_is_not_a_secret_finding_by_its_rules_title(self):
        model = _results_with_rules(
            [self.TITLE_RULE],
            self._advisory("npm-audit"),
            _neighbor("pkg/package.json", 1, 1, ["x = 1\n"]),
            _neighbor("pkg/package.json", 40, 40, [FAR_LINE]),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == "x = 1\n"
        assert _context(model, 2) == FAR_LINE

    def test_an_infrastructure_finding_is_still_a_secret_finding_by_its_rules_title(
        self,
    ):
        model = _results_with_rules(
            [self.TITLE_RULE],
            self._advisory("cdk-nag"),
            _neighbor("pkg/package.json", 40, 40, [FAR_LINE]),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == MASKED_LINE + "\n"

    def test_a_dependency_scanners_secret_tagged_rule_is_still_a_secret_rule(self):
        """trivy is a dependency scanner whose secret rules carry the ``secret``
        tag; a title that also says hard-coded credential does not drop them."""
        tagged = dict(self.TITLE_RULE, properties={"tags": ["secret"]})
        model = _results_with_rules(
            [tagged],
            self._advisory("trivy"),
            _neighbor("pkg/package.json", 1, 1, ["x = 1\n"]),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == MASKED_LINE + "\n"
