# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``mask_secrets_in_results``: masking by location and by value, result by result.

The end-to-end tests (``tests/unit/reporters/test_secret_masking_across_reports.py``)
run a whole scan. These pin the rules on small hand-built reports, including the
cases a scan does not reach: a value the scanner already masked in its message,
values too short to mask everywhere, base64 snippets, and running the masking
twice.

The values are derived at import time, so this source holds no string a secret
scanner would report.
"""

import hashlib
import string

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    MASKED_LINE,
    SecretValueShape,
    _mask_secret_value,
    exposed_secret_values,
    mask_secrets_in_results,
)


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


VALUE = _derived("masking-unit-value", 14)
SHORT = _derived("masking-unit-short", 3)
NAME = "pass" + "word"
HARDCODED = "Possible hardcoded " + NAME + ": "

ASSIGN_LINE = f'{NAME} = "{VALUE}"\n'
REUSE_LINE = f'run("login --token {VALUE}")\n'
OTHER_LINE = "import os\n"


def _result(rule_id, uri, line, message, snippet=None, context=None, scanner=None):
    region = {"startLine": line, "endLine": line}
    if snippet is not None:
        region["snippet"] = {"text": snippet}
    physical = {"artifactLocation": {"uri": uri}, "region": region}
    if context is not None:
        start, text = context
        physical["contextRegion"] = {"startLine": start, "snippet": {"text": text}}
    result = {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": message},
        "locations": [{"physicalLocation": physical}],
    }
    if scanner is not None:
        result["properties"] = {"scanner_name": scanner, "tags": [scanner]}
    return result


def _results(*results):
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": list(results)}],
        }
    )
    return model


def _region_text(result, region="region"):
    physical = result.locations[0].physicalLocation.root
    return getattr(physical, region).snippet.text


def _message(result):
    return result.message.root.text


class TestMaskingByLocation:
    def test_a_line_a_secret_finding_reports_is_masked_in_every_result(self):
        model = _results(
            _result(
                "SECRET-KEYWORD",
                "app.py",
                2,
                "Secret of type 'Keyword' detected",
                scanner="detect-secrets",
            ),
            _result(
                "B404",
                "app.py",
                1,
                "import",
                snippet=OTHER_LINE,
                context=(1, OTHER_LINE + ASSIGN_LINE),
                scanner="bandit",
            ),
        )

        mask_secrets_in_results(model)

        b404 = model.sarif.runs[0].results[1]
        assert _region_text(b404) == OTHER_LINE
        assert _region_text(b404, "contextRegion") == OTHER_LINE + MASKED_LINE + "\n"

    def test_a_line_in_another_file_is_left_alone(self):
        model = _results(
            _result(
                "SECRET-KEYWORD",
                "app.py",
                2,
                "Secret of type 'Keyword' detected",
                scanner="detect-secrets",
            ),
            _result(
                "B404",
                "lib.py",
                2,
                "import",
                snippet=ASSIGN_LINE,
                scanner="bandit",
            ),
        )

        mask_secrets_in_results(model)

        assert _region_text(model.sarif.runs[0].results[1]) == ASSIGN_LINE

    def test_a_secret_findings_own_snippets_are_masked_whole(self):
        """No line arithmetic for the secret finding's own excerpt.

        ferret-scan 2.5.3 writes the matched line as ``contextRegion.startLine``
        but starts the snippet one line earlier, so the matched line was numbered
        one too high and kept; a value too short to mask by value stayed in it.
        """
        short = SHORT + "d"
        model = _results(
            _result(
                "PERSON_NAME",
                "people.yaml",
                2,
                "Person name detected (confidence: 40.0% - LOW). Matched text: '"
                + short
                + "'",
                snippet=f"owner: {short}\n",
                context=(2, f"card: \nowner: {short}\n"),
                scanner="ferret-scan",
            ),
        )
        result = model.sarif.runs[0].results[0]
        result.relatedLocations = [result.locations[0].model_copy(deep=True)]
        related = result.relatedLocations[0].physicalLocation.root
        related.region.startLine = 7
        related.region.snippet.text = f"backup_owner: {short}\n"

        mask_secrets_in_results(model)

        assert _region_text(result) == MASKED_LINE + "\n"
        assert _region_text(result, "contextRegion") == (MASKED_LINE + "\n") * 2
        assert related.region.snippet.text == MASKED_LINE + "\n"

    def test_a_binary_snippet_at_a_reported_line_is_dropped(self):
        model = _results(
            _result(
                "SECRET-KEYWORD",
                "app.bin",
                1,
                "Secret of type 'Keyword' detected",
                scanner="detect-secrets",
            ),
        )
        region = (
            model.sarif.runs[0].results[0].locations[0].physicalLocation.root.region
        )
        from automated_security_helper.schemas.sarif_schema_model import (
            ArtifactContent,
        )

        region.snippet = ArtifactContent(binary="AAAA")

        mask_secrets_in_results(model)

        assert region.snippet.binary is None


#: Characters ``str.splitlines`` breaks at besides ``\n``, ``\r\n`` and ``\r``.
#: Scanners number lines by those three only, so a snippet holding one of these
#: cannot be placed line by line.
OTHER_LINE_SEPARATORS = {
    "vertical-tab": "\v",
    "form-feed": "\f",
    "file-separator": "\x1c",
    "group-separator": "\x1d",
    "record-separator": "\x1e",
    "next-line": "\x85",
    "line-separator": chr(0x2028),
    "paragraph-separator": chr(0x2029),
}


def _secret_on_line_3():
    return _result(
        "SECRET-KEYWORD",
        "app.py",
        3,
        "Secret of type 'Keyword' detected",
        scanner="detect-secrets",
    )


def _b105(value, uri="app.py", line=1, quote="'"):
    return _result(
        "B105",
        uri,
        line,
        HARDCODED + quote + value + quote,
        snippet=f"{NAME} = {quote}{value}{quote}\n",
        scanner="bandit",
    )


def _reuse(text, uri="deploy.py", line=5):
    return _result("B602", uri, line, "subprocess call", snippet=text, scanner="bandit")


class TestOnlyValuesThatLookLikeSecretsAreMaskedElsewhere:
    """A hard-coded password check quotes ordinary words as often as credentials.

    Masking ``password`` wherever it occurred rewrote rule descriptions, tags,
    other findings' messages (and so their IDs) and SBOM entries. A value is masked
    beyond its own finding only when it looks like a secret: at least eight
    characters, not letters alone, not a template placeholder, and not
    repetitive. Every value is still masked in its own finding.
    """

    @pytest.mark.parametrize(
        "value",
        [
            NAME,
            "secret",
            "access_token",
            "Enter your " + NAME,
            "${DB_" + NAME.upper() + "}",
            "{" + NAME + "}",
            "%(" + NAME + ")s",
            "aaaaaaaa1",
            _derived("masking-unit-seven", 7),
        ],
        ids=[
            "dictionary-word",
            "short-word",
            "identifier",
            "prose",
            "env-placeholder",
            "format-placeholder",
            "percent-placeholder",
            "repetitive",
            "seven-characters",
        ],
    )
    def test_a_value_that_does_not_look_like_a_secret_is_masked_only_in_its_finding(
        self, value
    ):
        reuse = f'log("{value}")\n'
        model = _results(_b105(value), _reuse(reuse))

        mask_secrets_in_results(model)

        assert _message(model.sarif.runs[0].results[0]) == (
            HARDCODED + "'" + _mask_secret_value(value) + "'"
        )
        assert _region_text(model.sarif.runs[0].results[1]) == reuse
        assert model.secret_value_shapes == []

    @pytest.mark.parametrize(
        "value",
        [
            VALUE,
            _derived("masking-unit-eight", 8),
            "Tr0ub4dor&3",
            "jane.doe@example.com",
        ],
        ids=["derived", "eight-characters", "mixed", "address"],
    )
    def test_a_value_that_looks_like_a_secret_is_masked_where_it_is_reused(self, value):
        model = _results(_b105(value), _reuse(f'log("{value}")\n'))

        mask_secrets_in_results(model)

        assert value not in _region_text(model.sarif.runs[0].results[1])

    def test_findings_that_hold_an_ordinary_word_keep_their_ids(self):
        before = _results(
            _b105(NAME),
            _reuse("send(" + NAME + ")\n"),
            _result(
                "python.lang.security.audit.logging",
                "lib/y.py",
                2,
                f"Avoid logging the user {NAME} in plain text",
                scanner="semgrep",
            ),
        )
        untouched = [
            vuln.id
            for vuln in before.to_flat_vulnerabilities()
            if vuln.rule_id != "B105"
        ]
        after = _results(
            _b105(NAME),
            _reuse("send(" + NAME + ")\n"),
            _result(
                "python.lang.security.audit.logging",
                "lib/y.py",
                2,
                f"Avoid logging the user {NAME} in plain text",
                scanner="semgrep",
            ),
        )

        mask_secrets_in_results(after)

        assert [
            vuln.id
            for vuln in after.to_flat_vulnerabilities()
            if vuln.rule_id != "B105"
        ] == untouched


class TestValuesFromTheMatch:
    """A secret finding that quotes no value gives the one its own region matched.

    semgrep's and opengrep's ``generic.secrets.*`` rules report the match by
    columns on the matched line: the key itself, or an assignment holding it. The
    value is read from there, so its reuse on a line no secret finding reports is
    masked too.
    """

    def _model(self):
        from tests.utils.secret_bearing_scan import SECRETS, opengrep_secret_sarif

        sarif = opengrep_secret_sarif()
        sarif["runs"][0]["results"].extend(
            [
                _reuse(f'run("--id {SECRETS.key_id}")\n', uri="src/deploy.py", line=3),
                _reuse(
                    f'run("--key {SECRETS.long_key}")\n', uri="src/deploy.py", line=4
                ),
            ]
        )
        model = AshAggregatedResults()
        model.sarif = SarifReport.model_validate(sarif)
        return model, SECRETS

    def test_a_matched_key_is_masked_where_it_is_reused(self):
        model, secrets = self._model()

        mask_secrets_in_results(model)

        reuses = model.sarif.runs[0].results[2:]
        assert secrets.key_id not in _region_text(reuses[0])
        assert _region_text(reuses[0]).startswith('run("--id ')

    def test_a_key_inside_a_matched_assignment_is_masked_where_it_is_reused(self):
        """The match spans the whole assignment; its string literal is the value."""
        model, secrets = self._model()

        mask_secrets_in_results(model)

        reuses = model.sarif.runs[0].results[2:]
        assert secrets.long_key not in _region_text(reuses[1])
        assert _region_text(reuses[1]).startswith('run("--key ')


class TestValuesAreMaskedInWhatFindingsReport:
    """Masking by value reaches the text a finding reports, not names and metadata.

    Rule metadata, tags and identifiers name things; rewriting them made a
    finding tagged ``secret`` stop being a secret finding on the next pass.
    """

    def _model(self, value):
        import json

        dumped = json.loads(
            _results(
                _b105(value),
                _result(
                    "CUSTOM-1",
                    "lib/x.py",
                    9,
                    f"Third-party finding near {value}",
                    snippet=f"call({value})\n",
                ),
            ).model_dump_json(by_alias=True)
        )
        run = dumped["sarif"]["runs"][0]
        run["tool"]["driver"]["rules"] = [
            {
                "id": "CUSTOM-1",
                "shortDescription": {"text": f"Example: {value}"},
                "properties": {"tags": ["secret", value]},
            }
        ]
        run["results"][1]["properties"] = {"tags": ["secret", value]}
        model = AshAggregatedResults.model_validate(dumped)
        model.additional_reports = {
            "syft": {"components": [{"name": value, "tags": [value]}]}
        }
        mask_secrets_in_results(model)
        return model

    def test_rule_metadata_and_tags_are_left_alone(self):
        model = self._model(VALUE)

        run = model.sarif.runs[0]
        rule = run.tool.driver.rules[0]
        assert rule.shortDescription.text == f"Example: {VALUE}"
        assert list(rule.properties.tags) == ["secret", VALUE]
        assert list(run.results[1].properties.tags) == ["secret", VALUE]
        assert model.additional_reports["syft"]["components"][0]["tags"] == [VALUE]

    def test_what_a_finding_reports_is_masked(self):
        """Control: the same value in a message, a snippet and a report field."""
        model = self._model(VALUE)

        result = model.sarif.runs[0].results[1]
        assert VALUE not in _message(result)
        assert VALUE not in _region_text(result)
        assert VALUE not in model.additional_reports["syft"]["components"][0]["name"]

    def test_a_finding_tagged_secret_is_still_one_after_masking(self):
        from automated_security_helper.utils.secret_masking import is_secret_finding

        # B105 quoting the word its neighbor is tagged with.
        model = self._model("secret")

        assert list(model.sarif.runs[0].results[1].properties.tags)[0] == "secret"
        assert is_secret_finding(model.sarif.runs[0].results[1])


class TestTokenBoundaries:
    """A value is masked as a whole token only."""

    @pytest.mark.parametrize(
        "text", ["x" + VALUE, VALUE + "y"], ids=["word-before", "word-after"]
    )
    def test_a_value_joined_to_a_word_on_one_side_is_left_alone(self, text):
        reuse = f'run("{text}")\n'
        model = _results(_b105(VALUE), _reuse(reuse))

        mask_secrets_in_results(model)

        assert _region_text(model.sarif.runs[0].results[1]) == reuse

    def test_another_literal_on_the_secret_line_is_not_a_value(self):
        """Only the literal whose mask the message shows is read back."""
        other = _derived("masking-unit-other-literal", 14)
        line = f'connect(user="{other}", {NAME}="{VALUE}")\n'
        model = _results(
            _result(
                "B106",
                "app.py",
                1,
                HARDCODED + "'" + _mask_secret_value(VALUE) + "'",
                snippet=line,
                scanner="bandit",
            ),
            _reuse(f'run("{other}")\n'),
        )

        mask_secrets_in_results(model)

        assert _region_text(model.sarif.runs[0].results[1]) == f'run("{other}")\n'

    def test_a_masked_line_keeps_its_indentation(self):
        model = _results(
            _result(
                "SECRET-KEYWORD",
                "app.py",
                2,
                "Secret of type 'Keyword' detected",
                scanner="detect-secrets",
            ),
            _result(
                "B404",
                "app.py",
                1,
                "import",
                context=(1, OTHER_LINE + "    " + ASSIGN_LINE),
                scanner="bandit",
            ),
        )

        mask_secrets_in_results(model)

        assert _region_text(model.sarif.runs[0].results[1], "contextRegion") == (
            OTHER_LINE + "    " + MASKED_LINE + "\n"
        )

    def test_a_binary_snippet_away_from_the_secret_line_is_kept(self):
        from automated_security_helper.schemas.sarif_schema_model import (
            ArtifactContent,
        )

        model = _results(
            _result(
                "SECRET-KEYWORD",
                "app.bin",
                2,
                "Secret of type 'Keyword' detected",
                scanner="detect-secrets",
            ),
            _result("B999", "app.bin", 5, "other", scanner="bandit"),
        )
        region = (
            model.sarif.runs[0].results[1].locations[0].physicalLocation.root.region
        )
        region.snippet = ArtifactContent(binary="AAAA")

        mask_secrets_in_results(model)

        assert region.snippet.binary == "AAAA"


class TestLineSeparators:
    """Snippets are split into lines the way scanners count them.

    A neighbor's context over lines 1-3 holds the secret on line 3. Split with
    ``str.splitlines``, a form feed or a Unicode line separator on line 2 made it
    "line 4", so line 4 was masked and the secret line was written in clear.
    """

    @pytest.mark.parametrize(
        "separator",
        list(OTHER_LINE_SEPARATORS.values()),
        ids=list(OTHER_LINE_SEPARATORS),
    )
    def test_a_snippet_holding_another_separator_is_masked_whole(self, separator):
        context = OTHER_LINE + "# section " + separator + "\n" + ASSIGN_LINE
        model = _results(
            _secret_on_line_3(),
            _result(
                "B404",
                "app.py",
                1,
                "import",
                snippet=OTHER_LINE,
                context=(1, context),
                scanner="bandit",
            ),
        )

        mask_secrets_in_results(model)

        masked = _region_text(model.sarif.runs[0].results[1], "contextRegion")
        assert VALUE not in masked
        assert masked == (MASKED_LINE + "\n") * 3

    def test_a_snippet_with_a_lone_carriage_return_is_masked_whole(self):
        """Scanners disagree on a lone ``\\r``, so its line numbers are not trusted."""
        context = OTHER_LINE + "# section\r" + ASSIGN_LINE
        model = _results(
            _secret_on_line_3(),
            _result(
                "B404",
                "app.py",
                1,
                "import",
                snippet=OTHER_LINE,
                context=(1, context),
                scanner="bandit",
            ),
        )

        mask_secrets_in_results(model)

        masked = _region_text(model.sarif.runs[0].results[1], "contextRegion")
        assert VALUE not in masked
        assert OTHER_LINE.strip() not in masked

    def test_windows_line_endings_are_placed_line_by_line(self):
        """Control: ``\\r\\n`` is one line break, and only the secret line is masked."""
        context = "import os\r\n# section\r\n" + ASSIGN_LINE.replace("\n", "\r\n")
        model = _results(
            _secret_on_line_3(),
            _result(
                "B404",
                "app.py",
                1,
                "import",
                snippet="import os\r\n",
                context=(1, context),
                scanner="bandit",
            ),
        )

        mask_secrets_in_results(model)

        masked = _region_text(model.sarif.runs[0].results[1], "contextRegion")
        assert masked == "import os\r\n# section\r\n" + MASKED_LINE + "\r\n"

    @pytest.mark.parametrize(
        "separator",
        list(OTHER_LINE_SEPARATORS.values()),
        ids=list(OTHER_LINE_SEPARATORS),
    )
    def test_a_separator_in_another_file_changes_nothing(self, separator):
        """Only snippets of a file with a secret finding are masked whole."""
        context = OTHER_LINE + "# section " + separator + "\n" + REUSE_LINE
        model = _results(
            _secret_on_line_3(),
            _result(
                "B602",
                "deploy.py",
                1,
                "subprocess call",
                snippet=OTHER_LINE,
                context=(1, context),
                scanner="bandit",
            ),
        )

        mask_secrets_in_results(model)

        assert _region_text(model.sarif.runs[0].results[1], "contextRegion") == context

    def test_a_value_is_recovered_from_a_context_holding_a_form_feed(self):
        """The B105's own line is found by the scanners' line count too.

        Its message holds the value already masked, so the value is read back from
        the finding's own line in its context; with ``splitlines`` the form feed
        put a different line there and the value's reuse elsewhere stayed in clear.
        """
        model = _results(
            _result(
                "B105",
                "app.py",
                3,
                HARDCODED + "'" + _mask_secret_value(VALUE) + "'",
                context=(1, OTHER_LINE + "# section \f\n" + ASSIGN_LINE),
                scanner="bandit",
            ),
            _result(
                "B602",
                "deploy.py",
                5,
                "subprocess call",
                snippet=REUSE_LINE,
                scanner="bandit",
            ),
        )

        mask_secrets_in_results(model)

        assert VALUE not in _region_text(model.sarif.runs[0].results[1])


class TestMaskingByValue:
    def test_a_value_a_message_quotes_is_masked_where_it_is_reused(self):
        model = _results(
            _result(
                "B105",
                "app.py",
                1,
                HARDCODED + "'" + VALUE + "'",
                snippet=ASSIGN_LINE,
                scanner="bandit",
            ),
            _result(
                "B602",
                "deploy.py",
                5,
                "subprocess call",
                snippet=REUSE_LINE,
                scanner="bandit",
            ),
        )

        mask_secrets_in_results(model)

        b602 = model.sarif.runs[0].results[1]
        assert VALUE not in _region_text(b602)
        assert _region_text(b602).startswith('run("login --token ')
        assert VALUE not in _message(model.sarif.runs[0].results[0])

    def test_a_value_the_scanner_already_masked_is_recovered_from_its_own_line(self):
        """Bandit masks its message before the results are merged.

        The value is then read back from the finding's own snippet, the string
        literal of the masked value's length and visible first and last
        characters, so its reuse on another line is masked too.
        """
        model = _results(
            _result(
                "B105",
                "app.py",
                1,
                HARDCODED + "'" + _mask_secret_value(VALUE) + "'",
                snippet=ASSIGN_LINE,
                scanner="bandit",
            ),
            _result(
                "B602",
                "deploy.py",
                5,
                "subprocess call",
                snippet=REUSE_LINE,
                scanner="bandit",
            ),
        )

        mask_secrets_in_results(model)

        assert VALUE not in _region_text(model.sarif.runs[0].results[1])

    def test_a_value_recovered_from_the_context_region_only(self):
        """A finding whose region carries no snippet but whose context does."""
        model = _results(
            _result(
                "B105",
                "app.py",
                2,
                HARDCODED + "'" + _mask_secret_value(VALUE) + "'",
                context=(1, OTHER_LINE + ASSIGN_LINE),
                scanner="bandit",
            ),
            _result(
                "B602",
                "deploy.py",
                5,
                "subprocess call",
                snippet=REUSE_LINE,
                scanner="bandit",
            ),
        )

        mask_secrets_in_results(model)

        assert VALUE not in _region_text(model.sarif.runs[0].results[1])

    def test_a_raw_value_holding_an_asterisk_is_masked_where_it_is_reused(self):
        """Only the exact shape ``_mask_secret_value`` writes counts as already masked.

        Any ``*`` used to send the value to the recovery from the finding's own
        line, which found nothing for a raw value, so its reuse stayed in clear.
        """
        value = VALUE[:4] + "*" + VALUE[5:]
        model = _results(
            _result("B105", "app.py", 1, HARDCODED + "'" + value + "'"),
            _result(
                "B602", "deploy.py", 5, "subprocess call", snippet=f'run("{value}")\n'
            ),
        )

        mask_secrets_in_results(model)

        assert value not in _region_text(model.sarif.runs[0].results[1])

    def test_a_masked_value_that_cannot_be_recovered_still_records_its_shape(self):
        """With no line to read it back from, the masked form still gives its shape."""
        model = _results(
            _result(
                "B105", "app.py", 1, HARDCODED + "'" + _mask_secret_value(VALUE) + "'"
            )
        )

        mask_secrets_in_results(model)

        assert [
            (shape.prefix, shape.suffix, shape.length)
            for shape in model.secret_value_shapes
        ] == [(VALUE[:2], VALUE[-1], len(VALUE))]

    def test_a_short_value_is_masked_only_in_its_own_finding(self):
        """Replacing a three-character token everywhere would change unrelated code."""
        model = _results(
            _result(
                "B105",
                "app.py",
                1,
                HARDCODED + "'" + SHORT + "'",
                scanner="bandit",
            ),
            _result(
                "B602",
                "deploy.py",
                5,
                "subprocess call",
                snippet=f"run('{SHORT}')\n",
                scanner="bandit",
            ),
        )

        mask_secrets_in_results(model)

        assert SHORT not in _message(model.sarif.runs[0].results[0])
        assert _region_text(model.sarif.runs[0].results[1]) == f"run('{SHORT}')\n"

    def test_a_value_inside_a_longer_token_is_left_alone(self):
        longer = "x" + VALUE + "y"
        model = _results(
            _result(
                "B105", "app.py", 1, HARDCODED + "'" + VALUE + "'", scanner="bandit"
            ),
            _result(
                "B602",
                "deploy.py",
                5,
                "subprocess call",
                snippet=f'run("{longer}")\n',
                scanner="bandit",
            ),
        )

        mask_secrets_in_results(model)

        assert _region_text(model.sarif.runs[0].results[1]) == f'run("{longer}")\n'


#: Masks one B105 whose message bandit already masked and whose own line holds an
#: unterminated quote followed by many backslashes: the string-literal search over
#: that line used to backtrack exponentially in their number.
_BACKSLASH_PROBE = r"""
import sys, time
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    _mask_secret_value, mask_secrets_in_results,
)
value = "abcdefgh"
line = 'pass' + 'word = "' + value + '"  # it' + "'s " + "\\" * int(sys.argv[1]) + "\n"
model = AshAggregatedResults()
model.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": [{
    "tool": {"driver": {"name": "test"}},
    "results": [{
        "ruleId": "B105", "level": "warning",
        "message": {"text": "Possible hardcoded pass" + "word: '"
                    + _mask_secret_value(value) + "'"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "app.py"},
            "region": {"startLine": 1, "endLine": 1, "snippet": {"text": line}},
        }}],
    }],
}]})
started = time.monotonic()
mask_secrets_in_results(model)
print(f"{time.monotonic() - started:.3f}")
"""


#: A value holding the quote character its message quotes it with.
QUOTED_VALUE = "ab'" + _derived("masking-unit-quoted", 10)


class TestQuotesInsideTheValue:
    """The quoted value runs to the last quote of the message, not the first.

    bandit writes the raw value between single quotes, so a value holding a
    quote cut the match short and left its tail in clear.
    """

    @pytest.mark.parametrize(
        "prefix",
        [HARDCODED, "Credit card (confidence: 15.0% - LOW). Matched text: "],
        ids=["bandit", "ferret"],
    )
    def test_the_whole_value_is_masked_in_its_message(self, prefix):
        model = _results(
            _result("B105", "app.py", 1, prefix + "'" + QUOTED_VALUE + "'"),
            _result(
                "B602",
                "deploy.py",
                5,
                "subprocess call",
                snippet=f'run("{QUOTED_VALUE}")\n',
            ),
        )

        mask_secrets_in_results(model)

        message = _message(model.sarif.runs[0].results[0])
        assert message == prefix + "'" + _mask_secret_value(QUOTED_VALUE) + "'"
        assert QUOTED_VALUE[3:] not in message
        # The whole value is the one masked where it is reused.
        assert QUOTED_VALUE[3:] not in _region_text(model.sarif.runs[0].results[1])

    def test_bandits_own_masking_masks_the_whole_value(self):
        from automated_security_helper.utils.secret_masking import mask_secret_in_text

        masked = mask_secret_in_text(HARDCODED + "'" + QUOTED_VALUE + "'", "B105")

        assert masked == HARDCODED + "'" + _mask_secret_value(QUOTED_VALUE) + "'"

    def test_a_double_quoted_value_holding_a_double_quote(self):
        value = 'cd"' + _derived("masking-unit-dquoted", 10)
        model = _results(_result("B105", "app.py", 1, HARDCODED + '"' + value + '"'))

        mask_secrets_in_results(model)

        assert _message(model.sarif.runs[0].results[0]) == (
            HARDCODED + '"' + _mask_secret_value(value) + '"'
        )

    def test_text_after_the_closing_quote_still_masks_the_value(self):
        """Fail closed: a message that does not end at the quote is matched as before."""
        model = _results(
            _result("B105", "app.py", 1, HARDCODED + "'" + VALUE + "' (in a test)")
        )

        mask_secrets_in_results(model)

        assert VALUE not in _message(model.sarif.runs[0].results[0])


class TestPathologicalInput:
    def test_a_line_of_backslashes_is_masked_in_bounded_time(self, tmp_path):
        """One line in a scanned file must not stall the scan or an MCP server.

        Run in a child process so a regression fails at the timeout instead of
        hanging the suite: the search holds the GIL, so a thread could not be
        stopped.
        """
        import subprocess
        import sys

        completed = subprocess.run(
            [sys.executable, "-c", _BACKSLASH_PROBE, "100000"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=tmp_path,
        )

        assert completed.returncode == 0, completed.stderr
        assert float(completed.stdout.strip().splitlines()[-1]) < 5.0


#: A PEM block as a file holds it, lines 11-14; the body is derived, not a key.
PEM_LINES = [
    "-----BEGIN RSA PRIVATE " + "KEY-----\n",
    _derived("pem-body-1", 40) + "\n",
    _derived("pem-body-2", 40) + "\n",
    "-----END RSA PRIVATE " + "KEY-----\n",
]
BEFORE_PEM = "x = 1\n"
AFTER_PEM = "y = 2\n"


def _private_key_finding(line=11, rule_id="SECRET-PRIVATE-KEY", tags=None):
    """detect-secrets reports a private key on its BEGIN line only."""
    result = _result(
        rule_id,
        "keys.py",
        line,
        "Secret of type 'Private Key' detected",
        scanner="detect-secrets",
    )
    if tags is not None:
        result["properties"]["tags"] = tags
        result["message"]["text"] = "Custom finding"
    return result


def _neighbor(line, context_start, context_lines):
    return _result(
        "B108",
        "keys.py",
        line,
        "other",
        context=(context_start, "".join(context_lines)),
        scanner="bandit",
    )


class TestOneFileUnderTwoNames:
    """A secret finding and a neighbor that name one file differently still match."""

    def _masked_context(self, secret_uri, neighbor_uri):
        model = _results(
            _result(
                "SECRET-KEYWORD",
                secret_uri,
                2,
                "Secret of type 'Keyword' detected",
                scanner="detect-secrets",
            ),
            _result(
                "B404",
                neighbor_uri,
                1,
                "import",
                snippet=OTHER_LINE,
                context=(1, OTHER_LINE + ASSIGN_LINE),
                scanner="bandit",
            ),
        )
        mask_secrets_in_results(model)
        return _region_text(model.sarif.runs[0].results[1], "contextRegion")

    @pytest.mark.parametrize(
        "secret_uri, neighbor_uri",
        [
            ("src/app/settings.py", "app/settings.py"),
            ("app/settings.py", "src/app/settings.py"),
            ("my%20app/settings.py", "my app/settings.py"),
            ("file:///work/my%20app/settings.py", "my app/settings.py"),
            ("./app/settings.py", "app\\settings.py"),
        ],
        ids=[
            "neighbor-relative-to-deeper-dir",
            "secret-relative-to-deeper-dir",
            "percent-encoded",
            "file-uri-percent-encoded",
            "dot-slash-and-backslash",
        ],
    )
    def test_the_same_file_is_masked(self, secret_uri, neighbor_uri):
        assert self._masked_context(secret_uri, neighbor_uri) == (
            OTHER_LINE + MASKED_LINE + "\n"
        )

    @pytest.mark.parametrize(
        "secret_uri, neighbor_uri",
        [
            ("app/settings.py", "xapp/settings.py"),
            ("app/settings.py", "other/settings.py"),
        ],
        ids=["name-suffix-not-a-directory", "another-directory"],
    )
    def test_another_file_of_the_same_name_is_left_alone(
        self, secret_uri, neighbor_uri
    ):
        """Control: a suffix match needs a path separator at the join."""
        assert self._masked_context(secret_uri, neighbor_uri) == (
            OTHER_LINE + ASSIGN_LINE
        )


class TestSaveModel:
    def test_results_filled_in_after_the_model_was_built_are_masked_when_saved(
        self, tmp_path
    ):
        """A scan without a report phase builds its model empty and fills it in later.

        ``model_post_init`` then masked nothing, so ``save_model`` is the masking
        that keeps the file clean.
        """
        model = AshAggregatedResults()
        model.sarif = SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "test"}},
                        "results": [
                            _result(
                                "B105",
                                "app.py",
                                1,
                                HARDCODED + "'" + VALUE + "'",
                                snippet=ASSIGN_LINE,
                                scanner="bandit",
                            ),
                            _result(
                                "B602",
                                "deploy.py",
                                5,
                                "subprocess call",
                                snippet=REUSE_LINE,
                                scanner="bandit",
                            ),
                        ],
                    }
                ],
            }
        )
        assert VALUE in model.sarif.model_dump_json()

        model.save_model(tmp_path)

        text = (tmp_path / "ash_aggregated_results.json").read_text(encoding="utf-8")
        assert "B602" in text
        assert VALUE not in text


class TestPrivateKeyBlocks:
    """A key reported on its BEGIN line is masked through its END line in every snippet."""

    def _context(self, model, position):
        return _region_text(model.sarif.runs[0].results[position], "contextRegion")

    def test_a_neighbors_context_over_the_whole_block_is_masked(self):
        model = _results(
            _private_key_finding(),
            _neighbor(10, 10, [BEFORE_PEM] + PEM_LINES + [AFTER_PEM]),
        )

        mask_secrets_in_results(model)

        assert self._context(model, 1) == (
            BEFORE_PEM + (MASKED_LINE + "\n") * 4 + AFTER_PEM
        )

    def test_a_context_over_the_body_alone_is_masked(self):
        """The END line is known from another snippet; this one holds only body lines."""
        model = _results(
            _private_key_finding(),
            _neighbor(12, 12, PEM_LINES[1:3]),
            _neighbor(15, 14, [PEM_LINES[3], AFTER_PEM]),
        )

        mask_secrets_in_results(model)

        assert self._context(model, 1) == (MASKED_LINE + "\n") * 2
        assert self._context(model, 2) == MASKED_LINE + "\n" + AFTER_PEM

    def test_with_no_end_line_in_any_snippet_every_later_line_is_masked(self):
        """Fail closed: where the block ends is unknown."""
        model = _results(
            _private_key_finding(),
            _neighbor(12, 12, PEM_LINES[1:3]),
            _neighbor(40, 40, [AFTER_PEM]),
        )

        mask_secrets_in_results(model)

        assert self._context(model, 1) == (MASKED_LINE + "\n") * 2
        assert self._context(model, 2) == MASKED_LINE + "\n"

    def test_a_secret_finding_on_a_begin_line_extends_through_end(self):
        """Any secret finding whose line is a BEGIN line, not only a private-key rule."""
        model = _results(
            _private_key_finding(rule_id="CUSTOM-1", tags=["secret"]),
            _neighbor(10, 10, [BEFORE_PEM] + PEM_LINES + [AFTER_PEM]),
        )

        mask_secrets_in_results(model)

        assert self._context(model, 1) == (
            BEFORE_PEM + (MASKED_LINE + "\n") * 4 + AFTER_PEM
        )

    def test_lines_before_the_block_and_in_other_files_are_kept(self):
        """Control."""
        other_file = _result(
            "B108",
            "other.py",
            12,
            "other",
            context=(12, "".join(PEM_LINES[1:3])),
            scanner="bandit",
        )
        model = _results(
            _private_key_finding(),
            _neighbor(9, 9, ["import os\n", BEFORE_PEM]),
            other_file,
        )

        mask_secrets_in_results(model)

        assert self._context(model, 1) == "import os\n" + BEFORE_PEM
        assert self._context(model, 2) == "".join(PEM_LINES[1:3])


class TestLargeRegions:
    def test_a_secret_region_of_millions_of_lines_takes_little_memory(self):
        """The reported lines are kept as ranges, not one entry per line.

        A stored results file whose secret finding ends at line 3,000,000 made
        ``ash report`` and the MCP readers allocate hundreds of megabytes.
        """
        import tracemalloc

        model = _results(
            _result(
                "SECRET-KEYWORD",
                "app.py",
                1,
                "Secret of type 'Keyword' detected",
                scanner="detect-secrets",
            ),
            _result(
                "B404",
                "app.py",
                1,
                "import",
                snippet=OTHER_LINE,
                context=(1, OTHER_LINE + ASSIGN_LINE),
                scanner="bandit",
            ),
        )
        region = (
            model.sarif.runs[0].results[0].locations[0].physicalLocation.root.region
        )
        region.endLine = 3_000_000

        tracemalloc.start()
        try:
            mask_secrets_in_results(model)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert peak < 20 * 1024 * 1024, peak
        # Both context lines fall inside the reported range.
        assert _region_text(model.sarif.runs[0].results[1], "contextRegion") == (
            (MASKED_LINE + "\n") * 2
        )


class TestMaskingAsAWhole:
    def test_results_without_secret_findings_are_unchanged(self):
        model = _results(
            _result(
                "B602",
                "deploy.py",
                5,
                "subprocess call",
                snippet=REUSE_LINE,
                context=(4, OTHER_LINE + REUSE_LINE),
                scanner="bandit",
            ),
        )
        before = model.sarif.model_dump_json()

        mask_secrets_in_results(model)

        assert model.sarif.model_dump_json() == before

    def test_masking_twice_changes_nothing_more(self):
        model = _results(
            _result(
                "B105",
                "app.py",
                1,
                HARDCODED + "'" + VALUE + "'",
                snippet=ASSIGN_LINE,
                scanner="bandit",
            ),
            _result(
                "B602",
                "deploy.py",
                5,
                "subprocess call",
                snippet=REUSE_LINE,
                scanner="bandit",
            ),
        )

        mask_secrets_in_results(model)
        once = model.sarif.model_dump_json()
        mask_secrets_in_results(model)

        assert model.sarif.model_dump_json() == once

    def test_values_in_additional_reports_are_masked(self):
        model = _results(
            _result(
                "B105", "app.py", 1, HARDCODED + "'" + VALUE + "'", scanner="bandit"
            ),
        )
        model.additional_reports = {"other": {"source": {"raw_results": REUSE_LINE}}}

        mask_secrets_in_results(model)

        assert VALUE not in str(model.additional_reports)


class TestReportersReceiveMaskedResults:
    """``ReportPhase`` masks the results before the first reporter is called."""

    def test_the_results_a_reporter_receives_hold_no_secret_value(self, tmp_path):
        from typing import Literal

        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.base.reporter_plugin import (
            ReporterPluginBase,
            ReporterPluginConfigBase,
        )
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.core.phases.report_phase import ReportPhase
        from automated_security_helper.core.progress import LiveProgressDisplay

        received = []

        class _RecordingReporterConfig(ReporterPluginConfigBase):
            name: Literal["recording-reporter"] = "recording-reporter"
            extension: str = "recording.json"
            enabled: bool = True

        class _RecordingReporter(ReporterPluginBase[_RecordingReporterConfig]):
            def model_post_init(self, context):
                if self.config is None:
                    self.config = _RecordingReporterConfig()
                return super().model_post_init(context)

            def report(self, model):
                received.append(model.sarif.model_dump_json())
                return "{}"

        model = _results(
            _result(
                "B105",
                "app.py",
                1,
                HARDCODED + "'" + VALUE + "'",
                snippet=ASSIGN_LINE,
                scanner="bandit",
            ),
            _result(
                "B602",
                "deploy.py",
                5,
                "subprocess call",
                snippet=REUSE_LINE,
                scanner="bandit",
            ),
        )
        assert VALUE in model.sarif.model_dump_json()
        output_dir = tmp_path / "out"
        context = PluginContext(
            source_dir=tmp_path / "src",
            output_dir=output_dir,
            work_dir=output_dir / "work",
            config=AshConfig(),
        )
        phase = ReportPhase(
            plugins=[_RecordingReporter],
            plugin_context=context,
            progress_display=LiveProgressDisplay(show_progress=False),
            asharp_model=model,
        )

        phase._execute_phase(
            report_dir=output_dir / "reports",
            aggregated_results=model,
            cli_output_formats=["recording-reporter"],
            python_based_plugins_only=False,
        )

        assert len(received) == 1
        assert VALUE not in received[0]
        assert VALUE not in (output_dir / "reports" / "ash.recording.json").read_text()


class TestStoredResultsAreMaskedWhenRead:
    """A results file written without masking is masked by every way of reading it.

    ``ash report``, ``ash merge``, ``--use-existing``, the MCP tools, scan
    tracking, the findings browser and a workspace's unified reports all build
    an ``AshAggregatedResults`` from the stored file through one of these.
    """

    def _stored(self, tmp_path):
        model = _results(
            _result(
                "B105",
                "app.py",
                1,
                HARDCODED + "'" + VALUE + "'",
                snippet=ASSIGN_LINE,
                scanner="bandit",
            ),
            _result(
                "B602",
                "deploy.py",
                5,
                "subprocess call",
                snippet=REUSE_LINE,
                scanner="bandit",
            ),
        )
        # Written as an ASH without masking wrote it: the model is masked as it
        # is built, so the unmasked SARIF is put back into the dump.
        import json

        dumped = json.loads(model.model_dump_json(by_alias=True))
        dumped["sarif"] = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "test"}},
                    "results": [
                        _result(
                            "B105",
                            "app.py",
                            1,
                            HARDCODED + "'" + VALUE + "'",
                            snippet=ASSIGN_LINE,
                            scanner="bandit",
                        ),
                        _result(
                            "B602",
                            "deploy.py",
                            5,
                            "subprocess call",
                            snippet=REUSE_LINE,
                            scanner="bandit",
                        ),
                    ],
                }
            ],
        }
        path = tmp_path / "ash_aggregated_results.json"
        path.write_text(json.dumps(dumped), encoding="utf-8")
        assert VALUE in path.read_text(encoding="utf-8")
        return path

    def test_model_validate_json(self, tmp_path):
        path = self._stored(tmp_path)

        model = AshAggregatedResults.model_validate_json(path.read_text())

        assert VALUE not in model.sarif.model_dump_json()

    def test_from_json_and_load_model(self, tmp_path):
        import json

        path = self._stored(tmp_path)

        for model in (
            AshAggregatedResults.from_json(path.read_text()),
            AshAggregatedResults.from_json(json.loads(path.read_text())),
            AshAggregatedResults.load_model(path),
        ):
            assert VALUE not in model.sarif.model_dump_json()

    def test_flat_findings_of_a_stored_file(self, tmp_path):
        path = self._stored(tmp_path)

        flat = AshAggregatedResults.load_model(path).to_flat_vulnerabilities()

        assert flat
        assert all(VALUE not in finding.model_dump_json() for finding in flat)


def _write_shards(tmp_path, shards):
    """Write one results file per (owned scanners, result), stamped as ``ash scan --shard-*``.

    Saved with ``save_model``, as a shard's own scan saves it.
    """
    from automated_security_helper.cli.merge import stamp_shard_assignment
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.enums import ScannerStatus
    from automated_security_helper.core.sharding import ShardAssignment
    from automated_security_helper.models.asharp_model import ScannerTargetStatusInfo

    scanners = sorted({name for owned, _ in shards for name in owned})
    dirs = []
    for index, (owned, result) in enumerate(shards):
        model = _results(result)
        # Every shard records the config it scanned under; ash merge refuses a
        # shard that records none.
        model.ash_config = AshConfig()
        for name in scanners:
            model.scanner_results[name] = ScannerTargetStatusInfo(
                status=ScannerStatus.FAILED,
                excluded=False,
                dependencies_satisfied=True,
            )
            model.additional_reports[name] = {
                "source": {"scanner_name": name, "status": "FAILED", "duration": 1}
            }
        stamp_shard_assignment(
            model,
            ShardAssignment(
                shard_index=index,
                shard_count=len(shards),
                assigned_scanners=owned,
                candidate_scanners=scanners,
            ),
        )
        shard_dir = tmp_path / f"shard{index}"
        shard_dir.mkdir()
        model.save_model(shard_dir)
        dirs.append(shard_dir)
    return dirs


class TestMergedShards:
    """``ash merge`` masks the merged results against every shard's secret findings.

    Shards split by scanner, so a secret one shard's scanner reports routinely sits
    in another shard's snippets: here detect-secrets (shard 0) reports app.py line
    2, and bandit (shard 1) has a contextRegion over lines 1-2. Each shard was
    masked only against its own findings.
    """

    def _shards(self, tmp_path):
        detect_secrets = _result(
            "SECRET-SECRET-KEYWORD",
            "app.py",
            2,
            "Secret of type 'Secret Keyword' detected",
            scanner="detect-secrets",
        )
        bandit = _result(
            "B404",
            "app.py",
            1,
            "Consider possible security implications",
            snippet=OTHER_LINE,
            context=(1, OTHER_LINE + ASSIGN_LINE),
            scanner="bandit",
        )
        # The bandit shard is written as its own scan wrote it: masked against its
        # own findings only, which leaves the neighbor's line in clear.
        dirs = _write_shards(
            tmp_path,
            [(["detect-secrets"], detect_secrets), (["bandit"], bandit)],
        )
        assert VALUE in (dirs[1] / "ash_aggregated_results.json").read_text()
        return dirs

    def _value_shards(self, tmp_path, exposing_shard_first=True):
        """One shard's B105 exposes VALUE; the other's semgrep finding has it in a snippet."""
        b105 = _result(
            "B105",
            "settings.py",
            1,
            # As BanditScanner writes it: the value already masked in the message.
            HARDCODED + "'" + _mask_secret_value(VALUE) + "'",
            snippet=ASSIGN_LINE,
            scanner="bandit",
        )
        semgrep = _result(
            "python.lang.security.audit.subprocess-shell-true",
            "deploy.py",
            5,
            "Found 'subprocess' function with 'shell=True'",
            snippet=REUSE_LINE,
            scanner="semgrep",
        )
        shards = [(["bandit"], b105), (["semgrep"], semgrep)]
        if not exposing_shard_first:
            shards.reverse()
        dirs = _write_shards(tmp_path, shards)
        exposing, other = dirs if exposing_shard_first else reversed(dirs)
        assert VALUE not in (exposing / "ash_aggregated_results.json").read_text()
        assert VALUE in (other / "ash_aggregated_results.json").read_text()
        return dirs

    @pytest.mark.parametrize(
        "exposing_shard_first", [True, False], ids=["exposing-first", "exposing-last"]
    )
    def test_a_value_one_shard_exposed_is_masked_in_another_shards_findings(
        self, tmp_path, monkeypatch, exposing_shard_first
    ):
        """No shard holds the value any more: one masked it, the other never knew.

        The exposing shard recorded the value's shape -- its visible prefix and
        suffix and its length -- and the merge masks every token of that shape in
        every shard, whichever shard index recorded it.
        """
        from automated_security_helper.cli.merge import merge_command

        monkeypatch.chdir(tmp_path)
        out = tmp_path / "merged"

        merge_command(
            results=[
                str(path) for path in self._value_shards(tmp_path, exposing_shard_first)
            ],
            output_dir=str(out),
            output_formats=["sarif"],
            fail_on_findings=False,
            fail_on_incomplete_scanners=False,
        )

        for relative in ("ash_aggregated_results.json", "reports/ash.sarif"):
            text = (out / relative).read_text(encoding="utf-8")
            assert "subprocess-shell-true" in text, relative
            assert VALUE not in text, relative
            # Control: the command line around the value is kept.
            assert "login --token " in text, relative

    def test_merge_shard_results_masks_across_shards(self, tmp_path):
        from automated_security_helper.cli.merge import merge_shard_results

        loaded = [
            (
                path,
                AshAggregatedResults.model_validate_json(
                    (path / "ash_aggregated_results.json").read_text()
                ),
            )
            for path in self._shards(tmp_path)
        ]

        merged = merge_shard_results(loaded)

        assert VALUE not in merged.model_dump_json()

    def test_the_merged_results_file_holds_no_value_from_another_shard(
        self, tmp_path, monkeypatch
    ):
        from automated_security_helper.cli.merge import merge_command

        monkeypatch.chdir(tmp_path)
        out = tmp_path / "merged"

        merge_command(
            results=[str(path) for path in self._shards(tmp_path)],
            output_dir=str(out),
            output_formats=["sarif"],
            fail_on_findings=False,
            fail_on_incomplete_scanners=False,
        )

        for relative in ("ash_aggregated_results.json", "reports/ash.sarif"):
            text = (out / relative).read_text(encoding="utf-8")
            assert "B404" in text, relative
            assert VALUE not in text, relative


class TestValuesAcrossResultSets:
    """What one masking learns is kept, so a later union of result sets can use it.

    After a result set is masked it no longer holds its values: the message shows
    the masked form and the line is masked by location. So each masking records
    the raw values it found on the model, where they are never serialized, and
    each value's shape -- its visible prefix, visible suffix and length -- which
    is written with the results. A workspace masks every project with the values;
    ``ash merge``, whose shards are separate processes, with the shapes.
    """

    def _masked_unit(self):
        model = _results(
            _result(
                "B105",
                "app.py",
                1,
                HARDCODED + "'" + VALUE + "'",
                snippet=ASSIGN_LINE,
                scanner="bandit",
            ),
        )
        mask_secrets_in_results(model)
        return model

    def _other_unit(self, snippet_text=REUSE_LINE):
        return _results(
            _result(
                "B602",
                "deploy.py",
                5,
                "subprocess call",
                snippet=snippet_text,
                scanner="bandit",
            ),
        )

    def test_a_masking_records_the_values_it_found_without_serializing_them(self):
        model = self._masked_unit()

        assert exposed_secret_values(model) == {VALUE}
        assert VALUE not in model.model_dump_json()

    def test_a_masking_records_each_values_shape_with_the_results(self):
        import json

        model = self._masked_unit()

        shape = SecretValueShape(prefix=VALUE[:2], suffix=VALUE[-1], length=len(VALUE))
        assert model.secret_value_shapes == [shape]
        assert json.loads(model.model_dump_json())["secret_value_shapes"] == [
            {
                "prefix": VALUE[:2],
                "suffix": VALUE[-1],
                "length": len(VALUE),
                "spans_whitespace": False,
            }
        ]

    def test_results_without_secret_findings_carry_no_shapes(self):
        model = self._other_unit()

        mask_secrets_in_results(model)

        assert "secret_value_shapes" not in model.model_dump_json()

    def test_values_passed_in_are_masked(self):
        """How a workspace masks one project with the values the others exposed."""
        model = self._other_unit()

        mask_secrets_in_results(model, values={VALUE})

        assert VALUE not in _region_text(model.sarif.runs[0].results[0])
        assert exposed_secret_values(model) == {VALUE}

    def test_a_recorded_shape_masks_a_token_of_that_shape(self):
        """How ``ash merge`` masks one shard with what another shard recorded."""
        import json

        other_shape = "q" + VALUE[1:]
        dumped = json.loads(
            self._other_unit(f'run("{VALUE}")\nrun("{other_shape}")\n').model_dump_json(
                by_alias=True
            )
        )
        dumped["secret_value_shapes"] = json.loads(
            self._masked_unit().model_dump_json()
        )["secret_value_shapes"]

        model = AshAggregatedResults.model_validate(dumped)

        text = _region_text(model.sarif.runs[0].results[0])
        assert VALUE not in text
        assert f'run("{_mask_secret_value(VALUE)}")' in text
        # A token that differs in a visible character is not that shape.
        assert f'run("{other_shape}")' in text

    def test_shapes_passed_in_are_recorded_and_masked(self):
        model = self._other_unit()
        shape = SecretValueShape(prefix=VALUE[:2], suffix=VALUE[-1], length=len(VALUE))

        mask_secrets_in_results(model, shapes=[shape])

        assert VALUE not in _region_text(model.sarif.runs[0].results[0])
        assert model.secret_value_shapes == [shape]

    def test_masking_by_shape_twice_changes_nothing_more(self):
        model = self._other_unit()
        shape = SecretValueShape(prefix=VALUE[:2], suffix=VALUE[-1], length=len(VALUE))
        mask_secrets_in_results(model, shapes=[shape])
        once = model.model_dump_json()

        mask_secrets_in_results(model)

        assert model.model_dump_json() == once
