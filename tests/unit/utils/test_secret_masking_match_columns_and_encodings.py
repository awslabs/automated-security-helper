# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Two edges of ``secret_masking``: a match read by columns, and a value in a URL or script.

``_matched_values`` reads the value of a secret finding that quotes none from the
snippet at the region's columns, which are the file line's. A snippet that is
only the matched text does not start at column 1, so those columns are not its
own. ``mask_secret_values_in_text`` masks a value in each of the forms listed in
``_TEXT_ENCODINGS``; percent-encoded and backslash-escaped forms are among them.

The values are derived at import time, so this source holds no string a secret
scanner would report.
"""

import hashlib
import string
from urllib.parse import quote, quote_plus

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    _mask_secret_value,
    exposed_secret_values,
    mask_secret_values_in_text,
    mask_secrets_in_results,
)


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


VALUE = _derived("masking-unit-value", 14)
TAIL = _derived("masking-encoding-tail", 6)


def _model(snippet, start_column, end_column, neighbor_line):
    """A secret finding quoting no value, with its columns, and a neighbor.

    The neighbor is a finding of another scanner on another line of the same file.
    """

    def result(rule_id, line, message, text, scanner, columns=None):
        region = {"startLine": line, "endLine": line, "snippet": {"text": text}}
        if columns is not None:
            region["startColumn"], region["endColumn"] = columns
        return {
            "ruleId": rule_id,
            "level": "warning",
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app/settings.py"},
                        "region": region,
                    }
                }
            ],
            "properties": {"scanner_name": scanner, "tags": [scanner]},
        }

    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "test"}},
                    "results": [
                        result(
                            "github-pat",
                            4,
                            "a GitHub personal access token",
                            snippet,
                            "detect-secrets",
                            (start_column, end_column),
                        ),
                        result("B404", 9, "import", neighbor_line, "bandit"),
                    ],
                }
            ],
        }
    )
    return model


class TestAMatchIsReadOnlyFromASnippetThatHoldsItsColumns:
    def test_a_snippet_that_is_only_the_matched_text_gives_no_value(self):
        """The columns are the file line's; the snippet is the match alone."""
        fragment = VALUE[1:]
        neighbor_line = f"other = {fragment}\n"
        model = _model(VALUE, 2, 2 + len(VALUE), neighbor_line)

        mask_secrets_in_results(model)

        assert exposed_secret_values(model) == set()
        neighbor = model.sarif.runs[0].results[1]
        assert (
            neighbor.locations[0].physicalLocation.root.region.snippet.text
            == neighbor_line
        )

    def test_a_snippet_that_is_the_whole_line_still_gives_the_literal(self):
        """Control: the same kind of region on a full-line snippet is read."""
        prefix = 'token = "'
        line = f'{prefix}{VALUE}"'
        model = _model(line, len(prefix), len(line) + 1, "import os\n")

        mask_secrets_in_results(model)

        assert exposed_secret_values(model) == {VALUE}


def _mask_in_the_encoding(value, encode):
    return encode(_mask_secret_value(value))


class TestAValueIsMaskedInTheFormsAReportWritesIt:
    def test_the_value_as_it_is_is_masked(self):
        """Control: the form every report writes."""
        value = f"{VALUE}/{TAIL}+="
        masked = mask_secret_values_in_text(f"token={value}\n", [value])

        assert value not in masked
        assert masked == f"token={_mask_secret_value(value)}\n"

    def test_a_percent_encoded_value_is_masked(self):
        value = f"{VALUE}/{TAIL}+="
        encoded = quote(value, safe="")
        assert encoded != value
        text = f"GET /download?token={encoded}&x=1\n"

        masked = mask_secret_values_in_text(text, [value])

        assert encoded not in masked
        assert masked == text.replace(
            encoded, _mask_in_the_encoding(value, lambda item: quote(item, safe=""))
        )

    def test_a_value_with_a_space_is_masked_written_with_a_plus(self):
        value = f"{VALUE} {TAIL}"
        encoded = quote_plus(value, safe="")
        assert "+" in encoded
        text = f"GET /download?token={encoded}&x=1\n"

        masked = mask_secret_values_in_text(text, [value])

        assert encoded not in masked
        assert masked == text.replace(
            encoded,
            _mask_in_the_encoding(value, lambda item: quote_plus(item, safe="")),
        )

    def test_a_value_with_a_single_quote_is_masked_backslash_escaped(self):
        value = f"{VALUE}'{TAIL}"
        escaped = value.replace("'", "\\'")
        text = f"run('--token {escaped}')\n"

        masked = mask_secret_values_in_text(text, [value])

        assert escaped not in masked
        assert VALUE not in masked
