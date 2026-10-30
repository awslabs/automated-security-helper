# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Where a secret line can be shown, and where a value exposed there is masked.

A code flow step or a related location at the secret line kept a value in its
result; a secret finding's related locations were not indexed; the annotation
regions of a location and the regions of an attachment were never placed; a
region with no ``endLine`` whose snippet spans several lines counted as one; a
key finding's own range was cut to the first END line; a finding was treated as
a private key when only its quoted value mentioned one; the Markdown rendering of
a snippet was masked by the text's line numbers; the global pass ran before the
local one and could break a local match; the findings browser's source masker
applied no local value; a value used as a dict key stayed; and a URL-typed field
was skipped.

Every value here is derived at import time; none is a credential, and the PEM
block is a shape with derived body lines, not a key.
"""

import hashlib
import string

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    MASKED_LINE,
    _line_spans,
    _mask_secret_value,
    mask_secret_values_in_tree,
    mask_secrets_in_results,
    source_snippet_masker,
)

pytestmark = pytest.mark.unit

NAME = "pass" + "word"
HARDCODED = "Possible hardcoded " + NAME + ": "


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


VALUE = _derived("more-locations", 11) + "9"
#: Four characters: masked in its own finding and in overlapping findings only.
SHORT = "pw" + _derived("short", 1) + "2"
SECRET_LINE = NAME + f' = "{VALUE}"\n'
PEM_LINES = [
    "-----BEGIN RSA PRIVATE " + "KEY-----\n",
    _derived("pem-body-1", 40) + "\n",
    _derived("pem-body-2", 40) + "\n",
    "-----END RSA PRIVATE " + "KEY-----\n",
]


def _physical(uri, line, snippet=None, end=None, context=None):
    region = {"startLine": line, "endLine": end if end is not None else line}
    if snippet is not None:
        region["snippet"] = {"text": snippet}
    physical = {"artifactLocation": {"uri": uri}, "region": region}
    if context is not None:
        start, text = context
        physical["contextRegion"] = {"startLine": start, "snippet": {"text": text}}
    return physical


def _result(rule_id, line, message, uri="app.py", scanner="bandit", **extra):
    result = {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": message},
        "locations": [{"physicalLocation": _physical(uri, line)}],
        "properties": {"scanner_name": scanner, "tags": [scanner]},
    }
    result.update(extra)
    return result


def _results(*results, run_extra=None):
    run = {"tool": {"driver": {"name": "test"}}, "results": list(results)}
    run.update(run_extra or {})
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": [run]})
    return model


def _message(model, position):
    return model.sarif.runs[0].results[position].message.root.text


def _physical_of(model, position, location=0):
    result = model.sarif.runs[0].results[position]
    return result.locations[location].physicalLocation.root


class TestACodeFlowStepAtTheSecretLine:
    def test_the_value_is_masked_in_the_results_message(self):
        taint = _result(
            "B404",
            20,
            "flows from " + SHORT + " to the sink",
            codeFlows=[
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": {
                                        "physicalLocation": _physical("app.py", 5)
                                    }
                                }
                            ]
                        }
                    ]
                }
            ],
        )
        model = _results(_result("B105", 5, HARDCODED + f"'{SHORT}'"), taint)

        mask_secrets_in_results(model)

        assert SHORT not in _message(model, 1)
        assert (
            _message(model, 1)
            == "flows from " + _mask_secret_value(SHORT) + " to the sink"
        )


class TestASecretFindingsRelatedLocation:
    def test_is_a_secret_location_for_other_findings(self):
        secret = _result(
            "SECRET-KEYWORD",
            5,
            "Secret Keyword",
            scanner="detect-secrets",
            relatedLocations=[{"physicalLocation": _physical("app.py", 9)}],
        )
        neighbor = _result("B404", 9, "import")
        neighbor["locations"][0]["physicalLocation"] = _physical(
            "app.py", 9, snippet=SECRET_LINE
        )
        model = _results(secret, neighbor)

        mask_secrets_in_results(model)

        assert _physical_of(model, 1).region.snippet.text == MASKED_LINE + "\n"


class TestAnnotationsAndAttachments:
    def test_an_annotation_region_at_a_secret_line_is_masked(self):
        neighbor = _result("B404", 20, "import")
        neighbor["locations"][0]["annotations"] = [
            {"startLine": 5, "snippet": {"text": SECRET_LINE}}
        ]
        model = _results(_result("B105", 5, HARDCODED + f"'{VALUE}'"), neighbor)

        mask_secrets_in_results(model)

        annotation = model.sarif.runs[0].results[1].locations[0].annotations[0]
        assert annotation.snippet.text == MASKED_LINE + "\n"

    def test_an_attachment_region_at_a_secret_line_is_masked(self):
        neighbor = _result(
            "B404",
            20,
            "import",
            attachments=[
                {
                    "artifactLocation": {"uri": "app.py"},
                    "regions": [{"startLine": 5, "snippet": {"text": SECRET_LINE}}],
                }
            ],
        )
        model = _results(_result("B105", 5, HARDCODED + f"'{VALUE}'"), neighbor)

        mask_secrets_in_results(model)

        region = model.sarif.runs[0].results[1].attachments[0].regions[0]
        assert region.snippet.text == MASKED_LINE + "\n"

    def test_a_secret_findings_own_annotation_is_masked_whole(self):
        secret = _result("B105", 5, HARDCODED + f"'{VALUE}'")
        secret["locations"][0]["annotations"] = [
            {"startLine": 40, "snippet": {"text": "other = " + VALUE + "\n"}}
        ]
        model = _results(secret)

        mask_secrets_in_results(model)

        annotation = model.sarif.runs[0].results[0].locations[0].annotations[0]
        assert annotation.snippet.text == MASKED_LINE + "\n"


class TestARegionWithNoEndLineAndAMultiLineSnippet:
    def test_covers_every_line_of_its_snippet(self):
        result = _result("B404", 3, "import")
        result["locations"][0]["physicalLocation"]["region"] = {
            "startLine": 3,
            "snippet": {"text": "a\nb\nc"},
        }
        model = _results(result)

        assert _line_spans(_physical_of(model, 0)) == [(3, 5)]

    def test_a_secret_region_masks_every_line_it_spans(self):
        secret = _result(
            "SECRET-KEYWORD", 5, "Secret Keyword", scanner="detect-secrets"
        )
        secret["locations"][0]["physicalLocation"]["region"] = {
            "startLine": 5,
            "snippet": {"text": "a = 1\nb = 2\n" + SECRET_LINE},
        }
        neighbor = _result("B404", 7, "import")
        neighbor["locations"][0]["physicalLocation"] = _physical(
            "app.py", 7, snippet=SECRET_LINE
        )
        model = _results(secret, neighbor)

        mask_secrets_in_results(model)

        assert _physical_of(model, 1).region.snippet.text == MASKED_LINE + "\n"


class TestAKeyFindingWithItsOwnRange:
    def test_a_range_past_the_first_end_line_is_kept(self):
        key = _result(
            "SECRET-PRIVATE-KEY",
            11,
            "Secret of type 'Private Key' detected",
            uri="keys.py",
            scanner="detect-secrets",
        )
        key["locations"][0]["physicalLocation"]["region"]["endLine"] = 20
        context = _result("B108", 12, "other", uri="keys.py")
        context["locations"][0]["physicalLocation"] = _physical(
            "keys.py", 12, context=(11, "".join(PEM_LINES))
        )
        later = _result("B108", 18, "other", uri="keys.py")
        later["locations"][0]["physicalLocation"] = _physical(
            "keys.py", 18, snippet="tail = 1\n"
        )
        model = _results(key, context, later)

        mask_secrets_in_results(model)

        assert _physical_of(model, 2).region.snippet.text == MASKED_LINE + "\n"
        assert _physical_of(model, 0).region.endLine == 20


class TestAPrivateKeyMentionedInAQuotedValue:
    def _neighbor(self):
        neighbor = _result("B404", 30, "import")
        neighbor["locations"][0]["physicalLocation"] = _physical(
            "app.py", 30, snippet="far = 1\n"
        )
        return neighbor

    def test_does_not_make_the_finding_a_key_finding(self):
        model = _results(
            _result("B105", 5, HARDCODED + "'my private key is here'"),
            self._neighbor(),
        )

        mask_secrets_in_results(model)

        assert _physical_of(model, 1).region.snippet.text == "far = 1\n"

    def test_a_message_about_a_private_key_still_does(self):
        """Control: with no END line known, every later line is masked."""
        model = _results(
            _result(
                "SECRET-PRIVATE-KEY",
                5,
                "Private key detected",
                scanner="detect-secrets",
            ),
            self._neighbor(),
        )

        mask_secrets_in_results(model)

        assert _physical_of(model, 1).region.snippet.text == MASKED_LINE + "\n"


class TestTheMarkdownRenderingOfASnippet:
    def test_is_masked_whole_when_the_snippet_reaches_a_secret_line(self):
        text = "x = 1\n" + SECRET_LINE
        neighbor = _result("B404", 1, "import")
        neighbor["locations"][0]["physicalLocation"] = {
            "artifactLocation": {"uri": "app.py"},
            "region": {"startLine": 1, "endLine": 1},
            "contextRegion": {
                "startLine": 1,
                "snippet": {
                    "text": text,
                    "rendered": {"text": text, "markdown": "```\n" + text + "```"},
                },
            },
        }
        model = _results(_result("B105", 2, HARDCODED + f"'{VALUE}'"), neighbor)

        mask_secrets_in_results(model)

        rendered = _physical_of(model, 1).contextRegion.snippet.rendered
        assert VALUE not in rendered.markdown
        # Every non-blank line of the rendering, the fences included: which
        # line of it holds the secret is not known from the text's numbers.
        assert rendered.markdown == (MASKED_LINE + "\n") * 3 + MASKED_LINE
        assert rendered.text == "x = 1\n" + MASKED_LINE + "\n"

    def test_is_kept_when_the_snippet_is_away_from_every_secret_line(self):
        """Control."""
        text = "x = 1\ny = 2\n"
        neighbor = _result("B404", 20, "import")
        neighbor["locations"][0]["physicalLocation"] = {
            "artifactLocation": {"uri": "app.py"},
            "region": {"startLine": 20, "endLine": 20},
            "contextRegion": {
                "startLine": 20,
                "snippet": {
                    "text": text,
                    "rendered": {"text": text, "markdown": "```\n" + text + "```"},
                },
            },
        }
        model = _results(_result("B105", 2, HARDCODED + f"'{VALUE}'"), neighbor)

        mask_secrets_in_results(model)

        rendered = _physical_of(model, 1).contextRegion.snippet.rendered
        assert rendered.markdown == "```\n" + text + "```"
        assert rendered.text == text


class TestTheLocalPassRunsFirst:
    def test_a_local_value_holding_a_propagating_token_is_masked_whole(self):
        local = "<" + VALUE + ">"
        model = _results(
            _result("B105", 5, HARDCODED + f"'{VALUE}'"),
            _result("B105", 5, HARDCODED + f"'{local}'"),
            _result("B404", 5, "ref " + local + " end"),
        )

        mask_secrets_in_results(model)

        assert _message(model, 2) == "ref " + _mask_secret_value(local) + " end"


class TestTheSourceMaskerOfTheFindingsBrowser:
    def test_applies_the_values_of_the_lines_it_shows(self):
        model = _results(_result("B105", 5, HARDCODED + f"'{SHORT}'"))
        mask = source_snippet_masker(model)

        shown = mask("app.py", 4, "a = 1\nb = 2\nc = '" + SHORT + "' + x\n")

        assert SHORT not in shown
        assert shown.splitlines()[0] == "a = 1"
        assert shown.splitlines()[1] == MASKED_LINE

    def test_lines_away_from_the_finding_keep_the_value(self):
        """Control: the value is masked where the finding reports it only."""
        model = _results(_result("B105", 5, HARDCODED + f"'{SHORT}'"))
        mask = source_snippet_masker(model)

        shown = mask("app.py", 40, "c = '" + SHORT + "'\n")

        assert shown == "c = '" + SHORT + "'\n"


class TestAValueUsedAsAKey:
    def test_is_masked_like_any_other_string(self):
        tree = {"tokens": {VALUE: "seen"}, "text": VALUE}

        mask_secret_values_in_tree(tree, [VALUE])

        assert tree["tokens"] == {_mask_secret_value(VALUE): "seen"}
        assert tree["text"] == _mask_secret_value(VALUE)


class TestAUrlTypedField:
    def test_a_value_in_the_repository_uri_is_masked(self):
        model = _results(
            _result("B105", 5, HARDCODED + f"'{VALUE}'"),
            run_extra={
                "versionControlProvenance": [
                    {"repositoryUri": f"https://user:{VALUE}@example.com/repo.git"}
                ]
            },
        )

        mask_secrets_in_results(model)

        uri = str(model.sarif.runs[0].versionControlProvenance[0].repositoryUri)
        assert VALUE not in uri
        assert uri.startswith("https://user:")
        assert uri.endswith("@example.com/repo.git")
