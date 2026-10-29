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
import string

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    MASKED_LINE,
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


def _result(rule_id, uri, line, message, scanner, context=None, end=None, tags=None):
    region = {"startLine": line, "endLine": end if end is not None else line}
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

    def test_the_end_line_found_is_kept_on_the_key_finding(self):
        model = self._model()

        mask_secrets_in_results(model)

        assert _region(model, 0).endLine == 14

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
        """cdk-nag's wrapper writes endLine == startLine."""
        model = _results(
            self._credential_finding(end=3),
            _neighbor("template.yaml", 6, 3, RESOURCE_LINES),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == (MASKED_LINE + "\n") * 4

    def test_a_producers_real_end_line_bounds_the_range(self):
        """Control: checkov reports the resource block's own last line."""
        model = _results(
            self._credential_finding(end=6),
            _neighbor("template.yaml", 8, 3, RESOURCE_LINES + ["Outputs: {}\n"]),
        )

        mask_secrets_in_results(model)

        assert _context(model, 1) == (MASKED_LINE + "\n") * 4 + "Outputs: {}\n"
