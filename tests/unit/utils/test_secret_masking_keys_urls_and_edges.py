# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Masking keeps no raw value in a key, a URL or a multi-line snippet's tail.

A region whose snippet holds a line break only some scanners count (form feed,
vertical tab, NEL, the Unicode line and paragraph separators) covered one line, so
the lines after the first stayed unmasked. A dict key (or the name of a model's
extra field) that holds a value was kept raw when another key already read like its
masked text. A URL that a model types as a URL holds the userinfo and path
percent-encoded, so a value with ``@``, ``:``, ``/``, ``#``, ``?``, ``%`` or a
non-ASCII character stayed in it. A value that ends in ``!`` or another password
character was read as the bare word.

Every value here is derived at import time or an ordinary word; none is a
credential.
"""

import hashlib
import string
from types import SimpleNamespace
from urllib.parse import quote

import pytest
from pydantic import BaseModel, ConfigDict

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    _mask_secret_value,
    _propagates,
    _region_last_line,
    mask_secret_values_in_tree,
    mask_secrets_in_results,
)

pytestmark = pytest.mark.unit

NAME = "pass" + "word"
HARDCODED = "Possible hardcoded " + NAME + ": "

#: The code points of the line breaks only some scanners count.
LINE_SEPARATOR = chr(0x2028)
PARAGRAPH_SEPARATOR = chr(0x2029)


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


VALUE = _derived("keys-urls-edges", 11) + "9"


def _region(text, end_line=None):
    return SimpleNamespace(endLine=end_line, snippet=SimpleNamespace(text=text))


class TestTheLastLineOfARegion:
    @pytest.mark.parametrize(
        "text, lines",
        [
            ("a\fb", 2),
            ("a\vb\vc", 3),
            ("a\x85b", 2),
            ("a" + LINE_SEPARATOR + "b", 2),
            ("a" + PARAGRAPH_SEPARATOR + "b", 2),
            ("a\x1cb", 2),
            ("a\rb", 2),
            ("a\r\nb", 2),
            ("a\nb\n", 2),
            ("one", 1),
            ("", 1),
        ],
    )
    def test_covers_every_line_whichever_breaks_count(self, text, lines):
        assert _region_last_line(_region(text), 5) == 5 + lines - 1

    def test_an_end_line_past_the_snippet_still_wins(self):
        assert _region_last_line(_region("a\fb", end_line=9), 5) == 9


class TestAKeyThatHoldsAValue:
    def test_two_keys_that_mask_alike_keep_no_raw_key(self):
        masked = _mask_secret_value(VALUE)
        tree = {VALUE: "first", masked: "second"}

        mask_secret_values_in_tree(tree, [VALUE], [])

        assert all(VALUE not in key for key in tree)
        assert sorted(tree.values()) == ["first", "second"]

    def test_the_same_in_the_other_order(self):
        masked = _mask_secret_value(VALUE)
        tree = {masked: "second", VALUE: "first"}

        mask_secret_values_in_tree(tree, [VALUE], [])

        assert all(VALUE not in key for key in tree)
        assert sorted(tree.values()) == ["first", "second"]

    def test_a_key_that_holds_nothing_exposed_is_kept(self):
        """Control."""
        tree = {"plain": "x", VALUE: "y"}

        mask_secret_values_in_tree(tree, [VALUE], [])

        assert tree["plain"] == "x"

    def test_the_name_of_a_models_extra_field_is_masked(self):
        class Bag(BaseModel):
            model_config = ConfigDict(extra="allow")

        bag = Bag.model_validate({VALUE: "x", "plain": "y"})

        mask_secret_values_in_tree(bag, [VALUE], [])

        extra = bag.__pydantic_extra__
        assert all(VALUE not in key for key in extra)
        assert extra["plain"] == "y"
        assert len(extra) == 2


def _report_with_a_url(url, *results):
    run = {
        "tool": {"driver": {"name": "test"}},
        "versionControlProvenance": [{"repositoryUri": url}],
        "results": list(results),
    }
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": [run]})
    return model


def _bandit(message):
    return {
        "ruleId": "B105",
        "level": "warning",
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 5, "endLine": 5},
                }
            }
        ],
        "properties": {"scanner_name": "bandit", "tags": ["bandit"]},
    }


class TestAUrlTypedField:
    #: Characters that percent-encoding changes: ``@ : / # ? %`` and a letter
    #: outside ASCII (U+00FC).
    PASSWORD = "pa@ss:w/rd#9?x%" + chr(0xFC)

    def _masked_uri(self, password):
        url = f"https://user:{quote(password, safe='')}@example.com/repo"
        model = _report_with_a_url(url, _bandit(HARDCODED + f"'{password}'"))

        mask_secrets_in_results(model)

        return str(model.sarif.runs[0].versionControlProvenance[0].repositoryUri)

    def test_a_value_with_reserved_characters_is_masked_in_its_encoded_form(self):
        uri = self._masked_uri(self.PASSWORD)

        assert quote(self.PASSWORD, safe="") not in uri
        assert self.PASSWORD not in uri

    def test_a_plain_value_is_masked_as_before(self):
        """Control."""
        uri = self._masked_uri(VALUE)

        assert VALUE not in uri

    def test_a_value_written_into_the_url_as_is_is_masked_in_pydantics_spelling(self):
        """A producer that writes the credential into the URL without encoding
        it: pydantic percent-encodes the ``@`` of the userinfo and leaves the
        ``!`` as it is, a spelling that neither the plain value nor
        ``quote(value, safe="")`` matches."""
        password = (
            _derived("url-userinfo", 5) + "@!" + _derived("url-userinfo-b", 5) + "9"
        )
        url = f"https://user:{password}@example.com/repo"
        model = _report_with_a_url(url, _bandit(HARDCODED + f"'{password}'"))
        written = str(model.sarif.runs[0].versionControlProvenance[0].repositoryUri)
        assert "%40!" in written and password not in written

        mask_secrets_in_results(model)

        uri = str(model.sarif.runs[0].versionControlProvenance[0].repositoryUri)
        assert quote(password, safe="!$&'()*+,%") not in uri
        assert quote(password, safe="") not in uri
        assert password not in uri
        assert _mask_secret_value(password) in uri

    def test_a_url_that_holds_nothing_exposed_is_kept(self):
        """Control."""
        url = "https://example.com/repo"
        model = _report_with_a_url(url, _bandit(HARDCODED + f"'{VALUE}'"))

        mask_secrets_in_results(model)

        provenance = model.sarif.runs[0].versionControlProvenance[0]
        assert str(provenance.repositoryUri) == url


class TestTheEndsOfAValue:
    @pytest.mark.parametrize("value", ["Password!", "Secretword!!", "Mypassword?"])
    def test_a_word_with_a_password_character_at_its_end_is_a_value(self, value):
        assert _propagates(value)

    @pytest.mark.parametrize(
        "value",
        [NAME + ":", "--access_token", "'" + NAME + "'", "(" + NAME + ")", NAME + "="],
    )
    def test_label_and_quote_punctuation_around_a_word_still_is_not(self, value):
        """Control."""
        assert not _propagates(value)
