# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A secret finding's source text outside its region snippets is masked whole.

The snippets of a secret finding's own regions were masked whole, but the source
text it carries elsewhere -- cdk-nag's ``properties.cfn_resource`` (the resource
with every property value), a ``properties.snippet``, a fix's inserted content
and deleted region, a fenced code block in its message -- was masked only where
a value the finding quoted occurred. A credential finding that quotes no value
(cdk-nag's and cfn-nag's never do; detect-secrets' do not) kept the credential.
The message's markdown and arguments were likewise masked only when the value
propagated.

The values here are placeholders derived at import time or plain words; none is
a credential.
"""

import hashlib
import json
import string

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    MASKED_LINE,
    _mask_secret_value,
    mask_secrets_in_results,
)

pytestmark = pytest.mark.unit


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


VALUE = _derived("source-text-value", 14)
#: Letters alone: masked in its own finding only, never propagated.
WORD = "pass" + "word"
HARDCODED = "Possible hardcoded " + WORD + ": "
#: A plaintext property value that is letters alone, so no value masking
#: reaches it; only the resource text as a whole can.
PLAINTEXT = "placeholder-example-value"
ASSIGN_LINE = f'{WORD} = "{VALUE}"\n'
REPLACEMENT_LINE = f'{WORD} = os.environ["TOKEN"]\n'
OTHER_LINE = "import os\n"


def _result(rule_id, uri, line, message, scanner, extra=None, snippet=None):
    region = {"startLine": line, "endLine": line}
    if snippet is not None:
        region["snippet"] = {"text": snippet}
    result = {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": message},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}
        ],
        "properties": {"scanner_name": scanner, "tags": [scanner]},
    }
    for name, value in (extra or {}).items():
        if name == "properties":
            result["properties"].update(value)
        else:
            result[name] = value
    return result


def _fix(uri, line, deleted, inserted):
    return {
        "description": {"text": "Read the value from the environment."},
        "artifactChanges": [
            {
                "artifactLocation": {"uri": uri},
                "replacements": [
                    {
                        "deletedRegion": {
                            "startLine": line,
                            "endLine": line,
                            "snippet": {"text": deleted},
                        },
                        "insertedContent": {"text": inserted},
                    }
                ],
            }
        ],
    }


def _results(*results):
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": list(results)}],
        }
    )
    return model


def _first(model):
    return model.sarif.runs[0].results[0]


def _replacement(result):
    return result.fixes[0].artifactChanges[0].replacements[0]


class TestASecretFindingsOwnSourceText:
    def test_a_resource_level_credential_finding_masks_its_resource(self):
        """cdk-nag: the message describes the credential and quotes no value;
        the resource with its plaintext property is the finding's own excerpt."""
        resource = {
            "Resources": {
                "Database": {
                    "Type": "AWS::RDS::DBInstance",
                    "Properties": {"MasterUserPassword": PLAINTEXT},
                }
            }
        }
        model = _results(
            _result(
                "AwsSolutions-RDS-1",
                "template.yaml",
                3,
                "The database password must not be a plaintext string.\n\n"
                "Exception Reason: N/A",
                "cdk-nag",
                extra={"properties": {"cfn_resource": resource}},
                snippet="Resources:\n  Database:\n",
            )
        )

        mask_secrets_in_results(model)

        dumped = json.dumps(_first(model).model_dump(mode="json", by_alias=True))
        assert PLAINTEXT not in dumped
        masked = getattr(_first(model).properties, "cfn_resource")
        assert masked["Resources"]["Database"]["Properties"] == {
            "MasterUserPassword": MASKED_LINE
        }

    def test_a_properties_snippet_is_masked_whole(self):
        model = _results(
            _result(
                "SECRET-KEYWORD",
                "app.py",
                2,
                "Secret of type 'Keyword' detected",
                "detect-secrets",
                extra={"properties": {"snippet": ASSIGN_LINE}},
            )
        )

        mask_secrets_in_results(model)

        assert getattr(_first(model).properties, "snippet") == MASKED_LINE + "\n"

    def test_a_fix_of_a_secret_finding_is_masked_whole(self):
        model = _results(
            _result(
                "SECRET-KEYWORD",
                "app.py",
                2,
                "Secret of type 'Keyword' detected",
                "detect-secrets",
                extra={"fixes": [_fix("app.py", 2, ASSIGN_LINE, REPLACEMENT_LINE)]},
            )
        )

        mask_secrets_in_results(model)

        replacement = _replacement(_first(model))
        assert replacement.deletedRegion.snippet.text == MASKED_LINE + "\n"
        assert replacement.insertedContent.text == MASKED_LINE + "\n"

    def test_a_fenced_block_in_the_message_is_masked(self):
        """The flat model reads the first fenced block as the finding's code. The
        info string is a line of the block like any other and is masked with it,
        on purpose: it is text the scanner wrote after the fence and can hold
        anything."""
        model = _results(
            _result(
                "SECRET-KEYWORD",
                "app.py",
                2,
                "Secret of type 'Keyword' detected\n\n```python\n"
                + ASSIGN_LINE
                + "```",
                "detect-secrets",
            )
        )

        mask_secrets_in_results(model)

        text = _first(model).message.root.text
        assert text == (
            "Secret of type 'Keyword' detected\n\n```"
            + (MASKED_LINE + "\n") * 2
            + "```"
        )

    def test_every_fenced_block_in_the_message_is_masked(self):
        """The flat model reads the first fenced block as the finding's code, but
        the Markdown and HTML reports render the whole message: a secret in the
        second block is masked as well as one in the first."""
        model = _results(
            _result(
                "SECRET-KEYWORD",
                "app.py",
                2,
                "Secret of type 'Keyword' detected\n\n```python\n"
                + OTHER_LINE
                + "```\n\nand again\n\n```python\n"
                + ASSIGN_LINE
                + "```",
                "detect-secrets",
            )
        )

        mask_secrets_in_results(model)

        text = _first(model).message.root.text
        two_lines = (MASKED_LINE + "\n") * 2
        assert text == (
            "Secret of type 'Keyword' detected\n\n```"
            + two_lines
            + "```\n\nand again\n\n```"
            + two_lines
            + "```"
        )

    def test_the_markdown_and_arguments_of_the_message_are_masked(self):
        """A value that does not propagate is still masked in its own message,
        in every form the message carries it."""
        model = _results(
            _result(
                "B105",
                "app.py",
                2,
                HARDCODED + "'" + WORD + "'",
                "bandit",
                extra={
                    "message": {
                        "text": HARDCODED + "'" + WORD + "'",
                        "markdown": "Finding: "
                        + HARDCODED
                        + "'"
                        + WORD
                        + "' in a module",
                        "arguments": [WORD],
                    }
                },
            )
        )

        mask_secrets_in_results(model)

        root = _first(model).message.root
        masked = _mask_secret_value(WORD)
        assert root.text == HARDCODED + "'" + masked + "'"
        assert root.markdown == "Finding: " + HARDCODED + "'" + masked + "' in a module"
        assert root.arguments == [masked]

    def test_every_leaf_of_the_resource_is_masked_whatever_its_key(self):
        """The resource is the finding's own excerpt: an embedded document's
        lowercase ``uri`` (an OpenAPI body) and a number are leaves of it too,
        not identifiers worth keeping."""
        resource = {
            "Type": "AWS::ApiGateway::RestApi",
            "Properties": {
                "Body": {
                    "paths": {"/": {"uri": "https://user:" + PLAINTEXT + "@host"}}
                },
                "Port": 5432,
                "Enabled": True,
            },
        }
        model = _results(
            _result(
                "AwsSolutions-APIG-1",
                "template.yaml",
                3,
                "The API password must not be a plaintext string.",
                "cdk-nag",
                extra={"properties": {"cfn_resource": resource}},
            )
        )

        mask_secrets_in_results(model)

        masked = getattr(_first(model).properties, "cfn_resource")
        assert masked["Properties"]["Body"]["paths"]["/"]["uri"] == MASKED_LINE
        assert masked["Properties"]["Port"] == MASKED_LINE
        assert masked["Properties"]["Enabled"] is True
        assert PLAINTEXT not in json.dumps(masked)

    def test_every_leaf_of_a_list_in_the_resource_is_masked(self):
        """A plaintext credential often sits in a list: an ECS container's
        environment is a list of name and value maps, its command a list of
        strings."""
        resource = {
            "Type": "AWS::ECS::TaskDefinition",
            "Properties": {
                "ContainerDefinitions": [
                    {
                        "Environment": [{"Name": "DB_USER", "Value": PLAINTEXT}],
                        "Command": ["--password", PLAINTEXT],
                    }
                ]
            },
        }
        model = _results(
            _result(
                "AwsSolutions-ECS-1",
                "template.yaml",
                3,
                "The task password must not be a plaintext string.",
                "cdk-nag",
                extra={"properties": {"cfn_resource": resource}},
            )
        )

        mask_secrets_in_results(model)

        masked = getattr(_first(model).properties, "cfn_resource")
        container = masked["Properties"]["ContainerDefinitions"][0]
        assert container["Environment"] == [{"Name": MASKED_LINE, "Value": MASKED_LINE}]
        assert container["Command"] == [MASKED_LINE, MASKED_LINE]
        assert PLAINTEXT not in json.dumps(masked)

    def test_a_fenced_block_with_no_closing_fence_is_masked_to_the_end(self):
        """A message cut short after its opening fence is still a code block to
        the reports."""
        model = _results(
            _result(
                "SECRET-KEYWORD",
                "app.py",
                2,
                "Secret of type 'Keyword' detected\n\n```python\n" + ASSIGN_LINE,
                "detect-secrets",
            )
        )

        mask_secrets_in_results(model)

        text = _first(model).message.root.text
        assert VALUE not in text
        assert text == (
            "Secret of type 'Keyword' detected\n\n```"
            + MASKED_LINE
            + "\n"
            + MASKED_LINE
            + "\n"
        )

    def test_a_tilde_fenced_block_in_the_message_is_masked(self):
        model = _results(
            _result(
                "SECRET-KEYWORD",
                "app.py",
                2,
                "Secret of type 'Keyword' detected\n\n~~~\n" + ASSIGN_LINE + "~~~",
                "detect-secrets",
            )
        )

        mask_secrets_in_results(model)

        text = _first(model).message.root.text
        assert VALUE not in text
        assert (
            text == "Secret of type 'Keyword' detected\n\n~~~\n" + MASKED_LINE + "\n~~~"
        )


class TestAnOverlappingFindingsSourceText:
    def _secret(self):
        return _result(
            "SECRET-KEYWORD",
            "app.py",
            2,
            "Secret of type 'Keyword' detected",
            "detect-secrets",
        )

    def test_a_properties_snippet_at_a_reported_line_is_masked(self):
        model = _results(
            self._secret(),
            _result(
                "B404",
                "app.py",
                2,
                "import",
                "bandit",
                extra={"properties": {"snippet": ASSIGN_LINE}},
            ),
        )

        mask_secrets_in_results(model)

        neighbor = model.sarif.runs[0].results[1]
        assert getattr(neighbor.properties, "snippet") == MASKED_LINE + "\n"

    def test_a_fix_at_a_reported_line_is_masked(self):
        model = _results(
            self._secret(),
            _result(
                "B404",
                "app.py",
                5,
                "import",
                "bandit",
                extra={"fixes": [_fix("app.py", 2, ASSIGN_LINE, REPLACEMENT_LINE)]},
            ),
        )

        mask_secrets_in_results(model)

        replacement = _replacement(model.sarif.runs[0].results[1])
        assert replacement.deletedRegion.snippet.text == MASKED_LINE + "\n"
        assert replacement.insertedContent.text == MASKED_LINE + "\n"

    def test_a_fix_and_a_snippet_away_from_every_reported_line_are_kept(self):
        """Control."""
        model = _results(
            self._secret(),
            _result(
                "B404",
                "app.py",
                9,
                "import",
                "bandit",
                extra={
                    "properties": {"snippet": OTHER_LINE},
                    "fixes": [_fix("app.py", 9, OTHER_LINE, "import sys\n")],
                },
            ),
        )

        mask_secrets_in_results(model)

        neighbor = model.sarif.runs[0].results[1]
        assert getattr(neighbor.properties, "snippet") == OTHER_LINE
        replacement = _replacement(neighbor)
        assert replacement.deletedRegion.snippet.text == OTHER_LINE
        assert replacement.insertedContent.text == "import sys\n"

    def test_a_fenced_block_of_a_finding_at_a_reported_line_is_masked_whole(self):
        """A detect-secrets finding exposes no value, so the line it reports is
        masked by position: a neighbor's fenced block quoting that line has no
        line numbers to place it by and is masked whole."""
        model = _results(
            self._secret(),
            _result(
                "B404",
                "app.py",
                2,
                "import\n\n```python\n" + ASSIGN_LINE + "```",
                "bandit",
            ),
        )

        mask_secrets_in_results(model)

        text = model.sarif.runs[0].results[1].message.root.text
        assert text == "import\n\n```" + (MASKED_LINE + "\n") * 2 + "```"

    def test_a_fenced_block_away_from_every_reported_line_is_kept(self):
        """Control."""
        model = _results(
            self._secret(),
            _result(
                "B404",
                "app.py",
                9,
                "import\n\n```python\n" + OTHER_LINE + "```",
                "bandit",
            ),
        )

        mask_secrets_in_results(model)

        text = model.sarif.runs[0].results[1].message.root.text
        assert text == "import\n\n```python\n" + OTHER_LINE + "```"

    @pytest.mark.parametrize("line", [3, 4])
    def test_a_fenced_block_quoting_context_around_its_finding_is_masked(self, line):
        """The secret is on line 2 and its finding quotes no value. A neighbor on
        line 3 or 4 quotes three lines of context in its message, the secret's
        line among them, and the block has no line numbers to place it by: a
        block of several lines reaches the lines around its finding's own."""
        block = "```python\n" + OTHER_LINE + ASSIGN_LINE + "x = 1\n" + "```"
        model = _results(
            self._secret(),
            _result("B404", "app.py", line, "import\n\n" + block, "bandit"),
        )

        mask_secrets_in_results(model)

        text = model.sarif.runs[0].results[1].message.root.text
        assert VALUE not in text
        assert MASKED_LINE in text

    def test_a_fenced_block_of_several_lines_away_from_the_secret_is_kept(self):
        """Control: the same block on line 9 cannot reach line 2."""
        block = "```python\n" + OTHER_LINE + ASSIGN_LINE + "x = 1\n" + "```"
        model = _results(
            self._secret(),
            _result("B404", "app.py", 9, "import\n\n" + block, "bandit"),
        )

        mask_secrets_in_results(model)

        text = model.sarif.runs[0].results[1].message.root.text
        assert text == "import\n\n" + block

    def test_a_long_example_in_a_message_does_not_reach_a_distant_secret(self):
        """A neighbor on line 20 whose message holds a 40-line example: the block
        is no context quote of line 2 (eighteen lines away), so the message, and
        with it the finding's ID, is left as written. Uncapped, the block's
        reach of 40 lines took in line 2 and every block in the message was
        masked."""
        block = "```python\n" + "x = 1\n" * 40 + "```"
        message = "import\n\n" + block
        model = _results(
            self._secret(),
            _result("B404", "app.py", 20, message, "bandit"),
        )

        mask_secrets_in_results(model)

        assert model.sarif.runs[0].results[1].message.root.text == message

    def test_a_long_example_in_a_message_still_reaches_a_near_secret(self):
        """Control: the same message on line 9, seven lines from line 2, is within
        the cap and is masked whole, as a block of several lines near the secret
        always was."""
        block = "```python\n" + "x = 1\n" * 40 + "```"
        model = _results(
            self._secret(),
            _result("B404", "app.py", 9, "import\n\n" + block, "bandit"),
        )

        mask_secrets_in_results(model)

        text = model.sarif.runs[0].results[1].message.root.text
        assert text == "import\n\n```" + (MASKED_LINE + "\n") * 41 + "```"

    def test_a_snippet_with_more_lines_than_its_region_is_masked_whole(self):
        """A tool's properties.snippet can carry context lines above the region;
        numbered from the region's first line the secret line escapes the range,
        so a snippet that cannot be placed is masked whole when any line it could
        cover is one a secret finding reports."""
        placeholder_line = WORD + " = " + PLAINTEXT + "\n"
        model = _results(
            self._secret(),
            _result(
                "B404",
                "app.py",
                3,
                "import",
                "bandit",
                extra={
                    "properties": {"snippet": OTHER_LINE + placeholder_line + "x = 1\n"}
                },
            ),
        )

        mask_secrets_in_results(model)

        neighbor = model.sarif.runs[0].results[1]
        assert getattr(neighbor.properties, "snippet") == (MASKED_LINE + "\n") * 3

    def test_a_snippet_with_more_lines_than_its_region_away_from_the_secret_is_kept(
        self,
    ):
        """Control: every line the snippet could cover is away from the reported one."""
        snippet = OTHER_LINE + "x = 1\n" + "y = 2\n"
        model = _results(
            self._secret(),
            _result(
                "B404",
                "app.py",
                9,
                "import",
                "bandit",
                extra={"properties": {"snippet": snippet}},
            ),
        )

        mask_secrets_in_results(model)

        neighbor = model.sarif.runs[0].results[1]
        assert getattr(neighbor.properties, "snippet") == snippet

    @pytest.mark.parametrize(
        ("region_line", "masked_whole"),
        [(1, True), (2, True), (3, True), (4, True), (5, False)],
    )
    def test_the_window_of_a_snippet_with_more_lines_than_its_region_has_two_edges(
        self, region_line, masked_whole
    ):
        """The secret is on line 2 and the snippet has three lines for a one-line
        region, so the snippet could start two lines above the region or run two
        lines below it: regions at lines 1 to 4 reach the secret line (the window
        runs from the region's line less two to its line plus two), the region
        at line 5 does not. A window of one line above, or none below, lets the
        snippets at lines 4 and 1 keep the secret line."""
        snippet = OTHER_LINE + "x = 1\n" + "y = 2\n"
        model = _results(
            self._secret(),
            _result(
                "B404",
                "app.py",
                region_line,
                "import",
                "bandit",
                extra={"properties": {"snippet": snippet}},
            ),
        )

        mask_secrets_in_results(model)

        shown = getattr(model.sarif.runs[0].results[1].properties, "snippet")
        assert shown == ((MASKED_LINE + "\n") * 3 if masked_whole else snippet)

    def _two_locations(self, second_uri, second_line):
        """A result whose snippet is harmless code, with a second location."""
        result = _result(
            "B404",
            "lib.py",
            4,
            "import",
            "bandit",
            extra={"properties": {"snippet": OTHER_LINE}},
        )
        result["locations"].append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": second_uri},
                    "region": {"startLine": second_line, "endLine": second_line},
                }
            }
        )
        return _results(self._secret(), result)

    def test_a_snippet_is_masked_when_a_later_location_is_on_a_secret_line(self):
        """Which location a ``properties.snippet`` belongs to depends on the tool,
        so a result whose second location is exactly the line a secret finding
        reports has its snippet masked whole, as the suite does wherever a
        placement is unclear."""
        model = self._two_locations("app.py", 2)

        mask_secrets_in_results(model)

        neighbor = model.sarif.runs[0].results[1]
        assert getattr(neighbor.properties, "snippet") == MASKED_LINE + "\n"

    def test_a_snippet_is_kept_when_no_location_is_on_a_secret_line(self):
        """Control: the second location is in the secret's file, away from its
        line."""
        model = self._two_locations("app.py", 9)

        mask_secrets_in_results(model)

        neighbor = model.sarif.runs[0].results[1]
        assert getattr(neighbor.properties, "snippet") == OTHER_LINE

    def test_a_snippet_is_kept_when_a_later_location_is_in_another_file(self):
        """Control: a file with no secret finding says nothing about the snippet."""
        model = self._two_locations("other.py", 2)

        mask_secrets_in_results(model)

        neighbor = model.sarif.runs[0].results[1]
        assert getattr(neighbor.properties, "snippet") == OTHER_LINE

    def _context_snippet_with_two_locations(self, second_uri, second_line):
        """A result whose first location is in a file with no secret finding and
        whose three-line snippet is the first lines of the second location's
        file, the second line being the one the secret finding reports."""
        result = _result(
            "B404",
            "lib.py",
            4,
            "import",
            "bandit",
            extra={"properties": {"snippet": OTHER_LINE + ASSIGN_LINE + "x = 1\n"}},
        )
        result["locations"].append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": second_uri},
                    "region": {"startLine": second_line, "endLine": second_line},
                }
            }
        )
        return _results(self._secret(), result)

    def test_a_snippet_with_context_lines_is_masked_by_a_later_locations_window(self):
        """The snippet has two more lines than the second location's region, so
        it could start two lines above that region or run two lines below it,
        the same window the first location gets. The second location is on line
        3 and the secret on line 2: the location itself is not on a reported
        line, but the snippet could be."""
        model = self._context_snippet_with_two_locations("app.py", 3)

        mask_secrets_in_results(model)

        shown = getattr(model.sarif.runs[0].results[1].properties, "snippet")
        assert VALUE not in shown
        assert shown == (MASKED_LINE + "\n") * 3

    def test_a_snippet_with_context_lines_is_kept_beyond_a_later_locations_window(
        self,
    ):
        """Control: the second location is on line 9, so the snippet's window
        runs from line 7 to line 11 and cannot reach line 2."""
        model = self._context_snippet_with_two_locations("app.py", 9)

        mask_secrets_in_results(model)

        shown = getattr(model.sarif.runs[0].results[1].properties, "snippet")
        assert shown == OTHER_LINE + ASSIGN_LINE + "x = 1\n"

    def test_a_snippet_with_context_lines_is_kept_for_a_later_location_elsewhere(
        self,
    ):
        """Control: a file with no secret finding says nothing about the snippet,
        however many context lines it has."""
        model = self._context_snippet_with_two_locations("other.py", 3)

        mask_secrets_in_results(model)

        shown = getattr(model.sarif.runs[0].results[1].properties, "snippet")
        assert shown == OTHER_LINE + ASSIGN_LINE + "x = 1\n"
