# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The constants module's name rules agree with themselves, and the scannable
extensions cover credential-bearing files.

Three defects, each pinned by a test red on the tree that carried it:

* The config loader's ``!ENV`` exclusion (the secret suffixes) was narrower than
  the module's own secret-shaped reading, which masks stream output, so a config
  file could interpolate names the same module classes as secret carriers.
  ``is_refused_config_environment_name`` is the one rule, and it reads all three.
* ``is_secret_shaped_environment_name`` missed a glued secret word followed by a
  separate qualifier segment (``ASH_GITHUBTOKEN_2``, ``ASH_DBPASSWORD_PROD``) and
  a stage word glued to a digit run (``ASH_DB_PASSWORD_PROD2``), although its
  docstring promised both.
* ``KNOWN_SCANNABLE_EXTENSIONS`` omitted ``pem``, ``key``, ``npmrc``, ``config``,
  ``mjs`` and ``cjs``, so the archive converter never extracted such a member
  and detect-secrets never read it.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.constants import (
    KNOWN_SCANNABLE_EXTENSIONS,
    is_refused_config_environment_name,
    is_secret_shaped_environment_name,
)

pytestmark = pytest.mark.unit


def test_a_dotfile_member_named_by_its_extension_is_scannable():
    """``"npmrc"`` in KNOWN_SCANNABLE_EXTENSIONS reaches a ``.npmrc`` member: the
    archive matcher reads a member's extension as the text after the last dot
    (``_archive_suffix``), not as ``Path.suffix``, which is empty for a dotfile.
    Pinned because a matcher that switched to ``Path.suffix`` would leave the
    entry dead with no test red."""
    from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
        _archive_suffix,
        _member_is_scannable,
    )

    assert "npmrc" in KNOWN_SCANNABLE_EXTENSIONS
    assert _archive_suffix(".npmrc") == "npmrc"
    assert _member_is_scannable(".npmrc") is True
    assert _member_is_scannable("pkg/.npmrc") is True
    # The control: a dotfile named by no entry or stem is not admitted.
    assert _member_is_scannable(".zz-planted-unknown") is False


@pytest.mark.parametrize(
    "name",
    [
        "ASH_DB_PASS",
        "ASH_GITHUB_PAT",
        "ASH_API_KEY_PROD",
        "ASH_API_KEY2",
        "ASH_APIKEY",
        "ASH_X_PASSPHRASE",
        "ASH_X_SECRETS",
        "ASH_X_KEYS",
        "ASH_X_TOKENS",
        "ASH_X_PASSWD",
        "ASH_X_PASSWORD_2",
        "ASH_GITHUBTOKEN",
        "ASH_DEPLOY_PAT",
        "ASH_X_AUTH",
        "ASH_MCP_AUTH_HEADER_VALUE",
    ],
)
def test_a_name_the_masking_rule_classes_as_a_secret_is_refused_to_a_config(name):
    # Red at the base: the function did not exist; the loader's suffix test
    # admitted every one of these but the last.
    assert is_refused_config_environment_name(name) is True


@pytest.mark.parametrize("name", ["ASH_OUTPUT_DIR", "ASH_LOG_LEVEL", "ASH_COMPAT"])
def test_a_plain_name_is_still_readable(name):
    assert is_refused_config_environment_name(name) is False


@pytest.mark.parametrize(
    "name", ["ASH_BEDROCK_MAX_TOKENS", "ash_bedrock_max_tokens", "ASH_X_MAX_TOKENS"]
)
def test_a_limit_named_after_the_word_is_readable(name):
    """The setting the Bedrock summary reporter reads for ``max_tokens``.

    Red at the base: ``_TOKENS`` is a listed suffix, and the masking rule's
    ends-with reading matches ``TOKENS`` too, so the one rule refused it and the
    loader that follows the rule left ``${ASH_BEDROCK_MAX_TOKENS}`` as written.
    """
    assert is_refused_config_environment_name(name) is False


@pytest.mark.parametrize("name", ["ASH_API_TOKENS", "ASH_X_TOKENS", "ASH_MAX_TOKEN"])
def test_the_control_a_token_name_without_the_limit_word_stays_refused(name):
    """A plural token name without ``MAX`` before it, and the singular, are
    still a credential's names: the allow is the limit's shape, not the word."""
    assert is_refused_config_environment_name(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "ASH_GITHUBTOKEN_2",
        "ASH_DBPASSWORD_PROD",
        "ASH_AWSSECRETACCESSKEY_PROD",
        "ASH_DB_PASSWORD_PROD2",
        "ASH_API_KEY_PROD2",
    ],
)
def test_a_glued_word_or_a_glued_stage_digit_qualifier_is_secret_shaped(name):
    # Red at the base: the ends-with reading saw the qualifier, and the
    # segment-run reading read PROD2 as not a qualifier.
    assert is_secret_shaped_environment_name(name) is True


@pytest.mark.parametrize(
    "name", ["ASH_AUTH_ENABLED", "ASH_PASS_THRESHOLD", "ASH_COMPAT_2", "ASH_TEST"]
)
def test_the_documented_non_matches_still_do_not_match(name):
    """The control: a flag or a limit named after the word, and the denylist."""
    assert is_secret_shaped_environment_name(name) is False


@pytest.mark.parametrize("extension", ["pem", "key", "npmrc", "config", "mjs", "cjs"])
def test_credential_bearing_and_module_extensions_are_scannable(extension):
    # Red at the base: none of these was in the list.
    assert extension in KNOWN_SCANNABLE_EXTENSIONS
