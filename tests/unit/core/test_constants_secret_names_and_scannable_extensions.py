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
