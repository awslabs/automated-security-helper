# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which environment variables an ASH config file may interpolate.

``AshConfig.from_file`` resolves ``${VAR:default}`` references in YAML. The
file it resolves them in is the project config, whose names are
``ASH_CONFIG_FILE_NAMES`` and which lives in the tree being scanned -- so the
set of names a config may name is a property of ASH, not of the config. These
tests pin that set from both sides: the names that must keep resolving because
the docs and ASH's own config use them, and the names that must not.

The resolved value is not confined to the field it lands in.
``AshAggregatedResults.ash_config`` carries the whole resolved config, and
``to_simple_dict`` writes it into ``ash_aggregated_results.json``; a
suppression ``reason`` additionally reaches ``ash.unused-suppressions.md`` via
``unused_suppressions_reporter``. That is why the bound is on the name at
resolution time rather than on any individual field: there is no field whose
value stays out of the output.

Fixture values here are obviously-not-credentials placeholder strings. Two
tests name credential-shaped *variables* -- the name, never a value -- because
naming them is the point of the assertion.
"""

import re

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    config_env_var_is_interpolatable,
)
from automated_security_helper.core.constants import (
    ASH_CONFIG_ENV_VAR_ALLOWLIST,
    ASH_CONFIG_ENV_VAR_PREFIX,
)

PLACEHOLDER = "ash-test-placeholder-value"

# The reference form the docs and ASH's own config use. The bare ``${VAR}``
# spelling does not resolve at all -- ``constructor_env_variables`` rebuilds the
# text to replace as ``":".join(group)``, which appends a colon the bare form
# never wrote -- so a test written against it would pass for the wrong reason.
REFERENCE = "${{{name}:None}}"


def _load(tmp_path, body: str) -> AshConfig:
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(body)
    return AshConfig.from_file(config_file)


class TestUnlistedNamesAreNotResolved:
    """A name outside the allowlist is left as written."""

    def test_arbitrary_name_is_not_resolved(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DEMO_UNLISTED_CONFIG_VAR", PLACEHOLDER)
        config = _load(
            tmp_path,
            f"project_name: {REFERENCE.format(name='DEMO_UNLISTED_CONFIG_VAR')}\n",
        )
        assert PLACEHOLDER not in config.project_name, (
            "an unlisted environment variable was resolved into project_name, "
            "which to_simple_dict writes into ash_aggregated_results.json"
        )
        assert config.project_name == "${DEMO_UNLISTED_CONFIG_VAR:None}", (
            "an unresolved reference must be left exactly as written, so that a "
            "typed field refuses it and an untyped one carries the literal"
        )

    def test_credential_named_variable_is_not_resolved(self, tmp_path, monkeypatch):
        # The variable NAME, with a placeholder value. Nothing here is a secret.
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", PLACEHOLDER)
        config = _load(
            tmp_path,
            f"project_name: {REFERENCE.format(name='AWS_SECRET_ACCESS_KEY')}\n",
        )
        assert PLACEHOLDER not in config.project_name

    def test_suppression_reason_is_not_a_second_route(self, tmp_path, monkeypatch):
        """``reason`` reaches ash.unused-suppressions.md, so it needs the bound too.

        It gets it for free -- the bound is applied once, in the constructor,
        before any field knows its own name -- and this test is what keeps that
        true if the check is ever moved to a per-field validator.
        """
        monkeypatch.setenv("DEMO_UNLISTED_CONFIG_VAR", PLACEHOLDER)
        reference = REFERENCE.format(name="DEMO_UNLISTED_CONFIG_VAR")
        config = _load(
            tmp_path,
            "global_settings:\n"
            "  suppressions:\n"
            "    - rule_id: SOME-RULE\n"
            "      path: app.py\n"
            f"      reason: {reference}\n",
        )
        assert config.global_settings.suppressions[0].reason == reference

    def test_lowercase_spelling_of_a_credential_name_is_not_resolved(
        self, tmp_path, monkeypatch
    ):
        """A differently-cased credential name is refused, like any other name.

        This goes through the loader rather than the predicate because the
        predicate is easy to get right in isolation and easy to bypass by
        resolving before consulting it.
        """
        monkeypatch.setenv("aws_secret_access_key", PLACEHOLDER)
        config = _load(
            tmp_path,
            f"project_name: {REFERENCE.format(name='aws_secret_access_key')}\n",
        )
        assert PLACEHOLDER not in config.project_name

    def test_prefix_must_be_a_prefix_not_a_substring(self):
        assert not config_env_var_is_interpolatable("NOT_ASH_SECRET")
        assert not config_env_var_is_interpolatable("MY_ASH_TOKEN")

    @pytest.mark.parametrize(
        "written,expected",
        [
            ("ASH_FOO", True),
            ("ash_foo", False),
            ("Ash_Foo", False),
            ("AWS_REGION", True),
            ("aws_region", False),
            ("Aws_Region", False),
        ],
    )
    def test_check_is_on_the_name_exactly_as_written(self, written, expected):
        """No case folding, in either direction.

        Pinning this is what makes the docstring's Windows paragraph auditable:
        an author who reintroduces ``.upper()`` has to come here and argue for
        it, and gets the argument that was already tried and withdrawn. It also
        pins the consequence -- on Windows ``aws_region`` will not resolve -- as
        a decision rather than an oversight.
        """
        assert config_env_var_is_interpolatable(written) is expected


class TestDocumentedNamesStillResolve:
    """The cases the docs and ASH's own config depend on must keep working."""

    def test_ash_prefixed_name_resolves(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_TEST_INTERPOLATION_PROBE", PLACEHOLDER)
        config = _load(
            tmp_path,
            f"project_name: {REFERENCE.format(name='ASH_TEST_INTERPOLATION_PROBE')}\n",
        )
        assert config.project_name == PLACEHOLDER

    @pytest.mark.parametrize(
        "name", ["AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE"]
    )
    def test_documented_aws_locator_names_resolve(self, tmp_path, monkeypatch, name):
        """``docs/plugins/aws/s3-reporter.md`` and ASH's own ``.ash/.ash.yaml``
        name these, and none of the three carries a credential."""
        monkeypatch.setenv(name, PLACEHOLDER)
        config = _load(tmp_path, f"project_name: {REFERENCE.format(name=name)}\n")
        assert config.project_name == PLACEHOLDER

    def test_explicit_env_tag_resolves_the_same_way(self, tmp_path, monkeypatch):
        """The docs write the tag; the implicit resolver makes it optional.

        Both spellings reach the same constructor, so both get the same bound.
        This test is here because the docs' spelling is the tagged one and a
        change that only covered the untagged one would look correct.
        """
        monkeypatch.setenv("ASH_TEST_INTERPOLATION_PROBE", PLACEHOLDER)
        config = _load(
            tmp_path,
            "project_name: !ENV ${ASH_TEST_INTERPOLATION_PROBE:None}\n",
        )
        assert config.project_name == PLACEHOLDER

    def test_unset_allowlisted_name_still_falls_back_to_its_default(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("ASH_TEST_INTERPOLATION_PROBE", raising=False)
        config = _load(
            tmp_path,
            "project_name: ${ASH_TEST_INTERPOLATION_PROBE:fallback-name}\n",
        )
        assert config.project_name == "fallback-name"


class TestAshOwnConfigStaysLoadable:
    """Every reference ASH's own config writes must be one ASH still resolves.

    ``.ash/.ash.yaml`` carries the reporter examples operators copy, including
    commented-out ones. If the allowlist and that file ever disagree, the file
    is the thing that breaks, so this reads the file rather than restating it.
    """

    def test_every_reference_in_ash_own_config_is_allowlisted(self):
        config_text = (
            __import__("pathlib")
            .Path(__file__)
            .parents[3]
            .joinpath(".ash", ".ash.yaml")
            .read_text(encoding="utf-8")
        )
        referenced = set(re.findall(r"\$\{(\w+):", config_text))
        assert referenced, (
            "expected .ash/.ash.yaml to still carry the reporter examples that "
            "reference environment variables"
        )
        unlisted = sorted(
            n for n in referenced if not config_env_var_is_interpolatable(n)
        )
        assert unlisted == [], (
            f"{unlisted} appear in ASH's own config but would no longer resolve. "
            f"Either add them to ASH_CONFIG_ENV_VAR_ALLOWLIST or rename them "
            f"with the {ASH_CONFIG_ENV_VAR_PREFIX} prefix."
        )

    def test_allowlist_holds_only_names_that_locate_rather_than_authenticate(self):
        """A guard on the allowlist itself, since growing it is the easy mistake.

        Every entry names a region or a profile -- a *where*, not a *with what*.
        A reader adding an entry has to justify it against that sentence, and a
        name ending in KEY, TOKEN, SECRET or PASSWORD cannot be.
        """
        for name in ASH_CONFIG_ENV_VAR_ALLOWLIST:
            assert not re.search(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", name), (
                f"{name} does not belong in the config interpolation allowlist"
            )
