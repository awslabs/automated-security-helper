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
    resolve_env_references,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import (
    ASH_CONFIG_ENV_VAR_ALLOWLIST,
    ASH_CONFIG_ENV_VAR_PREFIX,
)
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)

PLACEHOLDER = "ash-test-placeholder-value"

# The reference form the docs and ASH's own config use. The bare ``${VAR}``
# form has its own tests in TestBareReference below; the bound on names applies
# to both forms, and the tests above that class use this one.
REFERENCE = "${{{name}:None}}"
BARE_REFERENCE = "${{{name}}}"


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


class TestBareReference:
    """``${VAR}`` with no default resolves like ``${VAR:default}`` does.

    It used to be left exactly as written whatever the environment held, because
    the text to replace was rebuilt as ``":".join(groups)``, which appended a
    colon the bare form never wrote. The bound on names is unchanged: a bare
    reference reads only what the default form may read, and an unlisted name
    is left as written before the environment is consulted at all.
    """

    PROBE = "ASH_TEST_INTERPOLATION_PROBE"

    def test_bare_reference_resolves_when_set(self, tmp_path, monkeypatch):
        monkeypatch.setenv(self.PROBE, PLACEHOLDER)
        config = _load(
            tmp_path, f"project_name: {BARE_REFERENCE.format(name=self.PROBE)}\n"
        )
        assert config.project_name == PLACEHOLDER

    def test_bare_reference_with_env_tag_resolves(self, tmp_path, monkeypatch):
        monkeypatch.setenv(self.PROBE, PLACEHOLDER)
        config = _load(tmp_path, f"project_name: !ENV ${{{self.PROBE}}}\n")
        assert config.project_name == PLACEHOLDER

    def test_bare_reference_resolves_in_toml(self, tmp_path, monkeypatch):
        monkeypatch.setenv(self.PROBE, PLACEHOLDER)
        config_file = tmp_path / "ash.toml"
        config_file.write_text(f'project_name = "${{{self.PROBE}}}"\n')
        assert AshConfig.from_file(config_file).project_name == PLACEHOLDER

    def test_bare_reference_resolves_in_pyproject(self, tmp_path, monkeypatch):
        monkeypatch.setenv(self.PROBE, PLACEHOLDER)
        config_file = tmp_path / "pyproject.toml"
        config_file.write_text(f'[tool.ash]\nproject_name = "${{{self.PROBE}}}"\n')
        assert AshConfig.from_file(config_file).project_name == PLACEHOLDER

    @pytest.mark.parametrize(
        "name", ["AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE"]
    )
    def test_allowlisted_aws_names_resolve(self, tmp_path, monkeypatch, name):
        monkeypatch.setenv(name, PLACEHOLDER)
        config = _load(tmp_path, f"project_name: {BARE_REFERENCE.format(name=name)}\n")
        assert config.project_name == PLACEHOLDER

    def test_a_suffix_after_the_reference_is_kept(self, tmp_path, monkeypatch):
        """The default form already allowed text after the reference; so does this."""
        monkeypatch.setenv(self.PROBE, PLACEHOLDER)
        config = _load(tmp_path, f"project_name: ${{{self.PROBE}}}-suffix\n")
        assert config.project_name == f"{PLACEHOLDER}-suffix"

    def test_unset_variable_is_an_error_naming_it(self, monkeypatch):
        """No default was written, so there is nothing honest to substitute.

        An empty string or ``None`` would read as "the variable was set to
        nothing", and the literal ``${VAR}`` would reach a reporter as a bucket
        or region name. Both hide the mistake; the error names it.
        """
        monkeypatch.delenv(self.PROBE, raising=False)
        with pytest.raises(ASHConfigSourceError) as excinfo:
            resolve_env_references(BARE_REFERENCE.format(name=self.PROBE))
        message = str(excinfo.value)
        assert self.PROBE in message
        assert f"${{{self.PROBE}:" in message, (
            "the error should show the default form that would accept an unset variable"
        )

    def test_unset_variable_refuses_the_config_instead_of_the_defaults(
        self, tmp_path, monkeypatch
    ):
        """``resolve_config`` re-raises, so the scan exits 3 rather than running
        with the default configuration and none of this file's suppressions."""
        monkeypatch.delenv(self.PROBE, raising=False)
        source = tmp_path / "src"
        source.mkdir()
        (source / ".ash.yaml").write_text(
            f"project_name: {BARE_REFERENCE.format(name=self.PROBE)}\n"
        )
        with pytest.raises(ASHConfigValidationError) as excinfo:
            resolve_config(source_dir=source)
        assert self.PROBE in str(excinfo.value)
        assert ".ash.yaml" in str(excinfo.value), "the error should name the file"

    def test_unset_variable_behind_an_env_tag_refuses_the_config(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.delenv(self.PROBE, raising=False)
        source = tmp_path / "src"
        source.mkdir()
        (source / ".ash.yaml").write_text(f"project_name: !ENV ${{{self.PROBE}}}\n")
        with pytest.raises(ASHConfigValidationError) as excinfo:
            resolve_config(source_dir=source)
        assert self.PROBE in str(excinfo.value)
        assert ".ash.yaml" in str(excinfo.value)

    def test_unset_variable_in_a_base_names_the_variable_not_the_base(
        self, tmp_path, monkeypatch
    ):
        """In a base, the error names the variable, and not the base's path.

        A base can be named through an environment variable, so for a reference
        in a base the error says a file in the chain holds it, and gives the
        variable as written.
        """
        monkeypatch.delenv(self.PROBE, raising=False)
        hidden = "hidden-base-dir-4242"
        monkeypatch.setenv("ASH_TEST_INTERPOLATION_BASE", f"{hidden}/base.yaml")
        source = tmp_path / "src"
        (source / hidden).mkdir(parents=True)
        (source / hidden / "base.yaml").write_text(
            f"project_name: {BARE_REFERENCE.format(name=self.PROBE)}\n"
        )
        (source / ".ash.yaml").write_text(
            "extends: ${ASH_TEST_INTERPOLATION_BASE:base.yaml}\n"
        )
        with pytest.raises(ASHConfigValidationError) as excinfo:
            resolve_config(source_dir=source)
        message = str(excinfo.value)
        assert self.PROBE in message
        assert f"${{{self.PROBE}:None}}" in message
        assert hidden not in message, message

    def test_unset_variable_with_a_default_still_falls_back(self, monkeypatch):
        """Only the bare form is strict: ``${VAR:}`` and ``${VAR:None}`` are not."""
        monkeypatch.delenv(self.PROBE, raising=False)
        assert resolve_env_references(f"${{{self.PROBE}:}}") is None
        assert resolve_env_references(f"${{{self.PROBE}:None}}") is None
        assert resolve_env_references(f"${{{self.PROBE}:fallback}}") == "fallback"

    def test_set_but_empty_variable_resolves_to_nothing(self, monkeypatch):
        """Set to the empty string is set; it resolves the way ``${VAR:}`` does."""
        monkeypatch.setenv(self.PROBE, "")
        assert resolve_env_references(BARE_REFERENCE.format(name=self.PROBE)) is None

    def test_unlisted_name_is_not_resolved_through_the_bare_form(
        self, tmp_path, monkeypatch
    ):
        """The bare form must not widen what a config can read."""
        monkeypatch.setenv("DEMO_UNLISTED_CONFIG_VAR", PLACEHOLDER)
        reference = BARE_REFERENCE.format(name="DEMO_UNLISTED_CONFIG_VAR")
        config = _load(tmp_path, f"project_name: {reference}\n")
        assert PLACEHOLDER not in config.project_name
        assert config.project_name == reference

    def test_credential_name_is_not_resolved_through_the_bare_form(
        self, tmp_path, monkeypatch
    ):
        # The variable NAME, with a placeholder value. Nothing here is a secret.
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", PLACEHOLDER)
        reference = BARE_REFERENCE.format(name="AWS_SECRET_ACCESS_KEY")
        config = _load(tmp_path, f"project_name: {reference}\n")
        assert config.project_name == reference

    def test_unset_unlisted_name_is_left_as_written_not_an_error(
        self, tmp_path, monkeypatch
    ):
        """The name check comes first, so an unlisted name never reaches the
        "is it set" question, and the error cannot be used to probe for it."""
        monkeypatch.delenv("DEMO_UNLISTED_CONFIG_VAR", raising=False)
        reference = BARE_REFERENCE.format(name="DEMO_UNLISTED_CONFIG_VAR")
        config = _load(tmp_path, f"project_name: {reference}\n")
        assert config.project_name == reference

    def test_two_bare_references_in_one_value_are_left_as_written(
        self, tmp_path, monkeypatch
    ):
        """The pattern's default group runs to the last ``}``, so ``${A}/${B}``
        reads as ``A`` with trailing text inside the braces. Without the check for
        that shape the value became A's value alone and B's half was dropped."""
        monkeypatch.setenv("ASH_TEST_FIRST", "first")
        monkeypatch.setenv("ASH_TEST_SECOND", "second")
        value = "${ASH_TEST_FIRST}/${ASH_TEST_SECOND}"
        assert resolve_env_references(value) == value
        config = _load(tmp_path, f"project_name: {value}\n")
        assert config.project_name == value

    def test_unset_variable_in_toml_names_the_file(self, tmp_path, monkeypatch):
        monkeypatch.delenv(self.PROBE, raising=False)
        config_file = tmp_path / "ash.toml"
        config_file.write_text(f'project_name = "${{{self.PROBE}}}"\n')
        with pytest.raises(ASHConfigSourceError) as excinfo:
            AshConfig.from_file(config_file)
        message = str(excinfo.value)
        assert "ash.toml" in message, message
        assert self.PROBE in message

    def test_unset_variable_in_pyproject_names_the_file(self, tmp_path, monkeypatch):
        monkeypatch.delenv(self.PROBE, raising=False)
        config_file = tmp_path / "pyproject.toml"
        config_file.write_text(f'[tool.ash]\nproject_name = "${{{self.PROBE}}}"\n')
        with pytest.raises(ASHConfigSourceError) as excinfo:
            AshConfig.from_file(config_file)
        message = str(excinfo.value)
        assert "pyproject.toml" in message, message
        assert self.PROBE in message

    @pytest.mark.parametrize(
        "written", ["${ash_test_lower_probe}", "${ash_test_lower_probe:None}"]
    )
    def test_lowercase_ash_prefix_is_not_read(self, tmp_path, monkeypatch, written):
        """The prefix is matched as written. Both spellings are set, so folding
        the name's case where it is checked (``var_name.upper()`` passed to
        ``config_env_var_is_interpolatable``) lets the lowercase name through,
        and the read that follows finds one of the two values and fails here."""
        monkeypatch.setenv("ash_test_lower_probe", "lower-" + PLACEHOLDER)
        monkeypatch.setenv("ASH_TEST_LOWER_PROBE", "upper-" + PLACEHOLDER)
        config = _load(tmp_path, f"project_name: {written}\n")
        assert config.project_name == written
