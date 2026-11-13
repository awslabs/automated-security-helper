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

import logging
import re

import pytest
import yaml

from automated_security_helper.config.ash_config import (
    AshConfig,
    config_env_var_is_interpolatable,
    resolve_env_references,
)
from automated_security_helper.config.config_sources import (
    read_config_file,
    read_config_file_literally,
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

pytestmark = pytest.mark.unit

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

    def test_an_aws_name_outside_the_shared_rule_is_not_resolved(
        self, tmp_path, monkeypatch
    ):
        """The loader admits no AWS name beyond the shared rule's three. A
        credential-bearing name that looks like the allowlisted ones is left
        as written, so its value never reaches the configuration."""
        monkeypatch.setenv("AWS_SESSION_TOKEN", PLACEHOLDER)
        config = _load(
            tmp_path,
            f"project_name: {REFERENCE.format(name='AWS_SESSION_TOKEN')}\n",
        )
        assert PLACEHOLDER not in config.project_name, (
            "a name outside the shared readable-name rule was resolved into "
            "project_name"
        )
        assert config.project_name == "${AWS_SESSION_TOKEN:None}"

    def test_the_loader_admits_exactly_the_shared_rules_names(self):
        """The loader's predicate and the shared rule answer identically, and
        the answers are pinned: the two cannot drift apart one name at a
        time, in either direction."""
        from automated_security_helper.core.constants import (
            is_readable_environment_name,
        )

        admitted = ["ASH_ANY_NAME", *ASH_CONFIG_ENV_VAR_ALLOWLIST]
        refused = [
            "AWS_SESSION_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_ACCESS_KEY_ID",
            "HOME",
            "PATH",
            "",
        ]
        for name in admitted:
            assert config_env_var_is_interpolatable(name) is True, name
            assert is_readable_environment_name(name) is True, name
        for name in refused:
            assert config_env_var_is_interpolatable(name) is False, name
            assert is_readable_environment_name(name) is False, name

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

        The prefix admits every ``ASH_`` name, including ones not written yet, so
        the same guard applies to it: whatever ``ASH_`` name ends like a
        credential's is not interpolated, and the allowlist holds none.
        """
        for name in ASH_CONFIG_ENV_VAR_ALLOWLIST:
            assert not re.search(
                r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|HEADER_VALUE)", name
            ), f"{name} does not belong in the config interpolation allowlist"
            assert not _secret_shaped(name), name
        for suffix in SECRET_SUFFIXES:
            for name in (f"ASH_ANY_FUTURE{suffix}", f"ASH_ANY_FUTURE{suffix.lower()}"):
                assert not config_env_var_is_interpolatable(name), name


# Every suffix of a name a config may not read, and the name listed on its own.
SECRET_SUFFIXES = (
    "_KEY",
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_CREDENTIAL",
    "_CREDENTIALS",
    "_HEADER_VALUE",
)
CANARY = "ash-test-canary-c8e2"


def _secret_shaped(name: str) -> bool:
    from automated_security_helper.config import ash_config

    return ash_config.config_env_var_is_secret_shaped(name)


@pytest.fixture
def log_records(monkeypatch):
    """Every record any logger is asked to log, at every level."""
    seen = []
    monkeypatch.setattr(logging.Logger, "isEnabledFor", lambda self, level: True)
    monkeypatch.setattr(
        logging.Logger, "handle", lambda self, record: seen.append(record)
    )
    return seen


class TestSecretShapedNamesAreNotResolved:
    """An ``ASH_`` name that ends like a credential's is not interpolated.

    The prefix admits every ``ASH_`` variable in the process, and an operator or
    a wrapper can export a secret under one: ``ASH_MCP_AUTH_HEADER_VALUE`` is the
    documented case, which ash-mcp-serve and ash-container-init take out of the
    environment before ASH starts because a config could read it. A name ending
    in ``_KEY``, ``_TOKEN``, ``_SECRET``, ``_PASSWORD``, ``_CREDENTIAL``,
    ``_CREDENTIALS`` or ``_HEADER_VALUE``, in any case, and that name itself, is
    left as written, as an unlisted name is, and the warning names the variable
    and why, never its value. Every other ``ASH_`` name resolves as before.
    """

    @pytest.mark.parametrize(
        "name",
        [f"ASH_PROBE{suffix}" for suffix in SECRET_SUFFIXES]
        + ["ASH_PROBE_api_token", "ASH_MCP_AUTH_HEADER_VALUE"],
    )
    @pytest.mark.parametrize(
        "form", [REFERENCE, BARE_REFERENCE], ids=["default", "bare"]
    )
    def test_a_secret_shaped_name_is_left_as_written(
        self, tmp_path, monkeypatch, log_records, name, form
    ):
        monkeypatch.setenv(name, CANARY)
        reference = form.format(name=name)

        config = _load(tmp_path, f"project_name: {reference}\n")

        assert config.project_name == reference
        assert CANARY not in config.model_dump_json()
        messages = [record.getMessage() for record in log_records]
        assert not [m for m in messages if CANARY in m], messages
        named = [m for m in messages if name in m and "credential" in m]
        assert named, messages

    def test_an_operator_config_naming_the_auth_header_value_is_refused(
        self, tmp_path, monkeypatch, log_records
    ):
        """The case the wrappers guard against, through resolution of a config
        the operator named, the way a scan resolves it."""
        monkeypatch.setenv("ASH_MCP_AUTH_HEADER_VALUE", CANARY)
        config_file = tmp_path / "operator.yaml"
        config_file.write_text(
            "project_name: ${ASH_MCP_AUTH_HEADER_VALUE:None}\n", encoding="utf-8"
        )

        config = resolve_config(config_path=config_file, source_dir=tmp_path)

        assert CANARY not in config.model_dump_json()
        assert not [r for r in log_records if CANARY in r.getMessage()]

    @pytest.mark.parametrize(
        "name",
        [
            "ASH_PROBE_CANARY",
            # Like a suffix, but not one: the setting ASH reads for Bedrock.
            "ASH_BEDROCK_MAX_TOKENS",
            "ASH_KEYS_DIR",
            "ASH_S3_BUCKET_NAME",
            "AWS_REGION",
        ],
    )
    def test_control_other_names_still_resolve(self, tmp_path, monkeypatch, name):
        monkeypatch.setenv(name, CANARY)

        config = _load(tmp_path, f"project_name: {REFERENCE.format(name=name)}\n")

        assert config.project_name == CANARY
        assert config_env_var_is_interpolatable(name)
        assert not _secret_shaped(name)


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
        """``${A}/${B}``: the first reference has no colon and another closing
        brace follows it, so the resolver leaves the value as written. Without
        the check for that shape the value became A's value alone and B's half
        was dropped. (The pattern once read the default up to the last ``}``,
        which made this shape a reference with text inside its braces; it now
        ends at the first brace, and the text after the match is tested.)"""
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


class TestOneReferencePerValueAtItsStart:
    """A value holds one reference, at its start; anything else is the value's text.

    The contract, pinned here (no page of docs/ states it; the file an earlier
    docstring cited does not exist): a reference is ``${VAR}`` or
    ``${VAR:default}`` and ends at the brace that pairs with its opening one (a
    default may hold brace pairs, see test_a_default_holding_braces_is_read_whole),
    a reference after other text is not resolved, a second reference is not
    resolved, and a first reference followed by another closing brace
    (``${A}/${B}``, ``${A:x}${B}``) is left as written whether or not it wrote a
    default (test_a_reference_followed_by_another_brace_is_left_as_written).
    These tests pin each shape, so the behavior stays a deliberate choice.
    """

    def test_two_adjacent_references_are_left_as_written(self, tmp_path, monkeypatch):
        """``${A}${B}``, like ``${A}/${B}``: a second reference is not resolved,
        and the first, with no colon and another closing brace after it, is not
        a reference this resolver reads. Nothing is read from the environment."""
        monkeypatch.setenv("ASH_TEST_FIRST", "first")
        monkeypatch.setenv("ASH_TEST_SECOND", "second")
        value = "${ASH_TEST_FIRST}${ASH_TEST_SECOND}"
        assert resolve_env_references(value) == value
        config = _load(tmp_path, f"project_name: {value}\n")
        assert config.project_name == value

    def test_a_reference_after_other_text_is_left_as_written(
        self, tmp_path, monkeypatch
    ):
        """``prefix${A}``: the pattern is anchored at the value's start, so text
        before the reference leaves the whole value as written."""
        monkeypatch.setenv("ASH_TEST_FIRST", "first")
        value = "prefix${ASH_TEST_FIRST}"
        assert resolve_env_references(value) == value
        config = _load(tmp_path, f"project_name: {value}\n")
        assert config.project_name == value

    def test_a_second_reference_after_a_default_is_left_as_written(self, monkeypatch):
        """``${A:x}${B}``: a reference followed by another closing brace is the
        composite case whether or not it wrote a default, so the value is left
        as written, as ``${A}${B}`` is. The reference used to run to the LAST
        ``}``, which dropped the trailing text when A was set and made the
        default the garbled ``x}${B`` when it was not; a first cut then ended
        it at the first brace and resolved A around a literal ``${B}``, which a
        typed field accepts in the middle of a value where it refuses a value
        that still reads as a reference at its start."""
        monkeypatch.setenv("ASH_TEST_FIRST", "first")
        monkeypatch.delenv("ASH_TEST_UNSET", raising=False)
        assert (
            resolve_env_references("${ASH_TEST_FIRST:x}${ASH_TEST_SECOND}")
            == "${ASH_TEST_FIRST:x}${ASH_TEST_SECOND}"
        )
        assert (
            resolve_env_references("${ASH_TEST_UNSET:x}${ASH_TEST_SECOND}")
            == "${ASH_TEST_UNSET:x}${ASH_TEST_SECOND}"
        )


class TestAReferenceLeftAsItsOwnTextReadNothing:
    """A reference that resolved to its own text read nothing from the environment.

    An explicit ``!ENV ${A}${B}`` resolves to ``${A}${B}``, the value's own text
    with the tag gone: nothing was read. The run's record listed that text as a
    value read from the environment, and recorded a reference carrying A's value,
    while ``ash config validate``'s check listed nothing for the same file. Both
    views now agree with the check: no value, no reference. Hiding the text was
    safe (it is the file's own), but it put the file's text in the redaction
    list and disagreed with the check's.
    """

    @pytest.fixture
    def environment(self, monkeypatch):
        monkeypatch.setenv("ASH_TEST_FIRST", "first-value")
        monkeypatch.setenv("ASH_TEST_SECOND", "second-value")
        monkeypatch.delenv("ASH_CONFIG", raising=False)

    @pytest.mark.parametrize(
        "value",
        ["!ENV ${ASH_TEST_FIRST}${ASH_TEST_SECOND}", "!ENV prefix${ASH_TEST_FIRST}"],
        ids=["tagged-composite", "tagged-after-text"],
    )
    def test_the_run_s_record_lists_no_value_and_no_reference(
        self, tmp_path, environment, value
    ):
        from automated_security_helper.config.resolve_config import (
            load_config_file_for_run,
        )

        config_file = tmp_path / ".ash.yaml"
        config_file.write_text(f"project_name: {value}\n", encoding="utf-8")

        _document, config = load_config_file_for_run(config_file)

        assert config.project_name == value.removeprefix("!ENV ")
        assert config._environment_values == [], config._environment_values
        assert config._environment_references == (), config._environment_references

    def test_the_check_lists_no_value_for_the_same_file(self, tmp_path, environment):
        """The side the record now agrees with, pinned."""
        from automated_security_helper.config.config_validator import ConfigValidator

        config_file = tmp_path / ".ash.yaml"
        config_file.write_text(
            "project_name: !ENV ${ASH_TEST_FIRST}${ASH_TEST_SECOND}\n",
            encoding="utf-8",
        )

        check = ConfigValidator.check_config_file(config_file)

        assert check.environment_values == [], check.environment_values

    def test_a_resolved_reference_is_still_listed(self, tmp_path, environment):
        """The control: a reference that did resolve keeps its value in both."""
        from automated_security_helper.config.config_validator import ConfigValidator
        from automated_security_helper.config.resolve_config import (
            load_config_file_for_run,
        )

        config_file = tmp_path / ".ash.yaml"
        config_file.write_text(
            "project_name: !ENV ${ASH_TEST_FIRST}\n", encoding="utf-8"
        )

        _document, config = load_config_file_for_run(config_file)
        check = ConfigValidator.check_config_file(config_file)

        assert config.project_name == "first-value"
        assert config._environment_values == ["first-value"]
        assert [r.value for r in config._environment_references] == ["first-value"]
        assert check.environment_values == ["first-value"]


@pytest.mark.parametrize(
    "written", ["!ENV [a, b]", "!ENV {a: 1}"], ids=["sequence", "mapping"]
)
def test_an_env_tag_on_a_collection_is_refused_by_both_readers(tmp_path, written):
    """``!ENV`` tags one scalar. On a list or a mapping, the reader that resolves
    references and the one that returns the file as written refuse it with the
    same YAML error, so a check that reads the file literally fails where the
    scan's reader fails. A literal constructor that built the collection
    instead would return it, and differ here."""
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(f"project_name: {written}\n", encoding="utf-8")
    refusals = []
    for reader in (read_config_file, read_config_file_literally):
        with pytest.raises(yaml.YAMLError) as excinfo:
            reader(config_file)
        refusals.append(str(excinfo.value).splitlines()[0])
    assert refusals[0] == refusals[1]
    assert refusals[0].startswith("expected a scalar node"), refusals[0]


class TestTheOneNameRule:
    """The loader's secret-name exclusion is ``is_refused_config_environment_name``.

    The loader read the suffix tuple alone, so a qualified, glued or
    digit-suffixed credential name (``ASH_API_KEY_PROD``, ``ASH_API_KEY2``,
    ``ASH_APIKEY``) had no suffix match and was interpolated from an in-tree
    config while the masking rule classed the same name as a secret. The one
    rule reads the tuple, the listed names and the secret-shaped reading.
    """

    @pytest.mark.parametrize(
        "name",
        [
            "ASH_API_KEY_PROD",
            "ASH_API_KEY2",
            "ASH_APIKEY",
            "ASH_DB_PASSWORD_2",
            "ASH_GITHUBTOKEN",
        ],
    )
    def test_a_qualified_or_glued_secret_name_is_left_as_written(
        self, tmp_path, monkeypatch, log_records, name
    ):
        monkeypatch.setenv(name, CANARY)
        reference = REFERENCE.format(name=name)

        config = _load(tmp_path, f"project_name: {reference}\n")

        assert config.project_name == reference
        assert CANARY not in config.model_dump_json()
        assert _secret_shaped(name) and not config_env_var_is_interpolatable(name)
        messages = [record.getMessage() for record in log_records]
        assert not [m for m in messages if CANARY in m], messages

    @pytest.mark.parametrize(
        "name",
        # A flag or a limit named after the word, not the word's value: the one
        # rule admits these, as the tuple did.
        [
            "ASH_AUTH_ENABLED",
            "ASH_PASS_THRESHOLD",
            "ASH_KEYS_DIR",
            "ASH_S3_BUCKET_NAME",
        ],
    )
    def test_control_a_name_that_only_contains_the_word_still_resolves(
        self, tmp_path, monkeypatch, name
    ):
        monkeypatch.setenv(name, CANARY)

        config = _load(tmp_path, f"project_name: {REFERENCE.format(name=name)}\n")

        assert config.project_name == CANARY
        assert config_env_var_is_interpolatable(name)
        assert not _secret_shaped(name)
