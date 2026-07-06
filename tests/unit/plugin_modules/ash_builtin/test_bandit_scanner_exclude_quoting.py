"""Regression tests for the shape of the bandit ``--exclude=`` argv token."""

from pathlib import Path

from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
)


def test_process_config_options_exclude_argument_contains_no_literal_quotes(
    test_plugin_context,
):
    """No emitted ``--exclude=`` argv token contains a literal ``"`` character.

    Quote characters embedded in the value are passed verbatim into the
    child process argv (``subprocess`` runs with ``shell=False``) and
    become part of the exclusion pattern bandit sees.
    """
    scanner = BanditScanner(
        context=test_plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                excluded_paths=[
                    IgnorePathWithReason(path="cdk.out", reason="CDK synth output"),
                    IgnorePathWithReason(path=".venv", reason="Python virtualenv"),
                ]
            )
        ),
    )
    scanner._process_config_options()

    exclude_keys = [
        arg.key for arg in scanner.args.extra_args if arg.key.startswith("--exclude=")
    ]
    assert exclude_keys, (
        f"Expected at least one --exclude= token, got none. "
        f"All extra_args keys: {[a.key for a in scanner.args.extra_args]!r}"
    )

    offending = [key for key in exclude_keys if '"' in key]
    assert not offending, (
        f"--exclude tokens contain literal '\"' characters: {offending!r}"
    )


def test_process_config_options_exclude_argument_value_is_well_formed(
    test_plugin_context,
):
    """The ``--exclude=`` value is the comma-join of the expected glob entries."""
    user_paths = ["tests", "docs"]
    scanner = BanditScanner(
        context=test_plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                excluded_paths=[
                    IgnorePathWithReason(path=p, reason="value-preservation test")
                    for p in user_paths
                ]
            )
        ),
    )
    scanner._process_config_options()

    exclude_tokens = [
        arg.key for arg in scanner.args.extra_args if arg.key.startswith("--exclude=")
    ]
    assert exclude_tokens, "Expected at least one --exclude= token"

    # Mirror the source-code construction so the test stays correct under
    # any future Path-normalization changes: each KNOWN_IGNORE_PATHS item
    # contributes "{item}/**" plus "**/{item}/**", and each user
    # excluded_paths entry contributes "**/{path}/**".
    expected_entries: list[str] = []
    for item in KNOWN_IGNORE_PATHS:
        expected_entries.append(str(Path(item).joinpath("**")))
        expected_entries.append(str(Path("**").joinpath(item, "**")))
    for p in user_paths:
        expected_entries.append(str(Path("**").joinpath(p, "**")))

    for token in exclude_tokens:
        value = token[len("--exclude=") :]
        actual_entries = value.split(",")
        assert actual_entries == expected_entries, (
            f"--exclude= value did not match expected entries.\n"
            f"  token:    {token!r}\n"
            f"  actual:   {actual_entries!r}\n"
            f"  expected: {expected_entries!r}"
        )

    # All --exclude= tokens (multiple if _process_config_options is invoked
    # more than once) must carry the same value.
    distinct_values = {token[len("--exclude=") :] for token in exclude_tokens}
    assert len(distinct_values) == 1, (
        f"Expected all --exclude= tokens to carry the same value; got "
        f"{len(distinct_values)} distinct values: {distinct_values!r}"
    )
