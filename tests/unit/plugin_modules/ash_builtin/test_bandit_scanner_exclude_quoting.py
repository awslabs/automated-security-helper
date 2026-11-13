"""Regression tests for the shape of the bandit ``--exclude=`` argv token."""

from pathlib import Path

import pytest

from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BANDIT_DEFAULT_EXCLUDES,
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
    bandit_excluded_path_globs,
)

pytestmark = pytest.mark.unit


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

    # Each KNOWN_IGNORE_PATHS item, each of bandit's own default excludes (which
    # an explicit --exclude replaces, so ASH passes them too) and each user
    # excluded_paths entry contributes its bandit_excluded_path_globs, anchored
    # at the source directory. (They were "{item}/**", "**/{item}/**" and
    # "**/{path}/**", which never skipped a file entry's file and matched the
    # target's own path.)
    anchor = Path(test_plugin_context.source_dir).as_posix()
    expected_entries: list[str] = []
    for item in (*KNOWN_IGNORE_PATHS, *BANDIT_DEFAULT_EXCLUDES):
        expected_entries.extend(bandit_excluded_path_globs(anchor, item))
    for p in user_paths:
        expected_entries.extend(bandit_excluded_path_globs(anchor, p))
    assert expected_entries

    for token in exclude_tokens:
        value = token[len("--exclude=") :]
        actual_entries = value.split(",")
        # The argument has a size bound, so no glob is passed twice; today the
        # known ignore paths and bandit's defaults share no entry, and this
        # says so for any later change to either list.
        assert len(actual_entries) == len(set(actual_entries)), actual_entries
        assert actual_entries == expected_entries, (
            f"--exclude= value did not match expected entries.\n"
            f"  token:    {token!r}\n"
            f"  actual:   {actual_entries!r}\n"
            f"  expected: {expected_entries!r}"
        )

    # The options were processed twice (construction, then the call above), and
    # a second call rebuilds the arguments from the base ones, so there is
    # exactly one --exclude= token, not one per call.
    assert len(exclude_tokens) == 1, exclude_tokens
