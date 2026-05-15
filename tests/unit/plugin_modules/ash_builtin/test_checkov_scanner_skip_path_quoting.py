"""Regression tests for the shape of checkov ``--skip-path=`` argv tokens."""

import pytest

from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)


def test_process_config_options_skip_path_arguments_contain_no_literal_quotes(
    test_plugin_context,
):
    """No emitted ``--skip-path=`` argv token contains a literal ``"`` character.

    Quote characters embedded in the value are passed verbatim into the
    child process argv (``subprocess`` runs with ``shell=False``), and
    checkov compiles each ``--skip-path`` value as a regex, so a literal
    ``"`` would prevent the pattern from matching any real path.
    """
    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                skip_path=[
                    IgnorePathWithReason(path="cdk.out", reason="CDK synth output"),
                    IgnorePathWithReason(path=".venv", reason="Python virtualenv"),
                ]
            )
        ),
    )
    scanner._process_config_options()

    skip_path_keys = [
        arg.key for arg in scanner.args.extra_args if arg.key.startswith("--skip-path=")
    ]
    assert len(skip_path_keys) >= 2, (
        f"Expected at least two --skip-path= tokens (KNOWN_IGNORE_PATHS + "
        f"user entries), got {skip_path_keys!r}"
    )

    offending = [key for key in skip_path_keys if '"' in key]
    assert not offending, (
        f"--skip-path tokens contain literal '\"' characters: {offending!r}"
    )


@pytest.mark.parametrize(
    "user_path",
    [
        "cdk.out",
        ".venv",
        "node_modules",
        "tests/integration",
        "my-dir/sub_dir.123",
    ],
)
def test_process_config_options_skip_path_values_are_verbatim(
    test_plugin_context, user_path
):
    """Each user ``skip_path`` entry is emitted verbatim as ``--skip-path={path}``."""
    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                skip_path=[
                    IgnorePathWithReason(path=user_path, reason="value-preservation test"),
                ]
            )
        ),
    )
    scanner._process_config_options()

    skip_path_keys = [
        arg.key for arg in scanner.args.extra_args if arg.key.startswith("--skip-path=")
    ]

    expected_token = f"--skip-path={user_path}"
    assert expected_token in skip_path_keys, (
        f"Expected exact token {expected_token!r} among emitted --skip-path "
        f"tokens, but got {skip_path_keys!r}"
    )

    # _process_config_options is called twice during the scanner lifecycle
    # (once at model_post_init, once explicitly above), so the count of
    # --skip-path= tokens must be a multiple of len(KNOWN_IGNORE_PATHS) + 1.
    per_invocation_count = len(KNOWN_IGNORE_PATHS) + 1
    assert len(skip_path_keys) % per_invocation_count == 0, (
        f"Expected len(skip_path_keys)={len(skip_path_keys)} to be a multiple "
        f"of len(KNOWN_IGNORE_PATHS) + 1 = {per_invocation_count}; "
        f"keys={skip_path_keys!r}"
    )
