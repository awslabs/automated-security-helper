"""Regression test for the devil's-advocate finding:

The smoke_test() helper for substantive validators (claude plugin validate,
mcpb validate, q agent validate, etc.) MUST NOT silently swallow failures
that come from the validator itself. Specifically: a stderr containing
'no such file or directory' is a *legitimate* failure signal for these
commands when our generated artifact references a missing path. Earlier
versions of _invoke_cli soft-passed on that phrase, hiding real bugs.

This test confirms that _invoke_validator hard-fails when a real CLI
returns a real failure, while still soft-skipping when the binary is
absent entirely (env-quirk vs artifact bug — opposite policy).
"""
from __future__ import annotations

from pathlib import Path

from transpiler.core import BaseBackend


def test_validator_hard_fails_on_real_failure(tmp_path, monkeypatch):
    """When a CLI is on PATH and exits non-zero with a validator-style error,
    _invoke_validator must return ok=False — even if stderr contains
    'no such file or directory' (which is a legit validator signal, not a
    wrapper-target-missing signal)."""

    # Stub `which` to make it look like the CLI is installed.
    fake_bin = tmp_path / "fake-validator"
    fake_bin.write_text("#!/bin/sh\necho 'Error: no such file or directory: /missing/plugin.json' >&2\nexit 1\n")
    fake_bin.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + ":" + str(Path.cwd()))

    result = BaseBackend._invoke_validator(["fake-validator", "validate", "/some/dir"])
    assert result["ok"] is False, (
        f"_invoke_validator must hard-fail on a non-zero validator exit even "
        f"when stderr says 'no such file or directory' (got: {result})"
    )
    assert "no such file" in result["reason"].lower(), (
        f"failure reason should surface the validator stderr (got: {result['reason']!r})"
    )


def test_validator_soft_skips_when_cli_absent(monkeypatch, tmp_path):
    """When a CLI is not on PATH, _invoke_validator must soft-skip with
    skipped=True so CI runners without that CLI installed don't fail the
    build (structural validation has already covered the artifact)."""

    # Empty PATH → which returns None for every binary.
    monkeypatch.setenv("PATH", str(tmp_path))
    result = BaseBackend._invoke_validator(["definitely-not-a-real-cli-12345", "validate", "/x"])
    assert result["ok"] is True, f"missing CLI should soft-skip (got: {result})"
    assert result.get("skipped") is True, (
        f"missing CLI must set skipped=True for the smoke-test summary "
        f"to distinguish it from a real pass (got: {result})"
    )


def test_validator_soft_skips_on_macos_app_wrapper(tmp_path, monkeypatch):
    """When a wrapper script (toolbox-style symlink, nvm shim) execs a
    .app bundle path that has been removed, _invoke_validator must
    soft-skip — this is an env quirk on the dev's machine, not a real
    artifact failure. The signature is: stderr starts with an absolute
    path, contains '.app/Contents/', AND ends with 'no such file or
    directory'."""

    fake_bin = tmp_path / "wrapper-cli"
    fake_bin.write_text(
        "#!/bin/sh\n"
        "echo '/Users/dev/.toolbox/tools/q/1.19.3/Amazon Q.app/Contents/MacOS/q: "
        "no such file or directory' >&2\n"
        "exit 1\n"
    )
    fake_bin.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    result = BaseBackend._invoke_validator(["wrapper-cli", "validate", "/x"])
    assert result["ok"] is True, f"stale wrapper should soft-skip (got: {result})"
    assert result.get("skipped") is True
    assert "wrapper present but target missing" in result["detail"]
