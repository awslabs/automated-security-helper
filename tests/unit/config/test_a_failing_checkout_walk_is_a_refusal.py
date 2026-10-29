"""A checkout walk that fails is a config that cannot be judged, not a crash.

Two readers build the settings that confine a config file before they load it
(`repository_settings_for_root`), and that call walks the directory's git
checkouts. The walk answers fail-closed for a directory it cannot search, so
these tests make it raise the way a broken filesystem would, and check that
each reader refuses in its own structured way instead of raising out of the
tool or the gate.
"""

import json
from pathlib import Path

from tests.utils.helpers import mark_git_checkout


def _refusing_walk(monkeypatch) -> None:
    from automated_security_helper.config import sandbox_grants

    def refused(scan_root):
        raise PermissionError(13, "Permission denied", str(scan_root))

    monkeypatch.setattr(sandbox_grants, "scanned_trees", refused)


def _checkout_with(tmp_path: Path, relative: str, text: str) -> Path:
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    written = checkout / relative
    written.parent.mkdir(parents=True, exist_ok=True)
    written.write_text(text, encoding="utf-8")
    return checkout


def test_the_policy_check_refuses_when_the_checkout_walk_fails(tmp_path, monkeypatch):
    """The client-config rules are built from settings rooted at the working
    directory. The validator reads the config first, with the walk working; the
    walk then fails for the policy check alone, which answers a structured error
    that says it could not finish, instead of raising out of validate_config."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config.config_validator import ConfigValidator

    checkout = _checkout_with(tmp_path, ".ash/.ash.yaml", "project_name: checkout\n")
    named = tmp_path / "named.yaml"
    named.write_text("project_name: named\n", encoding="utf-8")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(checkout)
    check = ConfigValidator.check_config_file(named)
    _refusing_walk(monkeypatch)

    problems = mcp_tools._validated_document_denials(None, str(named), None, check)

    assert [p for p in problems if "runtime-override policy" in p["message"]], problems
    assert {p["type"] for p in problems} == {"validation_error"}, problems


def test_the_host_config_refusal_is_a_refusal_when_the_checkout_walk_fails(
    tmp_path, monkeypatch
):
    """Container and nix mode resolve the config on the host first and refuse
    what the scan would refuse. A walk that fails there is a refusal the gate
    returns (exit 3), not an OSError that escapes it. The same options with a
    working walk are not refused, so the refusal is the walk's."""
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _outer_mode_config_refusal,
    )

    checkout = _checkout_with(tmp_path, ".ash/.ash.yaml", "project_name: checkout\n")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    opts = ScanOptions(
        source_dir=checkout,
        output_dir=tmp_path / "out",
        config=str(checkout / ".ash" / ".ash.yaml"),
    )

    with monkeypatch.context() as patched:
        _refusing_walk(patched)
        refusal = _outer_mode_config_refusal(opts)

    assert isinstance(refusal, ASHConfigValidationError), refusal
    assert "could not be searched" in str(refusal), refusal
    assert _outer_mode_config_refusal(opts) is None


def test_validate_config_of_a_clean_file_is_valid_beside_an_in_tree_ash_config(
    tmp_path, monkeypatch
):
    """The server runs in a checkout whose file ASH_CONFIG names, and that file
    writes a limit only the operator may set, out of range. The rules' default
    config is read with the settings rooted at that working directory, so the
    file's limit is left out and the rules are readable: validate_config of a
    clean file is valid and not a config_policy_unreadable error."""
    from automated_security_helper.cli import mcp_tools

    checkout = _checkout_with(
        tmp_path,
        "configs/ash.yaml",
        "scanners:\n  detect-secrets:\n    options:\n      max_worker_output_mib: 4097\n",
    )
    clean = tmp_path / "clean.yaml"
    clean.write_text("project_name: clean\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(checkout / "configs" / "ash.yaml"))
    monkeypatch.chdir(checkout)

    result = mcp_tools.mcp_validate_config(config_path=str(clean))

    assert "config_policy_unreadable" not in json.dumps(result), result
    assert result.get("valid") is True, result
