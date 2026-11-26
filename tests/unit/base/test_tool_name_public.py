"""The uv tool-name helper has a public home.

Builtin plugins are the examples third parties copy, so the helper every one
of them calls must be a public name: ``tool_name``. It lives in
``automated_security_helper.base.uv_tool_mixin`` (the mixin module is the one
home every caller can import from: ``plugin_base`` imports from the mixin, so
the mixin cannot import the helper back from ``plugin_base``; and the helper
is a function, not a method, because the uv arms also run it against
duck-typed stand-ins that no base class reaches) and is re-exported by
``automated_security_helper.base.plugin_base``. ``_tool_name`` stays as a
thin deprecated alias so out-of-tree copies of the builtin plugins keep
working.
"""

import re
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGE = REPO_ROOT / "automated_security_helper"
MIXIN = PACKAGE / "base" / "uv_tool_mixin.py"

# The private token, not inside a longer identifier (so
# ``unquoted_failure_tool_name`` and ``_canonical_tool_name`` do not match).
PRIVATE_TOKEN = re.compile(r"(?<![A-Za-z0-9_])_tool_name(?![A-Za-z0-9_])")


def test_public_name_is_the_alias_for_a_representative_plugin():
    from automated_security_helper.base.uv_tool_mixin import _tool_name, tool_name

    representative = SimpleNamespace(command="bandit")
    assert tool_name(representative) == "bandit"
    assert tool_name(representative) == _tool_name(representative)
    toolless = SimpleNamespace(command=None)
    assert tool_name(toolless) == ""
    assert tool_name(toolless) == _tool_name(toolless)


def test_alias_is_a_thin_deprecated_wrapper_naming_the_public_name():
    from automated_security_helper.base.uv_tool_mixin import _tool_name, tool_name

    assert _tool_name is not tool_name, "the alias is its own def, not a rebind"
    assert "tool_name" in (_tool_name.__doc__ or "")
    assert "eprecated" in (_tool_name.__doc__ or "")


def test_public_name_is_reachable_from_plugin_base():
    from automated_security_helper.base import plugin_base, uv_tool_mixin

    assert plugin_base.tool_name is uv_tool_mixin.tool_name


def _private_call_sites(text: str) -> list[str]:
    """Lines of ``text`` that use the private name."""
    return [line for line in text.splitlines() if PRIVATE_TOKEN.search(line)]


def test_scan_finds_a_planted_private_call_site():
    planted = "from automated_security_helper.base.uv_tool_mixin import _tool_name\n"
    assert _private_call_sites(planted), "control: the scan must flag this"
    assert not _private_call_sites("unquoted_failure_tool_name = None\n")
    assert not _private_call_sites("_canonical_tool_name(resolved, names)\n")


def test_no_private_call_sites_remain_in_the_package():
    """In package source the private name survives only as the alias's def."""
    offenders = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        hits = _private_call_sites(path.read_text(encoding="utf-8"))
        if path == MIXIN:
            assert hits == ["def _tool_name(plugin: Any) -> str:"], hits
            continue
        if hits:
            offenders[str(path.relative_to(REPO_ROOT))] = hits
    assert offenders == {}, offenders


def test_every_builtin_caller_references_the_public_name():
    """Every module that called the helper at the refactor imports the
    public name from the mixin module (the example third parties copy)."""
    callers = [
        "base/plugin_base.py",
        "base/scanner_plugin.py",
        "plugin_modules/ash_builtin/converters/jupyter_converter.py",
        "plugin_modules/ash_builtin/scanners/bandit_scanner.py",
        "plugin_modules/ash_builtin/scanners/checkov_scanner.py",
        "plugin_modules/ash_builtin/scanners/npm_audit_scanner.py",
        "plugin_modules/ash_builtin/scanners/opengrep_scanner.py",
        "plugin_modules/ash_builtin/scanners/semgrep_scanner.py",
        "plugin_modules/ash_ferret_plugins/ferret_scanner.py",
        "plugin_modules/ash_snyk_plugins/snyk_code_scanner.py",
    ]
    public_use = re.compile(r"(?<![A-Za-z0-9_.])tool_name\(")
    for rel in callers:
        text = (PACKAGE / rel).read_text(encoding="utf-8")
        assert "uv_tool_mixin import" in text or "uv_tool_mixin" in text, rel
        assert public_use.search(text), f"{rel} does not call tool_name()"
