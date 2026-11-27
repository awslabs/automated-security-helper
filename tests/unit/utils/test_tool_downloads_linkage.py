"""The linkage a pinned release asset is recorded to have, and the read behind it.

``ToolAsset.linkage`` says whether a Linux asset is statically linked, needs glibc or
needs musl. Nothing in the tree measured that for most assets, so the honest default is
``unread`` and a value other than ``unread`` must carry the read it came from: where it
was made (``linkage_source``) and at which pinned version (``linkage_read_version``).
A read is of one release. When a pin moves, the old read no longer describes the new
asset, so the asset reads ``unread`` again and a person re-reads it.

Two reads are recorded today, and only those become values: opengrep's Linux builds are
static (the module's own account of the v2.0.0 assets) and uv's Linux builds are glibc
builds (the ``unknown-linux-gnu`` target triple in the pinned asset names). cfn-guard's
Linux builds were read as static at 3.2.1 and are pinned at 3.3.0, so they stay
``unread``.

The rows that need the new names read them inside the test bodies, so the file loads
where the names do not exist and the rows fail one by one.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import tool_downloads as td

pytestmark = pytest.mark.unit

_MODULE = Path(td.__file__).resolve()

#: What a recorded read looks like, for an asset the planted rows call ``demo v1.0.0``.
_RECORD = {"linkage_source": "the asset's own name", "linkage_read_version": "v1.0.0"}


def _asset(**changes):
    fields = {
        "tool": "demo",
        "version": "v1.0.0",
        "url": "https://example.invalid/demo",
        "sha256": "0" * 64,
        "member_name": "demo",
        "install_as": "demo",
    }
    fields.update(changes)
    return td.ToolAsset(**fields)


# ---------------------------------------------------------------------------
# The vocabulary and the refusal
# ---------------------------------------------------------------------------


def test_the_linkage_vocabulary_is_static_glibc_musl_or_unread() -> None:
    assert [member.value for member in td.Linkage] == [
        "static",
        "glibc",
        "musl",
        "unread",
    ]
    assert issubclass(td.Linkage, str)


def test_an_asset_is_unread_until_a_read_says_otherwise() -> None:
    asset = _asset()

    assert asset.linkage is td.Linkage.UNREAD
    assert asset.linkage_source == ""
    assert asset.linkage_read_version == ""


@pytest.mark.parametrize("name", ["STATIC", "GLIBC", "MUSL"])
def test_a_value_that_is_not_unread_needs_a_recorded_read(name: str) -> None:
    with pytest.raises(ValueError, match="needs a recorded read"):
        _asset(linkage=td.Linkage[name])


@pytest.mark.parametrize(
    "record",
    [
        {"linkage_source": "somewhere"},
        {"linkage_read_version": "v1.0.0"},
        {"linkage_source": "  ", "linkage_read_version": "v1.0.0"},
    ],
    ids=["source only", "version only", "blank source"],
)
def test_a_read_needs_both_where_it_was_made_and_at_which_version(record) -> None:
    with pytest.raises(ValueError, match="needs a recorded read"):
        _asset(linkage=td.Linkage.STATIC, **record)


def test_a_read_made_at_another_version_is_not_a_read_of_this_one() -> None:
    with pytest.raises(
        ValueError, match="was read at 'v0.9.0', not at the pinned 'v1.0.0'"
    ):
        _asset(
            linkage=td.Linkage.GLIBC,
            linkage_source="the asset's own name",
            linkage_read_version="v0.9.0",
        )


@pytest.mark.parametrize(
    "record",
    [{"linkage_source": "somewhere"}, {"linkage_read_version": "v1.0.0"}],
    ids=["a source", "a version"],
)
def test_an_unread_value_carries_no_read(record) -> None:
    with pytest.raises(ValueError, match="carries a read record"):
        _asset(**record)


@pytest.mark.parametrize("name", ["STATIC", "GLIBC", "MUSL"])
def test_a_value_with_its_read_is_accepted(name: str) -> None:
    asset = _asset(linkage=td.Linkage[name], **_RECORD)

    assert asset.linkage is td.Linkage[name]
    assert asset.linkage_source == _RECORD["linkage_source"]


def test_a_spelling_the_vocabulary_does_not_name_is_refused() -> None:
    with pytest.raises(ValueError):
        _asset(linkage="dynamic", **_RECORD)


def test_a_plain_string_that_names_a_member_is_that_member() -> None:
    assert _asset(linkage="static", **_RECORD).linkage is td.Linkage.STATIC


# ---------------------------------------------------------------------------
# The reads the module records
# ---------------------------------------------------------------------------

#: ``(tool, platform, arch) -> linkage value`` for every asset with a recorded read.
_READ = {
    ("opengrep", "linux", "amd64"): "static",
    ("opengrep", "linux", "arm64"): "static",
    ("uv", "linux", "amd64"): "glibc",
    ("uv", "linux", "arm64"): "glibc",
}


def _every_asset():
    for tool in td.downloadable_tools():
        for target_platform, arch in td.supported_platforms(tool):
            asset = td.get_tool_asset(tool, target_platform, arch)
            yield tool, target_platform, arch, asset


def test_exactly_the_recorded_reads_become_values() -> None:
    swept = list(_every_asset())

    # The denominator: a sweep over a few assets would pass whatever it held.
    assert len(swept) > 50, len(swept)
    assert {tool for tool, *_ in swept} >= {"opengrep", "uv", "cfn-guard", "trivy"}
    seeded = {
        (tool, target_platform, arch): asset.linkage.value
        for tool, target_platform, arch, asset in swept
        if asset.linkage is not td.Linkage.UNREAD
    }
    assert seeded == _READ


def test_every_recorded_read_says_where_and_is_of_the_pinned_version() -> None:
    for tool, target_platform, arch in sorted(_READ):
        asset = td.get_tool_asset(tool, target_platform, arch)

        assert asset.linkage_source.strip(), (tool, target_platform, arch)
        assert asset.linkage_read_version == asset.version, (tool, arch)
        assert asset.version == td.TOOL_VERSIONS[tool]


def test_cfn_guard_stays_unread_because_its_read_was_at_another_version() -> None:
    for arch in ("amd64", "arm64"):
        asset = td.get_tool_asset("cfn-guard", "linux", arch)

        assert asset.linkage is td.Linkage.UNREAD, arch
        assert asset.linkage_source == ""


def test_a_read_covers_the_linux_assets_it_was_made_of_and_no_other_platform() -> None:
    """opengrep's other platforms are not the builds the module read, and uv ships for
    no other platform."""
    for target_platform, arch in td.supported_platforms("opengrep"):
        asset = td.get_tool_asset("opengrep", target_platform, arch)
        expected = "static" if target_platform == "linux" else "unread"
        assert asset.linkage.value == expected, (target_platform, arch)
    assert td.supported_platforms("uv") == [("linux", "amd64"), ("linux", "arm64")]


@pytest.mark.parametrize(
    ("tool", "arch"),
    [("opengrep", "amd64"), ("opengrep", "arm64"), ("uv", "amd64"), ("uv", "arm64")],
)
def test_a_read_made_at_the_old_pin_does_not_survive_a_bump(
    tool: str, arch: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control is the same asset before the bump: it carries its read."""
    bumped = {"opengrep": "v2.0.1", "uv": "0.13.10"}[tool]
    before = td.get_tool_asset(tool, "linux", arch)
    assert before.linkage is not td.Linkage.UNREAD

    monkeypatch.setitem(td.TOOL_VERSIONS, tool, bumped)
    monkeypatch.setitem(td._DIGESTS_TAKEN_AT, tool, bumped)
    after = td.get_tool_asset(tool, "linux", arch)

    assert after.version == bumped
    assert after.linkage is td.Linkage.UNREAD
    assert after.linkage_source == ""
    assert after.linkage_read_version == ""


# ---------------------------------------------------------------------------
# The file the container build loads by path
# ---------------------------------------------------------------------------


def _imports_beyond_the_standard_library(source: str) -> list[str]:
    """Every module *source* imports, at any depth, that the installer's staged copy
    would not have: the standard library, plus the two package files staged beside
    ``utils/tool_downloads.py``."""
    staged = {
        "automated_security_helper.base.plugin_provisioning",
        "automated_security_helper.core.exceptions",
    }
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = ["." * node.level + (node.module or "")]
        else:
            continue
        for name in names:
            if name.split(".")[0] not in sys.stdlib_module_names and name not in staged:
                found.append(name)
    return sorted(found)


def test_the_import_check_flags_a_planted_import_and_passes_a_clean_one() -> None:
    planted = "import yaml\nfrom automated_security_helper.core.enums import X\n"
    lazy = "def read():\n    import yaml\n"
    relative = "from . import sibling\n"
    clean = (
        "import enum\n"
        "from typing import Optional\n"
        "from automated_security_helper.core.exceptions import E\n"
    )

    assert _imports_beyond_the_standard_library(planted) == [
        "automated_security_helper.core.enums",
        "yaml",
    ]
    assert _imports_beyond_the_standard_library(lazy) == ["yaml"]
    assert _imports_beyond_the_standard_library(relative) == ["."]
    assert _imports_beyond_the_standard_library(clean) == []


def test_the_download_table_still_imports_only_what_the_installer_stages() -> None:
    """``assets/install-pinned-tool.py`` loads this file by path from a directory
    holding it, ``core/exceptions.py`` and ``base/plugin_provisioning.py``."""
    source = _MODULE.read_text(encoding="utf-8")

    assert _imports_beyond_the_standard_library(source) == []
