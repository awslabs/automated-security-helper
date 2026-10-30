# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Three readings of utils/tool_downloads.py.

get_tool_asset raised a bare KeyError for a tool in the asset table but not in
TOOL_VERSIONS or the release URL table, past the graceful handling every other
refusal gets; its refusal for a platform the table lacks blamed the vendor
("publishes no release asset") where the table is ASH's choice; and the rules
bundle's version probe printed every installed bundle's version, so the check
passed while another version was installed too, and indexed the environment
without a default, so an unset variable read as a version mismatch.
"""

from __future__ import annotations

import contextlib
import io
import json

import pytest

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.utils import tool_downloads
from automated_security_helper.utils.tool_downloads import (
    THIRD_PARTY_LICENSES,
    get_tool_asset,
    supported_platforms,
)

pytestmark = pytest.mark.unit


def test_a_tool_missing_from_the_version_table_is_refused_by_name(monkeypatch):
    monkeypatch.setitem(
        tool_downloads._ASSET_TABLES, "acme-tool", {("linux", "amd64"): "acme.tar.gz"}
    )

    with pytest.raises(ToolNotProvisionableError) as raised:
        get_tool_asset("acme-tool", "linux", "amd64")

    assert "TOOL_VERSIONS" in str(raised.value)
    assert "_RELEASE_BASE_URLS" in str(raised.value)


def test_a_platform_the_table_lacks_is_refused_as_the_tables_choice():
    pairs = [("darwin", "arm64"), ("windows", "amd64"), ("darwin", "amd64")]
    absent = next(p for p in pairs if p not in supported_platforms("uv"))

    with pytest.raises(ToolNotProvisionableError) as raised:
        get_tool_asset("uv", *absent)

    message = str(raised.value)
    assert "download table" in message, message
    assert "publishes no release asset" not in message, message


def _probe_output(tmp_path, monkeypatch, rules_dir) -> tuple[str, str]:
    entry = THIRD_PARTY_LICENSES["aws-guard-rules-registry"]
    program = entry.version_probe[-1]
    if rules_dir is None:
        monkeypatch.delenv("ASH_CFN_GUARD_RULES_DIR", raising=False)
    else:
        monkeypatch.setenv("ASH_CFN_GUARD_RULES_DIR", str(rules_dir))
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        exec(compile(program, "<version_probe>", "exec"), {"__name__": "__probe__"})
    return out.getvalue(), err.getvalue()


def _manifest(rules_dir, version: str) -> None:
    bundle = rules_dir / f"aws-guard-rules-registry-{version}"
    bundle.mkdir(parents=True)
    (bundle / ".ash-rules-manifest.json").write_text(
        json.dumps({"version": version}), encoding="utf-8"
    )


def test_the_rules_probe_reports_the_pinned_bundle_only(tmp_path, monkeypatch):
    entry = THIRD_PARTY_LICENSES["aws-guard-rules-registry"]
    assert f"aws-guard-rules-registry-{entry.version}" in entry.version_probe[-1]
    rules = tmp_path / "rules"
    _manifest(rules, entry.version)
    _manifest(rules, "9.9.9")

    out, _ = _probe_output(tmp_path, monkeypatch, rules)

    assert out.split() == [entry.version], out


def test_the_rules_probe_says_when_the_directory_is_not_set(tmp_path, monkeypatch):
    out, err = _probe_output(tmp_path, monkeypatch, None)

    assert out == "", out
    assert "ASH_CFN_GUARD_RULES_DIR is not set" in err, err
