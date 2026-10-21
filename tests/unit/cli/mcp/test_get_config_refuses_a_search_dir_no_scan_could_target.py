# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A search_dir no scan could target refuses the get_config answer.

``search_dir`` is the directory the caller's scan will target, and the answer
judges the configuration for that target. A path that is not a directory --
a typo, a file, a deleted tree -- would judge the config against a tree no
scan can target, refusing in-tree entries a real scan of a real target drops.
It is refused instead, exactly as a scan of it refuses its source directory:
``error_type`` source_dir_not_usable and the usage exit code, so a client
can branch on the same refusal either tool answers for that target.
"""

import pytest

from automated_security_helper.cli import mcp_tools


@pytest.mark.parametrize("named", [True, False], ids=["named-file", "discovery"])
def test_a_search_dir_no_scan_could_target_is_refused_as_a_scan_refuses_it(
    tmp_path, monkeypatch, named
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "ash.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")
    missing = tmp_path / "no-such-target"

    answer = mcp_tools.mcp_get_config(
        config_path=str(config) if named else None,
        search_dir=str(missing),
    )

    assert answer["success"] is False, answer
    assert answer["error_type"] == "source_dir_not_usable", answer
    assert answer["exit_code"] == 5, answer
    assert "exit_code_meaning" in answer, answer


def test_a_search_dir_that_is_a_file_is_refused_the_same_way(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "ash.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")
    a_file = tmp_path / "a-file"
    a_file.write_text("not a directory\n", encoding="utf-8")

    answer = mcp_tools.mcp_get_config(config_path=str(config), search_dir=str(a_file))

    assert answer["success"] is False, answer
    assert answer["error_type"] == "source_dir_not_usable", answer
    assert answer["exit_code"] == 5, answer


def test_a_search_dir_that_is_a_directory_still_answers(tmp_path, monkeypatch):
    """Control: a real directory target keeps the answer, both branches."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    target = tmp_path / "repo"
    target.mkdir()
    config = tmp_path / "ash.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")

    named = mcp_tools.mcp_get_config(config_path=str(config), search_dir=str(target))
    discovered = mcp_tools.mcp_get_config(search_dir=str(target))

    # A successful answer is the resolved config itself, with no failure keys.
    assert named.get("success") is not False, named
    assert "error_type" not in named, named
    assert named.get("project_name") == "demo", named
    assert discovered.get("success") is not False, discovered
    assert "error_type" not in discovered, discovered


def test_a_symlinked_search_dir_answers_as_its_resolved_target(tmp_path, monkeypatch):
    """A search_dir that is a link to a directory answers as that directory.

    A scan of the link runs on the resolved target (resolve_scan_target
    collapses links before anything else), and the judgment that follows the
    target -- the checkout marking, the confinement root, the chain -- takes
    the root by every name it has. The answer for the link must be the
    answer for the directory it names, so the config shown is the one that
    scan would use.
    """
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "checkout"
    target = checkout / "src"
    target.mkdir(parents=True)
    # The tree is a checkout: which files count as the repository's own is
    # part of what the target decides.
    (checkout / ".git").mkdir()
    base = target / "base.ash.yaml"
    base.write_text("project_name: from-the-base\n", encoding="utf-8")
    config = target / "demo.ash.yaml"
    config.write_text("extends: ./base.ash.yaml\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    link = elsewhere / "link-to-target"
    link.symlink_to(target)

    by_link = mcp_tools.mcp_get_config(config_path=str(config), search_dir=str(link))
    by_target = mcp_tools.mcp_get_config(
        config_path=str(config), search_dir=str(target)
    )

    # Control: the real target's answer is the loaded chain, not a refusal.
    assert by_target.get("success") is not False, by_target
    assert by_target.get("project_name") == "from-the-base", by_target
    assert by_link == by_target


def test_a_search_dir_is_judged_by_the_scan_roots_not_the_config_roots(
    tmp_path, monkeypatch
):
    """search_dir crosses the scan tool's root gate, never the config gate.

    A deployment can allow different roots for scan targets and for config
    inputs. ``search_dir`` names the directory the caller's scan will target,
    so it is judged exactly as the scan tool judges its target: a target
    inside the scan roots answers even when it sits outside the config roots,
    and a target outside the scan roots is refused as the scan tool refuses
    it -- never as a config input. Judged by the config gate instead, a
    client passing its real scan target would be refused an answer the scan
    of that target accepts.
    """
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config_root = tmp_path / "cfg"
    config_root.mkdir()
    scan_parent = tmp_path / "scan"
    scan_target = scan_parent / "repo"
    scan_target.mkdir(parents=True)
    config = config_root / "ash.yaml"
    config.write_text("project_name: split-roots\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_parent))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(config_root))

    # Inside the scan roots, outside the config roots: the answer is given.
    inside = mcp_tools.mcp_get_config(
        config_path=str(config), search_dir=str(scan_target)
    )
    assert inside.get("success") is not False, inside
    assert "error_type" not in inside, inside
    assert inside.get("project_name") == "split-roots", inside

    # Outside the scan roots, inside the config roots: the scan tool's own
    # refusal, never the config gate's.
    outside = mcp_tools.mcp_get_config(
        config_path=str(config), search_dir=str(config_root)
    )
    assert outside["success"] is False, outside
    assert outside["error_type"] == "scan_target_not_permitted", outside


def test_the_working_directory_default_keeps_its_handling(monkeypatch, tmp_path):
    """Control: with no search_dir the discovery default is untouched -- the
    answer comes from the working directory as before, never this refusal."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)

    answer = mcp_tools.mcp_get_config()

    assert answer.get("error_type") != "source_dir_not_usable", answer
    assert answer.get("success") is not False, answer
