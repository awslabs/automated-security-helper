# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A test fixture does not write its config at a legacy location unless its subject is that location.

Why this exists
---------------
The canonical config file is ``.ash.yaml`` at the scan root. The older
``.ash/.ash.yaml`` and ``.ash/ash.yaml`` still load, with a deprecation warning,
so a test that builds its fixture there passes while quietly exercising the
legacy path instead of the canonical one. Such tests were migrated to the root
file; this guard keeps new ones from growing the legacy surface again.

A test file may name a legacy location in a quoted path spelling only if it is
listed in ``LEGACY_SUBJECT`` below with the reason its subject needs that
location (the legacy fallback itself, a link or an extends base inside the
``.ash`` directory, or a negative assertion that nothing is written there). To
add a file, put the reason in the table; the table is the review point.

What this checks
----------------
* Every quoted spelling of ``.ash/.ash.yaml``, ``.ash/ash.yaml`` or their ``.yml``
  and ``.json`` forms in a file under ``tests/`` belongs to a file in
  ``LEGACY_SUBJECT``. A spelling is a string literal that ends in the legacy path
  (with any prefix, an f-string and a ``Path("...")`` argument included), or a
  join of ``".ash"`` and the name with ``/`` or a comma, ``joinpath`` included.
  A path built through a variable (``ash_dir = root / ".ash"; ash_dir / "ash.yaml"``)
  cannot be seen by a text scan; tests of that shape say "Legacy location" in their
  docstring when the legacy path is the subject.
* Every ``LEGACY_SUBJECT`` entry still has such a spelling, so a file that was
  migrated does not stay on the list.
* The scanner flags a planted fixture (must-flag) and passes the canonical
  spelling (must-not-flag).
"""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

TESTS = Path(__file__).resolve().parents[2]
REPO = TESTS.parent

_NAME = r"(?:\.ash|ash)\.(?:ya?ml|json)"
LEGACY_SPELLING = re.compile(
    # A string literal that ends in the legacy path, whatever precedes it: a
    # prefix such as "repo/", an f-string, a Path("/x/.ash/.ash.yaml") argument.
    rf"""["'][^"'\n]*\.ash/{_NAME}["']"""
    # A path join of the two parts: "x" / ".ash" / "ash.yaml", (".ash", "ash.yaml"),
    # or .joinpath(".ash", ".ash.yaml").
    rf"""|["']\.ash["']\s*[/,]\s*["']{_NAME}["']"""
)

#: Files whose fixtures may name a legacy location, and why.
LEGACY_SUBJECT = {
    "integration/cli/test_mcp_stdio_server.py": "the extends base sits beside the config inside .ash/",
    "snapshot/config/test_snapshot_config_init.py": "asserts init writes nothing at the legacy location",
    "snapshot/errors/test_snapshot_errors_config.py": "init refuses to write .ash.yaml beside a legacy .ash/.ash.yaml",
    "snapshot/support/fixture_model.py": "the snapshot fixture repository carries its own legacy-path config",
    "snapshot/support/normalize.py": "rewrites the legacy default path text in recorded output",
    "snapshot/test_snapshot_normalizer.py": "sample text for the normalizer's legacy-path rewrite",
    "unit/cli/inspect/test_inspect_findings_app.py": "legacy discovery and canonical-beats-legacy in the inspector",
    "unit/cli/mcp/test_delivered_config_env.py": "an extends base in .ash/ beside the legacy config",
    "unit/cli/mcp/test_mcp_config_confinement.py": "extends-chain confinement is defined by the .ash/ directory",
    "unit/cli/test_config_commands.py": "the .gitignore init writes beside a config in .ash/",
    "unit/cli/test_config_commands_refuse_before_tracebacks.py": "init refuses a new file beside an existing legacy source",
    "unit/cli/test_config_default_file_name.py": "the move from the legacy name to .ash.yaml and legacy files still loading",
    "unit/cli/test_recorded_reference_fields.py": "covers both the legacy and the canonical location on purpose",
    "unit/config/test_a_client_supplied_suppression_saves_and_is_found_again.py": "a dangling .ash link the save must not create directories through",
    "unit/config/test_config_extends.py": "a base path resolves relative to a config inside .ash/",
    "unit/config/test_config_files_that_do_not_load.py": "a linked .ash directory and every legacy discovery location",
    "unit/config/test_config_source_discovery.py": "discovery precedence and the deprecation warning",
    "unit/config/test_config_sources_hardening.py": "the repository stays the root for a config found in .ash/",
    "unit/config/test_detect_secrets_output_limit_is_the_operators.py": "one discovered-route row keeps the legacy location",
    "unit/config/test_resolve_config_load_failures.py": "load failures at every location including the legacy one",
    "unit/config/test_the_canonical_config_file_is_ash_yaml_at_the_root.py": "the canonical-versus-legacy tests themselves",
    "unit/config/test_the_loader_reads_every_component_of_a_candidate_for_a_share.py": "a link inside the .ash directory",
    "unit/config/test_the_suppression_save_writes_through_a_link_in_dot_ash.py": "a link inside the .ash directory",
    "unit/core/test_repo_config_cannot_widen_sandbox.py": "symlink and .ash/ confinement cases of the legacy path",
    "unit/deploy/test_codecommit_gate_config_trust.py": "a pull request that still carries the deprecated location",
    "unit/docs/test_page_claims.py": "a config-validate case whose subject is the .ash directory",
    "unit/cli/mcp/test_scan_directory_names_a_discovered_config.py": "a broken file at the deprecated location is refused like the rest",
    "unit/interactions/test_config_log_names_the_loaded_file.py": "asserts the log names the canonical file and not the legacy path",
    "unit/interactions/test_container_config_reaches_the_scan.py": "an extends chain confined by the .ash/ directory",
    "unit/interactions/test_container_mount_containment.py": "a config in .ash/ may reach its parent",
    "unit/interactions/test_scan_config_load_failures.py": "the discovery matrix lists the legacy location beside the canonical ones",
    "unit/interactions/test_scan_does_not_run_in_tree_tools.py": "the dot-ash directory case beside the repository-root case",
    "unit/interactions/test_the_container_is_handed_only_the_operators_environment.py": "extends bases kept in the .ash directory",
    "unit/test_ash_bash_entrypoint_container_inputs.py": "symlinked .ash and extends-in-.ash cases",
    "unit/test_pre_commit_hooks_manifest.py": "asserts the docs page names the legacy path",
    "unit/test_sandbox_refused_by_every_container_entrypoint.py": "a symlink inside the .ash directory",
    "unit/utils/test_link_locations.py": "a symlinked .ash directory",
}


def _files_with_legacy_spelling(root: Path, skip: Path) -> set[str]:
    found = set()
    for path in sorted(root.rglob("*.py")):
        if path == skip or "test_data" in path.parts:
            continue
        if LEGACY_SPELLING.search(path.read_text(encoding="utf-8", errors="replace")):
            found.add(path.relative_to(root).as_posix())
    return found


def test_a_fixture_at_the_legacy_location_belongs_to_a_test_about_it() -> None:
    found = _files_with_legacy_spelling(TESTS, Path(__file__).resolve())
    stray = sorted(found - set(LEGACY_SUBJECT))
    assert stray == [], (
        "these test files build a config at a legacy location; put the fixture at "
        "the scan root as .ash.yaml, or, if the test is about the legacy location, "
        f"add the file to LEGACY_SUBJECT with the reason: {stray}"
    )


def test_no_script_writes_a_config_at_a_legacy_location() -> None:
    """The verification scripts write fixtures too; they write the canonical file."""
    assert (REPO / "scripts").is_dir()
    found = _files_with_legacy_spelling(REPO / "scripts", Path(__file__).resolve())
    assert found == set(), (
        f"scripts that write a legacy config location: {sorted(found)}"
    )


def test_every_listed_file_still_names_a_legacy_location() -> None:
    found = _files_with_legacy_spelling(TESTS, Path(__file__).resolve())
    stale = sorted(set(LEGACY_SUBJECT) - found)
    assert stale == [], (
        f"these files no longer name a legacy location; drop them: {stale}"
    )
    assert all(reason.strip() for reason in LEGACY_SUBJECT.values())


def test_the_scanner_flags_a_planted_fixture_and_passes_the_canonical_one(
    tmp_path,
) -> None:
    legacy = ".ash" + "/" + ".ash.yaml"
    (tmp_path / "test_planted_string.py").write_text(f'CONFIG = "{legacy}"\n')
    (tmp_path / "test_planted_join.py").write_text(
        'path = root / ".ash" / ".ash.yaml"\n'
    )
    (tmp_path / "test_planted_no_dot.py").write_text("p = '.ash/ash.yml'\n")
    (tmp_path / "test_planted_prefixed.py").write_text(
        'a = "repo/.ash/.ash.yaml"\nb = Path("/zz/.ash/.ash.yaml")\n'
        'c = f"/{key}/.ash/ash.yaml"\n'
    )
    (tmp_path / "test_planted_args.py").write_text(
        'a = Path(".ash", ".ash.yaml")\nb = root.joinpath(".ash", "ash.yaml")\n'
    )
    (tmp_path / "test_planted_json.py").write_text('p = ".ash/.ash.json"\n')
    (tmp_path / "test_canonical.py").write_text(
        'path = root / ".ash.yaml"\nname = "ash.yaml"\nj = root / ".ash.json"\n'
        'prose = "see `.ash/.ash.yaml` for the old name"\n'
    )
    found = _files_with_legacy_spelling(tmp_path, tmp_path / "none.py")
    assert found == {
        "test_planted_string.py",
        "test_planted_join.py",
        "test_planted_no_dot.py",
        "test_planted_prefixed.py",
        "test_planted_args.py",
        "test_planted_json.py",
    }
