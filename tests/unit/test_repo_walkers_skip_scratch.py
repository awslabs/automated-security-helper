# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No walk the test run performs may enter a per-run directory.

Why this file exists
--------------------
``tests/pytest-temp/<uuid>/`` is the tests' own scratch area, inside the
repository and gitignored, and the ``ash_temp_path`` fixture ``shutil.rmtree``s a
subtree of it on teardown. Under ``-n auto`` that teardown runs while other
workers are mid-walk, so any test that walks the repository root races it.

There are two distinct races, and that distinction is why this is a guard rather
than a third individual fix:

1. **Read after enumerate.** ``sorted(root.rglob("*.py"))`` is materialised in
   full, then each file is read. A file listed at the start can be gone by the
   time it is read. Fixed once, in ``test_project_isolation.py``, by filtering the
   walk's output.
2. **Scandir during descent.** ``rglob`` raises from *inside* its own traversal,
   before it yields anything, when a directory it listed is removed before it
   descends into it. Measured on macos-14 py3.11, in a different walker::

       _candidate_files -> REPO_ROOT.rglob("*")
         pathlib.py:397 _iterate_directories   (recursive)
         pathlib.py:386   with scandir(parent_path) as scandir_it:
         -> os.scandir(self)
         FileNotFoundError: .../tests/pytest-temp/<uuid>/test_output_dir

   No filter on the output can prevent that, because there is no output.

   Seen on one leg of a run whose other legs passed. An attempt to reproduce it
   by racing a real teardown failed to hit the window on 3.11 and 3.13. Measured
   since, deterministically: removing the directory at the moment ``rglob`` lists it, through an audit hook
   on ``os.scandir``, raises FileNotFoundError on 3.10 and 3.11, and on 3.12, 3.13
   and 3.14 the directory is skipped without an error. A newer interpreter still
   descends into the scratch tree and returns whatever is there, so the race is not
   gone there, only quieter. The fix is not scoped
   to an interpreter.

Fixing (1) does not fix (2). That is not a hypothetical: the first fix landed and
a second walker failed the same way three hours later, on a leg that had just been
added to the matrix. So the rule is structural -- walk with
``tests.utils.helpers.iter_repo_files``, which prunes ``dirnames`` in place so
``os.walk`` never descends into the scratch tree. Pruning removes the race;
filtering and exception-catching only narrow it.

Why this is an AST check and not a grep
---------------------------------------
A regex over source lines flags the traceback quoted above, which lives in a
docstring in ``helpers.py``. The cheapest way to make a text-matching guard green
is then to delete the explanation, which is precisely backwards -- the same
failure ``test_prose_about_the_hazard_is_not_counted_as_the_hazard`` documents in
``test_project_isolation.py``. Matching ``ast.Call`` nodes makes prose invisible
by construction, so the explanation can stay.

Two walks this guard could not see
----------------------------------
The first version matched ``REPO_ROOT.glob`` and ``REPO_ROOT.rglob`` by name, in
tests/ only. Two walks raced past it: one bound the root to ``REPO``, and two lived
in scripts the tests run on the real checkout (``collect_md_files`` in
scripts/verify_docs_freshness.py walked ``REPO_ROOT.rglob("*.md")``, and
``find_orphans`` in .github/scripts/check-snapshot-trailers.py walked
``(root / "tests").rglob`` with the root arriving as a parameter). So the sweep now
lives in ``tests.utils.walk_guard``, which evaluates what each walk's receiver is,
follows the scripts the tests load or run, and fails closed on a receiver it cannot
resolve. Its module docstring says exactly what it follows.

A receiver that only exists at run time (a path a call returns, an awaited result)
cannot be resolved, so the walk is flagged. Each such walk that is in fact safe is
named in ``_EXEMPT`` below by file, function and receiver, with the reason, and
``test_every_exemption_still_names_a_flagged_walk`` fails when an entry no longer
matches anything, so the list cannot rot into blanket permission.

It deliberately does not flag a walk of a subtree no per-run directory is under.
Walking ``automated_security_helper/`` or ``.github/`` is safe; there is nothing to
race.
"""

from __future__ import annotations

import importlib.util
import textwrap
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath
from types import ModuleType

import pytest

from automated_security_helper.utils.version_management import _load_toml
from tests.utils.helpers import (
    ASH_TEST_TEMP_ROOT,
    is_under_test_scratch,
    iter_repo_files,
)
from tests.utils.walk_guard import (
    PER_RUN_DIRS,
    Evaluator,
    InRepo,
    Private,
    Source,
    Sweep,
    node_modules_dirs,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = REPO_ROOT / "tests"

#: Walks the guard cannot resolve that are safe, by (file, function, receiver), with
#: the reason. Every entry must still name a flagged walk; see
#: test_every_exemption_still_names_a_flagged_walk.
_EXEMPT = {
    ("tests/utils/helpers.py", "iter_repo_files", "root"): (
        "The sanctioned walker: it removes the scratch tree from dirnames before "
        "os.walk descends. TestIterRepoFilesPrunesTheScratchTree covers it."
    ),
    (".github/scripts/check-snapshot-trailers.py", "_snapshot_dirs", "root / entry"): (
        "Walks only directories git reports as untracked and not ignored, pruning "
        "every directory git reports as ignored. "
        "TestScriptWalkersStayOutOfTheScratchTree removes a scratch directory at the "
        "moment the walk lists it and shows it is never entered."
    ),
    (".github/scripts/check-snapshot-trailers.py", "find_orphans", "entry"): (
        "One per-module directory inside a __snapshots__ directory that "
        "_snapshot_dirs returned, so never an ignored one."
    ),
    (
        "scripts/verify_multi_project_attribution.py",
        "find_scanner_error_logs",
        "scanner_dir",
    ): (
        "A fixed-depth pattern with no ** of its own; its one substitution is a "
        "scanner name taken from the scan's results, and it is applied to the "
        "scan's own output directory."
    ),
    ("tests/snapshot/mcp/test_snapshot_mcp_session_tools.py", "_files_under", "root"): (
        "The source an MCP session extracted, under the workspace root that the "
        "isolated_mcp_state fixture points at tmp_path."
    ),
    (
        "tests/unit/converters/test_converter_scanned_tree.py",
        "test_a_regular_archive_beside_a_symlinked_one_still_extracts",
        "extracted",
    ): (
        "What the converter extracted, under the work directory of "
        "test_plugin_context, which is inside this test's ash_temp_path."
    ),
    (".github/scripts/assert-publish-surfaces.py", "scan_tree", "github_dir"): (
        "The checkout's .github, which test_publish_surfaces_match_the_workflows "
        "passes as GITHUB_DIR. It holds workflows and scripts; no test or scan "
        "writes a per-run directory there."
    ),
    **{
        (path, function, "sandbox"): (
            "A session directory the test made with mark_session_workspace under "
            "its own tmp_path workspace root, holding only what the test wrote."
        )
        for path, function in (
            (
                "tests/unit/cli/mcp/test_session_workspace_is_removed_when_the_session_ends.py",
                "_sandbox_with_age",
            ),
            ("tests/unit/cli/mcp/test_session_workspace_lifecycle.py", "_sandbox"),
            (
                "tests/unit/cli/mcp/test_the_sweep_never_removes_a_running_scans_tree.py",
                "_age",
            ),
        )
    },
    **dict.fromkeys(
        (
            (
                "tests/unit/converters/test_archive_converter_limits.py",
                "files_written",
                "root",
            ),
            (
                "tests/unit/converters/test_archive_converter_limits.py",
                "assert_extracted",
                "extracted",
            ),
            (
                "tests/unit/converters/test_archive_plain_gzip_and_lfs_pointers.py",
                "written",
                "root",
            ),
            (
                "tests/unit/converters/test_archive_target_directories.py",
                "written",
                "root",
            ),
            (
                "tests/unit/converters/test_archive_target_directories.py",
                "test_a_failing_archive_leaves_nothing_where_another_was_extracted",
                "Path(converter.results_dir)",
            ),
            ("tests/unit/converters/test_archive_unreadable.py", "files_under", "root"),
        ),
        "The archive converter's results directory, or a directory it "
        "extracted into, under the output directory of the test's own "
        "plugin context in tmp_path.",
    ),
    (
        "tests/unit/interactions/test_scan_ignore_file_switch.py",
        "test_the_scan_set_is_every_file_but_ash_own_exclusions",
        "run.tree",
    ): "The tree the module's scans fixture built under tmp_path_factory.",
    ("tests/utils/container_scan.py", "scan_inside", "source"): (
        "A mount source of a container command a test assembled: that test's own "
        "tmp_path tree, output directory and config files. scan_inside is the "
        "harness the container tests share to play the scan inside."
    ),
    (
        "tests/unit/interactions/test_outer_modes_refuse_an_unusable_config_on_the_host.py",
        "output_snapshot",
        "self.output",
    ): "The output directory of the scan the test set up under its tmp_path.",
    **dict.fromkeys(
        (
            (
                "tests/unit/plugin_modules/ash_builtin/test_npm_audit_links_leaving_the_tree.py",
                "fake_run",
                "cwd",
            ),
            (
                "tests/unit/plugin_modules/ash_builtin/test_npm_audit_project_rc_ignored.py",
                "fake_run",
                "cwd",
            ),
        ),
        "The directory npm-audit hands its package manager: a project the test "
        "wrote under tmp_path, or the private copy package_manager_child makes "
        "of it.",
    ),
    **dict.fromkeys(
        (
            (
                "tests/unit/reporters/test_secret_masking_across_reports.py",
                "_written_outside_tool_output",
                "output_dir",
            ),
            (
                "tests/unit/reporters/test_secret_masking_across_reports.py",
                "test_the_projects_report_what_this_relies_on",
                "two_project_output / 'projects' / 'web'",
            ),
        ),
        "The output directory of a workspace scan the test ran under tmp_path.",
    ),
    (
        "tests/unit/test_agent_plugin_ash_version.py",
        "test_every_version_files_path_exists",
        "REPO_ROOT",
    ): (
        "Globs commitizen's version_files entries, which are literal paths with "
        "no wildcard, so the glob resolves one path and never descends. "
        "test_the_version_files_exemption_is_still_sound asserts that."
    ),
    (
        "tests/unit/utils/test_cdk_nag_unevaluated_rule.py",
        "test_the_prefix_appears_verbatim_in_the_installed_distribution",
        "root",
    ): (
        "The installed cdk-nag distribution, found through importlib.util.find_spec; "
        "no test creates or removes anything in it."
    ),
    ("tests/utils/gitleaks_fixture.py", "materialize", "dest"): (
        "The copy of the gitleaks fixture repository that materialize itself just "
        "made with shutil.copytree; every caller passes a path under its own "
        "tmp_path, and copytree refuses one that exists."
    ),
    ("tests/utils/trivy_fixture.py", "materialize", "dest"): (
        "The copy of the trivy fixture repository that materialize itself just made "
        "with shutil.copytree, under the caller's tmp_path."
    ),
    (
        "tests/integration/scanners/test_gitleaks_real_binary.py",
        "test_ash_scan_reports_critical_findings_and_writes_no_secret",
        "output",
    ): (
        "The output directory of the scan this test ran, inside its copy of the "
        "fixture under tmp_path."
    ),
    (
        "tests/unit/plugin_modules/ash_builtin/test_gitleaks_scanner.py",
        "fake_run",
        "root",
    ): (
        "The working directory the gitleaks scanner under test hands its re-scan: "
        "a directory of ASH's copies under the scanner's results directory, which "
        "the test puts under tmp_path."
    ),
}

_CONVERTER_OUTPUT = (
    "What the converter wrote, under the work directory of test_plugin_context, "
    "which is inside this test's own ash_temp_path. Only that test's teardown "
    "removes it, so no other worker races the walk."
)
_TEST_OWN_TREE = (
    "A directory this test (or its module-scoped fixture) made with tmp_path or "
    "tmp_path_factory.mktemp and passed in; the guard cannot follow the argument. "
    "Nothing outside that test removes it."
)
_NPM_AUDIT_CWD = (
    "The directory the npm-audit child was started in: a staged copy under the "
    "test's tmp_path, never the checkout or the scratch root."
)
_PRODUCT_PACKAGE = (
    "A subtree of the checkout's automated_security_helper package, resolved "
    "through a call the guard cannot follow; no per-run directory lies under it."
)
_SCANNER_STAGED_COPY = (
    "The directory the stand-in tool was handed on its command line: the "
    "scanner's own staged copy or rescan tree under the test's tmp_path output."
)
_PMC_COPY = (
    "The private copy package_manager_child made of the test's own tmp_path "
    "package, under the parent directory the test created."
)
_ACT_RUN_TREE = (
    "A directory of the act/CI-runner session the integration docs tests set up: "
    "the run's artifact store, output or work directory under the test's own "
    "session root in tmp."
)
_SCENARIO_TREE = (
    "The characterization scenario's own tree under its tmp path: <SRC>, <OUT>, "
    "<WORK> or the scenario's tmp itself. Only this scenario's teardown removes it."
)
_NON_UTF8_TREE = (
    "The test's own tree of non-UTF-8 names under its tmp_path; _entries reads "
    "it back bytes-for-bytes."
)

#: Walks of a directory the test made for itself, passed in as an argument or
#: returned by a call, so the guard cannot resolve it. Same rules as _EXEMPT.
_EXEMPT.update(
    {
        (
            "tests/unit/converters/test_archive_converter_limits.py",
            "files_written",
            "root",
        ): _CONVERTER_OUTPUT,
        (
            "tests/unit/converters/test_archive_converter_limits.py",
            "assert_extracted",
            "extracted",
        ): _CONVERTER_OUTPUT,
        (
            "tests/unit/converters/test_archive_target_directories.py",
            "written",
            "root",
        ): _CONVERTER_OUTPUT,
        (
            "tests/unit/converters/test_archive_target_directories.py",
            "test_a_failing_archive_leaves_nothing_where_another_was_extracted",
            "Path(converter.results_dir)",
        ): _CONVERTER_OUTPUT,
        (
            "tests/unit/converters/test_archive_plain_gzip_and_lfs_pointers.py",
            "written",
            "root",
        ): _CONVERTER_OUTPUT,
        (
            "tests/unit/converters/test_archive_unreadable.py",
            "files_under",
            "root",
        ): _CONVERTER_OUTPUT,
        (
            "tests/unit/interactions/test_scan_ignore_file_switch.py",
            "test_the_scan_set_is_every_file_but_ash_own_exclusions",
            "run.tree",
        ): (
            "The tree this module built under tmp_path_factory.mktemp for one scan "
            "variant; the scans fixture returns it from a cache the guard cannot read."
        ),
        (
            "tests/unit/reporters/test_secret_masking_across_reports.py",
            "_written_outside_tool_output",
            "output_dir",
        ): _TEST_OWN_TREE,
        (
            "tests/unit/reporters/test_secret_masking_across_reports.py",
            "test_the_projects_report_what_this_relies_on",
            "two_project_output / 'projects' / 'web'",
        ): _TEST_OWN_TREE,
        (
            "tests/unit/cli/mcp/test_the_sweep_never_removes_a_running_scans_tree.py",
            "_age",
            "sandbox",
        ): _TEST_OWN_TREE,
        (
            "tests/unit/cli/mcp/test_session_workspace_is_removed_when_the_session_ends.py",
            "_sandbox_with_age",
            "sandbox",
        ): _TEST_OWN_TREE,
        (
            "tests/unit/cli/mcp/test_session_workspace_lifecycle.py",
            "_sandbox",
            "sandbox",
        ): _TEST_OWN_TREE,
        (
            "tests/unit/plugin_modules/ash_builtin/test_npm_audit_links_leaving_the_tree.py",
            "fake_run",
            "cwd",
        ): _NPM_AUDIT_CWD,
        (
            "tests/unit/plugin_modules/ash_builtin/test_npm_audit_project_rc_ignored.py",
            "fake_run",
            "cwd",
        ): _NPM_AUDIT_CWD,
    }
)

#: Walks of a tree that only exists at run time, grouped by what makes it safe.
#: The receiver strings are the guard's own rendering; same rules as _EXEMPT.
_EXEMPT.update(
    {
        # act / CI-runner session trees
        (
            "tests/integration/docs/ci_runners/reports.py",
            "aggregated_results_in",
            "root",
        ): _ACT_RUN_TREE,
        (
            "tests/integration/docs/ci_runners/reports.py",
            "copy_without_links",
            "source",
        ): _ACT_RUN_TREE,
        (
            "tests/integration/docs/ci_runners/reports.py",
            "junit_counts",
            "root",
        ): _ACT_RUN_TREE,
        (
            "tests/integration/docs/ci_runners/reports.py",
            "_holds_something",
            "path",
        ): (
            "An entry of act's artifact store that artifact_problems found under the "
            "store it was given, which the tests put under their session root."
        ),
        (
            "tests/integration/docs/ci_runners/reports.py",
            "artifact_problems",
            "artifact_dir",
        ): _ACT_RUN_TREE,
        (
            "tests/integration/docs/ci_runners/reports.py",
            "results_from_artifact_store",
            "store",
        ): _ACT_RUN_TREE,
        (
            "tests/integration/docs/ci_runners/reports.py",
            "_copy_stored_artifact",
            "source",
        ): (
            "One artifact's directory inside act's store (the parent of the "
            "aggregated results file results_from_artifact_store found there), "
            "copied out for the caller."
        ),
        (
            "tests/integration/docs/ci_runners/run_act.py",
            "copy_local_uses",
            "source",
        ): (
            "A `uses:` path resolved under source_root with any '..' component "
            "refused first; local actions live under .github/, a subtree no per-run "
            "directory lies under."
        ),
        (
            "tests/integration/docs/ci_runners/run_act.py",
            "copy_local_uses",
            "target",
        ): (
            "What copytree just wrote under the act project, which the caller "
            "stages under the run's own work directory."
        ),
        (
            "tests/unit/test_docs_ci_runner_judgments.py",
            "test_every_jenkins_home_is_in_the_work_directory_and_none_is_uploaded",
            "upload",
        ): (
            "session.options.out, the upload directory of the fake session the test "
            "built under its tmp root; listing it is the assertion."
        ),
        (
            "tests/unit/test_docs_ci_runner_tools.py",
            "_tree",
            "root",
        ): (
            "A directory the archive tests extracted or staged under their own tmp "
            "paths; _tree is the module's listing helper."
        ),
        # a directory outside the checkout
        (
            "tests/integration/sandbox/test_sandbox_exec_services.py",
            "_readable_files",
            "directory",
        ): (
            "The keychain directory the unsandboxed control reads: /Library/Keychains, "
            "or Library/Keychains under developer_home, the runner's own home "
            "(_keychain_directory). Both are outside the checkout and no worker "
            "writes a per-run directory there."
        ),
        # literal globs
        (".github/scripts/combine-unit-coverage.py", "find_shard_dirs", "results"): (
            "results is the --results-dir the CI job downloads its own shard "
            "artifacts into (a tmp directory in the self-tests); the prefix "
            "main() builds from the job's OS, label and Python version carries "
            "no wildcard or separator, so the glob matches one directory "
            "level of that store and never descends."
        ),
        ("tests/unit/deploy/test_deploy_ash_cli_contract.py", "_pins", "DEPLOY"): (
            "PIN_SHAPES globs are literal module constants with no `**`, relative "
            "to deploy/, which holds no test scratch to race."
        ),
        # characterization harness
        (
            "tests/unit/characterization/_harness.py",
            "_chmod_and_remove",
            "root",
        ): (
            "A short root the harness itself created and is removing; "
            "make_writable raises before touching anything whose real path leaves "
            "real_root."
        ),
        (
            "tests/unit/characterization/_harness.py",
            "begin",
            "self.tmp",
        ): _SCENARIO_TREE,
        (
            "tests/unit/characterization/_harness.py",
            "begin",
            "self.src",
        ): _SCENARIO_TREE,
        (
            "tests/unit/characterization/_harness.py",
            "_run_scanner",
            "self.out",
        ): _SCENARIO_TREE,
        (
            "tests/unit/characterization/_harness.py",
            "golden",
            "self.src",
        ): _SCENARIO_TREE,
        (
            "tests/unit/characterization/_harness.py",
            "tree",
            "Path(root)",
        ): _SCENARIO_TREE,
        (
            "tests/unit/characterization/_harness.py",
            "_capture_argv_files",
            "path",
        ): (
            "A directory named in a captured launch's argv, listed only when "
            "_captured says it is inside the scenario's tmp (links never followed, "
            "entries capped at DIR_ENTRY_LIMIT)."
        ),
        (
            "tests/unit/characterization/test_harness_confinement.py",
            "<module>",
            "_tree(tmp)",
        ): (
            "_tree builds a two-entry fixture under its tmp argument, which every "
            "caller passes as the test's own tmp_path; the copytree source is "
            "that fixture."
        ),
        # cli, config, core
        (
            "tests/unit/cli/inspect/test_finding_text_is_not_markup.py",
            "_inspect_sources",
            "package",
        ): _PRODUCT_PACKAGE,
        (
            "tests/unit/cli/mcp/test_a_refused_scanner_selection_answers_failure.py",
            "test_a_refused_selection_leaves_the_output_tree_alone",
            "out",
        ): (
            "The workspace fixture's output directory under its tmp_path; the "
            "before/after listing is the test's whole point."
        ),
        (
            "tests/unit/cli/mcp/test_profile_registry_binding_write_is_staged.py",
            "_session_directories",
            "root",
        ): (
            "The session's directory under ASH_MCP_WORKSPACE_ROOT, which the "
            "module's autouse fixture points at a tmp_path workspace root."
        ),
        (
            "tests/unit/cli/test_outputs_hold_no_value_read_from_the_environment.py",
            "test_no_other_output_file_holds_a_value",
            "run['output']",
        ): (
            "The output directory of the scan the module's run fixture performed "
            "under its own tmp root."
        ),
        (
            "tests/unit/cli/test_recorded_config_quotes_no_env_value.py",
            "_log_files",
            "directory",
        ): (
            "A directory of the module's runs fixture, under the tmp_path_factory "
            "root it made."
        ),
        (
            "tests/unit/config/test_a_config_file_that_does_not_load_is_refused.py",
            "results_written",
            "self.output",
        ): "The output directory of the _Run, under the tmp_path the run fixture used.",
        (
            "tests/unit/core/phases/test_not_enabled_warning_quotes_no_env_value.py",
            "test_the_scan_logs_name_the_type",
            "directory",
        ): "The out directory of the module's runs fixture under its tmp root.",
        # converters
        (
            "tests/unit/converters/test_archive_member_admission.py",
            "_convert",
            "extracted",
        ): _CONVERTER_OUTPUT,
        (
            "tests/unit/converters/test_converters.py",
            "test_convert_tar_with_traversal_does_not_write_outside",
            "extracted_dir",
        ): _CONVERTER_OUTPUT,
        (
            "tests/unit/converters/test_converters.py",
            "test_convert_zip_with_traversal_does_not_write_outside",
            "extracted_dir",
        ): _CONVERTER_OUTPUT,
        (
            "tests/unit/converters/test_archive_members_ignored_in_source_terms.py",
            "_convert",
            "extracted",
        ): _CONVERTER_OUTPUT,
        (
            "tests/unit/converters/test_a_tar_is_extracted_past_where_tarfile_stops.py",
            "_extracted",
            "results",
        ): _CONVERTER_OUTPUT,
        (
            "tests/unit/converters/test_archive_members_follow_the_skip_scanning_contract.py",
            "_convert",
            "extracted",
        ): _CONVERTER_OUTPUT,
        (
            "tests/unit/converters/test_archive_converter_edge_inputs.py",
            "test_an_archive_with_a_member_past_the_host_limit_is_not_recorded_whole",
            "extracted",
        ): _CONVERTER_OUTPUT,
        (
            "tests/unit/converters/test_archive_member_named_with_a_backslash_is_scanned.py",
            "_converted",
            "extracted",
        ): _CONVERTER_OUTPUT,
        (
            "tests/unit/converters/test_which_archives_the_converter_extracts.py",
            "test_an_archive_that_fails_to_extract_leaves_nothing_and_is_refused",
            "Path(converter.results_dir)",
        ): _CONVERTER_OUTPUT,
        # scanner stand-ins reading the tree the tool was handed
        (
            "tests/unit/plugin_modules/ash_builtin/test_gitleaks_rescan_edges.py",
            "fake_run",
            "root",
        ): _SCANNER_STAGED_COPY,
        (
            "tests/unit/plugin_modules/ash_snyk_plugins/test_snyk_code_copy_is_what_snyk_reads.py",
            "run",
            "directory",
        ): _SCANNER_STAGED_COPY,
        (
            "tests/unit/plugin_modules/ash_snyk_plugins/test_snyk_code_scanner_behavior.py",
            "_side_effect",
            "tested",
        ): _SCANNER_STAGED_COPY,
        (
            "tests/unit/plugin_modules/test_walking_scanners_skip_links_leaving_the_tree.py",
            "_record",
            "tested",
        ): _SCANNER_STAGED_COPY,
        # the product package and package_manager_child copies
        (
            "tests/unit/base/test_missing_dependency_reason_has_one_reader.py",
            "_package_modules",
            "root",
        ): _PRODUCT_PACKAGE,
        (
            "tests/unit/utils/test_ignore_path_expiration.py",
            "test_no_reader_bypasses_active_ignore_paths",
            "self.PACKAGE",
        ): _PRODUCT_PACKAGE,
        (
            "tests/unit/utils/test_ignore_path_expiration.py",
            "_entry_fields",
            "self.PACKAGE",
        ): _PRODUCT_PACKAGE,
        (
            "tests/unit/utils/test_package_manager_child.py",
            "test_the_copy_holds_a_member_reached_first_through_a_link",
            "child.cwd",
        ): _PMC_COPY,
        (
            "tests/unit/utils/test_package_manager_child.py",
            "test_the_copy_holds_the_members_below_a_link_into_the_package",
            "child.cwd",
        ): _PMC_COPY,
        (
            "tests/unit/utils/test_package_manager_child.py",
            "test_the_copy_holds_the_members_below_a_linked_directory",
            "child.cwd",
        ): _PMC_COPY,
        (
            "tests/unit/utils/test_package_manager_child.py",
            "test_the_copy_holds_the_members_below_a_linked_directory_without_a_top_manifest",
            "child.cwd",
        ): _PMC_COPY,
        # non-UTF-8 fixture trees
        (
            "tests/unit/workspace/test_a_workspace_path_that_is_not_utf8_is_refused.py",
            "_entries",
            "os.fsencode(top)",
        ): _NON_UTF8_TREE,
        (
            "tests/unit/interactions/test_a_source_dir_that_is_not_utf8_is_refused.py",
            "_entries",
            "os.fsencode(top)",
        ): _NON_UTF8_TREE,
        # test helpers
        ("tests/utils/child_tool_starts.py", "starts", "directory"): (
            "The uv cache and uv tools directories the guard itself placed "
            "(self.uv_directories), under the root the test gave ChildToolStarts; "
            "listing what uv left is the probe's answer."
        ),
        (
            "tests/utils/source_delivery_doubles.py",
            "rmtree_calling_windows_unlink",
            "path",
        ): (
            "A stand-in for shutil.rmtree on Windows: it walks only the tree the "
            "caller is deleting, which every test passes as its own tmp tree."
        ),
        ("tests/utils/tool_guard.py", "files_left_in", "Path(home)"): (
            "The test's own session HOME, which the guard gave the run; listing "
            "what was left there is the assertion."
        ),
    }
)


@pytest.fixture(scope="module")
def sweep() -> Sweep:
    return Sweep.of_checkout()


@pytest.fixture(scope="module")
def offenders(sweep) -> dict:
    return sweep.offenders()


class TestNoWalkTheTestsRunEntersAPerRunDirectory:
    @pytest.mark.unit
    def test_the_sweep_reads_the_tests_and_the_scripts_they_reach(self, sweep):
        """Anti-vacuity: an empty sweep would make every assertion below pass."""
        names = {source.rel.name for source in sweep.tests}
        assert len(sweep.tests) > 500, f"only {len(sweep.tests)} test modules read"
        assert {"test_project_isolation.py", "helpers.py", "conftest.py"} <= names
        reached = {rel.as_posix(): reach.called for rel, reach in sweep.reached.items()}
        assert "collect_md_files" in reached["scripts/verify_docs_freshness.py"]
        assert "find_orphans" in reached[".github/scripts/check-snapshot-trailers.py"]
        assert sum(1 for _ in sweep.walks()) > 50, "the sweep found almost no walks"

    @pytest.mark.integration
    def test_no_walk_the_tests_run_can_enter_a_per_run_directory(self, offenders):
        unexempted = {
            key: lines for key, lines in offenders.items() if key not in _EXEMPT
        }
        assert unexempted == {}, (
            "these walks can enter a per-run directory (tests/pytest-temp, which "
            "other xdist workers create and remove, .ash/ash_output, .venv, "
            "node_modules), or walk something the guard cannot resolve. List files "
            "with git ls-files, or walk with tests.utils.helpers.iter_repo_files, "
            "which never enters the scratch tree. A receiver that only exists at run "
            "time and is safe goes in _EXEMPT with the reason:\n"
            + "\n".join(line for lines in unexempted.values() for line in lines)
        )

    @pytest.mark.integration
    def test_every_exemption_still_names_a_flagged_walk(self, offenders):
        """An exemption that matches nothing is either stale or misspelled."""
        stale = sorted(set(_EXEMPT) - set(offenders))
        assert stale == [], f"remove these from _EXEMPT: {stale}"

    @pytest.mark.unit
    def test_the_version_files_exemption_is_still_sound(self):
        """The one exemption holds only while no entry carries a wildcard.

        ``REPO_ROOT.glob("a/b.md")`` resolves one path. ``REPO_ROOT.glob("**/b.md")``
        walks the whole tree and would race exactly like the rest. So the exemption
        is conditional, and this is the condition.

        Read through the package's own ``_load_toml`` rather than ``tomllib``.
        ``tomllib`` is standard library only from 3.11 while ``requires-python``
        floors at 3.10, and a module-level ``import tomllib`` took out this whole
        file -- and therefore the guard itself -- on all three 3.10 legs.
        """
        settings = _load_toml(REPO_ROOT / "pyproject.toml")["tool"]["commitizen"]

        entries = settings["version_files"]
        assert entries, "version_files is empty, so the exemption guards nothing"
        wildcarded = [entry for entry in entries if "*" in entry or "?" in entry]
        assert wildcarded == [], (
            "a version_files entry now carries a wildcard, so "
            "test_every_version_files_path_exists globs recursively and races the "
            "scratch tree. Either drop the wildcard or convert that test to "
            "iter_repo_files and remove its exemption here: " + repr(wildcarded)
        )


def _source(rel: str, text: str) -> Source:
    return Source(PurePosixPath(rel), textwrap.dedent(text))


def _values(expression: str, bindings: str = "", rel: str = "tests/unit/test_x.py"):
    """What ``expression`` evaluates to after ``bindings``, in a synthetic module."""
    source = _source(rel, textwrap.dedent(bindings) + f"\n_PROBE = {expression}\n")
    return Evaluator([source]).lookup("_PROBE", source, None)


_PER_RUN = tuple(PurePosixPath(d) for d in PER_RUN_DIRS)


def _flagged(*sources: Source, scripts: tuple = ()) -> dict:
    """``(function, receiver)`` -> reasons, for a synthetic tree."""
    found = Sweep(sources, scripts).offenders(_PER_RUN)
    return {(fn, receiver): lines for (_, fn, receiver), lines in found.items()}


@pytest.mark.unit
class TestTheEvaluator:
    """What a receiver can be, read from the AST; nothing is imported or run."""

    def test_path_arithmetic_on_the_file_resolves_to_the_checkout(self):
        assert _values("Path(__file__).resolve().parents[2]") == {
            InRepo(PurePosixPath("."))
        }
        assert _values("Path(__file__).parent.parent") == {
            InRepo(PurePosixPath("tests"))
        }
        assert _values(
            "ROOT / 'tests' / 'unit'", "ROOT = Path(__file__).parents[2]"
        ) == {InRepo(PurePosixPath("tests/unit"))}
        assert _values("Path(f'{ROOT}/docs')", "ROOT = Path(__file__).parents[2]") == {
            InRepo(PurePosixPath("docs"))
        }

    def test_private_directories_are_recognized(self):
        source = """
            def f(tmp_path, tmp_path_factory, ash_temp_path):
                a = tmp_path / "x"
                b = tmp_path_factory.mktemp("y")
                c = Path(f"{ash_temp_path}/z")
                d = Path.home() / ".cache"
                return a, b, c, d
        """
        module = _source("tests/unit/test_x.py", source)
        evaluator = Evaluator([module])
        func = module.functions["f"][0]
        for name in "abcd":
            values = evaluator.lookup(name, module, func)
            assert values and all(isinstance(v, Private) for v in values), (
                name,
                values,
            )

    def test_loops_tuples_dicts_and_constructor_keywords_are_followed(self):
        bindings = """
            ROOT = Path(__file__).parents[2]
            DIRS = (ROOT / ".github", ROOT / "scripts")
            BY_NAME = {"a": ROOT / "docs"}
            context = PluginContext(output_dir=ROOT / "out")
        """
        assert _values(
            "LAST", textwrap.dedent(bindings) + "for d in DIRS:\n    LAST = d\n"
        ) == {
            InRepo(PurePosixPath(".github")),
            InRepo(PurePosixPath("scripts")),
        }
        assert _values("BY_NAME['a']", bindings) == {InRepo(PurePosixPath("docs"))}
        assert _values("context.output_dir", bindings) == {InRepo(PurePosixPath("out"))}

    def test_the_working_directory_is_the_checkout(self):
        """pytest runs from the repository root, so a walk of the cwd walks it."""
        root = {InRepo(PurePosixPath("."))}
        assert _values("Path.cwd()") == root
        assert _values("os.getcwd()", "import os") == root
        assert _values("Path('tests')") == {InRepo(PurePosixPath("tests"))}

    def test_anything_else_is_unknown_and_nothing_is_executed(self):
        for expression in (
            "__import__('subprocess').run(['false'])",
            "open('/etc/passwd').read()",
            "Path(__file__).with_name('x')",
            "UNBOUND / 'tests'",
            "Path(__file__).parents[UNBOUND]",
        ):
            values = _values(expression)
            assert values and not any(
                isinstance(v, (InRepo, Private)) for v in values
            ), (
                expression,
                values,
            )


@pytest.mark.unit
class TestTheDetector:
    """Synthetic trees: what is flagged, and what is not."""

    def test_walks_of_a_tree_holding_the_scratch_directory_are_flagged(self):
        test = _source(
            "tests/unit/test_x.py",
            """
            import ast, os, shutil
            from pathlib import Path
            REPO = Path(__file__).resolve().parents[2]
            REPO_ROOT = Path(__file__).resolve().parents[2]
            TESTS = REPO / "tests"
            PKG = REPO / "automated_security_helper"

            def a(): return REPO.rglob("*.yml")
            def b(): return TESTS.rglob("*.py")
            def c(): return list(os.walk(REPO))
            def d(dst): shutil.copytree(REPO, dst)
            def e(): return REPO.glob("**/x.yml")
            def f(): return PKG.rglob("*.py")
            def g(): return REPO.glob("*.yml")
            def h(): return REPO.glob(".github/**/*.yml")
            def i(tmp_path): return tmp_path.rglob("*")
            def j(ash_temp_path): return ash_temp_path.rglob("*")
            def k(tree): return ast.walk(tree)
            def m(where): return where.rglob("*")
            def n(): return _helper(REPO)
            def o(tmp_path): return _helper(tmp_path)
            def _helper(root): return list(root.rglob("*"))
            def p(): return REPO_ROOT.rglob("*")
            """,
        )
        flagged = _flagged(test)
        assert set(flagged) == {
            ("a", "REPO"),
            ("b", "TESTS"),
            ("c", "REPO"),
            ("d", "REPO"),
            ("e", "REPO"),
            ("m", "where"),
            ("_helper", "root"),
            ("p", "REPO_ROOT"),
        }, flagged
        assert "holds tests/pytest-temp/" in flagged[("b", "TESTS")][0]
        assert "cannot be resolved" in flagged[("m", "where")][0]

    def test_a_script_walk_is_flagged_only_when_a_test_runs_it_on_the_checkout(self):
        """The two shapes the first guard missed, in scripts the tests load."""
        docs = _source(
            "scripts/docs_gate.py",
            """
            from pathlib import Path
            REPO_ROOT = Path(__file__).resolve().parent.parent
            def collect_md_files():
                return sorted(REPO_ROOT.rglob("*.md"))
            def never_called():
                return sorted(REPO_ROOT.rglob("*.txt"))
            """,
        )
        orphans = _source(
            ".github/scripts/orphans.py",
            """
            def find_orphans(root):
                return sorted((root / "tests").rglob("__snapshots__"))
            """,
        )
        on_checkout = _source(
            "tests/unit/test_on_checkout.py",
            """
            import importlib.util
            from pathlib import Path
            REPO_ROOT = Path(__file__).resolve().parents[2]

            def gate():
                spec = importlib.util.spec_from_file_location(
                    "g", REPO_ROOT / "scripts" / "docs_gate.py"
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module

            def trailers():
                spec = importlib.util.spec_from_file_location(
                    "t", REPO_ROOT / ".github/scripts/orphans.py"
                )
                return importlib.util.module_from_spec(spec)

            def test_docs(gate):
                assert gate.collect_md_files()

            def test_orphans(trailers):
                assert trailers.find_orphans(REPO_ROOT) == []
            """,
        )
        flagged = _flagged(on_checkout, scripts=(docs, orphans))
        assert set(flagged) == {
            ("collect_md_files", "REPO_ROOT"),
            ("find_orphans", "root / 'tests'"),
        }, flagged

        on_tmp_only = _source(
            "tests/unit/test_on_tmp.py",
            textwrap.dedent(
                """
                import importlib.util
                from pathlib import Path
                REPO_ROOT = Path(__file__).resolve().parents[2]

                def trailers():
                    spec = importlib.util.spec_from_file_location(
                        "t", REPO_ROOT / ".github/scripts/orphans.py"
                    )
                    return importlib.util.module_from_spec(spec)

                def test_orphans(trailers, tmp_path):
                    assert trailers.find_orphans(tmp_path) == []
                """
            ),
        )
        assert _flagged(on_tmp_only, scripts=(docs, orphans)) == {}

    def test_node_modules_is_per_run_only_beside_a_package_json_outside_tests(self):
        """npm installs beside a project's package.json; a fixture's is test data."""
        found = node_modules_dirs(
            [
                "package.json",
                "deploy/cdk/package.json",
                "tests/test_data/scanners/guarddog/fixture_repo/npm_clean/package.json",
                "docs/not-a-package.json",
            ]
        )
        assert found == {
            PurePosixPath("node_modules"),
            PurePosixPath("deploy/cdk/node_modules"),
        }

    def test_prose_about_the_hazard_is_not_counted_as_the_hazard(self):
        """``helpers.py`` quotes the traceback; an AST check must not see it.

        Stated as a test because a future maintainer hitting a false positive here
        would reasonably reach for the delete key on the explanation, and the
        explanation is the most useful thing in that module.
        """
        helpers = (TESTS_ROOT / "utils" / "helpers.py").read_text(encoding="utf-8")
        assert "REPO_ROOT.rglob" in helpers, (
            "helpers.py no longer quotes the traceback, so this test is checking "
            "nothing about how the detector treats prose"
        )
        flagged = _flagged(_source("tests/utils/helpers.py", helpers))
        assert set(flagged) == {("iter_repo_files", "root")}, flagged


@pytest.mark.unit
class TestIterRepoFilesPrunesTheScratchTree:
    """The helper's own behavior, since five call sites now depend on it."""

    def test_a_scratch_file_is_not_yielded(self, ash_temp_path):
        planted = ash_temp_path / "planted_probe.py"
        planted.write_text("x = 1\n", encoding="utf-8")

        assert planted.exists(), "the fixture did not write the probe"
        yielded = {p.resolve() for p in iter_repo_files(REPO_ROOT)}
        assert planted.resolve() not in yielded

    def test_it_yields_real_source(self):
        """The companion: pruning must not have emptied the walk."""
        yielded = {p.name for p in iter_repo_files(REPO_ROOT)}
        assert "pyproject.toml" in yielded
        assert "helpers.py" in yielded

    def test_prune_scratch_false_does_yield_the_scratch_file(self, ash_temp_path):
        """The opt-out has to opt out, or the control that uses it proves nothing."""
        planted = ash_temp_path / "planted_probe.py"
        planted.write_text("x = 1\n", encoding="utf-8")

        yielded = {p.resolve() for p in iter_repo_files(REPO_ROOT, prune_scratch=False)}
        assert planted.resolve() in yielded

    def test_skip_dirs_is_honored(self):
        yielded = set(iter_repo_files(REPO_ROOT, skip_dirs=frozenset({"tests"})))
        assert not any("tests" in p.relative_to(REPO_ROOT).parts for p in yielded)
        assert yielded, "skipping tests/ emptied the whole walk"

    def test_a_vanishing_path_outside_the_scratch_tree_is_not_silently_skipped(
        self, tmp_path
    ):
        """The tolerance must be narrow, or blindness reads as cleanliness.

        ``os.walk`` ignores errors by default. If ``iter_repo_files`` inherited
        that, a walk that failed for any reason would return a short list and every
        sweep built on it would report a clean repository. Only the scratch tree is
        silently skipped; this pins that a path outside it is not classified as
        scratch, which is what routes it to the re-raising branch.
        """
        outside = tmp_path / "not-scratch"
        outside.mkdir()

        assert not is_under_test_scratch(outside)
        assert is_under_test_scratch(ASH_TEST_TEMP_ROOT / "whatever")

    def test_the_scratch_root_is_inside_the_repository(self):
        """If it were not, pruning it would be a no-op and this is all theatre."""
        assert ASH_TEST_TEMP_ROOT.resolve().is_relative_to(REPO_ROOT.resolve())


#: Walkers outside tests/ that tests run against the real checkout. The AST sweep
#: above reads tests/ only, so it cannot see them.
_SCRIPT_WALKERS = {
    "docs-corpus": REPO_ROOT / "scripts" / "verify_docs_freshness.py",
    "snapshot-orphans": REPO_ROOT
    / ".github"
    / "scripts"
    / "check-snapshot-trailers.py",
}


def _load_script(which: str) -> ModuleType:
    path = _SCRIPT_WALKERS[which]
    name = f"_walker_under_test_{which.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    # check-snapshot-trailers declares dataclasses, which resolve through sys.modules.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _run_walker(which: str) -> list[str]:
    """The walker's output as strings: collected files, or orphan problems."""
    module = _load_script(which)
    if which == "docs-corpus":
        return [str(path) for path in module.collect_md_files()]
    return list(module.find_orphans(REPO_ROOT))


def _plant(scratch: Path) -> Path:
    """A directory in the scratch tree holding what each walker would pick up."""
    planted = scratch / "planted"
    (planted / "inner" / "__snapshots__").mkdir(parents=True)
    (planted / "inner" / "planted_probe.md").write_text("# probe\n", encoding="utf-8")
    return planted


# Runs in a child interpreter, because an audit hook cannot be removed and a test
# worker should not keep one. The hook watches every directory listing. The first
# listing of the planted directory, or of anything under it, removes the planted
# directory before the listing proceeds: what another worker's ash_temp_path teardown
# does mid-walk, made deterministic. ``entered`` records every such listing.
_MID_WALK_REMOVAL = r"""
import importlib.util, json, os, shutil, sys
from pathlib import Path

repo, planted, script, which = sys.argv[1:5]
planted = os.path.realpath(planted)
sys.path.insert(0, repo)
state = {"armed": False, "entered": [], "removed": False}


def hook(event, args):
    if not state["armed"] or event not in ("os.scandir", "os.listdir"):
        return
    target = args[0] if args else None
    if target is None or isinstance(target, int):
        return
    path = os.path.realpath(os.fsdecode(target))
    if path != planted and not path.startswith(planted + os.sep):
        return
    state["entered"].append(path)
    if not state["removed"]:
        state["removed"] = True
        state["armed"] = False
        shutil.rmtree(planted)
        state["armed"] = True


sys.addaudithook(hook)
spec = importlib.util.spec_from_file_location("walker", script)
module = importlib.util.module_from_spec(spec)
sys.modules["walker"] = module
spec.loader.exec_module(module)
state["armed"] = True
try:
    if which == "docs-corpus":
        result = [str(p) for p in module.collect_md_files()]
    else:
        result = list(module.find_orphans(Path(repo)))
    error = None
except Exception as exc:
    result, error = None, f"{type(exc).__name__}: {exc}"
state["armed"] = False
print(json.dumps({"error": error, "entered": state["entered"],
                  "removed": state["removed"],
                  "returned": None if result is None else len(result)}))
"""


@pytest.mark.integration
@pytest.mark.parametrize("which", sorted(_SCRIPT_WALKERS))
class TestScriptWalkersStayOutOfTheScratchTree:
    """Two walkers in scripts that tests run on the real checkout, under xdist.

    ``scripts/verify_docs_freshness.py``'s ``collect_md_files`` walked
    ``REPO_ROOT.rglob("*.md")``, and ``test_docs_freshness_gate_can_fail`` runs it.
    ``.github/scripts/check-snapshot-trailers.py``'s ``find_orphans`` walked
    ``(root / "tests").rglob("__snapshots__")``, and ``test_snapshot_policy`` runs it
    on the repository. Both descended into ``tests/pytest-temp`` while other workers
    created and removed directories there: the scandir-during-descent race described
    at the top of this file, from code the AST sweep does not read.

    Each walker now takes its file list from git, which does not enter an ignored
    directory, and the scratch tree is ignored. The first test shows nothing in the
    scratch tree reaches a walker's output; the second removes a scratch directory at
    the moment a walker lists it and shows the walker never got there.
    """

    def test_nothing_in_the_scratch_tree_reaches_the_output(self, which, ash_temp_path):
        planted = _plant(ash_temp_path)

        output = _run_walker(which)

        assert planted.exists(), "the walker removed the planted directory"
        leaked = [entry for entry in output if "pytest-temp" in entry]
        assert leaked == [], f"{which} read the scratch tree: {leaked}"

    def test_a_scratch_directory_removed_mid_walk_is_never_entered(
        self, which, ash_temp_path
    ):
        planted = _plant(ash_temp_path)

        child = subprocess.run(
            [
                sys.executable,
                "-c",
                _MID_WALK_REMOVAL,
                str(REPO_ROOT),
                str(planted),
                str(_SCRIPT_WALKERS[which]),
                which,
            ],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=REPO_ROOT,
        )
        assert child.returncode == 0, child.stdout + child.stderr
        report = json.loads(child.stdout.strip().splitlines()[-1])

        assert report["error"] is None, (
            f"{which} raised when a scratch directory vanished mid-walk: "
            f"{report['error']}"
        )
        assert report["entered"] == [], (
            f"{which} listed a scratch directory, so it races any worker removing "
            f"one: {report['entered']}"
        )
        assert report["returned"] is not None
        if which == "docs-corpus":
            assert report["returned"] > 100, "the corpus came back nearly empty"
        assert planted.exists()


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
