"""The outer wrappers must not answer from a results file this invocation did not produce.

Container mode and Nix mode both re-execute ASH somewhere else and then read
``ash_aggregated_results.json`` back from the output directory. Neither wrapper can tell
"the scan did not happen" from "the scan happened and disliked what it found": the inner
entrypoint is this same CLI, so its exit codes are ASH's own, and every pre-run refusal in
``run_ash_container`` -- a non-numeric ``--container-uid``, a rejected revision, an
unresolvable OCI runner, a failed image build -- also reports 1.

So the file on disk is the only evidence, and without these tests it is not evidence at
all: it may have been written by an earlier run, of a different repository, with a
different scanner set. A stale clean report then reads as a clean scan.

The exit code is not the only casualty, and not the worst one. ``reports/`` is what a
caller publishes -- a summary comment, JUnit check results, a SARIF upload to code
scanning -- and publish steps usually run on failure as well as success, so that a failed
scan still explains itself. A wrapper that fixes only the exit code leaves an honest
non-zero status beside a previous run's clean report, which is the same false negative
wearing a badge a reviewer trusts more.

The tests below pin five properties:

1. Output that predates the invocation is not read back or left to be published. The
   wrappers clear what a local scan clears -- the four working directories and the three
   files the orchestrator removes -- so ``exists()`` afterwards means "this invocation
   produced this". ``projects/`` is excluded, because workspace mode's per-project trees
   are inputs to the run that follows.
2. A terminal status that is not a verdict is propagated rather than discarded. Verdicts
   are 0, 1 and 2, the statuses reached from a results file; 3 (invalid config) and 4
   (workspace definition or policy error) assert the opposite and must not be flattened
   into the read-back's 1. Exit 2 IS a verdict and must still reach the host's own
   exit-code computation, because the host applies filters the container was never told
   about.
3. A run that legitimately consumes an existing results file (``--use-existing``, which
   the host resolves into ``existing_results``) is exempt from (1), otherwise the fix
   would delete the very input that shape exists to read -- and the exemption is decided
   on the same truthiness ``run_ash_container`` uses to send ``--use-existing``, so the
   empty string cannot fall between them.
4. The refusal when cleanup fails is conditioned on the artifact still being there, not on
   the call having raised. A lost race, or a partial removal that finished the job, is not
   a reason to refuse a scan that would work.
5. A cleanup that cannot finish refuses the scan rather than proceeding, because a false
   clean report is worse than a refusal an operator can see.
"""

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _run_container_mode,
    _run_nix_mode,
)
from automated_security_helper.utils.subprocess_utils import create_completed_process

# A name that cannot have come from this invocation. Asserting on it, rather than on a
# finding count, is what makes "the wrapper answered from the stale file" observable: the
# wrapper either hands back a model carrying this name or it does not.
STALE_MARKER = "Report from an earlier run of a different repository"


def _seed_stale_results(output_dir: Path) -> Path:
    """Write a results file carrying critical findings and a recognizable name."""
    output_dir.mkdir(parents=True, exist_ok=True)
    results_file = output_dir / "ash_aggregated_results.json"
    results_file.write_text(
        json.dumps(
            {
                "name": STALE_MARKER,
                "sarif": {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "stale-scanner"}},
                            "results": [
                                {
                                    "ruleId": "STALE-001",
                                    "level": "error",
                                    "message": {"text": "critical finding"},
                                    "properties": {"issue_severity": "CRITICAL"},
                                }
                            ],
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    return results_file


def _seed_stale_sarif(output_dir: Path) -> Path:
    """Write the SARIF report that _compute_exit_code re-reads to count findings."""
    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    sarif_file = reports_dir / "ash.sarif"
    sarif_file.write_text(
        json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8"
    )
    return sarif_file


def _seed_stale_published_reports(output_dir: Path) -> dict[str, Path]:
    """Write the report files a caller publishes after the scan step, pass or fail.

    Named individually rather than as a glob because each has its own consumer, and the
    point of the assertion is that every one of them is gone: the summary becomes a pull
    request comment, the JUnit XML becomes check results, the GHAS SARIF is uploaded to
    code scanning.
    """
    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    published = {
        "summary_md": reports_dir / "ash.summary.md",
        "summary_txt": reports_dir / "ash.summary.txt",
        "junit": reports_dir / "ash.junit.xml",
        "ghas_sarif": reports_dir / "ash.ghas.sarif",
        "html": reports_dir / "ash.html",
    }
    for path in published.values():
        path.write_text(f"{STALE_MARKER}: no findings\n", encoding="utf-8")
    return published


def _seed_stale_working_tree(output_dir: Path) -> dict[str, Path]:
    """Write the remaining entries a local scan clears, one per name.

    Three files from ``ASHScanOrchestrator.initialize`` and the three working directories
    from ``ensure_directories`` that are not ``reports``. The whole output directory is
    uploaded as a build artifact by callers, so a stale scanner log is published too.
    """
    seeded: dict[str, Path] = {}
    for directory in ("analysis", "scanners", "converted"):
        path = output_dir / directory / "leftover.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(STALE_MARKER, encoding="utf-8")
        seeded[directory] = path
    for name in ("ash-ignore-report.txt", "ash-scan-set-files-list.txt"):
        path = output_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(STALE_MARKER, encoding="utf-8")
        seeded[name] = path
    return seeded


def _opts(tmp_path: Path, **overrides) -> ScanOptions:
    kwargs = {
        "source_dir": tmp_path / "src",
        "output_dir": tmp_path / "out",
    }
    kwargs.update(overrides)
    return ScanOptions(**kwargs)


class TestContainerModeStaleResults:
    def test_a_container_that_never_ran_is_not_answered_from_a_stale_file(
        self, tmp_path
    ):
        """returncode 1 with nothing written: every pre-run refusal has this shape."""
        opts = _opts(tmp_path)
        stale = _seed_stale_results(opts.output_dir)

        # What run_ash_container actually returns when it refuses before the run phase:
        # a CompletedProcess with returncode 1 and an empty argv. Nothing was built and
        # nothing was run, so nothing was written either.
        never_ran = create_completed_process(
            args=[],
            returncode=1,
            stdout="",
            stderr="Container UID must be a numeric value",
        )

        with (
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_container",
                return_value=never_ran,
            ),
            pytest.raises(SystemExit) as exit_info,
        ):
            _run_container_mode(opts, MagicMock())

        assert exit_info.value.code != 0
        assert exit_info.value.code != 2, (
            "2 means actionable findings, which asserts a scan happened; a container "
            "that never started has not shown the target to be clean or dirty"
        )
        assert not stale.exists(), (
            "the pre-existing results file must be removed before the run, so that its "
            "presence afterwards is evidence this invocation produced it"
        )

    def test_a_stale_sarif_report_is_removed_as_well(self, tmp_path):
        """_compute_exit_code recounts findings from reports/ash.sarif and lets that
        count override the in-memory one, so a stale SARIF decides the exit code on its
        own."""
        opts = _opts(tmp_path)
        _seed_stale_results(opts.output_dir)
        stale_sarif = _seed_stale_sarif(opts.output_dir)

        with (
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_container",
                return_value=create_completed_process(
                    args=[], returncode=1, stdout="", stderr="build failed"
                ),
            ),
            pytest.raises(SystemExit),
        ):
            _run_container_mode(opts, MagicMock())

        assert not stale_sarif.exists()

    def test_the_reports_a_caller_publishes_do_not_survive_a_container_that_never_ran(
        self, tmp_path
    ):
        """The exit code is honest and the published artifacts are not, without this.

        A caller's publish steps run on failure as well as success, so that a failed scan
        still explains itself. With only ``ash_aggregated_results.json`` and
        ``reports/ash.sarif`` removed, a build that never started still hands a previous
        run's summary to a pull request comment, its JUnit XML to check results and its
        GHAS SARIF to code scanning. Clearing the directory is what makes the report agree
        with the status.
        """
        opts = _opts(tmp_path)
        _seed_stale_results(opts.output_dir)
        published = _seed_stale_published_reports(opts.output_dir)
        working = _seed_stale_working_tree(opts.output_dir)

        with (
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_container",
                return_value=create_completed_process(
                    args=[], returncode=1, stdout="", stderr="image build failed"
                ),
            ),
            pytest.raises(SystemExit),
        ):
            _run_container_mode(opts, MagicMock())

        survivors = sorted(
            path.as_posix()
            for path in (*published.values(), *working.values())
            if path.exists()
        )
        assert survivors == [], (
            "every output a local scan clears must be cleared here too, or a caller "
            f"publishes a previous run's verdict: {survivors}"
        )

    def test_workspace_per_project_output_is_not_cleared(self, tmp_path):
        """``projects/<key>/`` is an input to the run that follows, not stale output.

        Workspace mode writes a complete single-project tree per project and the outer run
        rewrites only the unified top-level files. Widening the cleanup to the whole output
        directory would delete the per-project reports the workspace summary is built from.
        """
        opts = _opts(tmp_path)
        _seed_stale_results(opts.output_dir)
        per_project = opts.output_dir / "projects" / "service-a" / "reports"
        per_project.mkdir(parents=True, exist_ok=True)
        project_report = per_project / "ash.summary.md"
        project_report.write_text("per-project report", encoding="utf-8")

        with (
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_container",
                return_value=create_completed_process(
                    args=[], returncode=1, stdout="", stderr=""
                ),
            ),
            pytest.raises(SystemExit),
        ):
            _run_container_mode(opts, MagicMock())

        assert project_report.exists()

    def test_a_reports_path_that_is_a_file_is_removed_rather_than_refused(
        self, tmp_path
    ):
        """``reports`` as a regular file takes the unlink branch, not an rmtree failure.

        Removing it is what lets the inner run create the directory it expects. Refusing
        instead would turn a recoverable output directory into a scan that cannot start.
        """
        opts = _opts(tmp_path)
        opts.output_dir.mkdir(parents=True, exist_ok=True)
        not_a_directory = opts.output_dir / "reports"
        not_a_directory.write_text("left behind by something else", encoding="utf-8")

        def clean_scan(*args, **kwargs):
            (opts.output_dir / "ash_aggregated_results.json").write_text(
                json.dumps({"name": "produced by this invocation"}), encoding="utf-8"
            )
            return create_completed_process(args=[], returncode=0, stdout="", stderr="")

        with patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_container",
            side_effect=clean_scan,
        ):
            results = _run_container_mode(opts, MagicMock())

        assert not not_a_directory.exists()
        assert results.name == "produced by this invocation"

    def test_a_non_verdict_exit_status_is_propagated_not_discarded(self, tmp_path):
        """A container killed by the runtime still leaves whatever it had written.

        Unlinking beforehand cannot catch this one -- the file exists and is fresh -- so
        the status itself has to be terminal. 137 is SIGKILL, which is what an
        out-of-memory container reports; the partial report it left behind describes only
        the scanners that finished.
        """
        opts = _opts(tmp_path)
        opts.output_dir.mkdir(parents=True, exist_ok=True)

        def kill_after_partial_write(*args, **kwargs):
            (opts.output_dir / "ash_aggregated_results.json").write_text(
                json.dumps({"name": "partial"}), encoding="utf-8"
            )
            return create_completed_process(
                args=[], returncode=137, stdout="", stderr=""
            )

        with (
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_container",
                side_effect=kill_after_partial_write,
            ),
            pytest.raises(SystemExit) as exit_info,
        ):
            _run_container_mode(opts, MagicMock())

        assert exit_info.value.code == 137

    def test_exit_two_still_reaches_the_hosts_own_exit_code_computation(self, tmp_path):
        """The regression guard on the guard above.

        The container entrypoint is this same CLI, so 2 is a legitimate verdict meaning
        actionable findings. The host recomputes it from the results -- applying
        --min-severity and --ignore-suppressions, neither of which is forwarded into the
        container -- so a blanket "exit on any non-zero status" would report findings the
        operator asked to filter out.
        """
        opts = _opts(tmp_path)
        opts.output_dir.mkdir(parents=True, exist_ok=True)

        def dirty_scan(*args, **kwargs):
            (opts.output_dir / "ash_aggregated_results.json").write_text(
                json.dumps({"name": "produced by this invocation"}), encoding="utf-8"
            )
            return create_completed_process(args=[], returncode=2, stdout="", stderr="")

        with patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_container",
            side_effect=dirty_scan,
        ):
            results = _run_container_mode(opts, MagicMock())

        assert results.name == "produced by this invocation"

    def test_a_missing_results_file_exits_non_zero_rather_than_zero(self, tmp_path):
        """Surrounding contract, not coverage of the pre-run cleanup.

        This passes with the cleanup removed -- nothing was seeded, so the file is absent
        either way. It is kept because the property it pins is the one everything else
        here depends on: an outer mode with no results file to read must not report a
        clean scan. Delete the cleanup and this stays green; break the read-back's
        else-branch and it does not.
        """
        opts = _opts(tmp_path)
        opts.output_dir.mkdir(parents=True, exist_ok=True)

        with (
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_container",
                return_value=create_completed_process(
                    args=[], returncode=1, stdout="", stderr=""
                ),
            ),
            pytest.raises(SystemExit) as exit_info,
        ):
            _run_container_mode(opts, MagicMock())

        assert exit_info.value.code != 0

    def test_use_existing_runs_keep_the_file_they_were_asked_to_read(self, tmp_path):
        """The exemption, which is surrounding contract rather than coverage of the fix.

        --use-existing resolves to this exact file on the host, and the inner scan reads it
        through the /out mount, so removing it would delete the run's only input. This
        passes with the cleanup removed too -- a cleanup that never runs also keeps the
        file -- so it does not hold the fix. It holds the boundary of the fix: it is what
        reddens if the exemption is ever dropped.
        """
        opts = _opts(tmp_path)
        existing = _seed_stale_results(opts.output_dir)
        opts.existing_results = existing.as_posix()

        with patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_container",
            return_value=create_completed_process(
                args=[], returncode=0, stdout="", stderr=""
            ),
        ):
            results = _run_container_mode(opts, MagicMock())

        assert existing.exists()
        assert results.name == STALE_MARKER

    def test_build_only_runs_do_not_touch_the_results_file(self, tmp_path):
        """--no-run builds an image and exits; it never claims to have scanned, so it has
        no business deleting a prior report."""
        opts = _opts(tmp_path, run=False)
        stale = _seed_stale_results(opts.output_dir)

        with (
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_container",
                return_value=create_completed_process(
                    args=[], returncode=0, stdout="", stderr=""
                ),
            ),
            pytest.raises(SystemExit) as exit_info,
        ):
            _run_container_mode(opts, MagicMock())

        assert exit_info.value.code == 0
        assert stale.exists()

    def test_an_empty_existing_results_does_not_exempt_the_cleanup(self, tmp_path):
        """The one value the two sites could disagree on.

        ``run_ash_container`` appends ``--use-existing`` under ``if existing_results:``, so
        an empty string asks the inner scan to read nothing. If the cleanup exempted on
        ``is not None`` instead, a programmatic caller passing "" would keep a previous
        run's results file AND get no ``--use-existing`` -- so the file survives unread and
        the read-back answers from it. That is the exact failure this module closes,
        reached through the gap between the two conditions.
        """
        opts = _opts(tmp_path, existing_results="")
        stale = _seed_stale_results(opts.output_dir)

        with (
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_container",
                return_value=create_completed_process(
                    args=[], returncode=1, stdout="", stderr=""
                ),
            ),
            pytest.raises(SystemExit) as exit_info,
        ):
            _run_container_mode(opts, MagicMock())

        assert not stale.exists()
        assert exit_info.value.code != 0


class TestContainerStatusesThatAreNotVerdicts:
    """3 and 4 are ASH's own codes and are still not verdicts.

    ``ASH_EXIT_CODES`` is the table of everything the CLI can return, which is a wider
    question than "what did a scan conclude". 3 is raised by ``_run_local_mode`` before it
    writes the results file, and 4 is defined in ``models.workspace`` specifically so that
    "nothing was scanned" is distinguishable from 2's "a scan completed and found
    something". Trusting either sends the host to a read-back that finds nothing and
    reports 1, which discards the distinction the code existed to carry.
    """

    def test_an_invalid_config_status_is_propagated_rather_than_flattened_to_one(
        self, tmp_path
    ):
        """`--config` naming a malformed file: the container exits 3 having scanned
        nothing, and 3 is what a caller needs to see."""
        opts = _opts(tmp_path)
        opts.output_dir.mkdir(parents=True, exist_ok=True)
        logger = MagicMock()

        with (
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_container",
                return_value=create_completed_process(
                    args=[], returncode=3, stdout="", stderr=""
                ),
            ),
            pytest.raises(SystemExit) as exit_info,
        ):
            _run_container_mode(opts, logger)

        assert exit_info.value.code == 3
        reported = " ".join(str(call) for call in logger.error.call_args_list)
        assert "invalid config" in reported, (
            "the status is the whole diagnostic here -- there is no report to point the "
            f"operator at -- so the message has to name what it means; got: {reported}"
        )

    def test_a_workspace_definition_error_status_is_propagated(self, tmp_path):
        """Workspace container mode: 4 means the definition was rejected and no project
        ran. Flattening it to 1 merges it with "a scan errored"."""
        opts = _opts(tmp_path)
        opts.output_dir.mkdir(parents=True, exist_ok=True)

        with (
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_container",
                return_value=create_completed_process(
                    args=[], returncode=4, stdout="", stderr=""
                ),
            ),
            pytest.raises(SystemExit) as exit_info,
        ):
            _run_container_mode(opts, MagicMock())

        assert exit_info.value.code == 4

    def test_a_scan_error_status_still_reaches_the_read_back(self, tmp_path):
        """The guard against narrowing too far.

        1 is a verdict: ``_compute_exit_code`` returns it from a results file for an
        incomplete scan or an unevaluated rule. The host has to recompute it, because it
        applies ``--min-severity`` and ``--ignore-suppressions`` and the container was told
        neither. Excluding 1 alongside 3 and 4 would exit before reading the file this
        invocation just wrote.
        """
        opts = _opts(tmp_path)
        opts.output_dir.mkdir(parents=True, exist_ok=True)

        def errored_scan(*args, **kwargs):
            (opts.output_dir / "ash_aggregated_results.json").write_text(
                json.dumps({"name": "produced by this invocation"}), encoding="utf-8"
            )
            return create_completed_process(args=[], returncode=1, stdout="", stderr="")

        with patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_container",
            side_effect=errored_scan,
        ):
            results = _run_container_mode(opts, MagicMock())

        assert results.name == "produced by this invocation"


class TestCleanupFailureRefusesOnTheArtifactNotTheCall:
    """Fail closed on "the output is still there", not on "the call raised".

    On Windows an open handle from a virus scanner, a search indexer or an editor raises
    ``PermissionError`` from ``unlink``. Where the artifact is gone anyway, refusing turns a
    scan that would have worked into an error an operator cannot act on.
    """

    def test_an_error_on_an_artifact_that_is_already_gone_does_not_refuse(
        self, tmp_path
    ):
        opts = _opts(tmp_path)
        opts.output_dir.mkdir(parents=True, exist_ok=True)

        def clean_scan(*args, **kwargs):
            (opts.output_dir / "ash_aggregated_results.json").write_text(
                json.dumps({"name": "produced by this invocation"}), encoding="utf-8"
            )
            return create_completed_process(args=[], returncode=0, stdout="", stderr="")

        # Nothing was seeded, so every path is already absent when unlink raises. shutil
        # goes through os.unlink rather than Path.unlink, so the directory branch is
        # untouched by this patch.
        with (
            patch.object(
                Path,
                "unlink",
                side_effect=PermissionError("used by another process"),
            ),
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_container",
                side_effect=clean_scan,
            ) as container,
        ):
            results = _run_container_mode(opts, MagicMock())

        assert container.called, (
            "the container must still be started: the artifact the cleanup was asked to "
            "remove is not there, which is the state the cleanup wanted"
        )
        assert results.name == "produced by this invocation"

    def test_an_artifact_that_survives_the_error_still_refuses_the_scan(self, tmp_path):
        """The other half, and the reason the re-check is not a loosening.

        A results file that is still on disk is exactly the input the read-back cannot tell
        from this invocation's own output, so the scan must not start.
        """
        opts = _opts(tmp_path)
        stale = _seed_stale_results(opts.output_dir)

        with (
            patch.object(
                Path,
                "unlink",
                side_effect=PermissionError("used by another process"),
            ),
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_container",
            ) as container,
            pytest.raises(SystemExit) as exit_info,
        ):
            _run_container_mode(opts, MagicMock())

        assert exit_info.value.code == 1
        assert not container.called
        assert stale.exists()


class TestNixModeStaleResults:
    def test_a_nix_shell_that_never_opened_is_not_answered_from_a_stale_file(
        self, tmp_path
    ):
        """`nix` present on PATH but failing returns a bare non-zero status: run_ash_nix
        requests no capture, so stdout and stderr are both None and there is nothing
        else to inspect."""
        opts = _opts(tmp_path)
        stale = _seed_stale_results(opts.output_dir)

        with (
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_nix",
                return_value=create_completed_process(args=[], returncode=1),
            ),
            pytest.raises(SystemExit) as exit_info,
        ):
            _run_nix_mode(opts, MagicMock())

        assert exit_info.value.code != 0
        assert not stale.exists()

    def test_the_non_zero_shell_status_is_reported_above_debug(self, tmp_path, caplog):
        """The console handler and both file handlers sit at INFO, so a debug-level
        report of "the shell exited non-zero" is emitted nowhere -- not to the terminal
        and not to ash.log. It is the only diagnostic this path has."""
        opts = _opts(tmp_path)
        opts.output_dir.mkdir(parents=True, exist_ok=True)

        def dirty_scan(*args, **kwargs):
            (opts.output_dir / "ash_aggregated_results.json").write_text(
                json.dumps({"name": "produced by this invocation"}), encoding="utf-8"
            )
            return create_completed_process(args=[], returncode=42)

        logger = logging.getLogger("test_nix_visibility")
        with (
            caplog.at_level(logging.WARNING, logger="test_nix_visibility"),
            patch(
                "automated_security_helper.interactions.run_ash_scan.run_ash_nix",
                side_effect=dirty_scan,
            ),
        ):
            _run_nix_mode(opts, logger)

        assert any("42" in record.message for record in caplog.records), (
            "the shell's exit status must be reported at a level the configured "
            f"handlers actually emit; captured: {[r.message for r in caplog.records]}"
        )

    def test_use_existing_runs_keep_the_file_they_were_asked_to_read(self, tmp_path):
        """The Nix copy of the exemption. Surrounding contract, not coverage of the fix --
        see the container-mode test of the same name for why it stays anyway."""
        opts = _opts(tmp_path)
        existing = _seed_stale_results(opts.output_dir)
        opts.existing_results = existing.as_posix()

        with patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_nix",
            return_value=create_completed_process(args=[], returncode=0),
        ):
            results = _run_nix_mode(opts, MagicMock())

        assert existing.exists()
        assert results.name == STALE_MARKER
