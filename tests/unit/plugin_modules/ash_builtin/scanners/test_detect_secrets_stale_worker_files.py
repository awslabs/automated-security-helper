# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Stale detect-secrets worker files are removed when a scan starts.

The worker's request file carries the scan settings, environment-derived
values included, and its output file carries raw findings. Both live in the
scanner's results directory, which is what CI uploads, and both are deleted in
``_scan_in_worker``'s ``finally`` -- but a run killed outright leaves them
behind. A later scan over the same output directory removes them before it
writes anything, even when it ends early with nothing to scan, so a leftover
never rides along with a newer run's upload.

A private temp location instead was measured and rejected: under the bwrap
backend the worker sees a fresh tmpfs on /tmp (the file does not exist there),
and under the Landlock backend the read is refused, so a request file outside
the policy's mounted directories is unreadable exactly where the sandbox wraps
the worker.
"""

import os
import stat
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit


def _lockfile_only_scanner(tmp_path, monkeypatch):
    """A scanner whose scan starts and ends at "no scannable files".

    The source holds only a generated lockfile, which the scan set drops, so
    the worker is never reached and the start-of-scan cleanup is the only code
    that touches the worker file names.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
    )

    # Into tmp_path first: the baseline lookup checks .secrets.baseline paths
    # against the working directory, so a baseline there would replace the
    # scanner's configured settings.
    monkeypatch.chdir(tmp_path)
    for name in ("source", "output", "work"):
        (tmp_path / name).mkdir()
    (tmp_path / "source" / "package-lock.json").write_text("{}", encoding="utf-8")
    ctx = PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="stale-worker-files"),
    )
    config = DetectSecretsScannerConfig()
    scanner = DetectSecretsScanner(context=ctx, config=config)
    scanner.dependencies_satisfied = True
    monkeypatch.setattr(scanner, "_pre_scan", lambda **_kwargs: True)
    return scanner, ctx, config


def test_stale_worker_files_removed_on_a_scan_with_nothing_to_scan(
    tmp_path, monkeypatch
):
    scanner, ctx, config = _lockfile_only_scanner(tmp_path, monkeypatch)

    stale_dir = Path(scanner.results_dir).joinpath("source")
    stale_dir.mkdir(parents=True, exist_ok=True)
    request = stale_dir / "detect-secrets-worker-request.json"
    output = stale_dir / "detect-secrets-worker-output.json"
    request.write_text('{"settings": {"left": "by a killed run"}}', encoding="utf-8")
    output.write_text("[]", encoding="utf-8")

    scanner.scan(target=ctx.source_dir, target_type="source", config=config)

    assert not request.exists(), "stale worker request file left in the results dir"
    assert not output.exists(), "stale worker output file left in the results dir"


def test_cleanup_does_not_follow_a_symlinked_results_directory(tmp_path, monkeypatch):
    """A link planted at the target's results directory removes nothing outside.

    fs_guard's open_for_write already refuses a link on the write; the cleanup
    is the one other operation on these names, so it has to refuse the same
    way rather than unlink through the link.
    """
    scanner, ctx, config = _lockfile_only_scanner(tmp_path, monkeypatch)

    outside = tmp_path / "outside"
    outside.mkdir()
    outside_request = outside / "detect-secrets-worker-request.json"
    outside_request.write_text('{"settings": {"someone": "elses"}}', encoding="utf-8")
    results_dir = Path(scanner.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    try:
        (results_dir / "source").symlink_to(outside)
    except OSError:
        pytest.skip("this runner cannot create symlinks")

    scanner.scan(target=ctx.source_dir, target_type="source", config=config)

    assert outside_request.exists(), (
        "the cleanup followed the planted results-directory link and removed a "
        "file outside the results tree"
    )


def test_a_directory_at_a_worker_file_name_does_not_fail_the_early_cleanup(
    tmp_path, monkeypatch
):
    """A directory sitting at a worker file name is logged and left in place
    by the start-of-scan cleanup. This covers the cleanup only: a scan that
    goes on to reach the worker still fails at that directory (open_for_write
    refuses a directory at the request name, and the output name's removal
    refuses one there), until the operator removes it. This scan ends at "no
    scannable files", so only the cleanup sees the obstruction."""
    scanner, ctx, config = _lockfile_only_scanner(tmp_path, monkeypatch)

    stale_dir = Path(scanner.results_dir).joinpath("source")
    blocking = stale_dir / "detect-secrets-worker-request.json"
    blocking.mkdir(parents=True)

    # Must not raise: the cleanup logs the obstruction and the scan goes on to
    # its "no scannable files" end.
    scanner.scan(target=ctx.source_dir, target_type="source", config=config)

    assert blocking.is_dir(), "the directory at the worker file name was removed"


def test_stale_worker_files_removed_when_the_target_is_empty(tmp_path, monkeypatch):
    """The cleanup runs before every early return, the empty target included.

    An empty target directory ends the scan before anything else happens, and
    a converted-target scan takes this path whenever no converter produced
    output -- exactly the runs a leftover from a killed scan would otherwise
    sit through.
    """
    scanner, ctx, config = _lockfile_only_scanner(tmp_path, monkeypatch)
    (ctx.source_dir / "package-lock.json").unlink()

    stale_dir = Path(scanner.results_dir).joinpath("source")
    stale_dir.mkdir(parents=True, exist_ok=True)
    request = stale_dir / "detect-secrets-worker-request.json"
    request.write_text('{"settings": {"left": "by a killed run"}}', encoding="utf-8")

    scanner.scan(target=ctx.source_dir, target_type="source", config=config)

    assert not request.exists(), "the empty-target skip left the stale file"


def test_a_failed_cleanup_does_not_fail_the_scan(tmp_path, monkeypatch):
    """A cleanup refusal is logged and the scan goes on.

    An orphaned worker still holding the file, or a permission the results
    tree lost, must cost the run one WARNING, not the whole secrets scan.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )

    scanner, ctx, config = _lockfile_only_scanner(tmp_path, monkeypatch)

    def _refused(_root, _parts):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(module, "unlink_beneath", _refused)

    # Must not raise: the refusal is logged and the scan reaches its
    # "no scannable files" end.
    scanner.scan(target=ctx.source_dir, target_type="source", config=config)


def test_the_worker_removes_its_request_file_before_the_scan_runs(
    tmp_path, monkeypatch
):
    """The worker unlinks the request file between the parse and the scan.

    The caller's finally removes it for a run that ends; this covers the run
    that is killed mid-scan, shrinking the window the settings (environment-
    derived values included) sit in the results directory from the whole scan
    to the parse. The ORDER is the property: gone-after-main would also pass
    with the unlink after the scan, which is the whole window again. ``run``
    is stubbed to record whether the file still exists when the scan starts --
    which also keeps ``run``'s ``multiprocessing.set_start_method('fork',
    force=True)`` out of the pytest process, where it would change global
    state for every later test.
    """
    import json

    from automated_security_helper.utils import detect_secrets_worker

    request = tmp_path / "detect-secrets-worker-request.json"
    output = tmp_path / "detect-secrets-worker-output.json"
    request.write_text(
        json.dumps(
            {
                "root": str(tmp_path),
                "baseline": None,
                "settings": {"plugins_used": [{"name": "AWSKeyDetector"}]},
                "paths": [],
            }
        ),
        encoding="utf-8",
    )
    present_at_scan = []

    def _run(req):
        present_at_scan.append(request.exists())
        return []

    monkeypatch.setattr(detect_secrets_worker, "run", _run)

    assert detect_secrets_worker.main([str(request), str(output)]) == 0
    assert present_at_scan == [False], (
        "the request file must already be gone when the scan starts"
    )
    assert output.exists(), "the worker wrote no output"


@pytest.mark.skipif(
    not hasattr(os, "fchmod") or os.name == "nt",
    reason=(
        "POSIX modes: Windows under 3.13 has no fchmod, and on 3.13+ it only "
        "toggles the read-only bit, so S_IMODE never reads 0o600"
    ),
)
def test_the_request_file_is_written_owner_only(tmp_path, monkeypatch):
    """The request file is mode 0600 while it exists.

    It holds the scan settings, environment-derived values included, in the
    results directory; owner-only, so nothing else on the host reads it in
    the window before the worker removes it.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )
    from automated_security_helper.utils import subprocess_utils

    scanner, ctx, config = _lockfile_only_scanner(tmp_path, monkeypatch)
    secrets_collection_cls, _, _ = module._detect_secrets_api()
    scanner._secrets_collection = secrets_collection_cls()
    scanner._secrets_collection.root = ctx.source_dir
    seen_modes = []

    def _record_mode(**kwargs):
        for argument in kwargs.get("command", []):
            if str(argument).endswith("detect-secrets-worker-request.json"):
                seen_modes.append(stat.S_IMODE(Path(argument).stat().st_mode))
        return {"timed_out": True}

    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", _record_mode
    )
    work_dir = tmp_path / "worker-dir"
    work_dir.mkdir()

    scanner._scan_in_worker(
        baseline=None,
        scan_paths=[str(ctx.source_dir / "package-lock.json")],
        scan_settings_dict={"plugins_used": [{"name": "AWSKeyDetector"}]},
        work_dir=work_dir,
        scan_timeout=60,
    )

    assert seen_modes, "the worker command named no request file"
    assert seen_modes == [0o600], [oct(m) for m in seen_modes]


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_open_for_write_creates_a_file_with_the_given_mode(tmp_path):
    """The request file STARTS owner-only, not just ends up owner-only.

    Permissions are checked when a file is opened: a file created at the open()
    default (0o666 less the umask) and tightened by fchmod afterwards leaves a
    window in which a local reader who opens the empty file keeps read access
    to the JSON written next. A creation mode closes it: the file is 0o600
    from its first instant.
    """
    from automated_security_helper.utils.sandbox.fs_guard import open_for_write

    target = tmp_path / "request.json"
    with open_for_write(target, mode=0o600) as fp:
        mode = stat.S_IMODE(os.fstat(fp.fileno()).st_mode)
    assert mode == 0o600, oct(mode)


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_open_for_write_without_a_mode_matches_plain_open(tmp_path):
    """The control: without a mode, open_for_write keeps open()'s permissions
    (0o666 less the umask), so the guard still changes nothing for every other
    caller."""
    from automated_security_helper.utils.sandbox.fs_guard import open_for_write

    with open(tmp_path / "plain.txt", "w", encoding="utf-8") as fp:
        plain_mode = stat.S_IMODE(os.fstat(fp.fileno()).st_mode)
    with open_for_write(tmp_path / "guarded.txt") as fp:
        guarded_mode = stat.S_IMODE(os.fstat(fp.fileno()).st_mode)
    assert guarded_mode == plain_mode, (oct(guarded_mode), oct(plain_mode))


@pytest.mark.parametrize(
    "made", ["nothing", "results-dir-only"], ids=["fresh-output", "no-target-dir"]
)
def test_a_scan_on_a_fresh_output_directory_warns_nothing(tmp_path, monkeypatch, made):
    """The start-of-scan cleanup runs before the scanner's results directory
    for the target exists, which is every normal run on a fresh output
    directory. A missing directory is nothing to remove: no WARNING. Every
    other cell here creates the directory or patches the removal, so only this
    one sees the fresh case."""
    import logging

    from automated_security_helper.utils.log import ASH_LOGGER

    scanner, ctx, config = _lockfile_only_scanner(tmp_path, monkeypatch)
    results_dir = Path(scanner.results_dir)
    if made == "results-dir-only":
        results_dir.mkdir(parents=True)
    assert not (results_dir / "source").exists(), "the cell needs a fresh tree"
    warnings = []

    class _Collect(logging.Handler):
        def emit(self, record):
            warnings.append(record.getMessage())

    collector = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(collector)
    try:
        scanner.scan(target=ctx.source_dir, target_type="source", config=config)
    finally:
        ASH_LOGGER.removeHandler(collector)

    stale = [w for w in warnings if "stale" in w or "A directory sits" in w]
    assert stale == [], stale


def _worker_ready_scanner(tmp_path, monkeypatch):
    """A scanner, its config, and a work directory inside a results tree, set
    up to call ``_scan_in_worker`` directly."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )

    scanner, ctx, config = _lockfile_only_scanner(tmp_path, monkeypatch)
    secrets_collection_cls, _, _ = module._detect_secrets_api()
    scanner._secrets_collection = secrets_collection_cls()
    scanner._secrets_collection.root = ctx.source_dir
    work_dir = tmp_path / "results" / "source"
    work_dir.mkdir(parents=True)
    return scanner, ctx, module, work_dir


def _call_worker(scanner, ctx, work_dir):
    return scanner._scan_in_worker(
        baseline=None,
        scan_paths=[str(ctx.source_dir / "package-lock.json")],
        scan_settings_dict={"plugins_used": [{"name": "AWSKeyDetector"}]},
        work_dir=work_dir,
        scan_timeout=60,
    )


def test_a_finished_worker_run_leaves_neither_exchange_file(tmp_path, monkeypatch):
    """After a normal run, the request (the scan settings, environment-derived
    values included) and the output (raw findings) are both gone from the
    results directory CI uploads. The stand-in worker leaves its request in
    place, as a worker killed before its own early unlink would, so the
    finally is what removes both."""
    from automated_security_helper.utils import subprocess_utils

    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    request = work_dir / module.WORKER_REQUEST_FILE_NAME
    output = work_dir / module.WORKER_OUTPUT_FILE_NAME
    seen = []

    def _write_output(**_kwargs):
        seen.append(request.exists())
        output.write_text("[]", encoding="utf-8")
        return {"returncode": 0}

    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", _write_output
    )

    assert _call_worker(scanner, ctx, work_dir) is not None
    assert seen == [True], "the cell needs the request present while the worker runs"
    assert not request.exists(), "the request file was left in the results directory"
    assert not output.exists(), "the output file was left in the results directory"


def test_a_directory_at_one_exchange_name_keeps_the_scan_and_the_other_removal(
    tmp_path, monkeypatch
):
    """The finally removes each name on its own. A directory at the request
    name, which a process the worker left behind could put there once the
    worker removed its request, refuses that removal. The output's removal
    still runs, the scan's own result stands, and the refusal is a warning
    naming the file, as the start-of-scan cleanup does."""
    import logging

    from automated_security_helper.utils import subprocess_utils
    from automated_security_helper.utils.log import ASH_LOGGER

    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    request = work_dir / module.WORKER_REQUEST_FILE_NAME
    output = work_dir / module.WORKER_OUTPUT_FILE_NAME

    def _leave_a_directory(**_kwargs):
        output.write_text("[]", encoding="utf-8")
        request.unlink()
        request.mkdir()
        return {"returncode": 0}

    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", _leave_a_directory
    )
    warnings = []

    class _Collect(logging.Handler):
        def emit(self, record):
            warnings.append(record.getMessage())

    collector = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(collector)
    try:
        result = _call_worker(scanner, ctx, work_dir)
    finally:
        ASH_LOGGER.removeHandler(collector)

    assert result is not None
    assert not output.exists(), "the output's removal did not run"
    assert request.is_dir(), "the cell needs the directory left in place"
    assert any(module.WORKER_REQUEST_FILE_NAME in w for w in warnings), warnings


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
def test_a_work_directory_that_is_a_link_is_refused_before_anything_is_written(
    tmp_path, monkeypatch
):
    """A work directory that is a link is refused before the request is
    written, and the scan fails naming it. Nothing is written at the link's
    target, neither the request (the scan settings, environment-derived values
    among them) nor the raw findings, and the worker never starts.
    """
    from automated_security_helper.core.exceptions import ScannerError
    from automated_security_helper.utils import subprocess_utils

    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    work_dir.rmdir()
    work_dir.symlink_to(elsewhere, target_is_directory=True)
    started = []

    def _write_output(**_kwargs):
        started.append(True)
        (work_dir / module.WORKER_OUTPUT_FILE_NAME).write_text("[]", encoding="utf-8")
        return {"returncode": 0}

    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", _write_output
    )

    with pytest.raises(ScannerError, match="is a link or not a directory") as refused:
        _call_worker(scanner, ctx, work_dir)

    assert str(work_dir) in str(refused.value), refused.value
    assert started == [], "the worker started through the refused directory"
    assert not (elsewhere / module.WORKER_REQUEST_FILE_NAME).exists()
    assert not (elsewhere / module.WORKER_OUTPUT_FILE_NAME).exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
def test_a_work_directory_swapped_for_a_link_keeps_the_finally_inside(
    tmp_path, monkeypatch
):
    """The worker's removals refuse a link at the work directory itself.

    The finally runs right after the sandboxed process ended, the moment a
    process it left behind could have replaced the work directory with a link.
    Removing the two fixed names below that directory, with the directory
    opened by following links, would delete same-named files wherever the link
    points. Here the directory is swapped mid-run for a link to a directory
    holding both names; those two files must survive.
    """
    from automated_security_helper.utils import subprocess_utils

    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    outside = tmp_path / "outside"
    outside.mkdir()
    decoys = [
        outside / module.WORKER_REQUEST_FILE_NAME,
        outside / module.WORKER_OUTPUT_FILE_NAME,
    ]
    for decoy in decoys:
        decoy.write_text("not ASH's", encoding="utf-8")

    def _swap_then_time_out(**_kwargs):
        work_dir.rename(tmp_path / "results" / "moved-away")
        work_dir.symlink_to(outside, target_is_directory=True)
        return {"timed_out": True}

    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", _swap_then_time_out
    )

    assert _call_worker(scanner, ctx, work_dir) is None
    assert [decoy.exists() for decoy in decoys] == [True, True], (
        "the worker's finally deleted files outside the work directory"
    )


@pytest.mark.skipif(not hasattr(os, "fchmod") or os.name == "nt", reason="POSIX modes")
@pytest.mark.parametrize("left_behind", [False, True], ids=["fresh", "left-behind"])
def test_the_request_file_is_owner_only_when_the_tighten_is_refused(
    tmp_path, monkeypatch, left_behind
):
    """Owner-only for the whole run even on a filesystem that refuses chmod.

    Fresh: the file is created 0o600 (open_for_write's mode), so the refused
    tighten costs nothing. Left behind by a killed run at 0o644: opening it
    truncates it but keeps its mode, so with the tighten refused the settings
    would sit world-readable for the whole scan; the stale file is removed
    first, so this run's file is created 0o600 too.
    """
    from automated_security_helper.utils import subprocess_utils

    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    request = work_dir / module.WORKER_REQUEST_FILE_NAME
    if left_behind:
        request.write_text("{}", encoding="utf-8")
        request.chmod(0o644)
    monkeypatch.setattr(
        os, "fchmod", lambda fd, mode: (_ for _ in ()).throw(OSError(1, "refused"))
    )
    seen_modes = []

    def _record_mode(**_kwargs):
        seen_modes.append(stat.S_IMODE(request.stat().st_mode))
        return {"timed_out": True}

    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", _record_mode
    )

    assert _call_worker(scanner, ctx, work_dir) is None
    assert seen_modes == [0o600], [oct(m) for m in seen_modes]


MIB = 1 << 20


def _worker_writing(monkeypatch, module, work_dir, size):
    """The worker stand-in writes *size* bytes of output: an empty result,
    padded with the whitespace JSON allows after it."""
    from automated_security_helper.utils import subprocess_utils

    def _write_output(**_kwargs):
        (work_dir / module.WORKER_OUTPUT_FILE_NAME).write_bytes(
            b"[]" + b" " * (size - 2)
        )
        return {"returncode": 0}

    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", _write_output
    )


def _assert_names_the_limit(error_text, mib, cap=4096):
    """The refusal names the limit, the option that sets it, its cap, where the
    operator sets it, and the other remedy: the whole text."""
    assert error_text == (
        f"The detect-secrets worker's output is larger than {mib} MiB, the "
        "scanner's max_worker_output_mib, so none of its findings were read. "
        "Raise scanners.detect-secrets.options.max_worker_output_mib (at most "
        f"{cap}) with --config-overrides or a config file outside the scanned "
        "tree, or leave the files that produce most of the findings out of the "
        "scan with ignore_paths."
    ), error_text


class _ReadOfLength:
    """A stand-in for read_bytes_at_most's result that reports a length, so no
    file of that size is written."""

    def __init__(self, length):
        self._length = length

    def __len__(self):
        return self._length


def test_an_output_past_a_configured_limit_is_refused_naming_the_option(
    tmp_path, monkeypatch
):
    """The read-back is bounded by the scanner's max_worker_output_mib: output
    one byte past it is an error, not a parse, and the error says how to raise
    the limit. A process the worker left behind may have grown the file."""
    from automated_security_helper.core.exceptions import ScannerError

    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    scanner.config.options.max_worker_output_mib = 1
    _worker_writing(monkeypatch, module, work_dir, MIB + 1)

    with pytest.raises(ScannerError) as excinfo:
        _call_worker(scanner, ctx, work_dir)

    _assert_names_the_limit(str(excinfo.value), 1)


def test_an_output_at_a_configured_limit_is_read(tmp_path, monkeypatch):
    """The control: output of exactly the limit is read and parsed."""
    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    scanner.config.options.max_worker_output_mib = 1
    _worker_writing(monkeypatch, module, work_dir, MIB)

    _call_worker(scanner, ctx, work_dir)


def test_the_default_limit_is_256_mib_and_named_when_passed(tmp_path, monkeypatch):
    """At the default, the read asks for 256 MiB and one byte, and output past
    it is refused naming 256 MiB. Measured: a finding is about 300 bytes of
    output, so 64 MiB failed a legitimate scan of about 220,000 findings. No
    256 MiB file is written: the read is stood in for by one that reports its
    length."""
    from automated_security_helper.core.exceptions import ScannerError

    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    _worker_writing(monkeypatch, module, work_dir, 2)
    asked = []

    def _read(path, limit):
        asked.append(limit)
        return _ReadOfLength(limit)

    monkeypatch.setattr(module, "read_bytes_at_most", _read)

    with pytest.raises(ScannerError) as excinfo:
        _call_worker(scanner, ctx, work_dir)

    assert asked == [256 * MIB + 1], asked
    _assert_names_the_limit(str(excinfo.value), 256)


def test_an_output_past_the_largest_limit_is_refused_offering_only_ignore_paths(
    tmp_path, monkeypatch
):
    """At MAX_WORKER_OUTPUT_MIB the option cannot be raised, so the refusal
    says the limit is the most the option allows and offers only ignore_paths.
    The read is stood in for, as at the default."""
    from automated_security_helper.core.exceptions import ScannerError

    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    cap = module.MAX_WORKER_OUTPUT_MIB
    scanner.config.options.max_worker_output_mib = cap
    _worker_writing(monkeypatch, module, work_dir, 2)
    asked = []

    def _read(path, limit):
        asked.append(limit)
        return _ReadOfLength(limit)

    monkeypatch.setattr(module, "read_bytes_at_most", _read)

    with pytest.raises(ScannerError) as excinfo:
        _call_worker(scanner, ctx, work_dir)

    assert asked == [cap * MIB + 1], asked
    assert str(excinfo.value) == (
        f"The detect-secrets worker's output is larger than {cap} MiB, the most "
        "max_worker_output_mib allows, so none of its findings were read. Leave "
        "the files that produce most of the findings out of the scan with "
        "ignore_paths."
    ), str(excinfo.value)


def test_the_cap_the_refusal_names_is_the_options_bound(tmp_path, monkeypatch):
    """The "(at most N)" in the advice is MAX_WORKER_OUTPUT_MIB as the refusal
    is made, so the advice cannot name a cap the option does not have."""
    from automated_security_helper.core.exceptions import ScannerError

    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "MAX_WORKER_OUTPUT_MIB", 2048)
    scanner.config.options.max_worker_output_mib = 1
    _worker_writing(monkeypatch, module, work_dir, MIB + 1)

    with pytest.raises(ScannerError) as excinfo:
        _call_worker(scanner, ctx, work_dir)

    _assert_names_the_limit(str(excinfo.value), 1, cap=2048)


def test_the_option_s_description_and_bound_are_written_with_the_cap():
    """The field's ``le`` bound and the "at most N" in its description are
    written with MAX_WORKER_OUTPUT_MIB, the cap the refusal names: a literal
    4096 in either reads the same today and stays behind when the constant
    moves, which no value check notices."""
    import ast
    import inspect

    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )

    tree = ast.parse(inspect.getsource(module.DetectSecretsScannerConfigOptions))
    [field] = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AnnAssign)
        and getattr(node.target, "id", None) == "max_worker_output_mib"
    ]
    [call] = [
        node
        for node in ast.walk(field.annotation)
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Field"
    ]
    keywords = {keyword.arg: keyword.value for keyword in call.keywords}

    def names(node):
        return {part.id for part in ast.walk(node) if isinstance(part, ast.Name)}

    def literals(node):
        return [
            str(part.value) for part in ast.walk(node) if isinstance(part, ast.Constant)
        ]

    cap = str(module.MAX_WORKER_OUTPUT_MIB)
    for keyword in ("le", "description"):
        assert "MAX_WORKER_OUTPUT_MIB" in names(keywords[keyword]), keyword
        assert not [text for text in literals(keywords[keyword]) if cap in text], (
            keyword
        )


@pytest.mark.parametrize("value", [0, -1])
def test_a_limit_that_is_not_positive_is_refused(value):
    from pydantic import ValidationError

    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScannerConfigOptions,
    )

    # The control: a positive limit loads.
    assert (
        DetectSecretsScannerConfigOptions(max_worker_output_mib=8).max_worker_output_mib
        == 8
    )
    with pytest.raises(ValidationError):
        DetectSecretsScannerConfigOptions(max_worker_output_mib=value)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
def test_a_worker_output_replaced_by_a_link_is_not_read(tmp_path, monkeypatch):
    """The read-back does not follow a link left at the output name: the
    file it points to is never parsed as this scan's findings."""
    from automated_security_helper.utils import subprocess_utils

    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text("[]", encoding="utf-8")

    def _link_output(**_kwargs):
        (work_dir / module.WORKER_OUTPUT_FILE_NAME).symlink_to(elsewhere)
        return {"returncode": 0}

    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", _link_output
    )

    with pytest.raises(OSError):
        _call_worker(scanner, ctx, work_dir)


@pytest.mark.skipif(not hasattr(os, "fchmod"), reason="fchmod tightens here")
def test_a_refused_fchmod_does_not_fail_the_scan(tmp_path, monkeypatch):
    """Tightening a request file that already existed is best-effort.

    os.fchmod can be refused by the filesystem (an output tree on a CIFS or
    FUSE mount that rejects chmod). The file was already created owner-only,
    so the refusal costs a DEBUG line, not the whole secrets scan -- the
    cleanup beside it is best-effort too.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )
    from automated_security_helper.utils import subprocess_utils

    scanner, ctx, config = _lockfile_only_scanner(tmp_path, monkeypatch)
    secrets_collection_cls, _, _ = module._detect_secrets_api()
    scanner._secrets_collection = secrets_collection_cls()
    scanner._secrets_collection.root = ctx.source_dir

    def _refused(fd, mode):
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(os, "fchmod", _refused)
    monkeypatch.setattr(
        subprocess_utils,
        "run_command_with_output_handling",
        lambda **kwargs: {"timed_out": True},
    )
    work_dir = tmp_path / "worker-dir"
    work_dir.mkdir()

    # Must not raise: the timed-out return is the scan's answer, and the
    # refused tighten is a DEBUG line.
    out = scanner._scan_in_worker(
        baseline=None,
        scan_paths=[str(ctx.source_dir / "package-lock.json")],
        scan_settings_dict={"plugins_used": [{"name": "AWSKeyDetector"}]},
        work_dir=work_dir,
        scan_timeout=60,
    )
    assert out is None
