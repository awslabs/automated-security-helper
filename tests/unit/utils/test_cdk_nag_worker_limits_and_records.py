# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Bounds and records of the cdk-nag worker that the first cut left open.

Each test was red at the base it was written against:

- ``scan_timeout`` bounds the batch, so a child started after one died gets what is left
  of the limit, and nothing is started once the limit is spent;
- a child the runner could neither wait for nor stop fails every pending template and no
  new child is started beside it; a child that ended with no exit status is not said to
  have "exited None";
- an OSError raised in the child comes back as an OSError with its errno, strerror and
  file names, not as a plain Exception carrying the repr-quoted text;
- every path in the request file is absolute;
- the response is read in bounded pieces, never with one cap-sized allocation;
- the level the child collects at follows what ASH's last resort would show in-process;
- the batchless seam puts its scratch files in a temporary directory, not the cwd;
- batch membership is a set lookup.
"""

import json
import logging
import os
import tempfile
from pathlib import Path

import pytest

from automated_security_helper.utils import cdk_nag_worker
from automated_security_helper.utils import log as ash_log
from automated_security_helper.utils.subprocess_utils import COULD_NOT_STOP_REASON

pytestmark = pytest.mark.unit

SUBPROCESS_UTILS = "automated_security_helper.utils.subprocess_utils"
NOT_CFN = {"status": "not-cloudformation", "logs": []}


def _header_only_runner(outcome):
    """A runner whose child wrote the protocol header and nothing more."""

    def fake(command, **kwargs):
        response_path = Path(command[-1])
        response_path.write_text(
            json.dumps({"protocol": cdk_nag_worker.PROTOCOL_VERSION}) + "\n",
            encoding="utf-8",
        )
        return dict(outcome)

    return fake


# ---------------------------------------------------------------------------
# The batch's time limit
# ---------------------------------------------------------------------------


def test_a_retry_child_gets_what_is_left_of_the_scan_timeout(tmp_path, monkeypatch):
    """At the base every child was started with the full timeout."""
    clock = {"now": 1000.0}
    monkeypatch.setattr(cdk_nag_worker.time, "monotonic", lambda: clock["now"])
    seen = []

    def fake_run_child(
        pending, options, work_root, cwd, timeout, values, *, declared_timeout=None
    ):
        seen.append((list(pending), timeout, declared_timeout))
        clock["now"] += 100.0
        if len(seen) == 1:
            return (
                [NOT_CFN],
                "the cdk-nag worker process exited 1 before answering: x",
                False,
                {"returncode": 1},
            )
        return [NOT_CFN for _ in pending], None, False, {"returncode": 0}

    monkeypatch.setattr(cdk_nag_worker, "_run_child", fake_run_child)
    batch = cdk_nag_worker._Batch(
        ["a.yaml", "b.yaml", "c.yaml"], tmp_path, tmp_path, timeout=300.0, values=()
    )

    batch._evaluate(list(batch.templates), {"nag_packs": ["AwsSolutionsChecks"]})

    assert seen[0][1] == 300.0
    assert seen[0][2] == 300.0
    assert seen[1][0] == ["c.yaml"]
    assert seen[1][1] == pytest.approx(200.0)
    assert seen[1][2] == 300.0
    assert "b.yaml" in batch.errors
    assert "c.yaml" in batch.answers


def test_no_child_is_started_once_the_scan_timeout_is_spent(tmp_path, monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(cdk_nag_worker.time, "monotonic", lambda: clock["now"])
    seen = []

    def fake_run_child(
        pending, options, work_root, cwd, timeout, values, *, declared_timeout=None
    ):
        seen.append(list(pending))
        clock["now"] += 400.0
        return (
            [NOT_CFN],
            "the cdk-nag worker process exited 1 before answering: x",
            False,
            {"returncode": 1},
        )

    monkeypatch.setattr(cdk_nag_worker, "_run_child", fake_run_child)
    batch = cdk_nag_worker._Batch(
        ["a.yaml", "b.yaml", "c.yaml"], tmp_path, tmp_path, timeout=300.0, values=()
    )

    batch._evaluate(list(batch.templates), {})

    assert len(seen) == 1
    assert "time ran out" in batch.errors["c.yaml"]
    assert "scan_timeout" in batch.errors["c.yaml"]


def test_no_child_is_started_with_less_than_it_needs_to_start(tmp_path, monkeypatch):
    """With 0.3 s of the limit left a child was still started; it cannot get past jsii
    startup, is certain to time out, and the pending templates then read "timed out
    after 300 s ... was killed" beside an extra timed-out record. Below the minimum the
    "time ran out" reason, which describes this case, is given without a child."""
    clock = {"now": 1000.0}
    monkeypatch.setattr(cdk_nag_worker.time, "monotonic", lambda: clock["now"])
    seen = []

    def fake_run_child(
        pending, options, work_root, cwd, timeout, values, *, declared_timeout=None
    ):
        seen.append(list(pending))
        clock["now"] += 300.0 - 0.3
        return (
            [NOT_CFN],
            "the cdk-nag worker process exited 1 before answering: x",
            False,
            {"returncode": 1},
        )

    monkeypatch.setattr(cdk_nag_worker, "_run_child", fake_run_child)
    batch = cdk_nag_worker._Batch(
        ["a.yaml", "b.yaml", "c.yaml"], tmp_path, tmp_path, timeout=300.0, values=()
    )

    batch._evaluate(list(batch.templates), {})

    assert len(seen) == 1
    assert "time ran out" in batch.errors["c.yaml"]
    assert "was killed" not in batch.errors["c.yaml"]
    assert batch.failed_child_responses == [{"returncode": 1}]


def test_a_batch_with_no_timeout_bounds_nothing(tmp_path, monkeypatch):
    seen = []

    def fake_run_child(
        pending, options, work_root, cwd, timeout, values, *, declared_timeout=None
    ):
        seen.append(timeout)
        if len(seen) == 1:
            return (
                [NOT_CFN],
                "the cdk-nag worker process exited 1 before answering: x",
                False,
                {"returncode": 1},
            )
        return [NOT_CFN for _ in pending], None, False, {"returncode": 0}

    monkeypatch.setattr(cdk_nag_worker, "_run_child", fake_run_child)
    batch = cdk_nag_worker._Batch(
        ["a.yaml", "b.yaml", "c.yaml"], tmp_path, tmp_path, timeout=None, values=()
    )

    batch._evaluate(list(batch.templates), {})

    assert seen == [None, None]


# ---------------------------------------------------------------------------
# A child the runner could not stop, outside a timeout
# ---------------------------------------------------------------------------


def test_a_child_that_could_not_be_stopped_fails_the_rest_now(tmp_path, monkeypatch):
    """At the base the reason read 'exited None' and the rest went to a new child."""
    monkeypatch.setattr(
        f"{SUBPROCESS_UTILS}.run_command_with_output_handling",
        _header_only_runner(
            {"returncode": None, "could_not_stop": True, "stderr": "wait failed"}
        ),
    )

    answers, reason, fail_rest, recorded = cdk_nag_worker._run_child(
        ["a.yaml", "b.yaml"], {}, tmp_path / "out", tmp_path, 30.0, ()
    )

    assert answers == []
    assert fail_rest is True
    assert COULD_NOT_STOP_REASON in reason
    assert "exited None" not in reason
    assert "no new worker was started" in reason
    assert recorded.get("could_not_stop") is True


def test_no_second_child_starts_beside_one_that_could_not_be_stopped(
    tmp_path, monkeypatch
):
    calls = []

    def fake_run_child(
        pending, options, work_root, cwd, timeout, values, *, declared_timeout=None
    ):
        calls.append(list(pending))
        return (
            [],
            f"the cdk-nag worker did not finish, and {COULD_NOT_STOP_REASON}.",
            True,
            {"returncode": None, "could_not_stop": True},
        )

    monkeypatch.setattr(cdk_nag_worker, "_run_child", fake_run_child)
    batch = cdk_nag_worker._Batch(
        ["a.yaml", "b.yaml", "c.yaml"], tmp_path, tmp_path, timeout=30.0, values=()
    )

    batch._evaluate(list(batch.templates), {})

    assert calls == [["a.yaml", "b.yaml", "c.yaml"]]
    assert set(batch.errors) == {"a.yaml", "b.yaml", "c.yaml"}
    assert batch.could_not_stop_response is not None


def test_a_child_with_no_exit_status_is_not_said_to_have_exited_none(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        f"{SUBPROCESS_UTILS}.run_command_with_output_handling",
        _header_only_runner({"returncode": None, "stderr": "gone"}),
    )

    _, reason, fail_rest, _ = cdk_nag_worker._run_child(
        ["a.yaml"], {}, tmp_path / "out", tmp_path, 30.0, ()
    )

    assert fail_rest is False
    assert "exited None" not in reason
    assert "ended without an exit status" in reason
    assert "gone" in reason


def test_a_child_with_an_exit_status_still_names_it(tmp_path, monkeypatch):
    monkeypatch.setattr(
        f"{SUBPROCESS_UTILS}.run_command_with_output_handling",
        _header_only_runner({"returncode": 3, "stderr": "boom"}),
    )

    _, reason, _, _ = cdk_nag_worker._run_child(
        ["a.yaml"], {}, tmp_path / "out", tmp_path, 30.0, ()
    )

    assert "exited 3 before answering: boom" in reason


# ---------------------------------------------------------------------------
# An OSError across the boundary
# ---------------------------------------------------------------------------


def test_an_os_error_crosses_with_its_errno_and_file_names():
    """At the base kind was 'other' and the parent rebuilt a plain Exception."""
    raised = FileNotFoundError(2, "No such file or directory", "/tree/t\\x1b.yaml")

    answer = cdk_nag_worker._raised_answer(raised)

    assert answer["kind"] == "os"
    assert answer["type"] == "FileNotFoundError"
    assert answer["errno"] == 2
    assert answer["strerror"] == "No such file or directory"
    assert answer["filename"] == "/tree/t\\x1b.yaml"
    assert answer["filename2"] is None

    with pytest.raises(OSError) as excinfo:
        cdk_nag_worker._raise_as_reported(answer)

    rebuilt = excinfo.value
    assert type(rebuilt).__name__ == "FileNotFoundError"
    assert rebuilt.errno == 2
    assert rebuilt.strerror == "No such file or directory"
    assert rebuilt.filename == "/tree/t\\x1b.yaml"
    assert str(rebuilt) == str(raised)


def test_an_os_error_with_two_files_keeps_both():
    raised = FileExistsError(17, "File exists", "/a", None, "/b")

    answer = cdk_nag_worker._raised_answer(raised)
    with pytest.raises(OSError) as excinfo:
        cdk_nag_worker._raise_as_reported(answer)

    assert excinfo.value.filename == "/a"
    assert excinfo.value.filename2 == "/b"
    assert str(excinfo.value) == str(raised)


def test_a_rebuilt_os_error_is_the_builtin_subclass_the_child_raised():
    """A class made by name over OSError had the name and nothing else: an
    ``except PermissionError`` or an isinstance check in the parent missed it, because
    CPython maps errno to its subclass only when OSError itself is constructed."""
    raised = PermissionError(13, "Permission denied", "/tree/secret.yaml")

    answer = cdk_nag_worker._raised_answer(raised)
    with pytest.raises(PermissionError) as excinfo:
        cdk_nag_worker._raise_as_reported(answer)

    assert isinstance(excinfo.value, OSError)
    assert excinfo.value.errno == 13
    assert excinfo.value.filename == "/tree/secret.yaml"
    assert str(excinfo.value) == str(raised)


def test_an_os_error_carries_its_windows_error_code_across():
    """Windows prints the native code ("[WinError 5] ...") and the text of a rebuilt
    error without it read "[Errno 13]" there; the code crosses in the answer and is
    given back to the constructor, which every other platform reads and ignores."""
    raised = OSError(13, "Access is denied", "x")
    answer = cdk_nag_worker._raised_answer(raised)
    assert "winerror" in answer
    assert answer["winerror"] == getattr(raised, "winerror", None)

    # The wire form a Windows child would send; rebuilt on any platform.
    answer["winerror"] = 5
    with pytest.raises(OSError) as excinfo:
        cdk_nag_worker._raise_as_reported(answer)
    assert excinfo.value.errno == 13
    assert excinfo.value.filename == "x"


def test_an_os_error_on_a_file_descriptor_keeps_the_descriptor():
    """An integer filename (a descriptor) prints as ": 3"; it was dropped as not a
    path, and the suffix with it."""
    raised = OSError(9, "Bad file descriptor", 3)

    answer = cdk_nag_worker._raised_answer(raised)
    assert answer["filename"] == 3
    with pytest.raises(OSError) as excinfo:
        cdk_nag_worker._raise_as_reported(answer)

    assert excinfo.value.filename == 3
    assert str(excinfo.value) == str(raised)


def test_an_os_error_without_an_errno_keeps_its_text():
    raised = OSError("socket closed")

    answer = cdk_nag_worker._raised_answer(raised)
    with pytest.raises(OSError) as excinfo:
        cdk_nag_worker._raise_as_reported(answer)

    assert str(excinfo.value) == "socket closed"
    assert type(excinfo.value).__name__ == "OSError"


def test_a_plain_exception_still_crosses_as_before():
    answer = cdk_nag_worker._raised_answer(ValueError("bad"))

    assert answer["kind"] == "other"
    with pytest.raises(Exception) as excinfo:
        cdk_nag_worker._raise_as_reported(answer)
    assert not isinstance(excinfo.value, OSError)
    assert type(excinfo.value).__name__ == "ValueError"


# ---------------------------------------------------------------------------
# The request file
# ---------------------------------------------------------------------------


def test_every_path_in_the_request_is_absolute(tmp_path, monkeypatch):
    """At the base the caller's relative spellings were written as given."""
    requests = []

    def fake(command, **kwargs):
        requests.append(json.loads(Path(command[-2]).read_text(encoding="utf-8")))
        Path(command[-1]).write_text(
            json.dumps({"protocol": cdk_nag_worker.PROTOCOL_VERSION}) + "\n",
            encoding="utf-8",
        )
        return {"returncode": 1, "stderr": ""}

    monkeypatch.setattr(f"{SUBPROCESS_UTILS}.run_command_with_output_handling", fake)
    monkeypatch.chdir(tmp_path)

    cdk_nag_worker._run_child(
        ["rel/t.yaml"],
        {"outdir": "rel/out", "scan_root": "rel", "nag_packs": None},
        Path("rel/out"),
        Path("."),
        None,
        (),
    )

    request = requests[0]
    assert Path(request["cwd"]).is_absolute()
    assert (
        request["cwd"] == tmp_path.resolve().as_posix()
        or request["cwd"] == tmp_path.as_posix()
    )
    assert all(Path(t).is_absolute() for t in request["templates"])
    assert request["templates"][0].endswith("/rel/t.yaml")
    assert Path(request["options"]["outdir"]).is_absolute()
    assert Path(request["options"]["scan_root"]).is_absolute()
    assert request["options"]["nag_packs"] is None


# ---------------------------------------------------------------------------
# Reading the response
# ---------------------------------------------------------------------------


def test_the_response_is_read_in_bounded_pieces(tmp_path, monkeypatch):
    """At the base one read asked for the cap plus one byte, a 512 MiB buffer."""
    response = tmp_path / "response.jsonl"
    lines = [json.dumps({"protocol": cdk_nag_worker.PROTOCOL_VERSION})]
    lines += [json.dumps(NOT_CFN) for _ in range(3)]
    response.write_text("\n".join(lines) + "\n", encoding="utf-8")
    sizes = []
    real_fdopen = os.fdopen

    class Recording:
        def __init__(self, inner):
            self._inner = inner

        def read(self, n=-1):
            sizes.append(n)
            return self._inner.read(n)

        def fileno(self):
            return self._inner.fileno()

        def __enter__(self):
            self._inner.__enter__()
            return self

        def __exit__(self, *exc):
            return self._inner.__exit__(*exc)

    monkeypatch.setattr(
        os,
        "fdopen",
        lambda fd, *args, **kwargs: Recording(real_fdopen(fd, *args, **kwargs)),
    )

    answers = cdk_nag_worker._read_answers(response)

    assert len(answers) == 3
    assert sizes, "the response was never read"
    assert max(sizes) <= cdk_nag_worker._READ_CHUNK_BYTES
    assert max(sizes) < cdk_nag_worker._MAX_RESPONSE_BYTES


# ---------------------------------------------------------------------------
# The level the child collects at
# ---------------------------------------------------------------------------


def test_the_child_collects_what_the_last_resort_would_show(monkeypatch):
    """At the base an "ash" logger with no handler fell back to WARNING, dropping the
    debug records the last resort shows in-process at a debug gate."""
    logger = ash_log.ASH_LOGGER
    monkeypatch.setattr(logger, "handlers", [])
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(logger, "disabled", False)
    original_level = logger.level
    original_gate = ash_log._LAST_RESORT.level
    logger.setLevel(logging.DEBUG)
    ash_log.configure_last_resort_level(logging.DEBUG)
    try:
        assert cdk_nag_worker._lowest_kept_log_level() == logging.DEBUG
    finally:
        logger.setLevel(original_level)
        ash_log._LAST_RESORT.setLevel(original_gate)


def test_the_child_collects_nothing_below_the_last_resorts_gate(monkeypatch):
    logger = ash_log.ASH_LOGGER
    monkeypatch.setattr(logger, "handlers", [])
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(logger, "disabled", False)
    original_level = logger.level
    original_gate = ash_log._LAST_RESORT.level
    logger.setLevel(logging.DEBUG)
    ash_log.configure_last_resort_level(logging.ERROR)
    try:
        assert cdk_nag_worker._lowest_kept_log_level() == logging.ERROR
    finally:
        logger.setLevel(original_level)
        ash_log._LAST_RESORT.setLevel(original_gate)


def test_a_handlers_level_still_decides_when_one_is_attached(monkeypatch):
    logger = ash_log.ASH_LOGGER
    handler = logging.Handler(level=logging.INFO)
    monkeypatch.setattr(logger, "handlers", [handler])
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(logger, "disabled", False)
    original_level = logger.level
    logger.setLevel(logging.DEBUG)
    try:
        assert cdk_nag_worker._lowest_kept_log_level() == logging.INFO
    finally:
        logger.setLevel(original_level)


# ---------------------------------------------------------------------------
# The batchless seam's scratch directory
# ---------------------------------------------------------------------------


def test_a_batchless_call_with_no_outdir_uses_a_scratch_directory(
    tmp_path, monkeypatch
):
    """At the base the work root was the process's working directory."""
    seen = {}

    def fake_run_child(
        pending, options, work_root, cwd, timeout, values, *, declared_timeout=None
    ):
        seen["work_root"] = Path(work_root)
        seen["existed"] = Path(work_root).is_dir()
        return [NOT_CFN for _ in pending], None, False, {"returncode": 0}

    monkeypatch.setattr(cdk_nag_worker, "_run_child", fake_run_child)
    monkeypatch.chdir(tmp_path)

    assert cdk_nag_worker.run_cdk_nag_against_cfn_template(tmp_path / "t.yaml") is None

    assert seen["work_root"] != Path.cwd()
    assert seen["existed"] is True
    assert Path(tempfile.gettempdir()) in seen["work_root"].parents
    assert not seen["work_root"].exists()
    assert not (tmp_path / cdk_nag_worker._WORK_DIR_NAME).exists()


def test_a_batchless_call_with_an_outdir_keeps_it(tmp_path, monkeypatch):
    seen = {}

    def fake_run_child(
        pending, options, work_root, cwd, timeout, values, *, declared_timeout=None
    ):
        seen["work_root"] = Path(work_root)
        return [NOT_CFN for _ in pending], None, False, {"returncode": 0}

    monkeypatch.setattr(cdk_nag_worker, "_run_child", fake_run_child)

    assert (
        cdk_nag_worker.run_cdk_nag_against_cfn_template(
            tmp_path / "t.yaml", outdir=tmp_path / "out"
        )
        is None
    )

    assert seen["work_root"] == tmp_path / "out"


# ---------------------------------------------------------------------------
# Membership
# ---------------------------------------------------------------------------


def test_batch_membership_is_a_set_lookup(tmp_path):
    batch = cdk_nag_worker._Batch(["a.yaml", "b.yaml"], tmp_path, tmp_path)
    assert isinstance(batch._template_keys, frozenset)
    assert batch._template_keys == {"a.yaml", "b.yaml"}


# ---------------------------------------------------------------------------
# Redaction of the child's stderr
# ---------------------------------------------------------------------------


def test_a_value_holding_an_escape_code_is_hidden_from_the_reason(
    tmp_path, monkeypatch
):
    """At the base the stderr was stripped of its codes BEFORE the redaction read it,
    so a value that itself holds a code was never matched and printed whole in its
    stripped spelling."""
    value = "SUPER\x1b[0mSECRETVALUE"
    monkeypatch.setattr(
        f"{SUBPROCESS_UTILS}.run_command_with_output_handling",
        _header_only_runner({"returncode": 1, "stderr": f"token {value} refused\n"}),
    )

    _, reason, _, _ = cdk_nag_worker._run_child(
        ["a.yaml"], {}, tmp_path / "out", tmp_path, 30.0, (value,)
    )

    assert "SUPERSECRETVALUE" not in reason, reason
    assert value not in reason, reason
    assert "\x1b" not in reason, reason


def test_a_value_split_by_a_code_in_the_text_is_still_hidden(tmp_path, monkeypatch):
    """The control: the stripped pass redact_then_split keeps is what catches this."""
    value = "SUPERSECRETVALUE"
    monkeypatch.setattr(
        f"{SUBPROCESS_UTILS}.run_command_with_output_handling",
        _header_only_runner(
            {"returncode": 1, "stderr": "token SUPER\x1b[KSECRETVALUE refused\n"}
        ),
    )

    _, reason, _, _ = cdk_nag_worker._run_child(
        ["a.yaml"], {}, tmp_path / "out", tmp_path, 30.0, (value,)
    )

    assert value not in reason, reason
    assert "\x1b" not in reason, reason
