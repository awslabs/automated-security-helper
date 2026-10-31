# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Run cdk-nag in a child process, so the scanner sandbox can wrap it.

Why this exists. cdk-nag is a jsii library: importing it starts a NodeJS kernel, and
``utils/cdk_nag_wrapper.py`` used to run inside the ASH process. An OS sandbox wraps a
process, not a function call, so while cdk-nag ran in-process ``--sandbox`` could only
refuse it. Moving the evaluation into a child started through the ordinary spawn path
(``run_command_with_output_handling``) puts the child -- and the ``node`` process jsii
starts from it -- inside whatever sandbox scope the scanner executor entered.

Shape. The parent writes one request file listing every template a ``scan()`` call will
evaluate; one child imports cdk-nag once and evaluates them in order, appending one
answer line per template to a response file as each finishes. One child per scan
rather than per template because starting the jsii kernel costs seconds, and the
in-process version paid it once per process.

The child is started with ``python -c`` and drops ``sys.path[0]`` before importing
anything. ``python -m`` would put the working directory -- usually the repository
being scanned -- first on the import path, and a ``yaml.py`` or ``cdk_nag.py`` in that
repository would then run as ASH's own code.

Both files live in a directory under the scanner's results directory. That is the only
location a sandboxed scanner may write and the parent can read, because the sandbox gives
the child a private ``/tmp``. The directory is removed when the batch ends, so the
results directory holds exactly what it held when cdk-nag ran in-process.

The seam the scanner calls is :func:`run_cdk_nag_against_cfn_template`, with the
wrapper's own signature, and one call per template as before. Inside a
:func:`cdk_nag_worker_batch` block the first call runs the child for the whole batch and
every call returns its template's answer from that one run. Unit tests replace this name
on the scanner module, as they replaced the in-process wrapper, and then no child starts.

What crosses the process boundary, and why each piece does:

- The wrapper's three outcomes: None (not a CloudFormation template), a response with
  ``failure`` set, or a response with SARIF results. Results travel as
  ``Result.model_dump(exclude_unset=True)`` and are re-validated, so the report the
  scanner writes with ``exclude_unset=True`` is the one it wrote before.
- An exception the wrapper raised, as its class name and ``str()``, re-raised in the
  parent as an exception with the same name and text and the same base class
  (``YAMLError``, ``UnicodeDecodeError``, or ``Exception``). The scanner classifies a parse
  failure differently from any other exception, and prints ``type(e).__name__``, so both
  have to survive.
- The log records the wrapper emitted for each template, replayed through ``ASH_LOGGER``
  when the scanner asks for that template, so ``ash.log`` and the console show what they
  showed before, in the same place.
- The parent's working directory. ``get_shortest_name`` names a template relative to the
  current directory, and those names appear in finding URIs, messages and synth output
  paths. The child cannot rely on its own working directory, which a sandbox may not
  even let it enter, so it names templates against the parent's, by passing that directory
  as the ``cwd`` argument of the shared ``get_shortest_name``.

Failure and time limits. The scanner's ``scan_timeout`` bounds the BATCH: the first
child gets the whole limit, and a child started after one died gets what is left of it,
so one ``scan()`` call never runs past the limit however many children it took. (Each
child used to get the full limit afresh, so a batch whose children kept dying ran for
many multiples of the configured time.) A child that dies keeps the answers it gave,
fails the template it was working on, and a new child takes the rest, whether it died on
the first template or a later one; a child that never wrote its protocol header reached
no template, fails none, and the whole list goes to one more child. A child killed at
the timeout fails every template still pending, and so does a second child in a row that
answers nothing with the same reason as the first (a failure every child shares, such as
the interpreter not starting), each with the child's exit status (or the timeout) and
the tail of its stderr, redacted whole with the scan's environment values before it is
cut into lines. A child the spawn helper
could not wait for and could not stop fails every pending template too, and no new child
is started beside it: it may still be evaluating the same templates into the same output
directory. ``SystemExit`` and ``KeyboardInterrupt`` raised inside the child are not
exceptions the wrapper could raise to the scanner before; they now end the child and fail
its pending templates.

Paths cross to the child absolute: the templates, the output directory, the scan root and
the parent's working directory. The child runs in its own scratch directory and may not
be able to enter the parent's (a sandbox), so a relative path would resolve against the
wrong place there.
"""

from __future__ import annotations

import builtins
import contextvars
import functools
import json
import logging
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import (
    IO,
    TYPE_CHECKING,
    Any,
    Dict,
    Iterator,
    List,
    Optional,
    Sequence,
)

if TYPE_CHECKING:
    from automated_security_helper.utils.cdk_nag_wrapper import CdkNagWrapperResponse

#: Bumped when the request or response shape changes, so a stale child is refused.
#: 2 added ``scan_root`` to the options.
PROTOCOL_VERSION = 2

_WORK_DIR_NAME = ".cdk-nag-worker"


# ---------------------------------------------------------------------------
# Child side
# ---------------------------------------------------------------------------


class _RecordCollector(logging.Handler):
    """Keeps every record the wrapper logs, to hand back with its template's answer."""

    def __init__(self, level: int = 1) -> None:
        super().__init__(level=level)
        self.records: List[Dict[str, Any]] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(
            {
                "level": record.levelno,
                "message": record.getMessage(),
                "pathname": record.pathname,
                "lineno": record.lineno,
                "funcName": record.funcName,
                # A message logged with MARKUP styles itself and has its values
                # shown and escaped for Rich; replayed as text, it was shown again.
                "markup": bool(getattr(record, "markup", False)),
            }
        )

    def take(self) -> List[Dict[str, Any]]:
        taken, self.records = self.records, []
        return taken


def _exception_kind(exc: BaseException) -> str:
    from yaml import YAMLError

    from automated_security_helper.utils.scanned_tree import TreeInputRefused

    if isinstance(exc, YAMLError):
        return "yaml"
    if isinstance(exc, UnicodeDecodeError):
        return "unicode"
    if isinstance(exc, TreeInputRefused):
        return "refused"
    if isinstance(exc, OSError):
        return "os"
    return "other"


def _raised_answer(exc: BaseException) -> Dict[str, Any]:
    """The wire form of an exception the wrapper raised for one template.

    Its class name and text, and what the parent needs to rebuild it with the same base
    class: a refusal's path and reason, and an OSError's errno, strerror and file names.
    An OSError used to cross as a plain ``Exception`` carrying ``str(exc)``, so
    ``error_text`` in the parent, which names an OSError's files as given instead of by
    repr, no longer saw an OSError; its repr-quoted file names reached ash.log and the
    SARIF with their backslashes and control escapes doubled.
    """
    answer: Dict[str, Any] = {
        "status": "raised",
        "kind": _exception_kind(exc),
        "type": type(exc).__name__,
        "message": str(exc),
    }
    if answer["kind"] == "refused":
        answer["path"] = getattr(exc, "path", None)
        answer["reason"] = getattr(exc, "reason", None)
    elif answer["kind"] == "os":
        answer["errno"] = exc.errno if isinstance(exc.errno, int) else None  # type: ignore[attr-defined]
        answer["strerror"] = (
            exc.strerror if isinstance(exc.strerror, str) else None  # type: ignore[attr-defined]
        )
        # Windows carries the native error code beside errno and prints it
        # ("[WinError 5] Access is denied"); a rebuilt error without it printed
        # "[Errno 13]" instead, so the text did not survive the crossing there.
        winerror = getattr(exc, "winerror", None)
        answer["winerror"] = (
            winerror
            if isinstance(winerror, int) and not isinstance(winerror, bool)
            else None
        )
        for attribute in ("filename", "filename2"):
            value = getattr(exc, attribute, None)
            if isinstance(value, (str, bytes)):
                answer[attribute] = os.fsdecode(value)
            elif isinstance(value, int) and not isinstance(value, bool):
                # A file descriptor, which OSError prints as ": 3".
                answer[attribute] = value
            else:
                answer[attribute] = None
    return answer


def _answer_for_response(
    response: "Optional[CdkNagWrapperResponse]",
) -> Dict[str, Any]:
    """The wire form of one wrapper return value. Inverse of :func:`_response_from`."""
    if response is None:
        return {"status": "not-cloudformation"}
    return {
        "status": "response",
        "failure": response.failure,
        "outdir": response.outdir.as_posix() if response.outdir else None,
        "results": None
        if response.results is None
        else {
            pack: [
                finding.model_dump(mode="json", exclude_unset=True)
                for finding in findings
            ]
            for pack, findings in response.results.items()
        },
    }


def _evaluate(request: Dict[str, Any], out: IO[str]) -> None:
    """Evaluate every template, writing one answer line per template as it finishes.

    One line at a time, flushed, so that a child killed part way -- a node crash, the
    scan timeout -- still hands back the answers it reached, and only the template it
    was working on is lost.
    """
    from automated_security_helper.utils import cdk_nag_wrapper
    from automated_security_helper.utils.get_shortest_name import get_shortest_name
    from automated_security_helper.utils.log import ASH_LOGGER

    parent_cwd = Path(request["cwd"])
    # The shared helper with the parent's working directory bound: this process may not
    # be able to enter that directory (a sandbox), so the helper is told where the
    # names are relative to instead of reading the cwd of the process it runs in.
    setattr(
        cdk_nag_wrapper,
        "get_shortest_name",
        functools.partial(get_shortest_name, cwd=parent_cwd),
    )
    try:
        os.chdir(parent_cwd)
    except OSError:
        # Inside a sandbox that does not expose it. Template paths are absolute, and
        # names are computed against parent_cwd above, so nothing depends on it.
        pass

    # Only what the parent would keep: records below every handler's level there are
    # dropped on replay, so carrying them across is wasted work.
    log_level = int(request.get("log_level", 1))
    collector = _RecordCollector(log_level)
    ASH_LOGGER.handlers = [collector]
    ASH_LOGGER.setLevel(log_level)

    options = request["options"]
    out.write(json.dumps({"protocol": PROTOCOL_VERSION}) + "\n")
    out.flush()
    for template in request["templates"]:
        answer: Dict[str, Any]
        try:
            response = cdk_nag_wrapper.run_cdk_nag_against_cfn_template(
                template_path=Path(template),
                nag_packs=options["nag_packs"],
                outdir=Path(options["outdir"]) if options["outdir"] else None,
                include_compliant_checks=options["include_compliant_checks"],
                stack_name=options["stack_name"],
                honor_template_suppressions=options["honor_template_suppressions"],
                scan_root=(
                    Path(options["scan_root"]) if options.get("scan_root") else None
                ),
            )
            answer = _answer_for_response(response)
        except Exception as exc:
            # A refusal is re-raised in the parent as the class itself, with its
            # path and reason, so the scanner treats it as the skip it is; an
            # OSError as an OSError, with its files (_raised_answer).
            answer = _raised_answer(exc)
        answer["logs"] = collector.take()
        out.write(json.dumps(answer) + "\n")
        out.flush()


def main(argv: List[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: cdk_nag_worker REQUEST.json RESPONSE.jsonl\n")
        return 2
    request_path, response_path = Path(argv[0]), Path(argv[1])
    request = json.loads(request_path.read_text(encoding="utf-8"))
    if request.get("protocol") != PROTOCOL_VERSION:
        from automated_security_helper.utils.terminal_text import shown_on_one_line

        # The request's value as read, which the file may hold as anything.
        sys.stderr.write(
            shown_on_one_line(
                f"cdk-nag worker speaks protocol {PROTOCOL_VERSION}, request carries "
                f"{request.get('protocol')}"
            )
            + "\n"
        )
        return 2
    # Exclusively: the parent made this directory fresh for the run and wrote the
    # request into it with fs_guard, so anything already at the name, a link
    # included, is refused rather than opened. Reported as the protocol mismatch
    # is, an error exit with a line on stderr, which the parent quotes as the
    # reason the child gave no answer.
    try:
        out = open(response_path, "x", encoding="utf-8")
    except FileExistsError:
        from automated_security_helper.utils.terminal_text import shown_on_one_line

        # The path is the parent's argument, shown as text, not obeyed.
        sys.stderr.write(
            shown_on_one_line(
                f"cdk-nag worker: the response file {response_path} already exists, "
                "and the worker writes only a file it creates"
            )
            + "\n"
        )
        return 2
    with out:
        _evaluate(request, out)
    return 0


# ---------------------------------------------------------------------------
# Parent side
# ---------------------------------------------------------------------------


def _raise_as_reported(answer: Dict[str, Any]) -> None:
    """Raise what the wrapper raised in the child: same class name, same text."""
    from yaml import YAMLError

    name = str(answer.get("type") or "Exception")
    message = str(answer.get("message") or "")
    kind = answer.get("kind")
    if kind == "refused":
        from automated_security_helper.utils.scanned_tree import TreeInputRefused

        raise TreeInputRefused(
            str(answer.get("path") or ""), str(answer.get("reason") or message)
        )
    if kind == "yaml":
        raise type(name, (YAMLError,), {})(message)
    if kind == "unicode":
        unicode_cls = type(
            name, (UnicodeDecodeError,), {"__str__": lambda self: message}
        )
        raise unicode_cls("utf-8", b"", 0, 1, message)
    if kind == "os":
        # An OSError with the child's errno, strerror and file names, so error_text
        # in this process names its files as given, as it does for an OSError raised
        # here. OSError's own __str__ is kept: that is what error_text rewrites. With
        # no errno there is nothing for that text to be built from, so the message
        # crosses as the class's text instead.
        #
        # The builtin class itself when the name is one (FileNotFoundError,
        # PermissionError, ...), so an `except PermissionError` or an isinstance
        # check in the parent sees what the child saw. A class made by name over
        # OSError had the name and nothing else: CPython maps errno to its subclass
        # only when OSError itself is constructed, and a made class is not it.
        builtin = getattr(builtins, name, None)
        os_cls = (
            builtin
            if isinstance(builtin, type) and issubclass(builtin, OSError)
            else type(name, (OSError,), {})
        )
        errno = answer.get("errno")
        if isinstance(errno, int) and not isinstance(errno, bool):
            fields = (
                errno,
                str(answer.get("strerror") or message),
                answer.get("filename"),
                # The native code on Windows, which the text there is built from;
                # read and ignored on every other platform.
                answer.get("winerror"),
                answer.get("filename2"),
            )
            try:
                rebuilt: OSError = os_cls(*fields)
            except TypeError:
                # No builtin OSError subclass refuses these five fields: every one
                # takes OSError's own (errno, strerror, filename, winerror,
                # filename2), and BlockingIOError reads an int third field as its
                # characters_written rather than raising, so a descriptor-valued
                # filename (": 3") lands there and its text drops the suffix. Kept
                # for an OSError subclass another runtime constructs differently.
                rebuilt = type(name, (OSError,), {})(*fields)
            raise rebuilt
        raise os_cls(message)
    raise type(name, (Exception,), {})(message)


def _replay_logs(answer: Dict[str, Any]) -> None:
    from automated_security_helper.utils.log import ASH_LOGGER

    # Rebuilt as records rather than re-logged, so the file and line in ash.log name
    # the wrapper code that logged them, not this function.
    for entry in answer.get("logs") or []:
        level = int(entry["level"])
        if not ASH_LOGGER.isEnabledFor(level):
            continue
        ASH_LOGGER.handle(
            ASH_LOGGER.makeRecord(
                ASH_LOGGER.name,
                level,
                str(entry.get("pathname") or __file__),
                int(entry.get("lineno") or 0),
                str(entry["message"]),
                (),
                None,
                func=str(entry.get("funcName") or ""),
                # As the wrapper logged it: markup, or text.
                extra={"markup": entry.get("markup") is True},
            )
        )


def _response_from(answer: Dict[str, Any]) -> "CdkNagWrapperResponse":
    from automated_security_helper.schemas.sarif_schema_model import Result
    from automated_security_helper.utils.cdk_nag_wrapper import CdkNagWrapperResponse

    raw_results = answer.get("results")
    results = (
        None
        if raw_results is None
        else {
            pack: [Result.model_validate(item) for item in items]
            for pack, items in raw_results.items()
        }
    )
    outdir = answer.get("outdir")
    return CdkNagWrapperResponse(
        results=results,
        outdir=Path(outdir) if outdir else None,
        failure=answer.get("failure"),
    )


#: How the child is started. ``-c`` rather than ``-m`` so the first entry of
#: ``sys.path`` -- the working directory, which is usually the repository being
#: scanned -- can be removed before anything is imported. Under ``-m`` a ``yaml.py``,
#: ``cdk_nag.py`` or ``automated_security_helper/`` at the top of the scanned tree
#: would be imported and run in place of the real module. ``-P`` would do the same and
#: needs Python 3.11; ``-I`` would also drop PYTHONPATH, which an install may rely on.
#: Only an empty first entry is removed: under PYTHONSAFEPATH (or -P) Python does not
#: add the working directory, and sys.path[0] is then a real entry such as the
#: stdlib zip.
_CHILD_BOOTSTRAP = (
    "import sys; sys.path[:1] = [] if sys.path[:1] == [''] else sys.path[:1]; "
    "from automated_security_helper.utils.cdk_nag_worker import main; "
    "sys.exit(main(sys.argv[1:]))"
)

#: A response larger than this is not one the child wrote for a scan's templates.
_MAX_RESPONSE_BYTES = 512 * 1024 * 1024

#: How much of the response is read per call. One ``read(_MAX_RESPONSE_BYTES + 1)``
#: asked the buffered reader for a 512 MiB buffer up front, for a response of a few
#: kilobytes; the cap is enforced on the running total instead.
_READ_CHUNK_BYTES = 1024 * 1024

#: The least of the batch's time limit a new child is started with. A child needs
#: seconds to start the jsii kernel before it can answer anything; one started with
#: less is certain to time out, and used to add a timed-out record and a "killed at
#: the limit" reason for templates that were never going to be evaluated. Bounded
#: by half the configured limit (``_child_floor``): a fixed floor above a small
#: limit refused every second child, so the headerless retry the batch promises,
#: and every retry after a child died at once, read "time ran out" with almost
#: the whole limit left.
_MIN_CHILD_SECONDS = 5.0


def _child_floor(timeout: Optional[float]) -> float:
    """The least of what is left of ``timeout`` another child is started with."""
    if timeout is None:
        return _MIN_CHILD_SECONDS
    return min(_MIN_CHILD_SECONDS, timeout / 2)


def _key(template: "str | Path") -> str:
    """One spelling per template, whatever separator or type the caller used."""
    return Path(template).as_posix()


def _read_answers(response_path: Path) -> List[Dict[str, Any]]:
    """The complete answer lines the child wrote, in order; see ``_read_response``."""
    return _read_response(response_path)[1]


def _read_response(
    response_path: Path,
) -> tuple[bool, List[Dict[str, Any]], bool]:
    """``(started, answers, cut)``: whether the child wrote its protocol header, the
    complete answer lines it wrote after it, in order, and whether the response ran
    past the size cap so that answers after the cap were not read.

    The header is the first thing the child writes, before it looks at a template, so
    its absence is a structural fact about the child's run: it never got as far as its
    templates (the interpreter did not start, ASH's own import failed, the request
    could not be read). The wrapper imports cdk-nag and resolves node lazily, inside
    the first template's evaluation, after the header is written, so those two failures
    come back as a ``failure`` or ``raised`` answer, not as a child with no header. The
    batch gives a first child with no header one more try, and reads a second child
    with no header as a failure every child shares, whatever the stderr says. A header
    with no answers is a child that started and died on its first template.

    The file is in a directory a sandboxed child can write, so it is opened without
    following a symlink and read up to a cap: a child must not be able to point the
    unsandboxed parent at another file, or at a device that never ends. A trailing
    line cut short by the child dying is ignored, as is anything after a line that
    does not parse.

    The path is checked to be a regular file BEFORE it is opened, and opened without
    blocking: an ``O_RDONLY`` open of a FIFO waits for a writer that never comes, and
    the check that followed the open was never reached, so a FIFO planted at the
    response path hung the unsandboxed parent. The check is repeated on the opened
    descriptor, so a file swapped for a FIFO between the two is still refused.

    Past the cap, the complete lines inside it are still read rather than the whole
    response being dropped: a child that answered every template into a response
    larger than the cap used to fail the whole batch with "exited 0 before
    answering", and the answers it had written were lost with it. The answers that
    fit are kept and ``cut`` is True; the template whose line crosses the cap is the
    one the caller fails, naming the cap, and those after it go to a new child.

    An answer line too deep for the JSON parser (a RecursionError, which is not a
    ValueError) ends the answers as a malformed line does; the parser's own recursion
    limit is the bound on what a child may hand the parent. What this function cannot
    read without raising (a symlink the sandboxed child swapped in between the checks
    and the open, which ``O_NOFOLLOW`` refuses with ELOOP) raises to the caller, which
    keeps the runner's outcome for the child whatever became of its response.
    """
    if not response_path.exists() or response_path.is_symlink():
        return False, [], False
    try:
        if not stat.S_ISREG(os.lstat(response_path).st_mode):
            return False, [], False
    except OSError:
        return False, [], False
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    fd = os.open(response_path, flags)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return False, [], False
        # In bounded pieces up to one byte past the cap, so the cap check below
        # still sees a response that crossed it without a cap-sized allocation.
        chunks: List[bytes] = []
        total = 0
        while total <= _MAX_RESPONSE_BYTES:
            chunk = handle.read(min(_READ_CHUNK_BYTES, _MAX_RESPONSE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
    cut = len(data) > _MAX_RESPONSE_BYTES
    if cut:
        # Only what fits, cut back to the last complete line; the fragment after it
        # is dropped below as a line cut short.
        data = data[:_MAX_RESPONSE_BYTES]
        data = data[: data.rfind(b"\n") + 1]
    lines = data.decode("utf-8", errors="replace").split("\n")
    if not lines:
        return False, [], cut
    try:
        header = json.loads(lines[0])
    except (ValueError, RecursionError):
        return False, [], cut
    if not isinstance(header, dict) or header.get("protocol") != PROTOCOL_VERSION:
        return False, [], cut
    answers: List[Dict[str, Any]] = []
    # The last element is the text after the final newline: empty for a complete
    # file, a fragment for a child that died mid-write. Either way it is not an answer.
    for line in lines[1:-1]:
        try:
            answer = json.loads(line)
        except (ValueError, RecursionError):
            break
        if not isinstance(answer, dict) or not isinstance(answer.get("status"), str):
            break
        answers.append(answer)
    return True, answers, cut


def _failure_signature(response: Dict[str, Any], reason: str) -> tuple:
    """What two answerless children must share for their failure to be one failure.

    The exit code as the runner reported it, and the reason text with paths and numbers
    masked: a traceback through the child's per-run scratch directory, a pid in a node
    fatal-error line, or a byte count differ from child to child while the failure is
    the same, and an exact compare read every such pair as two different failures and
    paid a third child for it.
    """
    masked = re.sub(r"(?:[A-Za-z]:)?[\\/][^\s|'\"]+", "<path>", reason)
    # Hex before decimal: a faulthandler thread id ("Current thread 0x7f3c2a...") or a
    # native frame address in a node fatal-error line differ from run to run too, and
    # masking only their digits left their letters, so the same crash still read as two.
    masked = re.sub(r"0[xX][0-9a-fA-F]+", "<n>", masked)
    masked = re.sub(r"\d+", "<n>", masked)
    return (response.get("returncode"), masked)


def _lowest_kept_log_level() -> int:
    """The lowest level a record of the wrapper's would reach a handler at, for the child.

    Asked of :func:`~automated_security_helper.utils.log.delivers`, which walks what
    ``ASHLogger.callHandlers`` walks: the "ash" logger's handlers, its parents' while it
    propagates, and, when no handler takes the record, the last resort ASH's loggers
    use, at that handler's own configured level. Reading only ``ASH_LOGGER.handlers``
    and falling back to WARNING when the list was empty dropped the debug and verbose
    records the last resort would have shown in-process: the MCP server runs scans
    with no handler of its own on "ash", and ``--debug`` there showed the wrapper's
    debug lines in-process and none from the child. Above CRITICAL when nothing
    delivers at any level, so the child then carries no record across.
    """
    from automated_security_helper.utils.log import ASH_LOGGER, delivers

    lowest = logging.CRITICAL + 1
    for level in range(1, logging.CRITICAL + 1):
        if delivers(ASH_LOGGER, level):
            lowest = level
            break
    return max(lowest, ASH_LOGGER.getEffectiveLevel(), 1)


def _run_child(
    templates: List[str],
    options: Dict[str, Any],
    work_root: Path,
    cwd: Path,
    timeout: Optional[float],
    values: Sequence[str],
    *,
    declared_timeout: Optional[float] = None,
) -> "tuple[List[Dict[str, Any]], Optional[str], bool, Dict[str, Any]]":
    """Evaluate ``templates`` in one child.

    Returns the answers it gave, in template order and possibly fewer than asked for;
    the reason it stopped early, or None; whether every template still pending has to
    fail with that reason now (the child ran out of time, or it could not be stopped
    and may still be running, so no new child may be started beside it); and the
    runner's response for the child as recorded (its exit code, and the
    ``could_not_stop`` state of a stop that failed), so the scanner can record a child
    that died or could not be stopped the way it records any other tool's run.
    ``values`` are the scan config's environment values: the reason quotes the child's
    stderr, which can echo one, and it is redacted HERE, before the tail is cut from
    it, because the cut rewrites a value's line breaks as the joiner and no later
    whole-spelling redaction can match that. ``timeout`` is what this child may take,
    which for a child started after another died is what is left of the batch's limit;
    ``declared_timeout`` is the configured limit the timeout reason names, so the
    reason tells the operator which setting to raise.
    """
    from automated_security_helper.utils.subprocess_utils import (
        COULD_NOT_STOP_ENDING,
        WAS_KILLED_ENDING,
        response_could_not_stop,
        run_command_with_output_handling,
    )

    # Absolute, because the request and response paths go to the child on its argv
    # and the child is started with this directory as its cwd: a relative work_root
    # (an ``outdir`` given relative to the parent's cwd) made argv paths the child
    # resolved against work_dir instead, and it never found its request.
    work_dir = Path(work_root).absolute().joinpath(_WORK_DIR_NAME, uuid.uuid4().hex)
    # A directory of this child's own, every time, retries included: one already
    # at the name is not reused, so no request or response file is ever left
    # from an earlier child.
    work_dir.parent.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir()
    request_path = work_dir.joinpath("request.json")
    response_path = work_dir.joinpath("response.jsonl")
    try:
        from automated_security_helper.utils.sandbox.fs_guard import open_for_write

        # Absolute, every path of it: the child runs in work_dir and chdirs to the
        # parent's cwd only when the sandbox lets it, so a relative template, output
        # directory, scan root or cwd would resolve against the wrong place there.
        # The caller's spellings are kept on this side as the batch's keys; the
        # answers come back by position, so the keys never cross.
        absolute_options = dict(options)
        for key in ("outdir", "scan_root"):
            if absolute_options.get(key):
                absolute_options[key] = (
                    Path(absolute_options[key]).absolute().as_posix()
                )
        # Guarded: under a sandbox this directory is one the scanner can write.
        with open_for_write(request_path) as handle:
            handle.write(
                json.dumps(
                    {
                        "protocol": PROTOCOL_VERSION,
                        "cwd": Path(cwd).absolute().as_posix(),
                        "log_level": _lowest_kept_log_level(),
                        "options": absolute_options,
                        "templates": [
                            Path(template).absolute().as_posix()
                            for template in templates
                        ],
                    }
                )
            )
        outcome = run_command_with_output_handling(
            command=[
                sys.executable,
                "-c",
                _CHILD_BOOTSTRAP,
                request_path.as_posix(),
                response_path.as_posix(),
            ],
            results_dir=None,
            stdout_preference="return",
            stderr_preference="return",
            # The child's own work directory. It chdirs to the request's cwd (ASH's)
            # itself, so names come out as they did in-process; this only has to be
            # a directory the sandbox can see, which work_dir is.
            cwd=work_dir,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            values=values,
        )
        # The runner's outcome is known here, whatever becomes of the response. A
        # read that raises (ELOOP from O_NOFOLLOW on a symlink the sandboxed child
        # swapped in after the checks, an OSError on a device planted at the path)
        # used to escape this function, and the batch then dropped the outcome and
        # started a new child beside one that may still be running, the hazard the
        # could-not-stop branch below exists to prevent. The response then reads as
        # a child with no header, and the reason names the read that failed.
        unreadable: Optional[str] = None
        try:
            started, answers, cut = _read_response(response_path)
        except Exception as exc:
            started, answers, cut = False, [], False
            unreadable = type(exc).__name__
        answers = answers[: len(templates)]
        # A copy of the runner's response with one fact of this run added: whether
        # the child wrote its protocol header, that is, reached its templates. The
        # batch reads it to tell a startup failure (shared by every child) from a
        # crash a template provoked; the scanner's exit-code recorder reads only
        # ``returncode`` and the stop flags and is not affected by the extra key.
        recorded = dict(outcome) if isinstance(outcome, dict) else {}
        if recorded:
            recorded["worker_started"] = started
        if len(answers) == len(templates):
            return answers, None, False, recorded
        if outcome.get("timed_out"):
            # The limit through the one formatter every timeout message uses
            # (error_text.timeout_limit_token), as its own quoted token. With
            # no values: cdk-nag's section is builtin, and a config file cannot
            # read its scan_timeout from the environment (the strict load
            # refuses a reference there), so no environment value is this limit.
            from automated_security_helper.utils.error_text import timeout_limit_token

            # The configured limit, not the remainder this child was given: the
            # operator raises the setting, and a child started after another died
            # was bounded by what was left of it.
            limit = timeout_limit_token(
                declared_timeout if declared_timeout is not None else timeout, ()
            )
            # "Was killed" only when the stop worked, from the response's
            # recorded state (the flag, or a timeout with no exit code): a
            # stop that failed left the child running, and the one thing this
            # reason must not say is that it is gone.
            ending = (
                COULD_NOT_STOP_ENDING
                if response_could_not_stop(outcome)
                else WAS_KILLED_ENDING
            ) + "."
            reason = (
                f"the cdk-nag worker timed out after {limit}{ending} Raise "
                "scanners.cdk-nag.options.scan_timeout if these templates "
                "legitimately need longer."
            )
            return answers, reason, True, recorded
        if response_could_not_stop(outcome):
            # Not a timeout, and the runner could neither wait for the child nor
            # stop it (its wait failed, then its stop failed). The child may still be
            # evaluating the pending templates into this output directory, so the
            # pending templates fail NOW and no new child is started beside it: a
            # second child writing the same synth directories while the first still
            # runs would grade one template from the other's report. "Exited None"
            # was what this case used to read, which is the one thing a reason about
            # a process that may be running must not say.
            reason = (
                f"the cdk-nag worker did not finish{COULD_NOT_STOP_ENDING}. The "
                "templates it had not answered were not evaluated, and no new worker "
                "was started for them while it may still be running."
            )
            return answers, reason, True, recorded
        # Redacted whole BEFORE the split (redact_then_split): the " | " join
        # below rewrites a value's line break, so a redaction after it could
        # not match the value's spelling and both halves would print. The text
        # goes in with its escape codes: redact_then_split reads the value as
        # written first and then the stripped text, so a value that itself
        # holds a code is matched, and a code inside the text that split a
        # value is matched too. Stripping here first left only the stripped
        # spelling to match, the order error_text documents as the weaker one.
        from automated_security_helper.utils.error_text import redact_then_split

        stderr = [
            line
            for line in redact_then_split(outcome.get("stderr") or "", values)
            if line.strip()
        ]
        tail = " | ".join(stderr[-5:]) if stderr else "no stderr"
        code = outcome.get("returncode")
        if cut and code == 0:
            # The child answered every template and exited clean; its response
            # outgrew the cap. The complete answers inside the cap were kept above;
            # the template whose answer crossed it is failed here by name of the
            # cap, not as a worker death, and the templates after it get a new child.
            reason = (
                f"the cdk-nag worker's response outgrew its {_MAX_RESPONSE_BYTES}-byte "
                f"cap after {len(answers)} complete answer(s), so this template's "
                "answer was not read; the templates after it are evaluated by a new "
                "worker"
            )
            return answers, reason, False, recorded
        ended = (
            f"exited {code}"
            if isinstance(code, int) and not isinstance(code, bool)
            else "ended without an exit status"
        )
        reason = f"the cdk-nag worker process {ended} before answering: {tail}"
        if unreadable is not None:
            reason = (
                f"the cdk-nag worker's response could not be read ({unreadable}); "
                + reason
            )
        return answers, reason, False, recorded
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
        try:
            work_dir.parent.rmdir()
        except OSError:
            pass


class _Batch:
    """The templates one ``scan()`` call will evaluate, and the child's answers."""

    def __init__(
        self,
        templates: List[str],
        work_root: Path,
        cwd: Path,
        timeout: Optional[float] = None,
        values: Sequence[str] = (),
    ) -> None:
        # values defaults empty for the batchless wrapper fallback, where the
        # caller is not a scanner and has no scan config to take them from;
        # the scanner seam (cdk_nag_worker_batch) requires them.
        self.templates = [_key(t) for t in templates]
        # Membership is asked once per template the scanner evaluates; against the
        # list that was one scan of every candidate per call, quadratic in the
        # number of JSON and YAML files of the tree.
        self._template_keys = frozenset(self.templates)
        self.work_root = work_root
        self.cwd = cwd
        self.timeout = timeout
        self.values = tuple(values)
        self.options: Optional[Dict[str, Any]] = None
        self.answers: Dict[str, Dict[str, Any]] = {}
        self.errors: Dict[str, str] = {}
        # What the scanner records about the children, the way it records any other
        # tool's run: the runner's response for every child that did not answer
        # everything it was asked (its exit code, in order), and the response of a
        # child whose stop failed, which is still running, whether or not it had
        # answered everything first. Neither used to leave this module: the child's
        # death reached the scanner as per-template text only, so the plugin's
        # exit-code record and its could-not-stop state never saw a worker child, and
        # the run-level could-not-stop gate (which fail_on_incomplete_scanners does
        # not relax) never fired for cdk-nag.
        self.failed_child_responses: List[Dict[str, Any]] = []
        self.could_not_stop_response: Optional[Dict[str, Any]] = None

    def _record_child(self, response: Dict[str, Any]) -> None:
        from automated_security_helper.utils.subprocess_utils import (
            response_could_not_stop,
        )

        self.failed_child_responses.append(response)
        if self.could_not_stop_response is None and response_could_not_stop(response):
            self.could_not_stop_response = response

    def _evaluate(self, pending: List[str], options: Dict[str, Any]) -> None:
        """Answer or fail every template in ``pending``.

        A child that dies fails only the template it was working on; the rest go to a
        new child. That holds for a death on the first template too: a crash the first
        template provokes used to fail every template in the batch, while the same
        crash on a later template failed only that one. A child that never wrote its
        protocol header never reached a template, so no template is blamed for it:
        the whole pending list goes to one more child, and a one-off startup failure
        (an OOM kill, a spawn that did not happen) costs nothing. The retry is bounded
        so a failure every child shares is not paid once per template: a second child
        in a row that answers nothing fails everything still pending when its failure
        is the first's. Two signals say so. The structural one: a second child with no
        header is a startup failure every child shares, whatever the text says. The
        textual one, for a child that did start: the same exit code and the same
        reason once paths and numbers are masked (a per-run scratch path or a pid in
        the text does not make two failures of one). Two neighboring templates that
        each crash a started child for their own reasons give two different
        signatures, so the second is not taken as shared and the next template still
        gets its own child; three answerless children in a row fail the rest whatever
        their signatures, so a run of crashing templates stays bounded. A child that
        ran out of time fails everything still pending at once, as before, and so does
        a child the runner could not stop.

        The timeout bounds the whole of this call, not each child. The first child
        gets the configured limit; a child started after one died gets what is left
        of it, and when nothing is left, or less than a child needs to get past jsii
        startup (``_child_floor``: a few seconds, never more than half the limit, so
        a small limit still admits the retry), the pending templates fail with the
        timeout reason without a child being started. Each child used to get the full
        limit afresh, so a batch whose children kept dying ran for about half as many
        limits as it had templates.

        A child the runner could not stop is recorded for the scanner's run-level
        gate whether or not it had answered every template first: a child that
        answered everything and then hung in teardown past the limit, with a failed
        stop, is still a process that may be running.
        """
        from automated_security_helper.utils.subprocess_utils import (
            response_could_not_stop,
        )

        answerless_in_a_row = 0
        last_signature: Optional[tuple] = None
        deadline = None if self.timeout is None else time.monotonic() + self.timeout
        first_child = True
        while pending:
            if first_child or deadline is None:
                child_timeout = self.timeout
            else:
                remaining = deadline - time.monotonic()
                if remaining <= _child_floor(self.timeout):
                    from automated_security_helper.utils.error_text import (
                        timeout_limit_token,
                    )

                    limit = timeout_limit_token(self.timeout, ())
                    error = (
                        f"the cdk-nag worker's time ran out after {limit}: earlier "
                        "worker children spent the scan's limit, or left too little "
                        "of it for another to start, so these templates were not "
                        "evaluated. Raise scanners.cdk-nag.options.scan_timeout if "
                        "these templates legitimately need longer."
                    )
                    for template in pending:
                        self.errors[template] = error
                    return
                child_timeout = remaining
            first_child = False
            try:
                answers, error, fail_rest, response = _run_child(
                    pending,
                    options,
                    self.work_root,
                    self.cwd,
                    child_timeout,
                    self.values,
                    declared_timeout=self.timeout,
                )
            except Exception as exc:
                answers, error, fail_rest = [], f"{type(exc).__name__}: {exc}", False
                response = {}
            for template, answer in zip(pending, answers):
                self.answers[template] = answer
            if error is None:
                if (
                    response
                    and response_could_not_stop(response)
                    and self.could_not_stop_response is None
                ):
                    # Every template answered, then the runner could not stop the
                    # child (a hang in jsii or node teardown past the limit whose
                    # stop failed). Not a failed child, so no exit-code record; a
                    # process that may still be running, so the gate has to see it.
                    self.could_not_stop_response = response
                return
            if response:
                # An empty response is the runner raising before any child ran; it
                # carries no exit code and is not a child's record.
                self._record_child(response)
            rest = pending[len(answers) :]
            # A runner that raised left no response: the child never started either.
            started = bool(response.get("worker_started")) if response else False
            signature = _failure_signature(response, error)
            shared = (
                not answers
                and answerless_in_a_row > 0
                and (
                    not started
                    or signature == last_signature
                    or answerless_in_a_row >= 2
                )
            )
            if fail_rest or shared:
                for template in rest:
                    self.errors[template] = error
                return
            if not answers and not started and answerless_in_a_row == 0:
                # The first child with no header: it never reached a template, so
                # none is failed for it. The same list goes to one more child; a
                # second child with no header is the shared failure above and fails
                # them all, so this costs at most one extra child.
                answerless_in_a_row = 1
                last_signature = signature
                continue
            if answers:
                answerless_in_a_row = 0
                last_signature = None
            else:
                answerless_in_a_row += 1
                last_signature = signature
            self.errors[rest[0]] = error
            pending = rest[1:]

    def answer_for(self, template: str, options: Dict[str, Any]) -> Dict[str, Any]:
        from automated_security_helper.utils.log import ASH_LOGGER

        key = _key(template)
        if self.options is None:
            self.options = options
        if options != self.options or key not in self._template_keys:
            # Not something the scanner does: it lists every template up front and
            # computes one set of options. Answered correctly, by a child of its own,
            # and said out loud, because paying jsii startup per template is exactly
            # what the batch exists to avoid.
            ASH_LOGGER.debug(
                f"cdk-nag worker: {template} is outside the batch it was called in; "
                "evaluating it in a separate child"
            )
            single = _Batch(
                [key], self.work_root, self.cwd, self.timeout, values=self.values
            )
            try:
                return single.answer_for(key, options)
            finally:
                # Its child is a child of this scan: a death or a failed stop there
                # reaches the scanner's records through this batch, which is the one
                # the scanner reads after its loop. Thrown away with the batch, that
                # child never reached the exit-code record or the could-not-stop gate.
                self.failed_child_responses.extend(single.failed_child_responses)
                if self.could_not_stop_response is None:
                    self.could_not_stop_response = single.could_not_stop_response
        if key not in self.answers and key not in self.errors:
            self._evaluate(
                [
                    t
                    for t in self.templates
                    if t not in self.answers and t not in self.errors
                ],
                options,
            )
        if key in self.errors:
            raise RuntimeError(self.errors[key])
        if key not in self.answers:
            raise RuntimeError("the cdk-nag worker gave no answer for this template")
        return self.answers[key]


_ACTIVE_BATCH: contextvars.ContextVar[Optional[_Batch]] = contextvars.ContextVar(
    "ash_cdk_nag_worker_batch", default=None
)


@contextmanager
def cdk_nag_worker_batch(
    templates: List[str],
    work_root: Path,
    cwd: Optional[Path] = None,
    timeout: Optional[float] = None,
    *,
    values: Sequence[str],
) -> Iterator["_Batch"]:
    """Evaluate ``templates`` in one child, on the first call made inside the block.

    ``work_root`` must be a directory the scanner may write, which inside a sandbox
    means its results directory. ``timeout`` bounds the whole batch: the first child
    gets all of it, a child started after one died gets what is left, and a child
    killed at it fails every template it had not answered. ``values`` are the scan config's
    environment values, which the worker's failure reasons are redacted with:
    required, with no empty default, so a caller cannot silently run the
    worker with redaction off.

    Yields the batch, so the caller can read ``failed_child_responses`` and
    ``could_not_stop_response`` after its loop and record a child that died, or one
    ASH could not stop, on the plugin the way every other scanner's tool run is.
    """
    batch = _Batch(
        templates,
        Path(work_root),
        Path(cwd) if cwd else Path.cwd(),
        timeout,
        values=values,
    )
    token = _ACTIVE_BATCH.set(batch)
    try:
        yield batch
    finally:
        _ACTIVE_BATCH.reset(token)


def run_cdk_nag_against_cfn_template(
    template_path: Path,
    nag_packs: Optional[List[str]] = None,
    outdir: Optional[Path] = None,
    include_compliant_checks: bool = False,
    stack_name: str = "ASHCDKNagScanner",
    honor_template_suppressions: bool = True,
    scan_root: Optional[Path] = None,
) -> "Optional[CdkNagWrapperResponse]":
    """``cdk_nag_wrapper.run_cdk_nag_against_cfn_template``, evaluated in a child.

    Same arguments, same return values, same exceptions (by name and text), with one
    stated difference: the response's ``template`` is None here. The wrapper sets it to
    the template's model, which is the template's whole content; the scanner never
    reads it, so it does not cross the process boundary. Outside a
    :func:`cdk_nag_worker_batch` block each call starts its own child, in a scratch
    directory of its own when no ``outdir`` is given: the working directory used to
    serve, and one the process could not write turned the wrapper's "not a
    CloudFormation template" answer into an error about the scratch files.
    """
    options = {
        "nag_packs": list(nag_packs) if nag_packs is not None else None,
        "outdir": Path(outdir).as_posix() if outdir is not None else None,
        "include_compliant_checks": include_compliant_checks,
        "stack_name": stack_name,
        "honor_template_suppressions": honor_template_suppressions,
        "scan_root": Path(scan_root).as_posix() if scan_root is not None else None,
    }
    batch = _ACTIVE_BATCH.get()
    scratch_root: Optional[str] = None
    if batch is None:
        if outdir is not None:
            work_root = Path(outdir)
        else:
            scratch_root = tempfile.mkdtemp(prefix="ash-cdk-nag-worker-")
            work_root = Path(scratch_root)
        batch = _Batch([str(template_path)], work_root, Path.cwd())
    try:
        answer = batch.answer_for(str(template_path), options)
    finally:
        if scratch_root is not None:
            shutil.rmtree(scratch_root, ignore_errors=True)

    _replay_logs(answer)
    status = answer.get("status")
    if status == "not-cloudformation":
        return None
    if status == "raised":
        _raise_as_reported(answer)
    if status != "response":
        raise RuntimeError(f"the cdk-nag worker returned an unknown status {status!r}")
    return _response_from(answer)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
