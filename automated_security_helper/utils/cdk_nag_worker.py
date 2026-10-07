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
  even let it enter, so it names templates against the parent's.

Failure and time limits. Each child is bounded by the scanner's ``scan_timeout``. A
child that dies after answering some templates keeps those answers, fails the template
it was working on, and a new child takes the rest; a child that answered nothing, or
was killed at the timeout, fails every template still pending, each with the child's
exit status (or the timeout) and the tail of its stderr. ``SystemExit`` and
``KeyboardInterrupt`` raised inside the child are not exceptions the wrapper could
raise to the scanner before; they now end the child and fail its pending templates.
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import re
import shutil
import stat
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, Callable, Dict, Iterator, List, Optional

if TYPE_CHECKING:
    from automated_security_helper.utils.cdk_nag_wrapper import CdkNagWrapperResponse

#: Bumped when the request or response shape changes, so a stale child is refused.
PROTOCOL_VERSION = 1

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
            }
        )

    def take(self) -> List[Dict[str, Any]]:
        taken, self.records = self.records, []
        return taken


def _shortest_name_relative_to(cwd: Path) -> Callable[["str | Path"], "str | Path"]:
    """``get_shortest_name`` as the parent process would compute it.

    Same logic as ``utils/get_shortest_name.py``, with the parent's working directory in
    place of ``Path.cwd()``.
    """

    def get_shortest_name(input: "str | Path") -> "str | Path":  # noqa: A002
        if input == ".":
            return input
        in_path = Path(input)
        probe = in_path if in_path.is_absolute() else cwd / in_path
        if not probe.exists():
            return input
        input_posix = probe.absolute().as_posix()
        cwd_posix = cwd.absolute().as_posix()
        shortest: "str | Path"
        if input_posix.startswith(cwd_posix) and input_posix != cwd_posix:
            shortest = probe.absolute().relative_to(cwd)
        else:
            shortest = input
        return Path(shortest).as_posix()

    return get_shortest_name


def _exception_kind(exc: BaseException) -> str:
    from yaml import YAMLError

    if isinstance(exc, YAMLError):
        return "yaml"
    if isinstance(exc, UnicodeDecodeError):
        return "unicode"
    return "other"


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
    from automated_security_helper.utils.log import ASH_LOGGER

    parent_cwd = Path(request["cwd"])
    setattr(
        cdk_nag_wrapper, "get_shortest_name", _shortest_name_relative_to(parent_cwd)
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
            )
            answer = _answer_for_response(response)
        except Exception as exc:
            answer = {
                "status": "raised",
                "kind": _exception_kind(exc),
                "type": type(exc).__name__,
                "message": str(exc),
            }
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
        sys.stderr.write(
            f"cdk-nag worker speaks protocol {PROTOCOL_VERSION}, request carries "
            f"{request.get('protocol')}\n"
        )
        return 2
    with open(response_path, "w", encoding="utf-8") as out:
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
    if kind == "yaml":
        raise type(name, (YAMLError,), {})(message)
    if kind == "unicode":
        unicode_cls = type(
            name, (UnicodeDecodeError,), {"__str__": lambda self: message}
        )
        raise unicode_cls("utf-8", b"", 0, 1, message)
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


def _key(template: "str | Path") -> str:
    """One spelling per template, whatever separator or type the caller used."""
    return Path(template).as_posix()


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _read_answers(response_path: Path) -> List[Dict[str, Any]]:
    """The complete answer lines the child wrote, in order.

    The file is in a directory a sandboxed child can write, so it is opened without
    following a symlink and read up to a cap: a child must not be able to point the
    unsandboxed parent at another file, or at a device that never ends. A trailing
    line cut short by the child dying is ignored, as is anything after a line that
    does not parse.
    """
    if not response_path.exists() or response_path.is_symlink():
        return []
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(response_path, flags)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return []
        data = handle.read(_MAX_RESPONSE_BYTES + 1)
    if len(data) > _MAX_RESPONSE_BYTES:
        return []
    lines = data.decode("utf-8", errors="replace").split("\n")
    if not lines:
        return []
    try:
        header = json.loads(lines[0])
    except ValueError:
        return []
    if not isinstance(header, dict) or header.get("protocol") != PROTOCOL_VERSION:
        return []
    answers: List[Dict[str, Any]] = []
    # The last element is the text after the final newline: empty for a complete
    # file, a fragment for a child that died mid-write. Either way it is not an answer.
    for line in lines[1:-1]:
        try:
            answer = json.loads(line)
        except ValueError:
            break
        if not isinstance(answer, dict) or not isinstance(answer.get("status"), str):
            break
        answers.append(answer)
    return answers


def _lowest_kept_log_level() -> int:
    """The lowest level any of ASH's log handlers would keep, for the child."""
    from automated_security_helper.utils.log import ASH_LOGGER

    levels = [h.level for h in ASH_LOGGER.handlers]
    lowest = min(levels) if levels else logging.WARNING
    return max(lowest, ASH_LOGGER.getEffectiveLevel(), 1)


def _run_child(
    templates: List[str],
    options: Dict[str, Any],
    work_root: Path,
    cwd: Path,
    timeout: Optional[float],
) -> "tuple[List[Dict[str, Any]], Optional[str], bool]":
    """Evaluate ``templates`` in one child.

    Returns the answers it gave, in template order and possibly fewer than asked for;
    the reason it stopped early, or None; and whether that reason was the timeout.
    """
    from automated_security_helper.utils.subprocess_utils import (
        run_command_with_output_handling,
    )

    work_dir = work_root.joinpath(_WORK_DIR_NAME, uuid.uuid4().hex)
    work_dir.mkdir(parents=True, exist_ok=True)
    request_path = work_dir.joinpath("request.json")
    response_path = work_dir.joinpath("response.jsonl")
    try:
        from automated_security_helper.utils.sandbox.fs_guard import open_for_write

        # Guarded: under a sandbox this directory is one the scanner can write.
        with open_for_write(request_path) as handle:
            handle.write(
                json.dumps(
                    {
                        "protocol": PROTOCOL_VERSION,
                        "cwd": cwd.as_posix(),
                        "log_level": _lowest_kept_log_level(),
                        "options": options,
                        "templates": templates,
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
        )
        answers = _read_answers(response_path)[: len(templates)]
        if len(answers) == len(templates):
            return answers, None, False
        if outcome.get("timed_out"):
            reason = (
                f"the cdk-nag worker timed out after {timeout}s and was killed. Raise "
                "scanners.cdk-nag.options.scan_timeout if these templates "
                "legitimately need longer."
            )
            return answers, reason, True
        stderr = _strip_ansi(outcome.get("stderr") or "").strip().splitlines()
        tail = " | ".join(stderr[-5:]) if stderr else "no stderr"
        reason = (
            f"the cdk-nag worker process exited {outcome.get('returncode')} "
            f"before answering: {tail}"
        )
        return answers, reason, False
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
    ) -> None:
        self.templates = [_key(t) for t in templates]
        self.work_root = work_root
        self.cwd = cwd
        self.timeout = timeout
        self.options: Optional[Dict[str, Any]] = None
        self.answers: Dict[str, Dict[str, Any]] = {}
        self.errors: Dict[str, str] = {}

    def _evaluate(self, pending: List[str], options: Dict[str, Any]) -> None:
        """Answer or fail every template in ``pending``.

        A child that dies after answering some templates fails only the one it was
        working on; the rest go to a new child. A child that answered nothing, or ran
        out of time, fails everything still pending: starting another would repeat
        the same failure once per template.
        """
        while pending:
            try:
                answers, error, timed_out = _run_child(
                    pending, options, self.work_root, self.cwd, self.timeout
                )
            except Exception as exc:
                answers, error, timed_out = [], f"{type(exc).__name__}: {exc}", False
            for template, answer in zip(pending, answers):
                self.answers[template] = answer
            if error is None:
                return
            rest = pending[len(answers) :]
            if not answers or timed_out:
                for template in rest:
                    self.errors[template] = error
                return
            self.errors[rest[0]] = error
            pending = rest[1:]

    def answer_for(self, template: str, options: Dict[str, Any]) -> Dict[str, Any]:
        from automated_security_helper.utils.log import ASH_LOGGER

        key = _key(template)
        if self.options is None:
            self.options = options
        if options != self.options or key not in self.templates:
            # Not something the scanner does: it lists every template up front and
            # computes one set of options. Answered correctly, by a child of its own,
            # and said out loud, because paying jsii startup per template is exactly
            # what the batch exists to avoid.
            ASH_LOGGER.debug(
                f"cdk-nag worker: {template} is outside the batch it was called in; "
                "evaluating it in a separate child"
            )
            single = _Batch([key], self.work_root, self.cwd, self.timeout)
            return single.answer_for(key, options)
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
) -> Iterator[None]:
    """Evaluate ``templates`` in one child, on the first call made inside the block.

    ``work_root`` must be a directory the scanner may write, which inside a sandbox
    means its results directory. ``timeout`` bounds each child; a child killed at it
    fails every template it had not answered.
    """
    token = _ACTIVE_BATCH.set(
        _Batch(templates, Path(work_root), Path(cwd) if cwd else Path.cwd(), timeout)
    )
    try:
        yield
    finally:
        _ACTIVE_BATCH.reset(token)


def run_cdk_nag_against_cfn_template(
    template_path: Path,
    nag_packs: Optional[List[str]] = None,
    outdir: Optional[Path] = None,
    include_compliant_checks: bool = False,
    stack_name: str = "ASHCDKNagScanner",
    honor_template_suppressions: bool = True,
) -> "Optional[CdkNagWrapperResponse]":
    """``cdk_nag_wrapper.run_cdk_nag_against_cfn_template``, evaluated in a child.

    Same arguments, same return values, same exceptions (by name and text). Outside a
    :func:`cdk_nag_worker_batch` block each call starts its own child.
    """
    options = {
        "nag_packs": list(nag_packs) if nag_packs is not None else None,
        "outdir": Path(outdir).as_posix() if outdir is not None else None,
        "include_compliant_checks": include_compliant_checks,
        "stack_name": stack_name,
        "honor_template_suppressions": honor_template_suppressions,
    }
    batch = _ACTIVE_BATCH.get()
    if batch is None:
        work_root = Path(outdir) if outdir is not None else Path.cwd()
        batch = _Batch([str(template_path)], work_root, Path.cwd())
    answer = batch.answer_for(str(template_path), options)

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
