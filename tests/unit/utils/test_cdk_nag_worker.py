# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The cdk-nag worker: cdk-nag evaluated in a child the scanner sandbox can wrap.

What these pin, and why each matters:

- The child starts through the spawn choke point, so an active sandbox scope
  rewrites it. Without that, moving cdk-nag out of process buys nothing.
- The child does not import from the directory ASH runs in. That directory is usually
  the repository being scanned, and ``python -m`` would import a ``yaml.py`` there as
  ASH's own code.
- One child per batch. jsii startup costs seconds, so a child per template would
  multiply scan time by the template count. That includes Windows-style spellings of
  the same path, and a malformed response; neither may fall back to a child per
  template.
- Every wrapper outcome survives the boundary: None, a ``failure`` response, results,
  and an exception by class name, text and base class. The scanner tells a parse
  failure from any other exception, and it prints ``type(e).__name__``.
- A child that dies keeps the answers it gave. Only the template it was on fails, and a
  new child takes the rest; that holds for a death on the first template too. A child
  that never wrote its protocol header reached no template, so none is blamed: the list
  goes to one more child. A second child in a row that gives nothing fails what is
  pending at once when its failure is the first's: a second child with no header is a
  startup failure every child shares, whatever its stderr says, and a child that did
  start shares the failure when its exit code and its reason, with paths, hex addresses
  and numbers masked, are the first's. Two started children that crash for their own
  reasons do not; three answerless children in a row fail the rest whatever they say.
  Any child that ran into ``scan_timeout`` fails what is pending at once. So a failure
  every child shares is paid twice, not once per template.
- A child the runner could not stop is recorded for the scanner's run-level gate even
  when it had answered every template first; a response the parent could not read keeps
  the runner's outcome for the child; a response past the size cap fails the template
  whose answer crossed it by name of the cap; a child started for a template outside
  the batch is recorded on the batch.
- The response file is read without blocking and only when it is a regular file, so a
  FIFO planted at its path cannot hang the parent; a response past the size cap keeps
  the complete answers inside the cap.
- A child that died or could not be stopped is recorded on the batch, for the scanner to
  record on the plugin as it records any other tool's run.
- The response file sits where a sandboxed child can write, so the parent does not
  follow a symlink there.
- The scratch directory under the results directory is gone afterwards, so the results
  directory looks exactly as it did when cdk-nag ran in-process.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

import pytest
from yaml import YAMLError

from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactContent,
    ArtifactLocation,
    Kind,
    Level,
    Location,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
)
from automated_security_helper.utils import cdk_nag_worker
from automated_security_helper.utils.cdk_nag_wrapper import CdkNagWrapperResponse
from automated_security_helper.utils.get_shortest_name import get_shortest_name

SUBPROCESS_UTILS = "automated_security_helper.utils.subprocess_utils"
NOT_CFN = {"status": "not-cloudformation", "logs": []}


def _fake_child(
    answers_by_template,
    calls: List[List[str]],
    returncode: int = 0,
    answer_first: Optional[int] = None,
    timed_out: bool = False,
    stderr: Optional[str] = None,
):
    """A stand-in for run_command_with_output_handling that plays the child's part.

    Writes the header, then one answer line per template, as the real child does.
    ``answer_first`` stops after that many answers and reports ``returncode``: a child
    that died part way (``answer_first=0`` is a child that wrote its header and died on
    its first template). ``answers_by_template=None`` is a child that died before
    writing anything, its header included. ``stderr`` replaces the default noise.
    """
    stderr = (
        "noise\n\x1b[31mTraceback\x1b[0m\nOSError: boom" if stderr is None else stderr
    )

    def fake(command, **kwargs):
        calls.append(list(command))
        request_path, response_path = Path(command[-2]), Path(command[-1])
        request = json.loads(request_path.read_text(encoding="utf-8"))
        if answers_by_template is None:
            return {"returncode": returncode, "stderr": stderr}
        templates = request["templates"]
        if answer_first is not None:
            templates = templates[:answer_first]
        lines = [json.dumps({"protocol": cdk_nag_worker.PROTOCOL_VERSION})]
        lines += [json.dumps(answers_by_template[t]) for t in templates]
        response_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        if answer_first is not None:
            return {"returncode": returncode, "stderr": stderr, "timed_out": timed_out}
        return {"returncode": 0}

    return fake


def _call(template, outdir: Path):
    return cdk_nag_worker.run_cdk_nag_against_cfn_template(
        template_path=template,
        nag_packs=["AwsSolutionsChecks"],
        outdir=outdir,
        include_compliant_checks=False,
        honor_template_suppressions=True,
    )


def _templates(tmp_path: Path, n: int) -> List[Path]:
    paths = []
    for i in range(n):
        p = tmp_path / f"t{i}.yaml"
        p.write_text("Resources: {}\n", encoding="utf-8")
        paths.append(p)
    return paths


def _patch_spawn(monkeypatch, fake) -> None:
    monkeypatch.setattr(f"{SUBPROCESS_UTILS}.run_command_with_output_handling", fake)


@pytest.mark.unit
def test_one_child_answers_the_whole_batch(tmp_path, monkeypatch):
    templates = _templates(tmp_path, 3)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    calls: List[List[str]] = []
    _patch_spawn(monkeypatch, _fake_child(answers, calls))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, values=()
    ):
        results = [_call(t, outdir) for t in templates]
    assert results == [None, None, None]
    assert len(calls) == 1, "a child per template would pay jsii startup each time"
    assert calls[0][:3] == [sys.executable, "-c", cdk_nag_worker._CHILD_BOOTSTRAP]


@pytest.mark.unit
def test_the_scratch_directory_is_removed(tmp_path, monkeypatch):
    template = _templates(tmp_path, 1)[0]
    _patch_spawn(monkeypatch, _fake_child({template.as_posix(): NOT_CFN}, []))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir, values=()):
        _call(template, outdir)
    assert not (outdir / ".cdk-nag-worker").exists()


@pytest.mark.unit
def test_children_that_die_before_answering_fail_everything_after_two_tries(
    tmp_path, monkeypatch
):
    """A failure every child shares (here, every child dies at once) costs two children:
    the first fails its template, the second proves the failure is not that template's
    and fails everything still pending."""
    templates = _templates(tmp_path, 3)
    calls: List[List[str]] = []
    _patch_spawn(monkeypatch, _fake_child(None, calls, returncode=1))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, values=()
    ):
        for t in templates:
            with pytest.raises(RuntimeError) as raised:
                _call(t, outdir)
            message = str(raised.value)
            assert "exited 1" in message
            assert "OSError: boom" in message
            assert "\x1b[" not in message, "terminal color codes leaked into the error"
    assert len(calls) == 2, (
        "a second answerless child in a row must fail the rest, not be started once "
        f"per template; got {len(calls)} children for {len(templates)} templates"
    )


@pytest.mark.unit
def test_a_child_that_dies_on_the_first_template_fails_only_that_template(
    tmp_path, monkeypatch
):
    """The same crash on a later template failed only that one; the first was treated
    differently and failed the whole batch. At the base the second and third templates
    here were failed with the first child's reason and no second child was started.
    The child here wrote its header and died ON the first template (``answer_first=0``);
    a child with no header at all is the next test's."""
    templates = _templates(tmp_path, 3)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    calls: List[List[str]] = []
    dies = _fake_child({}, calls, returncode=139, answer_first=0)
    finishes = _fake_child(answers, calls)

    def fake(command, **kwargs):
        return (dies if not calls else finishes)(command, **kwargs)

    _patch_spawn(monkeypatch, fake)
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, values=()
    ):
        with pytest.raises(RuntimeError, match="exited 139"):
            _call(templates[0], outdir)
        assert _call(templates[1], outdir) is None
        assert _call(templates[2], outdir) is None
    assert len(calls) == 2


@pytest.mark.unit
def test_a_child_with_no_header_gives_its_first_template_back_to_the_next_child(
    tmp_path, monkeypatch
):
    """A child that never wrote its protocol header never reached a template (an OOM
    kill at startup, a spawn that did not happen), so no template is blamed for it: the
    whole list goes to one more child, and when that one starts nothing is lost. Before
    this read the first template was failed as if the child had died on it, and a
    one-off startup failure graded a template that was never evaluated as failed."""
    templates = _templates(tmp_path, 3)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    fake, calls = _children_in_turn(
        _fake_child(None, [], returncode=137),
        _fake_child(answers, []),
    )
    _patch_spawn(monkeypatch, fake)
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, values=()
    ) as batch:
        for t in templates:
            assert _call(t, outdir) is None
    assert len(calls) == 2, calls
    # The child that died is still a recorded child, for the scanner's exit codes.
    assert [r.get("returncode") for r in batch.failed_child_responses] == [137]


@pytest.mark.unit
def test_a_child_with_no_header_then_a_started_crash_fails_only_the_crashed_template(
    tmp_path, monkeypatch
):
    """The mixed run: the first child never started, the second started and died on
    the first template, the third finishes. The first template fails with the second
    child's reason, nothing is taken as shared, and the rest are evaluated."""
    templates = _templates(tmp_path, 3)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    fake, calls = _children_in_turn(
        _fake_child(None, [], returncode=137),
        _fake_child({}, [], returncode=139, answer_first=0),
        _fake_child(answers, []),
    )
    _patch_spawn(monkeypatch, fake)
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, values=()
    ):
        with pytest.raises(RuntimeError, match="exited 139"):
            _call(templates[0], outdir)
        assert _call(templates[1], outdir) is None
        assert _call(templates[2], outdir) is None
    assert len(calls) == 3, calls


@pytest.mark.unit
def test_a_child_that_died_part_way_keeps_its_answers(tmp_path, monkeypatch):
    """The child answered the first template and died on the second. The first keeps
    its answer, the second fails, and a new child takes the third."""
    templates = _templates(tmp_path, 3)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    calls: List[List[str]] = []
    dies = _fake_child(answers, calls, returncode=139, answer_first=1)
    finishes = _fake_child(answers, calls)

    def fake(command, **kwargs):
        return (dies if not calls else finishes)(command, **kwargs)

    _patch_spawn(monkeypatch, fake)
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, values=()
    ):
        assert _call(templates[0], outdir) is None
        with pytest.raises(RuntimeError, match="exited 139"):
            _call(templates[1], outdir)
        assert _call(templates[2], outdir) is None
    assert len(calls) == 2


@pytest.mark.unit
@pytest.mark.parametrize(
    "limit,token",
    [
        pytest.param(7.5, r"'7\.5' s", id="fraction"),
        # A whole limit prints whole, never '1e+06'.
        pytest.param(1000000, r"'1000000' s", id="large"),
    ],
)
def test_a_timed_out_child_fails_what_it_had_not_answered(
    tmp_path, monkeypatch, limit, token
):
    templates = _templates(tmp_path, 3)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    calls: List[List[str]] = []
    timeouts: List[object] = []
    inner = _fake_child(answers, calls, returncode=124, answer_first=1, timed_out=True)

    def fake(command, **kwargs):
        timeouts.append(kwargs.get("timeout"))
        return inner(command, **kwargs)

    _patch_spawn(monkeypatch, fake)
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, timeout=limit, values=()
    ):
        assert _call(templates[0], outdir) is None
        for t in templates[1:]:
            with pytest.raises(RuntimeError, match=rf"timed out after {token}"):
                _call(t, outdir)
    assert timeouts == [limit], "the timeout reaches the spawn and is not retried"


@pytest.mark.unit
def test_the_timeout_line_prints_the_shared_limit_token(tmp_path, monkeypatch):
    """The worker's timeout line prints its limit through the one formatter
    every timeout message uses (error_text.timeout_limit_token), so it cannot
    drift from the others: a stand-in token is what the line shows. The cell
    above pins what that token prints for a whole and a fractional limit."""
    from automated_security_helper.utils import error_text

    monkeypatch.setattr(
        error_text, "timeout_limit_token", lambda limit, values: "<the shared token>"
    )
    templates = _templates(tmp_path, 2)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    _patch_spawn(
        monkeypatch,
        _fake_child(answers, [], returncode=124, answer_first=1, timed_out=True),
    )
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, timeout=67, values=()
    ):
        assert _call(templates[0], outdir) is None
        with pytest.raises(RuntimeError, match="timed out after <the shared token>"):
            _call(templates[1], outdir)


def _could_not_stop_child(answers_by_template, answer_first: int):
    """A child killed at the timeout whose stop failed: the flag kept, no code."""
    inner = _fake_child(
        answers_by_template,
        [],
        returncode=124,
        answer_first=answer_first,
        timed_out=True,
    )

    def fake(command, **kwargs):
        outcome = inner(command, **kwargs)
        outcome["returncode"] = None
        outcome["could_not_stop"] = True
        outcome["could_not_stop_pid"] = 4242
        return outcome

    return fake


@pytest.mark.unit
def test_a_timeout_the_worker_could_not_stop_is_never_said_killed(
    tmp_path, monkeypatch
):
    """The worker's timeout line, like every sibling site: "was killed" only
    when the stop worked. A stop that failed left the child running, and the
    reason must say so instead."""
    templates = _templates(tmp_path, 2)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    _patch_spawn(monkeypatch, _could_not_stop_child(answers, answer_first=1))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, timeout=5, values=()
    ):
        assert _call(templates[0], outdir) is None
        with pytest.raises(RuntimeError) as excinfo:
            _call(templates[1], outdir)
    message = str(excinfo.value)
    assert "may still be running" in message, message
    assert "was killed" not in message, message


@pytest.mark.unit
def test_a_stopped_worker_timeout_keeps_was_killed(tmp_path, monkeypatch):
    """The control: a timeout whose stop worked IS a killed child."""
    templates = _templates(tmp_path, 2)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    _patch_spawn(
        monkeypatch,
        _fake_child(answers, [], returncode=124, answer_first=1, timed_out=True),
    )
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, timeout=5, values=()
    ):
        assert _call(templates[0], outdir) is None
        with pytest.raises(RuntimeError) as excinfo:
            _call(templates[1], outdir)
    message = str(excinfo.value)
    assert "was killed" in message, message
    assert "may still be running" not in message, message


@pytest.mark.unit
def test_the_scanner_passes_its_scan_timeout():
    import inspect

    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        cdk_nag_scanner,
    )

    source = inspect.getsource(cdk_nag_scanner.CdkNagScanner.scan)
    assert "timeout=self._effective_scan_timeout()" in source


@pytest.mark.unit
@pytest.mark.parametrize("content", ["{not json", "[]", '{"protocol": 999}\n'])
def test_a_malformed_response_fails_the_batch_after_two_tries(
    tmp_path, monkeypatch, content
):
    """A malformed response is an answerless child: two children, never one per
    template."""
    templates = _templates(tmp_path, 3)
    calls: List[List[str]] = []

    def fake(command, **kwargs):
        calls.append(command)
        Path(command[-1]).write_text(content, encoding="utf-8")
        return {"returncode": 0}

    _patch_spawn(monkeypatch, fake)
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, values=()
    ):
        for t in templates:
            with pytest.raises(RuntimeError):
                _call(t, outdir)
    assert len(calls) == 2


@pytest.mark.unit
def test_a_symlinked_response_is_not_followed(tmp_path, monkeypatch):
    """The response file sits where a sandboxed child can write. Replacing it with a
    link must not make the parent read the link's target."""
    target = tmp_path / "elsewhere.jsonl"
    target.write_text(
        json.dumps({"protocol": cdk_nag_worker.PROTOCOL_VERSION})
        + "\n"
        + json.dumps(NOT_CFN)
        + "\n",
        encoding="utf-8",
    )
    template = _templates(tmp_path, 1)[0]

    def fake(command, **kwargs):
        Path(command[-1]).symlink_to(target)
        return {"returncode": 0}

    _patch_spawn(monkeypatch, fake)
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir, values=()):
        with pytest.raises(RuntimeError):
            _call(template, outdir)


@pytest.mark.unit
def test_every_spelling_of_a_template_shares_the_batch(tmp_path, monkeypatch):
    """The scanner lists templates as posix strings and passes Path objects; on
    Windows ``str(Path)`` has backslashes. Every spelling has to find the batch, or
    each template pays for a child of its own."""
    templates = _templates(tmp_path, 3)
    answers = {cdk_nag_worker._key(t): NOT_CFN for t in templates}
    calls: List[List[str]] = []
    _patch_spawn(monkeypatch, _fake_child(answers, calls))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [t.as_posix() for t in templates], outdir, values=()
    ):
        assert _call(templates[0], outdir) is None
        assert _call(Path(str(templates[1])), outdir) is None
        assert _call(str(templates[2]), outdir) is None
    assert len(calls) == 1
    assert cdk_nag_worker._key(Path("C:/x/t.yaml")) == cdk_nag_worker._key(
        "C:/x/t.yaml"
    )


@pytest.mark.integration
def test_control_a_child_that_keeps_sys_path_0_imports_from_the_scanned_directory(
    tmp_path, monkeypatch
):
    """The test below, with the bootstrap's first statement removed.

    The child changes into ASH's working directory, and under ``-c`` the ``''``
    entry follows it, so the planted ``cdk_nag.py`` is what it imports. Shows the
    test below can fail.

    The planted module leaves its mark and then raises an ImportError, which the
    wrapper answers itself, before it imports aws_cdk: this control runs no jsii
    and starts no node. It used to let the planted module import quietly and wait
    for ``_build_nag_pack`` to refuse it, but that refusal sits after the aws_cdk
    import, so the control needed a working node in the child. Under the unit tool
    guard the child resolves node to the guard's stand-in, first on its PATH, jsii
    read the stand-in's empty output as its handshake, and the control failed for
    that reason on every POSIX run, with the stand-in's start counted at teardown.
    """
    first_statement = "sys.path[:1] = [] if sys.path[:1] == [''] else sys.path[:1]; "
    assert first_statement in cdk_nag_worker._CHILD_BOOTSTRAP
    monkeypatch.setattr(
        cdk_nag_worker,
        "_CHILD_BOOTSTRAP",
        cdk_nag_worker._CHILD_BOOTSTRAP.replace(first_statement, ""),
    )
    marker, response = _run_from_a_planted_repository(tmp_path, monkeypatch)
    assert "cdk_nag" in marker.read_text()
    assert response is not None and response.failure is not None
    assert PLANTED_IMPORT_MESSAGE in response.failure


#: What the planted ``cdk_nag.py`` raises once it has left its mark. The wrapper
#: answers an ImportError from ``import cdk_nag`` with a response that carries the
#: exception's text, so the control reads this back without any jsii.
PLANTED_IMPORT_MESSAGE = "planted cdk_nag imported from the scanned directory"


def _run_from_a_planted_repository(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    marker = tmp_path / "IMPORTED"
    for name in ("yaml", "cdk_nag", "pydantic"):
        (repo / f"{name}.py").write_text(
            f"open({str(marker)!r}, 'a').write({name!r})\n", encoding="utf-8"
        )
    # The planted cdk_nag leaves its mark and then refuses to import, so the child
    # never gets as far as aws_cdk, jsii or node; the wrapper's own handling of an
    # import failure answers with a response naming it.
    (repo / "cdk_nag.py").write_text(
        f"open({str(marker)!r}, 'a').write('cdk_nag')\n"
        f"raise ImportError({PLANTED_IMPORT_MESSAGE!r})\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(repo)
    monkeypatch.delenv("PYTHONSAFEPATH", raising=False)
    template = tmp_path / "t.yaml"
    template.write_text(
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n", encoding="utf-8"
    )
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir, values=()):
        response = _call(template, outdir)
    return marker, response


@pytest.mark.integration
def test_the_child_does_not_import_from_the_scanned_directory(tmp_path, monkeypatch):
    """A real child, started from a directory holding modules that leave a mark when
    imported. Under ``python -m`` the working directory is first on the import path,
    so scanning a repository would run its code as ASH's."""
    repo = tmp_path / "repo"
    repo.mkdir()
    marker = tmp_path / "IMPORTED"
    for name in ("yaml", "cdk_nag", "pydantic"):
        (repo / f"{name}.py").write_text(
            f"open({str(marker)!r}, 'a').write({name!r})\n", encoding="utf-8"
        )
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "cdk_nag.py").write_text(
        "raise ImportError('no module named jsii_shadow')\n", encoding="utf-8"
    )
    monkeypatch.setenv("PYTHONPATH", str(shadow))
    monkeypatch.chdir(repo)
    template = tmp_path / "t.yaml"
    template.write_text(
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n", encoding="utf-8"
    )
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir, values=()):
        response = _call(template, outdir)
    assert not marker.exists(), f"the child imported {marker.read_text()} from its cwd"
    assert response is not None and response.failure is not None


@pytest.mark.unit
@pytest.mark.parametrize(
    ("kind", "type_name", "message", "base"),
    [
        ("yaml", "ParserError", "while parsing a flow sequence", YAMLError),
        (
            "unicode",
            "UnicodeDecodeError",
            "'utf-8' codec can't decode",
            UnicodeDecodeError,
        ),
        ("other", "KeyError", "'Unknown cdk-nag pack requested: Nope'", Exception),
    ],
)
def test_an_exception_keeps_its_name_text_and_base(
    tmp_path, monkeypatch, kind, type_name, message, base
):
    template = _templates(tmp_path, 1)[0]
    answers = {
        template.as_posix(): {
            "status": "raised",
            "kind": kind,
            "type": type_name,
            "message": message,
            "logs": [],
        }
    }
    _patch_spawn(monkeypatch, _fake_child(answers, []))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir, values=()):
        with pytest.raises(base) as raised:
            _call(template, outdir)
    assert type(raised.value).__name__ == type_name
    assert str(raised.value) == message
    if kind != "yaml":
        assert not isinstance(raised.value, YAMLError)


def _fields_set(model) -> object:
    """Every nested model's ``model_fields_set``, so an unset field that came back set
    (or the reverse) shows up even where its value is the default."""
    from pydantic import BaseModel, RootModel

    if isinstance(model, RootModel):
        return ("root", _fields_set(model.root))
    if isinstance(model, BaseModel):
        return {
            name: _fields_set(getattr(model, name))
            for name in sorted(model.model_fields_set)
        }
    if isinstance(model, list):
        return [_fields_set(item) for item in model]
    return None


@pytest.mark.unit
def test_results_and_failure_round_trip_unchanged():
    """Shaped like a wrapper finding: explicit ``suppressions=None``, enums, a region
    with a snippet, and a property bag carrying extra keys."""
    finding = Result(
        suppressions=None,
        properties=PropertyBag(
            cdk_nag_finding={
                "rule_id": "AwsSolutions-S1",
                "compliance": "Non-Compliant",
            },
            tags=["aws", "cdk-nag"],
        ),
        ruleId="AwsSolutions-S1",
        level=Level.error,
        kind=Kind.fail,
        message=Message(root=Message1(text="S3 bucket has no access logs")),
        analysisTarget=ArtifactLocation(uri="cfn/t.yaml"),
        locations=[
            Location(
                id=1,
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri="cfn/t.yaml"),
                        region=Region(
                            startLine=3,
                            endLine=3,
                            startColumn=2,
                            endColumn=12,
                            snippet=ArtifactContent(text="Resources:\n  B: {}\n"),
                        ),
                    )
                ),
            )
        ],
    )
    original = CdkNagWrapperResponse(
        results={"AwsSolutions": [finding], "HIPAA": []},
        outdir=Path("/out/x"),
        failure="the validation report could not be read",
    )
    wire = json.loads(json.dumps(cdk_nag_worker._answer_for_response(original)))
    rebuilt = cdk_nag_worker._response_from(wire)
    assert rebuilt.failure == original.failure
    assert rebuilt.outdir == original.outdir
    assert list(rebuilt.results) == ["AwsSolutions", "HIPAA"]
    assert rebuilt.results["HIPAA"] == []
    again = rebuilt.results["AwsSolutions"][0]
    for options in ({"exclude_unset": True}, {}, {"by_alias": True}):
        assert again.model_dump_json(**options) == finding.model_dump_json(**options)
    assert _fields_set(again) == _fields_set(finding)
    assert cdk_nag_worker._answer_for_response(None) == {"status": "not-cloudformation"}


@pytest.mark.unit
def test_logs_are_replayed_with_their_origin(tmp_path, monkeypatch, caplog):
    template = _templates(tmp_path, 1)[0]
    answers = {
        template.as_posix(): {
            "status": "not-cloudformation",
            "logs": [
                {
                    "level": logging.ERROR,
                    "message": "cdk-nag could not be imported",
                    "pathname": "/x/cdk_nag_wrapper.py",
                    "lineno": 742,
                    "funcName": "run_cdk_nag_against_cfn_template",
                }
            ],
        }
    }
    _patch_spawn(monkeypatch, _fake_child(answers, []))
    outdir = tmp_path / "out"
    with caplog.at_level(logging.DEBUG, logger="ash"):
        with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir, values=()):
            _call(template, outdir)
    records = [
        r for r in caplog.records if r.getMessage() == "cdk-nag could not be imported"
    ]
    assert len(records) == 1
    assert records[0].levelno == logging.ERROR
    assert records[0].filename == "cdk_nag_wrapper.py"
    assert records[0].lineno == 742


@pytest.mark.unit
def test_template_names_match_get_shortest_name_in_the_parent(tmp_path, monkeypatch):
    """Built from the parent's directory, then used from another one, as the child
    does."""
    parent = tmp_path / "parent"
    inside = parent / "cfn" / "t.yaml"
    inside.parent.mkdir(parents=True)
    inside.write_text("x", encoding="utf-8")
    elsewhere = tmp_path / "child"
    elsewhere.mkdir()
    candidates = (inside, str(inside), Path(sys.executable), ".", "missing.yaml")
    monkeypatch.chdir(parent)
    expected = [get_shortest_name(c) for c in candidates]
    emulated = cdk_nag_worker._shortest_name_relative_to(Path.cwd())
    monkeypatch.chdir(elsewhere)
    assert [emulated(c) for c in candidates] == expected
    assert emulated(inside) == "cfn/t.yaml"


@pytest.mark.integration
def test_a_real_child_reports_a_failed_cdk_nag_import(tmp_path, monkeypatch, caplog):
    """End to end, with a real child. A ``cdk_nag`` that cannot be imported is first on
    the child's path, so the outcome does not depend on whether the cdk extra is
    installed here, and it is the wrapper's own failure path that answers."""
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "cdk_nag.py").write_text(
        "raise ImportError('no module named jsii_shadow')\n", encoding="utf-8"
    )
    monkeypatch.setenv("PYTHONPATH", str(shadow))
    template = tmp_path / "t.yaml"
    template.write_text(
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n", encoding="utf-8"
    )
    outdir = tmp_path / "out"
    with caplog.at_level(logging.ERROR, logger="ash"):
        with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir, values=()):
            response = _call(template, outdir)
    assert isinstance(response, CdkNagWrapperResponse)
    assert response.failure is not None
    assert "cdk-nag could not be imported (ImportError" in response.failure
    assert response.results == {}
    assert any("could not be imported" in r.getMessage() for r in caplog.records)
    assert not (outdir / ".cdk-nag-worker").exists()


@pytest.mark.integration
def test_the_child_is_started_through_the_sandbox_choke_point(tmp_path):
    """An active sandbox scope rewrites the child's command. The fake backend replaces
    it with a process that exits 3, so the batch can only fail with exit 3 if the
    spawn went through ``_prepare_spawn``."""
    from automated_security_helper.utils.sandbox.backends import (
        SandboxBackend,
        SpawnPlan,
    )
    from automated_security_helper.utils.sandbox.policy import SandboxRequirements
    from automated_security_helper.utils.sandbox.scope import (
        SandboxScope,
        sandbox_scope,
    )

    seen: List[List[str]] = []

    class ExitThree(SandboxBackend):
        name = "test-exit-three"

        def plan(self, argv, env, policy) -> SpawnPlan:  # type: ignore[override]
            seen.append(list(argv))
            return SpawnPlan(
                argv=[sys.executable, "-c", "import sys; sys.exit(3)"], env=dict(env)
            )

    scope = SandboxScope(
        backend=ExitThree(),
        scanner_name="cdk-nag",
        requirements=SandboxRequirements(),
        source_dir=tmp_path,
        output_dir=tmp_path,
        results_dir=tmp_path / "out",
        scan_target=tmp_path,
        offline=True,
    )
    template = _templates(tmp_path, 1)[0]
    outdir = tmp_path / "out"
    with sandbox_scope(scope):
        with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir, values=()):
            with pytest.raises(RuntimeError, match="exited 3"):
                _call(template, outdir)
    assert seen and seen[0][:3] == [
        sys.executable,
        "-c",
        cdk_nag_worker._CHILD_BOOTSTRAP,
    ]


@pytest.mark.unit
def test_the_scanner_declares_a_sandboxable_no_network_child():
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
        CdkNagScanner,
    )

    from automated_security_helper.utils.sandbox.policy import SandboxRequirements

    requirements = CdkNagScanner.sandbox_requirements
    assert isinstance(requirements, SandboxRequirements)
    assert requirements.network is False
    assert not any(p.startswith("NODE_") for p in requirements.env_prefixes), (
        "NODE_OPTIONS can carry a --require into the hidden home directory"
    )


@pytest.mark.unit
def test_the_worker_refuses_a_request_from_another_protocol(tmp_path, capsys):
    request = tmp_path / "request.json"
    request.write_text(json.dumps({"protocol": 999}), encoding="utf-8")
    assert cdk_nag_worker.main([str(request), str(tmp_path / "response.jsonl")]) == 2
    assert not (tmp_path / "response.jsonl").exists()
    assert "protocol" in capsys.readouterr().err


@pytest.mark.unit
@pytest.mark.parametrize("stale", ["file", "link"])
def test_a_response_already_there_is_an_error_result_not_a_traceback(
    tmp_path, capsys, stale
):
    """The child creates its response file; anything at the name is refused."""
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {
                "protocol": cdk_nag_worker.PROTOCOL_VERSION,
                "cwd": tmp_path.as_posix(),
                "log_level": logging.WARNING,
                "options": {},
                "templates": [],
            }
        ),
        encoding="utf-8",
    )
    response = tmp_path / "response.jsonl"
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text("kept\n")
    if stale == "file":
        response.write_text("stale\n")
    else:
        response.symlink_to(elsewhere)

    assert cdk_nag_worker.main([str(request), str(response)]) == 2

    err = capsys.readouterr().err
    assert "already exists" in err and "Traceback" not in err, err
    assert elsewhere.read_text() == "kept\n"
    if stale == "file":
        assert response.read_text() == "stale\n"


@pytest.mark.unit
def test_each_child_gets_a_directory_of_its_own(tmp_path, monkeypatch):
    """A retry's directory is new: one already at its name is not reused."""
    import uuid

    outdir = tmp_path / "out"
    taken = uuid.UUID(int=1)
    (outdir / ".cdk-nag-worker" / taken.hex).mkdir(parents=True)
    monkeypatch.setattr(cdk_nag_worker.uuid, "uuid4", lambda: taken)

    with pytest.raises(FileExistsError):
        cdk_nag_worker._run_child(["t.yaml"], {}, outdir, tmp_path, None, ())


# ---------------------------------------------------------------------------
# The child's shortest-name emulation: a sibling of the working directory
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_sibling_directory_sharing_the_cwds_name_prefix_is_not_made_relative(
    tmp_path,
):
    """``/work2/t.yaml`` is not inside ``/work``. At the base the bare string-prefix test
    said it was, ``relative_to`` raised ValueError, and the template was counted as a
    failed target."""
    cwd = tmp_path / "work"
    cwd.mkdir()
    sibling = tmp_path / "work2" / "t.yaml"
    sibling.parent.mkdir()
    sibling.write_text("Resources: {}\n", encoding="utf-8")
    emulated = cdk_nag_worker._shortest_name_relative_to(cwd)

    assert emulated(sibling) == sibling.as_posix()
    inside = cwd / "t.yaml"
    inside.write_text("Resources: {}\n", encoding="utf-8")
    assert emulated(inside) == "t.yaml"


# ---------------------------------------------------------------------------
# The response file: a FIFO cannot hang the parent, and the cap keeps what fits
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
def test_a_fifo_at_the_response_path_does_not_hang_the_parent(tmp_path):
    """At the base ``_read_answers`` opened the FIFO read-only and blocked for a writer
    that never comes; the regular-file check after the open was never reached. The
    read runs in a thread so the base's hang reads as a timeout, not a stuck suite."""
    import threading

    fifo = tmp_path / "response.jsonl"
    os.mkfifo(fifo)
    result: List[object] = []

    def read():
        result.append(cdk_nag_worker._read_answers(fifo))

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    reader.join(timeout=5)
    if reader.is_alive():
        # Release the blocked open so the thread can end, then fail.
        writer = os.open(fifo, os.O_WRONLY | getattr(os, "O_NONBLOCK", 0))
        os.close(writer)
        reader.join(timeout=5)
        pytest.fail("_read_answers blocked on a FIFO at the response path")
    assert result == [[]]


@pytest.mark.unit
def test_a_response_past_the_cap_keeps_the_complete_answers_inside_it(
    tmp_path, monkeypatch
):
    """At the base a response larger than the cap returned no answers at all, so a child
    that evaluated every template failed the whole batch."""
    header = json.dumps({"protocol": cdk_nag_worker.PROTOCOL_VERSION}) + "\n"
    answer = json.dumps({"status": "not-cloudformation", "logs": []}) + "\n"
    # Two complete answers fit; the third crosses the cap.
    cap = len(header) + 2 * len(answer) + len(answer) // 2
    monkeypatch.setattr(cdk_nag_worker, "_MAX_RESPONSE_BYTES", cap)
    response = tmp_path / "response.jsonl"
    response.write_text(header + answer * 3, encoding="utf-8")

    answers = cdk_nag_worker._read_answers(response)

    assert len(answers) == 2, answers
    started, _, cut = cdk_nag_worker._read_response(response)
    assert started is True
    assert cut is True, "a response past the cap has to say so, for the reason"


# ---------------------------------------------------------------------------
# What the scanner can record about the children
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_the_batch_records_a_child_ash_could_not_stop(tmp_path, monkeypatch):
    """The scanner reads it after its loop and records the could-not-stop state the
    run-level gate reads; at the base nothing left this module but per-template text."""
    templates = _templates(tmp_path, 2)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    _patch_spawn(monkeypatch, _could_not_stop_child(answers, answer_first=1))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, timeout=5, values=()
    ) as batch:
        assert _call(templates[0], outdir) is None
        with pytest.raises(RuntimeError):
            _call(templates[1], outdir)

    assert batch.could_not_stop_response is not None
    assert batch.could_not_stop_response.get("could_not_stop") is True
    assert batch.could_not_stop_response.get("could_not_stop_pid") == 4242


@pytest.mark.unit
def test_the_batch_records_the_exit_code_of_a_child_that_died(tmp_path, monkeypatch):
    templates = _templates(tmp_path, 2)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    _patch_spawn(monkeypatch, _fake_child(answers, [], returncode=139, answer_first=1))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, values=()
    ) as batch:
        assert _call(templates[0], outdir) is None
        with pytest.raises(RuntimeError, match="exited 139"):
            _call(templates[1], outdir)

    assert [r.get("returncode") for r in batch.failed_child_responses] == [139]
    assert batch.could_not_stop_response is None


@pytest.mark.unit
def test_a_relative_work_root_still_hands_the_child_paths_it_can_find(
    tmp_path, monkeypatch
):
    """The child runs with the work directory as its cwd and takes the request and
    response paths on its argv, so they must be absolute. At the base a relative
    ``outdir`` produced relative argv paths, resolved by the child against its own cwd,
    and the request was never found."""
    monkeypatch.chdir(tmp_path)
    templates = _templates(tmp_path, 1)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    calls: List[List[str]] = []
    _patch_spawn(monkeypatch, _fake_child(answers, calls))

    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], Path("relative-out"), values=()
    ):
        assert _call(templates[0], Path("relative-out")) is None

    request_path, response_path = Path(calls[0][-2]), Path(calls[0][-1])
    assert request_path.is_absolute(), request_path
    assert response_path.is_absolute(), response_path


def _children_in_turn(*fakes):
    """Dispatch each child start to the next fake in order."""
    calls: List[List[str]] = []

    def fake(command, **kwargs):
        index = min(len(calls), len(fakes) - 1)
        calls.append(list(command))
        return fakes[index](command, **kwargs)

    return fake, calls


@pytest.mark.unit
def test_two_answerless_children_with_different_reasons_are_not_one_shared_failure(
    tmp_path, monkeypatch
):
    """Two neighboring templates each crash a STARTED child (its header is written) for
    their own reason: the second crash is not the first's, so the third template still
    gets its own child instead of being failed with the second template's reason, as it
    was before this read."""
    templates = _templates(tmp_path, 3)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    fake, calls = _children_in_turn(
        _fake_child({}, [], returncode=134, answer_first=0),
        _fake_child({}, [], returncode=139, answer_first=0),
        _fake_child(answers, []),
    )
    _patch_spawn(monkeypatch, fake)
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, values=()
    ):
        with pytest.raises(RuntimeError, match="exited 134"):
            _call(templates[0], outdir)
        with pytest.raises(RuntimeError, match="exited 139"):
            _call(templates[1], outdir)
        assert _call(templates[2], outdir) is None
    assert len(calls) == 3


@pytest.mark.unit
def test_three_answerless_children_in_a_row_fail_the_rest_whatever_their_reasons(
    tmp_path, monkeypatch
):
    """The bound: a run of started children crashing with differing reasons stops at the
    third child."""
    templates = _templates(tmp_path, 4)
    fake, calls = _children_in_turn(
        _fake_child({}, [], returncode=1, answer_first=0),
        _fake_child({}, [], returncode=2, answer_first=0),
        _fake_child({}, [], returncode=3, answer_first=0),
    )
    _patch_spawn(monkeypatch, fake)
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, values=()
    ):
        with pytest.raises(RuntimeError, match="exited 1 "):
            _call(templates[0], outdir)
        with pytest.raises(RuntimeError, match="exited 2 "):
            _call(templates[1], outdir)
        with pytest.raises(RuntimeError, match="exited 3 "):
            _call(templates[2], outdir)
        with pytest.raises(RuntimeError, match="exited 3 "):
            _call(templates[3], outdir)
    assert len(calls) == 3


@pytest.mark.unit
def test_two_children_that_never_started_are_one_shared_failure_whatever_they_said(
    tmp_path, monkeypatch
):
    """A child that wrote no protocol header never reached its templates: a startup
    failure (the interpreter did not start, ASH's own import failed) that every child
    shares. The two children here fail with texts that stay different once paths and
    numbers are masked, so the textual signal alone would take the second for a new
    failure and pay a third child. The structural signal decides instead: two
    headerless children, and the rest is failed with the second's reason."""
    templates = _templates(tmp_path, 3)
    fake, calls = _children_in_turn(
        _fake_child(
            None,
            [],
            returncode=1,
            stderr='Traceback\n  File "/tmp/ash-work/cdk-nag/run-one/request.json"\n'
            "ModuleNotFoundError: No module named 'automated_security_helper'",
        ),
        _fake_child(
            None,
            [],
            returncode=1,
            stderr="ImportError: libpython3.so: cannot open shared object file",
        ),
    )
    _patch_spawn(monkeypatch, fake)
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, values=()
    ):
        for t in templates:
            with pytest.raises(RuntimeError, match="cannot open shared object file"):
                _call(t, outdir)
    assert len(calls) == 2, calls
    # The control for the reading: the two reasons do not mask to one signature, so
    # only the header rule can have joined them.
    assert cdk_nag_worker._failure_signature(
        {"returncode": 1}, "exited 1 before answering: No module named 'x'"
    ) != cdk_nag_worker._failure_signature(
        {"returncode": 1}, "exited 1 before answering: cannot open shared object file"
    )


@pytest.mark.unit
def test_a_started_childs_crash_whose_text_differs_only_in_paths_and_numbers_is_shared(
    tmp_path, monkeypatch
):
    """Two started children die the same way; only a pid and a scratch path in the
    stderr differ. Masked, the reasons are one, so the second child proves the failure
    shared and the rest is failed, where an exact compare paid a third child."""
    templates = _templates(tmp_path, 3)
    fake, calls = _children_in_turn(
        _fake_child(
            {},
            [],
            returncode=134,
            answer_first=0,
            stderr="FATAL ERROR: heap out of memory (pid 4242)\n"
            "at /tmp/ash-work/cdk-nag/run-one/bin/jsii-runtime.js",
        ),
        _fake_child(
            {},
            [],
            returncode=134,
            answer_first=0,
            stderr="FATAL ERROR: heap out of memory (pid 4301)\n"
            "at /tmp/ash-work/cdk-nag/run-two/bin/jsii-runtime.js",
        ),
    )
    _patch_spawn(monkeypatch, fake)
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, values=()
    ):
        for t in templates:
            with pytest.raises(RuntimeError, match="heap out of memory"):
                _call(t, outdir)
    assert len(calls) == 2, calls


@pytest.mark.unit
def test_the_failure_signature_masks_paths_and_numbers_but_keeps_the_exit_code():
    one = cdk_nag_worker._failure_signature(
        {"returncode": 134},
        "exited 134 before answering: at /tmp/w/run-one/x.js | pid 4242",
    )
    two = cdk_nag_worker._failure_signature(
        {"returncode": 134},
        "exited 134 before answering: at /tmp/w/run-two/x.js | pid 4301",
    )
    other_code = cdk_nag_worker._failure_signature(
        {"returncode": 139},
        "exited 139 before answering: at /tmp/w/run-one/x.js | pid 4242",
    )
    assert one == two
    assert one != other_code


@pytest.mark.unit
def test_the_failure_signature_masks_hex_addresses_too():
    """faulthandler prints the current thread as a hex id and a node fatal-error line
    prints native frames as hex addresses; both differ from run to run. Masking digits
    alone left the hex letters, so the same crash read as two failures and cost a third
    child. (Short addresses here; real ones are longer and differ the same way.)"""
    one = cdk_nag_worker._failure_signature(
        {"returncode": 134},
        "exited 134 before answering: Current thread 0x7f3c2a | at 0x55d1a2",
    )
    two = cdk_nag_worker._failure_signature(
        {"returncode": 134},
        "exited 134 before answering: Current thread 0x7e9c1b | at 0x55e2f3",
    )
    assert one == two
    assert one != cdk_nag_worker._failure_signature(
        {"returncode": 134}, "exited 134 before answering: Current thread 0x7f3c2a"
    )


@pytest.mark.unit
def test_a_response_that_outgrew_the_cap_fails_the_cut_template_by_name_of_the_cap(
    tmp_path, monkeypatch
):
    """The batch above the read: the child exited clean having answered every template,
    and the third answer crossed the cap. The two inside it pass; the third is failed
    with a reason that names the cap, not as a worker that "exited 0 before answering",
    and no child is counted as answerless for it."""
    header = json.dumps({"protocol": cdk_nag_worker.PROTOCOL_VERSION}) + "\n"
    templates = _templates(tmp_path, 3)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    answer = json.dumps(NOT_CFN) + "\n"
    cap = len(header) + 2 * len(answer) + len(answer) // 2
    monkeypatch.setattr(cdk_nag_worker, "_MAX_RESPONSE_BYTES", cap)
    calls: List[List[str]] = []
    _patch_spawn(monkeypatch, _fake_child(answers, calls))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, values=()
    ) as batch:
        assert _call(templates[0], outdir) is None
        assert _call(templates[1], outdir) is None
        with pytest.raises(RuntimeError, match="outgrew") as raised:
            _call(templates[2], outdir)
    assert "exited 0 before answering" not in str(raised.value)
    assert str(cap) in str(raised.value)
    assert len(calls) == 1, calls
    # Recorded as a child that did not answer everything it was asked, with the exit
    # code it had: a clean one.
    assert [r.get("returncode") for r in batch.failed_child_responses] == [0]


@pytest.mark.unit
def test_an_answer_too_deep_for_the_parser_ends_the_answers_without_raising(tmp_path):
    """``json.loads`` raises RecursionError, not ValueError, on a deeply nested line;
    uncaught it escaped the read and the batch lost the child's outcome. The answers
    before the line are kept; the line and what follows are not answers."""
    deep = "[" * 100000 + "]" * 100000
    response = tmp_path / "response.jsonl"
    response.write_text(
        json.dumps({"protocol": cdk_nag_worker.PROTOCOL_VERSION})
        + "\n"
        + json.dumps(NOT_CFN)
        + "\n"
        + deep
        + "\n"
        + json.dumps(NOT_CFN)
        + "\n",
        encoding="utf-8",
    )

    started, answers, cut = cdk_nag_worker._read_response(response)

    assert started is True
    assert answers == [NOT_CFN]
    assert cut is False


@pytest.mark.unit
def test_a_read_that_raises_keeps_the_childs_outcome_and_its_could_not_stop_state(
    tmp_path, monkeypatch
):
    """The runner's outcome is known before the response is read. A read that raised
    (ELOOP from O_NOFOLLOW on a symlink the sandboxed child swapped in after the
    checks) escaped ``_run_child``, the batch dropped the outcome, and a new child was
    started beside one the runner could not stop, the hazard the could-not-stop branch
    exists to prevent."""
    import errno

    def swapped(path):
        raise OSError(errno.ELOOP, "Too many levels of symbolic links", str(path))

    monkeypatch.setattr(cdk_nag_worker, "_read_response", swapped)
    _patch_spawn(
        monkeypatch,
        _header_only_outcome(
            {"returncode": None, "could_not_stop": True, "stderr": "wait failed"}
        ),
    )

    answers, reason, fail_rest, recorded = cdk_nag_worker._run_child(
        ["a.yaml", "b.yaml"], {}, tmp_path / "out", tmp_path, 30.0, ()
    )

    assert answers == []
    assert fail_rest is True
    assert recorded.get("could_not_stop") is True
    assert recorded.get("worker_started") is False
    assert "no new worker was started" in reason


@pytest.mark.unit
def test_a_read_that_raises_on_a_clean_exit_names_the_read_in_the_reason(
    tmp_path, monkeypatch
):
    def swapped(path):
        raise OSError(40, "Too many levels of symbolic links", str(path))

    monkeypatch.setattr(cdk_nag_worker, "_read_response", swapped)
    _patch_spawn(monkeypatch, _header_only_outcome({"returncode": 0, "stderr": ""}))

    answers, reason, fail_rest, recorded = cdk_nag_worker._run_child(
        ["a.yaml"], {}, tmp_path / "out", tmp_path, 30.0, ()
    )

    assert answers == []
    assert fail_rest is False
    assert recorded.get("returncode") == 0
    assert "could not be read (OSError)" in reason


def _header_only_outcome(outcome):
    """A runner whose child wrote the protocol header and nothing more."""

    def fake(command, **kwargs):
        Path(command[-1]).write_text(
            json.dumps({"protocol": cdk_nag_worker.PROTOCOL_VERSION}) + "\n",
            encoding="utf-8",
        )
        return dict(outcome)

    return fake


@pytest.mark.unit
def test_a_child_that_answered_everything_but_could_not_be_stopped_is_recorded(
    tmp_path, monkeypatch
):
    """The child wrote every answer, then hung in teardown past the limit and the stop
    failed. Before this read ``_run_child`` returned on the complete answers before the
    stop state was looked at, so the response was treated as a clean success and the
    run-level could-not-stop gate never saw a process that may still be running."""
    templates = _templates(tmp_path, 2)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    _patch_spawn(monkeypatch, _could_not_stop_child(answers, answer_first=2))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, timeout=5, values=()
    ) as batch:
        assert _call(templates[0], outdir) is None
        assert _call(templates[1], outdir) is None

    assert batch.could_not_stop_response is not None
    assert batch.could_not_stop_response.get("could_not_stop_pid") == 4242
    # Not a failed child: every template was answered, so no exit-code record.
    assert batch.failed_child_responses == []


@pytest.mark.unit
def test_a_child_started_outside_the_batch_is_recorded_on_the_batch(
    tmp_path, monkeypatch
):
    """``answer_for`` evaluates a template outside the batch in a child of its own; that
    child's death reached no record before this read, because the single-template batch
    it ran in was thrown away with its records."""
    inside, outside = _templates(tmp_path, 2)
    _patch_spawn(monkeypatch, _fake_child({}, [], returncode=139, answer_first=0))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch([str(inside)], outdir, values=()) as batch:
        with pytest.raises(RuntimeError, match="exited 139"):
            _call(outside, outdir)

    assert [r.get("returncode") for r in batch.failed_child_responses] == [139]


@pytest.mark.unit
def test_a_runner_that_raised_before_any_child_ran_leaves_no_child_record(
    tmp_path, monkeypatch
):
    """The runner raising is not a child's exit; nothing is recorded for the scanner's
    exit-code recorder to read. Before this read an empty response was appended."""
    templates = _templates(tmp_path, 2)

    def raising(*args, **kwargs):
        raise RuntimeError("the scratch directory could not be made")

    monkeypatch.setattr(cdk_nag_worker, "_run_child", raising)
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, values=()
    ) as batch:
        for t in templates:
            with pytest.raises(RuntimeError, match="scratch directory"):
                _call(t, outdir)

    assert batch.failed_child_responses == []
    assert batch.could_not_stop_response is None
