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
  new child takes the rest. A child that gave nothing, or ran into ``scan_timeout``,
  fails what is pending, once.
- The response file sits where a sandboxed child can write, so the parent does not
  follow a symlink there.
- The scratch directory under the results directory is gone afterwards, so the results
  directory looks exactly as it did when cdk-nag ran in-process.
"""

from __future__ import annotations

import json
import logging
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
):
    """A stand-in for run_command_with_output_handling that plays the child's part.

    Writes the header, then one answer line per template, as the real child does.
    ``answer_first`` stops after that many answers and reports ``returncode``: a child
    that died part way. ``answers_by_template=None`` is a child that died before
    writing anything.
    """

    def fake(command, **kwargs):
        calls.append(list(command))
        request_path, response_path = Path(command[-2]), Path(command[-1])
        request = json.loads(request_path.read_text(encoding="utf-8"))
        stderr = "noise\n\x1b[31mTraceback\x1b[0m\nOSError: boom"
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


def test_one_child_answers_the_whole_batch(tmp_path, monkeypatch):
    templates = _templates(tmp_path, 3)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    calls: List[List[str]] = []
    _patch_spawn(monkeypatch, _fake_child(answers, calls))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch([str(t) for t in templates], outdir):
        results = [_call(t, outdir) for t in templates]
    assert results == [None, None, None]
    assert len(calls) == 1, "a child per template would pay jsii startup each time"
    assert calls[0][:3] == [sys.executable, "-c", cdk_nag_worker._CHILD_BOOTSTRAP]


def test_the_scratch_directory_is_removed(tmp_path, monkeypatch):
    template = _templates(tmp_path, 1)[0]
    _patch_spawn(monkeypatch, _fake_child({template.as_posix(): NOT_CFN}, []))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir):
        _call(template, outdir)
    assert not (outdir / ".cdk-nag-worker").exists()


def test_a_child_that_died_before_answering_fails_everything_once(
    tmp_path, monkeypatch
):
    templates = _templates(tmp_path, 2)
    calls: List[List[str]] = []
    _patch_spawn(monkeypatch, _fake_child(None, calls, returncode=1))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch([str(t) for t in templates], outdir):
        for t in templates:
            with pytest.raises(RuntimeError) as raised:
                _call(t, outdir)
            message = str(raised.value)
            assert "exited 1" in message
            assert "OSError: boom" in message
            assert "\x1b[" not in message, "terminal color codes leaked into the error"
    assert len(calls) == 1, "a child that answered nothing must not be restarted"


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
    with cdk_nag_worker.cdk_nag_worker_batch([str(t) for t in templates], outdir):
        assert _call(templates[0], outdir) is None
        with pytest.raises(RuntimeError, match="exited 139"):
            _call(templates[1], outdir)
        assert _call(templates[2], outdir) is None
    assert len(calls) == 2


def test_a_timed_out_child_fails_what_it_had_not_answered(tmp_path, monkeypatch):
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
        [str(t) for t in templates], outdir, timeout=7.5
    ):
        assert _call(templates[0], outdir) is None
        for t in templates[1:]:
            with pytest.raises(RuntimeError, match=r"timed out after 7\.5s"):
                _call(t, outdir)
    assert timeouts == [7.5], "the timeout reaches the spawn and is not retried"


def test_the_scanner_passes_its_scan_timeout():
    import inspect

    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        cdk_nag_scanner,
    )

    source = inspect.getsource(cdk_nag_scanner.CdkNagScanner.scan)
    assert "timeout=self._effective_scan_timeout()" in source


@pytest.mark.parametrize("content", ["{not json", "[]", '{"protocol": 999}\n'])
def test_a_malformed_response_fails_the_batch_once(tmp_path, monkeypatch, content):
    templates = _templates(tmp_path, 3)
    calls: List[List[str]] = []

    def fake(command, **kwargs):
        calls.append(command)
        Path(command[-1]).write_text(content, encoding="utf-8")
        return {"returncode": 0}

    _patch_spawn(monkeypatch, fake)
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch([str(t) for t in templates], outdir):
        for t in templates:
            with pytest.raises(RuntimeError):
                _call(t, outdir)
    assert len(calls) == 1


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
    with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir):
        with pytest.raises(RuntimeError):
            _call(template, outdir)


def test_every_spelling_of_a_template_shares_the_batch(tmp_path, monkeypatch):
    """The scanner lists templates as posix strings and passes Path objects; on
    Windows ``str(Path)`` has backslashes. Every spelling has to find the batch, or
    each template pays for a child of its own."""
    templates = _templates(tmp_path, 3)
    answers = {cdk_nag_worker._key(t): NOT_CFN for t in templates}
    calls: List[List[str]] = []
    _patch_spawn(monkeypatch, _fake_child(answers, calls))
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch([t.as_posix() for t in templates], outdir):
        assert _call(templates[0], outdir) is None
        assert _call(Path(str(templates[1])), outdir) is None
        assert _call(str(templates[2]), outdir) is None
    assert len(calls) == 1
    assert cdk_nag_worker._key(Path("C:/x/t.yaml")) == cdk_nag_worker._key(
        "C:/x/t.yaml"
    )


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
    with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir):
        response = _call(template, outdir)
    assert not marker.exists(), f"the child imported {marker.read_text()} from its cwd"
    assert response is not None and response.failure is not None


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
    with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir):
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
        with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir):
            _call(template, outdir)
    records = [
        r for r in caplog.records if r.getMessage() == "cdk-nag could not be imported"
    ]
    assert len(records) == 1
    assert records[0].levelno == logging.ERROR
    assert records[0].filename == "cdk_nag_wrapper.py"
    assert records[0].lineno == 742


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
        with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir):
            response = _call(template, outdir)
    assert isinstance(response, CdkNagWrapperResponse)
    assert response.failure is not None
    assert "cdk-nag could not be imported (ImportError" in response.failure
    assert response.results == {}
    assert any("could not be imported" in r.getMessage() for r in caplog.records)
    assert not (outdir / ".cdk-nag-worker").exists()


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
        with cdk_nag_worker.cdk_nag_worker_batch([str(template)], outdir):
            with pytest.raises(RuntimeError, match="exited 3"):
                _call(template, outdir)
    assert seen and seen[0][:3] == [
        sys.executable,
        "-c",
        cdk_nag_worker._CHILD_BOOTSTRAP,
    ]


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


def test_the_worker_refuses_a_request_from_another_protocol(tmp_path, capsys):
    request = tmp_path / "request.json"
    request.write_text(json.dumps({"protocol": 999}), encoding="utf-8")
    assert cdk_nag_worker.main([str(request), str(tmp_path / "response.jsonl")]) == 2
    assert not (tmp_path / "response.jsonl").exists()
    assert "protocol" in capsys.readouterr().err
