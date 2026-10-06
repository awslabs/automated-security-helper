# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/e2e/assert_quick_create.py, the quick-create channel's e2e verdict.

The CI leg (scripts/e2e/quick_create.sh) shows each negative control failing against
real renders. These tests pin the assertion logic case by case on the whole unit-test
matrix, so a change that stops one class of defect from being reported fails here even
when the shell leg is not run. Each rejection is matched on its message, so a case
cannot pass by being rejected for an unrelated reason.
"""

from __future__ import annotations

import importlib.util
import json
import shlex
import sys
import urllib.parse
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ASSERT = REPO_ROOT / "scripts" / "e2e" / "assert_quick_create.py"
RENDERER = REPO_ROOT / "scripts" / "render_quick_create_links.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, path
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


aq = _load(ASSERT, "ash_e2e_assert_quick_create")
renderer = _load(RENDERER, "ash_render_quick_create_links_for_e2e")

DOTTED = {
    "bucket": "ash-e2e.quick-create.invalid",
    "bucket_region": "eu-west-2",
    "key_prefix": "e2e prefix+v4/",
    "launch_regions": ["us-east-1", "eu-west-2"],
}
UNDOTTED = {
    "bucket": "ash-e2e-quick-create-invalid",
    "bucket_region": "us-east-1",
    "key_prefix": "",
    "launch_regions": ["us-east-1"],
}


def _render(tmp_path: Path, hosting: dict) -> tuple[Path, Path]:
    config = tmp_path / "hosting.json"
    config.write_text(json.dumps(hosting), encoding="utf-8")
    out = tmp_path / "links.md"
    assert (
        renderer.main(["r", "render", "--hosting", str(config), "--out", str(out)]) == 0
    )
    return config, out


def _judge(text: str, hosting: dict, addressing: str):
    stacks = aq.load_templates(aq.DEFAULT_TEMPLATES)
    return aq.judge(text, hosting, stacks, addressing)


def _fails(problems: list[str], needle: str) -> None:
    assert problems, "accepted, but it must be rejected"
    assert any(needle in p for p in problems), problems


class TestARealRenderIsAccepted:
    """The control: without it every rejection below could come from a judge that
    rejects everything."""

    @pytest.mark.parametrize(
        "hosting, addressing", [(DOTTED, "path"), (UNDOTTED, "virtual")]
    )
    def test_accepted(self, tmp_path, hosting, addressing):
        _, doc = _render(tmp_path, hosting)
        regions, params, problems = _judge(
            doc.read_text(encoding="utf-8"), hosting, addressing
        )
        assert problems == []
        stacks = aq.load_templates(aq.DEFAULT_TEMPLATES)
        assert set(regions) == set(stacks)
        assert all(r == hosting["launch_regions"] for r in regions.values())
        assert params > 0

    def test_the_dotted_render_is_path_style(self, tmp_path):
        _, doc = _render(tmp_path, DOTTED)
        text = doc.read_text(encoding="utf-8")
        urls = aq.CONSOLE_URL_RE.findall(text)
        assert urls
        for url in urls:
            fields = dict(urllib.parse.parse_qsl(url.split("#", 1)[1].split("?", 1)[1]))
            assert fields["templateURL"].startswith(
                "https://s3.eu-west-2.amazonaws.com/ash-e2e.quick-create.invalid/"
                "e2e%20prefix%2Bv4/"
            ), fields["templateURL"]


class TestEachDefectIsRejected:
    def test_dotted_bucket_addressed_virtual_hosted(self, tmp_path):
        _, doc = _render(tmp_path, DOTTED)
        text = doc.read_text(encoding="utf-8").replace(
            urllib.parse.quote(
                "https://s3.eu-west-2.amazonaws.com/ash-e2e.quick-create.invalid/",
                safe="",
            ),
            urllib.parse.quote(
                "https://ash-e2e.quick-create.invalid.s3.eu-west-2.amazonaws.com/",
                safe="",
            ),
        )
        _fails(_judge(text, DOTTED, "path")[2], "path addressing")

    def test_undotted_render_judged_as_path_style(self, tmp_path):
        _, doc = _render(tmp_path, UNDOTTED)
        _fails(
            _judge(doc.read_text(encoding="utf-8"), UNDOTTED, "path")[2],
            "path addressing",
        )

    def test_a_different_bucket(self, tmp_path):
        _, doc = _render(tmp_path, UNDOTTED)
        other = dict(UNDOTTED, bucket="some-other-bucket")
        _fails(_judge(doc.read_text(encoding="utf-8"), other, "virtual")[2], "requires")

    def test_a_missing_launch_region(self, tmp_path):
        _, doc = _render(tmp_path, UNDOTTED)
        wider = dict(UNDOTTED, launch_regions=["us-east-1", "us-west-2"])
        problems = _judge(doc.read_text(encoding="utf-8"), wider, "virtual")[2]
        _fails(problems, "no link launches")
        _fails(problems, "requires 12")

    def test_a_duplicated_link(self, tmp_path):
        _, doc = _render(tmp_path, UNDOTTED)
        text = doc.read_text(encoding="utf-8")
        first = aq.CONSOLE_URL_RE.findall(text)[0]
        _fails(
            _judge(text + f"\n[again]({first})\n", UNDOTTED, "virtual")[2],
            "more than one link",
        )

    @pytest.mark.parametrize(
        "edit, needle",
        [
            (
                ("param_AshVersion=v3.7.0", "param_AshVersion=v9.9.9"),
                "declares Default",
            ),
            (("param_AshVersion=", "param_AshVerison="), "not declared"),
            (("stackName=AshAgentCore", "stackName=Other"), "stackName is"),
            (("?region=us-east-1#", "?region=eu-west-2#"), "same region"),
            (
                ("#/stacks/create/review?", "#/stacks/create/"),
                "fragment does not start",
            ),
        ],
    )
    def test_a_hand_edited_link(self, tmp_path, edit, needle):
        _, doc = _render(tmp_path, UNDOTTED)
        text = doc.read_text(encoding="utf-8")
        assert edit[0] in text, edit
        _fails(
            _judge(text.replace(edit[0], edit[1], 1), UNDOTTED, "virtual")[2], needle
        )

    def test_a_noecho_parameter(self, tmp_path):
        _, doc = _render(tmp_path, UNDOTTED)
        text = doc.read_text(encoding="utf-8").replace(
            "stackName=AshAgentCore",
            "stackName=AshAgentCore&param_McpAuthHeaderValue=x",
            1,
        )
        _fails(_judge(text, UNDOTTED, "virtual")[2], "NoEcho")

    def test_a_document_with_no_links(self):
        problems = _judge("no links here", UNDOTTED, "virtual")[2]
        _fails(problems, "found 0 console link")
        _fails(problems, "vacuous")


class TestTheCommandLine:
    def test_lint_failure_fails_the_assertion(self, tmp_path, capsys):
        config, doc = _render(tmp_path, UNDOTTED)
        fake = shlex.join(
            [
                sys.executable,
                "-c",
                "import sys; sys.exit(2 if 'AshFargate' in sys.argv[1] else 0)",
            ]
        )
        rc = aq.main(
            [
                "--doc",
                str(doc),
                "--hosting",
                str(config),
                "--addressing",
                "virtual",
                "--lint-cmd",
                fake,
            ]
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "AshFargate" in err and "exited 2" in err

    def test_lint_receives_the_launch_regions(self, tmp_path, capsys):
        config, doc = _render(tmp_path, DOTTED)
        record = tmp_path / "argv.txt"
        fake = shlex.join(
            [
                sys.executable,
                "-c",
                f"import sys; open({str(record)!r}, 'a').write(' '.join(sys.argv[1:]) + chr(10))",
            ]
        )
        rc = aq.main(
            [
                "--doc",
                str(doc),
                "--hosting",
                str(config),
                "--addressing",
                "path",
                "--lint-cmd",
                fake,
            ]
        )
        assert rc == 0, capsys.readouterr().err
        lines = record.read_text(encoding="utf-8").splitlines()
        assert len(lines) == len(aq.load_templates(aq.DEFAULT_TEMPLATES))
        assert all(line.endswith("--regions us-east-1 eu-west-2") for line in lines), (
            lines
        )

    def test_a_linter_that_cannot_start_is_a_usage_error(self, tmp_path, capsys):
        # --lint-cmd is POSIX-quoted on every platform, so shlex.join is how a caller
        # builds it. The program here is a native path, which on Windows is full of
        # backslashes; the message must name it intact, which an unquoted path split
        # with POSIX rules would not.
        config, doc = _render(tmp_path, UNDOTTED)
        absent = tmp_path / "no such dir" / "cfn-lint"
        rc = aq.main(
            [
                "--doc",
                str(doc),
                "--hosting",
                str(config),
                "--addressing",
                "virtual",
                "--lint-cmd",
                shlex.join([str(absent), "--non-zero-exit-code", "error"]),
            ]
        )
        assert rc == 2
        err = capsys.readouterr().err
        assert "cannot run the linter" in err and repr(str(absent)) in err, err

    def test_an_empty_bucket_is_a_usage_error(self, tmp_path):
        config = tmp_path / "hosting.json"
        config.write_text(json.dumps(dict(UNDOTTED, bucket="")), encoding="utf-8")
        doc = tmp_path / "doc.md"
        doc.write_text("", encoding="utf-8")
        assert (
            aq.main(
                ["--doc", str(doc), "--hosting", str(config), "--addressing", "virtual"]
            )
            == 2
        )
