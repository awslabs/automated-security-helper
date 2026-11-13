# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The rewrites that make a docs pipeline run the ASH of the pull request under test.

WHY THIS EXISTS
---------------
Every pipeline on the CI pages installs a released ASH: an ``INSTALL_SPEC`` that names
a git tag, or a call to ASH's reusable workflows at that tag. Run as written, the Docs
CI Runners workflow would test the release, not the pull request. So before a block
runs, tests/integration/docs/ci_runners/rewrite.py replaces each of those with the
pull request's own ASH:

* an install line takes the wheel built in the job, with its sha256 in the URL, so pip
  checks the file and records the hash in the install's direct_url.json. The CodeBuild
  agent has no way to mount the wheel and would scan a wheel left in the source, so it
  takes the head commit from the base repository instead;
* a reusable-workflow call takes the pull request's own workflow file, with
  ``ash-version`` the head commit and ``ash-repo`` the base repository;
* a job image becomes its pinned digest, or stays an image the run built itself;
* after each install, a step prints the installed distribution's direct_url.json
  between fixed markers, which provenance.py reads back;
* a CircleCI job gets a last step, run whatever happened before it, that copies the
  reports to a second mount, because ``circleci local execute`` discards the project
  directory when the job ends.

Each rewrite is an exact string replacement with an expected count. A block that
matches none of the install forms is an error naming the block, so a docs change to an
install line cannot quietly test the release. Every value a rewrite writes is literal:
no ``${{``, ``$RUNNER_TEMP``, ``$HOME`` or ``~`` for a shell or a runner to expand later.

The head commit comes from the event: ``pull_request.head.sha`` on a pull request and
GITHUB_SHA on workflow_dispatch. Anything else, or a missing value, is an error, never
a fallback from one to the other.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import re
import sys
import warnings
from pathlib import Path, PurePosixPath

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_RUNNERS = REPO_ROOT / "tests" / "integration" / "docs" / "ci_runners"
PACKAGE = "_ash_ci_runners"
HEAD = "0123456789abcdef0123456789abcdef01234567"
OTHER = "fedcba9876543210fedcba9876543210fedcba98"
REPOSITORY = "awslabs/automated-security-helper"
WHEEL_SHA256 = "d" * 64
PY_DIGEST = "public.ecr.aws/docker/library/python@sha256:" + "e" * 64
CIMG_DIGEST = "docker.io/cimg/python@sha256:" + "f" * 64
BUILT_IMAGE = "registry.example.com/security/automated-security-helper:ci"
NOT_LITERAL = ("${{", "$RUNNER_TEMP", "$HOME", "~")
#: How the pipeline checks name a variable pip or uv reads a setting from.
INSTALLER_SETTING = "a setting pip or uv reads from the environment"


def _module(stem: str):
    if PACKAGE not in sys.modules:
        init = CI_RUNNERS / "__init__.py"
        if not init.is_file():
            pytest.fail("missing tests/integration/docs/ci_runners/__init__.py")
        spec = importlib.util.spec_from_file_location(
            PACKAGE, init, submodule_search_locations=[str(CI_RUNNERS)]
        )
        assert spec and spec.loader
        package = importlib.util.module_from_spec(spec)
        sys.modules[PACKAGE] = package
        spec.loader.exec_module(package)
    if not (CI_RUNNERS / f"{stem}.py").is_file():
        pytest.fail(f"missing tests/integration/docs/ci_runners/{stem}.py")
    return importlib.import_module(f"{PACKAGE}.{stem}")


def _api(stem: str, name: str):
    module = _module(stem)
    if not hasattr(module, name):
        pytest.fail(f"tests/integration/docs/ci_runners/{stem}.py defines no {name}")
    return getattr(module, name)


def _checks():
    name = "_ash_docs_checks"
    if name not in sys.modules:
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
        spec = importlib.util.spec_from_file_location(
            name, REPO_ROOT / "scripts" / "docs_checks.py"
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def _version() -> str:
    return _checks().current_version(str(REPO_ROOT))


def _release_spec() -> str:
    """The install spec the pages pin, built here so this file holds no release pin."""
    return (
        "automated-security-helper[cdk] @ git+https://github.com/"
        + REPOSITORY
        + ".git@v"
        + _version()
    )


def _block(rel: str, kind: str | None = None, lang: str | None = None, index: int = 0):
    page = _checks().parse_page(REPO_ROOT / rel, REPO_ROOT)
    blocks = [
        b
        for b in page.blocks
        if (
            kind is None or (b.marker is not None and b.marker.keys.get("kind") == kind)
        )
        and (lang is None or b.lang == lang)
    ]
    assert len(blocks) > index, f"{rel} has no such block"
    return blocks[index]


def _load(text: str):
    document = yaml.safe_load(text)
    if isinstance(document, dict) and True in document:
        document["on"] = document.pop(True)
    return document


def _context(runner: str, wheel: Path, **extra):
    install_spec = _api("rewrite", "install_spec")
    context = _api("rewrite", "RewriteContext")
    return context(
        runner=runner,
        install_spec=install_spec(
            runner,
            wheel=wheel,
            wheel_sha256=WHEEL_SHA256,
            head_sha=HEAD,
            repository=REPOSITORY,
        ),
        head_sha=HEAD,
        repository=REPOSITORY,
        version=_version(),
        images=extra.pop("images", {}),
        built_images=frozenset(extra.pop("built_images", ())),
        report_mount=extra.pop("report_mount", None),
    )


def _applied(result, rule: str) -> list:
    return [a for a in result.applied if a.rule == rule]


def _count(result, rule: str) -> int:
    return sum(a.count for a in _applied(result, rule))


def _assert_literal(result) -> None:
    for applied in result.applied:
        if applied.rule in ("install", "reusable-workflow", "ash-version", "image"):
            for word in NOT_LITERAL:
                assert word not in applied.new, (
                    f"the {applied.rule} rewrite writes {applied.new!r}, which holds "
                    f"{word}; every value it writes is literal"
                )


#: Where the runner job builds the wheel. A POSIX path on every host the unit tests run
#: on: the runners are Linux.
WHEEL = PurePosixPath(
    "/home/runner/work/_temp/ash-wheel/automated_security_helper-0-py3-none-any.whl"
)
#: WHEEL's file URI, written out rather than computed by the code under test.
WHEEL_URI = "file:///home/runner/work/_temp/ash-wheel/automated_security_helper-0-py3-none-any.whl"


# ---------------------------------------------------------------------------
# The primitive: an exact replacement with an expected count
# ---------------------------------------------------------------------------


def test_replace_exact_replaces_exactly_the_expected_count():
    replace_exact = _api("rewrite", "replace_exact")
    assert replace_exact("a b a", "a", "c", count=2, where="page.md:12") == "c b c"


@pytest.mark.parametrize(
    "text,count,found", [("a b a", 1, 2), ("b b", 1, 0), ("b b", 0, 0)]
)
def test_replace_exact_refuses_any_other_count_and_names_the_block(text, count, found):
    replace_exact = _api("rewrite", "replace_exact")
    error = _api("rewrite", "RewriteError")
    assert issubclass(error, ValueError)
    with pytest.raises(error) as raised:
        replace_exact(text, "a", "c", count=count, where="docs/page.md:12")
    message = str(raised.value)
    assert "docs/page.md:12" in message and f"found {found}" in message, message


# ---------------------------------------------------------------------------
# What an install line becomes, per runner
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "runner,expected",
    [
        ("act", WHEEL_URI + "#sha256=" + WHEEL_SHA256),
        ("jenkinsfile-runner-lts", WHEEL_URI + "#sha256=" + WHEEL_SHA256),
        ("jenkinsfile-runner-bundled", WHEEL_URI + "#sha256=" + WHEEL_SHA256),
        ("gitlab-ci-local", f"file:///ash-wheel/{WHEEL.name}#sha256={WHEEL_SHA256}"),
        ("circleci", f"file:///ash-wheel/{WHEEL.name}#sha256={WHEEL_SHA256}"),
        ("codebuild-agent", f"git+https://github.com/{REPOSITORY}.git@{HEAD}"),
    ],
)
def test_install_spec_names_the_ash_under_test(runner, expected):
    install_spec = _api("rewrite", "install_spec")
    got = install_spec(
        runner,
        wheel=WHEEL,
        wheel_sha256=WHEEL_SHA256,
        head_sha=HEAD,
        repository=REPOSITORY,
    )
    assert got == f"automated-security-helper[cdk] @ {expected}"
    assert _api("rewrite", "WHEEL_MOUNT") == "/ash-wheel"


@pytest.mark.parametrize(
    "change",
    [
        {"runner": "azure-pipelines"},
        {"wheel": PurePosixPath("dist/x.whl")},
        {"wheel": PurePosixPath("~/dist/x.whl")},
        {"wheel": PurePosixPath("/home/runner/$RUNNER_TEMP/x.whl")},
        {"wheel_sha256": "D" * 64},
        {"head_sha": HEAD[:12]},
        {"repository": "automated-security-helper"},
    ],
    ids=[
        "unknown runner",
        "relative wheel",
        "tilde",
        "variable",
        "upper hex",
        "short sha",
        "no owner",
    ],
)
def test_install_spec_refuses_anything_that_is_not_literal_and_exact(change):
    install_spec = _api("rewrite", "install_spec")
    error = _api("rewrite", "RewriteError")
    args = {
        "runner": "act",
        "wheel": WHEEL,
        "wheel_sha256": WHEEL_SHA256,
        "head_sha": HEAD,
        "repository": REPOSITORY,
        **change,
    }
    runner = args.pop("runner")
    with pytest.raises(error):
        install_spec(runner, **args)


# ---------------------------------------------------------------------------
# The real pages' pipelines
# ---------------------------------------------------------------------------


def test_github_plain_steps_job_installs_the_wheel_and_records_provenance():
    block = _block(
        "docs/content/how-to/ci/github-actions.md", "github-actions", index=1
    )
    rewrite = _api("rewrite", "rewrite_pipeline")
    begin = _api("provenance", "PROVENANCE_BEGIN")
    end = _api("provenance", "PROVENANCE_END")
    context = _context("act", WHEEL)
    result = rewrite("github-actions", block.body, context, where="github-actions.md:4")
    assert [(a.old, a.new, a.count) for a in _applied(result, "install")] == [
        (_release_spec(), context.install_spec, 1)
    ]
    _assert_literal(result)
    document = _load(result.text)
    job = document["jobs"]["ash"]
    assert job["env"]["INSTALL_SPEC"] == context.install_spec
    names = [step.get("name") for step in job["steps"]]
    install, scan = names.index("Install ASH"), names.index("Run ASH")
    printing = [
        index
        for index, step in enumerate(job["steps"])
        if begin in str(step.get("run", "")) and end in str(step.get("run", ""))
    ]
    assert len(printing) == 1 and install <= printing[0] < scan, (
        "one step, at or right after the install and before the scan, prints the "
        f"install's direct_url.json between the markers; steps: {names}"
    )
    run = job["steps"][printing[0]]["run"]
    assert "direct_url.json" in run
    if printing[0] == install:
        assert run.index("uv tool install") < run.index(begin)
    assert _count(result, "provenance") == 1


def test_github_reusable_workflow_calls_run_the_pull_requests_workflows():
    first = _block("docs/content/getting-started/ci.md", "github-actions", index=0)
    second = _block("docs/content/getting-started/ci.md", "github-actions", index=1)
    text = first.body.rstrip("\n") + "\n" + second.body  # "a second job under jobs:"
    rewrite = _api("rewrite", "rewrite_pipeline")
    result = rewrite("github-actions", text, _context("act", WHEEL), where="ci.md:1+2")
    jobs = _load(result.text)["jobs"]
    assert jobs["ash"]["uses"] == "./.github/workflows/run-ash-security-scan.yml"
    assert jobs["sarif"]["uses"] == "./.github/workflows/upload-ash-sarif.yml"
    assert jobs["ash"]["with"]["ash-version"] == HEAD
    assert jobs["ash"]["with"]["ash-repo"] == REPOSITORY
    assert "ash-version" not in (jobs["sarif"].get("with") or {})
    assert _count(result, "reusable-workflow") == 2
    assert _count(result, "ash-version") == 1
    _assert_literal(result)


def test_gitlab_pipeline_installs_the_mounted_wheel_on_pinned_images():
    block = _block("docs/content/how-to/ci/gitlab-ci.md", "gitlab-ci", index=0)
    rewrite = _api("rewrite", "rewrite_pipeline")
    begin = _api("provenance", "PROVENANCE_BEGIN")
    context = _context("gitlab-ci-local", WHEEL, images={"python:3.12": PY_DIGEST})
    result = rewrite("gitlab-ci", block.body, context, where="gitlab-ci.md:1")
    document = _load(result.text)
    assert document["ash-scan"]["variables"]["INSTALL_SPEC"] == (
        f"automated-security-helper[cdk] @ file:///ash-wheel/{WHEEL.name}"
        f"#sha256={WHEEL_SHA256}"
    )
    assert document["ash-scan"]["image"] == PY_DIGEST
    assert document["ash-gate"]["image"] == PY_DIGEST
    assert _count(result, "install") == 1 and _count(result, "image") == 2
    before = document["ash-scan"]["before_script"]
    installs = [i for i, line in enumerate(before) if "pip install" in str(line)]
    printing = [i for i, line in enumerate(before) if begin in str(line)]
    assert len(installs) == 1 and len(printing) == 1, before
    assert printing[0] > installs[0] or (
        printing[0] == installs[0]
        and str(before[installs[0]]).index("pip install")
        < str(before[installs[0]]).index(begin)
    )
    _assert_literal(result)


def test_gitlab_job_on_an_image_the_run_built_needs_no_install_line():
    block = _block("docs/content/how-to/ci/gitlab-ci.md", "gitlab-ci", index=1)
    rewrite = _api("rewrite", "rewrite_pipeline")
    context = _context("gitlab-ci-local", WHEEL, built_images={BUILT_IMAGE})
    result = rewrite("gitlab-ci", block.body, context, where="gitlab-ci.md:2")
    assert _load(result.text)["ash-scan"]["image"] == BUILT_IMAGE
    assert _applied(result, "install") == []


def test_gitlab_job_image_with_no_pin_is_refused():
    block = _block("docs/content/how-to/ci/gitlab-ci.md", "gitlab-ci", index=0)
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    with pytest.raises(error) as raised:
        rewrite(
            "gitlab-ci",
            block.body,
            _context("gitlab-ci-local", WHEEL),
            where="gitlab-ci.md:1",
        )
    assert "python:3.12" in str(raised.value) and "gitlab-ci.md:1" in str(raised.value)


def test_codebuild_buildspec_installs_the_head_commit_of_the_base_repository():
    block = _block("docs/content/how-to/ci/other-ci.md", "buildspec", index=0)
    rewrite = _api("rewrite", "rewrite_pipeline")
    context = _context("codebuild-agent", WHEEL)
    result = rewrite("buildspec", block.body, context, where="other-ci.md:codebuild")
    document = _load(result.text)
    assert document["env"]["variables"]["INSTALL_SPEC"] == (
        f"automated-security-helper[cdk] @ git+https://github.com/{REPOSITORY}.git@{HEAD}"
    )
    assert _count(result, "install") == 1
    _assert_literal(result)


def test_jenkinsfile_installs_the_wheel_from_its_path_on_the_host():
    block = _block("docs/content/how-to/ci/other-ci.md", lang="groovy", index=0)
    rewrite = _api("rewrite", "rewrite_pipeline")
    context = _context("jenkinsfile-runner-lts", WHEEL)
    result = rewrite("jenkinsfile", block.body, context, where="other-ci.md:jenkins")
    assert f"INSTALL_SPEC = '{context.install_spec}'" in result.text
    assert _release_spec() not in result.text
    assert _count(result, "install") == 1
    _assert_literal(result)


def _circleci_config() -> str:
    """The CircleCI block the docs carry, with the release spec built here."""
    return f"""\
version: 2.1
jobs:
  ash:
    docker:
      - image: cimg/python:3.12-node
    environment:
      INSTALL_SPEC: "{_release_spec()}"
    steps:
      - checkout
      - run:
          name: Install ASH and the scanner tools
          command: |
            python -m venv "$HOME/ash-venv"
            "$HOME/ash-venv/bin/pip" install --quiet "$INSTALL_SPEC"
      - run:
          name: Run ASH
          command: |
            export PATH="$HOME/ash-venv/bin:$PATH"
            ash scan --mode local --no-progress --fail-on-findings
      - store_test_results:
          path: .ash/ash_output/reports/ash.junit.xml
      - store_artifacts:
          path: .ash/ash_output
          destination: ash-output
workflows:
  ash:
    jobs:
      - ash
"""


def test_circleci_job_copies_its_reports_out_whatever_happened():
    rewrite = _api("rewrite", "rewrite_pipeline")
    original = yaml.safe_load(_circleci_config())
    context = _context(
        "circleci",
        WHEEL,
        images={"cimg/python:3.12-node": CIMG_DIGEST},
        report_mount="/ash-reports",
    )
    result = rewrite(
        "circleci", _circleci_config(), context, where="other-ci.md:circleci"
    )
    job = yaml.safe_load(result.text)["jobs"]["ash"]
    assert job["docker"] == [{"image": CIMG_DIGEST}]
    assert job["environment"]["INSTALL_SPEC"] == context.install_spec
    steps = job["steps"]
    page_steps = original["jobs"]["ash"]["steps"]
    assert steps[0] == "checkout"
    assert page_steps[2] in steps, "the scan step is kept as the page has it"
    assert [s for s in steps if isinstance(s, dict) and "run" not in s] == page_steps[
        3:
    ], "store_test_results and store_artifacts are kept, in order"
    last = steps[-1]["run"]
    assert last.get("when") == "always"
    assert ".ash/ash_output" in last["command"] and "/ash-reports" in last["command"]
    assert _count(result, "report-copy") == 1
    assert _count(result, "image") == 1 and _count(result, "install") == 1
    _assert_literal(result)


def test_a_block_with_no_install_form_is_an_error_naming_it():
    text = """\
on:
  pull_request:
jobs:
  ash:
    runs-on: ubuntu-latest
    steps:
      - run: pip install automated-security-helper
      - run: ash scan --mode local
"""
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    with pytest.raises(error) as raised:
        rewrite("github-actions", text, _context("act", WHEEL), where="page.md:7")
    assert "page.md:7" in str(raised.value)


# ---------------------------------------------------------------------------
# Where the head commit and the repository come from
# ---------------------------------------------------------------------------


def _event_env(
    tmp_path: Path, name: str, payload: dict | None, sha: str | None
) -> dict:
    environ = {"GITHUB_EVENT_NAME": name, "GITHUB_REPOSITORY": REPOSITORY}
    if payload is not None:
        path = tmp_path / "event.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        environ["GITHUB_EVENT_PATH"] = str(path)
    if sha is not None:
        environ["GITHUB_SHA"] = sha
    return environ


def test_head_sha_is_the_pull_requests_head_on_a_pull_request(tmp_path):
    head_sha = _api("rewrite", "head_sha")
    environ = _event_env(
        tmp_path, "pull_request", {"pull_request": {"head": {"sha": HEAD}}}, OTHER
    )
    assert head_sha(environ) == HEAD, (
        "never GITHUB_SHA, the merge commit, on a pull request"
    )


def test_head_sha_is_github_sha_on_workflow_dispatch(tmp_path):
    head_sha = _api("rewrite", "head_sha")
    assert (
        head_sha(_event_env(tmp_path, "workflow_dispatch", {"inputs": {}}, HEAD))
        == HEAD
    )


@pytest.mark.parametrize(
    "name,payload,sha",
    [
        ("pull_request", {"pull_request": {}}, HEAD),
        ("pull_request", None, HEAD),
        ("pull_request", {"pull_request": {"head": {"sha": "not-a-sha"}}}, HEAD),
        ("workflow_dispatch", {"inputs": {}}, None),
        ("workflow_dispatch", {"pull_request": {"head": {"sha": HEAD}}}, None),
        ("push", {"after": HEAD}, HEAD),
    ],
    ids=[
        "pull request without head sha",
        "pull request without event file",
        "pull request with a bad sha",
        "dispatch without GITHUB_SHA",
        "dispatch never reads the payload",
        "another event",
    ],
)
def test_head_sha_never_falls_back(tmp_path, name, payload, sha):
    head_sha = _api("rewrite", "head_sha")
    error = _api("rewrite", "RewriteError")
    with pytest.raises(error):
        head_sha(_event_env(tmp_path, name, payload, sha))


def test_base_repository_is_github_repository_and_nothing_else():
    base_repository = _api("rewrite", "base_repository")
    error = _api("rewrite", "RewriteError")
    assert base_repository({"GITHUB_REPOSITORY": REPOSITORY}) == REPOSITORY
    for environ in (
        {},
        {"GITHUB_REPOSITORY": ""},
        {"GITHUB_REPOSITORY": "a/b/c"},
        {"GITHUB_REPOSITORY": "a b/c"},
    ):
        with pytest.raises(error):
            base_repository(environ)


# ---------------------------------------------------------------------------
# The image GitLab's own-image example runs, built from the pull request
# ---------------------------------------------------------------------------


def _argv_value(argv: list[str], flag: str) -> list[str]:
    return [argv[i + 1] for i, word in enumerate(argv[:-1]) if word == flag]


@pytest.mark.parametrize(
    "base,repository",
    [
        (
            "public.ecr.aws/docker/library/python:3.12-slim-bookworm",
            "public.ecr.aws/docker/library/python",
        ),
        (
            "registry.example:5000/team/python:3.12",
            "registry.example:5000/team/python",
        ),
        (
            "public.ecr.aws/docker/library/python",
            "public.ecr.aws/docker/library/python",
        ),
    ],
    ids=["tag", "registry port and tag", "no tag"],
)
def test_the_ci_image_is_built_from_the_dockerfile_s_pinned_base_digest(
    tmp_path, base, repository
):
    build_argv = _api("rewrite", "ci_image_build_argv")
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        f"ARG BASE_IMAGE={base}\n"
        "ARG BASE_IMAGE_DIGEST=sha256:" + "a" * 64 + "\n"
        "FROM ${BASE_IMAGE} AS core\nFROM core AS ci\n",
        encoding="utf-8",
    )
    argv = build_argv(dockerfile, tag=BUILT_IMAGE)
    assert argv[:2] == ["docker", "build"]
    assert _argv_value(argv, "--target") == ["ci"]
    assert _argv_value(argv, "-t") == [BUILT_IMAGE]
    assert _argv_value(argv, "-f") == [str(dockerfile)]
    assert _argv_value(argv, "--build-arg") == [
        f"BASE_IMAGE={repository}@sha256:" + "a" * 64
    ]
    assert argv[-1] == str(tmp_path)


def test_the_real_dockerfile_s_base_is_built_by_digest():
    build_argv = _api("rewrite", "ci_image_build_argv")
    dockerfile = REPO_ROOT / "Dockerfile"
    defaults = _checks().dockerfile_arg_defaults(dockerfile.read_text(encoding="utf-8"))
    (base,) = defaults["BASE_IMAGE"]
    (digest,) = defaults["BASE_IMAGE_DIGEST"]
    # The reference carries the digest and no tag: the tag is dropped from the last
    # path component, so a registry port stays.
    path, slash, last = base.rpartition("/")
    repository = path + slash + last.partition(":")[0]
    argv = build_argv(dockerfile, tag=BUILT_IMAGE)
    assert _argv_value(argv, "--build-arg") == [f"BASE_IMAGE={repository}@{digest}"]


def test_a_dockerfile_without_a_base_digest_is_refused(tmp_path):
    build_argv = _api("rewrite", "ci_image_build_argv")
    error = _api("rewrite", "RewriteError")
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "ARG BASE_IMAGE=python:3.12\nFROM ${BASE_IMAGE}\n", encoding="utf-8"
    )
    with pytest.raises(error):
        build_argv(dockerfile, tag=BUILT_IMAGE)


# ---------------------------------------------------------------------------
# Every real block, with the counts its rewrite has, and the job of each print
# ---------------------------------------------------------------------------


def _real_block(name: str):
    """(kind, pipeline text, context) for each real block the rewrites run on."""
    gha = "docs/content/how-to/ci/github-actions.md"
    if name == "getting-started/ci.md #1 + #2":
        first = _block("docs/content/getting-started/ci.md", "github-actions", index=0)
        second = _block("docs/content/getting-started/ci.md", "github-actions", index=1)
        text = first.body.rstrip("\n") + "\n" + second.body
        return "github-actions", text, _context("act", WHEEL)
    if name == "how-to/ci/github-actions.md #3":
        return (
            "github-actions",
            _block(gha, "github-actions", index=0).body,
            _context("act", WHEEL),
        )
    if name == "how-to/ci/github-actions.md #4":
        return (
            "github-actions",
            _block(gha, "github-actions", index=1).body,
            _context("act", WHEEL),
        )
    if name == "how-to/scale-large-repos.md":
        block = _block("docs/content/how-to/scale-large-repos.md", "github-actions")
        return "github-actions", block.body, _context("act", WHEEL)
    if name == "how-to/ci/gitlab-ci.md #9":
        block = _block("docs/content/how-to/ci/gitlab-ci.md", "gitlab-ci", index=0)
        context = _context("gitlab-ci-local", WHEEL, images={"python:3.12": PY_DIGEST})
        return "gitlab-ci", block.body, context
    if name == "how-to/ci/gitlab-ci.md #10":
        block = _block("docs/content/how-to/ci/gitlab-ci.md", "gitlab-ci", index=1)
        context = _context("gitlab-ci-local", WHEEL, built_images={BUILT_IMAGE})
        return "gitlab-ci", block.body, context
    if name == "how-to/ci/other-ci.md Jenkinsfile":
        block = _block("docs/content/how-to/ci/other-ci.md", lang="groovy", index=0)
        return "jenkinsfile", block.body, _context("jenkinsfile-runner-lts", WHEEL)
    if name == "how-to/ci/other-ci.md buildspec":
        block = _block("docs/content/how-to/ci/other-ci.md", "buildspec", index=0)
        return "buildspec", block.body, _context("codebuild-agent", WHEEL)
    assert name == "CircleCI"
    context = _context(
        "circleci",
        WHEEL,
        images={"cimg/python:3.12-node": CIMG_DIGEST},
        report_mount="/ash-reports",
    )
    return "circleci", _circleci_config(), context


#: Per block: the count of each rule, and (job, whether it has a matrix) for each
#: provenance print, in pipeline order.
REAL_BLOCK_COUNTS = {
    "getting-started/ci.md #1 + #2": ({"reusable-workflow": 2, "ash-version": 1}, []),
    "how-to/ci/github-actions.md #3": ({"reusable-workflow": 2, "ash-version": 1}, []),
    "how-to/ci/github-actions.md #4": (
        {"install": 1, "artifact-actions": 1, "provenance": 1},
        [("ash", False)],
    ),
    "how-to/scale-large-repos.md": (
        # Three artifact steps: the shard upload, the merge job's download and its
        # upload of the merged output.
        {"install": 1, "artifact-actions": 3, "serial-matrix": 1, "provenance": 2},
        [("shard", True), ("merge", False)],
    ),
    "how-to/ci/gitlab-ci.md #9": (
        {"install": 1, "image": 2, "provenance": 1},
        [("ash-scan", False)],
    ),
    "how-to/ci/gitlab-ci.md #10": ({"built-provenance": 1}, []),
    "how-to/ci/other-ci.md Jenkinsfile": (
        {"install": 1, "provenance": 1},
        [(None, False)],
    ),
    "how-to/ci/other-ci.md buildspec": (
        {"install": 1, "provenance": 1},
        [(None, False)],
    ),
    "CircleCI": (
        {"install": 1, "image": 1, "provenance": 1, "report-copy": 1},
        [("ash", False)],
    ),
}


@pytest.mark.parametrize("name", list(REAL_BLOCK_COUNTS))
def test_each_real_block_rewrites_with_its_expected_counts(name):
    rewrite = _api("rewrite", "rewrite_pipeline")
    kind, text, context = _real_block(name)
    result = rewrite(kind, text, context, where=name)
    counts: dict[str, int] = {}
    for applied in result.applied:
        counts[applied.rule] = counts.get(applied.rule, 0) + applied.count
    expected_counts, expected_prints = REAL_BLOCK_COUNTS[name]
    assert counts == expected_counts
    prints = [
        (applied.job, applied.matrix)
        for applied in _applied(result, "provenance")
        for _ in range(applied.count)
    ]
    assert prints == expected_prints
    _assert_literal(result)


# ---------------------------------------------------------------------------
# What act 0.2.89 cannot run: the current artifact actions and a parallel matrix
# ---------------------------------------------------------------------------

#: The pinned releases the act rewrite writes, spelled out here rather than imported.
UPLOAD_V4 = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
DOWNLOAD_V4 = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
SCALE_PAGE = "docs/content/how-to/scale-large-repos.md"


def _scale_rewrite():
    block = _block(SCALE_PAGE, "github-actions")
    rewrite = _api("rewrite", "rewrite_pipeline")
    return block.body, rewrite(
        "github-actions", block.body, _context("act", WHEEL), where="scale.md:1"
    )


def test_act_runs_the_pages_artifact_steps_on_the_pinned_v4_actions():
    body, result = _scale_rewrite()
    # The page keeps naming the current releases for the people who use GitHub.
    assert "actions/upload-artifact@043fb46d" in body
    assert "actions/download-artifact@9000827c" in body
    assert result.original == body
    steps = [s for job in _load(result.text)["jobs"].values() for s in job["steps"]]
    upload = [s for s in steps if str(s.get("uses", "")).startswith("actions/upload-")]
    download = [s for s in steps if "download-artifact" in str(s.get("uses", ""))]
    # Two uploads (each shard's, and the merge job's of the merged output) and the
    # merge job's one download.
    assert [s["uses"] for s in upload] == [UPLOAD_V4, UPLOAD_V4]
    assert [s["uses"] for s in download] == [DOWNLOAD_V4]
    assert "# v4.6.2" in result.text and "# v4.3.0" in result.text
    # Each step keeps its inputs, which v4 reads as v7 and v8 do; the uploads pair
    # with the page's by artifact name.
    original = [
        s
        for job in _load(body)["jobs"].values()
        for s in job["steps"]
        if "-artifact@" in str(s.get("uses", ""))
    ]
    uploads_by_name = {
        s["with"]["name"]: s for s in original if "upload-artifact@" in s["uses"]
    }
    assert sorted(uploads_by_name) == ["ash-merged", "ash-shard-${{ matrix.shard }}"]
    for step in upload:
        assert step["with"] == uploads_by_name[step["with"]["name"]]["with"]
        assert step["if"] == uploads_by_name[step["with"]["name"]]["if"]
    (original_download,) = [s for s in original if "download-artifact@" in s["uses"]]
    assert download[0]["with"] == original_download["with"]
    # The two upload lines are the same release, so the rewrite records them as one
    # change made twice.
    assert {
        (a.old.split("@")[0], a.count) for a in _applied(result, "artifact-actions")
    } == {("actions/upload-artifact", 2), ("actions/download-artifact", 1)}


def test_act_runs_the_pages_matrix_one_entry_at_a_time():
    body, result = _scale_rewrite()
    jobs = _load(result.text)["jobs"]
    strategy = jobs["shard"]["strategy"]
    assert strategy["max-parallel"] == 1
    assert strategy["matrix"] == _load(body)["jobs"]["shard"]["strategy"]["matrix"]
    assert strategy["fail-fast"] is False
    assert "strategy" not in jobs["merge"]
    assert "act issue 6028" in result.text
    assert _count(result, "serial-matrix") == 1


def test_the_artifact_and_matrix_rewrites_change_nothing_a_second_time():
    _, result = _scale_rewrite()
    artifacts = _api("rewrite", "_rewrite_artifact_actions")
    matrices = _api("rewrite", "_serialize_matrices")
    again: list = []
    text = artifacts(result.text, "scale.md:1", again)
    text = matrices(text, "scale.md:1", again)
    assert text == result.text and again == []


def test_an_existing_max_parallel_is_set_to_one_and_only_on_a_matrix():
    matrices = _api("rewrite", "_serialize_matrices")
    text = (
        "jobs:\n"
        "  a:\n"
        "    strategy:\n"
        "      max-parallel: 4  # as the page has it\n"
        "      matrix:\n"
        "        n: [1, 2]\n"
        "    steps: []\n"
        "  b:\n"
        "    strategy:\n"
        "      fail-fast: false\n"
        "    steps: []\n"
    )
    applied: list = []
    jobs = _load(matrices(text, "page.md:3", applied))["jobs"]
    assert jobs["a"]["strategy"]["max-parallel"] == 1
    assert "max-parallel" not in jobs["b"]["strategy"]
    assert sum(a.count for a in applied) == 1


@pytest.mark.parametrize(
    "old,count,new,named",
    [
        (
            # The shard job's upload and the merge job's: the first is the one quoted.
            "      - uses: actions/upload-artifact@043fb46d",
            2,
            '      - uses: "actions/upload-artifact@043fb46d',
            "actions/upload-artifact",
        ),
        (
            (
                "    strategy:\n      fail-fast: false\n      matrix:\n"
                "        shard: [0, 1, 2, 3]\n"
            ),
            1,
            "    strategy: {matrix: {shard: [0, 1, 2, 3]}}\n",
            "the job shard has a matrix",
        ),
    ],
    ids=["a quoted uses", "a flow-style strategy"],
)
def test_an_artifact_step_or_matrix_the_rewrite_cannot_read_is_refused(
    old, count, new, named
):
    body = _block(SCALE_PAGE, "github-actions").body
    assert body.count(old) == count
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    with pytest.raises(error) as raised:
        rewrite(
            "github-actions",
            body.replace(old, new, 1),
            _context("act", WHEEL),
            where="scale.md:1",
        )
    message = str(raised.value)
    assert "scale.md:1" in message and named in message, message


# ---------------------------------------------------------------------------
# A second source of ASH, beside the rewritten install, is refused
# ---------------------------------------------------------------------------


def _with_step(run: str, env: str = "") -> str:
    """A job that installs INSTALL_SPEC, then runs ``run``, then scans."""
    return (
        "on:\n  pull_request:\njobs:\n  ash:\n    runs-on: ubuntu-latest\n"
        f'    env:\n      INSTALL_SPEC: "{_release_spec()}"\n{env}'
        "    steps:\n"
        "      - name: Install ASH\n"
        '        run: uv tool install "${INSTALL_SPEC}"\n'
        "      - name: Another step\n"
        f"        run: |\n          {run}\n"
        "      - name: Run ASH\n"
        "        run: ash scan --mode local\n"
    )


def _release_archive(suffix: str) -> str:
    return f"https://github.com/{REPOSITORY}/archive/refs/tags/v{_version()}.{suffix}"


@pytest.mark.parametrize(
    "run,env,named",
    [
        (
            "pip install --upgrade automated-security-helper",
            "",
            "pip install --upgrade",
        ),
        (
            "uv tool install --force automated-security-helper",
            "",
            "uv tool install --force",
        ),
        ("uvx --from automated-security-helper ash scan", "", "uvx --from"),
        ("pipx install automated-security-helper", "", "pipx install"),
        ("python -m pip install automated_security_helper", "", "python -m pip"),
        ("uv pip install --system automated-security-helper", "", "uv pip install"),
        (None, "", "archive/refs/tags"),
        (
            f"pip install git+https://github.com/{REPOSITORY}",
            "",
            f"git+https://github.com/{REPOSITORY}",
        ),
        ("pip install -r requirements.txt", "", "-r requirements.txt"),
        ('pip install "$ASH_ZIP"', None, "archive/refs/tags"),
    ],
    ids=[
        "pip upgrade from the index",
        "uv tool install from the index",
        "uvx from the index",
        "pipx from the index",
        "python -m pip from the index",
        "uv pip from the index",
        "a release tarball",
        "git without a ref",
        "a requirements file",
        "a second variable naming a release archive",
    ],
)
def test_a_second_source_of_ash_is_refused_by_line(run, env, named):
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    if run is None:
        run = "pip install " + _release_archive("tar.gz")
    if env is None:
        env = f"      ASH_ZIP: {_release_archive('zip')}\n"
    with pytest.raises(error) as raised:
        rewrite(
            "github-actions",
            _with_step(run, env),
            _context("act", WHEEL),
            where="page.md:9",
        )
    message = str(raised.value)
    assert "page.md:9" in message and named in message, message


@pytest.mark.parametrize(
    "run",
    [
        'uv tool dir --bin >> "${GITHUB_PATH}"',
        '"$(uv tool dir --bin)/ash" dependencies install --tool grype',
        "cp -r .ash/ash_output reports && echo automated-security-helper",
        'uv tool install "${INSTALL_SPEC}" && cp -r .ash/ash_output reports',
        'uv tool install --force --quiet "${INSTALL_SPEC}"',
        '"$HOME/ash-venv/bin/pip" install -qU --no-deps "$INSTALL_SPEC"',
    ],
)
def test_a_line_that_installs_no_other_ash_is_kept(run):
    rewrite = _api("rewrite", "rewrite_pipeline")
    result = rewrite(
        "github-actions", _with_step(run), _context("act", WHEEL), where="page.md:9"
    )
    assert run in result.text


@pytest.mark.parametrize(
    "line",
    [
        f"  other:\n    uses: {REPOSITORY}/.github/workflows/upload-ash-sarif.yml@main\n",
        f"  other:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: {REPOSITORY}@v1\n",
    ],
    ids=["a workflow at another ref", "an action at a ref"],
)
def test_a_release_reference_left_after_the_rewrite_is_refused(line):
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    with pytest.raises(error) as raised:
        rewrite(
            "github-actions",
            _with_step("echo ok") + line,
            _context("act", WHEEL),
            where="page.md:9",
        )
    assert "page.md:9" in str(raised.value)


def test_a_scan_workflow_call_without_ash_version_is_refused():
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    text = (
        "on:\n  pull_request:\njobs:\n  ash:\n    uses: "
        f"{REPOSITORY}/.github/workflows/run-ash-security-scan.yml@v{_version()}\n"
    )
    with pytest.raises(error) as raised:
        rewrite("github-actions", text, _context("act", WHEEL), where="page.md:9")
    assert "page.md:9" in str(raised.value) and "ash-version" in str(raised.value)


def test_an_install_spec_no_command_installs_is_refused():
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    text = _with_step("echo ok").replace('uv tool install "${INSTALL_SPEC}"', "echo hi")
    with pytest.raises(error) as raised:
        rewrite("github-actions", text, _context("act", WHEEL), where="page.md:9")
    assert "page.md:9" in str(raised.value)


# ---------------------------------------------------------------------------
# An install the rewrites cannot follow is refused, never run against another ASH
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "run,named",
    [
        ("poetry add automated-security-helper", "poetry add"),
        ("poetry install --no-root", "poetry install"),
        ("pdm add automated-security-helper", "pdm add"),
        ("pipenv install automated-security-helper", "pipenv install"),
        ("conda install -y -c conda-forge automated-security-helper", "conda install"),
        ("uv sync --frozen", "uv sync"),
        ("uv run --with ruff ash scan --mode local", "uv run"),
        (
            '"$HOME/ash/bin/pip" install --quiet ash-plugin-example',
            "ash-plugin-example",
        ),
        ("pip install .", "pip install ."),
        (
            'uv tool install --with ash-plugin-example "${INSTALL_SPEC}"',
            "--with ash-plugin-example",
        ),
        ("INSTALL_SPEC=automated-security-helper==3.7.0", "INSTALL_SPEC="),
        (
            "brew install awslabs/automated-security-helper/ash",
            "runs brew, whose installs",
        ),
        ("brew install ash", "runs brew, whose installs"),
        (
            "/home/linuxbrew/.linuxbrew/bin/brew install ash",
            "runs brew, whose installs",
        ),
        ('echo "$(brew install ash)"', "runs brew, whose installs"),
        (
            'test -x "$(brew --prefix)/bin/ash" || brew install ash',
            "runs brew, whose installs",
        ),
        (
            'case "$RUNNER_OS" in macOS) brew install ash ;; esac',
            "runs brew, whose installs",
        ),
        ('"$(brew --prefix)/bin/pip3" install "$ASH_SRC"', "the rewrites follow only"),
        (
            '"$HOME"/ash-venv/bin/pip install ash-plugin-example',
            "the rewrites follow only",
        ),
        ("brew `echo install` ash", "runs brew, whose installs"),
        ("pip `echo install` ash-plugin-example", "cannot tell what"),
        ("uvx `echo ash` scan", "runs a tool uvx installs"),
        ("ASH_BIN=`brew install ash`", "runs brew, whose installs"),
        ("$(true) brew install ash", "runs brew, whose installs"),
        (
            "$(brew --prefix) pip install ash-plugin-example",
            "the rewrites follow only",
        ),
        (
            "# a note \\\n          pip install ash-plugin-example",
            "the rewrites follow only",
        ),
        ("pip --cache-dir list install ash-plugin-example", "the rewrites follow only"),
        ("pip --cach list install ash-plugin-example", "cannot tell what"),
        (
            "uv --cache-dir venv pip install ash-plugin-example",
            "the rewrites follow only",
        ),
        (
            "uv pip --cache-dir list install ash-plugin-example",
            "the rewrites follow only",
        ),
        ("pipx --index-url list install ash-plugin-example", "cannot tell what"),
        (
            "uv --preview-features venv pip install ash-plugin-example",
            "cannot tell what",
        ),
        ("true & pip install ash-plugin-example", "the rewrites follow only"),
        ("true |& pip install ash-plugin-example", "the rewrites follow only"),
        (
            "X='`' uv `true` tool install automated-security-helper==3.7.0",
            "the rewrites follow only",
        ),
        (
            "X=\"'\" Y='`' uv `true` tool install automated-security-helper==3.7.0",
            "the rewrites follow only",
        ),
        (
            "X=$'\\'`' uv `true` tool install automated-security-helper==3.7.0",
            "the rewrites follow only",
        ),
        (
            'exec >> "$GITHUB_ENV"\n          echo PIP_TARGET=/opt/other',
            INSTALLER_SETTING,
        ),
        (
            '"$HOME/ash-venv/bin/pip" --python /usr/bin/python3 install "$INSTALL_SPEC"',
            "--python, which is not one of its flags",
        ),
        (
            'uv --config-file f.toml tool install "${INSTALL_SPEC}"',
            "--config-file, which is not one of its flags",
        ),
        ("pip config set install.target /opt/other", "writes pip's configuration"),
        ("pip config unset install.target", "writes pip's configuration"),
        ("pip config --editor vi edit", "writes pip's configuration"),
        (
            '"$HOME/ash-venv/bin/pip" config --user set install.target /opt/other',
            "writes pip's configuration",
        ),
        (
            "python -m pip config set global.index-url https://example.com/simple",
            "writes pip's configuration",
        ),
    ],
    ids=[
        "poetry add",
        "poetry install of a project",
        "pdm add",
        "pipenv install",
        "conda install",
        "uv sync of a project",
        "uv run in a project",
        "pip install of another package",
        "pip install of the checkout",
        "another package beside the spec",
        "INSTALL_SPEC set again in a script",
        "Homebrew's formula from the tap install.md names",
        "Homebrew's formula by its short name",
        "Homebrew by its path",
        "Homebrew in a command substitution",
        "Homebrew after a read of its prefix",
        "Homebrew in a case branch",
        "pip by a path that starts with a command substitution",
        "pip by a path that starts with a quoted variable",
        "Homebrew with its subcommand in a backquote substitution",
        "pip with its subcommand in a backquote substitution",
        "uvx with its tool in a backquote substitution",
        "Homebrew inside a backquote substitution",
        "Homebrew after a command substitution in the command's place",
        "pip after a command substitution with an option in it",
        "pip after a comment line that ends in a backslash",
        "pip install after an option whose value is a pip command",
        "pip install after a shortened option",
        "uv pip install after a global option's value",
        "uv pip install after a global option inside the group",
        "pipx after an option it is not known to take",
        "uv pip install after a global option its help does not list",
        "pip after a background command",
        "pip after a pipe of both streams",
        "uv tool install after a backquote in single quotes",
        "uv tool install after a single quote in double quotes",
        "uv tool install after an escaped quote in $'...'",
        "a pip setting printed into the env file",
        "the spec by pip after another interpreter given before install",
        "the spec by uv tool install after a settings file given before tool",
        "a pip setting written by pip config set",
        "a pip setting removed by pip config unset",
        "pip's configuration opened in an editor",
        "a pip setting written by the venv's pip after a config option",
        "a pip setting written by python -m pip",
    ],
)
def test_an_install_the_rewrites_cannot_follow_is_refused(run, named):
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    with pytest.raises(error) as raised:
        rewrite(
            "github-actions", _with_step(run), _context("act", WHEEL), where="page.md:9"
        )
    message = str(raised.value)
    assert "page.md:9" in message and named in message, message


def test_an_install_spec_set_again_for_one_step_is_refused():
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    text = _with_step("echo ok").replace(
        "      - name: Install ASH\n",
        "      - name: Install ASH\n"
        "        env:\n"
        "          INSTALL_SPEC: automated-security-helper==3.7.0\n",
    )
    with pytest.raises(error) as raised:
        rewrite("github-actions", text, _context("act", WHEEL), where="page.md:9")
    message = str(raised.value)
    assert "page.md:9" in message and "automated-security-helper==3.7.0" in message


@pytest.mark.parametrize(
    "run",
    [
        'python3 -m venv "$HOME/ash-venv"',
        "uv --version",
        "uv tool list",
        'echo "pip, poetry and conda are not used here"',
        "sudo apt-get install -y --no-install-recommends ruby-dev",
        "brew --version",
        'echo "or run brew install ash"',
        'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"',
        '"$(brew --prefix)/bin/ash" scan --mode local',
        "brew --prefix ash",
        "brew config",
        "brew list --versions",
        "brew info ash",
        'echo "(optional) brew install ash"',
        "echo $(date) pip install x",
        "`brew --prefix`/bin/ash scan --mode local",
        "brew info `echo ash`",
        "uv --quiet tool --offline list",
        'uv -qn --cache-dir "$RUNNER_TEMP/uv-cache" cache dir',
        'pip --disable-pip-version-check --cache-dir "$RUNNER_TEMP/pip-cache" list',
        'uv --cache-dir "$RUNNER_TEMP/uv-cache" --version',
        "echo 2>&1 pip install ash-plugin-example",
        'echo "PIP_TARGET and UV_OVERRIDE are not set here"',
        "echo 'pip install ash-plugin-example'",
        "bash -c 'echo pip install ash-plugin-example'",
        'echo "eval pip install ash-plugin-example"',
        "eval " * 8 + "echo ok",
        "pip config list",
        "pip config --user get install.target",
        "pip config debug",
    ],
)
def test_a_command_that_installs_no_python_package_is_kept(run):
    rewrite = _api("rewrite", "rewrite_pipeline")
    result = rewrite(
        "github-actions", _with_step(run), _context("act", WHEEL), where="page.md:9"
    )
    assert run in result.text


#: A second variable naming a release, which no check of an install line reads.
ASH_SRC_ENV = "      ASH_SRC: automated-security-helper==3.7.0\n"


@pytest.mark.parametrize(
    "run,env,refusal",
    [
        (
            'pipx run --spec "$ASH_SRC" ash scan',
            ASH_SRC_ENV,
            "installs or runs a package with pipx",
        ),
        (
            '"$HOME/v/bin/pip" install "$INSTALL_SPEC" -rreq.txt',
            "",
            "installs from a requirements file",
        ),
        (
            '"$HOME/v/bin/pip" install "$INSTALL_SPEC" --requirement=req.txt',
            "",
            "installs from a requirements file",
        ),
        (
            'uv tool install --from=automated-security-helper==3.7.0 "${INSTALL_SPEC}"',
            "",
            "installs ASH from somewhere other than the rewritten install spec",
        ),
        (
            'uv tool install --from="$ASH_SRC" "${INSTALL_SPEC}"',
            ASH_SRC_ENV,
            "the rewrites follow only",
        ),
        (
            'uv tool install --with=ash-plugin-example "${INSTALL_SPEC}"',
            "",
            "the rewrites follow only",
        ),
        ('python -m pip install "$ASH_SRC"', ASH_SRC_ENV, "the rewrites follow only"),
        (
            '"$HOME/ash-venv/bin/pip" install --python=/usr/bin/python3 "$INSTALL_SPEC"',
            "",
            "which is not one of its flags",
        ),
        (
            'uv tool install --config-file=f.toml "${INSTALL_SPEC}"',
            "",
            "which is not one of its flags",
        ),
        (
            'uv tool install --overrides=overrides.txt "${INSTALL_SPEC}"',
            "",
            "which is not one of its flags",
        ),
        (
            '"$HOME/ash-venv/bin/pip" install --target=/opt/other "$INSTALL_SPEC"',
            "",
            "which is not one of its flags",
        ),
        (
            '"$HOME/ash-venv/bin/pip" install -t/opt/other "$INSTALL_SPEC"',
            "",
            "which is not one of its flags",
        ),
        (
            '"$HOME/ash-venv/bin/pip" install --target --quiet "$INSTALL_SPEC"',
            "",
            "which is not one of its flags",
        ),
        (
            'uv tool install -cconstraints.txt "${INSTALL_SPEC}"',
            "",
            "which is not one of its flags",
        ),
        (
            '"$HOME/ash-venv/bin/pip" install "$INSTALL_SPEC" ash-plugin-example',
            "",
            "installs Python packages, and the rewrites follow only",
        ),
        (
            '"$HOME/ash-venv/bin/pip" install $INSTALL_SPEC',
            "",
            "installs Python packages, and the rewrites follow only",
        ),
        (
            'UV_OVERRIDE=overrides.txt uv tool install "${INSTALL_SPEC}"',
            "",
            INSTALLER_SETTING,
        ),
        (
            'env UV_CONSTRAINT=constraints.txt uv tool install "${INSTALL_SPEC}"',
            "",
            INSTALLER_SETTING,
        ),
        (
            'PIP_TARGET=/opt/other "$HOME/ash-venv/bin/pip" install "$INSTALL_SPEC"',
            "",
            INSTALLER_SETTING,
        ),
        (
            (
                'PIP_CONSTRAINT=constraints.txt "$HOME/ash-venv/bin/pip" install '
                '"$INSTALL_SPEC"'
            ),
            "",
            INSTALLER_SETTING,
        ),
        ("export PIP_TARGET=/opt/other", "", INSTALLER_SETTING),
        (
            'timeout 5m uv tool install --overrides overrides.txt "${INSTALL_SPEC}"',
            "",
            "which is not one of its flags",
        ),
        (
            (
                'timeout 5m "$HOME/ash-venv/bin/pip" install --target=/opt/other '
                '"$INSTALL_SPEC"'
            ),
            "",
            "which is not one of its flags",
        ),
    ],
    ids=[
        "pipx run of a spec in another variable",
        "a requirements file joined to -r",
        "a requirements file after --requirement=",
        "ASH named in --from=",
        "a variable in --from=",
        "another package in --with=",
        "python -m pip of a spec in another variable",
        "another interpreter after --python=",
        "a settings file after --config-file=",
        "an overrides file after --overrides=",
        "another directory after --target=",
        "another directory joined to -t",
        "a flag taken as the value of --target",
        "a constraints file joined to -c",
        "another package after the spec",
        "the spec unquoted, which the print does not find",
        "a uv overrides file set before uv tool install",
        "a uv constraints file set by env before uv tool install",
        "a pip target directory set before pip install",
        "a pip constraints file set before pip install",
        "a pip target directory exported",
        "options after timeout and its duration",
        "pip options after timeout and its duration",
    ],
)
def test_an_install_only_one_check_reads_is_refused_by_that_check(run, env, refusal):
    """Each input gets past every other check, so the message names the one that
    refused it, and the input is accepted if that check is gone."""
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    with pytest.raises(error) as raised:
        rewrite(
            "github-actions",
            _with_step(run, env),
            _context("act", WHEEL),
            where="page.md:9",
        )
    message = str(raised.value)
    assert "page.md:9" in message and run in message and refusal in message, message


# ---------------------------------------------------------------------------
# A script is read as bash reads it
# ---------------------------------------------------------------------------


def _script(*lines: str) -> str:
    """``lines`` as one ``run`` of _with_step: each line after the first indented as
    the block scalar's first line is, so the script holds them as given."""
    return "\n          ".join(lines)


@pytest.mark.parametrize(
    "run,named",
    [
        ('X="a b" pip install ash-plugin-example', "the rewrites follow only"),
        ("X='a b' pip install ash-plugin-example", "the rewrites follow only"),
        ('X="a;b" pip install ash-plugin-example', "the rewrites follow only"),
        (
            'X="a b" uv tool install --overrides overrides.txt "${INSTALL_SPEC}"',
            "which is not one of its flags",
        ),
        (
            'pip --cache-dir "c list" install git+https://github.com/someone/fork.git',
            "--cache-dir, which is not one of its flags",
        ),
        (
            'uv --cache-dir "c venv" pip install --system ash-plugin-example',
            "the rewrites follow only",
        ),
        ('eval "pip install ash-plugin-example"', "the rewrites follow only"),
        ("bash -c 'pip install ash-plugin-example'", "the rewrites follow only"),
        (
            'sh -ec "cd /tmp && pip install ash-plugin-example"',
            "the rewrites follow only",
        ),
        (
            "find . -name x -exec sh -c 'pip install ash-plugin-example' \\;",
            "the rewrites follow only",
        ),
        ("eval " * 9 + "echo ok", "runs a script nested too deep to read"),
    ],
    ids=[
        "pip after an assignment whose double-quoted value holds a blank",
        "pip after an assignment whose single-quoted value holds a blank",
        "pip after an assignment whose quoted value holds a semicolon",
        "uv tool install options after an assignment with a quoted blank",
        "pip install after a quoted option value that holds a pip command",
        "uv pip install after a quoted option value that holds a uv command",
        "pip in the script eval runs",
        "pip in a shell's -c script",
        "pip after && in a shell's -c script",
        "pip in the -c script of a shell find runs",
        "a script nested deeper than the checks read",
    ],
)
def test_a_command_is_read_as_bash_splits_it_into_words(run, named):
    """A quoted string is one word, whatever it holds, so ``X="a b"`` is an assignment
    and ``--cache-dir "c list"`` is one option with its value; and the script eval or
    a shell's -c runs is read as commands of its own, eight deep, and refused deeper
    (the kept eight-deep script is among the kept commands)."""
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    with pytest.raises(error) as raised:
        rewrite(
            "github-actions", _with_step(run), _context("act", WHEEL), where="page.md:9"
        )
    message = str(raised.value)
    assert "page.md:9" in message and named in message, message


#: Lines a backslash continues, each pair refused once read joined, with the
#: refusal it gets.
CONTINUED_LINES = {
    "an option's value on the next line": (
        ("pip --cache-dir \\", "  list install ash-plugin-example"),
        "--cache-dir, which is not one of its flags",
    ),
    "an untagged image of ASH run on the next line": (
        ("docker \\", "  run ghcr.io/awslabs/automated-security-helper"),
        "is an image of ASH named with no tag",
    ),
    "a pip setting's name split over the lines": (
        ("export PIP_\\", "TARGET=/opt/other"),
        INSTALLER_SETTING,
    ),
    "ASH named on the next line": (
        ("uv \\", "  tool install automated-security-helper==3.7.0"),
        "installs ASH from somewhere other than the rewritten install spec",
    ),
}


def _continued(where: str, lines: tuple[str, ...]):
    """A pipeline that runs ``lines`` ``where``: (kind, text, context)."""
    if where == "a step's script":
        return "github-actions", _with_step(_script(*lines)), _context("act", WHEEL)
    if where.startswith("after a here-document"):
        start = "cat <<'EOF'" if "quoted" in where else "cat <<EOF"
        run = _script(start, "it's", "EOF", *lines)
        return "github-actions", _with_step(run), _context("act", WHEEL)
    anchor = '"$WORKSPACE_TMP/ash/bin/pip" install --quiet "$INSTALL_SPEC"\n'
    text = _jenkinsfile()
    assert text.count(anchor) == 1, "the page's Jenkinsfile installs from its venv"
    text = text.replace(anchor, anchor + "".join(f"{line}\n" for line in lines))
    return "jenkinsfile", text, _context("jenkinsfile-runner-lts", WHEEL)


@pytest.mark.parametrize(
    "where",
    [
        "a step's script",
        "after a here-document holding an apostrophe",
        "after a here-document with a quoted delimiter holding an apostrophe",
        "in a Jenkinsfile's sh ''' script",
    ],
)
@pytest.mark.parametrize("case", list(CONTINUED_LINES))
def test_lines_a_backslash_continues_are_read_joined(where, case):
    """bash joins a line that ends in a backslash outside single quotes with the next,
    and Groovy does the same in a ``'''`` string, so every check reads the two as one:
    after a here-document, whose lines open no quote whatever they hold, and in a
    Jenkinsfile's sh script, which is read as the script it is rather than as a quote
    in the Groovy text. The lines in a step's script are the control."""
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    lines, named = CONTINUED_LINES[case]
    kind, text, context = _continued(where, lines)
    with pytest.raises(error) as raised:
        rewrite(kind, text, context, where="page.md:9")
    message = str(raised.value)
    assert "page.md:9" in message and named in message, message


def _gitlab_ci() -> str:
    return _block("docs/content/how-to/ci/gitlab-ci.md", "gitlab-ci", index=0).body


class _TagsAsValues(yaml.SafeLoader):
    """A loader that reads a tagged sequence as the sequence it tags, to show a block
    is YAML apart from its tag."""


_TagsAsValues.add_multi_constructor(
    "!", lambda loader, _suffix, node: loader.construct_sequence(node)
)

#: A GitLab pipeline the plain safe loader cannot load: one holding a tag, and one
#: of two documents (a component's ``spec:`` header, then the pipeline).
UNLOADABLE_GITLAB = {
    "a tag": lambda text: (
        text.rstrip("\n")
        + "\n.setup:\n  script:\n    - echo setup\n"
        + ".with-setup:\n  script: !reference [.setup, script]\n"
    ),
    "a second document": lambda text: (
        "spec:\n  inputs:\n    stage:\n      default: test\n---\n" + text
    ),
}


@pytest.mark.parametrize("change", list(UNLOADABLE_GITLAB))
def test_a_gitlab_block_with_a_tag_or_two_documents_is_refused_before_the_run(change):
    """The rewrite loads a pipeline with PyYAML's plain safe loader, which takes no
    tag and one document, so it refuses such a block with an error naming it before
    anything runs: the run's checks, which read only the pipeline the rewrite wrote,
    never meet one, while the controls check reads one as YAML loads it
    (pipelines.runs_ash)."""
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    context = _context("gitlab-ci-local", WHEEL, images={"python:3.12": PY_DIGEST})
    plain = _gitlab_ci()
    assert rewrite("gitlab-ci", plain, context, where="page.md:9").applied
    text = UNLOADABLE_GITLAB[change](plain)
    assert list(yaml.load_all(text, Loader=_TagsAsValues)), "the block is YAML"
    with pytest.raises(error) as raised:
        rewrite("gitlab-ci", text, context, where="page.md:9")
    message = str(raised.value)
    assert "page.md:9" in message and "the pipeline does not parse" in message, message


def _buildspec() -> str:
    return _block("docs/content/how-to/ci/other-ci.md", "buildspec", index=0).body


def _jenkinsfile() -> str:
    return _block("docs/content/how-to/ci/other-ci.md", lang="groovy", index=0).body


#: A pipeline of each kind that sets a pip or uv setting in one of its env scopes:
#: (kind, text, context), the name it sets, built when the test runs.
SETTING_SCOPES = {
    "a workflow env": lambda: (
        "github-actions",
        _with_step("echo ok").replace(
            "jobs:\n", "env:\n  UV_OVERRIDE: overrides.txt\njobs:\n", 1
        ),
        _context("act", WHEEL),
        "UV_OVERRIDE",
    ),
    "a job env": lambda: (
        "github-actions",
        _with_step("echo ok", "      PIP_TARGET: /opt/other\n"),
        _context("act", WHEEL),
        "PIP_TARGET",
    ),
    "a step env": lambda: (
        "github-actions",
        _with_step("echo ok").replace(
            "      - name: Install ASH\n",
            "      - name: Install ASH\n        env:\n          UV_CONFIG_FILE: uv.toml\n",
        ),
        _context("act", WHEEL),
        "UV_CONFIG_FILE",
    ),
    "GitLab variables": lambda: (
        "gitlab-ci",
        _gitlab_ci().replace(
            "    INSTALL_SPEC: ", "    PIP_TARGET: /opt/other\n    INSTALL_SPEC: ", 1
        ),
        _context("gitlab-ci-local", WHEEL, images={"python:3.12": PY_DIGEST}),
        "PIP_TARGET",
    ),
    "a CircleCI environment": lambda: (
        "circleci",
        _circleci_config().replace(
            "      INSTALL_SPEC: ",
            "      UV_CONSTRAINT: constraints.txt\n      INSTALL_SPEC: ",
            1,
        ),
        _context(
            "circleci",
            WHEEL,
            images={"cimg/python:3.12-node": CIMG_DIGEST},
            report_mount="/ash-reports",
        ),
        "UV_CONSTRAINT",
    ),
    "buildspec env variables": lambda: (
        "buildspec",
        _buildspec().replace(
            "    INSTALL_SPEC: ",
            "    PIP_CONSTRAINT: constraints.txt\n    INSTALL_SPEC: ",
            1,
        ),
        _context("codebuild-agent", WHEEL),
        "PIP_CONSTRAINT",
    ),
    "a Jenkinsfile environment": lambda: (
        "jenkinsfile",
        _jenkinsfile().replace(
            "    INSTALL_SPEC = '",
            "    PIP_TARGET = '/opt/other'\n    INSTALL_SPEC = '",
            1,
        ),
        _context("jenkinsfile-runner-lts", WHEEL),
        "PIP_TARGET",
    ),
}


@pytest.mark.parametrize("scope", list(SETTING_SCOPES))
def test_a_pip_or_uv_setting_in_a_pipeline_scope_is_refused(scope):
    """pip reads every long option from a PIP_ variable (PIP_TARGET, PIP_CONSTRAINT)
    and uv reads UV_OVERRIDE, UV_CONSTRAINT and UV_CONFIG_FILE, so a pipeline that
    sets one could change where or what the followed install puts in place without
    an option on its line. The same pipeline without the setting is each kind's own
    test above."""
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    kind, text, context, name = SETTING_SCOPES[scope]()
    assert name in text, "the setting was written into the pipeline"
    with pytest.raises(error) as raised:
        rewrite(kind, text, context, where="page.md:9")
    message = str(raised.value)
    assert "page.md:9" in message and name in message, message
    assert INSTALLER_SETTING in message, message


# ---------------------------------------------------------------------------
# An image of ASH other than the one the run builds is refused
# ---------------------------------------------------------------------------

#: An image of ASH a page could name. It is never pulled: the rewrite refuses it.
ASH_IMAGE = "public.ecr.aws/aws-appsec/automated-security-helper"
ASH_IMAGE_PIN = ASH_IMAGE + "@sha256:" + "b" * 64


def _gitlab_with_job(image: str) -> str:
    """gitlab-ci.md's first pipeline, with one more job that runs on ``image``."""
    block = _block("docs/content/how-to/ci/gitlab-ci.md", "gitlab-ci", index=0)
    return (
        block.body.rstrip("\n")
        + f"\n\nash-other:\n  stage: test\n  image: {image}\n  script:\n"
        + "    - ash scan --mode local --no-progress\n"
    )


@pytest.mark.parametrize(
    "image",
    [
        f"{ASH_IMAGE}:v{_version()}",
        "registry.example.com/security/automated-security-helper:latest",
        ASH_IMAGE,
        ASH_IMAGE_PIN,
    ],
    ids=[
        "the release image by tag",
        "the built image's name under another tag",
        "an image of ASH with no tag",
        "an image of ASH by a digest the run did not build",
    ],
)
def test_a_gitlab_job_on_an_image_of_ash_the_run_did_not_build_is_refused(image):
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    context = _context(
        "gitlab-ci-local",
        WHEEL,
        images={"python:3.12": PY_DIGEST, image: ASH_IMAGE_PIN},
        built_images={BUILT_IMAGE},
    )
    with pytest.raises(error) as raised:
        rewrite("gitlab-ci", _gitlab_with_job(image), context, where="gitlab-ci.md:1")
    message = str(raised.value)
    assert "gitlab-ci.md:1" in message and image in message, message


def _github_with_job(job: str) -> str:
    """A pipeline that installs INSTALL_SPEC, with one more job."""
    return _with_step("echo ok") + "  other:\n    runs-on: ubuntu-latest\n" + job


@pytest.mark.parametrize(
    "job",
    [
        f"    container: {ASH_IMAGE}:v{_version()}\n    steps:\n      - run: ash scan\n",
        (
            f"    container:\n      image: {ASH_IMAGE}:v{_version()}\n"
            "    steps:\n      - run: ash scan\n"
        ),
        (
            f"    services:\n      ash:\n        image: {ASH_IMAGE}:v{_version()}\n"
            "    steps:\n      - run: echo ok\n"
        ),
        f"    steps:\n      - uses: docker://{ASH_IMAGE}:v{_version()}\n",
        (
            '    steps:\n      - run: >-\n          docker run --rm -v "$PWD:/src" '
            f"{ASH_IMAGE}:v{_version()} ash scan --mode local\n"
        ),
        f"    steps:\n      - run: docker run --rm {ASH_IMAGE} ash scan\n",
        (
            f"    env:\n      ASH_IMAGE: {ASH_IMAGE}:v{_version()}\n"
            '    steps:\n      - run: docker pull "$ASH_IMAGE"\n'
        ),
    ],
    ids=[
        "a job container by tag",
        "a job container's image by tag",
        "a service by tag",
        "a docker step by tag",
        "docker run by tag",
        "docker run with no tag",
        "a variable naming the image by tag",
    ],
)
def test_a_github_job_on_an_image_of_ash_is_refused(job):
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    with pytest.raises(error) as raised:
        rewrite(
            "github-actions",
            _github_with_job(job),
            _context("act", WHEEL),
            where="page.md:9",
        )
    message = str(raised.value)
    assert "page.md:9" in message and ASH_IMAGE in message, message


def test_a_jenkins_agent_on_an_image_of_ash_is_refused():
    block = _block("docs/content/how-to/ci/other-ci.md", lang="groovy", index=0)
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    image = f"{ASH_IMAGE}:v{_version()}"
    text = block.body.replace(
        "agent { label 'linux' }", f"agent {{ docker {{ image '{image}' }} }}"
    )
    assert image in text
    with pytest.raises(error) as raised:
        rewrite(
            "jenkinsfile",
            text,
            _context("jenkinsfile-runner-lts", WHEEL),
            where="other-ci.md:jenkins",
        )
    message = str(raised.value)
    assert "other-ci.md:jenkins" in message and image in message, message


#: Images of ASH named with no tag, which only the checks of where a job's image is
#: written can find: nothing in the text after the name marks them as an image.
UNTAGGED_CONTAINER = "public.ecr.aws/x/automated-security-helper"
UNTAGGED_DOCKER_STEP = "ghcr.io/awslabs/automated-security-helper"


@pytest.mark.parametrize(
    "job,image",
    [
        (
            f"    container: {UNTAGGED_CONTAINER}\n    steps:\n      - run: ash scan\n",
            UNTAGGED_CONTAINER,
        ),
        (
            f"    steps:\n      - uses: docker://{UNTAGGED_DOCKER_STEP}\n",
            UNTAGGED_DOCKER_STEP,
        ),
    ],
    ids=["a job container with no tag", "a docker step with no tag"],
)
def test_a_github_job_on_an_untagged_image_of_ash_is_refused_as_one(job, image):
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    with pytest.raises(error) as raised:
        rewrite(
            "github-actions",
            _github_with_job(job),
            _context("act", WHEEL),
            where="page.md:9",
        )
    message = str(raised.value)
    assert "page.md:9" in message, message
    assert f"{image} is an image of ASH named with no tag" in message, message


def test_a_jenkins_agent_on_an_untagged_image_of_ash_is_refused_as_one():
    block = _block("docs/content/how-to/ci/other-ci.md", lang="groovy", index=0)
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    text = block.body.replace(
        "agent { label 'linux' }",
        f"agent {{ docker {{ image '{UNTAGGED_CONTAINER}' }} }}",
    )
    assert UNTAGGED_CONTAINER in text
    with pytest.raises(error) as raised:
        rewrite(
            "jenkinsfile",
            text,
            _context("jenkinsfile-runner-lts", WHEEL),
            where="other-ci.md:jenkins",
        )
    message = str(raised.value)
    assert "other-ci.md:jenkins" in message, message
    assert f"{UNTAGGED_CONTAINER} is an image of ASH named with no tag" in message


def test_a_circleci_job_on_an_image_of_ash_is_refused():
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    image = f"{ASH_IMAGE}:v{_version()}"
    text = _circleci_config().replace("cimg/python:3.12-node", image)
    context = _context(
        "circleci", WHEEL, images={image: ASH_IMAGE_PIN}, report_mount="/ash-reports"
    )
    with pytest.raises(error) as raised:
        rewrite("circleci", text, context, where="other-ci.md:circleci")
    message = str(raised.value)
    assert "other-ci.md:circleci" in message and image in message, message


# ---------------------------------------------------------------------------
# The job on the image the run built prints that image's ASH before its scan
# ---------------------------------------------------------------------------


def test_the_job_on_the_built_image_prints_its_ash_right_before_the_scan():
    block = _block("docs/content/how-to/ci/gitlab-ci.md", "gitlab-ci", index=1)
    rewrite = _api("rewrite", "rewrite_pipeline")
    begin = _api("provenance", "PROVENANCE_BEGIN")
    end = _api("provenance", "PROVENANCE_END")
    program = _api("provenance", "BUILT_PRINT_PROGRAM")
    context = _context("gitlab-ci-local", WHEEL, built_images={BUILT_IMAGE})
    result = rewrite("gitlab-ci", block.body, context, where="gitlab-ci.md:2")
    built = _applied(result, "built-provenance")
    assert [(a.count, a.job, a.matrix) for a in built] == [(1, "ash-scan", False)]
    original, document = _load(block.body), _load(result.text)
    assert document["ash-scan"]["image"] == BUILT_IMAGE
    script = document["ash-scan"]["script"]
    printing = [
        i for i, item in enumerate(script) if begin in str(item) and end in str(item)
    ]
    scan = [i for i, item in enumerate(script) if str(item).startswith("ash scan")]
    assert len(printing) == 1 and len(scan) == 1, script
    assert printing[0] == scan[0] - 1, "the print is the command right before the scan"
    assert str(script[printing[0]]).startswith("python3 -I -c ")
    assert program in str(script[printing[0]])
    assert built[0].new.strip() == "- " + _single_quoted(script[printing[0]])
    del script[printing[0]]
    assert document == original, "nothing else changes, and the gate gets no print"


def _single_quoted(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def test_a_built_image_job_with_a_matrix_prints_once_per_entry():
    block = _block("docs/content/how-to/ci/gitlab-ci.md", "gitlab-ci", index=1)
    rewrite = _api("rewrite", "rewrite_pipeline")
    text = block.body.replace("  stage: test\n", "  stage: test\n  parallel: 2\n", 1)
    context = _context("gitlab-ci-local", WHEEL, built_images={BUILT_IMAGE})
    result = rewrite("gitlab-ci", text, context, where="gitlab-ci.md:2")
    built = _applied(result, "built-provenance")
    assert [(a.count, a.job, a.matrix) for a in built] == [(1, "ash-scan", True)]


@pytest.mark.parametrize(
    "changes",
    [
        [
            (
                (
                    "  image: registry.example.com/security/automated-security-helper:ci\n"
                    "  script:\n"
                ),
                (
                    "  image: registry.example.com/security/automated-security-helper:ci\n"
                    "  variables:\n"
                    f'    INSTALL_SPEC: "{_release_spec()}"\n'
                    "  before_script:\n"
                    '    - /opt/ash/bin/pip install --quiet "$INSTALL_SPEC"\n'
                    "  script:\n"
                ),
            )
        ],
        [("      ash scan --mode local", "      echo scan --mode local")],
        [
            ("  script:\n    - ash_exit=0\n    - >-\n", "  script: >-\n"),
            ('    - echo "$ash_exit" > ash-exit-code.txt\n', ""),
        ],
    ],
    ids=[
        "a job that installs ASH again on the built image",
        "no job on the built image runs ASH",
        "a scan that is not an item of a list",
    ],
)
def test_a_built_image_pipeline_the_print_cannot_follow_is_refused(changes):
    block = _block("docs/content/how-to/ci/gitlab-ci.md", "gitlab-ci", index=1)
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    text = block.body
    for old, new in changes:
        assert old in text
        text = text.replace(old, new, 1)
    assert isinstance(_load(text)["ash-scan"], dict), "the changed pipeline parses"
    context = _context("gitlab-ci-local", WHEEL, built_images={BUILT_IMAGE})
    with pytest.raises(error) as raised:
        rewrite("gitlab-ci", text, context, where="gitlab-ci.md:2")
    assert "gitlab-ci.md:2" in str(raised.value)


def test_a_second_built_image_job_whose_scan_is_one_scalar_is_refused():
    """The first job gets its print, so only the check of the second job's script
    can refuse it: a scan in a scalar has no item for a print to go before."""
    block = _block("docs/content/how-to/ci/gitlab-ci.md", "gitlab-ci", index=1)
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    text = (
        block.body.rstrip("\n")
        + f"\n\nash-again:\n  stage: test\n  image: {BUILT_IMAGE}\n"
        + "  script: ash scan --mode local --no-progress\n"
    )
    assert _load(text)["ash-again"]["script"] == "ash scan --mode local --no-progress"
    context = _context("gitlab-ci-local", WHEEL, built_images={BUILT_IMAGE})
    with pytest.raises(error) as raised:
        rewrite("gitlab-ci", text, context, where="gitlab-ci.md:2")
    message = str(raised.value)
    assert "gitlab-ci.md:2" in message and "ash-again" in message, message
    assert "in a script that is not a list of commands" in message, message


def test_a_circleci_job_on_a_built_image_is_refused():
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    text = _circleci_config().replace("cimg/python:3.12-node", BUILT_IMAGE)
    context = _context(
        "circleci", WHEEL, built_images={BUILT_IMAGE}, report_mount="/ash-reports"
    )
    with pytest.raises(error) as raised:
        rewrite("circleci", text, context, where="other-ci.md:circleci")
    assert "other-ci.md:circleci" in str(raised.value)


# ---------------------------------------------------------------------------
# Values a context holds are literal
# ---------------------------------------------------------------------------


def _context_args(**change):
    args = {
        "runner": "act",
        "install_spec": "automated-security-helper[cdk] @ "
        + WHEEL_URI
        + "#sha256="
        + WHEEL_SHA256,
        "head_sha": HEAD,
        "repository": REPOSITORY,
        "version": "0.0.0",
    }
    args.update(change)
    return args


@pytest.mark.parametrize(
    "change",
    [
        {
            "install_spec": "automated-security-helper[cdk] @ file:///home/~runner/"
            "x.whl#sha256=" + WHEEL_SHA256
        },
        {
            "install_spec": "automated-security-helper[cdk] @ file:///$RUNNER_TEMP/"
            "x.whl#sha256=" + WHEEL_SHA256
        },
        {"images": {"python:3.12": "$HOME/python@sha256:" + "e" * 64}},
        {"images": {"python:3.12": "~/python@sha256:" + "e" * 64}},
        {"images": {"python:3.12": "${RUNNER_TEMP}/python@sha256:" + "e" * 64}},
        {"built_images": frozenset({"$HOME/ash:ci"})},
        {"built_images": frozenset({"~/ash:ci"})},
        {"built_images": frozenset({"${RUNNER_TEMP}/ash:ci"})},
    ],
    ids=[
        "install spec with a tilde",
        "install spec with a variable",
        "image pin under $HOME",
        "image pin under a tilde",
        "image pin under ${RUNNER_TEMP}",
        "built image under $HOME",
        "built image under a tilde",
        "built image under ${RUNNER_TEMP}",
    ],
)
def test_a_context_value_that_is_not_literal_is_refused(change):
    context = _api("rewrite", "RewriteContext")
    error = _api("rewrite", "RewriteError")
    with pytest.raises(error):
        context(**_context_args(**change))


@pytest.mark.parametrize("job", [".", ".."])
def test_a_circleci_job_named_like_a_directory_is_refused(job):
    rewrite = _api("rewrite", "rewrite_pipeline")
    error = _api("rewrite", "RewriteError")
    text = _circleci_config().replace("\n  ash:\n", f'\n  "{job}":\n', 1)
    context = _context(
        "circleci",
        WHEEL,
        images={"cimg/python:3.12-node": CIMG_DIGEST},
        report_mount="/ash-reports",
    )
    with pytest.raises(error) as raised:
        rewrite("circleci", text, context, where="other-ci.md:circleci")
    assert "other-ci.md:circleci" in str(raised.value)


def test_the_install_spec_is_built_without_a_deprecated_call():
    install_spec = _api("rewrite", "install_spec")
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        for runner in ("act", "gitlab-ci-local"):
            install_spec(
                runner,
                wheel=WHEEL,
                wheel_sha256=WHEEL_SHA256,
                head_sha=HEAD,
                repository=REPOSITORY,
            )


# ---------------------------------------------------------------------------
# The scan workflow a reusable call runs prints the provenance of its ASH
# ---------------------------------------------------------------------------

SCAN_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"
UVX_FROM = 'uvx --from "${ASH_UVX_SOURCE}"'
UVX_REINSTALL = 'uvx --reinstall --from "${ASH_UVX_SOURCE}"'


def _scan_steps(text: str) -> list:
    return yaml.safe_load(text)["jobs"]["ash"]["steps"]


def _on_v4_actions(steps: list) -> list:
    """``steps`` with each artifact action's ``uses`` on the pin act runs it at."""
    pins = {
        "actions/upload-artifact": UPLOAD_V4,
        "actions/download-artifact": DOWNLOAD_V4,
    }
    moved = []
    for step in steps:
        action = str(step.get("uses", "")).split("@")[0]
        if action in pins:
            step = {**step, "uses": pins[action]}
        moved.append(step)
    return moved


def _artifact_steps(text: str) -> list:
    return [
        step
        for job in yaml.safe_load(text)["jobs"].values()
        for step in job["steps"]
        if "-artifact@" in str(step.get("uses", ""))
    ]


def test_the_scan_workflow_prints_the_provenance_of_the_ash_it_runs():
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    begin = _api("provenance", "PROVENANCE_BEGIN")
    end = _api("provenance", "PROVENANCE_END")
    text = SCAN_WORKFLOW.read_text(encoding="utf-8")
    result = rewrite_called(
        "run-ash-security-scan.yml", text, where="run-ash-security-scan.yml"
    )
    assert [(a.rule, a.count, a.job, a.matrix) for a in result.applied] == [
        ("artifact-actions", 1, None, False),
        ("artifact-actions", 1, None, False),
        ("called-provenance", 1, "ash", False),
    ]
    original, steps = _scan_steps(text), _scan_steps(result.text)
    scans = [
        i
        for i, step in enumerate(original)
        if UVX_REINSTALL in str(step.get("run", ""))
    ]
    assert len(scans) == 1, "the scan is the one step that rebuilds the environment"
    printing = [
        i
        for i, step in enumerate(steps)
        if begin in str(step.get("run", "")) and end in str(step.get("run", ""))
    ]
    assert printing == [scans[0] + 1], (
        "one print, right after the scan, so it reads the environment the scan built"
    )
    step = steps[scans[0] + 1]
    assert step["run"].strip().startswith(f"{UVX_FROM} python -I -c ")
    assert "--reinstall" not in step["run"], (
        "the form the later steps use, which reuses the scan's environment"
    )
    assert step.get("if") == "${{ !cancelled() }}", "it runs when the scan failed too"
    assert steps[: scans[0] + 1] + steps[scans[0] + 2 :] == _on_v4_actions(original)


def test_the_called_scan_workflow_runs_its_artifact_steps_on_the_pinned_v4_actions():
    """The scan workflow's own upload and download steps pin the releases whose
    requests act's artifact server refuses, as the pages' steps do, so the copy act
    runs gets the same swap as a block; each step keeps its inputs and condition."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    text = SCAN_WORKFLOW.read_text(encoding="utf-8")
    before = {s["uses"].split("@")[0]: s for s in _artifact_steps(text)}
    assert set(before) == {"actions/upload-artifact", "actions/download-artifact"}
    assert before["actions/upload-artifact"]["uses"] != UPLOAD_V4, (
        "the workflow pins a release act cannot serve, which the swap stands in for"
    )
    assert before["actions/download-artifact"]["uses"] != DOWNLOAD_V4
    result = rewrite_called(
        "run-ash-security-scan.yml", text, where="run-ash-security-scan.yml"
    )
    assert result.original == text
    after = _artifact_steps(result.text)
    assert [s["uses"] for s in after] == [UPLOAD_V4, DOWNLOAD_V4]
    assert "# v4.6.2" in result.text and "# v4.3.0" in result.text
    for step in after:
        given = before[step["uses"].split("@")[0]]
        assert step["with"] == given["with"]
        assert step.get("if") == given.get("if")
    assert {
        (a.old.split("@")[0], a.new.split(" #")[0], a.count)
        for a in _applied(result, "artifact-actions")
    } == {
        ("actions/upload-artifact", UPLOAD_V4, 1),
        ("actions/download-artifact", DOWNLOAD_V4, 1),
    }
    # Every other step is as given, and the print follows the scan as before.
    rest = [
        s
        for s in _scan_steps(result.text)
        if "-artifact@" not in str(s.get("uses", ""))
    ]
    print_steps = [
        s
        for s in rest
        if s.get("name") == _api("rewrite", "CALLED_PROVENANCE_STEP_NAME")
    ]
    assert len(print_steps) == 1
    rest.remove(print_steps[0])
    assert rest == [
        s for s in _scan_steps(text) if "-artifact@" not in str(s.get("uses", ""))
    ]


def test_only_the_first_uvx_step_of_the_scan_workflow_gets_the_print():
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    begin = _api("provenance", "PROVENANCE_BEGIN")
    text = (
        "on:\n  workflow_call:\nenv:\n  ASH_UVX_SOURCE: automated-security-helper[cdk] "
        "@ git+https://github.com/${{ inputs.ash-repo }}@${{ inputs.ash-version }}\n"
        "jobs:\n  ash:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo first\n"
        f"      - run: {UVX_FROM} ash dependencies install --tool grype\n"
        f"      - run: {UVX_FROM} ash scan\n"
    )
    result = rewrite_called("run-ash-security-scan.yml", text, where="scan workflow")
    steps = _scan_steps(result.text)
    assert [begin in str(s.get("run", "")) for s in steps] == [
        False,
        False,
        True,
        False,
    ]


#: The scan workflow's ASH_UVX_SOURCE, built from the inputs the block's rewrite sets.
SOURCE_FROM_INPUTS = (
    "automated-security-helper[cdk] "
    "@ git+https://github.com/${{ inputs.ash-repo }}@${{ inputs.ash-version }}"
)


def _scan_workflow(
    *steps: str,
    job_env: str = "",
    source: str = SOURCE_FROM_INPUTS,
    top: str = "",
    workflow_env: str = "",
) -> str:
    """A scan workflow: ``top`` holds top-level keys, ``workflow_env`` more workflow
    env lines, and ``job_env`` more keys of the job ``ash``."""
    return (
        f"on:\n  workflow_call:\n{top}env:\n  ASH_UVX_SOURCE: {source}\n{workflow_env}"
        f"jobs:\n  ash:\n    runs-on: ubuntu-latest\n{job_env}    steps:\n"
        + "".join(steps)
    )


def test_the_print_follows_the_step_that_rebuilds_the_environment():
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    begin = _api("provenance", "PROVENANCE_BEGIN")
    text = _scan_workflow(
        f"      - run: {UVX_FROM} ash dependencies install --tool grype\n",
        f"      - run: {UVX_REINSTALL} ash scan\n",
        f"      - run: {UVX_FROM} ash report\n",
    )
    result = rewrite_called("run-ash-security-scan.yml", text, where="scan workflow")
    steps = _scan_steps(result.text)
    assert [begin in str(s.get("run", "")) for s in steps] == [
        False,
        False,
        True,
        False,
    ]
    assert steps[2].get("if") == "${{ !cancelled() }}"


@pytest.mark.parametrize(
    "steps,job_env",
    [
        (
            (
                f"      - run: {UVX_REINSTALL} ash scan\n",
                f"      - run: {UVX_REINSTALL} ash report\n",
            ),
            "",
        ),
        (
            (
                (
                    "      - env:\n          ASH_UVX_SOURCE: automated-security-helper\n"
                    f"        run: {UVX_REINSTALL} ash scan\n"
                ),
            ),
            "",
        ),
        (
            (f"      - run: {UVX_REINSTALL} ash scan\n",),
            "    env:\n      ASH_UVX_SOURCE: automated-security-helper\n",
        ),
    ],
    ids=[
        "two steps rebuild the environment",
        "a step sets ASH_UVX_SOURCE again",
        "the job sets ASH_UVX_SOURCE again",
    ],
)
def test_a_scan_workflow_whose_scan_environment_is_not_one_source_is_refused(
    steps, job_env
):
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    grype = f"      - run: {UVX_FROM} ash dependencies install --tool grype\n"
    text = _scan_workflow(grype, *steps, job_env=job_env)
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", text, where="copied scan workflow")
    assert "copied scan workflow" in str(raised.value)


def test_another_called_workflow_is_left_as_it_is():
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    path = REPO_ROOT / ".github" / "workflows" / "upload-ash-sarif.yml"
    text = path.read_text(encoding="utf-8")
    result = rewrite_called("upload-ash-sarif.yml", text, where="upload-ash-sarif.yml")
    assert result.text == text and tuple(result.applied) == ()


def test_a_scan_workflow_without_the_uvx_step_is_refused():
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    text = _scan_workflow("      - run: echo hi\n")
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", text, where="copied scan workflow")
    message = str(raised.value)
    assert "copied scan workflow" in message and "no step runs uvx" in message, message


def test_a_scan_workflow_whose_source_names_a_release_is_refused():
    """A literal ASH_UVX_SOURCE installs that release whatever the block's rewrite
    sets the inputs to; the workflow is otherwise one the print can follow."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    release = (
        f"automated-security-helper[cdk] @ git+https://github.com/{REPOSITORY}"
        f"@v{_version()}"
    )
    text = _scan_workflow(
        f"      - run: {UVX_FROM} ash dependencies install --tool grype\n",
        f"      - run: {UVX_REINSTALL} ash scan\n",
        source=release,
    )
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", text, where="copied scan workflow")
    message = str(raised.value)
    assert "copied scan workflow" in message, message
    assert "is not built from the ash-repo and ash-version inputs" in message, message


def _script_step(*lines: str) -> str:
    """A step whose ``run`` is a block scalar holding ``lines``."""
    return "      - run: |\n" + "".join(f"          {line}\n" for line in lines)


SCAN_STEP = f"      - run: {UVX_REINSTALL} ash scan\n"
SCAN_LINE = f"{UVX_REINSTALL} ash scan"
RELEASE_SOURCE = "automated-security-helper==3.7.0"


@pytest.mark.parametrize(
    "steps",
    [
        (
            _script_step(
                "export ASH_UVX_SOURCE=automated-security-helper==3.7.0",
                f"{UVX_REINSTALL} ash scan",
            ),
        ),
        (
            _script_step(
                "ASH_UVX_SOURCE=automated-security-helper==3.7.0",
                f"{UVX_REINSTALL} ash scan",
            ),
        ),
        (
            _script_step(
                'echo "ASH_UVX_SOURCE=automated-security-helper==3.7.0" >> '
                '"$GITHUB_ENV"'
            ),
            SCAN_STEP,
        ),
        (
            _script_step(
                'echo "ASH_UVX_SOURCE<<EOF" >> "$GITHUB_ENV"',
                'echo "automated-security-helper==3.7.0" >> "$GITHUB_ENV"',
                'echo "EOF" >> "$GITHUB_ENV"',
            ),
            SCAN_STEP,
        ),
        (
            _script_step(
                "read -r ASH_UVX_SOURCE < source.txt", f"{UVX_REINSTALL} ash scan"
            ),
        ),
        (
            _script_step(
                "printf -v ASH_UVX_SOURCE '%s' automated-security-helper",
                f"{UVX_REINSTALL} ash scan",
            ),
        ),
        (_script_step("printf -vASH_UVX_SOURCE '%s' x", SCAN_LINE),),
        (_script_step("ASH_UVX_SOURCE+=x", SCAN_LINE),),
        (_script_step("mapfile -t ASH_UVX_SOURCE < source.txt", SCAN_LINE),),
        (_script_step("readarray ASH_UVX_SOURCE < source.txt", SCAN_LINE),),
        (_script_step(f'export "ASH_UVX_SOURCE"={RELEASE_SOURCE}', SCAN_LINE),),
        (_script_step(f"export ASH_UVX_SOURC\\E={RELEASE_SOURCE}", SCAN_LINE),),
        (
            _script_step(f"echo ASH_UVX_SOURCE'='{RELEASE_SOURCE} >> \"$GITHUB_ENV\""),
            SCAN_STEP,
        ),
        (
            _script_step(
                "declare -n source_ref=ASH_UVX_SOURCE",
                f"source_ref={RELEASE_SOURCE}",
                SCAN_LINE,
            ),
        ),
        (
            _script_step(
                f"for ASH_UVX_SOURCE in {RELEASE_SOURCE}; do break; done", SCAN_LINE
            ),
        ),
        (_script_step(f"export $'\\x41SH_UVX_SOURCE'={RELEASE_SOURCE}", SCAN_LINE),),
        (
            _script_step(
                f"eval \"$(printf 'true\\nASH_UVX_SOURCE={RELEASE_SOURCE}')\"",
                SCAN_LINE,
            ),
        ),
        (_script_step("exec {ASH_UVX_SOURCE}>/dev/null", SCAN_LINE),),
        (
            _script_step(
                "{",
                f'  echo "ASH_UVX_SOURCE={RELEASE_SOURCE}"',
                "} > source.env",
                ". ./source.env",
                SCAN_LINE,
            ),
        ),
        (_script_step("export ASH_UVX_\\", f"SOURCE={RELEASE_SOURCE}", SCAN_LINE),),
        (
            _script_step(
                f"export ASH_UVX_{{SOURCE,UNUSED}}={RELEASE_SOURCE}", SCAN_LINE
            ),
        ),
        (
            _script_step(
                'echo() { export "$1"; }',
                f"echo ASH_UVX_SOURCE={RELEASE_SOURCE}",
                SCAN_LINE,
            ),
        ),
        (
            _script_step(
                "shopt -s expand_aliases",
                "alias echo=export",
                f"echo ASH_UVX_SOURCE={RELEASE_SOURCE}",
                SCAN_LINE,
            ),
        ),
        (
            _script_step(
                "QUOTED='",
                f"# ' ; export ASH_UVX_SOURCE={RELEASE_SOURCE}",
                SCAN_LINE,
            ),
        ),
        (
            _script_step(
                'QUOTED="',
                f"# ${{ASH_UVX_SOURCE:={RELEASE_SOURCE}}}",
                '"',
                SCAN_LINE,
            ),
        ),
        (
            _script_step(
                'env -i PATH="$PATH" bash -c \': "${ASH_UVX_SOURCE:='
                + RELEASE_SOURCE
                + '}"; '
                + SCAN_LINE
                + "'"
            ),
        ),
        (_script_step(f': "${{ASH_UVX_SOURCE={RELEASE_SOURCE}}}"', SCAN_LINE),),
        (
            _script_step(
                "cat > /dev/null <<EOF",
                "it's",
                "EOF",
                "QUOTED='",
                f"# ' ; export ASH_UVX_SOURCE={RELEASE_SOURCE}",
                SCAN_LINE,
            ),
        ),
        (
            _script_step(
                "# set the source \\",
                f"export ASH_UVX_SOURCE={RELEASE_SOURCE}",
                SCAN_LINE,
            ),
        ),
        (
            _script_step(
                "echo start # set the source \\",
                f"export ASH_UVX_SOURCE={RELEASE_SOURCE}",
                SCAN_LINE,
            ),
        ),
        (_script_step(f': "${{ASH_UVX_SOURCE[0]:={RELEASE_SOURCE}}}"', SCAN_LINE),),
        (
            _script_step(
                f"export ASH_UVX_{{${{X}},SOURCE}}={RELEASE_SOURCE}", SCAN_LINE
            ),
        ),
        (
            _script_step(
                "cat > /dev/null <<EOF",
                "it's",
                "EOF",
                "export ASH_UVX_\\",
                f"SOURCE={RELEASE_SOURCE}",
                SCAN_LINE,
            ),
        ),
        (
            _script_step(
                f"export ASH_UVX_{{{{x}},SOURCE}}={RELEASE_SOURCE} || true", SCAN_LINE
            ),
        ),
        (
            _script_step(
                f"export ASH_UVX_{{{{x}}{{y}},SOURCE}}={RELEASE_SOURCE} || true",
                SCAN_LINE,
            ),
        ),
        (
            _script_step(
                f"export ASH_{{UVX_{{x}},UVX_SOURCE}}={RELEASE_SOURCE} || true",
                SCAN_LINE,
            ),
        ),
    ],
    ids=[
        "export before the scan",
        "an assignment before the scan",
        "a GITHUB_ENV line",
        "a GITHUB_ENV value with a delimiter",
        "read into it before the scan",
        "printf -v into it before the scan",
        "printf -v joined to the name",
        "an append",
        "mapfile into it",
        "readarray into it",
        "export of a quoted name",
        "export of a name with a backslash in it",
        "a GITHUB_ENV line with a quoted equals sign",
        "a nameref to it",
        "a for loop over it",
        "export of a name spelled with an escape",
        "eval of a line a printf escape separates",
        "a file descriptor allocated into it",
        "a print captured by a redirection on another line",
        "export of a name continued on the next line",
        "export of a name a brace expansion spells",
        "a function named echo",
        "an alias named echo",
        "a comment line that closes a quote",
        "a comment line inside a quote",
        "a default assigned in a cleared environment",
        "a default assigned without a colon",
        "a comment line that closes a quote opened after a here-document",
        "export after a comment line that ends in a backslash",
        "export after a comment that ends a line in a backslash",
        "a default assigned through a subscript",
        "export of a name a brace expansion holding a parameter spells",
        "export of a name continued on the next line after a here-document",
        "export of a name an outer brace group around a literal one spells",
        "export of a name an outer brace group around two literal ones spells",
        "export of a name a brace alternative holding a literal group spells",
    ],
)
def test_a_scan_workflow_whose_script_sets_the_source_is_refused(steps):
    """The print step reads the workflow's ASH_UVX_SOURCE, so a script that sets it
    again could scan with another ASH than the one the print records."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    grype = f"      - run: {UVX_FROM} ash dependencies install --tool grype\n"
    text = _scan_workflow(grype, *steps)
    assert isinstance(_scan_steps(text), list), "the workflow parses"
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", text, where="copied scan workflow")
    message = str(raised.value)
    assert "copied scan workflow" in message, message
    assert "in a script of the job ash, sets ASH_UVX_SOURCE" in message, message


def test_a_script_that_only_reads_the_source_is_kept():
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    begin = _api("provenance", "PROVENANCE_BEGIN")
    text = _scan_workflow(
        _script_step(
            "# ASH_UVX_SOURCE is set once, for the workflow.",
            'echo "source: ${ASH_UVX_SOURCE}"',
            'test -n "$ASH_UVX_SOURCE"',
            f"{UVX_REINSTALL} ash scan",
        )
    )
    result = rewrite_called("run-ash-security-scan.yml", text, where="scan workflow")
    steps = _scan_steps(result.text)
    assert [begin in str(s.get("run", "")) for s in steps] == [False, True]


@pytest.mark.parametrize(
    "steps,job_env,named",
    [
        (
            (_script_step('cat source.env >> "$GITHUB_ENV"'), SCAN_STEP),
            "",
            "in a script of the job ash, names GITHUB_ENV",
        ),
        (
            (
                _script_step(f'echo "::set-env name=ASH_UVX_SOURCE::{RELEASE_SOURCE}"'),
                SCAN_STEP,
            ),
            "",
            "in a script of the job ash, runs the set-env workflow command",
        ),
        (
            (SCAN_STEP,),
            "    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n",
            "names ACTIONS_ALLOW_UNSECURE_COMMANDS",
        ),
        (
            (
                (
                    "      - env:\n          ENV_FILE: ${{ github.env }}\n"
                    '        run: cat source.env >> "$ENV_FILE"\n'
                ),
                SCAN_STEP,
            ),
            "",
            "in an env value in the job ash, names GITHUB_ENV",
        ),
        (
            (
                (
                    "      - uses: actions/github-script@v7\n        with:\n"
                    "          script: core.exportVariable('ASH_UVX_SOURCE', "
                    f"'{RELEASE_SOURCE}')\n"
                ),
                SCAN_STEP,
            ),
            "",
            "in an input in the job ash, sets ASH_UVX_SOURCE",
        ),
    ],
    ids=[
        "a file appended to GITHUB_ENV",
        "the set-env workflow command",
        "the workflow commands that set variables turned on",
        "GITHUB_ENV's path through a step's env",
        "an action's input that sets it",
    ],
)
def test_a_scan_workflow_step_that_could_set_the_source_for_later_steps_is_refused(
    steps, job_env, named
):
    """GITHUB_ENV, and the set-env command where the runner honors it, set variables
    for every step after the one that uses them, the print step included."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    grype = f"      - run: {UVX_FROM} ash dependencies install --tool grype\n"
    text = _scan_workflow(grype, *steps, job_env=job_env)
    assert isinstance(_scan_steps(text), list), "the workflow parses"
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", text, where="copied scan workflow")
    message = str(raised.value)
    assert "copied scan workflow" in message and named in message, message


@pytest.mark.parametrize(
    "line",
    [
        "# ASH_UVX_SOURCE=<requirement> is set once, for the workflow.",
        "printf '%s\\n' \"$ASH_UVX_SOURCE\"",
        'echo "${#ASH_UVX_SOURCE} characters"',
        'echo "${{ env.ASH_UVX_SOURCE }}"',
        'PREVIOUS_ASH_UVX_SOURCE="${ASH_UVX_SOURCE}"',
    ],
    ids=[
        "a comment",
        "printf of its value",
        "its length",
        "the expression of its value",
        "a longer name",
    ],
)
def test_a_line_that_reads_the_source_is_kept_in_a_script_that_redirects(line):
    """Each line is kept by the rule that tells it from a setting, not because it
    only prints: the script pipes the scan's output, so no line of it prints only to
    the job's log."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    begin = _api("provenance", "PROVENANCE_BEGIN")
    text = _scan_workflow(_script_step(line, f"{SCAN_LINE} | tee scan.log"))
    result = rewrite_called("run-ash-security-scan.yml", text, where="scan workflow")
    steps = _scan_steps(result.text)
    assert [begin in str(s.get("run", "")) for s in steps] == [False, True]
    assert line in result.text


@pytest.mark.parametrize(
    "line",
    ["echo read ASH_UVX_SOURCE", 'echo "ASH_UVX_SOURCE=${ASH_UVX_SOURCE}"'],
    ids=["a command name echoed", "a setting echoed"],
)
def test_a_line_that_only_prints_the_name_to_the_log_is_kept(line):
    """The name is printed, not set: the line is an echo with nothing that sends its
    output anywhere, in a script with no redirection, pipe or substitution that could
    send it to a file read back later."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    begin = _api("provenance", "PROVENANCE_BEGIN")
    text = _scan_workflow(_script_step(line, SCAN_LINE))
    result = rewrite_called("run-ash-security-scan.yml", text, where="scan workflow")
    steps = _scan_steps(result.text)
    assert [begin in str(s.get("run", "")) for s in steps] == [False, True]
    assert line in result.text


@pytest.mark.parametrize(
    "lines",
    [
        ('mkdir -p "${ASH_OUTPUT_DIR}"/{reports,scanners}',),
        ("for attempt in {1..300}; do break; done",),
        ('test -n "${ASH_UVX_SOURCE:?the workflow sets it}"',),
        ('echo "start"', "# ASH_UVX_SOURCE is set once, for the workflow."),
        ("echo ok # it's set once", "# ASH_UVX_SOURCE is set once, for the workflow."),
        ("QUOTED='ASH_UVX_\\", "SOURCE is the text'"),
        ("mkdir -p out/{{x},reports}",),
    ],
    ids=[
        "a brace expansion that spells no name",
        "a numeric sequence",
        "an error when it is unset",
        "a comment after a closed quote",
        "a comment after a line whose own comment holds a quote",
        "a backslash that ends a line inside single quotes",
        "an outer brace group around a literal one that spells no name",
    ],
)
def test_a_script_the_source_checks_read_as_not_setting_it_is_kept(lines):
    """Brace expansions are written out, a ``#`` line counts as a comment only with no
    quote open above it, and ``${NAME:?}`` does not assign: none of these is a
    setting."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    begin = _api("provenance", "PROVENANCE_BEGIN")
    text = _scan_workflow(_script_step(*lines, SCAN_LINE))
    result = rewrite_called("run-ash-security-scan.yml", text, where="scan workflow")
    steps = _scan_steps(result.text)
    assert [begin in str(s.get("run", "")) for s in steps] == [False, True]
    assert all(line in result.text for line in lines)


#: An expression GitHub evaluates to a mapping that sets the scan's source.
SOURCE_EXPRESSION = (
    "'${{ fromJSON(''{\"ASH_UVX_SOURCE\": \"" + RELEASE_SOURCE + "\"}'') }}'"
)


@pytest.mark.parametrize(
    "steps,job_env,top,named",
    [
        (
            (
                (
                    f"      - shell: env ASH_UVX_SOURCE={RELEASE_SOURCE} bash -e {{0}}\n"
                    f"        run: {SCAN_LINE}\n"
                ),
            ),
            "",
            "",
            (
                f"`shell: env ASH_UVX_SOURCE={RELEASE_SOURCE} bash -e {{0}}`, in the "
                "job ash, is not bash or sh"
            ),
        ),
        (
            (
                (
                    "      - shell: bash -c 'bash {0} >> \"$GITHUB_ENV\"'\n"
                    f"        run: echo ASH_UVX_SOURCE={RELEASE_SOURCE}\n"
                ),
                SCAN_STEP,
            ),
            "",
            "",
            "in the job ash, is not bash or sh",
        ),
        (
            (
                (
                    "      - shell: pwsh\n        run: |\n"
                    f"          $ASH_UVX_SOURCE = '{RELEASE_SOURCE}'\n"
                    f"          {SCAN_LINE}\n"
                ),
            ),
            "",
            "",
            "`shell: pwsh`, in the job ash, is not bash or sh",
        ),
        (
            (SCAN_STEP,),
            (
                "    defaults:\n      run:\n"
                f"        shell: env ASH_UVX_SOURCE={RELEASE_SOURCE} bash -e {{0}}\n"
            ),
            "",
            "in the defaults of the job ash, is not bash or sh",
        ),
        (
            (SCAN_STEP,),
            "",
            (
                "defaults:\n  run:\n"
                f"    shell: env ASH_UVX_SOURCE={RELEASE_SOURCE} bash -e {{0}}\n"
            ),
            "in the defaults of the workflow, is not bash or sh",
        ),
        (
            (SCAN_STEP,),
            "",
            "defaults: '${{ fromJSON(''{}'') }}'\n",
            "the defaults of the workflow are",
        ),
        (
            (f"      - env: {SOURCE_EXPRESSION}\n        run: {SCAN_LINE}\n",),
            "",
            "",
            "the env of the job ash or one of its steps is",
        ),
        (
            (SCAN_STEP,),
            f"    env: {SOURCE_EXPRESSION}\n",
            "",
            "the env of the job ash or one of its steps is",
        ),
        (
            (
                (
                    "      - uses: actions/github-script@v7\n"
                    "        with: '${{ fromJSON(''{\"script\": \"x\"}'') }}'\n"
                ),
                SCAN_STEP,
            ),
            "",
            "",
            "the with of the job ash or one of its steps is",
        ),
    ],
    ids=[
        "a step's shell that sets the source for the scan alone",
        "a step's shell that writes GITHUB_ENV",
        "a step's shell whose scripts the checks do not read",
        "a job's default shell",
        "the workflow's default shell",
        "the workflow's defaults as an expression",
        "a step's env as an expression",
        "a job's env as an expression",
        "a step's inputs as an expression",
    ],
)
def test_a_scan_workflow_whose_shell_or_env_the_checks_cannot_read_is_refused(
    steps, job_env, top, named
):
    """A shell given as a command runs words of its own before the script, so it can
    set ASH_UVX_SOURCE for the scan while the print, on the default shell, reads the
    workflow's value; and an env or inputs given as an expression holds names no
    check reads."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    grype = f"      - run: {UVX_FROM} ash dependencies install --tool grype\n"
    text = _scan_workflow(grype, *steps, job_env=job_env, top=top)
    assert isinstance(_scan_steps(text), list), "the workflow parses"
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", text, where="copied scan workflow")
    message = str(raised.value)
    assert "copied scan workflow" in message and named in message, message


def test_a_scan_workflow_step_on_bash_or_sh_is_kept():
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    begin = _api("provenance", "PROVENANCE_BEGIN")
    text = _scan_workflow(
        f"      - shell: sh\n        run: {UVX_FROM} ash dependencies install\n",
        f"      - shell: bash\n        run: {SCAN_LINE}\n",
        job_env="    defaults:\n      run:\n        shell: bash\n",
        top="defaults:\n  run:\n    shell: bash\n",
    )
    result = rewrite_called("run-ash-security-scan.yml", text, where="scan workflow")
    steps = _scan_steps(result.text)
    assert [begin in str(s.get("run", "")) for s in steps] == [False, False, True]


def test_the_real_scan_workflow_runs_its_steps_on_bash_and_is_kept():
    """The control for the shell rule: the real workflow names a shell on some of its
    steps, every one of them bash, and the rewrite keeps it."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    text = SCAN_WORKFLOW.read_text(encoding="utf-8")
    steps = _scan_steps(text)
    shells = [step["shell"] for step in steps if "shell" in step]
    assert shells and set(shells) == {"bash"}, shells
    result = rewrite_called(
        "run-ash-security-scan.yml", text, where="run-ash-security-scan.yml"
    )
    assert [a.rule for a in result.applied] == [
        "artifact-actions",
        "artifact-actions",
        "called-provenance",
    ]


@pytest.mark.parametrize(
    "steps,job_env,workflow_env,named",
    [
        (
            (
                f"      - env:\n          BASH_ENV: ./setup.sh\n        run: {SCAN_LINE}\n",
            ),
            "",
            "",
            "the job ash or one of its steps sets BASH_ENV",
        ),
        ((SCAN_STEP,), "    env:\n      ENV: ./setup.sh\n", "", "sets ENV"),
        ((SCAN_STEP,), "", "  BASH_ENV: ./setup.sh\n", "the workflow sets BASH_ENV"),
        (
            (_script_step("export BASH_ENV=./setup.sh", SCAN_LINE),),
            "",
            "",
            "in a script of the job ash, names BASH_ENV or ENV",
        ),
        (
            (
                (
                    "      - env:\n"
                    "          BASH_FUNC_echo%%: '() { export \"$1\"; }'\n"
                    f"        run: {SCAN_LINE}\n"
                ),
            ),
            "",
            "",
            "the job ash or one of its steps sets BASH_FUNC_echo%%",
        ),
        (
            (
                _script_step(
                    "export 'BASH_FUNC_echo%%=() { export \"$1\"; }'", SCAN_LINE
                ),
            ),
            "",
            "",
            "in a script of the job ash, names BASH_ENV or ENV",
        ),
    ],
    ids=[
        "BASH_ENV in a step's env",
        "ENV in a job's env",
        "BASH_ENV in the workflow's env",
        "BASH_ENV exported in a script",
        "a function exported through a step's env",
        "a function exported in a script",
    ],
)
def test_a_scan_workflow_that_sets_a_file_the_shell_runs_first_is_refused(
    steps, job_env, workflow_env, named
):
    """bash runs the file BASH_ENV names before a script, and sh the one ENV names,
    so either could set ASH_UVX_SOURCE for the scan from a file no check reads."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    grype = f"      - run: {UVX_FROM} ash dependencies install --tool grype\n"
    text = _scan_workflow(grype, *steps, job_env=job_env, workflow_env=workflow_env)
    assert isinstance(_scan_steps(text), list), "the workflow parses"
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", text, where="copied scan workflow")
    message = str(raised.value)
    assert "copied scan workflow" in message and named in message, message


def test_a_workflow_env_value_that_names_github_env_is_refused():
    """The workflow's own env values are read too: here one holds GITHUB_ENV's path,
    and a step appends to it through a name no other check reads."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    text = _scan_workflow(
        f"      - run: {UVX_FROM} ash dependencies install --tool grype\n",
        '      - run: cat source.env >> "$ENV_FILE"\n',
        SCAN_STEP,
        workflow_env="  ENV_FILE: ${{ github.env }}\n",
    )
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", text, where="copied scan workflow")
    message = str(raised.value)
    assert "in an env value of the workflow, names GITHUB_ENV" in message, message


def test_a_script_with_more_brace_expansions_than_are_read_is_refused():
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    text = _scan_workflow(_script_step("echo " + "{a,b}" * 9, SCAN_LINE))
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", text, where="copied scan workflow")
    message = str(raised.value)
    assert "in a script of the job ash, has more brace expansions" in message, message


#: The words every uv call names its source with, in a refusal.
UV_CALL_REFUSAL = (
    "but every uvx, uv tool run and uv run call in the scan workflow installs from"
)


@pytest.mark.parametrize(
    "run,named",
    [
        (
            f"uvx --reinstall --from {RELEASE_SOURCE} ash scan",
            f"names --from {RELEASE_SOURCE}",
        ),
        (
            'uvx --reinstall --from "${ASH_UVX_SOURCE%@*}@v3.0.0" ash scan',
            'names --from "${ASH_UVX_SOURCE%@*}@v3.0.0"',
        ),
        (
            f"{SCAN_LINE} && uv tool run --from {RELEASE_SOURCE} ash report",
            f"names --from {RELEASE_SOURCE}",
        ),
        (
            f"{SCAN_LINE} && uv run --no-project --with {RELEASE_SOURCE} -- python -V",
            f"names --with {RELEASE_SOURCE}",
        ),
        (
            f"{SCAN_LINE} && uv run --no-project -- python -V",
            "names no --with",
        ),
        (
            f"{UVX_REINSTALL} --with {RELEASE_SOURCE} ash scan",
            f'names --from "${{ASH_UVX_SOURCE}}", --with {RELEASE_SOURCE}',
        ),
        (
            f"{SCAN_LINE} && uvx automated-security-helper@3.7.0 report",
            "names no --from",
        ),
        (
            (
                f'{SCAN_LINE}; (cd "${{RUNNER_TEMP}}" && env -u ASH_CONFIG uvx --from '
                f"{RELEASE_SOURCE} ash report)"
            ),
            f"names --from {RELEASE_SOURCE}",
        ),
        (
            f"# a release scan \\\n          uvx --from {RELEASE_SOURCE} ash --version",
            f"names --from {RELEASE_SOURCE}",
        ),
        (
            f"uv `true` tool run --from {RELEASE_SOURCE} ash --version",
            f"names --from {RELEASE_SOURCE}",
        ),
        (
            f"uv `true` run --no-project --with {RELEASE_SOURCE} -- python -V",
            f"names --with {RELEASE_SOURCE}",
        ),
        (
            f'uvx --from "${{ASH_UVX_SOURCE}}" `true` --with {RELEASE_SOURCE} ash',
            f'names --from "${{ASH_UVX_SOURCE}}", --with {RELEASE_SOURCE}',
        ),
        (
            f'{UVX_REINSTALL} --python "3.12\n          " --with {RELEASE_SOURCE} ash scan',
            f'names --from "${{ASH_UVX_SOURCE}}", --with {RELEASE_SOURCE}',
        ),
        (
            f"{UVX_REINSTALL} -qw {RELEASE_SOURCE} ash scan",
            f'names --from "${{ASH_UVX_SOURCE}}", --with {RELEASE_SOURCE}',
        ),
        (
            f"{UVX_REINSTALL} --overrides overrides.txt ash scan",
            "names --overrides overrides.txt",
        ),
        (
            f"{UVX_REINSTALL} -c constraints.txt ash scan",
            "names --constraints constraints.txt",
        ),
        (
            (
                f'{SCAN_LINE} && uv run --no-project --with "${{ASH_UVX_SOURCE}}" '
                "--build-constraints build.txt -- python -V"
            ),
            "names --build-constraints build.txt",
        ),
        (
            f"{UVX_REINSTALL} --config-file uv.toml ash scan",
            "names --config-file uv.toml",
        ),
        (
            f"X='`' uv `true` tool run --from {RELEASE_SOURCE} ash --version",
            f"names --from {RELEASE_SOURCE}",
        ),
    ],
    ids=[
        "the scan pinned to a release",
        "the scan pinned to a tag of the inputs' repository",
        "uv tool run of a release",
        "uv run with a release",
        "uv run with no source",
        "a second source beside the workflow's",
        "uvx of a package by name",
        "uvx after env -u",
        "uvx after a comment line that ends in a backslash",
        "uv tool run after a backquote pair",
        "uv run after a backquote pair",
        "a second source after a backquote pair",
        "a second source after a quoted value that spans a line",
        "a second source in clustered short options",
        "an overrides file",
        "a constraints file by its short option",
        "a build constraints file on uv run",
        "a uv configuration file",
        # This check refuses it first; the check for ash and installer words outside
        # a uv call refuses it too when the call is not read.
        "uv tool run after a backquote in single quotes",
    ],
)
def test_a_scan_workflow_uv_call_with_another_source_is_refused(run, named):
    """The print runs ``uvx --from "${ASH_UVX_SOURCE}"``, so a uvx, uv tool run or uv
    run call that installs from anything else could run an ASH the print does not
    show."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    grype = f"      - run: {UVX_FROM} ash dependencies install --tool grype\n"
    text = _scan_workflow(grype, _script_step(run))
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", text, where="copied scan workflow")
    message = str(raised.value)
    assert "copied scan workflow" in message, message
    assert "in a script of the job ash" in message, message
    assert named in message and UV_CALL_REFUSAL in message, message


@pytest.mark.parametrize("option,expected", [("--from", 7), ("--with", 5)])
def test_each_uv_call_of_the_real_scan_workflow_is_read(option, expected):
    """The control for the rule above: the real workflow's seven uvx calls and five
    uv run calls each pass it, and each is refused once its source names a
    release."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    text = SCAN_WORKFLOW.read_text(encoding="utf-8")
    source = f'{option} "${{ASH_UVX_SOURCE}}"'
    starts = [i for i in range(len(text)) if text.startswith(source, i)]
    assert len(starts) == expected, starts
    for start in starts:
        changed = (
            text[:start] + f"{option} {RELEASE_SOURCE}" + text[start + len(source) :]
        )
        with pytest.raises(error) as raised:
            rewrite_called(
                "run-ash-security-scan.yml", changed, where="copied scan workflow"
            )
        message = str(raised.value)
        line = text.count("\n", 0, start) + 1
        assert UV_CALL_REFUSAL in message, (line, message)
        assert f"names {option} {RELEASE_SOURCE}" in message, (line, message)


def test_a_uv_call_with_its_source_joined_or_after_its_options_is_read():
    """``--from="${ASH_UVX_SOURCE}"`` is the same source, and a ``--reinstall`` after
    ``--from`` still makes its step the one that rebuilds the environment."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    begin = _api("provenance", "PROVENANCE_BEGIN")
    text = _scan_workflow(
        '      - run: uvx --from="${ASH_UVX_SOURCE}" ash dependencies install\n',
        '      - run: uvx --from "${ASH_UVX_SOURCE}" --reinstall ash scan\n',
        f"      - run: {UVX_FROM} ash report\n",
    )
    result = rewrite_called("run-ash-security-scan.yml", text, where="scan workflow")
    steps = _scan_steps(result.text)
    assert [begin in str(s.get("run", "")) for s in steps] == [
        False,
        False,
        True,
        False,
    ]
    assert steps[2].get("if") == "${{ !cancelled() }}"


@pytest.mark.parametrize(
    "steps,printed,after_the_scan",
    [
        (
            (
                f"      - run: {UVX_FROM} ash dependencies install --tool grype\n",
                f"      - run: {UVX_FROM} ash scan --reinstall\n",
            ),
            [False, True, False],
            False,
        ),
        (
            (
                f"      - run: {UVX_FROM} ash dependencies install --tool grype\n",
                f"      - run: {UVX_REINSTALL} ash scan\n",
                f"      - run: {UVX_FROM} ash report --reinstall\n",
            ),
            [False, False, True, False],
            True,
        ),
    ],
    ids=[
        "the command's --reinstall in a workflow that rebuilds nothing",
        "the command's --reinstall after the scan's own",
    ],
)
def test_a_reinstall_given_to_the_command_a_uvx_call_runs_rebuilds_nothing(
    steps, printed, after_the_scan
):
    """``--reinstall`` rebuilds the environment only as an option of uvx itself,
    before the command it runs; after ``ash`` it is ash's own argument, so it neither
    makes its step the scan nor a second step that rebuilds."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    begin = _api("provenance", "PROVENANCE_BEGIN")
    text = _scan_workflow(*steps)
    result = rewrite_called("run-ash-security-scan.yml", text, where="scan workflow")
    result_steps = _scan_steps(result.text)
    assert [begin in str(s.get("run", "")) for s in result_steps] == printed
    condition = result_steps[printed.index(True)].get("if")
    assert (condition == "${{ !cancelled() }}") is after_the_scan, condition


def test_a_scan_workflow_s_read_only_commands_are_kept():
    """The control for the rules below: a step on one of the actions the real workflow
    pins, a read of a uv setting, ASH's output directory named in a path, a uv run
    call, and a uv call whose own argument spans a quoted line break."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    begin = _api("provenance", "PROVENANCE_BEGIN")
    lines = (
        "printf '%s\\n' \"$UV_CACHE_DIR\"",
        "cp -r .ash/ash_output reports",
        "uv run --with \"${ASH_UVX_SOURCE}\" python -c 'print(1)'",
        f'{UVX_FROM} ash report --output-dir "out',
        'dir"',
        SCAN_LINE,
    )
    text = _scan_workflow(
        "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n",
        f"      - run: {UVX_FROM} ash dependencies install --tool grype\n",
        _script_step(*lines),
    )
    result = rewrite_called("run-ash-security-scan.yml", text, where="scan workflow")
    steps = _scan_steps(result.text)
    assert [begin in str(s.get("run", "")) for s in steps] == [
        False,
        False,
        False,
        True,
    ]


#: How the scan workflow's check names a word of ash or of an installer that stands
#: anywhere but as the command of a uv call.
OUTSIDE_A_UV_CALL = "other than as the command of a uvx or uv run call"


@pytest.mark.parametrize(
    "line,named",
    [
        ('X="a b" ash --version', "runs ash other than through uvx"),
        ('X="a;b" ash --version', "runs ash other than through uvx"),
        ("timeout 10m ash --version", OUTSIDE_A_UV_CALL),
        ("sudo -u runner ash --version", OUTSIDE_A_UV_CALL),
        ("env -u FOO ash --version", OUTSIDE_A_UV_CALL),
        (f"env -C /tmp uv tool install {RELEASE_SOURCE}", OUTSIDE_A_UV_CALL),
        ("exec -a name ash --version", OUTSIDE_A_UV_CALL),
        ("eval ash --version", OUTSIDE_A_UV_CALL),
        ("setsid ash --version", OUTSIDE_A_UV_CALL),
        ("a\\sh --version", "runs ash other than through uvx"),
        ('"a"sh --version', "runs ash other than through uvx"),
        (f"u\\v tool install {RELEASE_SOURCE}", "runs uv tool install"),
        ("true & ash --version", "runs ash other than through uvx"),
        ("true |& ash --version", "runs ash other than through uvx"),
        (
            (
                f'{UVX_FROM} ash scan --output-dir "$(X="a b" pip install '
                f'{RELEASE_SOURCE})"'
            ),
            "runs pip install",
        ),
        (
            f'{UVX_FROM} ash scan --output-dir "$(echo pip install {RELEASE_SOURCE})"',
            OUTSIDE_A_UV_CALL,
        ),
        (f"X='`' uv `true` tool install {RELEASE_SOURCE}", "runs uv `true`"),
        ("uv --version", OUTSIDE_A_UV_CALL),
        ("uv cache dir", OUTSIDE_A_UV_CALL),
        ("pip --version", OUTSIDE_A_UV_CALL),
        ("pip list", OUTSIDE_A_UV_CALL),
        ("pipx list", OUTSIDE_A_UV_CALL),
        ("uv --quiet tool --offline list", OUTSIDE_A_UV_CALL),
        ('uv -qn --cache-dir "$RUNNER_TEMP/uv-cache" cache dir', OUTSIDE_A_UV_CALL),
        (
            'pip --disable-pip-version-check --cache-dir "$RUNNER_TEMP/pip-cache" list',
            OUTSIDE_A_UV_CALL,
        ),
        ('uv --cache-dir "$RUNNER_TEMP/uv-cache" --version', OUTSIDE_A_UV_CALL),
    ],
    ids=[
        "an assignment with a quoted blank before ash",
        "an assignment with a quoted semicolon before ash",
        "ash after timeout and its duration",
        "ash after sudo -u and a user",
        "ash after env -u and a name",
        "uv tool install after env -C and a directory",
        "ash after exec -a and a name",
        "ash after eval",
        "ash after setsid",
        "ash with a backslash in its name",
        "ash with a quoted part of its name",
        "uv with a backslash in its name",
        "ash after a background command",
        "ash after a pipe of both streams",
        "pip inside an argument of a uvx call",
        "pip printed inside an argument of a uvx call",
        # The command check refuses it first, once it reads the backquote in single
        # quotes as a character; the word check refuses it when it does not.
        "uv tool install after a backquote in single quotes",
        "uv --version",
        "uv cache dir",
        "pip --version",
        "pip list",
        "pipx list",
        "uv with global flags before and inside a group",
        "uv with clustered flags and a global option's value",
        "pip with general options before its command",
        "uv with a global option's value and no command",
    ],
)
def test_a_scan_workflow_line_that_names_ash_or_an_installer_is_refused(line, named):
    """Every word of ash or of an installer in the real workflow's scripts is the
    command of a uvx or uv run call, or text an echo or printf prints, so any other
    one is refused, wherever it stands and however it is quoted. A word glued from
    quoted parts, or after an assignment
    with a quoted value, is read as the command name bash reads; a word the checks do
    not read as one can still be one to bash (after a prefix that takes a value, or
    after eval); and a command that installs nothing is refused with the rest."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    text = _scan_workflow(
        f"      - run: {UVX_FROM} ash dependencies install --tool grype\n",
        _script_step(line, SCAN_LINE),
    )
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", text, where="copied scan workflow")
    message = str(raised.value)
    assert "copied scan workflow" in message and named in message, message


@pytest.mark.parametrize(
    "steps,job_env,workflow_env,named",
    [
        (
            (_script_step(f"uv tool install {RELEASE_SOURCE}", "ash --version"),),
            "",
            "",
            "runs uv tool install",
        ),
        ((_script_step("ash --version"),), "", "", "runs ash other than through uvx"),
        ((_script_step(f"pip install {RELEASE_SOURCE}"),), "", "", "runs pip install"),
        (
            (_script_step(f"python -m pip install {RELEASE_SOURCE}"),),
            "",
            "",
            "runs pip install",
        ),
        (
            (_script_step(f"pipx install {RELEASE_SOURCE}"),),
            "",
            "",
            "runs pipx install",
        ),
        (
            (_script_step(f"uv pip install --system {RELEASE_SOURCE}"),),
            "",
            "",
            "runs uv pip install",
        ),
        (
            (
                (
                    "      - env:\n          UV_OVERRIDE: overrides.txt\n"
                    f"        run: {SCAN_LINE}\n"
                ),
            ),
            "",
            "",
            "the job ash or one of its steps sets UV_OVERRIDE",
        ),
        ((SCAN_STEP,), "", "  UV_CONSTRAINT: constraints.txt\n", "sets UV_CONSTRAINT"),
        (
            (_script_step("export UV_OVERRIDE=overrides.txt", SCAN_LINE),),
            "",
            "",
            "in a script of the job ash, sets a UV_ variable",
        ),
        (
            (SCAN_STEP,),
            "    container: python:3.12\n",
            "",
            "the job ash sets container",
        ),
        (
            (SCAN_STEP,),
            (
                "    container:\n      image: python:3.12\n      env:\n"
                f"        ASH_UVX_SOURCE: {RELEASE_SOURCE}\n"
            ),
            "",
            "the job ash sets container",
        ),
        (
            (SCAN_STEP,),
            "    services:\n      cache:\n        image: redis:7\n",
            "",
            "the job ash sets services",
        ),
        (
            (_script_step(f"pip --cache-dir list install {RELEASE_SOURCE}"),),
            "",
            "",
            "runs pip install",
        ),
        (
            (_script_step(f"pip --cach list install {RELEASE_SOURCE}"),),
            "",
            "",
            "cannot tell what",
        ),
        (
            (
                _script_step(
                    f"uv --cache-dir venv pip install --system {RELEASE_SOURCE}"
                ),
            ),
            "",
            "",
            "runs uv pip install",
        ),
        (
            (
                _script_step(
                    f"uv pip --cache-dir list install --system {RELEASE_SOURCE}"
                ),
            ),
            "",
            "",
            "runs uv pip install",
        ),
        (
            (_script_step(f"pipx --index-url list install {RELEASE_SOURCE}"),),
            "",
            "",
            "cannot tell what",
        ),
        (
            (
                _script_step(
                    f"uv --preview-features venv pip install --system {RELEASE_SOURCE}"
                ),
            ),
            "",
            "",
            "cannot tell what",
        ),
        (
            (_script_step(f"pip -x list install {RELEASE_SOURCE}"),),
            "",
            "",
            "cannot tell what",
        ),
        (
            ("      - uses: some-org/run-ash-action@v1\n", SCAN_STEP),
            "",
            "",
            "uses some-org/run-ash-action@v1, an action other than",
        ),
        (
            ("      - uses: actions/checkout@v7\n", SCAN_STEP),
            "",
            "",
            "uses actions/checkout@v7, an action other than",
        ),
        (
            ("      - uses: actions/checkout@main\n", SCAN_STEP),
            "",
            "",
            "uses actions/checkout@main, an action other than",
        ),
        (
            (f"      - uses: actions/checkout@{OTHER[:7]}\n", SCAN_STEP),
            "",
            "",
            f"uses actions/checkout@{OTHER[:7]}, an action other than",
        ),
        (
            (f"      - uses: someone/checkout@{OTHER}\n", SCAN_STEP),
            "",
            "",
            f"uses someone/checkout@{OTHER}, an action other than",
        ),
        (
            (f"      - uses: actions/cache/other@{OTHER}\n", SCAN_STEP),
            "",
            "",
            f"uses actions/cache/other@{OTHER}, an action other than",
        ),
        (
            ("      - uses: ./.github/actions/scan\n", SCAN_STEP),
            "",
            "",
            "uses ./.github/actions/scan, an action other than",
        ),
        (
            (SCAN_STEP,),
            "    uses: ./.github/workflows/other.yml\n",
            "",
            "the job ash uses ./.github/workflows/other.yml",
        ),
        (
            (
                _script_step(
                    f'uv run --with "${{ASH_UVX_SOURCE}}" pip install {RELEASE_SOURCE}'
                ),
            ),
            "",
            "",
            "runs pip through uv run",
        ),
        (
            (
                _script_step(
                    'uv run --with "${ASH_UVX_SOURCE}" uv tool install --force '
                    + RELEASE_SOURCE
                ),
            ),
            "",
            "",
            "runs uv through uv run",
        ),
        (
            (_script_step(f"{UVX_FROM} pip install ash-plugin-example"),),
            "",
            "",
            "runs pip through uvx",
        ),
        (
            (
                _script_step(
                    'uv run --no-project --with "${ASH_UVX_SOURCE}" -- pip install '
                    + RELEASE_SOURCE
                ),
            ),
            "",
            "",
            "runs pip through uv run",
        ),
        (
            (_script_step("pip config set install.target /opt/other"),),
            "",
            "",
            "runs pip config",
        ),
    ],
    ids=[
        "ash from uv tool install",
        "ash with no uvx",
        "pip install of a release",
        "python -m pip install of a release",
        "pipx install of a release",
        "uv pip install of a release",
        "a uv setting in a step's env",
        "a uv setting in the workflow's env",
        "a uv setting exported in a script",
        "a job container",
        "a job container with its own env",
        "a job's services",
        "pip install after an option whose value is a read-only command",
        "pip install after a shortened option",
        "uv pip install after a global option's value",
        "uv pip install after a global option inside the group",
        "pipx after an option it is not known to take",
        "uv pip install after a global option its help does not list",
        "pip after a short option it is not known to take",
        "a step on another action",
        "a step on a pinned action at a tag",
        "a step on a pinned action at a branch",
        "a step on a pinned action at a short commit",
        "a step on an action of another owner by a pinned action's name",
        "a step on another action of a pinned action's repository",
        "a step on a local action",
        "a job that calls another workflow",
        "pip as the command uv run runs",
        "uv tool install as the command uv run runs",
        "pip as the command uvx runs",
        "pip after -- as the command uv run runs",
        "a pip setting written by pip config set",
    ],
)
def test_a_scan_workflow_that_could_run_another_ash_is_refused(
    steps, job_env, workflow_env, named
):
    """The scan workflow runs ASH only through ``uvx --from "${ASH_UVX_SOURCE}"``: an
    ``ash`` run any other way, another installer, also as the command a uvx or uv run
    call runs, a uv setting that changes what a call resolves, and a container or
    services whose image and env no check reads are each refused. The real workflow
    has none of them (its own tests are the control)."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    grype = f"      - run: {UVX_FROM} ash dependencies install --tool grype\n"
    text = _scan_workflow(grype, *steps, job_env=job_env, workflow_env=workflow_env)
    assert isinstance(_scan_steps(text), list), "the workflow parses"
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", text, where="copied scan workflow")
    message = str(raised.value)
    assert "copied scan workflow" in message and named in message, message


@pytest.mark.parametrize(
    "pin", [OTHER, OTHER.upper()], ids=["lower case", "upper case"]
)
def test_a_bump_of_the_scan_workflow_s_action_pins_is_kept(pin):
    """A pin bump (Dependabot's or Renovate's) moves an action the workflow uses to
    another full commit SHA, the form the repository's own pinning check takes, and
    needs no change to the checks; the same action at a tag is refused, since a tag
    can move."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    text = SCAN_WORKFLOW.read_text(encoding="utf-8")
    pins = re.findall(r"uses: ([\w./-]+)@([0-9a-f]{40})", text)
    assert len(pins) >= 10, pins
    bumped = re.sub(r"(uses: [\w./-]+@)[0-9a-f]{40}", lambda m: m[1] + pin, text)
    assert bumped.count(f"@{pin}") == len(pins), "every pin was bumped"
    result = rewrite_called("run-ash-security-scan.yml", bumped, where="bumped")
    # The bumped artifact actions are swapped to the v4 pins as any ref is; the
    # bump of every other pin is kept.
    assert [a.rule for a in result.applied] == [
        "artifact-actions",
        "artifact-actions",
        "called-provenance",
    ]
    name, sha = pins[0]
    tagged = text.replace(f"{name}@{sha}", f"{name}@v1", 1)
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", tagged, where="tagged")
    assert f"uses {name}@v1, an action other than" in str(raised.value)
    # The two artifact actions are swapped to their pinned releases before the checks
    # run, so the pin check reads the workflow as given: a tag or a branch on either is
    # refused as on any other action, not passed because the swap pinned it.
    upload = re.search(r"uses: (actions/upload-artifact)@([0-9a-f]{40})", text)
    assert upload, "the scan workflow uploads an artifact"
    for ref in ("v4", "main"):
        moved = text.replace(f"{upload[1]}@{upload[2]}", f"{upload[1]}@{ref}", 1)
        with pytest.raises(error) as raised:
            rewrite_called("run-ash-security-scan.yml", moved, where="moved")
        assert f"uses {upload[1]}@{ref}, an action other than" in str(raised.value), ref


def _here_document_step(opening: str) -> str:
    return (
        f"      - run: |\n          {opening}\n          ash scan\n          PY\n"
        f"          {SCAN_LINE}\n"
    )


def test_a_quoted_here_document_fed_to_python_is_not_read_as_commands():
    """The body of ``python3 -I - <<'PY'`` is Python's input, as the real workflow's
    helper steps use it, so a line of it that would be a command in a shell (here
    ``ash scan``) is not one. The same body is refused for a shell, for an unquoted
    delimiter, and where a shell is also a word of the command."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    kept = rewrite_called(
        "run-ash-security-scan.yml",
        _scan_workflow(_here_document_step("python3 -I - <<'PY'")),
        where="scan workflow",
    )
    assert [a.rule for a in kept.applied] == ["called-provenance"]
    for opening in ("bash <<'PY'", "python3 -I - <<PY", "bash -s python3 <<'PY'"):
        with pytest.raises(error) as raised:
            rewrite_called(
                "run-ash-security-scan.yml",
                _scan_workflow(_here_document_step(opening)),
                where="scan workflow",
            )
        assert "runs ash other than through uvx" in str(raised.value), opening


def test_a_message_that_names_ash_is_kept_and_a_substitution_in_it_is_read():
    """``echo`` and ``printf`` run nothing they print, so the real workflow's messages
    that say ``ash dependencies install`` pass. A command substitution inside one runs,
    so ``$(ash scan)`` there is refused, and so is the same words in any other
    command."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")

    def run(line: str):
        step = f"      - run: |\n          {line}\n          {SCAN_LINE}\n"
        return rewrite_called(
            "run-ash-security-scan.yml", _scan_workflow(step), where="scan workflow"
        )

    for line in (
        'echo "This ASH installs tools with ash dependencies install --tool."',
        "printf '%s\\n' \"run ash dependencies install\"",
    ):
        assert [a.rule for a in run(line).applied] == ["called-provenance"], line
    for line in (
        'echo "result: $(ash scan)"',
        'timeout 10m ash scan "run ash dependencies install"',
        'grep "ash dependencies install" notes.txt',
    ):
        with pytest.raises(error) as raised:
            run(line)
        assert "ash" in str(raised.value), line


def test_the_yaml_tag_named_env_is_kept_and_an_env_assignment_is_not():
    """A script that writes the YAML tag ``!ENV`` as a string, as the real workflow's
    config step does, passes; ``ENV=./setup.sh`` in the same place is refused."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    tag = f"      - run: |\n          echo '!ENV' > /dev/null\n          {SCAN_LINE}\n"
    kept = rewrite_called(
        "run-ash-security-scan.yml", _scan_workflow(tag), where="scan workflow"
    )
    assert [a.rule for a in kept.applied] == ["called-provenance"]
    assignment = tag.replace("echo '!ENV' > /dev/null", "export ENV=./setup.sh")
    with pytest.raises(error) as raised:
        rewrite_called(
            "run-ash-security-scan.yml",
            _scan_workflow(assignment),
            where="scan workflow",
        )
    assert "names BASH_ENV or ENV" in str(raised.value)


PIN_STEP_HEAD = "      - name: Pin the ASH ref to a commit\n        id: ash-pin\n"
PIN_WRITE = (
    '            echo "ASH_UVX_SOURCE=automated-security-helper[cdk] @ '
    'git+https://github.com/${ASH_REPO}@${COMMIT}"\n'
)
THIRD_WRITER = (
    "      - name: Write the source again\n"
    '        run: echo "ASH_UVX_SOURCE=automated-security-helper==3.7.0" '
    '>> "${GITHUB_ENV}"\n'
)


@pytest.mark.parametrize(
    "edit",
    [
        # The pin step's statement, written for another ref.
        lambda text: text.replace(PIN_WRITE, PIN_WRITE.replace("${COMMIT}", "main")),
        # The same statement in a step with another id.
        lambda text: text.replace(PIN_STEP_HEAD, PIN_STEP_HEAD.replace("ash-pin", "x")),
        # A third step that writes the source.
        lambda text: text.replace(PIN_STEP_HEAD, THIRD_WRITER + PIN_STEP_HEAD),
    ],
    ids=["another ref", "another step id", "a third writer"],
)
def test_only_the_two_steps_that_pin_the_source_may_write_it(edit):
    """The real workflow replaces ASH_UVX_SOURCE through GITHUB_ENV in two steps, by
    id, with the exact statements the rewrite allows them (_SOURCE_WRITERS). A changed
    statement, one in a step with another id, and a further writer are each refused,
    where the real workflow passes."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    text = SCAN_WORKFLOW.read_text(encoding="utf-8")
    assert PIN_STEP_HEAD in text and PIN_WRITE.strip() in text
    changed = edit(text)
    assert changed != text, "the edit changed nothing"
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", changed, where="copied scan")
    message = str(raised.value)
    assert "in a script of the job ash" in message, message
    assert "ASH_UVX_SOURCE" in message, message


@pytest.mark.parametrize(
    "source",
    [
        (
            f'{RELEASE_SOURCE} ; extra == "${{{{ inputs.ash-repo }}}}'
            '${{ inputs.ash-version }}"'
        ),
        (
            "automated-security-helper[cdk] @ git+https://gitlab.example.com/"
            "${{ inputs.ash-repo }}@${{ inputs.ash-version }}"
        ),
        SOURCE_FROM_INPUTS + "#subdirectory=plugins",
    ],
    ids=[
        "a release, with the inputs in a marker",
        "the inputs on another host",
        "a subdirectory of the repository",
    ],
)
def test_a_scan_workflow_source_other_than_the_inputs_form_is_refused(source):
    """Each value names both inputs, and only the scan workflow's own form of them
    installs the ASH the inputs name."""
    rewrite_called = _api("rewrite", "rewrite_called_workflow")
    error = _api("rewrite", "RewriteError")
    assert "inputs.ash-repo" in source and "inputs.ash-version" in source
    text = _scan_workflow(
        f"      - run: {UVX_FROM} ash dependencies install --tool grype\n",
        SCAN_STEP,
        source=source,
    )
    assert _load(text)["env"]["ASH_UVX_SOURCE"] == source, "the value parses as given"
    with pytest.raises(error) as raised:
        rewrite_called("run-ash-security-scan.yml", text, where="copied scan workflow")
    message = str(raised.value)
    assert "copied scan workflow" in message, message
    assert "is not built from the ash-repo and ash-version inputs" in message, message
