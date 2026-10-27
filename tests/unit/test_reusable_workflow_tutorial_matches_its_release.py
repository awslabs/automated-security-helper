# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CI pages show a call of the reusable workflow that the documented release accepts.

Why this file exists
--------------------
docs/content/how-to/ci/github-actions.md and docs/content/getting-started/ci.md show how
to call ``.github/workflows/run-ash-security-scan.yml``, pinned to the release the page
documents (``@v{{VERSION}}`` in the template). GitHub refuses a call that passes an input
the called workflow does not declare, so a copy of the example pinned to a release that
lacks one of the inputs never starts.

The docs publish on every push to main, before a release carries the newest inputs
(``config-ref``, ``config-ref-missing``, ``skip-unknown-tools`` and the ``install-*``
inputs after ``install-opengrep``). The pages handle that by passing only inputs that
v3.7.0 and v3.7.1 declare in their examples, and by naming the gap in the text under the
inputs table. They no longer use a conditional block of the template: the template manager
fills the version placeholders and nothing else.

What this asserts
-----------------
1. The template manager fills ``{{VERSION}}`` in any text and leaves other text alone.
2. Each page rendered for v3.7.0, v3.7.1, v3.7.2, v3.8.0 and v4.0.0 has one example
   calling the workflow, pinned to that version. Every input the example passes is one
   this tree's run-ash-security-scan.yml declares, and for v3.7.0 and v3.7.1 none is one
   the workflow gained after v3.7.1.
3. The inputs table's page says that v3.7.0 and v3.7.1 have fewer inputs.
4. The committed pages, whatever version they document, follow the same rule.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest
import yaml

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_template_manager.py"
INPUTS_PAGE = REPO_ROOT / "docs" / "content" / "how-to" / "ci" / "github-actions.md"
PAGES = [
    pytest.param(INPUTS_PAGE, id="how-to-github-actions"),
    pytest.param(
        REPO_ROOT / "docs" / "content" / "getting-started" / "ci.md",
        id="getting-started-ci",
    ),
]
SCAN_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"
LAST_RELEASE_WITHOUT_THE_INPUTS = (3, 7, 1)
VERSIONS = ["3.7.0", "3.7.1", "3.7.2", "3.8.0", "4.0.0"]
# The inputs this tree's workflow declares and the workflow at the v3.7.1 tag does not
# (the difference of the two `workflow_call.inputs` key sets).
INPUTS_AFTER_THE_LAST_RELEASE_WITHOUT_THEM = frozenset(
    {
        "config-ref",
        "config-ref-missing",
        "skip-unknown-tools",
        "install-actionlint",
        "install-cfn-guard",
        "install-cfn-nag",
        "install-gitleaks",
        "install-trivy",
    }
)


def _manager():
    spec = importlib.util.spec_from_file_location(
        "version_template_manager", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.VersionTemplateManager(REPO_ROOT)


def _render(text: str, version: str) -> str:
    return _manager().render(text, version)


def _template(page: Path) -> str:
    return page.with_name(page.name + ".template").read_text(encoding="utf-8")


def _packaged_version() -> str:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["tool"]["commitizen"]["version"]


def _release(version: str) -> tuple[int, int, int]:
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    assert match, version
    return tuple(int(part) for part in match.groups())


def _declared_inputs() -> set[str]:
    workflow = yaml.safe_load(SCAN_WORKFLOW.read_text(encoding="utf-8"))
    # YAML 1.1 reads the key `on` as the boolean True.
    triggers = workflow.get("on", workflow.get(True))
    return set(triggers["workflow_call"]["inputs"])


def _accepted_inputs(version: str) -> set[str]:
    """The inputs a call pinned to version can pass."""
    declared = _declared_inputs()
    if _release(version) <= LAST_RELEASE_WITHOUT_THE_INPUTS:
        return declared - INPUTS_AFTER_THE_LAST_RELEASE_WITHOUT_THEM
    return declared


def _call(doc: str) -> dict:
    """The job of the page's one example that calls run-ash-security-scan.yml."""
    blocks = re.findall(r"```yaml\n(.*?)```", doc, re.DOTALL)
    found = [b for b in blocks if "run-ash-security-scan.yml@" in b]
    assert len(found) == 1, (
        f"expected one example calling the workflow, found {len(found)}"
    )
    jobs = yaml.safe_load(found[0])["jobs"].values()
    (job,) = [j for j in jobs if "run-ash-security-scan.yml@" in j.get("uses", "")]
    return job


def _check_the_call(doc: str, version: str) -> None:
    job = _call(doc)
    assert job["uses"].endswith(f"run-ash-security-scan.yml@v{version}"), job["uses"]
    assert job["with"]["ash-version"] == f"v{version}"
    unknown = sorted(set(job["with"]) - _accepted_inputs(version))
    assert not unknown, (
        f"the example for v{version} passes inputs that release's "
        f"run-ash-security-scan.yml does not declare: {unknown}"
    )


class TestTheTemplateManagerFillsThePlaceholder:
    def test_the_placeholder_becomes_the_version_in_any_text(self):
        assert _render("a {{VERSION}}\n", "main") == "a main\n"
        assert _render("@v{{VERSION}}\n", "3.8.0rc1") == "@v3.8.0rc1\n"

    def test_text_without_a_placeholder_is_unchanged(self):
        assert _render("plain\n", "not a version") == "plain\n"


class TestTheCIPagesMatchTheReleaseTheyDocument:
    @pytest.mark.parametrize("page", PAGES)
    @pytest.mark.parametrize("version", VERSIONS)
    def test_the_example_is_pinned_to_the_release_and_passes_inputs_it_declares(
        self, page, version
    ):
        _check_the_call(_render(_template(page), version), version)

    @pytest.mark.parametrize("version", VERSIONS)
    def test_the_inputs_page_says_the_first_two_releases_have_fewer(self, version):
        doc = _render(_template(INPUTS_PAGE), version)
        assert "v3.7.0 and v3.7.1 has fewer inputs" in doc, (
            "the page does not say that v3.7.0 and v3.7.1 lack inputs the table lists"
        )
        assert all(name in doc for name in INPUTS_AFTER_THE_LAST_RELEASE_WITHOUT_THEM)

    @pytest.mark.parametrize("page", PAGES)
    def test_the_committed_page_follows_the_rule(self, page):
        _check_the_call(page.read_text(encoding="utf-8"), _packaged_version())
