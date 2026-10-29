# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The install-commands check reports an install command a reader cannot run.

No docs job installs ASH: every install command in the docs is illustrative, so the
runner never runs one, and the CLI check reads only the ``ash`` commands. A command
naming an extra ASH does not have, a Python outside ``requires-python``, a ref that
is not a release, or a uv installer fetched without following its redirect passed
every check. Each rule below gets a planted defect, in every place an install command
is written (a shell block, marked illustrative or not, a CI file, a Jenkinsfile, an
inline code span, a template), and the clean page uses every form a rule allows.

The pages live in tmp_path, with a code tree whose pyproject.toml states the extras and
the supported Pythons, and a docs tree whose pyproject.toml states the release. The
ref forms come from scripts/version_template_manager.py, copied in, as the check reads
them there.

The repository URL and the flake prefix are assembled rather than written, because
tests/unit/test_agent_plugin_ash_version.py reads every pinned install ref in the
repository and would report the planted stale ones here as real.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKS_PATH = REPO_ROOT / "scripts" / "docs_checks.py"
GATE_PATH = REPO_ROOT / "scripts" / "verify_docs_freshness.py"
FENCE = "```"

_REPO = "automated-security-" + "helper"
_URL = f"https://github.com/awslabs/{_REPO}"
_GIT = f"git+{_URL}.git"
_FLAKE = f"github:awslabs/{_REPO}"
_SHA = "0123456789abcdef0123456789abcdef01234567"


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


dc = _load("_ash_docs_checks", CHECKS_PATH)


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _messages(findings) -> list[str]:
    return [str(f) for f in findings]


def _assert_reports(findings, expected: str, line: int | None = None) -> None:
    hits = [f for f in findings if expected in f.message]
    assert hits, (
        f"expected a finding containing {expected!r}, got: {_messages(findings)}"
    )
    if line is not None:
        assert any(f.line == line for f in hits), (
            f"expected line {line}: {_messages(hits)}"
        )


CODE_PYPROJECT = """\
[project]
name = "automated-security-helper"
requires-python = ">=3.10,<3.15"

[project.optional-dependencies]
cdk = ["aws-cdk-lib"]
symbols = ["tree-sitter"]
"""

PLUGIN_PYPROJECT = """\
[project]
name = "a-plugin"
requires-python = ">=3.12"

[project.optional-dependencies]
test = ["pytest"]
"""


@pytest.fixture
def trees(tmp_path):
    """(docs root, code root): the release in one, the package metadata in the other."""
    root = tmp_path / "docs"
    code = tmp_path / "code"
    _write(root, "pyproject.toml", '[tool.commitizen]\nversion = "3.7.0"\n')
    _write(
        root,
        dc.TEMPLATE_MANAGER,
        (REPO_ROOT / dc.TEMPLATE_MANAGER).read_text(encoding="utf-8"),
    )
    _write(code, "pyproject.toml", CODE_PYPROJECT)
    _write(code, "tools/plugin/pyproject.toml", PLUGIN_PYPROJECT)
    return root, code


def _check(trees, text: str, rel: str = "docs/page.md", counts=None):
    root, code = trees
    page = _write(root, rel, text)
    return dc.check_install_commands([page], root, code=code, counts=counts)


CLEAN = f"""# Install

{FENCE}bash
curl -LsSf https://astral.sh/uv/install.sh | sh
curl -sSfL https://astral.sh/uv/0.9.0/install.sh | UV_INSTALL_DIR="$HOME/bin" sh
curl --proto '=https' --location https://astral.sh/uv/install.sh -o install.sh
uv tool install --python 3.12 '{_REPO}[cdk] @ {_GIT}@v3.7.0'
uvx --python 3.14 --from '{_REPO}[cdk,symbols] @ {_GIT}@main' ash --version
pipx install --python python3.10 '{_REPO}[CDK] @ {_GIT}@{_SHA}'
pip install "{_REPO} @ {_GIT}@v3.7.0"
uv sync --python 3.12 --extra cdk --extra symbols
uv sync --project tools/plugin --extra test --python 3.13
uv run --extra=cdk mypy automated_security_helper/
git clone --depth 1 --branch v3.7.0 {_URL}.git
git clone {_URL}.git --branch main
git ls-remote {_URL} refs/tags/v3.7.0 refs/heads/main
ash build-image --ash-revision-to-install v3.7.0
export ASH_NIX_FLAKE_REF={_FLAKE}/main
uv run python scripts/docs_versions.py deploy --ref refs/tags/v0.0.1 --branch docs-preview
uv tool install --python 3.9 some-other-tool
git clone --branch v1.0 https://github.com/example/other.git
{FENCE}

<!-- doctest: illustrative reason="installs from GitHub over the network" -->
{FENCE}bash
uv tool install '{_REPO}[symbols] @ {_GIT}@v3.7.0'
{FENCE}

`@v3` is a floating tag: it moves to each new 3.x release.

{FENCE}bash
uvx --from '{_GIT}@v3' ash --version
{FENCE}

<!-- doctest: config kind=github-actions -->
{FENCE}yaml
jobs:
  ash:
    uses: awslabs/{_REPO}/.github/workflows/run-ash-security-scan.yml@v3.7.0
    with:
      ash-version: v3.7.0
  install:
    runs-on: ubuntu-latest
    env:
      INSTALL_SPEC: "{_REPO}[cdk] @ {_GIT}@v3.7.0"
    steps:
      - uses: actions/checkout@v4
      - run: pip install "$INSTALL_SPEC" && uv tool install --python 3.12 x
{FENCE}

<!-- doctest: config kind=pre-commit -->
{FENCE}yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: end-of-file-fixer
  - repo: {_URL}
    rev: v3.7.0
    hooks:
      - id: ash-simple-scan
{FENCE}

{FENCE}groovy
pipeline {{
  environment {{
    INSTALL_SPEC = '{_REPO}[cdk] @ {_GIT}@v3.7.0'
  }}
  stages {{ stage('ASH') {{ steps {{ sh 'pip install "$INSTALL_SPEC"' }} }} }}
}}
{FENCE}

Install it with `uv tool install --python 3.12 '{_REPO}[cdk] @ {_GIT}@v3.7.0'`, or
pin `{_FLAKE}/{_SHA}`. A pin is written `{_REPO}.git@v<version>`, or `@$REF` in a
script, and a template writes `{_REPO}.git@v{{{{VERSION}}}}`.
"""


def _pin(ref: str) -> str:
    return f"{FENCE}bash\nuv tool install '{_REPO} @ {_GIT}@{ref}'\n{FENCE}\n"


DEFECTS = [
    # Extras
    (
        "extra in a spec",
        f"{FENCE}bash\nuv tool install '{_REPO}[nosuchextra] @ {_GIT}@v3.7.0'\n{FENCE}\n",
        "ASH has no extra 'nosuchextra'",
        2,
    ),
    (
        "second extra in a spec",
        f"{FENCE}bash\npip install '{_REPO}[cdk,symbol] @ {_GIT}@v3.7.0'\n{FENCE}\n",
        "ASH has no extra 'symbol'",
        2,
    ),
    (
        "--extra",
        f"{FENCE}bash\nuv sync --extra cdk --extra nosuchextra\n{FENCE}\n",
        "has no extra 'nosuchextra'",
        2,
    ),
    (
        "--extra= on another project",
        f"{FENCE}bash\nuv run --project tools/plugin --extra=cdk pytest\n{FENCE}\n",
        "tools/plugin/pyproject.toml has no extra 'cdk'",
        2,
    ),
    (
        "local project extra",
        "Install with `pip install -e '.[dev]'` from the repository root.\n",
        "has no extra 'dev'",
        1,
    ),
    (
        "extra in a CI env",
        (
            f"<!-- doctest: config kind=gitlab-ci -->\n{FENCE}yaml\nscan:\n  variables:\n"
            f'    INSTALL_SPEC: "{_REPO}[cdk,nosuchextra] @ {_GIT}@v3.7.0"\n{FENCE}\n'
        ),
        "ASH has no extra 'nosuchextra'",
        5,
    ),
    (
        "extra in a Jenkinsfile",
        f"{FENCE}groovy\nenvironment {{\n  SPEC = '{_REPO}[nosuchextra] @ {_GIT}@v3.7.0'\n}}\n{FENCE}\n",
        "ASH has no extra 'nosuchextra'",
        3,
    ),
    # Pythons
    (
        "--python below",
        f"{FENCE}bash\nuv tool install --python 3.9 '{_REPO} @ {_GIT}@v3.7.0'\n{FENCE}\n",
        "--python 3.9 is outside ASH's requires-python >=3.10,<3.15",
        2,
    ),
    (
        "--python above",
        f"{FENCE}bash\nuvx --python=3.15 --from '{_GIT}@v3.7.0' ash --version\n{FENCE}\n",
        "--python=3.15 is outside",
        2,
    ),
    (
        "pipx --python",
        f"{FENCE}bash\npipx install --python python3.9 '{_REPO} @ {_GIT}@v3.7.0'\n{FENCE}\n",
        "--python python3.9 is outside",
        2,
    ),
    (
        "uv sync --python",
        f"{FENCE}bash\nuv sync --python 3.9 --extra cdk\n{FENCE}\n",
        "--python 3.9 is outside",
        2,
    ),
    (
        "uv -p",
        f"{FENCE}bash\nuv venv -p 3.9\n{FENCE}\n",
        "-p 3.9 is outside",
        2,
    ),
    (
        "--python on another project",
        f"{FENCE}bash\nuv sync --project tools/plugin --python 3.11\n{FENCE}\n",
        "outside tools/plugin/pyproject.toml's requires-python >=3.12",
        2,
    ),
    # Refs
    ("ref that does not exist", _pin("v9.9.9"), "names v9.9.9", 2),
    ("stale release", _pin("v3.6.0"), "names v3.6.0", 2),
    ("a branch", _pin("develop"), "names develop", 2),
    ("a short SHA", _pin("0123456"), "names 0123456", 2),
    ("an unexplained floating tag", _pin("v3"), "names v3", 2),
    (
        "git clone --branch",
        f"{FENCE}bash\ngit clone --branch v3.6.0 {_URL}.git\n{FENCE}\n",
        "names v3.6.0",
        2,
    ),
    (
        "ls-remote refs/tags",
        f"{FENCE}bash\ngit ls-remote {_URL} refs/tags/v3.6.0\n{FENCE}\n",
        "names v3.6.0",
        2,
    ),
    (
        "ls-remote refs/heads",
        f"{FENCE}bash\ngit ls-remote {_URL} refs/heads/develop\n{FENCE}\n",
        "names develop",
        2,
    ),
    (
        "--ash-revision-to-install",
        f"{FENCE}bash\nash build-image --ash-revision-to-install v3.6.0\n{FENCE}\n",
        "names v3.6.0",
        2,
    ),
    (
        "flake ref",
        f"{FENCE}bash\nexport ASH_NIX_FLAKE_REF={_FLAKE}/v3.6.0\n{FENCE}\n",
        "names v3.6.0",
        2,
    ),
    (
        "pre-commit rev",
        (
            f"<!-- doctest: config kind=pre-commit -->\n{FENCE}yaml\nrepos:\n"
            f"  - repo: {_URL}\n    rev: v3.6.0\n    hooks:\n      - id: ash-simple-scan\n{FENCE}\n"
        ),
        "names v3.6.0",
        5,
    ),
    (
        "uses:",
        (
            f"<!-- doctest: config kind=github-actions -->\n{FENCE}yaml\njobs:\n  ash:\n"
            f"    uses: awslabs/{_REPO}/.github/workflows/x.yml@v3.6.0\n{FENCE}\n"
        ),
        "names v3.6.0",
        5,
    ),
    (
        "ash-version:",
        (
            f"<!-- doctest: config kind=github-actions -->\n{FENCE}yaml\njobs:\n  ash:\n"
            f"    uses: awslabs/{_REPO}/.github/workflows/x.yml@v3.7.0\n"
            f"    with:\n      ash-version: v3.6.0\n{FENCE}\n"
        ),
        "names v3.6.0",
        7,
    ),
    (
        "inline span",
        f"Install it with `uv tool install '{_REPO} @ {_GIT}@v3.6.0'`.\n",
        "names v3.6.0",
        1,
    ),
    # The uv installer
    (
        "curl without -L",
        f"{FENCE}bash\ncurl -sSf https://astral.sh/uv/install.sh | sh\n{FENCE}\n",
        "curl fetches the uv installer without -L",
        2,
    ),
    (
        "curl of a pinned installer without -L",
        f"{FENCE}console\n$ curl -s https://astral.sh/uv/0.9.0/install.sh | sh\n{FENCE}\n",
        "without -L",
        2,
    ),
    # Every form of block
    (
        "illustrative block",
        (
            f'<!-- doctest: illustrative reason="installs from GitHub over the network" -->\n'
            f"{FENCE}bash\nuv tool install '{_REPO}[nosuchextra] @ {_GIT}@v3.7.0'\n{FENCE}\n"
        ),
        "ASH has no extra 'nosuchextra'",
        3,
    ),
    (
        "CI run step",
        (
            f"<!-- doctest: config kind=github-actions -->\n{FENCE}yaml\njobs:\n  a:\n"
            f"    steps:\n      - run: curl -sSf https://astral.sh/uv/install.sh | sh\n{FENCE}\n"
        ),
        "without -L",
        6,
    ),
    (
        "Jenkinsfile sh",
        f"{FENCE}groovy\nsh '''\n  uv tool install --python 3.9 '{_REPO} @ {_GIT}@v3.7.0'\n'''\n{FENCE}\n",
        "--python 3.9 is outside",
        3,
    ),
]


def test_install_commands_pass_every_valid_form(trees):
    counts: dict[str, int] = {}
    assert _check(trees, CLEAN, counts=counts) == []
    assert all(counts.get(rule) for rule in ("extras", "python", "refs", "curl")), (
        counts
    )


@pytest.mark.parametrize(
    "case,text,expected,line", DEFECTS, ids=[c[0] for c in DEFECTS]
)
def test_install_check_can_fail(trees, case, text, expected, line):
    _assert_reports(_check(trees, text), expected, line)


def test_a_template_is_checked_with_its_placeholders(trees):
    """A template renders {{VERSION}} to the release; a misspelled placeholder is a bad ref."""
    good = (
        f"{FENCE}bash\nuv tool install '{_REPO} @ {_GIT}@v{{{{VERSION}}}}'\n{FENCE}\n"
    )
    assert _check(trees, good, rel="docs/page.md.template") == []
    bad = good.replace("{{VERSION}}", "{{VERISON}}")
    _assert_reports(
        _check(trees, bad, rel="docs/page.md.template"), "names v{{VERISON}}", 2
    )
    release = good.replace("{{VERSION}}", "{{RELEASE}}")
    _assert_reports(
        _check(trees, release, rel="docs/page.md.template"), "names v{{RELEASE}}", 2
    )


def test_a_floating_tag_passes_only_where_the_page_says_it_moves(trees):
    pin = _pin("v3")
    _assert_reports(_check(trees, pin), "names v3")
    explained = "Use `@v3`, the latest 3.x release, if you want updates.\n\n" + pin
    assert _check(trees, explained) == []
    _assert_reports(
        _check(trees, explained.replace("@v3`", "@v4`").replace("@v3'", "@v4'")),
        "names v4",
    )


def test_the_check_reports_checking_nothing(trees):
    _assert_reports(
        _check(trees, "# No install commands\n\nJust prose.\n"), "nothing was checked"
    )


def test_the_real_docs_have_install_commands_for_every_rule():
    """Each rule examines real commands on the live corpus, so none passes vacuously."""
    gate = _load("_ash_docs_gate_for_install", GATE_PATH)
    counts: dict[str, int] = {}
    dc.check_install_commands(gate.collect_md_files(), REPO_ROOT, counts=counts)
    for rule in ("extras", "python", "refs", "curl"):
        assert counts.get(rule, 0) > 0, counts
