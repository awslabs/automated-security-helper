# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No code string or docs page installs ASH, or runs ``ash``, by a bare PyPI name.

Why this file exists
--------------------
ASH installs from git; it is not published to PyPI. The PyPI name
``automated-security-helper`` belongs to an unrelated placeholder project (one
release, version 11.0.2, a wheel with metadata and no code) whose version
outranks every ASH release, and ``ash`` belongs to another unrelated project. A
hint that says ``pip install "automated-security-helper[symbols]"`` therefore
installs that unrelated project instead, and an MCP client entry that
runs ``uvx --with=. ash mcp`` resolves that other ``ash`` as the tool to run.

Three hints of this kind were fixed one at a time before this file existed: the
MCP server's reinstall hint (``cli/mcp/__init__.py``), and the cdk-nag scanner's
log line and ``get_installation_commands`` (``cdk_nag_scanner.py``). Each fix
was local, so the same text kept surviving elsewhere. This gate checks every
place a user reads install advice in one pass.

What it checks
--------------
Every file git tracks under ``automated_security_helper/``, ``docs/``,
``ash-agent-plugins/``, ``skills/``, ``.github/``, ``examples/`` and ``deploy/``
(``node_modules`` never), plus ``README.md``, its template, ``CONTRIBUTING.md``
and ``DEVELOPMENT.md``. Without a checkout it walks the same roots on disk. In
Python files it reads every string expression, docstrings included, and no
comments: comments are where the history of a changed hint belongs, and no user
reads them. What counts as a bare-name install is defined, with its limits, in
``tests/utils/bare_install_names.py``.

The gate is shown able to fail three ways: the matcher is run on the commands
it must report and on the git-URL forms it must accept, a planted copy of the
tree is reported line by line, and a vacuity check proves the walk reads the
files that carried the hints this gate was written for.

What it does not cover
----------------------
The rest of the tree (``scripts/``, ``tests/``, ``Dockerfile`` and other root
files); a sweep of it at the time this gate widened found no install text
there. MCP client configs written as YAML or TOML. Python comments. Hints
assembled at runtime from values that are not module-level constants; the
runtime-hint tests pin those messages as users see them
(``tests/unit/utils/test_ash_install.py``,
``tests/unit/utils/test_symbol_suppressions.py`` and the detect-secrets
behavior tests).
"""

from __future__ import annotations

import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

from tests.utils.bare_install_names import (
    BINARY_SUFFIXES,
    EXPORTED_CONSTANTS,
    find_bare_installs,
    find_in_file,
    normalize,
)
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS, iter_repo_files

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Directories read in full, relative to the repository root.
SCANNED_DIRS = (
    "automated_security_helper",
    "docs",
    "ash-agent-plugins",
    "skills",
    ".github",
    "examples",
    "deploy",
)
#: Single files read in addition.
SCANNED_FILES = ("README.md", "README.md.template", "CONTRIBUTING.md", "DEVELOPMENT.md")
#: Directories never read: build caches and vendored dependency trees, which a
#: checkout's index does not hold either.
_SKIPPED_DIRS = frozenset({"__pycache__", "node_modules"})

GIT_URL = "https://github.com/awslabs/automated-security-helper.git"

#: The example external plugin package, which users copy as a starting point.
EXAMPLE_PYPROJECT = REPO_ROOT / "examples" / "ash_plugins_example" / "pyproject.toml"
#: A poetry dependency on ASH given as a version constraint string, active or
#: commented out. Poetry resolves that from PyPI, where the name is not ASH's.
_VERSION_CONSTRAINT_DEPENDENCY = re.compile(
    r"""^\s*#?\s*["']?automated[-_.]security[-_.]helper["']?\s*=\s*["']""",
    re.IGNORECASE | re.MULTILINE,
)


def _tracked_files(root: Path) -> list[Path] | None:
    """The files git tracks under the scanned roots, or None without a checkout.

    None when ``root`` is not the top of a git work tree (an unpacked sdist, a
    planted tree in a test), or git cannot run there.
    """
    try:
        top = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            timeout=CHILD_TIMEOUT_SECONDS,
        ).stdout.strip()
        if not top or Path(top).resolve() != root.resolve():
            return None
        listed = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--",
                *SCANNED_DIRS,
                *SCANNED_FILES,
            ],
            capture_output=True,
            check=True,
            timeout=CHILD_TIMEOUT_SECONDS,
        ).stdout.decode("utf-8")
    except (OSError, subprocess.CalledProcessError):
        return None
    return [root / name for name in listed.split("\0") if name]


def _walked_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for name in SCANNED_DIRS:
        if (root / name).is_dir():
            files.extend(iter_repo_files(root / name, skip_dirs=_SKIPPED_DIRS))
    files.extend(root / name for name in SCANNED_FILES)
    return files


def _scanned_files(root: Path) -> list[Path]:
    """Every file the gate reads: what git tracks, else everything on disk.

    Reading the index rather than the disk keeps an untracked editor swap file
    or build output from failing the gate on one machine.
    """
    candidates = _tracked_files(root)
    if candidates is None:
        candidates = _walked_files(root)
    return sorted(
        path
        for path in candidates
        if path.is_file()
        and path.suffix.lower() not in BINARY_SUFFIXES
        and not _SKIPPED_DIRS.intersection(path.relative_to(root).parts)
    )


def _offenders(root: Path) -> list[str]:
    return [
        f"{path.relative_to(root).as_posix()}:{line}: {snippet}"
        for path in _scanned_files(root)
        for line, snippet in find_in_file(path)
    ]


@pytest.mark.integration
def test_no_code_or_docs_page_installs_ash_by_a_bare_name():
    offenders = _offenders(REPO_ROOT)
    assert offenders == [], (
        "These lines install ASH, or run `ash`, by a name that PyPI resolves to "
        "an unrelated project. Install from git instead, e.g. "
        f"'automated-security-helper[symbols] @ git+{GIT_URL}@v<version>', "
        "`uvx --from git+<repo>@v<version> ash`, or `uvx --from <checkout> ash` "
        "for a local checkout:\n" + "\n".join(offenders)
    )


@pytest.mark.integration
def test_the_gate_reads_the_files_that_carried_bare_name_hints():
    """A walk that silently read nothing would pass the gate above."""
    scanned = {p.relative_to(REPO_ROOT).as_posix() for p in _scanned_files(REPO_ROOT)}
    expected = {
        "README.md",
        "automated_security_helper/cli/mcp/__init__.py",
        "automated_security_helper/config/config_linter.py",
        "automated_security_helper/plugin_modules/ash_builtin/scanners/cdk_nag_scanner.py",
        "automated_security_helper/plugin_modules/ash_builtin/scanners/detect_secrets_scanner.py",
        "automated_security_helper/utils/symbol_spans.py",
        # The pages that carried hints before the documentation rewrite, under the
        # names the rewrite gave them: the MCP page, the container page, the install
        # page's template and the suppressions page.
        "docs/content/how-to/mcp-server.md",
        "docs/content/how-to/run-in-a-container.md",
        "docs/content/how-to/install.md.template",
        "docs/content/how-to/suppress-findings.md",
        # The roots added after the gate first shipped: plugin bundles, skills,
        # CI workflows, examples and the deploy packages, and the contributor
        # guides.
        "ash-agent-plugins/agentic-coding/transpiler/_base/mcp.json",
        "skills/ash-mcp/SKILL.md",
        ".github/workflows/run-ash-security-scan.yml",
        "examples/ash_plugins_example/pyproject.toml",
        "deploy/cdk-constructs/README.md",
        "CONTRIBUTING.md",
        "DEVELOPMENT.md",
    }
    assert expected <= scanned, sorted(expected - scanned)
    assert not any("/node_modules/" in f"/{name}" for name in scanned)
    assert sum(name.endswith(".py") for name in scanned) > 150
    assert sum(name.endswith(".md") for name in scanned) > 50


# The commands below are the shapes this gate exists to report. Several are the
# exact text that stood in the tree when it was written.
BARE_NAME_INSTALLS = {
    "pip": "pip install automated-security-helper",
    "pip-extra-quoted": 'pip install "automated-security-helper[symbols]"',
    "uv-tool-install-extra": 'uv tool install "automated-security-helper[symbols]"',
    "uvx-distribution-name": "uvx automated-security-helper --mode local --source-dir .",
    "uvx-with-dot-runs-pypi-ash": "uvx --with=. ash mcp",
    "uvx-force-directory-with-dot": "uvx --force --directory=/path/to/ash --with=. ash mcp",
    "prose-extra-hint": "Until it is, they match nothing. Install automated-security-helper[{}]",
    "prose-reinstall-in-code-span": (
        "reinstall ASH (`pip install --force-reinstall automated-security-helper`) "
        "or install the library directly with `pip install detect-secrets`."
    ),
    "pipx": "pipx install automated-security-helper",
    "python-m-pip-pinned": "python3 -m pip install --upgrade automated-security-helper==3.7.1",
    "uv-pip-underscore-spelling": "uv pip install automated_security_helper",
    "pip-mixed-case": "pip install Automated-Security-Helper",
    "pip-extra-and-specifier": "pip install 'automated-security-helper[cdk]>=3'",
    "uv-add": "uv add automated-security-helper",
    "sudo-pip3": "sudo pip3 install automated-security-helper",
    "windows-pip-exe": r"C:\Python312\Scripts\pip.exe install automated-security-helper",
    "line-continuation": "pip install \\\n    automated-security-helper",
    "pip-ash": "pip install ash",
    "uvx-ash": "uvx ash",
    "uvx-ash-at-version": "uvx ash@latest scan",
    "uv-tool-run-ash": "uv tool run ash --help",
    "pipx-run-ash": "pipx run ash scan",
    "uv-tool-install-ash-pinned": "uv tool install ash==0.1.3",
    "uv-run-with-ash": "uv run --with ash ash scan",
    "uvx-with-bare-extra": "uvx --with automated-security-helper[cdk] cdk synth",
    "uvx-from-bare-name": "uvx --from automated-security-helper ash",
    "pipx-run-spec-bare-name": "pipx run --spec automated-security-helper ash",
    "requirements-line": "automated-security-helper==3.7.1",
    "pipenv-install-ash": "pipenv install ash",
    "pipenv-install-distribution-name": "pipenv install automated-security-helper",
    "pipenv-install-extra": "pipenv install 'automated-security-helper[symbols]'",
    "pipenv-install-dev": "pipenv install --dev automated-security-helper",
    "pipenv-run-pip-install": "pipenv run pip install automated-security-helper",
    "uv-add-dev": "uv add --dev ash",
    "uv-add-extra": 'uv add "automated-security-helper[cdk]"',
    "uv-add-optional-group": "uv add --optional scan automated-security-helper",
    "rye-add": "rye add automated-security-helper",
    "rye-add-ash-dev": "rye add --dev ash",
    "rye-add-features": "rye add automated-security-helper --features symbols",
    "rye-install": "rye install automated-security-helper",
    "rye-tools-install": "rye tools install ash",
    "conda-install": "conda install -c conda-forge ash",
    "mamba-install": "mamba install automated-security-helper",
    "micromamba-install": "micromamba install ash",
    "alias-uvx-distribution-name": 'alias ash="uvx automated-security-helper"',
    "alias-uvx-ash": 'alias ash="uvx ash"',
    "alias-uvx-from-bare-name": 'alias ash="uvx --from automated-security-helper ash"',
    "alias-single-quoted": "alias ash='uvx automated-security-helper'",
    "export-command-variable": 'export ASH="uvx automated-security-helper"',
    "uvx-prerelease-package": "uvx --prerelease-package pkg=allow ash mcp",
    # Each of these three is reported by one rule alone: HTML entities decoded,
    # a JSON string array rebuilt, a `\\` continuation joined.
    "html-entities-only": "<code>uvx &quot;ash&quot; mcp</code>",
    "dockerfile-exec-form-uvx": 'RUN ["uvx", "ash", "mcp"]',
    "line-continuation-ash": "pip install \\\n    ash",
    "pip-download": "pip download ash",
    "pip-wheel": "pip wheel automated-security-helper",
    "uv-pip-reinstall-package-and-bare-target": (
        "uv pip install --reinstall-package automated-security-helper "
        "automated-security-helper"
    ),
    "prose-without-install": "Add automated-security-helper[symbols] to your environment",
    "html-code": "<code>pip install automated-security-helper</code>",
    "html-pre": "<pre>pip install automated-security-helper</pre>",
    "html-entity-quotes": "pip install &quot;automated-security-helper[symbols]&quot;",
    "command-substitution": "echo $(pip install automated-security-helper)",
    "pipx-inject": "pipx inject ash-env automated-security-helper",
    "poetry-add": "poetry add automated-security-helper",
    "pdm-add": "pdm add automated-security-helper",
    "dockerfile-exec-form": 'RUN ["pip", "install", "automated-security-helper"]',
    "uvx-link-mode": "uvx --link-mode copy ash mcp",
    "uvx-prerelease": "uvx --prerelease allow automated-security-helper",
    "uvx-color": "uvx --color never ash",
    "uvx-exclude-newer": "uvx --exclude-newer 2026-01-01 ash",
    "uvx-resolution": "uvx --resolution lowest ash",
    "uvx-refresh-package": "uvx --refresh-package ash ash",
    "uvx-env-file": "uvx --env-file .env ash mcp",
    "uvx-config-setting": "uvx -C key=value ash",
    "uv-tool-run-python": "uv tool run --python 3.12 ash",
    "pipx-run-python": "pipx run --python python3.12 ash",
    "pipx-run-pip-args": "pipx run --pip-args='--pre' ash",
    "requirements-bare-name": "automated-security-helper",
    "requirements-compatible-release": "automated-security-helper ~= 3.7",
    "requirements-hash": "automated-security-helper==3.7.1 --hash=sha256:abc",
    "requirements-comment": "automated-security-helper  # ASH",
    "pyproject-dependency": 'dependencies = ["automated-security-helper"]',
    "pyproject-optional-dependency": 'ash = ["automated-security-helper>=3"]',
    "pyproject-array-item": '    "automated-security-helper",',
    "poetry-caret": 'automated-security-helper = "^3.7"',
    "poetry-star": 'automated-security-helper = "*"',
    "mcp-json-env-between": '{"command": "uvx", "env": {"FASTMCP_LOG_LEVEL": "ERROR"}, "args": ["--with=.", "ash", "mcp"]}',
    "mcp-json-type-between": '{"command": "uvx", "type": "stdio", "args": ["ash", "mcp"]}',
    "mcp-json-args-first": '{"args": ["ash", "mcp"], "env": {}, "command": "uvx"}',
    "mcp-json-command-path": '{"command": "/home/u/.local/bin/uvx", "args": ["ash", "mcp"]}',
    "mcp-json-uv-tool-run": '{"command": "uv", "args": ["tool", "run", "ash", "mcp"]}',
    "mcp-json-pipx-run": '{"command": "pipx", "args": ["run", "ash", "mcp"]}',
    "mcp-js-object": "{command: 'uvx', args: ['ash', 'mcp']}",
    "mcp-json-fenced-in-markdown": textwrap.dedent(
        """\
        ```json
        {
          "mcpServers": {
            "ash": {
              "command": "uvx",
              "env": {"FASTMCP_LOG_LEVEL": "ERROR"},
              "args": ["--with=.", "ash", "mcp"]
            }
          }
        }
        ```
        """
    ),
    "mcp-json-with-dot": textwrap.dedent(
        """\
        {
          "mcpServers": {
            "ash": {
              "command": "uvx",
              "args": [
                "--directory=/path/to/your/automated-security-helper",
                "--with=.",
                "ash",
                "mcp"
              ]
            }
          }
        }
        """
    ),
}

# Install forms that resolve to ASH, and text that only looks similar. Several
# are the fixed hints and the documented install commands.
RESOLVING_OR_UNRELATED = {
    "pip-git-url": f"pip install git+{GIT_URL}@v3.7.1",
    "pipx-git-url": f"pipx install git+{GIT_URL}@v3.7.1",
    "uvx-git-url": f"uvx git+{GIT_URL}@v3.7.1 --mode local",
    "direct-reference-quoted": f'pip install "automated-security-helper[symbols] @ git+{GIT_URL}@v3.7.1"',
    "direct-reference-unquoted": f"pip install automated-security-helper[symbols] @ git+{GIT_URL}@v3.7.1",
    "direct-reference-unspaced": f"pip install automated-security-helper[symbols]@git+{GIT_URL}@v3.7.1",
    "prose-direct-reference": f"Install automated-security-helper[symbols] @ git+{GIT_URL}@v3.7.1",
    "uvx-from-equals-git": "uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.7.1 ash mcp",
    "uvx-from-git": f"uvx --from git+{GIT_URL}@v3.7.1 ash --help",
    "uvx-with-direct-reference": f'uvx --with "automated-security-helper[cdk] @ git+{GIT_URL}@v3.7.1" cdk synth',
    "uvx-from-local-checkout": "uvx --directory=/path/to/automated-security-helper --from=. ash mcp",
    "mcp-cli-reinstall-hint": f"pip install --force-reinstall 'git+{GIT_URL}'",
    "cdk-dependencies-hint": "Install them with: ash dependencies install",
    "extra-packages-by-name": "pip install tree-sitter tree-sitter-python",
    "pipx-upgrade-reuses-recorded-spec": "pipx upgrade automated-security-helper",
    "ash-runs-after-install": f"uv tool install git+{GIT_URL}@v3.7.1 && ash --mode local",
    "separate-code-spans": "Run `pip install -e .` and then `ash --help`.",
    "uv-run-project-script": "uv run ash scan",
    "editable-local-extra": "pip install -e '.[symbols]'",
    "local-directory": "pip install ./automated-security-helper",
    "cloned-directory": "pip install automated-security-helper/",
    "image-tag": "docker build --tag automated-security-helper:ci --target ci .",
    "cd-into-clone": "cd automated-security-helper",
    "names-that-contain-ash": "pip install hash flash ashlar ash-plugin-example",
    "spdx-creator": "Tool: automated-security-helper-3.7.1",
    "skills-add": "npx skills add awslabs/automated-security-helper",
    "module-run": "python -m automated_security_helper.cli scan",
    "nix-flake-ref": 'export ASH_NIX_FLAKE_REF="github:awslabs/automated-security-helper/v3.7.1"',
    "workflow-direct-reference": (
        "ASH_UVX_SOURCE: automated-security-helper[cdk] @ "
        "git+https://github.com/${{ inputs.ash-repo }}@${{ inputs.ash-version }}"
    ),
    "requirements-direct-reference": f"automated-security-helper[cdk] @ git+{GIT_URL}@v3.7.1",
    "poetry-git-table": f'automated-security-helper = {{git = "{GIT_URL}", tag = "v3.7.1"}}',
    "poetry-path-table": 'automated-security-helper = {path = "../../", develop = true}',
    "json-name-value": '{"name": "automated-security-helper", "versionInfo": "3.7.1"}',
    "json-analyzer-id": '    "id": "automated-security-helper",',
    "entry-point": 'automated-security-helper = "automated_security_helper.cli.entrypoint:main"',
    "build-include-list": 'include = [ "automated_security_helper", "/Dockerfile",]',
    "default-image-name": '                "automated-security-helper"',
    "ruby-assertion-argument": '    assert_match "automated-security-helper", shell_output("ash --version")',
    "prose-naming-the-project": "automated-security-helper is a security scanner",
    "pipx-inject-into-ash": "pipx inject automated-security-helper tree-sitter-python",
    "pdm-add-direct-reference": f"pdm add 'automated-security-helper @ git+{GIT_URL}@v3.7.1'",
    "dockerfile-exec-form-git": f'RUN ["pip", "install", "git+{GIT_URL}@v3.7.1"]',
    "html-code-git": f"<code>pip install git+{GIT_URL}@v3.7.1</code>",
    "uvx-link-mode-from-git": f"uvx --link-mode copy --from git+{GIT_URL}@v3.7.1 ash mcp",
    "mcp-json-env-between-from-git": (
        '{"command": "uvx", "env": {}, "args": '
        '["--from=git+https://github.com/awslabs/automated-security-helper@v3.7.1", "ash", "mcp"]}'
    ),
    "pipenv-run-project-script": "pipenv run ash scan",
    "pipenv-install-editable-git": f"pipenv install -e git+{GIT_URL}@v3.7.1#egg=automated-security-helper",
    "pipenv-install-direct-reference": f'pipenv install "automated-security-helper[symbols] @ git+{GIT_URL}@v3.7.1"',
    "pipenv-install-local-checkout": "pipenv install -e .",
    "pipenv-install-requirements-file": "pipenv install -r requirements.txt",
    "uv-add-direct-reference": f'uv add "automated-security-helper @ git+{GIT_URL}@v3.7.1"',
    "uv-add-git-url": f"uv add git+{GIT_URL} --tag v3.7.1",
    "uv-add-requirements-file": "uv add -r requirements.txt",
    "rye-add-git": f"rye add automated-security-helper --git {GIT_URL} --tag v3.7.1",
    "rye-add-git-equals": f"rye add automated-security-helper --git={GIT_URL}",
    "rye-add-path": "rye add automated-security-helper --path ../automated-security-helper",
    "rye-install-url": "rye install ash --url https://example.invalid/ash-3.7.1.tar.gz",
    "rye-run-script": "rye run ash scan",
    "conda-install-other": "conda install -c conda-forge python=3.12 nodejs",
    "pip-download-git": f"pip download git+{GIT_URL}@v3.7.1",
    "alias-uvx-git": f'alias ash="uvx git+{GIT_URL}@v3.7.1"',
    "alias-uvx-from-direct-reference": (
        f"alias ash=\"uvx --from 'automated-security-helper[symbols] @ "
        f"git+{GIT_URL}@v3.7.1' ash\""
    ),
    "uv-pip-reinstall-hint": (
        "/opt/ash/bin/python -m uv pip install --python /opt/ash/bin/python "
        f"--reinstall-package automated-security-helper git+{GIT_URL}@0123abcd"
    ),
    "uv-pip-upgrade-package-short": f"uv pip install -P ash git+{GIT_URL}@v3.7.1",
    "mcp-json-uv-run-project": '{"command": "uv", "args": ["run", "--project=/src/ash", "ash", "mcp"]}',
    "mcp-json-from-git": textwrap.dedent(
        """\
        {
          "mcpServers": {
            "ash": {
              "command": "uvx",
              "args": [
                "--from=git+https://github.com/awslabs/automated-security-helper@v3.7.1",
                "ash",
                "mcp"
              ]
            }
          }
        }
        """
    ),
}


@pytest.mark.unit
@pytest.mark.parametrize(
    "text", BARE_NAME_INSTALLS.values(), ids=BARE_NAME_INSTALLS.keys()
)
def test_bare_name_installs_are_reported(text):
    assert find_bare_installs(text), f"not reported: {text!r}"


@pytest.mark.unit
@pytest.mark.parametrize(
    "text", RESOLVING_OR_UNRELATED.values(), ids=RESOLVING_OR_UNRELATED.keys()
)
def test_installs_that_resolve_to_ash_are_not_reported(text):
    assert find_bare_installs(text) == []


# Python source shapes. Each is checked through find_in_file, the gate's own
# reader, so a shape it reports here is one the gate reports in the tree.
PYTHON_BARE_NAME_INSTALLS = {
    # The shape of the cdk-nag scanner's install command before it was fixed.
    "argv-list-with-extra": """
        import sys

        def get_installation_commands():
            return [
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "automated-security-helper[cdk]",
                ]
            ]
        """,
    "argv-list-reinstall": """
        import sys
        CMD = [sys.executable, "-m", "pip", "install", "--force-reinstall", "automated-security-helper"]
        """,
    "argv-uv-tool-install": """
        CMD = ["uv", "tool", "install", "automated-security-helper[symbols]"]
        """,
    "argv-tuple-uvx-with-dot": """
        CMD = ("uvx", "--with=.", "ash", "mcp")
        """,
    "concatenated-name": """
        NAME = "automated-security-helper"
        HINT = "pip install " + NAME
        """,
    "fstring-name": """
        NAME = "automated-security-helper"
        HINT = f"pip install {NAME}[symbols]"
        """,
    "prose-without-install": """
        HINT = "Add automated-security-helper[symbols] to your environment"
        """,
    "percent-format": """
        HINT = "pip install %s" % "automated-security-helper"
        """,
    "str-format": """
        HINT = "{} install automated-security-helper".format("pip")
        """,
    "requirement-literal-alone": """
        REQUIREMENT = "automated-security-helper[cdk]"
        """,
    # ash_install exports the distribution name for building install text; it is
    # only meaningful with a direct reference after it.
    "imported-name-constant": """
        from automated_security_helper.utils.ash_install import ASH_DISTRIBUTION_NAME

        HINT = f"pip install {ASH_DISTRIBUTION_NAME}[symbols]"
        """,
    "imported-name-attribute": """
        from automated_security_helper.utils import ash_install

        HINT = "pip install " + ash_install.ASH_DISTRIBUTION_NAME
        """,
    "imported-name-in-argv": """
        from automated_security_helper.utils.ash_install import ASH_DISTRIBUTION_NAME

        def command(extra):
            return ["pip", "install", f"{ASH_DISTRIBUTION_NAME}[{extra}]"]
        """,
}

PYTHON_RESOLVING_OR_UNRELATED = {
    "distribution-name-constant": """
        ASH_DISTRIBUTION_NAME = "automated-security-helper"
        """,
    "direct-reference-built-from-pieces": """
        ASH_DISTRIBUTION_NAME = "automated-security-helper"

        def requirement(extra, source):
            return f"{ASH_DISTRIBUTION_NAME}[{extra}] @ {source}"
        """,
    "direct-reference-concatenated": f"""
        REQ = "automated-security-helper[symbols]" + " @ git+{GIT_URL}@v3.7.1"
        """,
    "argv-from-metadata": """
        import sys

        def command(requirements):
            return [sys.executable, "-m", "pip", "install", *requirements]
        """,
    "report-analyzer-id": """
        ANALYZER = {"id": "automated-security-helper", "name": "ASH"}
        """,
    "image-name": """
        IMAGE = "automated-security-helper:custom"
        """,
    "imported-name-in-direct-reference": """
        from automated_security_helper.utils.ash_install import ASH_DISTRIBUTION_NAME

        def requirement(extra, source):
            return f"{ASH_DISTRIBUTION_NAME}[{extra}] @ {source}"
        """,
}


@pytest.mark.unit
def test_the_exported_constants_the_matcher_folds_are_the_real_ones():
    """The matcher reads ``ASH_DISTRIBUTION_NAME`` from other modules by value."""
    from automated_security_helper.utils import ash_install

    assert EXPORTED_CONSTANTS == {
        name: getattr(ash_install, name) for name in EXPORTED_CONSTANTS
    }


@pytest.mark.unit
@pytest.mark.parametrize(
    "source",
    PYTHON_BARE_NAME_INSTALLS.values(),
    ids=PYTHON_BARE_NAME_INSTALLS.keys(),
)
def test_python_shapes_are_reported(tmp_path, source):
    path = tmp_path / "shape.py"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    assert find_in_file(path), source


@pytest.mark.unit
@pytest.mark.parametrize(
    "source",
    PYTHON_RESOLVING_OR_UNRELATED.values(),
    ids=PYTHON_RESOLVING_OR_UNRELATED.keys(),
)
def test_python_shapes_that_resolve_or_are_unrelated_are_not_reported(tmp_path, source):
    path = tmp_path / "shape.py"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    assert find_in_file(path) == []


@pytest.mark.integration
def test_a_planted_tree_is_reported_line_by_line(tmp_path):
    """The gate's own walk, run over a planted tree, reports exactly the bad lines."""
    guide = tmp_path / "docs" / "content" / "docs" / "guide.md"
    guide.parent.mkdir(parents=True)
    guide.write_text(
        textwrap.dedent(
            f"""\
            # Guide

            ```bash
            pip install "automated-security-helper[symbols]"
            pip install "automated-security-helper[symbols] @ git+{GIT_URL}@v3.7.1"
            ```

            ```json
            {{
              "command": "uvx",
              "args": [
                "--with=.",
                "ash",
                "mcp"
              ]
            }}
            ```
            """
        ),
        encoding="utf-8",
    )
    hint = tmp_path / "automated_security_helper" / "hint.py"
    hint.parent.mkdir(parents=True)
    hint.write_text(
        textwrap.dedent(
            f'''\
            """Module docstring with nothing to report."""

            # This hint used to read "pip install automated-security-helper[cdk]".
            EXTRA = "symbols"
            MESSAGE = (
                f"Symbol suppressions need the optional '{{EXTRA}}' extra. Install "
                f"automated-security-helper[{{EXTRA}}]"
            )
            FIXED = "automated-security-helper[symbols] @ git+{GIT_URL}@v3.7.1"
            # A bare requirement literal is reported even though HINT completes it.
            REQUIREMENT = f"automated-security-helper[{{EXTRA}}]"
            HINT = f"Install it with: pip install '{{REQUIREMENT}} @ git+{GIT_URL}@v3.7.1'"
            '''
        ),
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text(
        "uvx automated-security-helper\n", encoding="utf-8"
    )
    (tmp_path / "docs" / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\xff\xfe")

    reported = {entry.split(": ", 1)[0] for entry in _offenders(tmp_path)}

    # Line 6 is the first line of MESSAGE's literal; line 10 is the JSON entry's
    # "command"; line 11 is REQUIREMENT, a bare requirement on its own. The
    # comment on line 3, the git requirements and HINT, which folds REQUIREMENT
    # into a direct reference, are not reported.
    assert reported == {
        "README.md:1",
        "automated_security_helper/hint.py:6",
        "automated_security_helper/hint.py:11",
        "docs/content/docs/guide.md:4",
        "docs/content/docs/guide.md:10",
    }


@pytest.mark.integration
def test_planted_lines_for_other_installers_are_reported(tmp_path):
    """pipenv, rye, conda and uv add lines are reported through the gate's own walk."""
    page = tmp_path / "docs" / "content" / "docs" / "installers.md"
    page.parent.mkdir(parents=True)
    page.write_text(
        textwrap.dedent(
            f"""\
            ```bash
            pipenv install ash
            pipenv run ash scan
            pipenv install -e git+{GIT_URL}@v3.7.1#egg=automated-security-helper
            rye add automated-security-helper
            rye add automated-security-helper --git {GIT_URL} --tag v3.7.1
            uv add --dev ash
            uv add "automated-security-helper @ git+{GIT_URL}@v3.7.1"
            conda install -c conda-forge ash
            alias ash="uvx automated-security-helper"
            alias ash="uvx git+{GIT_URL}@v3.7.1"
            ```
            """
        ),
        encoding="utf-8",
    )

    reported = {entry.split(": ", 1)[0] for entry in _offenders(tmp_path)}

    assert reported == {
        "docs/content/docs/installers.md:2",
        "docs/content/docs/installers.md:5",
        "docs/content/docs/installers.md:7",
        "docs/content/docs/installers.md:9",
        "docs/content/docs/installers.md:10",
    }


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
        timeout=CHILD_TIMEOUT_SECONDS,
    )


@pytest.mark.integration
def test_in_a_checkout_only_tracked_files_are_read(tmp_path):
    """An editor's swap file or a build output is not a file the repository ships.

    Before, the gate walked the filesystem, so an untracked ``.swp`` under
    ``docs/`` (not UTF-8) failed it on a developer's machine and nowhere else.
    """
    guide = tmp_path / "docs" / "guide.md"
    guide.parent.mkdir(parents=True)
    guide.write_text("pip install automated-security-helper\n", encoding="utf-8")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "docs/guide.md")
    (tmp_path / "docs" / ".guide.md.swp").write_bytes(b"b0VIM \xff\xfe\x00")
    untracked = tmp_path / "docs" / "notes.md"
    untracked.write_text("uvx ash\n", encoding="utf-8")

    assert _offenders(tmp_path) == [
        "docs/guide.md:1: pip install automated-security-helper"
    ]


@pytest.mark.integration
def test_without_a_checkout_the_walk_skips_dependency_trees(tmp_path):
    """No git (an unpacked sdist, say): every file is read, node_modules excepted."""
    readme = tmp_path / "deploy" / "README.md"
    vendored = tmp_path / "deploy" / "node_modules" / "pkg" / "README.md"
    vendored.parent.mkdir(parents=True)
    readme.write_text("pip install automated-security-helper\n", encoding="utf-8")
    vendored.write_text("pip install automated-security-helper\n", encoding="utf-8")
    bundle = tmp_path / "ash-agent-plugins" / "plugins" / "mcpb" / "ash.mcpb"
    bundle.parent.mkdir(parents=True)
    bundle.write_bytes(b"PK\x03\x04\xff\xfe")
    (tmp_path / "CONTRIBUTING.md").write_text("uvx ash mcp\n", encoding="utf-8")

    assert _offenders(tmp_path) == [
        "CONTRIBUTING.md:1: uvx ash mcp",
        "deploy/README.md:1: pip install automated-security-helper",
    ]


@pytest.mark.integration
def test_a_file_the_gate_cannot_read_fails_it(tmp_path):
    """A text file that is not UTF-8 is an error, not a file skipped unread."""
    page = tmp_path / "docs" / "page.md"
    page.parent.mkdir(parents=True)
    page.write_bytes(b"pip install automated-security-helper \xff\xfe\n")
    with pytest.raises(UnicodeDecodeError):
        _offenders(tmp_path)


@pytest.mark.unit
def test_the_mcp_testing_guide_keeps_the_checkouts_extras():
    """Every ``uv sync`` command line in the guide keeps the developer's extras.

    A plain ``uv sync`` is exact: it removes every package the lockfile's
    default set does not name, so the cdk and symbols extras a developer
    installed are gone after it (measured on a toy project with uv 0.12, which
    also showed ``uv run`` and ``uv sync --inexact`` keeping them). The guide's
    server config uses ``uv run``, so its repair steps must not undo that.
    """
    guide = REPO_ROOT / "docs" / "content" / "docs" / "MCP-SERVER-TESTING-GUIDE.md"
    syncs = [
        line.strip()
        for line in guide.read_text(encoding="utf-8").splitlines()
        if re.match(r"\s*uv sync\b", line)
    ]
    assert syncs, "the guide no longer gives a uv sync step; update this test"
    assert [line for line in syncs if "--inexact" not in line] == [], syncs


@pytest.mark.unit
def test_the_mcp_testing_guide_does_not_call_the_ash_package_warning_harmless():
    """uv's warning about a package named ``ash`` means the unrelated project ran.

    The guide used to call that warning safe to ignore; it now says to switch
    the configuration to ``uv run``.
    """
    guide = REPO_ROOT / "docs" / "content" / "docs" / "MCP-SERVER-TESTING-GUIDE.md"
    lines = guide.read_text(encoding="utf-8").splitlines()
    warning = [
        i for i, line in enumerate(lines) if "is not provided by package `ash`" in line
    ]
    assert warning, "the guide no longer shows uv's warning; update this test"
    for index in warning:
        labels = [line for line in lines[:index] if line.startswith("**")]
        label = labels[-1] if labels else ""
        assert "ignore" not in label.lower(), (index + 1, label)
        after = "\n".join(lines[index : index + 8])
        assert "`uv run`" in after, (index + 1, after)


def _requirement_names(requirements: list[str]) -> list[str]:
    """The PEP 503-normalized project name of each PEP 508 requirement string."""
    return [
        normalize(re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", req).group(1))
        for req in requirements
    ]


@pytest.mark.unit
def test_the_example_plugin_package_declares_no_dependency_on_ash():
    """The example is a ``[project]`` package with no requirement on ASH's name.

    The package is installed into the environment ASH already runs in (its
    README's Installation section), so it names ASH in no dependency list: a
    requirement on ``automated-security-helper`` would be resolved from PyPI,
    where that name is not ASH's. The example used to be a poetry package with a
    path dependency on this checkout and a commented git alternative pinned to
    the packaged release; the pyproject's own comment above ``dependencies``
    now says why neither is declared, and ``[tool.commitizen] version_files``
    accordingly lists nothing to rewrite in it (an entry whose file holds no
    version would fail ``--check-consistency`` at the next release).
    """
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python 3.10
        import tomli as tomllib

    example = tomllib.loads(EXAMPLE_PYPROJECT.read_text(encoding="utf-8"))
    assert "poetry" not in example.get("tool", {}), sorted(example["tool"])
    project = example["project"]
    declared = _requirement_names(project.get("dependencies", []))
    for group, requirements in project.get("optional-dependencies", {}).items():
        declared += [f"{group}:{name}" for name in _requirement_names(requirements)]
    assert not any(
        name.rsplit(":", 1)[-1] in {"automated-security-helper", "ash"}
        for name in declared
    ), declared
    pyproject = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    entries = pyproject["tool"]["commitizen"]["version_files"]
    assert not any(
        entry.startswith("examples/ash_plugins_example/") for entry in entries
    ), entries


@pytest.mark.unit
def test_the_example_plugin_package_says_why_ash_is_not_a_dependency():
    """The pyproject and the README both tell a copier not to add the dependency.

    A user who copies the package as a starting point reads one of the two, and
    the natural edit, ``dependencies = ["automated-security-helper"]``, installs
    PyPI's unrelated project. The README's install commands name the git
    repository or the checkout path instead.
    """
    pyproject_text = EXAMPLE_PYPROJECT.read_text(encoding="utf-8")
    assert re.search(
        r"^#.*\bNo dependency on automated-security-helper\b",
        pyproject_text,
        re.MULTILINE,
    ), pyproject_text
    readme = (EXAMPLE_PYPROJECT.parent / "README.md").read_text(encoding="utf-8")
    assert "declares no dependency on `automated-security-helper`" in readme
    assert GIT_URL in readme
    assert "./examples/ash_plugins_example" in readme


@pytest.mark.unit
def test_the_example_plugin_package_offers_no_version_constraint_on_ash():
    """No line, commented out or not, offers ``automated-security-helper = "*"``.

    A user who uncomments such a line gets PyPI's unrelated project. A git
    alternative is written as a table (``{git = ..., tag = ...}``) and is fine.
    """
    text = EXAMPLE_PYPROJECT.read_text(encoding="utf-8")
    offered = [
        line.strip()
        for line in text.splitlines()
        if _VERSION_CONSTRAINT_DEPENDENCY.match(line)
    ]
    assert offered == []
