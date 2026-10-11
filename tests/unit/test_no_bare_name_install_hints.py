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
Every file under ``automated_security_helper/`` and ``docs/`` (the MCP testing
guide is ``docs/content/docs/MCP-SERVER-TESTING-GUIDE.md``), plus the root
``README.md`` and its template. In Python files it reads every string literal,
docstrings included, and no comments: comments are where the history of a
changed hint belongs, and no user reads them. What counts as a bare-name install
is defined, with its limits, in ``tests/utils/bare_install_names.py``.

The gate is shown able to fail three ways: the matcher is run on the commands
it must report and on the git-URL forms it must accept, a planted copy of the
tree is reported line by line, and a vacuity check proves the walk reads the
files that carried the hints this gate was written for.

What it does not cover
----------------------
Other directories (``ash-agent-plugins/``, ``skills/``, ``.github/``, and
``examples/`` apart from the plugin example's ``pyproject.toml``, which the last
two tests here check) and MCP client configs written as YAML or TOML. Python
comments. Hints assembled at runtime from pieces that never share a string
literal; the runtime-hint tests pin those messages as users see them
(``tests/unit/utils/test_symbol_suppressions.py`` and the detect-secrets
behavior tests).
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest

from tests.utils.bare_install_names import (
    BINARY_SUFFIXES,
    find_bare_installs,
    find_in_file,
)
from tests.utils.helpers import iter_repo_files

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Directories walked in full, relative to the repository root.
SCANNED_DIRS = ("automated_security_helper", "docs")
#: Single files scanned in addition.
SCANNED_FILES = ("README.md", "README.md.template")

GIT_URL = "https://github.com/awslabs/automated-security-helper.git"

#: The example external plugin package, which users copy as a starting point.
EXAMPLE_PYPROJECT = REPO_ROOT / "examples" / "ash_plugins_example" / "pyproject.toml"
#: A poetry dependency on ASH given as a version constraint string, active or
#: commented out. Poetry resolves that from PyPI, where the name is not ASH's.
_VERSION_CONSTRAINT_DEPENDENCY = re.compile(
    r"""^\s*#?\s*["']?automated[-_.]security[-_.]helper["']?\s*=\s*["']""",
    re.IGNORECASE | re.MULTILINE,
)


def _scanned_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for name in SCANNED_DIRS:
        if (root / name).is_dir():
            files.extend(
                p
                for p in iter_repo_files(
                    root / name, skip_dirs=frozenset({"__pycache__"})
                )
                if p.suffix.lower() not in BINARY_SUFFIXES
            )
    files.extend(root / name for name in SCANNED_FILES if (root / name).is_file())
    return sorted(files)


def _offenders(root: Path) -> list[str]:
    return [
        f"{path.relative_to(root).as_posix()}:{line}: {snippet}"
        for path in _scanned_files(root)
        for line, snippet in find_in_file(path)
    ]


def test_no_code_or_docs_page_installs_ash_by_a_bare_name():
    offenders = _offenders(REPO_ROOT)
    assert offenders == [], (
        "These lines install ASH, or run `ash`, by a name that PyPI resolves to "
        "an unrelated project. Install from git instead, e.g. "
        f"'automated-security-helper[symbols] @ git+{GIT_URL}@v<version>', "
        "`uvx --from git+<repo>@v<version> ash`, or `uvx --from <checkout> ash` "
        "for a local checkout:\n" + "\n".join(offenders)
    )


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
        "docs/content/docs/MCP-SERVER-TESTING-GUIDE.md",
        "docs/content/docs/building-your-own-image.md",
        "docs/content/docs/installation-guide.md.template",
        "docs/content/docs/suppressions.md",
    }
    assert expected <= scanned, sorted(expected - scanned)
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
    "python-m-pip-pinned": "python3 -m pip install --upgrade automated-security-helper==3.7.0",
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
    "requirements-line": "automated-security-helper==3.7.0",
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
    "pip-git-url": f"pip install git+{GIT_URL}@v3.7.0",
    "pipx-git-url": f"pipx install git+{GIT_URL}@v3.7.0",
    "uvx-git-url": f"uvx git+{GIT_URL}@v3.7.0 --mode local",
    "direct-reference-quoted": f'pip install "automated-security-helper[symbols] @ git+{GIT_URL}@v3.7.0"',
    "direct-reference-unquoted": f"pip install automated-security-helper[symbols] @ git+{GIT_URL}@v3.7.0",
    "direct-reference-unspaced": f"pip install automated-security-helper[symbols]@git+{GIT_URL}@v3.7.0",
    "prose-direct-reference": f"Install automated-security-helper[symbols] @ git+{GIT_URL}@v3.7.0",
    "uvx-from-equals-git": "uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.7.0 ash mcp",
    "uvx-from-git": f"uvx --from git+{GIT_URL}@v3.7.0 ash --help",
    "uvx-with-direct-reference": f'uvx --with "automated-security-helper[cdk] @ git+{GIT_URL}@v3.7.0" cdk synth',
    "uvx-from-local-checkout": "uvx --directory=/path/to/automated-security-helper --from=. ash mcp",
    "mcp-cli-reinstall-hint": f"pip install --force-reinstall 'git+{GIT_URL}'",
    "cdk-dependencies-hint": "Install them with: ash dependencies install",
    "extra-packages-by-name": "pip install tree-sitter tree-sitter-python",
    "pipx-upgrade-reuses-recorded-spec": "pipx upgrade automated-security-helper",
    "ash-runs-after-install": f"uv tool install git+{GIT_URL}@v3.7.0 && ash --mode local",
    "separate-code-spans": "Run `pip install -e .` and then `ash --help`.",
    "uv-run-project-script": "uv run ash scan",
    "editable-local-extra": "pip install -e '.[symbols]'",
    "local-directory": "pip install ./automated-security-helper",
    "cloned-directory": "pip install automated-security-helper/",
    "image-tag": "docker build --tag automated-security-helper:ci --target ci .",
    "cd-into-clone": "cd automated-security-helper",
    "names-that-contain-ash": "pip install hash flash ashlar ash-plugin-example",
    "spdx-creator": "Tool: automated-security-helper-3.7.0",
    "skills-add": "npx skills add awslabs/automated-security-helper",
    "module-run": "python -m automated_security_helper.cli scan",
    "nix-flake-ref": 'export ASH_NIX_FLAKE_REF="github:awslabs/automated-security-helper/v3.7.0"',
    "workflow-direct-reference": (
        "ASH_UVX_SOURCE: automated-security-helper[cdk] @ "
        "git+https://github.com/${{ inputs.ash-repo }}@${{ inputs.ash-version }}"
    ),
    "mcp-json-from-git": textwrap.dedent(
        """\
        {
          "mcpServers": {
            "ash": {
              "command": "uvx",
              "args": [
                "--from=git+https://github.com/awslabs/automated-security-helper@v3.7.0",
                "ash",
                "mcp"
              ]
            }
          }
        }
        """
    ),
}


@pytest.mark.parametrize(
    "text", BARE_NAME_INSTALLS.values(), ids=BARE_NAME_INSTALLS.keys()
)
def test_bare_name_installs_are_reported(text):
    assert find_bare_installs(text), f"not reported: {text!r}"


@pytest.mark.parametrize(
    "text", RESOLVING_OR_UNRELATED.values(), ids=RESOLVING_OR_UNRELATED.keys()
)
def test_installs_that_resolve_to_ash_are_not_reported(text):
    assert find_bare_installs(text) == []


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
            pip install "automated-security-helper[symbols] @ git+{GIT_URL}@v3.7.0"
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
            FIXED = "automated-security-helper[symbols] @ git+{GIT_URL}@v3.7.0"
            # A fragment that a later literal completes is not a hint by itself.
            REQUIREMENT = f"automated-security-helper[{{EXTRA}}]"
            HINT = f"Install it with: pip install '{{REQUIREMENT}} @ git+{GIT_URL}@v3.7.0'"
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
    # "command". The comment on line 3, the git requirements and the REQUIREMENT
    # fragment are not reported.
    assert reported == {
        "README.md:1",
        "automated_security_helper/hint.py:6",
        "docs/content/docs/guide.md:4",
        "docs/content/docs/guide.md:10",
    }


def test_a_file_the_gate_cannot_read_fails_it(tmp_path):
    """A text file that is not UTF-8 is an error, not a file skipped unread."""
    page = tmp_path / "docs" / "page.md"
    page.parent.mkdir(parents=True)
    page.write_bytes(b"pip install automated-security-helper \xff\xfe\n")
    with pytest.raises(UnicodeDecodeError):
        _offenders(tmp_path)


def test_the_example_plugin_package_depends_on_ash_by_path():
    """The example's live dependency on ASH is a path dependency on this checkout."""
    text = EXAMPLE_PYPROJECT.read_text(encoding="utf-8")
    assert re.search(
        r"^automated-security-helper\s*=\s*\{[^}]*\bpath\s*=", text, re.MULTILINE
    ), text


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
