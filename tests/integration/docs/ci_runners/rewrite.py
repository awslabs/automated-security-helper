# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The rewrites that make a docs pipeline run the ASH of the pull request under test.

Every pipeline on the CI pages installs a released ASH: an ``INSTALL_SPEC`` naming a
git tag, a call to ASH's reusable workflows at that tag, or a job on an image of ASH.
Run as written, a page's pipeline would test the release. rewrite_pipeline returns the
pipeline file with those replaced, and a record of every change (``.applied``), under
these rules:

``install``
    The release spec becomes install_spec(): the wheel built in the job, with its
    sha256 in the URL fragment. pip checks the file against it, refuses a mismatch,
    and records the hash in the install's direct_url.json without the fragment. uv
    neither checks nor strips it: it records the URL as given, fragment and all, and
    no hash, so the harness hashes the wheel file again after each run. The CodeBuild
    agent has no way to mount the wheel and would scan one left in the source, so it
    takes the head commit of the base repository instead.
``reusable-workflow``
    A call of ``awslabs/automated-security-helper/.github/workflows/<file>`` at the
    release tag becomes a call of the pull request's copy, ``./.github/workflows/<file>``.
``ash-version``
    The scan workflow's ``ash-version`` becomes the head commit, and ``ash-repo`` the
    base repository, on the line after it. The commit is written quoted and followed
    by ``# pragma: allowlist secret``: a forty-digit hex value on a user's own
    workflow line is what detect-secrets reads as a high-entropy string, and the
    pragma is the marker ASH's own files use for a value that is not a secret.
``artifact-actions`` (github-actions)
    ``actions/upload-artifact`` and ``actions/download-artifact`` at any ref become the
    pinned v4 releases (ACT_UPLOAD_ARTIFACT, ACT_DOWNLOAD_ARTIFACT), because act 0.2.89
    cannot take the v6 and later releases' requests (see _rewrite_artifact_actions).
    The page keeps naming the current releases. The same rule runs on the copy of
    run-ash-security-scan.yml a block calls (rewrite_called_workflow), whose own
    artifact steps act serves no better.
``serial-matrix`` (github-actions)
    Every ``strategy:`` with a ``matrix:`` gets ``max-parallel: 1``, because act runs
    the entries of a matrix at once and its action cache races on them (see
    _serialize_matrices).
``image`` (gitlab-ci, circleci)
    A job image becomes its pinned digest from RewriteContext.images. An image the run
    built itself stays. Any other image is an error naming it.
``provenance``
    After each install of ``INSTALL_SPEC``, a command prints the installed
    distribution's direct_url.json between provenance.py's markers: a step of its own
    right after the install step in a GitHub Actions job, the next line in a script,
    the next item in a YAML list of commands. Each record names the job the print is
    in and whether that job has a matrix, so the harness knows how many prints a run
    makes.
``built-provenance`` (gitlab-ci)
    In each job on an image the run builds (RewriteContext.built_images, the
    checkout's ``Dockerfile --target ci``) whose script runs ``ash``, a command right
    before the first one that does prints, from inside the image, the installed ASH's
    version and direct_url.json, the count and a digest of its package files, and the
    sha256 of its METADATA and entry_points.txt
    (provenance.built_provenance_print_command). The image's install records no
    commit, so provenance.built_provenance_problems compares those with the wheel the
    run built from the same checkout. Each record names its job and whether that job
    has a matrix, as the provenance records do.
``report-copy`` (circleci)
    A last step, run whatever happened before it, copies ``.ash/ash_output`` to
    ``<report_mount>/<job>/``, because ``circleci local execute`` discards the project
    directory when the job ends.

The first four, artifact-actions and serial-matrix are string replacements with a
count. provenance,
built-provenance and report-copy insert text at places read from the parsed YAML, and
the result is parsed again to check that each insertion landed where it should.

A block the rewrites cannot follow is an error naming it, rather than a run measured
against an ASH other than the one under test. That is a block with none of the install
forms, no reusable call and no image the run built, and a block that could get ASH from
somewhere else once the rewrite is done:

* a command that installs Python packages and is not one of the two installs of
  INSTALL_SPEC the provenance print follows (``uv tool install "${INSTALL_SPEC}"`` and
  ``<venv>/bin/pip install [flags] "$INSTALL_SPEC"``): such an install with an option
  other than one of its flags, before or after its command, any other install or run by
  pip, uv, uvx or pipx, a project install such as ``uv sync``, ``uv run`` or
  ``pip install .``, and any use of an installer the rewrites do not model (poetry,
  pdm, pipenv, conda, mamba, micromamba, pixi, hatch, rye, easy_install, pip-sync,
  and Homebrew's brew, which installs ASH's formula, other than the queries
  ``brew shellenv``, ``--prefix``, ``config``, ``list``, ``info`` and ``--version``),
  and ``pip config set``, ``unset`` or ``edit``, which writes a setting a later
  install reads;
* an installer line naming the package other than through the rewritten spec, an
  install of the spec with an option that names another package (``--with``,
  ``--from``, ``-e``), any reference to ASH's repository besides that spec, and an
  install from a requirements file;
* INSTALL_SPEC set to anything but the rewritten spec, for a job or a step or in a
  script;
* an image of ASH, meaning a reference naming automated-security-helper or the base
  repository, other than one the run builds, whether named by tag, with no tag or by
  digest: a job or service image, a GitHub job container or ``docker://`` step, a
  Jenkins agent image, or an argument of ``docker``, ``podman``, ``finch`` or
  ``nerdctl`` ``run``, ``pull`` or ``create``;
* a job on an image the run builds that installs ASH again, a pipeline on such an image
  in which no job runs ASH, and a CircleCI job on one, which gets no print.

A docs change to an install line therefore cannot quietly test the release. Every value
the four replacements write is literal: no ``${{``, ``$RUNNER_TEMP``, ``$HOME`` or ``~``
for a shell or a runner to expand later. The head commit and the repository come from
the outer environment (head_sha, base_repository), with no fallback from one source to
another.

rewrite_called_workflow does the same for the reusable workflow a block calls: the pull
request's run-ash-security-scan.yml gets a print step (rule ``called-provenance``) that
runs ``uvx --from "${ASH_UVX_SOURCE}" python``, the form its later steps use to reuse
the environment the scan ran in. It goes right after the one step that rebuilds that
environment with ``uvx --reinstall`` (the scan), and runs even when that step failed;
in a workflow where no step reinstalls, it goes right after the first uvx step, which
builds the environment the others reuse. ASH_UVX_SOURCE has to be the workflow's own
form of the two inputs (CALLED_SCAN_SOURCE). A workflow with two reinstalling steps is
refused, and so is one that sets ASH_UVX_SOURCE again for a job or a step (the two
statements of _SOURCE_WRITERS, which pin the source to a commit, excepted), names it in
a script, an action's input or an env value other than to read its value, names
GITHUB_ENV, BASH_ENV or ENV, runs the set-env workflow command, or names
ACTIONS_ALLOW_UNSECURE_COMMANDS (_uvx_source_problem); one with a uvx, ``uv tool run``
or ``uv run`` call that installs from anything but ``"${ASH_UVX_SOURCE}"`` alone or
names a uv overrides, constraints or settings file; one that runs ``ash`` other than
through uvx, installs packages with another installer, or sets a UV_ setting or a
BASH_FUNC_ name; one with a step or default shell other than bash or sh, or a job
container or services; and one whose env, inputs or defaults are an expression rather
than a mapping. So every uvx call installs from the one source, which names the head
commit.

Limits: the provenance print follows an install written as ``uv tool install
"${INSTALL_SPEC}"`` or ``<venv>/bin/pip install ... "$INSTALL_SPEC"``; another form is
an error rather than a run without provenance, and so is such an install with any
option but one of its flags (_PIP_INSTALL_FLAGS, _UV_TOOL_INSTALL_FLAGS), since an
option with a value can change where or what it installs. A flag before the command
(``uv --offline tool install``) is refused too, as an install whose Python cannot be
told. The
insertions read the block layout of the YAML, so a pipeline written in flow style
(``steps: [...]``) is refused by the check that follows them. The install and image
checks read each script once, as bash reads it (_read_script): its quotes and escapes,
the lines a backslash continues, its substitutions, here-documents and case patterns,
so a command's words are the ones bash splits it into (``X="a b"`` is one assignment,
``--cache-dir "c list"`` one option and its value). A Jenkinsfile's scripts are its
Groovy strings, each read on its own (_groovy_strings). A word is read as a program
where bash runs one (_command_names): first in a command or in a substitution, after
assignments, after a keyword or a wrapper such as ``sudo``, ``env`` or ``xargs``, and
after a case pattern; and the script eval runs, or a shell's or su's -c, is read as
commands too (_scripts_run). A command assembled at run time from variables, and one
another program runs from a string (``ssh host '...'``, ``watch '...'``), are not seen
by the install-line checks, and an image of ASH named with no tag in a variable is not
seen by the image check. INSTALL_SPEC set under a quoted or escaped
name (``export "INSTALL_SPEC"=...``) is not seen by the INSTALL_SPEC check; the
provenance print after the install that reads it shows what it installed. A
configuration file pip or uv reads (``pip.conf``, ``uv.toml``) that a pipeline writes
other than with ``pip config``, or that is already on the runner, is not seen either,
and it can change where or what the followed install puts in place, as one in the
working directory can for the scan workflow (rewrite_called_workflow).
"""

from __future__ import annotations

import bisect
import difflib
import functools
import importlib.util
import itertools
import json
import re
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePath, PurePosixPath
from typing import Any

import yaml

from .provenance import (
    DISTRIBUTION,
    built_provenance_print_command,
    direct_url_print_command,
    file_uri,
)

REPO_ROOT = Path(__file__).resolve().parents[4]

#: Where gitlab-ci-local and the CircleCI CLI mount the directory holding the wheel.
WHEEL_MOUNT = "/ash-wheel"

#: The repository the pages install ASH from, at the release tag.
RELEASE_REPOSITORY = "awslabs/automated-security-helper"
REQUIREMENT = f"{DISTRIBUTION}[cdk]"

#: The runners each kind of pipeline block runs under.
RUNNERS_OF_KIND: Mapping[str, frozenset[str]] = {
    "github-actions": frozenset({"act"}),
    "gitlab-ci": frozenset({"gitlab-ci-local"}),
    "jenkinsfile": frozenset({"jenkinsfile-runner-lts", "jenkinsfile-runner-bundled"}),
    "buildspec": frozenset({"codebuild-agent"}),
    "circleci": frozenset({"circleci"}),
}
RUNNERS = frozenset().union(*RUNNERS_OF_KIND.values())
#: Runners whose pipelines install from the wheel's path on the host.
HOST_WHEEL_RUNNERS = frozenset(
    {"act", "jenkinsfile-runner-lts", "jenkinsfile-runner-bundled"}
)
#: Runners whose pipelines install from the wheel mounted at WHEEL_MOUNT.
MOUNTED_WHEEL_RUNNERS = frozenset({"gitlab-ci-local", "circleci"})

#: Text a literal value never holds: each is expanded later by a shell or a runner.
NOT_LITERAL = ("${{", "$RUNNER_TEMP", "$HOME", "~")

#: The artifact actions act 0.2.89 can run, each at a full commit SHA with its release
#: in the comment, and the action they stand in for. act's artifact server rejects
#: upload-artifact v7's CreateArtifact request (upload-artifact v7.0.0 sends the
#: ``mime_type`` field, which act's strict decode refuses, act issue 6114), and the
#: download-artifact v8 request fails the same way; the v4 releases work.
ACT_UPLOAD_ARTIFACT = (
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2"
)
ACT_DOWNLOAD_ARTIFACT = (
    "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0"
)
#: ``uses:`` of an artifact action at any ref, with the comment after it, to line end.
_ARTIFACT_USES = re.compile(
    r"(?m)^(?P<head>[ \t]*(?:-[ \t]+)?uses:[ \t]*)"
    r"(?P<action>actions/(?:upload|download)-artifact)@[^\s#]+(?:[ \t]+#[^\n]*)?[ \t]*$"
)
#: A ``strategy:`` line with nothing after it (a block mapping follows).
_STRATEGY_LINE = re.compile(r"^(?P<indent> *)strategy:[ \t]*(?:#.*)?$")

#: The step that prints the install's direct_url.json in a GitHub Actions job.
PROVENANCE_STEP_NAME = "Print the direct_url.json of the installed ASH"
#: The step that copies a CircleCI job's reports to the host.
REPORT_COPY_STEP_NAME = "Copy the reports to the host"
#: The interpreter of the environment ``uv tool install`` writes ASH to.
UV_TOOL_PYTHON = f'"$(uv tool dir)/{DISTRIBUTION}/bin/python"'

#: The interpreter ASH is installed into in the image the run builds: the Dockerfile's
#: ``uv pip install --system``, into the base image's Python, first on its PATH.
BUILT_IMAGE_PYTHON = "python3"

#: The reusable workflow that installs ASH, and the step rewrite_called_workflow adds.
CALLED_SCAN_WORKFLOW = "run-ash-security-scan.yml"
CALLED_PROVENANCE_STEP_NAME = "Print the direct_url.json of the ASH this workflow runs"
#: The interpreter of the environment ``uvx --from "${ASH_UVX_SOURCE}"`` builds.
UVX_SOURCE_PYTHON = 'uvx --from "${ASH_UVX_SOURCE}" python'
#: When the print after the scan runs: also after a failed scan, never on a cancel.
AFTER_THE_SCAN = "${{ !cancelled() }}"
#: The scan workflow's ASH_UVX_SOURCE, exactly: the package and extra the pages
#: install, from the ``ash-repo`` repository at the ``ash-version`` ref, the two inputs
#: the block's rewrite sets to the base repository and the head commit.
CALLED_SCAN_SOURCE = (
    REQUIREMENT
    + " @ git+https://github.com/${{ inputs.ash-repo }}@${{ inputs.ash-version }}"
)
#: The statements, by the id of the step that holds them, with which the scan workflow
#: replaces the workflow-level ASH_UVX_SOURCE through GITHUB_ENV. The first step writes
#: the same form from the checked inputs; the second writes it again with the commit
#: the ref names, and ASH_ASSETS_URL beside it. Each is the workflow's own form of the
#: source (REQUIREMENT, the repository, one ref or commit), so a later uvx call still
#: installs from one source. rewrite_called_workflow cuts these exact statements out of
#: the step's script before it reads the script (_without_source_writer); every other
#: line of the step is read as before, and so is a changed statement or the same
#: statement in a step with another id.
_SOURCE_WRITERS = {
    "ash-source": (
        f'echo "ASH_UVX_SOURCE={REQUIREMENT} @ '
        'git+https://github.com/${repo}@${version_url}" >> "${GITHUB_ENV}"'
    ),
    "ash-pin": (
        "{\n"
        f'  echo "ASH_UVX_SOURCE={REQUIREMENT} @ '
        'git+https://github.com/${ASH_REPO}@${COMMIT}"\n'
        '  echo "ASH_ASSETS_URL=https://raw.githubusercontent.com/'
        '${ASH_REPO}/${COMMIT}/automated_security_helper/assets"\n'
        '} >> "$GITHUB_ENV"'
    ),
}

_SHA1 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?/[A-Za-z0-9._-]+")
_LITERAL_PATH = re.compile(r"/[A-Za-z0-9._/-]*")
_JOB_ID = re.compile(r"[A-Za-z0-9_.-]+")
#: A character that would continue a version or a file name after a match.
_CONTINUES = re.compile(r"[A-Za-z0-9._+-]")
#: Characters a literal reference never holds: each is quoting or expansion.
_NOT_LITERAL_CHARACTERS = frozenset("$~`\"'\\")

_INSTALL_VARIABLE = r'"\$(?:INSTALL_SPEC|\{INSTALL_SPEC\})"'
_ANY_INSTALL = re.compile(r"\binstall\b[^\n]*" + _INSTALL_VARIABLE)
_UV_TOOL_INSTALL = re.compile(r"\buv\s+tool\s+install\b[^\n]*" + _INSTALL_VARIABLE)
_PIP_INSTALL = re.compile(
    r'(?P<pip>"[^"\n]*/bin/pip3?"|[^\s"\'=;&|()]*/bin/pip3?)\s+install\b[^\n]*'
    + _INSTALL_VARIABLE
)
#: The options that name what a uvx or uv run call installs, and the one value the
#: scan workflow's calls give them: ``--from`` for uvx and ``uv tool run``, ``--with``
#: (or ``-w``) for ``uv run``.
_UV_SOURCE_OPTIONS = frozenset(
    {"--from", "--with", "--with-editable", "--with-requirements"}
)
_UV_SOURCE = '"${ASH_UVX_SOURCE}"'
#: uv's options that read a file which can change what a call resolves without naming
#: another source: overrides, constraints and a configuration file.
_UV_SETTING_OPTIONS = frozenset(
    {
        "--overrides",
        "--override",
        "--constraints",
        "--constraint",
        "--build-constraints",
        "--build-constraint",
        "--config-file",
    }
)
#: uv's long options that take a value, from ``uv tool run --help`` and
#: ``uv run --help`` (uv 0.13.0), so that a value is not read as the command name.
_UV_VALUE_OPTIONS = frozenset(
    {
        "--allow-insecure-host",
        "--build-constraints",
        "--cache-dir",
        "--color",
        "--config-file",
        "--config-setting",
        "--config-settings-package",
        "--constraints",
        "--default-index",
        "--directory",
        "--env-file",
        "--exclude-newer",
        "--exclude-newer-package",
        "--extra",
        "--extra-index-url",
        "--find-links",
        "--fork-strategy",
        "--from",
        "--group",
        "--index",
        "--index-strategy",
        "--index-url",
        "--keyring-provider",
        "--link-mode",
        "--no-binary-package",
        "--no-build-isolation-package",
        "--no-build-package",
        "--no-editable-package",
        "--no-extra",
        "--no-group",
        "--no-sources-package",
        "--only-group",
        "--overrides",
        "--package",
        "--prerelease",
        "--prerelease-package",
        "--project",
        "--python",
        "--python-platform",
        "--refresh-package",
        "--reinstall-package",
        "--resolution",
        "--torch-backend",
        "--upgrade-group",
        "--upgrade-package",
        "--with",
        "--with-editable",
        "--with-requirements",
    }
)
#: uv's short options that take a value, by the long option each stands for; its
#: other short options (``-q``, ``-v``, ``-n``, ``-U``, ``-m``, ``-s``, ``-h``) take none.
_UV_SHORT_VALUES = {
    "w": "--with",
    "c": "--constraints",
    "b": "--build-constraints",
    "i": "--index-url",
    "f": "--find-links",
    "P": "--upgrade-package",
    "C": "--config-setting",
    "p": "--python",
}
#: A uv setting read from the environment, such as UV_OVERRIDE or UV_CONSTRAINT.
_UV_SETTING_WORD = re.compile(r"(?<!\w)UV_\w+")
#: A setting of pip or uv read from the environment: pip reads every long option from
#: PIP_<NAME> (PIP_TARGET, PIP_CONSTRAINT), and uv reads UV_OVERRIDE, UV_CONSTRAINT,
#: UV_CONFIG_FILE and the rest of its UV_ settings.
_INSTALLER_SETTING_WORD = re.compile(r"(?<!\w)(?:PIP|UV)_\w+")
_INSTALLER_SETTING = (
    "a setting pip or uv reads from the environment, which can change where or what an "
    "install puts in place without an option on its line"
)
#: The shells a step of the scan workflow may run its script with: the ones whose
#: scripts these checks read as written. A shell given as a command (``bash -e {0}``)
#: runs words of its own before the script.
_SCAN_SHELLS = frozenset({"bash", "sh"})
#: The actions the scan workflow's steps use, by name: the only ones a step may use,
#: since what an action runs is not read by these checks, and each only at a full
#: commit SHA (_ACTION_PIN), since a tag or a branch can move. A new action is added
#: here with the workflow change; a pin bump of one of these needs no change here.
_SCAN_ACTIONS = frozenset(
    {
        "actions/cache/restore",
        "actions/cache/save",
        "actions/checkout",
        "actions/download-artifact",
        "actions/setup-python",
        "actions/upload-artifact",
        "astral-sh/setup-uv",
        "github/codeql-action/upload-sarif",
        "mikepenz/action-junit-report",
        "mshick/add-pr-comment",
        "ruby/setup-ruby",
    }
)
#: A full commit SHA, in the form the repository's action-pinning check takes one:
#: 40 hex digits.
_ACTION_PIN = re.compile(r"[0-9a-fA-F]{40}")
#: The variables that name a file bash or sh runs before a script, and the names bash
#: reads functions from (``BASH_FUNC_echo%%``). ``!ENV`` is not one: it is the name of
#: the YAML tag ASH's configuration loader uses for an environment reference, which a
#: Python script of the scan workflow writes as a string, and a word that starts with
#: ``!`` is neither an assignment nor an expansion of ENV in bash or sh.
_SHELL_ENV = re.compile(r"(?<![\w!])(?:(?:BASH_)?ENV(?!\w)|BASH_FUNC_\S*)")
#: pip's commands that install nothing and change no setting. ``pip config`` is not
#: among them: its set, unset and edit write the configuration a later install reads.
_PIP_READ_ONLY = frozenset(
    {
        "list",
        "show",
        "freeze",
        "check",
        "inspect",
        "cache",
        "debug",
        "help",
        "hash",
        "completion",
        "index",
        "search",
    }
)
#: The actions of ``pip config`` that read the configuration and write nothing.
_PIP_CONFIG_READS = frozenset({"list", "get", "debug"})
_PIP_TOOL = re.compile(r"pip3?(?:\.\d+)?")
#: ASH_UVX_SOURCE as a whole name, in a line read with its quoting removed (_readings).
_UVX_SOURCE_WORD = re.compile(r"ASH_UVX_SOURCE(?!\w)")
#: What, right before the name, makes it a read of its value: ``$NAME``, ``${NAME``,
#: ``${!NAME``, ``${#NAME``, and the expression ``${{ env.NAME``.
_UVX_SOURCE_READ = re.compile(r"(?:\$|\$\{[!#]?|\$\{\{\s*env\.)$")
#: What, right after a ``${NAME`` read, makes it an assignment: ``${NAME:=value}`` and
#: ``${NAME=value}``, also through a subscript (``${NAME[0]:=value}``).
_ASSIGNS_DEFAULT = re.compile(r"(?:\[[^\]]*\])?:?=(?!=)")
#: A brace group, innermost first, that is not a parameter expansion (``${...}``).
_BRACES = re.compile(r"(?<!\$)\{(?P<body>[^{}]*)\}")
#: A parameter expansion with no brace inside it, which _brace_expansions writes as one
#: character so that a brace group around it (``{${X},SOURCE}``) is still expanded.
_PARAMETER = re.compile(r"\$\{[^{}]*\}")
_PARAMETER_MARK = "\x00"
#: A brace group bash leaves as it is (``{x}``), as _brace_expansions writes it: one
#: character that spells no name, so the group around it can be expanded.
_BRACE_MARK = "\x01"
_LETTER_SEQUENCE = re.compile(r"(?P<a>[A-Za-z])\.\.(?P<b>[A-Za-z])(?:\.\.-?\d+)?")
_NUMBER_SEQUENCE = re.compile(r"-?\d+\.\.-?\d+(?:\.\.-?\d+)?")
#: How many words _brace_expansions writes out before it gives up.
_MAX_BRACE_WORDS = 256
#: The characters that open a quote: a single or double quote, or a backquote.
_QUOTE_CHARACTERS = frozenset("'\"`")
#: Options right before the name, which some commands take joined to it:
#: ``printf -vNAME``, ``read -aNAME``.
_JOINED_OPTIONS = re.compile(r"(?:^|\s)-[A-Za-z]+$")
_ENDS_IN_A_WORD_CHARACTER = re.compile(r"\w$")
#: The file whose lines set variables for the later steps of a job: GITHUB_ENV, or the
#: expression ``github.env``.
_ENV_FILE = re.compile(
    r"(?<!\w)GITHUB_ENV(?!\w)|(?<![\w.])github\s*(?:\.\s*env|\[\s*env\s*\])(?![\w-])",
    re.IGNORECASE,
)
#: The workflow command that sets a variable for the later steps, where the runner
#: honors it, and the variable that turns it and add-path on.
_SET_ENV = re.compile(r"::\s*set-env(?![\w-])", re.IGNORECASE)
_UNSECURE_COMMANDS = "ACTIONS_ALLOW_UNSECURE_COMMANDS"
#: A line that only prints: echo or printf and plain words, with nothing that
#: redirects, pipes, substitutes or runs another command.
_PRINT_ONLY = re.compile(r"[ \t]*(?:echo|printf)(?:[ \t]+[^\s|&;<>()`]+)*[ \t]*")
#: What lets a later command read what a line prints, or makes echo or printf run
#: something else: a redirection, a pipe, a command or process substitution, a
#: coprocess, and a function or an alias (``echo() { export "$1"; }``).
_CAPTURES = re.compile(
    r"[<>|`]|\$\(|\(\s*\)|(?<![\w.-])(?:coproc|function|alias)(?![\w.-])"
)
#: The escapes printf, ``echo -e`` and ``$'...'`` decode: hex, Unicode and octal codes,
#: a control character (``\cX``), and a letter or digit (``\n``, ``\t``, ``\E``).
_ESCAPE = re.compile(
    r"\\(?:x(?P<x>[0-9A-Fa-f]{1,2})|u(?P<u>[0-9A-Fa-f]{1,4})"
    r"|U(?P<U>[0-9A-Fa-f]{1,8})|0?(?P<o>[0-7]{1,3})|c.|[A-Za-z0-9])"
)
_QUOTING = str.maketrans("", "", "'\"\\")
#: Why _uvx_source_problem refused a line, by the kind it returns.
_SOURCE_PROBLEMS = {
    "sets": (
        "sets ASH_UVX_SOURCE, or names it other than to read its value, so a uvx call "
        "after it may install an ASH other than the one the inputs name, while the "
        "print reads the workflow's"
    ),
    "env-file": (
        "names GITHUB_ENV, whose lines set variables for the steps after it, so it "
        "could set ASH_UVX_SOURCE for their uvx calls (a read of the file is not told "
        "apart from a write)"
    ),
    "set-env": (
        "runs the set-env workflow command, which sets a variable for the steps after "
        "it, so it could set ASH_UVX_SOURCE for their uvx calls"
    ),
    "shell-env": (
        "names BASH_ENV or ENV, a file bash or sh runs before a script, or a BASH_FUNC_ "
        "variable, a function bash defines from its environment, so it could set "
        "ASH_UVX_SOURCE for a scan that runs after it"
    ),
    "uv-env": (
        "sets a UV_ variable, a setting of uv that can change what a uv call after it "
        "resolves without naming another source"
    ),
    "braces": (
        f"has more brace expansions than the {_MAX_BRACE_WORDS} words the checks "
        "write out, so whether one of them spells ASH_UVX_SOURCE cannot be told"
    ),
}

#: The package tools, Python's and Homebrew's, by name. The rewrites follow two
#: installs by pip and uv; every other install is refused.
_TOOL_NAMES = (
    r"pip-sync|pipenv|pipx|pip3?(?:\.\d+)?|uvx|uv|poetry|pdm|conda"
    r"|micromamba|mamba|pixi|hatch|rye|easy_install|brew"
)
#: A package tool as a word in text: a bare name, or a path to it, quoted or not.
_PACKAGE_TOOL = re.compile(
    r"""(?<![\w.$/-])"?(?:[^\s"'`;&|()<>]*/)?"""
    rf"(?P<tool>{_TOOL_NAMES})"
    r'"?(?![\w.-])'
)
#: A package tool as the program a word names (_Word.name).
_TOOL_NAME = re.compile(_TOOL_NAMES)
#: Installers the rewrites do not model: any use with a subcommand is refused. brew
#: installs ASH's formula, from the tap install.md names or by its short name.
_UNFOLLOWED_TOOLS = frozenset(
    {
        "pip-sync",
        "pipenv",
        "poetry",
        "pdm",
        "conda",
        "micromamba",
        "mamba",
        "pixi",
        "hatch",
        "rye",
        "easy_install",
        "brew",
    }
)
_PIP_COMMANDS = frozenset(
    {
        "install",
        "download",
        "uninstall",
        "freeze",
        "inspect",
        "list",
        "show",
        "check",
        "config",
        "search",
        "cache",
        "index",
        "wheel",
        "hash",
        "completion",
        "debug",
        "help",
        "lock",
    }
)
#: uv commands whose name is two words.
_UV_GROUPS = frozenset({"tool", "pip", "python", "cache", "self", "auth"})
#: uv and pipx commands that install nothing a pipeline could run ASH from.
_UV_READ_ONLY = frozenset(
    {
        "tool dir",
        "tool list",
        "venv",
        "pip list",
        "pip show",
        "pip freeze",
        "python find",
        "python list",
        "cache dir",
    }
)
_PIPX_READ_ONLY = frozenset({"list", "environment", "ensurepath", "completions"})
#: brew commands that install nothing: what a pipeline runs to set up or ask Homebrew.
_BREW_READ_ONLY = frozenset(
    {"shellenv", "--prefix", "config", "list", "info", "--version"}
)


@dataclass(frozen=True)
class _LeadingOptions:
    """The options a tool takes before its command name: long ones that take a value
    and long ones that take none, and its short flags. None of the tools read here
    takes a short option with a value there."""

    values: frozenset[str] = frozenset()
    flags: frozenset[str] = frozenset()
    short_flags: frozenset[str] = frozenset()


#: uv's global options (``uv --help``, uv 0.13.0), the ones uv takes before a command,
#: or between a group such as ``pip`` and its command (``uv pip --cache-dir DIR
#: install``). uv also takes global options its help does not list, some with a value
#: (``--preview-features``, ``--python-preference``); those are not among these.
_UV_GLOBAL_OPTIONS = _LeadingOptions(
    values=frozenset(
        {
            "--allow-insecure-host",
            "--cache-dir",
            "--color",
            "--config-file",
            "--directory",
            "--project",
        }
    ),
    flags=frozenset(
        {
            "--help",
            "--managed-python",
            "--no-cache",
            "--no-config",
            "--no-managed-python",
            "--no-progress",
            "--no-python-downloads",
            "--offline",
            "--quiet",
            "--system-certs",
            "--verbose",
            "--version",
        }
    ),
    short_flags=frozenset("hnqvV"),
)
#: pip's general options (the general group of pip 26.1.2), the ones it reads before
#: a command name. pip also takes a long option shortened (``--cach`` for
#: ``--cache-dir``); a shortened name is not among these, so it is not read.
_PIP_GENERAL_OPTIONS = _LeadingOptions(
    values=frozenset(
        {
            "--cache-dir",
            "--cert",
            "--client-cert",
            "--default-timeout",
            "--exists-action",
            "--keyring-provider",
            "--local-log",
            "--log",
            "--log-file",
            "--proxy",
            "--python",
            "--resume-retries",
            "--retries",
            "--timeout",
            "--trusted-host",
            "--use-deprecated",
            "--use-feature",
        }
    ),
    flags=frozenset(
        {
            "--debug",
            "--disable-pip-version-check",
            "--help",
            "--isolated",
            "--no-cache-dir",
            "--no-color",
            "--no-input",
            "--no-python-version-warning",
            "--quiet",
            "--require-venv",
            "--require-virtualenv",
            "--verbose",
            "--version",
        }
    ),
    short_flags=frozenset("hqvV"),
)
#: pipx is read with no options before its command: what one there takes is not
#: modeled, so a call with one is not read.
_PIPX_LEADING_OPTIONS = _LeadingOptions()
#: The flags of ``pip install`` (pip 26.1.2's install command with its general
#: options, the ones that take no value): the only options an install of INSTALL_SPEC
#: by pip may carry, before or after ``install``. An option with a value can change
#: where or what it installs (``--python``, ``--target``, ``--prefix``, ``-c``).
_PIP_INSTALL_FLAGS = _LeadingOptions(
    flags=frozenset(
        {
            "--break-system-packages",
            "--check-build-dependencies",
            "--compile",
            "--debug",
            "--disable-pip-version-check",
            "--dry-run",
            "--force-reinstall",
            "--help",
            "--ignore-installed",
            "--ignore-requires-python",
            "--isolated",
            "--no-build-isolation",
            "--no-cache-dir",
            "--no-clean",
            "--no-color",
            "--no-compile",
            "--no-dependencies",
            "--no-deps",
            "--no-index",
            "--no-input",
            "--no-python-version-warning",
            "--no-user",
            "--no-warn-conflicts",
            "--no-warn-script-location",
            "--pre",
            "--prefer-binary",
            "--quiet",
            "--require-hashes",
            "--require-venv",
            "--require-virtualenv",
            "--upgrade",
            "--use-pep517",
            "--user",
            "--verbose",
            "--version",
        }
    ),
    short_flags=frozenset("IUVhqv"),
)
#: The flags of ``uv tool install`` (``uv tool install --help``, uv 0.13.0, with its
#: global options), less ``--editable``/``-e``, which installs from another source:
#: the only options an install of INSTALL_SPEC by uv may carry. An option with a value
#: can change what it installs (``--config-file``, ``--overrides``, ``-c``,
#: ``--with``, ``--from``).
_UV_TOOL_INSTALL_FLAGS = _LeadingOptions(
    flags=frozenset(
        {
            "--compile-bytecode",
            "--force",
            "--help",
            "--lfs",
            "--managed-python",
            "--no-binary",
            "--no-build",
            "--no-build-isolation",
            "--no-cache",
            "--no-config",
            "--no-index",
            "--no-managed-python",
            "--no-progress",
            "--no-python-downloads",
            "--no-require-build-hashes",
            "--no-sources",
            "--offline",
            "--quiet",
            "--refresh",
            "--reinstall",
            "--require-build-hashes",
            "--system-certs",
            "--upgrade",
            "--verbose",
        }
    ),
    short_flags=frozenset("Uhnqv"),
)
_SPEC_VARIABLES = frozenset({"$INSTALL_SPEC", "${INSTALL_SPEC}"})
#: The two installs the provenance print follows, as the refusals name them.
_FOLLOWED_INSTALLS = (
    'the rewrites follow only `uv tool install "${INSTALL_SPEC}"` and `<venv>/bin/pip '
    'install "$INSTALL_SPEC"`, with flags alone'
)
#: Words after which the next word is a command name: shell keywords and wrappers.
_COMMAND_PREFIXES = frozenset(
    {
        "then",
        "do",
        "else",
        "elif",
        "if",
        "while",
        "until",
        "!",
        "exec",
        "time",
        "nohup",
        "sudo",
        "env",
        "command",
        "xargs",
        "nice",
        "timeout",
        "stdbuf",
    }
)
_PYTHON_WORD = re.compile(r"(?:\S*/)?python(?:\d+(?:\.\d+)?)?")
#: An assignment word, read from its text: a name, a subscript or none, then ``=`` or
#: ``+=``, the name unquoted. Its value may be quoted (``X="a b"``).
_ASSIGNMENT_WORD = re.compile(r"[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=")
#: A definition of INSTALL_SPEC: a shell or Groovy assignment, quoted value or bare.
_SPEC_ASSIGNMENT = re.compile(
    r"""(?<![\w.$-])INSTALL_SPEC\s*\+?=(?!=)\s*"""
    r"""(?:(?P<q>['"])(?P<quoted>.*?)(?P=q)|(?P<bare>[^\s;]*))"""
)
#: The ``ash`` command, as a command word.
_ASH_COMMAND = re.compile(r"""(?<![\w.$/-])"?(?:[^\s"'`;&|()<>]*/)?ash"?(?![\w.-])""")

#: An image repository of ASH: a path component automated-security-helper.
_ASH_IMAGE_PATH = re.compile(
    r"(?:^|/)automated[-_.]security[-_.]helper(?:/|$)", re.IGNORECASE
)
#: An image of ASH named with a tag or a digest, anywhere in a pipeline's text.
_ASH_IMAGE_REFERENCE = re.compile(
    r"(?<![\w.:@-])(?:[\w.-]+(?::\d+)?/)?(?:[\w.-]+/)*"
    r"automated[-_.]security[-_.]helper(?:/[\w.-]+)*"
    r"(?::\w[\w.-]{0,127}|@sha256:[0-9a-f]{64})(?![\w./:@-])",
    re.IGNORECASE,
)
#: A Jenkins Pipeline image: ``image '<ref>'``, ``docker.image('<ref>')``.
_JENKINS_IMAGE = re.compile(r"""\bimage\s*\(?\s*(['"])(?P<ref>[^'"\s]+)\1""")
#: A command that runs or pulls a container image.
_CONTAINER_RUN = re.compile(
    r"(?<![\w.-])(?:docker|podman|finch|nerdctl)\s+(?:container\s+|image\s+)?"
    r"(?:run|pull|create)(?![\w-])"
)
#: GitLab's keywords at the top of a pipeline, which name no job.
_GITLAB_KEYWORDS = frozenset(
    {
        "default",
        "include",
        "stages",
        "variables",
        "workflow",
        "image",
        "services",
        "cache",
        "before_script",
        "after_script",
        "spec",
    }
)

#: A command that installs or runs Python packages.
_INSTALLER = re.compile(
    r"(?<![\w.-])(?:pipx|uvx|pip3?(?:\.\d+)?|uv\s+(?:pip|tool|run|add))(?![\w-])"
)
_ASH_NAME = re.compile(r"automated[-_.]security[-_.]helper", re.IGNORECASE)
#: An install from a file of requirements, which can name any ASH.
_REQUIREMENTS = re.compile(
    r"(?:^|\s)(?:-r|--requirements?|--with-requirements)(?:\s|=|$)"
    r"|(?:^|\s)-r\S|\buv\s+pip\s+sync\b"
)
#: ASH's repository: a URL of it on GitHub, or a call of one of its actions or
#: workflows at a ref.
_ASH_REPOSITORY = re.compile(
    r"(?:github\.com|githubusercontent\.com)[/:]awslabs/automated[-_.]security[-_.]helper"
    r"|\bawslabs/automated[-_.]security[-_.]helper(?:/[^\s\"'@]*)?@",
    re.IGNORECASE,
)


class RewriteError(ValueError):
    """A pipeline, or a value for one, that cannot be made to test the pull request."""


@dataclass(frozen=True)
class Applied:
    """One rule's change: what it matched, what it wrote, and how many times.

    A provenance record (rules ``provenance`` and ``called-provenance``) also names
    the job the print is in (None for a pipeline with no jobs, a buildspec or a
    Jenkinsfile) and whether that job has a matrix, so it runs once per entry.
    """

    rule: str
    old: str
    new: str
    count: int
    job: str | None = None
    matrix: bool = False


@dataclass(frozen=True)
class RewriteResult:
    #: The rewritten pipeline file.
    text: str
    applied: tuple[Applied, ...]
    #: The pipeline as it was given.
    original: str

    def diff(self, where: str = "pipeline") -> str:
        """The rewrite as a unified diff, for the job log."""
        return "".join(
            difflib.unified_diff(
                self.original.splitlines(keepends=True),
                self.text.splitlines(keepends=True),
                f"{where} (as on the page)",
                f"{where} (as run)",
            )
        )


def _not_literal(value: str) -> str | None:
    """What makes ``value`` something a shell or a runner expands, or None."""
    word = next((word for word in NOT_LITERAL if word in value), None)
    if word is not None:
        return word
    found = sorted(_NOT_LITERAL_CHARACTERS.intersection(value))
    if found:
        return found[0]
    return next((c for c in value if c.isspace()), None)


def _digest_reference_problem(ref: str) -> str | None:
    name, at, digest = ref.partition("@")
    if not at or not name or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        return "is not <name>@sha256:<64 hex>"
    if any(c.isspace() for c in name) or ":" in name.rpartition("/")[2]:
        return "carries a tag beside its digest"
    return None


def _check_sha(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _SHA1.fullmatch(value):
        raise RewriteError(f"{what} is not a 40-character lower-case SHA: {value!r}")
    return value


def _check_repository(value: Any, what: str) -> str:
    if (
        not isinstance(value, str)
        or not _REPOSITORY.fullmatch(value)
        or value.rpartition("/")[2] in (".", "..")
    ):
        raise RewriteError(f"{what} is not owner/name: {value!r}")
    return value


@dataclass(frozen=True)
class RewriteContext:
    """What the rewrites write: the runner's install spec, the head commit, the images."""

    runner: str
    install_spec: str
    head_sha: str
    repository: str
    version: str
    #: A page's image -> its pinned ``<name>@sha256:<hex>`` reference.
    images: Mapping[str, str] = field(default_factory=dict)
    #: Images the run builds itself; a job on one keeps it.
    built_images: frozenset[str] = frozenset()
    #: The absolute path a CircleCI job copies its reports to, mounted from the host.
    report_mount: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "images", dict(self.images))
        object.__setattr__(self, "built_images", frozenset(self.built_images))
        if self.runner not in RUNNERS:
            raise RewriteError(f"no rewrites for runner {self.runner!r}")
        prefix = f"{REQUIREMENT} @ "
        url = self.install_spec[len(prefix) :]
        if not self.install_spec.startswith(prefix) or _not_literal(url):
            raise RewriteError(
                f"the install spec {self.install_spec!r} is not {prefix}<literal URL>"
            )
        _check_sha(self.head_sha, "the head commit")
        if self.runner in HOST_WHEEL_RUNNERS | MOUNTED_WHEEL_RUNNERS:
            mounted = self.runner in MOUNTED_WHEEL_RUNNERS
            start = f"file://{WHEEL_MOUNT}/" if mounted else "file:///"
            if not (url.startswith(start) and "#sha256=" in url):
                raise RewriteError(
                    f"{self.runner} installs the wheel from {start}... with its sha256, "
                    f"not {url!r}"
                )
        elif not (url.startswith("git+https://") and url.endswith(f"@{self.head_sha}")):
            raise RewriteError(
                f"{self.runner} installs the head commit {self.head_sha} from git, not "
                f"{url!r}"
            )
        _check_repository(self.repository, "the repository")
        if not self.version or any(c.isspace() for c in self.version):
            raise RewriteError(f"not a version: {self.version!r}")
        for page_image, pinned in self.images.items():
            problem = _digest_reference_problem(pinned)
            if problem is None and _not_literal(pinned):
                problem = f"holds {_not_literal(pinned)!r}, so it is not literal"
            if not page_image or problem:
                raise RewriteError(f"the pin {pinned!r} for {page_image!r} {problem}")
        for built in self.built_images:
            if not built or _not_literal(built):
                raise RewriteError(f"not a literal image reference: {built!r}")
        if self.report_mount is not None and not (
            _LITERAL_PATH.fullmatch(self.report_mount) and ".." not in self.report_mount
        ):
            raise RewriteError(
                f"the report mount {self.report_mount!r} is not a literal absolute path"
            )


def replace_exact(text: str, old: str, new: str, *, count: int, where: str) -> str:
    """``text`` with ``old`` replaced by ``new``, when it occurs exactly ``count`` times.

    Any other number of occurrences, 0 included whatever ``count`` says, is a
    RewriteError naming ``where`` and the number found.
    """
    found = text.count(old) if old else 0
    if found == 0 or found != count:
        raise RewriteError(f"{where}: expected {count} of {old!r}, found {found}")
    return text.replace(old, new)


def install_spec(
    runner: str,
    *,
    wheel: PurePath,
    wheel_sha256: str,
    head_sha: str,
    repository: str,
) -> str:
    """The requirement a runner's pipelines install the ASH under test from.

    act and the Jenkinsfile Runner legs run on the host: the wheel's own path, as a
    file URI. gitlab-ci-local and the CircleCI CLI run jobs in containers, with the
    wheel's directory mounted at WHEEL_MOUNT. Both carry the wheel's sha256 in the URL
    fragment. The CodeBuild agent takes the head commit of the base repository.
    """
    if runner not in RUNNERS:
        raise RewriteError(f"no install spec for runner {runner!r}")
    text = str(wheel)
    if not wheel.is_absolute() or "~" in text or "$" in text:
        raise RewriteError(f"the wheel is not a literal absolute path: {text!r}")
    if not wheel.name.endswith(".whl"):
        raise RewriteError(f"not a wheel: {text!r}")
    if not isinstance(wheel_sha256, str) or not _SHA256.fullmatch(wheel_sha256):
        raise RewriteError(
            f"the wheel's sha256 is not 64 lower-case hex digits: {wheel_sha256!r}"
        )
    _check_sha(head_sha, "the head commit")
    _check_repository(repository, "the repository")
    if runner in HOST_WHEEL_RUNNERS:
        url = f"{file_uri(wheel)}#sha256={wheel_sha256}"
    elif runner in MOUNTED_WHEEL_RUNNERS:
        mounted = PurePosixPath(WHEEL_MOUNT, wheel.name)
        url = f"{file_uri(mounted)}#sha256={wheel_sha256}"
    else:
        url = f"git+https://github.com/{repository}.git@{head_sha}"
    return f"{REQUIREMENT} @ {url}"


def head_sha(environ: Mapping[str, str]) -> str:
    """The commit under test, from the outer workflow's environment.

    On pull_request it is the event's ``pull_request.head.sha``, never GITHUB_SHA (the
    merge commit, which the base repository may not serve). On workflow_dispatch it is
    GITHUB_SHA, never the payload. Anything else is an error, never a fallback.
    """
    event = environ.get("GITHUB_EVENT_NAME")
    if event == "pull_request":
        path = environ.get("GITHUB_EVENT_PATH")
        if not path:
            raise RewriteError("GITHUB_EVENT_PATH is not set on a pull_request event")
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise RewriteError(f"cannot read the event file {path}: {error}") from error
        pull_request = (
            payload.get("pull_request") if isinstance(payload, dict) else None
        )
        head = pull_request.get("head") if isinstance(pull_request, dict) else None
        sha = head.get("sha") if isinstance(head, dict) else None
        return _check_sha(sha, "the event's pull_request.head.sha")
    if event == "workflow_dispatch":
        return _check_sha(environ.get("GITHUB_SHA"), "GITHUB_SHA")
    raise RewriteError(
        f"no head commit for event {event!r}: only pull_request and workflow_dispatch "
        "run these pipelines"
    )


def base_repository(environ: Mapping[str, str]) -> str:
    """GITHUB_REPOSITORY, the repository the workflow runs in, as owner/name."""
    return _check_repository(environ.get("GITHUB_REPOSITORY"), "GITHUB_REPOSITORY")


# ---------------------------------------------------------------------------
# Exact replacements
# ---------------------------------------------------------------------------


def _replace_reference(
    text: str, old: str, new: str, *, rule: str, where: str, applied: list[Applied]
) -> str:
    """Replace every occurrence of ``old``, a reference ending at a version or a name.

    An occurrence the text continues (``@v1.2.3`` inside ``@v1.2.34``) is a different
    reference, and an error rather than a partial match.
    """
    total = text.count(old)
    if total == 0:
        return text
    continued = sum(
        bool(_CONTINUES.match(text, match.end()))
        for match in re.finditer(re.escape(old), text)
    )
    if continued:
        raise RewriteError(
            f"{where}: {continued} of the {total} occurrences of {old!r} continue "
            "into a longer version or name"
        )
    text = replace_exact(text, old, new, count=total, where=where)
    applied.append(Applied(rule, old, new, total))
    return text


def _rewrite_ash_version(
    text: str, ctx: RewriteContext, where: str, applied: list[Applied]
) -> str:
    if re.search(r"(?m)^[ \t]*ash-repo:", text):
        raise RewriteError(f"{where}: the block already sets ash-repo")
    line = re.compile(
        r"(?m)^(?P<indent>[ \t]*)ash-version:[ \t]*(?P<q>[\"']?)"
        + re.escape(f"v{ctx.version}")
        + r"(?P=q)[ \t]*$"
    )
    # The commit id is written with detect-secrets' allowlist pragma: the rewritten
    # workflow sits in the scanned tree, and a 40-hex value is a high-entropy string
    # to that scanner, so without the pragma the rewrite plants an actionable finding
    # the page's fixture does not count (measured on the hosted act legs).
    pragma = "# pragma: allowlist secret"
    text, count = line.subn(
        lambda m: (
            f'{m["indent"]}ash-version: "{ctx.head_sha}" {pragma}\n'
            f'{m["indent"]}ash-repo: "{ctx.repository}"'
        ),
        text,
    )
    if count:
        applied.append(
            Applied(
                "ash-version",
                f"ash-version: v{ctx.version}",
                f'ash-version: "{ctx.head_sha}" {pragma}\nash-repo: "{ctx.repository}"',
                count,
            )
        )
    calls = text.count("./.github/workflows/run-ash-security-scan.yml")
    if calls != count:
        raise RewriteError(
            f"{where}: {calls} call(s) of run-ash-security-scan.yml but {count} "
            f"`ash-version: v{ctx.version}` line(s); a call without one installs ASH "
            "from another ref than the head commit"
        )
    return text


def _images_in(document: Any) -> list[str]:
    """Every image a GitLab or CircleCI pipeline names: ``image`` keys and services."""
    found: list[Any] = []

    def name(value: Any) -> Any:
        return value.get("name") if isinstance(value, dict) else value

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "image":
                    found.append(name(value))
                elif key == "services" and isinstance(value, list):
                    found.extend(name(service) for service in value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(document)
    return found


def _rewrite_images(
    text: str, document: Any, ctx: RewriteContext, where: str, applied: list[Applied]
) -> tuple[str, bool]:
    """Pin every job image; returns the text and whether a job runs on a built image."""
    images = _images_in(document)
    used_built = False
    for image in dict.fromkeys(images):
        if not isinstance(image, str):
            raise RewriteError(f"{where}: an image that is not a name: {image!r}")
        if image in ctx.built_images:
            used_built = True
            continue
        if image not in ctx.images:
            raise RewriteError(
                f"{where}: the image {image} has no pinned digest and is not one the "
                "run builds"
            )
        pinned = ctx.images[image]
        line = re.compile(
            r"(?m)^(?P<lead>[ \t]*(?:-[ \t]+)?image:[ \t]*)(?P<q>[\"']?)"
            + re.escape(image)
            + r"(?P=q)(?P<tail>[ \t]*(?:#.*)?)$"
        )
        expected = images.count(image)
        text, count = line.subn(
            lambda m, pinned=pinned: m["lead"] + m["q"] + pinned + m["q"] + m["tail"],
            text,
        )
        if count != expected:
            raise RewriteError(
                f"{where}: the pipeline names the image {image} {expected} time(s) "
                f"but has {count} `image: {image}` line(s) to pin, found {count}"
            )
        applied.append(Applied("image", image, pinned, count))
    return text, used_built


# ---------------------------------------------------------------------------
# Insertions, at places read from the parsed YAML
# ---------------------------------------------------------------------------


@dataclass
class _Insertion:
    #: The index of the line the inserted lines go before.
    before: int
    #: Where two insertions go before one line, the lower order goes first.
    order: int
    lines: list[str]
    rule: str
    #: The text the insertion follows, for its record.
    anchor: str
    #: The print commands among ``lines``.
    commands: list[str] = field(default_factory=list)
    #: The job the insertion is in, and whether that job has a matrix.
    job: str | None = None
    matrix: bool = False


def _job_of(kind: str, keys: list[Any], document: Any) -> tuple[str | None, bool]:
    """The job a value at ``keys`` belongs to, and whether that job has a matrix."""
    if not isinstance(document, dict):
        return None, False
    if kind in ("github-actions", "circleci") and len(keys) > 1 and keys[0] == "jobs":
        job = str(keys[1])
        body = (document.get("jobs") or {}).get(keys[1])
        if kind == "github-actions":
            strategy = body.get("strategy") if isinstance(body, dict) else None
            return job, isinstance(strategy, dict) and "matrix" in strategy
        return job, _circleci_job_has_matrix(document, job)
    if kind == "gitlab-ci" and keys:
        body = document.get(keys[0])
        return str(keys[0]), isinstance(body, dict) and "parallel" in body
    if kind == "buildspec":
        return None, "batch" in document
    return None, False


def _circleci_job_has_matrix(document: dict[str, Any], job: str) -> bool:
    """Whether a CircleCI workflow runs ``job`` with a matrix."""
    for workflow in (document.get("workflows") or {}).values():
        entries = workflow.get("jobs") if isinstance(workflow, dict) else None
        for entry in entries or ():
            if isinstance(entry, dict) and isinstance(entry.get(job), dict):
                if "matrix" in entry[job]:
                    return True
    return False


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _item_end(lines: list[str], start: int, dash_column: int) -> int:
    """The index after a block-sequence item that starts on line ``start``.

    The item ends at the next non-blank line indented no deeper than its dash; blank
    lines before that line stay after whatever is inserted there.
    """
    index = start + 1
    while index < len(lines) and not (
        lines[index].strip() and _indent(lines[index]) <= dash_column
    ):
        index += 1
    while index > start + 1 and not lines[index - 1].strip():
        index -= 1
    return index


Chain = tuple[tuple[yaml.Node, Any], ...]


def _scalars(node: yaml.Node, chain: Chain = ()) -> Iterator[tuple[yaml.Node, Chain]]:
    """Every value scalar under ``node``, with the (container, key or index) above it."""
    if isinstance(node, yaml.ScalarNode):
        yield node, chain
    elif isinstance(node, yaml.SequenceNode):
        for index, item in enumerate(node.value):
            yield from _scalars(item, (*chain, (node, index)))
    elif isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            yield from _scalars(value, (*chain, (node, getattr(key, "value", None))))


def _mapping_value(node: yaml.Node | None, key: str) -> yaml.Node | None:
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            if getattr(k, "value", None) == key:
                return v
    return None


def _interpreters(command_line: str, where: str) -> list[str]:
    """The interpreters an install line of ``INSTALL_SPEC`` writes ASH into."""
    found = []
    if _UV_TOOL_INSTALL.search(command_line):
        found.append(UV_TOOL_PYTHON)
    for match in _PIP_INSTALL.finditer(command_line):
        found.append(re.sub(r"/bin/pip3?(\"?)$", r"/bin/python\1", match["pip"]))
    if not found and _ANY_INSTALL.search(command_line):
        raise RewriteError(
            f"{where}: cannot tell which Python `{command_line.strip()}` installs ASH "
            "into, so its provenance cannot be printed"
        )
    return list(dict.fromkeys(found))


def _interpreters_in(script: str, where: str) -> list[str]:
    found = (p for line in script.split("\n") for p in _interpreters(line, where))
    return list(dict.fromkeys(found))


def _yaml_single_quoted(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _step_after(
    lines: list[str],
    sequence: yaml.Node,
    index: int,
    *,
    name: str,
    commands: list[str],
    rule: str,
    anchor: str,
    job: str | None,
    matrix: bool,
    condition: str | None = None,
) -> _Insertion:
    """A GitHub Actions step running ``commands``, right after step ``index``, with
    ``if: <condition>`` when one is given."""
    dash = sequence.start_mark.column
    pad = " " * dash
    return _Insertion(
        before=_item_end(lines, sequence.value[index].start_mark.line, dash),
        order=0,
        lines=[
            f"{pad}- name: {name}",
            *([f"{pad}  if: {condition}"] if condition else []),
            f"{pad}  run: |",
            *(f"{pad}    {command}" for command in commands),
        ],
        rule=rule,
        anchor=anchor,
        commands=commands,
        job=job,
        matrix=matrix,
    )


def _github_provenance(
    lines: list[str], root: yaml.Node, document: Any, where: str
) -> list[_Insertion]:
    """A print step right after each step that installs ASH."""
    steps: dict[tuple[int, int], tuple[yaml.Node, int, list[str], str, list[Any]]] = {}
    for node, chain in _scalars(root):
        interpreters = _interpreters_in(str(node.value), where)
        if not interpreters:
            continue
        keys = [key for _, key in chain]
        anchor = next(
            line.strip()
            for line in str(node.value).split("\n")
            if _interpreters(line, where)
        )
        if len(keys) != 5 or (keys[0], keys[2], keys[4]) != ("jobs", "steps", "run"):
            raise RewriteError(
                f"{where}: `{anchor}` is not the run of a job's step, so no step can "
                "print its provenance after it"
            )
        sequence, index = chain[3]
        entry = steps.setdefault(
            (id(sequence), index), (sequence, index, [], anchor, keys)
        )
        entry[2].extend(p for p in interpreters if p not in entry[2])
    insertions = []
    for sequence, index, interpreters, anchor, keys in steps.values():
        job, matrix = _job_of("github-actions", keys, document)
        insertions.append(
            _step_after(
                lines,
                sequence,
                index,
                name=PROVENANCE_STEP_NAME,
                commands=[direct_url_print_command(p) for p in interpreters],
                rule="provenance",
                anchor=anchor,
                job=job,
                matrix=matrix,
            )
        )
    return insertions


def _script_line_insertions(
    lines: list[str],
    indices: range,
    where: str,
    *,
    job: str | None = None,
    matrix: bool = False,
) -> list[_Insertion]:
    """A print on the line after each install line among ``lines[indices]``."""
    insertions = []
    for index in indices:
        line = lines[index]
        interpreters = _interpreters(line, where)
        if not interpreters:
            continue
        if line.rstrip().endswith(("\\", "&&", "||", "|")):
            raise RewriteError(
                f"{where}: `{line.strip()}` continues on the next line, so no print "
                "can follow it there"
            )
        pad = line[: _indent(line)]
        commands = [direct_url_print_command(p) for p in interpreters]
        insertions.append(
            _Insertion(
                before=index + 1,
                order=0,
                lines=[f"{pad}{command}" for command in commands],
                rule="provenance",
                anchor=line.strip(),
                commands=commands,
                job=job,
                matrix=matrix,
            )
        )
    return insertions


def _yaml_provenance(
    kind: str, lines: list[str], root: yaml.Node, document: Any, where: str
) -> list[_Insertion]:
    """A print after each install: the next line of a script, or the next list item."""
    insertions = []
    for node, chain in _scalars(root):
        value = str(node.value)
        interpreters = _interpreters_in(value, where)
        if not interpreters:
            continue
        job, matrix = _job_of(kind, [key for _, key in chain], document)
        if node.style == "|":
            end = min(node.end_mark.line, len(lines))
            found = _script_line_insertions(
                lines,
                range(node.start_mark.line, end),
                where,
                job=job,
                matrix=matrix,
            )
            expected = sum(bool(_interpreters(v, where)) for v in value.split("\n"))
            if len(found) != expected:
                raise RewriteError(
                    f"{where}: a script has {expected} install line(s) but "
                    f"{len(found)} were found in its text, so no print can be placed"
                )
            insertions.extend(found)
        elif chain and isinstance(chain[-1][0], yaml.SequenceNode):
            dash = chain[-1][0].start_mark.column
            commands = [direct_url_print_command(p) for p in interpreters]
            insertions.append(
                _Insertion(
                    before=_item_end(lines, node.start_mark.line, dash),
                    order=0,
                    lines=[
                        f"{' ' * dash}- {_yaml_single_quoted(command)}"
                        for command in commands
                    ],
                    rule="provenance",
                    anchor=value.strip(),
                    commands=commands,
                    job=job,
                    matrix=matrix,
                )
            )
        else:
            raise RewriteError(
                f"{where}: `{value.strip()}` is neither a line of a script nor an item "
                "of a list of commands, so no print can follow it"
            )
    return insertions


def _jenkinsfile_provenance(lines: list[str], where: str) -> list[_Insertion]:
    """A print on the line after each install line of an ``sh '''`` script."""
    insertions = _script_line_insertions(lines, range(len(lines)), where)
    for insertion in insertions:
        if "\n".join(lines[: insertion.before - 1]).count("'''") % 2 != 1:
            raise RewriteError(
                f"{where}: `{insertion.anchor}` is not inside an sh ''' script, so no "
                "print can follow it"
            )
    return insertions


def _runs_ash(script: str) -> bool:
    """Whether a script runs the ``ash`` command (_command_names)."""
    return any(
        command.words[index].name == "ash"
        for line in _read_script(script)
        for command in line.commands
        for index in _command_names(command.words)
    )


def _gitlab_job_image(document: Any, job: str) -> Any:
    """The image a GitLab job runs on: its own, else ``default:``'s, else the
    pipeline's."""
    if not isinstance(document, dict):
        return None
    for holder in (document.get(job), document.get("default"), document):
        image = holder.get("image") if isinstance(holder, dict) else None
        if image is not None:
            return image.get("name") if isinstance(image, dict) else image
    return None


def _built_provenance(
    lines: list[str],
    root: yaml.Node,
    document: Any,
    ctx: RewriteContext,
    where: str,
) -> list[_Insertion]:
    """A print of the image's ASH right before the first command that runs ``ash``, in
    each GitLab job on an image the run builds."""
    insertions = []
    for key, job in root.value if isinstance(root, yaml.MappingNode) else ():
        name = str(getattr(key, "value", ""))
        if (
            name in _GITLAB_KEYWORDS
            or name.startswith(".")
            or not isinstance(job, yaml.MappingNode)
            or _gitlab_job_image(document, name) not in ctx.built_images
        ):
            continue
        target = None
        for script_key in ("before_script", "script"):
            node = _mapping_value(job, script_key)
            if isinstance(node, yaml.SequenceNode):
                for item in node.value:
                    if not isinstance(item, yaml.ScalarNode):
                        raise RewriteError(
                            f"{where}: the job {name}'s {script_key} holds an item "
                            "that is not a command, so no print can be placed in it"
                        )
                    if _runs_ash(str(item.value)):
                        target = (node, item)
                        break
            elif node is not None and _runs_ash(str(getattr(node, "value", ""))):
                raise RewriteError(
                    f"{where}: the job {name} runs ASH in a {script_key} that is not a "
                    "list of commands, so no print can go before it"
                )
            if target is not None:
                break
        if target is None:
            continue
        sequence, item = target
        dash, line = sequence.start_mark.column, item.start_mark.line
        if not (
            job.start_mark.line <= sequence.start_mark.line < job.end_mark.line
            and lines[line][dash:].startswith("- ")
        ):
            raise RewriteError(
                f"{where}: the command in the job {name} that runs ASH is not an item "
                "written in the job, so no print can go before it"
            )
        command = built_provenance_print_command(BUILT_IMAGE_PYTHON)
        body = document.get(name) if isinstance(document, dict) else None
        insertions.append(
            _Insertion(
                before=line,
                order=0,
                lines=[f"{' ' * dash}- {_yaml_single_quoted(command)}"],
                rule="built-provenance",
                anchor=str(item.value).strip().split("\n")[0],
                commands=[command],
                job=name,
                matrix=isinstance(body, dict) and "parallel" in body,
            )
        )
    return insertions


def _check_built_prints(
    document: Any, insertions: list[_Insertion], where: str
) -> None:
    """Each built-image print is the command right before its job's first ``ash``."""
    for insertion in insertions:
        body = document.get(insertion.job) if isinstance(document, dict) else None
        commands = [
            command
            for key in ("before_script", "script")
            for command in (body.get(key) if isinstance(body, dict) else None) or ()
        ]
        found = [i for i, c in enumerate(commands) if c == insertion.commands[0]]
        runs = [i for i, c in enumerate(commands) if _runs_ash(str(c))]
        if len(found) != 1 or not runs or runs[0] != found[0] + 1:
            raise RewriteError(
                f"{where}: the print of the image's ASH in the job {insertion.job} did "
                "not land right before the command that runs ASH"
            )
    _check_print_lines(document, [c for i in insertions for c in i.commands], where)


def _report_copy(
    lines: list[str], root: yaml.Node, ctx: RewriteContext, where: str
) -> list[_Insertion]:
    """A last step in each CircleCI job that copies its reports to the host."""
    if ctx.report_mount is None:
        raise RewriteError(f"{where}: a CircleCI job needs a report mount to copy to")
    jobs = _mapping_value(root, "jobs")
    if not isinstance(jobs, yaml.MappingNode) or not jobs.value:
        raise RewriteError(f"{where}: no jobs whose reports could be copied")
    insertions = []
    for key, job in jobs.value:
        job_id = str(getattr(key, "value", ""))
        if not _JOB_ID.fullmatch(job_id) or not job_id.strip("."):
            raise RewriteError(f"{where}: the job id {job_id!r} is not a plain name")
        steps = _mapping_value(job, "steps")
        if not isinstance(steps, yaml.SequenceNode) or not steps.value:
            raise RewriteError(f"{where}: the job {job_id} has no list of steps")
        dash = steps.start_mark.column
        last = steps.value[-1].start_mark.line
        target = f"{ctx.report_mount.rstrip('/')}/{job_id}"
        pad, keys, script = " " * dash, " " * (dash + 4), " " * (dash + 6)
        insertions.append(
            _Insertion(
                before=_item_end(lines, last, dash),
                order=1,
                lines=[
                    f"{pad}- run:",
                    f"{keys}name: {REPORT_COPY_STEP_NAME}",
                    f"{keys}when: always",
                    f"{keys}command: |",
                    f'{script}mkdir -p "{target}"',
                    (
                        f"{script}if [ -d .ash/ash_output ]; then "
                        f'cp -R .ash/ash_output "{target}/"; '
                        'else echo "no .ash/ash_output to copy"; fi'
                    ),
                ],
                rule="report-copy",
                anchor=lines[last].strip(),
                job=job_id,
            )
        )
    return insertions


def _apply_insertions(
    text: str, insertions: list[_Insertion], applied: list[Applied]
) -> str:
    lines = text.split("\n")
    by_line: dict[int, list[_Insertion]] = {}
    for insertion in sorted(insertions, key=lambda i: (i.before, i.order)):
        by_line.setdefault(insertion.before, []).append(insertion)
    out: list[str] = []
    for index in range(len(lines) + 1):
        for insertion in by_line.get(index, ()):
            out.extend(insertion.lines)
        if index < len(lines):
            out.append(lines[index])
    counted: dict[tuple[str, str, str, str | None, bool], int] = {}
    for insertion in insertions:
        record = (
            insertion.rule,
            insertion.anchor,
            "\n".join(insertion.lines),
            insertion.job,
            insertion.matrix,
        )
        counted[record] = counted.get(record, 0) + 1
    applied.extend(
        Applied(rule, old, new, count, job=job, matrix=matrix)
        for (rule, old, new, job, matrix), count in counted.items()
    )
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Checks of the result
# ---------------------------------------------------------------------------


def _load(text: str, where: str) -> Any:
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise RewriteError(f"{where}: the pipeline does not parse: {error}") from error


def _compose(text: str, where: str) -> yaml.Node:
    """The pipeline's YAML node tree, whose marks give each node's line and column."""
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as error:
        raise RewriteError(f"{where}: the pipeline does not parse: {error}") from error
    if root is None:
        raise RewriteError(f"{where}: the pipeline is empty")
    return root


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)


def _check_print_steps(document: Any, inserted: int, where: str) -> None:
    """Each print step of a GitHub Actions pipeline directly follows an install step."""
    found = 0
    jobs = document.get("jobs") if isinstance(document, dict) else None
    for job in (jobs or {}).values():
        steps = job.get("steps") if isinstance(job, dict) else None
        for index, step in enumerate(steps or ()):
            if not (
                isinstance(step, dict) and step.get("name") == PROVENANCE_STEP_NAME
            ):
                continue
            previous = steps[index - 1] if index else None
            run = previous.get("run") if isinstance(previous, dict) else None
            if not _interpreters_in(str(run or ""), where):
                raise RewriteError(
                    f"{where}: a provenance step does not follow an install step"
                )
            found += 1
    if found != inserted:
        raise RewriteError(
            f"{where}: {inserted} provenance step(s) inserted but {found} found after "
            "an install step in the parsed pipeline"
        )


def _check_print_lines(document: Any, commands: list[str], where: str) -> None:
    """Each print command of a pipeline is a command of its own in the parsed YAML."""
    wanted = set(commands)
    found = sum(
        line.strip() in wanted
        for value in _strings(document)
        for line in value.split("\n")
    )
    if found != len(commands):
        raise RewriteError(
            f"{where}: {len(commands)} provenance print(s) inserted but {found} are "
            "commands of their own in the parsed pipeline"
        )


def _check_report_copy(document: Any, inserted: int, where: str) -> None:
    found = 0
    jobs = document.get("jobs") if isinstance(document, dict) else None
    for job in (jobs or {}).values():
        steps = job.get("steps") if isinstance(job, dict) else None
        last = steps[-1] if steps else None
        run = last.get("run") if isinstance(last, dict) else None
        if isinstance(run, dict) and run.get("name") == REPORT_COPY_STEP_NAME:
            found += 1
    if found != inserted:
        raise RewriteError(
            f"{where}: {inserted} report copy step(s) inserted but {found} are the "
            "last step of their job"
        )


# ---------------------------------------------------------------------------
# Reading a shell script as bash reads it
# ---------------------------------------------------------------------------

#: What ends a word outside quotes, besides a blank and a line break.
_WORD_ENDS = frozenset(";&|()<>")
#: Stands for a substitution or a parameter expansion in a word's literal form. It
#: spells no name, so a word that holds one where a program's name would be names no
#: program.
_EXPANDED = "\x00"
#: The operators that end a command, longest first.
_CONTROL_OPERATORS = (";;&", ";;", ";&", "&&", "||", "|&", "|", "&", ";")
#: The redirection operators, longest first.
_REDIRECTIONS = (
    "<<<",
    "<<-",
    "<<",
    "<>",
    "<&",
    "<",
    ">>",
    ">|",
    ">&",
    ">",
    "&>>",
    "&>",
)
#: A file descriptor written before a redirection: a number, or a name in braces that
#: bash allocates one into (``2>&1``, ``{fd}>file``).
_DESCRIPTOR = re.compile(r"(?:\d+|\{[A-Za-z_]\w*\})(?=[<>])(?![<>]\()")
#: What follows ``$`` in a parameter expansion written without braces.
_PARAMETER_NAME = re.compile(r"[A-Za-z_]\w*|[0-9@*#?$!-]")
#: The escapes of a ``$'...'`` string that stand for one character, besides the codes
#: _ESCAPE reads.
_ANSI_C_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "e": "\x1b",
    "E": "\x1b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "?": "?",
}
#: Groovy's escapes in a string literal, by the character after the backslash.
_GROOVY_ESCAPES = {
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "$": "$",
    "/": "/",
}
#: The shells whose -c script, and the commands whose -c or --command command, are
#: read as scripts of their own (_scripts_run).
_SHELLS = frozenset({"bash", "sh", "dash", "zsh", "ksh", "mksh"})
_SWITCH_USER = frozenset({"su", "runuser"})
#: A Python interpreter as a word of a command: ``python``, ``python3``, ``python3.12``
#: or a path to one.
_PYTHON_PROGRAM = re.compile(r"(?:.*/)?python[0-9.]*")
#: The words that make a here-document shell input even when a Python interpreter is
#: also a word of its command (``bash -s python``, ``eval python``).
_SHELL_INPUT_WORDS = (
    _SHELLS | _SWITCH_USER | {"eval", "source", ".", "busybox", "toybox"}
)
#: The options of those shells that take a value (``-o pipefail``, ``-O extglob``).
_SHELL_VALUE_OPTIONS = frozenset({"-o", "+o", "-O", "+O", "--rcfile", "--init-file"})
#: How deep a script inside a script is read: the words eval runs, a -c script, a line
#: of a here-document. A command that runs one deeper is refused (_Command.unread).
_MAX_SCRIPT_DEPTH = 8


@dataclass(frozen=True)
class _Word:
    """A word of a command: ``text`` as written, and ``value`` as bash reads it before
    it expands anything, with its quotes and escapes removed and each substitution and
    parameter expansion kept as written. ``literal`` is ``value`` with each of those
    written as _EXPANDED. ``start`` and ``end`` are offsets into the code it was read
    from (_Reader.code)."""

    text: str
    value: str
    literal: str
    start: int
    end: int

    @property
    def name(self) -> str:
        """The program the word names: its last path component (``pip`` for
        ``"$HOME/v/bin/pip"``), or nothing when that component holds an expansion."""
        last = self.literal.rpartition("/")[2]
        return "" if _EXPANDED in last else last


@dataclass(frozen=True)
class _Command:
    """A simple command: its words, its redirections and their targets left out, and
    ``text``, the code it was read from, which ``start`` and ``end`` place in the code of
    the script ``source`` numbers. ``scripts`` are the indices of the words that hold a
    script it runs (_scripts_run), which is read as commands of its own; ``inner`` are
    where, in ``text``, the commands of its substitutions and those words are.
    ``unread`` says it runs a script nested deeper than _MAX_SCRIPT_DEPTH, which is not
    read, so the checks refuse it."""

    words: tuple[_Word, ...]
    text: str
    start: int
    end: int
    source: int
    scripts: frozenset[int] = frozenset()
    inner: tuple[tuple[int, int], ...] = ()
    unread: bool = False


@dataclass(frozen=True)
class _Line:
    """A line of a script as bash joins it (_read_script). ``comment`` says the source
    checks skip it: its first non-blank character is ``#``, and it holds no quote or
    backquote, since a line that does may close a quote and run what follows it.
    ``commands`` are the commands that start on it, those of its substitutions and of
    the scripts it runs included, in the order they start."""

    text: str
    comment: bool
    commands: tuple[_Command, ...]


def _continues(line: str) -> bool:
    """Whether ``line`` ends in a backslash no other backslash escapes."""
    return (len(line) - len(line.rstrip("\\"))) % 2 == 1


def _joined(lines: list[str]) -> list[str]:
    """``lines`` with each one that ends in a backslash (_continues) joined to the next,
    the backslash and the line break removed."""
    out: list[str] = []
    pending = ""
    for line in lines:
        if _continues(line):
            pending += line[:-1]
            continue
        out.append(pending + line)
        pending = ""
    if pending:
        out.append(pending)
    return out


def _ansi_c(body: str) -> str:
    """The value of a ``$'...'`` string whose body is ``body``: _ESCAPE's codes, ``\\cX``
    and _ANSI_C_ESCAPES decoded; any other backslash is kept with what follows it."""
    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\" or index + 1 == len(body):
            out.append(char)
            index += 1
            continue
        following = body[index + 1]
        code = _ESCAPE.match(body, index)
        if code and any(code[group] for group in ("x", "u", "U", "o")):
            out.append(_decoded_escape(code))
            index = code.end()
        elif following == "c" and index + 2 < len(body):
            out.append(chr(ord(body[index + 2]) & 0x1F))
            index += 3
        else:
            out.append(_ANSI_C_ESCAPES.get(following, char + following))
            index += 2
    return "".join(out)


class _Reader:
    """Reads a shell script once, the way bash does, into the commands it runs and its
    lines (_read_script).

    It reads single and double quotes, ``$'...'`` and backslash escapes; the line
    continuations bash joins, a backslash and a line break outside single quotes and
    ``$'...'``; command substitutions (``$(...)``, a backquote pair, ``<(...)``) and
    parameter expansions (``${...}``, ending at the first ``}`` outside a quote or a
    nested expansion); subshells; redirections, whose targets are no words of their
    command; here-documents; comments, from a ``#`` that starts a word; and the
    patterns of a case statement, whose ``)`` closes nothing. ``code`` is the script as
    bash joins it, less the lines of its here-documents, and each offset is into it.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.index = 0
        self.code: list[str] = []
        #: How many quotes, backquote pairs and ``${`` are open: a line break ends a
        #: line only outside them.
        self.quotes = 0
        #: Where in ``code`` each line break that ends a line is.
        self.ends: list[int] = []
        #: The here-documents the line being read opens: delimiter, whether tabs are
        #: stripped (``<<-``), whether the delimiter is quoted, and whether it is
        #: Python's input (a quoted delimiter on a command with a Python interpreter
        #: and no shell among its words).
        self.pending: list[tuple[str, bool, bool, bool]] = []
        #: Each here-document's lines, with how many lines of code end before them and
        #: whether it is Python's input.
        self.documents: list[tuple[int, list[str], bool]] = []
        #: Each command read: its words and where it starts and ends in ``code``.
        self.found: list[tuple[list[_Word], int, int]] = []

    def peek(self, offset: int = 0) -> str:
        at = self.index + offset
        return self.text[at] if at < len(self.text) else ""

    def take(self) -> str:
        char = self.text[self.index]
        self.index += 1
        self.code.append(char)
        return char

    def join(self) -> None:
        """Skip the line continuations at the reader's place."""
        while self.text.startswith("\\\n", self.index):
            self.index += 2

    def read_list(self, closing: str) -> None:
        """Read commands up to ``closing`` (``)`` or a backquote, left unread for the
        caller) or, with ``closing`` empty, to the end of the text."""
        words: list[_Word] = []
        start = end = -1
        target = ""
        cases = 0
        pattern = False

        def finish() -> None:
            nonlocal words, start, end, target
            if words:
                self.found.append((words, start, end))
            words, start, end, target = [], -1, -1, ""

        while True:
            self.join()
            char = self.peek()
            if not char or (char == "`" and closing == "`"):
                break
            if char in " \t\r":
                self.take()
                continue
            if char == "\n":
                finish()
                self.take()
                if not self.quotes:
                    self.ends.append(len(self.code) - 1)
                if self.pending:
                    self.read_documents()
                continue
            if char == "#":
                while self.peek() not in ("", "\n"):
                    self.take()
                continue
            if char == ")":
                if pattern:
                    pattern = False
                elif closing == ")":
                    break
                # A ) that closes nothing read here, as after a case pattern: a
                # command starts after it.
                finish()
                self.take()
                continue
            if char == "(":
                finish()
                self.take()
                if not pattern:
                    self.read_list(")")
                    if self.peek() == ")":
                        self.take()
                continue
            if pattern and char == "|":
                self.take()
                continue
            descriptor = _DESCRIPTOR.match(self.text, self.index)
            at = descriptor.end() if descriptor else self.index
            redirection = next(
                (op for op in _REDIRECTIONS if self.text.startswith(op, at)), ""
            )
            if redirection and not self.text.startswith("(", at + len(redirection)):
                if start < 0:
                    start = len(self.code)
                while self.index < at + len(redirection):
                    self.take()
                end = len(self.code)
                target = redirection
                continue
            operator = next(
                (
                    op
                    for op in _CONTROL_OPERATORS
                    if self.text.startswith(op, self.index)
                ),
                "",
            )
            if operator:
                finish()
                for _ in operator:
                    self.take()
                if operator in (";;", ";&", ";;&") and cases:
                    pattern = True
                continue
            word = self.read_word(closing)
            if word.end == word.start:
                self.take()
                continue
            if target:
                if target in ("<<", "<<-"):
                    quoted = word.text != word.value
                    names = {each.value.rsplit("/", 1)[-1] for each in words}
                    python = (
                        quoted
                        and any(_PYTHON_PROGRAM.fullmatch(each.value) for each in words)
                        and not names & _SHELL_INPUT_WORDS
                    )
                    self.pending.append((word.value, target == "<<-", quoted, python))
                target = ""
                end = word.end
                continue
            if pattern:
                if word.value == "esac":
                    cases -= 1
                    pattern = False
                continue
            if not words and word.value == "esac" and cases:
                cases -= 1
                continue
            if start < 0:
                start = word.start
            words.append(word)
            end = word.end
            if len(words) == 3 and words[0].value == "case" and word.value == "in":
                cases += 1
                pattern = True
                finish()
        finish()

    def read_word(self, closing: str) -> _Word:
        """Read the word at the reader's place."""
        start = len(self.code)
        value: list[str] = []
        literal: list[str] = []
        while True:
            self.join()
            char = self.peek()
            if not char or char in " \t\r\n":
                break
            if char in "<>" and self.peek(1) == "(":
                self.substitution(value, literal)
                continue
            if char in _WORD_ENDS or (char == "`" and closing == "`"):
                break
            if char == "\\":
                self.take()
                escaped = self.take() if self.peek() else "\\"
                value.append(escaped)
                literal.append(escaped)
            elif char == "'":
                self.take()
                body = self.single()
                value.append(body)
                literal.append(body)
            elif char == '"':
                self.take()
                self.double(value, literal)
            elif char == "`":
                self.backquote(value, literal)
            elif char == "$":
                self.dollar(value, literal, quoted=False)
            else:
                value.append(self.take())
                literal.append(char)
        text = "".join(self.code[start:])
        return _Word(text, "".join(value), "".join(literal), start, len(self.code))

    def single(self) -> str:
        """Read a single-quoted string, its opening quote read; return its body."""
        end = self.text.find("'", self.index)
        end = len(self.text) if end < 0 else end
        body = self.text[self.index : end]
        self.code.extend(body)
        self.index = end
        if self.peek():
            self.take()
        return body

    def ansi(self) -> str:
        """Read a ``$'...'`` string, its opening read; return its value."""
        body: list[str] = []
        while self.peek():
            char = self.take()
            if char == "'":
                break
            body.append(char)
            if char == "\\" and self.peek():
                body.append(self.take())
        return _ansi_c("".join(body))

    def double(self, value: list[str], literal: list[str]) -> None:
        """Read a double-quoted string, its opening quote read: a backslash escapes
        ``$``, a backquote, ``"``, a backslash and a line break, and a substitution or
        an expansion inside it is read as one."""
        self.quotes += 1
        while self.peek():
            char = self.peek()
            if char == '"':
                self.take()
                break
            if char == "\\":
                following = self.peek(1)
                if following == "\n":
                    self.index += 2
                    continue
                self.take()
                if following in ("$", "`", '"', "\\"):
                    self.take()
                    value.append(following)
                    literal.append(following)
                else:
                    value.append(char)
                    literal.append(char)
            elif char == "`":
                self.backquote(value, literal)
            elif char == "$":
                self.dollar(value, literal, quoted=True)
            else:
                value.append(self.take())
                literal.append(char)
        self.quotes -= 1

    def dollar(self, value: list[str], literal: list[str], *, quoted: bool) -> None:
        """Read what a ``$`` at the reader's place starts. ``$'...'`` and ``$"..."``
        are quotes only outside double quotes."""
        following = self.peek(1)
        if following == "(":
            self.substitution(value, literal)
            return
        if following in ("'", '"') and not quoted:
            self.take()
            self.take()
            if following == "'":
                body = self.ansi()
                value.append(body)
                literal.append(body)
            else:
                self.double(value, literal)
            return
        start = len(self.code)
        name = _PARAMETER_NAME.match(self.text, self.index + 1)
        if following == "{":
            self.take()
            self.take()
            self.parameter(quoted=quoted)
        elif name:
            while self.index < name.end():
                self.take()
        else:
            value.append(self.take())
            literal.append("$")
            return
        value.append("".join(self.code[start:]))
        literal.append(_EXPANDED)

    def substitution(self, value: list[str], literal: list[str]) -> None:
        """Read a command or process substitution (``$(``, ``<(`` or ``>(``), written
        into ``value`` as it is. Its commands are read as any others are."""
        start = len(self.code)
        self.take()
        self.take()
        self.read_list(")")
        if self.peek():
            self.take()
        value.append("".join(self.code[start:]))
        literal.append(_EXPANDED)

    def backquote(self, value: list[str], literal: list[str]) -> None:
        """Read a backquote substitution, written into ``value`` as it is."""
        start = len(self.code)
        self.take()
        self.quotes += 1
        self.read_list("`")
        self.quotes -= 1
        if self.peek():
            self.take()
        value.append("".join(self.code[start:]))
        literal.append(_EXPANDED)

    def parameter(self, *, quoted: bool) -> None:
        """Read the rest of a ``${...}`` expansion, its ``${`` read: up to the first
        ``}`` outside a quote, a nested expansion or a substitution, where bash ends
        one. Single quotes in it are quotes only outside double quotes."""
        self.quotes += 1
        ignored: list[str] = []
        while True:
            self.join()
            char = self.peek()
            if not char:
                break
            if char == "}":
                self.take()
                break
            if char == "\\":
                self.take()
                if self.peek():
                    self.take()
            elif char == "'" and not quoted:
                self.take()
                self.single()
            elif char == '"':
                self.take()
                self.double(ignored, ignored)
            elif char == "`":
                self.backquote(ignored, ignored)
            elif char == "$":
                self.dollar(ignored, ignored, quoted=quoted)
            else:
                self.take()
        self.quotes -= 1

    def read_documents(self) -> None:
        """Read the lines of the here-documents the line just ended opens, each up to
        its delimiter line, into ``documents``. bash joins the lines of one whose
        delimiter is unquoted where a backslash continues them before it looks for the
        delimiter, and reads one with a quoted delimiter as written. Either way the
        lines a backslash continues are joined for reading (_joined), as a shell given
        the document joins them."""
        for delimiter, strip, quoted, python in self.pending:
            lines: list[str] = []
            pending = ""
            while self.index < len(self.text):
                end = self.text.find("\n", self.index)
                end = len(self.text) if end < 0 else end
                line = self.text[self.index : end]
                self.index = min(end + 1, len(self.text))
                if strip:
                    line = line.lstrip("\t")
                if not quoted and _continues(line):
                    pending += line[:-1]
                    continue
                line, pending = pending + line, ""
                if line.rstrip("\r") == delimiter:
                    break
                lines.append(line)
            if pending:
                lines.append(pending)
            self.documents.append((len(self.ends), _joined(lines), python))
        self.pending = []


#: A number for each script read, to tell apart the code their offsets are into.
_SCRIPT_NUMBERS = itertools.count(1)


@functools.lru_cache(maxsize=4096)
def _read_script(text: str, depth: int = 0) -> tuple[_Line, ...]:
    """The lines of a script as bash joins them, each with its commands (_Reader): the
    lines a backslash continues are one, a line break inside a quote or a backquote
    pair is kept inside its line, and each line of a here-document is a line of its
    own, read as a script. A command's substitutions are read as commands of their
    own, and so is a script it runs (_scripts_run), up to _MAX_SCRIPT_DEPTH deep."""
    reader = _Reader(text)
    reader.read_list("")
    code = "".join(reader.code)
    source = next(_SCRIPT_NUMBERS)
    starts = [0, *(end + 1 for end in reader.ends)]
    found = sorted(reader.found, key=lambda item: (item[1], -item[2]))
    commands: list[list[_Command]] = [[] for _ in starts]
    for words, start, end in found:
        runs = _scripts_run(tuple(words))
        unread = bool(runs) and depth >= _MAX_SCRIPT_DEPTH
        if unread:
            runs = []
        inner = sorted(
            {
                (other_start - start, other_end - start)
                for _, other_start, other_end in found
                if start < other_start and other_end <= end
            }
            | {
                (words[index].start - start, words[index].end - start)
                for indices, _ in runs
                for index in indices
            }
        )
        command = _Command(
            words=tuple(words),
            text=code[start:end],
            start=start,
            end=end,
            source=source,
            scripts=frozenset(index for indices, _ in runs for index in indices),
            inner=tuple(inner),
            unread=unread,
        )
        line = bisect.bisect_right(starts, start) - 1
        commands[line].append(command)
        for _, script in runs:
            commands[line] += [
                each
                for script_line in _read_script(script, depth + 1)
                for each in script_line.commands
            ]
    lines: list[_Line] = []
    for number, start in enumerate(starts):
        end = reader.ends[number] if number < len(reader.ends) else len(code)
        line = code[start:end]
        comment = line.lstrip().startswith("#") and not _QUOTE_CHARACTERS & set(line)
        lines.append(_Line(line, comment, tuple(commands[number])))
        for after, document, python in reader.documents:
            if after != number + 1:
                continue
            for body in document:
                # A here-document fed to Python is a line of text for the checks that
                # read lines, but no commands: it is not a shell script, and what a
                # Python program runs is not read by these checks, as for any program.
                read = (
                    ()
                    if python or depth >= _MAX_SCRIPT_DEPTH
                    else _read_script(body, depth + 1)
                )
                lines.append(
                    _Line(body, False, tuple(c for each in read for c in each.commands))
                )
    return tuple(lines)


def _command_names(words: tuple[_Word, ...]) -> list[int]:
    """The indices of the words of a command that bash runs as programs: the first
    word that is not an assignment, nor an unquoted substitution or expansion alone,
    which can expand to nothing (``$(true) brew install ash``); after a keyword or a
    wrapper (_COMMAND_PREFIXES), the next such word past the options, numbers and
    assignments after it (``sudo -E pip``, ``nice -n 10 pip``); and the module of
    ``python -m``. The word after an option of a wrapper that takes a value is read as
    the program (``sudo -u runner pip`` runs ``runner``), so the program after it is
    not read as one."""
    names: list[int] = []
    prefix = False
    for index, word in enumerate(words):
        if _ASSIGNMENT_WORD.match(word.text) or (
            set(word.literal) == {_EXPANDED} and word.text[:1] not in ("'", '"')
        ):
            continue
        if prefix and (word.value.startswith("-") or word.value.isdigit()):
            continue
        names.append(index)
        if word.value in _COMMAND_PREFIXES or word.value in ("{", "}"):
            prefix = True
            continue
        if _PYTHON_WORD.fullmatch(word.name):
            module = _python_module(words, index + 1)
            if module is not None:
                names.append(module)
        break
    return names


def _python_module(words: tuple[_Word, ...], index: int) -> int | None:
    """The index of the module a python word's ``-m`` runs, its options read past from
    ``index``, or None when it runs none."""
    while index < len(words):
        value = words[index].value
        if value == "-m":
            return index + 1 if index + 1 < len(words) else None
        if not value.startswith("-"):
            return None
        index += 1
    return None


def _scripts_run(words: tuple[_Word, ...]) -> list[tuple[tuple[int, ...], str]]:
    """The scripts a command runs from its words, each with the indices of the words
    it is read from: the words eval runs, joined as eval joins them; the -c script of
    a shell (_SHELLS) wherever that shell stands among the words, as after ``find
    -exec`` or ``xargs``; and the -c or --command of su or runuser."""
    found: list[tuple[tuple[int, ...], str]] = []
    for index in _command_names(words):
        if words[index].value == "eval" and index + 1 < len(words):
            joined = " ".join(word.value for word in words[index + 1 :])
            found.append((tuple(range(index + 1, len(words))), joined))
            break
    for index, word in enumerate(words):
        if word.name in _SHELLS:
            script = _shell_script(words, index)
            if script is not None:
                found.append(((script,), words[script].value))
        elif word.name in _SWITCH_USER:
            found += [((at,), text) for at, text in _switch_user_command(words, index)]
    return found


def _shell_script(words: tuple[_Word, ...], index: int) -> int | None:
    """The index of the script the shell at ``index`` runs with -c, or None."""
    command = False
    position = index + 1
    while position < len(words):
        option = words[position].value
        if option == "--":
            position += 1
            break
        if option in _SHELL_VALUE_OPTIONS:
            position += 2
        elif option.startswith("--"):
            position += 1
        elif len(option) > 1 and option[0] in "-+":
            command = command or (option[0] == "-" and "c" in option[1:])
            position += 2 if {"o", "O"} & set(option[1:]) else 1
        else:
            break
    return position if command and position < len(words) else None


def _switch_user_command(words: tuple[_Word, ...], index: int) -> list[tuple[int, str]]:
    """The command su or runuser at ``index`` runs: its -c or --command value."""
    position = index + 1
    while position < len(words):
        option = words[position].value
        if option == "--":
            break
        if option.startswith("--command="):
            return [(position, option.partition("=")[2])]
        if option == "--command" or (
            len(option) > 1 and option[0] == "-" and option[1] != "-" and "c" in option
        ):
            rest = "" if option == "--command" else option[option.index("c") + 1 :]
            if rest:
                return [(position, rest)]
            if position + 1 < len(words):
                return [(position + 1, words[position + 1].value)]
            return []
        position += 1
    return []


def _groovy_strings(text: str) -> list[str]:
    """The value of each string literal of a Jenkinsfile's Groovy text, in order: the
    scripts its sh steps run among them. ``'''`` and ``\"\"\"`` strings and one-line
    ``'`` and ``\"`` strings are read, with Groovy's escapes decoded and a backslash
    before a line break joining the two lines, as Groovy reads them; ``//`` and
    ``/* */`` comments are skipped. A ``${...}`` that Groovy fills in is kept as
    written, and read as a parameter expansion."""
    found: list[str] = []
    index = 0
    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = len(text) if end < 0 else end + 2
            continue
        quote = next(
            (q for q in ("'''", '"""', "'", '"') if text.startswith(q, index)), ""
        )
        if not quote:
            index += 1
            continue
        index += len(quote)
        value: list[str] = []
        while index < len(text) and not text.startswith(quote, index):
            char = text[index]
            if len(quote) == 1 and char == "\n":
                break
            if char == "\\" and index + 1 < len(text):
                following = text[index + 1]
                code = text[index + 2 : index + 6]
                if following == "\n":
                    index += 2
                elif following == "u" and re.fullmatch(r"[0-9A-Fa-f]{4}", code):
                    value.append(chr(int(code, 16)))
                    index += 6
                else:
                    value.append(_GROOVY_ESCAPES.get(following, char + following))
                    index += 2
                continue
            value.append(char)
            index += 1
        index += len(quote)
        found.append("".join(value))
    return found


def _shell_scripts(kind: str, text: str, document: Any) -> list[str]:
    """The shell scripts a pipeline holds, each read on its own: every string of a
    YAML pipeline, and every string literal of a Jenkinsfile (_groovy_strings)."""
    if kind == "jenkinsfile":
        return _groovy_strings(text)
    return list(_strings(document))


def _pipeline_commands(kind: str, text: str, document: Any) -> Iterator[_Command]:
    """Every command of a pipeline's shell scripts (_shell_scripts, _read_script)."""
    for script in _shell_scripts(kind, text, document):
        for line in _read_script(script):
            yield from line.commands


def _pipeline_texts(kind: str, text: str, document: Any) -> list[tuple[_Line, ...]]:
    """The lines of each of a pipeline's shell scripts (_read_script), and for a
    Jenkinsfile, the lines of its Groovy text as written too, which set the
    environment its scripts run in (``environment { INSTALL_SPEC = '...' }``)."""
    scripts = [_read_script(s) for s in _shell_scripts(kind, text, document)]
    if kind == "jenkinsfile":
        scripts.append(tuple(_Line(line, False, ()) for line in text.split("\n")))
    return scripts


def _command_name(tool: str, arguments: list[str]) -> tuple[str, int] | None:
    """The command a call of uv, pip or pipx runs, read past the options the tool takes
    before it, and the index of the first argument after it: ``uv --cache-dir venv pip
    install`` runs ``pip install``, not ``venv``. A uv group and its command make one
    name (``tool install``), with uv's global options between them read too. The name
    is empty when the call names no command (``pip --version``).

    None when an option before the name is not one the tool is known to take there (a
    shortened pip option such as ``--cach``, a uv option its help does not list such as
    ``--preview-features``, any option before a pipx command): its value could be the
    word that would be read as the name."""
    if tool == "uv":
        options, groups = _UV_GLOBAL_OPTIONS, _UV_GROUPS
    elif _PIP_TOOL.fullmatch(tool):
        options, groups = _PIP_GENERAL_OPTIONS, frozenset()
    else:
        options, groups = _PIPX_LEADING_OPTIONS, frozenset()
    words: list[str] = []
    index = 0
    while index < len(arguments):
        word = arguments[index]
        index += 1
        if word.startswith("--"):
            name, equals, _ = word.partition("=")
            if name in options.values:
                index += 0 if equals else 1
            elif name not in options.flags:
                return None
        elif len(word) > 1 and word.startswith("-"):
            if not set(word[1:]) <= options.short_flags:
                return None
        else:
            words.append(word)
            if words[0] not in groups or len(words) == 2:
                break
    return " ".join(words), index


def _followed_install_problem(
    segment: str, arguments: list[str], end: int, flags: _LeadingOptions, where: str
) -> str | None:
    """Why an install by pip or ``uv tool install`` is not one the provenance print
    follows, or None when it is: its arguments ``arguments``, whose command ends at
    ``end``, must name INSTALL_SPEC alone, with no option but one of ``flags``, before
    or after the command. Any other option can change where or what it installs
    (``pip --python OTHER install``, ``pip install --target=DIR``, ``uv tool install
    --config-file=FILE``), and so can one whose value is joined to it or is the next
    word, a flag included (``--target --quiet``)."""
    shown = segment.strip()
    for word in arguments:
        if not word.startswith("-"):
            continue
        if word.startswith("--"):
            known = word in flags.flags
        else:
            known = set(word[1:]) <= flags.short_flags
        if not known:
            return (
                f"`{shown}` gives the install {word}, which is not one of its flags "
                f"and can change where or what it installs, and {_FOLLOWED_INSTALLS}"
            )
    names = [word for word in arguments[end:] if not word.startswith("-")]
    if (
        len(names) == 1
        and names[0] in _SPEC_VARIABLES
        and _interpreters(segment, where)
    ):
        return None
    return f"`{shown}` installs Python packages, and {_FOLLOWED_INSTALLS}"


def _pip_config_writes(arguments: list[str]) -> bool:
    """Whether ``pip config`` with ``arguments`` (those after ``config``) can write
    pip's configuration: its action, the first word that is neither an option nor the
    value of ``--editor``, is anything but one that only reads (_PIP_CONFIG_READS)."""
    index = 0
    while index < len(arguments):
        word = arguments[index]
        if word == "--editor":
            index += 2
        elif word.startswith("-"):
            index += 1
        else:
            return word not in _PIP_CONFIG_READS
    return False


def _arguments(command: _Command, index: int) -> list[str]:
    """The values of the words after the program at ``index``, empty ones left out."""
    return [word.value for word in command.words[index + 1 :] if word.value]


def _unfollowed_install(command: _Command, where: str) -> str | None:
    """Why a command installs Python packages in a way the rewrites cannot follow. Each
    program it runs (_command_names) is read by the name its word gives it, and the
    command a uv, pip or pipx call runs is read past the options before it
    (_command_name)."""
    segment = command.text
    shown = segment.strip()
    if command.unread:
        return f"`{shown}` runs a script nested too deep to read"
    for index in _command_names(command.words):
        tool = command.words[index].name
        if not _TOOL_NAME.fullmatch(tool):
            continue
        arguments = _arguments(command, index)
        names = [word for word in arguments if not word.startswith("-")]
        if not names:
            continue
        if tool == "brew" and arguments[0] in _BREW_READ_ONLY:
            continue
        if tool in _UNFOLLOWED_TOOLS:
            return f"`{shown}` runs {tool}, whose installs the rewrites do not follow"
        if tool == "uvx":
            return (
                f"`{shown}` runs a tool uvx installs, which the rewrites do not follow"
            )
        read = _command_name(tool, arguments)
        if read is None:
            return f"cannot tell what `{shown}` runs, so it could install another ASH"
        runs, end = read
        if not runs:
            continue
        if tool == "pipx":
            if runs in _PIPX_READ_ONLY:
                continue
            return f"`{shown}` installs or runs a package with pipx"
        if tool == "uv":
            if runs in _UV_READ_ONLY:
                continue
            if runs != "tool install":
                return f"`{shown}` installs Python packages, and {_FOLLOWED_INSTALLS}"
            problem = _followed_install_problem(
                segment, arguments, end, _UV_TOOL_INSTALL_FLAGS, where
            )
            if problem:
                return problem
            continue
        if runs not in _PIP_COMMANDS:
            return f"cannot tell what `{shown}` runs, so it could install another ASH"
        if runs == "config" and _pip_config_writes(arguments[end:]):
            return (
                f"`{shown}` writes pip's configuration, which a later install reads, so "
                "it can change where or what that install puts in place"
            )
        if runs == "install":
            problem = _followed_install_problem(
                segment, arguments, end, _PIP_INSTALL_FLAGS, where
            )
            if problem:
                return problem
    return None


def _followed_lines_problem(command: _Command, where: str) -> str | None:
    """Why an install the provenance print follows is not one it can follow, read
    wherever it stands in the command: the print follows every line _UV_TOOL_INSTALL
    or _PIP_INSTALL matches (_interpreters), whether or not _unfollowed_install read
    the install as a program the command runs (``timeout 5m uv tool install``), so its
    options get the same check (_followed_install_problem). Both patterns put the
    command right after the tool, so its words (``tool install``, ``install``) are the
    first arguments. A match inside a substitution or a script the command runs is
    that command's own; one inside another word, such as a quoted argument, is an
    install whose options cannot be read, and is refused."""
    segment = command.text
    found = [
        (match.start(), 2, _UV_TOOL_INSTALL_FLAGS)
        for match in _UV_TOOL_INSTALL.finditer(segment)
    ] + [
        (match.start("pip"), 1, _PIP_INSTALL_FLAGS)
        for match in _PIP_INSTALL.finditer(segment)
    ]
    for position, end, flags in found:
        if any(start <= position < stop for start, stop in command.inner):
            continue
        index = next(
            (
                i
                for i, word in enumerate(command.words)
                if word.start - command.start <= position < word.end - command.start
            ),
            None,
        )
        name = command.words[index].name if index is not None else ""
        if not (name == "uv" if end == 2 else _PIP_TOOL.fullmatch(name)):
            return (
                f"`{segment.strip()}` holds an install the provenance print follows "
                f"whose options cannot be read, and {_FOLLOWED_INSTALLS}"
            )
        arguments = _arguments(command, index)
        problem = _followed_install_problem(segment, arguments, end, flags, where)
        if problem:
            return problem
    return None


def _install_spec_definitions(
    kind: str, text: str, document: Any, ctx: RewriteContext, where: str
) -> None:
    """Refuse INSTALL_SPEC set to anything but the rewritten spec, anywhere."""

    def check(value: Any, shown: str) -> None:
        if value != ctx.install_spec:
            raise RewriteError(
                f"{where}: `{shown}` sets INSTALL_SPEC to something other than the "
                "rewritten install spec, so the install that reads it could install "
                "another ASH"
            )

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "INSTALL_SPEC":
                    check(value, f"INSTALL_SPEC: {value}")
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(document)
    for lines in _pipeline_texts(kind, text, document):
        for line in lines:
            for match in _SPEC_ASSIGNMENT.finditer(line.text):
                check(
                    match["quoted"] if match["q"] else match["bare"], line.text.strip()
                )


def _installer_settings(kind: str, text: str, document: Any, where: str) -> None:
    """Refuse a pipeline that sets a variable pip or uv reads a setting from
    (_INSTALLER_SETTING_WORD): as a key of any mapping of a YAML pipeline, which takes
    in every env scope (a workflow's, job's or step's env, GitLab variables, a CircleCI
    environment, a buildspec's env.variables), or in any line of a script or of a
    Jenkinsfile's Groovy text (_pipeline_texts) that names one other than to read its
    value (_names_the_source: an assignment, an export, ``env NAME=value``, a
    Jenkinsfile environment entry). A line that only prints the name is kept, in a
    script that sends nothing elsewhere (_prints_only, _captures), as the scan
    workflow's checks keep one."""

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and _INSTALLER_SETTING_WORD.fullmatch(key):
                    raise RewriteError(
                        f"{where}: `{key}: {value}` sets {key}, {_INSTALLER_SETTING}"
                    )
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(document)
    for lines in _pipeline_texts(kind, text, document):
        captured = _captures(lines)
        for line in lines:
            readings = _readings(line.text)
            if not captured and _prints_only(readings[0]):
                continue
            if any(
                _names_the_source(reading, _INSTALLER_SETTING_WORD)
                for reading in readings
            ):
                raise RewriteError(
                    f"{where}: `{line.text.strip()}` sets a PIP_ or UV_ variable, "
                    f"{_INSTALLER_SETTING}"
                )


def _other_sources(
    kind: str, text: str, document: Any, ctx: RewriteContext, where: str
) -> None:
    """Refuse a pipeline that could get ASH from anywhere but the rewritten spec.

    That is a line naming ASH's repository (a URL of it, or one of its workflows or
    actions at a ref) other than in the install spec; an installer command (pip, uv,
    uvx, pipx) that names the package other than through the spec or the variable
    holding it; an install from a requirements file; any other command that installs
    Python packages besides the two installs of INSTALL_SPEC the print follows; and
    INSTALL_SPEC set to anything but the rewritten spec.
    """
    for line in text.replace(ctx.install_spec, "").split("\n"):
        if _ASH_REPOSITORY.search(line):
            raise RewriteError(
                f"{where}: `{line.strip()}` names ASH's repository, so the pipeline "
                "could run an ASH other than the one the rewritten install spec names"
            )
    for command in _pipeline_commands(kind, text, document):
        segment = command.text
        if _INSTALLER.search(segment):
            named = segment.replace(ctx.install_spec, "")
            for variable in ('"$INSTALL_SPEC"', '"${INSTALL_SPEC}"'):
                named = named.replace(variable, "")
            if _ASH_NAME.search(named):
                raise RewriteError(
                    f"{where}: `{segment.strip()}` installs ASH from somewhere "
                    "other than the rewritten install spec"
                )
            if _REQUIREMENTS.search(segment):
                raise RewriteError(
                    f"{where}: `{segment.strip()}` installs from a requirements "
                    "file, which can name any ASH"
                )
        problem = _unfollowed_install(command, where) or _followed_lines_problem(
            command, where
        )
        if problem:
            raise RewriteError(
                f"{where}: {problem}, so the pipeline could run an ASH other than the "
                "one under test"
            )
    _installer_settings(kind, text, document, where)
    _install_spec_definitions(kind, text, document, ctx, where)


def _image_parts(ref: str) -> tuple[str, str]:
    """An image reference's repository, and what follows it: ``:<tag>``,
    ``@<digest>``, or nothing."""
    name, at, digest = ref.removeprefix("docker://").partition("@")
    path, slash, last = name.rpartition("/")
    last, colon, tag = last.partition(":")
    suffix = f"@{digest}" if at else (f":{tag}" if colon else "")
    return path + slash + last, suffix


def _is_ash_image(ref: str, ctx: RewriteContext) -> bool:
    """Whether ``ref`` names an image of ASH: a repository with a path component
    automated-security-helper, or the base repository's own image."""
    repository = _image_parts(ref)[0].lower()
    own = ctx.repository.lower()
    return bool(_ASH_IMAGE_PATH.search(repository)) or (
        repository == own or repository.endswith(f"/{own}")
    )


def _github_images(document: Any) -> list[Any]:
    """The images a GitHub workflow's jobs run on: containers, services and docker
    steps."""
    found: list[Any] = []
    jobs = document.get("jobs") if isinstance(document, dict) else None
    for job in (jobs or {}).values() if isinstance(jobs, dict) else ():
        if not isinstance(job, dict):
            continue
        container = job.get("container")
        found.append(
            container.get("image") if isinstance(container, dict) else container
        )
        services = job.get("services")
        for service in (services or {}).values() if isinstance(services, dict) else ():
            found.append(service.get("image") if isinstance(service, dict) else service)
        for step in job.get("steps") or ():
            uses = step.get("uses") if isinstance(step, dict) else None
            if isinstance(uses, str) and uses.startswith("docker://"):
                found.append(uses)
    return [image for image in found if image is not None]


def _ash_images(
    kind: str, text: str, document: Any, ctx: RewriteContext, where: str
) -> None:
    """Refuse an image of ASH other than one the run builds, however it is named."""
    refs = [match.group(0) for match in _ASH_IMAGE_REFERENCE.finditer(text)]
    own = re.escape(ctx.repository)
    refs += re.findall(
        rf"(?<![\w.:@-])(?:[\w.-]+(?::\d+)?/)*{own}(?::\w[\w.-]{{0,127}}"
        rf"|@sha256:[0-9a-f]{{64}})(?![\w./:@-])",
        text,
        flags=re.IGNORECASE,
    )
    if kind in ("gitlab-ci", "circleci"):
        refs += _images_in(document)
    elif kind == "github-actions":
        refs += _github_images(document)
    elif kind == "jenkinsfile":
        refs += [match["ref"] for match in _JENKINS_IMAGE.finditer(text)]
    for command in _pipeline_commands(kind, text, document):
        if _CONTAINER_RUN.search(command.text):
            refs += [w.value for w in command.words if _is_ash_image(w.value, ctx)]
    for ref in dict.fromkeys(r for r in refs if isinstance(r, str)):
        bare = ref.removeprefix("docker://")
        if bare in ctx.built_images or not _is_ash_image(bare, ctx):
            continue
        suffix = _image_parts(bare)[1]
        how = (
            "by digest"
            if suffix.startswith("@")
            else "by tag"
            if suffix
            else "with no tag"
        )
        built = ", ".join(sorted(ctx.built_images)) or "none"
        raise RewriteError(
            f"{where}: {bare} is an image of ASH named {how}, not an image the run "
            f"builds ({built}), so the job would run that image's ASH instead of the "
            "one under test"
        )


# ---------------------------------------------------------------------------
# The rewrite
# ---------------------------------------------------------------------------


def _rewrite_artifact_actions(text: str, where: str, applied: list[Applied]) -> str:
    """Run the pipeline's artifact steps on the v4 actions act 0.2.89 can run.

    The pages name the current ``actions/upload-artifact`` and
    ``actions/download-artifact`` for the people who use GitHub. act 0.2.89, the newest
    release, cannot serve them: upload-artifact v7.0.0 and later send a
    ``mime_type`` field that act's artifact server rejects as unknown (act issue 6114,
    pull requests 6115 and 6174 fix it and are not merged), and the later releases of
    both actions are reported to fail against it too. The v4 releases work. So each
    ``uses:`` of either action, at any ref, becomes ACT_UPLOAD_ARTIFACT or
    ACT_DOWNLOAD_ARTIFACT, and the step's ``with:`` block is left as it is: ``name``,
    ``path``, ``pattern`` and ``merge-multiple`` mean the same in v4. A line already on
    the pinned release is left alone, so the rewrite can run twice.

    A ``uses:`` of either action that the pattern does not read (a quoted value, a flow
    mapping) is an error, since that step would still run a release act cannot serve.
    """
    pinned = {
        "actions/upload-artifact": ACT_UPLOAD_ARTIFACT,
        "actions/download-artifact": ACT_DOWNLOAD_ARTIFACT,
    }
    found: dict[str, int] = {}

    def swap(match: re.Match[str]) -> str:
        new = pinned[match["action"]]
        old = match.group(0).removeprefix(match["head"]).rstrip()
        if old == new:
            return match.group(0)
        found[old] = found.get(old, 0) + 1
        return match["head"] + new

    text = _ARTIFACT_USES.sub(swap, text)
    for old, count in found.items():
        action = old.split("@", 1)[0]
        applied.append(Applied("artifact-actions", old, pinned[action], count))
    for line in text.split("\n"):
        for action, new in pinned.items():
            if "uses:" in line and f"{action}@" in line and new not in line:
                raise RewriteError(
                    f"{where}: {line.strip()!r} uses {action} in a form the rewrite "
                    "does not read, so act would run a release it cannot serve"
                )
    return text


def _serialize_matrices(text: str, where: str, applied: list[Applied]) -> str:
    """Give every ``strategy:`` that has a ``matrix:`` the line ``max-parallel: 1``.

    act runs the entries of a matrix at the same time whatever ``--concurrent-jobs``
    says, and its action cache then races when several entries fetch one action
    (act issue 6028, reported cause: one entry reads the cached repository while
    another deletes its working branch, and the step fails with ``failed to read
    'action.yml' ... file does not exist``). ``max-parallel`` is the setting act reads
    to bound a matrix, so one entry runs at a time. A ``max-parallel`` already in the
    block is set to 1. The result is read back as YAML: a matrix the line edit did not
    reach (a ``strategy`` written as a flow mapping) is an error.
    """
    lines = text.split("\n")
    inserted = 0
    for index in range(len(lines) - 1, -1, -1):
        header = _STRATEGY_LINE.match(lines[index])
        if not header:
            continue
        indent = len(header["indent"])
        end = index + 1
        while end < len(lines) and (
            not lines[end].strip()
            or len(lines[end]) - len(lines[end].lstrip(" ")) > indent
        ):
            end += 1
        body = [
            k
            for k in range(index + 1, end)
            if lines[k].strip() and not lines[k].lstrip().startswith("#")
        ]
        if not body:
            continue
        child = len(lines[body[0]]) - len(lines[body[0]].lstrip(" "))
        keys = {
            m["key"]: k
            for k in body
            if (m := re.match(r" {%d}(?P<key>[\w-]+):" % child, lines[k]))
        }
        if "matrix" not in keys:
            continue
        pad = " " * child
        if "max-parallel" in keys:
            current = lines[keys["max-parallel"]]
            if current.split(":", 1)[1].split("#", 1)[0].strip() == "1":
                continue
            lines[keys["max-parallel"]] = f"{pad}max-parallel: 1"
        else:
            lines[index + 1 : index + 1] = [
                f"{pad}# act runs matrix entries at once and its action cache",
                f"{pad}# races on them (act issue 6028), so one runs at a time.",
                f"{pad}max-parallel: 1",
            ]
        inserted += 1
    if inserted:
        applied.append(
            Applied(
                "serial-matrix",
                "strategy: matrix",
                "strategy: matrix, max-parallel: 1",
                inserted,
            )
        )
    text = "\n".join(lines)
    document = _load(text, where)
    jobs = document.get("jobs") if isinstance(document, dict) else None
    for job_id, body in jobs.items() if isinstance(jobs, dict) else ():
        strategy = body.get("strategy") if isinstance(body, dict) else None
        if (
            isinstance(strategy, dict)
            and "matrix" in strategy
            and strategy.get("max-parallel") != 1
        ):
            raise RewriteError(
                f"{where}: the job {job_id} has a matrix that the max-parallel edit "
                "did not reach, so act would run its entries at once"
            )
    return text


def rewrite_pipeline(
    kind: str, text: str, ctx: RewriteContext, *, where: str
) -> RewriteResult:
    """The pipeline file ``text`` of a ``kind`` block, made to run the ASH under test.

    ``where`` names the block (``page.md:<line>``) in every error.
    """
    if kind not in RUNNERS_OF_KIND:
        raise RewriteError(f"{where}: config kind={kind} has no runner to rewrite for")
    if ctx.runner not in RUNNERS_OF_KIND[kind]:
        raise RewriteError(
            f"{where}: a {kind} block runs under "
            f"{', '.join(sorted(RUNNERS_OF_KIND[kind]))}, not {ctx.runner}"
        )
    applied: list[Applied] = []
    original = text
    release_spec = (
        f"{REQUIREMENT} @ git+https://github.com/{RELEASE_REPOSITORY}.git"
        f"@v{ctx.version}"
    )
    text = _replace_reference(
        text,
        release_spec,
        ctx.install_spec,
        rule="install",
        where=where,
        applied=applied,
    )
    if kind == "github-actions":
        prefix = f"{RELEASE_REPOSITORY}/.github/workflows/"
        files = re.findall(
            re.escape(prefix) + r"([A-Za-z0-9._-]+)" + re.escape(f"@v{ctx.version}"),
            text,
        )
        for file in dict.fromkeys(files):
            text = _replace_reference(
                text,
                f"{prefix}{file}@v{ctx.version}",
                f"./.github/workflows/{file}",
                rule="reusable-workflow",
                where=where,
                applied=applied,
            )
        text = _rewrite_ash_version(text, ctx, where, applied)
        text = _rewrite_artifact_actions(text, where, applied)
        text = _serialize_matrices(text, where, applied)
    used_built = False
    document = None if kind == "jenkinsfile" else _load(text, where)
    _ash_images(kind, text, document, ctx, where)
    if kind in ("gitlab-ci", "circleci"):
        text, used_built = _rewrite_images(text, document, ctx, where, applied)
        document = _load(text, where)
        if used_built and kind != "gitlab-ci":
            raise RewriteError(
                f"{where}: a {kind} job runs on an image the run builds, and only a "
                "GitLab job on one gets a print of that image's ASH"
            )
    installs = any(a.rule == "install" for a in applied)
    reusable = any(a.rule == "reusable-workflow" for a in applied)
    if not (installs or reusable or used_built):
        raise RewriteError(
            f"{where}: the block installs ASH in none of the forms the rewrites know "
            f"(INSTALL_SPEC {release_spec!r}, a call of ASH's reusable workflows at "
            f"v{ctx.version}, or a job on an image the run builds), so it would not "
            "run the ASH under test"
        )
    _other_sources(kind, text, document, ctx, where)
    lines = text.split("\n")
    if kind == "jenkinsfile":
        insertions = _jenkinsfile_provenance(lines, where)
    else:
        root = _compose(text, where)
        if kind == "github-actions":
            insertions = _github_provenance(lines, root, document, where)
        else:
            insertions = _yaml_provenance(kind, lines, root, document, where)
        if kind == "gitlab-ci":
            built = _built_provenance(lines, root, document, ctx, where)
            both = {i.job for i in insertions} & {i.job for i in built}
            if both:
                raise RewriteError(
                    f"{where}: the job {', '.join(sorted(map(str, both)))} runs on an "
                    "image the run builds and installs ASH again, so which ASH it runs "
                    "cannot be told"
                )
            if used_built and not built:
                raise RewriteError(
                    f"{where}: no job on an image the run builds runs ash, so the "
                    "block runs no ASH to measure"
                )
            insertions += built
        if kind == "circleci":
            insertions += _report_copy(lines, root, ctx, where)
    provenance = [i for i in insertions if i.rule == "provenance"]
    if installs and not provenance:
        raise RewriteError(
            f"{where}: the block sets the install spec, but no install of "
            "INSTALL_SPEC was found to print the provenance after"
        )
    text = _apply_insertions(text, insertions, applied)
    if kind != "jenkinsfile":
        document = _load(text, where)
        if kind == "github-actions":
            _check_print_steps(document, len(provenance), where)
        else:
            _check_print_lines(
                document, [c for i in provenance for c in i.commands], where
            )
        if kind == "gitlab-ci":
            built = [i for i in insertions if i.rule == "built-provenance"]
            _check_built_prints(document, built, where)
        if kind == "circleci":
            copies = sum(i.rule == "report-copy" for i in insertions)
            _check_report_copy(document, copies, where)
    return RewriteResult(text=text, applied=tuple(applied), original=original)


def _decoded_escape(match: re.Match[str]) -> str:
    for group, base in (("x", 16), ("u", 16), ("U", 16), ("o", 8)):
        if match[group]:
            code = int(match[group], base)
            return chr(code) if code <= sys.maxunicode else " "
    return " "


def _readings(line: str) -> tuple[str, str]:
    """``line`` read two ways with its quoting gone, since what it spells depends on
    what reads it: with quotes and backslashes dropped, as the shell drops them
    (``ASH_UVX_SOURC\\E`` is ``ASH_UVX_SOURCE``); and with each escape that printf,
    ``echo -e`` or ``$'...'`` decodes written out first (``\\x41`` is ``A``), and any
    other letter's escape read as a break between words (``\\n``). The ``$`` of
    ``$'...'`` and ``$"..."`` goes with the quotes."""
    unquoted = re.sub(r"\$(?=['\"])", "", line)
    return (
        unquoted.translate(_QUOTING),
        _ESCAPE.sub(_decoded_escape, unquoted).translate(_QUOTING),
    )


def _brace_alternatives(body: str) -> list[str] | None:
    """The words a brace group with ``body`` expands to, or None when bash leaves it
    as it is. A numeric sequence is one number: ASH_UVX_SOURCE holds no digit, so no
    number of a sequence can spell part of it."""
    if "," in body:
        return body.split(",")
    letters = _LETTER_SEQUENCE.fullmatch(body)
    if letters:
        low, high = sorted((ord(letters["a"]), ord(letters["b"])))
        return [chr(code) for code in range(low, high + 1)]
    if _NUMBER_SEQUENCE.fullmatch(body):
        return ["0"]
    return None


def _brace_expansions(reading: str) -> list[str] | None:
    """``reading`` with its brace expansions written out, every combination, as bash
    expands them (``ASH_UVX_{SOURCE,UNUSED}`` holds ``ASH_UVX_SOURCE``), or None when
    there are more than _MAX_BRACE_WORDS. Each parameter expansion is first written as
    one _PARAMETER_MARK, which spells no name, so that a brace group around one
    (``ASH_UVX_{${X},SOURCE}``) is expanded too; and so is each group bash leaves as it
    is once no group inside it expands (_BRACE_MARK), so that a group around one
    (``ASH_UVX_{{x},SOURCE}``) is expanded as well. A reading with none is returned as
    it is."""
    masked = reading
    while True:
        unmasked, masked = masked, _PARAMETER.sub(_PARAMETER_MARK, masked)
        if masked == unmasked:
            break
    done: list[str] = []
    pending = [masked]
    while pending:
        current = pending.pop()
        group = next(
            (
                (match, alternatives)
                for match in _BRACES.finditer(current)
                for alternatives in [_brace_alternatives(match["body"])]
                if alternatives is not None
            ),
            None,
        )
        if group is None:
            literal = _BRACES.search(current)
            if literal is not None:
                pending.append(
                    current[: literal.start()] + _BRACE_MARK + current[literal.end() :]
                )
                continue
            done.append(current)
            continue
        match, alternatives = group
        pending += [
            current[: match.start()] + alternative + current[match.end() :]
            for alternative in alternatives
        ]
        if len(done) + len(pending) > _MAX_BRACE_WORDS:
            return None
    return [reading] if done == [masked] else done


def _names_the_source(reading: str, name: re.Pattern[str] = _UVX_SOURCE_WORD) -> bool:
    """Whether ``reading`` names ASH_UVX_SOURCE (or another ``name``) other than to read
    its value: as a word of its own, after ``=``, ``{`` or any other mark, or joined to
    an option (``-vASH_UVX_SOURCE``). ``$NAME``, ``${NAME}``, ``${#NAME}``,
    ``${!NAME}``, ``${NAME:?}``, ``${{ env.NAME }}`` and a longer name are not it.
    ``${NAME:=value}``, ``${NAME=value}`` and ``${NAME[0]:=value}`` are: they set the
    variable when it is unset, as it is in a command run with an emptied environment
    (``env -i``, ``sudo``)."""
    for match in name.finditer(reading):
        before = reading[: match.start()]
        read = _UVX_SOURCE_READ.search(before)
        if read is not None and not (
            read.group().startswith("${")
            and _ASSIGNS_DEFAULT.match(reading, match.end())
        ):
            continue
        if (
            read is None
            and _ENDS_IN_A_WORD_CHARACTER.search(before)
            and not _JOINED_OPTIONS.search(before)
        ):
            continue
        return True
    return False


def _prints_only(reading: str) -> bool:
    """Whether a line is an echo, or a printf with no ``-v``, of plain words."""
    if not _PRINT_ONLY.fullmatch(reading):
        return False
    words = reading.split()
    return words[0] == "echo" or not any(word.startswith("-v") for word in words[1:])


def _captures(lines: tuple[_Line, ...]) -> bool:
    """Whether a later command could read what one of ``lines`` prints, or echo and
    printf could run something else (_CAPTURES), in a line as written or in either of
    its readings."""
    return any(
        _CAPTURES.search(reading)
        for line in lines
        for reading in (line.text, *_readings(line.text))
    )


def _uvx_source_problem(text: str) -> tuple[str, str] | None:
    """The first line of ``text`` that could set ASH_UVX_SOURCE, and how (a key of
    _SOURCE_PROBLEMS), or None.

    ``text`` is a step's script, an action's input or an env value, read in lines as
    bash joins them, a quoted line break kept inside its line (_read_script). Each
    line is read with its quoting removed, two ways (_readings), and each reading also
    with its brace expansions written out (_brace_expansions); a line with more of
    them than that writes out is refused. A line is refused when any reading:

    * names ASH_UVX_SOURCE other than to read its value (_names_the_source): an
      assignment or an append, alone or after export, declare, local or eval, or
      written to a file; the target of read, printf -v, mapfile, readarray, getopts,
      a for loop, a nameref or an allocated file descriptor; a default assigned with
      ``${NAME:=value}``; and any other use, since what can set a variable is not
      listed here;
    * names a UV_ variable other than to read it, by the same rule: a setting of uv
      that can change what a uv call resolves (UV_OVERRIDE, UV_CONSTRAINT);
    * runs the set-env workflow command;
    * names GITHUB_ENV, or the expression ``github.env``, read or written, since a read
      of the file is not told apart from a write;
    * names BASH_ENV or ENV, the file bash or sh runs before a script, or a
      BASH_FUNC_ variable, from which bash defines a function.

    Kept: a comment line (_Line: its first non-blank character is ``#``, it holds no
    quote, and no quote is open from the lines above), and a line that only
    prints the name to the job's log (_prints_only), in a text in which nothing could
    send what it prints elsewhere or make the print run something else (_captures: no
    redirection, pipe, command or process substitution, coprocess, function or alias
    anywhere in the text). So these harmless forms are refused: the name in any other
    line (``env | grep ASH_UVX_SOURCE``), a print of it in a text that redirects
    anything, a comment that holds a quote, a comment after a command on its line, and
    any read of GITHUB_ENV.

    Not seen: a name or a command that exists only once something has been expanded
    (a variable, a command substitution, a ``${{ }}`` expression), and a program, a
    sourced file or an action that writes GITHUB_ENV, or the environment of what it
    starts, itself.
    """
    lines = _read_script(text)
    captured = _captures(lines)
    for each in lines:
        line = each.text
        if each.comment:
            continue
        base = _readings(line)
        readings = list(base)
        for reading in base:
            expanded = _brace_expansions(reading)
            if expanded is None:
                return line.strip(), "braces"
            readings += [found for found in expanded if found not in readings]
        if any(_SET_ENV.search(reading) for reading in (line, *readings)):
            return line.strip(), "set-env"
        sets = captured or not _prints_only(base[0])
        if sets and any(_names_the_source(reading) for reading in readings):
            return line.strip(), "sets"
        if sets and any(
            _names_the_source(reading, _UV_SETTING_WORD) for reading in readings
        ):
            return line.strip(), "uv-env"
        if any(_ENV_FILE.search(reading) for reading in (line, *readings)):
            return line.strip(), "env-file"
        if any(_SHELL_ENV.search(reading) for reading in (line, *readings)):
            return line.strip(), "shell-env"
    return None


@dataclass(frozen=True)
class _UvCall:
    """A call of uvx, ``uv tool run`` or ``uv run`` in a script."""

    #: The logical line it is on.
    line: str
    #: ``uvx`` for uvx and ``uv tool run``, ``uv run`` for uv run.
    kind: str
    #: Its words after uvx or uv as written, up to the end of the command or a ``--``.
    words: tuple[str, ...]
    #: Where its own words are in the code it was read from: the uv word, the options
    #: and their values, and the command the call runs. That command is the one word a
    #: call may hold of ash (an installer there is refused, _scan_script_problem); the
    #: call's other words are its command's arguments.
    start: int
    end: int
    #: The program the call runs (_Word.name), empty when it names none.
    runs: str = ""


def _command_uv_calls(command: _Command, line: str) -> Iterator[_UvCall]:
    """Every call of uvx, ``uv tool run`` or ``uv run`` among a command's words,
    wherever it stands in the command (after ``env -u NAME`` too). A ``uv`` whose words
    up to a ``--`` hold no ``run`` is another uv command."""
    for index, word in enumerate(command.words):
        if word.name not in ("uv", "uvx"):
            continue
        rest = command.words[index + 1 :]
        values = [each.value for each in rest]
        cut = values.index("--") if "--" in values else len(values)
        kind = _uv_call_kind(word.name, values[:cut])
        if kind is None:
            continue
        at = _uv_read(tuple(each.text for each in rest))[1]
        runs = rest[at].name if at < len(rest) else ""
        end = rest[at].end if at < len(rest) else command.end
        words = tuple(each.text for each in rest[:cut])
        yield _UvCall(line, kind, words, word.start, end, runs)


def _uv_calls(text: str) -> Iterator[_UvCall]:
    """Every call of uvx, ``uv tool run`` or ``uv run`` in ``text`` (_command_uv_calls),
    outside the lines skipped as comments (_Line). A call's words are its command's,
    so its words after a quoted line break are its own."""
    for line in _read_script(text):
        if line.comment:
            continue
        for command in line.commands:
            yield from _command_uv_calls(command, line.text)


def _uv_call_kind(tool: str, words: list[str]) -> str | None:
    """``uvx`` for a call of uvx or ``uv tool run``, ``uv run`` for uv run, given its
    words up to a ``--``, or None for another uv command: one whose words hold no
    ``run``."""
    if tool == "uvx" or any(pair == ("tool", "run") for pair in zip(words, words[1:])):
        return "uvx"
    return "uv run" if "run" in words else None


def _uv_options(words: tuple[str, ...]) -> list[tuple[str, str]]:
    """The options among a uv call's words (_uv_read)."""
    return _uv_read(words)[0]


def _uv_read(words: tuple[str, ...]) -> tuple[list[tuple[str, str]], int]:
    """The options among a uv call's words, each with its value (empty for a flag) and
    short ones under their long names (``-qw x`` is ``-q`` and ``--with x``), and the
    index of the command the call runs (the length of ``words`` when there is none).

    A long option is read wherever it stands, in either form (``--from=value`` or the
    next word). Short options are read up to the command the call runs, the first word
    that is neither an option, an option's value, nor ``tool`` or ``run``; after it
    they are that command's own."""
    options: list[tuple[str, str]] = []
    waiting: str | None = None
    command = len(words)
    for index, word in enumerate(words):
        in_options = index < command
        if waiting is not None:
            options.append((waiting, word))
            waiting = None
        elif word.startswith("--"):
            name, equals, value = word.partition("=")
            if equals:
                options.append((name, value))
            elif name in _UV_VALUE_OPTIONS:
                waiting = name
            else:
                options.append((name, ""))
        elif in_options and len(word) > 1 and word.startswith("-"):
            for position, letter in enumerate(word[1:], 1):
                if letter in _UV_SHORT_VALUES:
                    value = word[position + 1 :].removeprefix("=")
                    if value:
                        options.append((_UV_SHORT_VALUES[letter], value))
                    else:
                        waiting = _UV_SHORT_VALUES[letter]
                    break
                options.append((f"-{letter}", ""))
        elif in_options and word not in ("tool", "run"):
            command = index
    if waiting is not None:
        options.append((waiting, ""))
    return options, command


def _rebuilds(call: _UvCall) -> bool:
    """Whether a uvx call rebuilds its environment: ``--reinstall`` is among uvx's own
    options, before the command it runs (_uv_read). After that command it is the
    command's own argument (``uvx --from ... ash scan --reinstall``)."""
    command = _uv_read(call.words)[1]
    return any(name == "--reinstall" for name, _ in _uv_read(call.words[:command])[0])


def _uv_call_problem(call: _UvCall) -> str | None:
    """What a uv call names as what it installs, when that is anything but
    ``"${ASH_UVX_SOURCE}"`` alone: given to ``--from`` by uvx and ``uv tool run``, and
    to ``--with`` (or ``-w``) by uv run. Every option that names a package counts
    (_uv_options), and so does one that reads a file of overrides, constraints or uv
    settings (_UV_SETTING_OPTIONS), which can change what the call installs."""
    wanted = "--from" if call.kind == "uvx" else "--with"
    options = _uv_options(call.words)
    settings = [(name, value) for name, value in options if name in _UV_SETTING_OPTIONS]
    if settings:
        return (
            "names "
            + ", ".join(f"{name} {value}" for name, value in settings)
            + ", a file that can change what the call installs"
        )
    found = [(name, value) for name, value in options if name in _UV_SOURCE_OPTIONS]
    if found == [(wanted, _UV_SOURCE)]:
        return None
    if not found:
        return f"names no {wanted}"
    return "names " + ", ".join(f"{name} {value}" for name, value in found)


def _scan_script_problem(text: str) -> str | None:
    """Why a script of the scan workflow could run an ASH other than the one
    ``"${ASH_UVX_SOURCE}"`` names (_scan_command_problem, _scan_words_problem), read
    one command at a time with the commands of its substitutions; the script another
    command runs (eval, a shell's -c) is read as commands of its own after it. A uv
    call whose command is an installer (pip, ``uv tool install``, uvx, the rest of
    _PACKAGE_TOOL) is refused too: it installs packages into the environment the call
    builds from the one source. Lines skipped as comments (_Line) are not read."""
    commands = [
        command
        for line in _read_script(text)
        if not line.comment
        for command in line.commands
    ]
    for command in commands:
        group = [
            other
            for other in commands
            if other.source == command.source
            and command.start <= other.start
            and other.end <= command.end
        ]
        if any(
            other is not command
            and other.source == command.source
            and other.start <= command.start
            and command.end <= other.end
            for other in commands
        ):
            continue
        for each in group:
            problem = _scan_command_problem(each)
            if problem is not None:
                return problem
        for each in group:
            for call in _command_uv_calls(each, ""):
                if _TOOL_NAME.fullmatch(call.runs):
                    return (
                        f"`{each.text.strip()}` runs {call.runs} through {call.kind}, "
                        "an installer other than the uv calls the print follows"
                    )
        problem = _scan_words_problem(command, group)
        if problem is not None:
            return problem
    return None


def _scan_command_problem(command: _Command) -> str | None:
    """Why a command of the scan workflow could run an ASH other than the one
    ``"${ASH_UVX_SOURCE}"`` names: a program it runs (_command_names) is ``ash``, other
    than through uvx, or an installer (pip, pipx, ``uv tool install``, ``uv pip``,
    Homebrew and the rest of _PACKAGE_TOOL). Their read-only commands are kept, and so
    are the uv calls _uv_calls reads. The command a uv, pip or pipx call runs is read
    past the options before it (_command_name); a call whose options there are not
    read is refused."""
    shown = command.text.strip()
    if command.unread:
        return f"`{shown}` runs a script nested too deep to read"
    names = _command_names(command.words)
    for index in names:
        if command.words[index].name == "ash":
            return f"`{shown}` runs ash other than through uvx"
    for index in names:
        tool = command.words[index].name
        if not _TOOL_NAME.fullmatch(tool) or tool == "uvx":
            continue
        arguments = _arguments(command, index)
        named = [word for word in arguments if not word.startswith("-")]
        if not named or (tool == "brew" and arguments[0] in _BREW_READ_ONLY):
            continue
        if tool not in ("uv", "pipx") and not _PIP_TOOL.fullmatch(tool):
            return f"`{shown}` runs {tool} {named[0]}"
        read = _command_name(tool, arguments)
        if read is None:
            return f"cannot tell what `{shown}` runs, so it could install another ASH"
        runs = read[0]
        if tool == "uv":
            kept = _UV_READ_ONLY | {"run", "tool run"}
        elif tool == "pipx":
            kept = _PIPX_READ_ONLY
        else:
            kept = _PIP_READ_ONLY
        if runs and runs not in kept:
            return f"`{shown}` runs {tool} {runs}"
    return None


def _without_printed_text(command: _Command, masked: str) -> str:
    """``masked`` (the text of ``command``) with the words an ``echo`` or ``printf``
    prints blanked, except the commands of their substitutions (``command.inner``),
    which stay to be read. The program is the one word bash runs (_command_names), so
    the words after it are text to print, and an ``ash`` or an installer named in a
    message (``echo "run ash dependencies install"``) runs nothing. Any other command is
    returned as it is."""
    names = _command_names(command.words)
    if len(names) != 1 or command.words[names[0]].name not in ("echo", "printf"):
        return masked
    kept = [False] * len(masked)
    for start, end in command.inner:
        for index in range(max(start, 0), min(end, len(masked))):
            kept[index] = True
    chars = list(masked)
    for word in command.words[names[0] + 1 :]:
        for index in range(word.start - command.start, word.end - command.start):
            if 0 <= index < len(chars) and not kept[index]:
                chars[index] = " "
    return "".join(chars)


def _scan_words_problem(command: _Command, group: list[_Command]) -> str | None:
    """Why a word of a scan workflow command could run another ASH: any word of ash or
    of an installer is refused wherever it stands, outside the own words of a uv call
    of the command or of its substitutions (``group``, _command_uv_calls), in its text
    read with its quoting removed (_readings). bash can run a word as a command where
    these checks do not read one (``timeout 10m ash``, ``eval ash``), and every such
    word in the real workflow is the command of a uvx or uv run call, or text an echo
    or printf prints (_without_printed_text: its substitutions are still read). A
    read-only command is refused with the rest."""
    shown = command.text.strip()
    masked = command.text
    for each in group:
        for call in _command_uv_calls(each, ""):
            start, end = call.start - command.start, call.end - command.start
            masked = masked[:start] + " " * (end - start) + masked[end:]
    masked = _without_printed_text(command, masked)
    for reading in _readings(masked):
        for pattern in (_ASH_COMMAND, _PACKAGE_TOOL):
            found = pattern.search(reading)
            if found is not None:
                return (
                    f"`{shown}` names {found.group()} other than as the command of a "
                    "uvx or uv run call"
                )
    return None


def _check_shell(value: Any, place: str, where: str) -> None:
    """Refuse a shell other than bash or sh, the ones whose scripts the checks read."""
    if value not in _SCAN_SHELLS:
        raise RewriteError(
            f"{where}: `shell: {value}`, in {place}, is not bash or sh: a shell given "
            "as a command runs words of its own before the script, so it could set "
            "ASH_UVX_SOURCE for that step alone while the print reads the workflow's, "
            "and another shell's scripts are not read by these checks"
        )


def _check_defaults(holder: Mapping[str, Any], place: str, where: str) -> None:
    """Refuse defaults that are not a mapping, or whose shell is not bash or sh."""
    defaults = holder.get("defaults")
    if defaults is None:
        return
    run = defaults.get("run") if isinstance(defaults, dict) else None
    if not isinstance(defaults, dict) or not isinstance(run, (dict, type(None))):
        raise RewriteError(
            f"{where}: the defaults of {place} are {defaults!r}, not a mapping, so the "
            "shell its steps run with cannot be read"
        )
    if run is not None and "shell" in run:
        _check_shell(run["shell"], f"the defaults of {place}", where)


def _check_env_names(env: Mapping[Any, Any], place: str, where: str) -> None:
    """Refuse an env that sets BASH_ENV or ENV, a file bash or sh runs first; a
    BASH_FUNC_ name, from which bash defines a function; or a UV_ setting, which can
    change what a uv call resolves."""
    for name in env:
        if not isinstance(name, str):
            continue
        if name.startswith("BASH_FUNC_"):
            raise RewriteError(
                f"{where}: {place} sets {name}, from which bash defines a function, so "
                "a command of the scan could run something no check reads"
            )
        if name in ("BASH_ENV", "ENV"):
            raise RewriteError(
                f"{where}: {place} sets {name}, a file bash or sh runs before a "
                "script, so it could set ASH_UVX_SOURCE for the scan from a file no "
                "check reads"
            )
        if name.startswith("UV_"):
            raise RewriteError(
                f"{where}: {place} sets {name}, a setting of uv that can change what a "
                "uv call resolves without naming another source"
            )


def _without_source_writer(step: Mapping[str, Any]) -> Any:
    """The script of a step with the one statement _SOURCE_WRITERS allows its id cut
    out, written exactly and once. A script that does not hold it, or holds it twice,
    is returned whole, so that every line of it is read."""
    run = step.get("run")
    allowed = _SOURCE_WRITERS.get(step.get("id"))
    if isinstance(run, str) and allowed is not None and run.count(allowed) == 1:
        return run.replace(allowed, "", 1)
    return run


def rewrite_called_workflow(file_name: str, text: str, *, where: str) -> RewriteResult:
    """A reusable workflow a block calls, made to print the provenance of its ASH.

    For run-ash-security-scan.yml, one step (rule ``called-provenance``) runs the
    print program with ``uvx --from "${ASH_UVX_SOURCE}" python``: the form, with no
    ``--reinstall``, that the workflow's later steps use to reuse the environment the
    scan built. It goes right after the step that rebuilds that environment with
    ``uvx --reinstall --from "${ASH_UVX_SOURCE}"`` (the scan; a ``--reinstall`` after
    the command uvx runs is that command's own, _rebuilds), with
    ``if: ${{ !cancelled() }}`` so that a failed scan still gets its record. In a
    workflow where no step reinstalls, it goes right after the first step that runs
    ``uvx --from "${ASH_UVX_SOURCE}"``, which builds the environment every later call
    reuses. Two reinstalling steps are an error, since then no one environment is the
    scan's.

    ASH_UVX_SOURCE has to be set for the whole workflow to CALLED_SCAN_SOURCE:
    the ``ash-repo`` repository at the ``ash-version`` ref, the inputs the block's
    rewrite set to the base repository and the head commit. The workflow replaces it
    for the steps after two of its steps, by id ``ash-source`` and ``ash-pin``, with
    the same form of the repository and one ref, then the commit that ref names
    (_SOURCE_WRITERS); those two statements are the only writes of it that are kept.
    A job or a step that sets it again in its ``env`` is an error, since the print
    step reads the workflow's value, and so is:

    * a script, an action's input or an env value with a line that could set it for
      the uvx calls after it (_uvx_source_problem);
    * a call of uvx, ``uv tool run`` or ``uv run`` there that installs from anything
      but ``--from "${ASH_UVX_SOURCE}"`` (``--with`` for uv run) alone, or that names
      a file of overrides, constraints or uv settings (_uv_calls, _uv_call_problem),
      such as a scan pinned to a release;
    * a script that runs ``ash`` other than through such a call, or installs
      packages with another installer (pip, pipx, ``uv tool install``, ``uv pip``),
      also as the command such a call runs, which could put another ASH on the PATH
      or in the call's environment (_scan_script_problem);
    * a step's shell, or a job's or the workflow's default shell, other than bash or
      sh: a shell given as a command runs words of its own before the script, so it
      could set the variable for the scan alone while the print, on the default
      shell, reads the workflow's value;
    * a job's or a step's env or inputs, or defaults, that are not a mapping (an
      expression), whose names no check can read;
    * a job with a container or services, whose image and env no check reads;
    * a step that uses an action other than the eleven the workflow uses (_SCAN_ACTIONS),
      or one of them at anything but a full commit SHA (a tag or a branch can move),
      and a job that calls another workflow, whose code no check reads;
    * BASH_ENV, ENV, a BASH_FUNC_ name or a UV_ setting in an env;
    * a workflow that names ACTIONS_ALLOW_UNSECURE_COMMANDS, which turns on the
      workflow commands that set variables and PATH.

    So every uvx call installs ASH from one source, at a full commit SHA, and a
    rebuild changes at most ASH's dependencies, never which ASH. Not seen: a
    ``uv.toml`` or ``pyproject.toml`` uv reads from the working directory, which can
    hold the same settings; what a step appends to GITHUB_PATH, which the real
    workflow does for its tools' directories, so a program a later step finds on the
    PATH (uvx included) is not checked; and which commit of one of the eleven actions a
    step uses, so a pin bump passes and what the bumped action does is left to the
    review of that bump, as for the repository's other workflows. Any other file is
    returned as it is, with no records.

    Before the print is placed, the workflow's ``actions/upload-artifact`` and
    ``actions/download-artifact`` steps are moved to the v4 releases act can serve
    (rule ``artifact-actions``, _rewrite_artifact_actions), as a block's own steps
    are: the workflow's current pins send the request act's artifact server refuses,
    so its ``ash`` job would fail at the upload and the jobs that need the artifact
    would never run. The swap changes a ``uses:`` line only, so the step list the
    print is placed in is that of the given text.
    """
    if PurePosixPath(file_name).name != CALLED_SCAN_WORKFLOW:
        return RewriteResult(text=text, applied=(), original=text)
    original = text
    applied: list[Applied] = []
    text = _rewrite_artifact_actions(text, where, applied)
    document = _load(text, where)
    # The action pins are checked on the text as given: the swap above has already
    # moved the two artifact actions to their pinned releases, so a tag or a branch on
    # either ("@v4", "@main") would pass a check of the swapped text.
    original_document = _load(original, where)
    original_jobs = (
        original_document.get("jobs") if isinstance(original_document, dict) else None
    )
    root = _compose(text, where)
    env = document.get("env") if isinstance(document, dict) else None
    source = env.get("ASH_UVX_SOURCE") if isinstance(env, dict) else None
    if source != CALLED_SCAN_SOURCE:
        raise RewriteError(
            f"{where}: ASH_UVX_SOURCE is not built from the ash-repo and ash-version "
            f"inputs in the workflow's own form, {CALLED_SCAN_SOURCE!r}, but is "
            f"{source!r}, so its ASH is not the one the calling block names"
        )
    if _UNSECURE_COMMANDS.lower() in text.lower():
        raise RewriteError(
            f"{where}: the workflow names {_UNSECURE_COMMANDS}, which turns on the "
            "set-env and add-path workflow commands, so a step could set "
            "ASH_UVX_SOURCE or PATH for the steps after it"
        )
    _check_env_names(env, "the workflow", where)
    _check_defaults(document, "the workflow", where)
    texts = [("an env value of the workflow", value, False) for value in env.values()]
    parsed_jobs = document.get("jobs")
    if not isinstance(parsed_jobs, dict):
        raise RewriteError(
            f"{where}: the workflow's jobs are not a mapping of jobs, so their steps "
            "cannot be read"
        )
    for job_id, body in parsed_jobs.items():
        steps = body.get("steps") if isinstance(body, dict) else None
        if not isinstance(body, dict) or not isinstance(steps, (list, type(None))):
            raise RewriteError(
                f"{where}: the job {job_id}, or its list of steps, is not written as "
                "one, so its steps cannot be read"
            )
        _check_defaults(body, f"the job {job_id}", where)
        for key in ("container", "services"):
            if key in body:
                raise RewriteError(
                    f"{where}: the job {job_id} sets {key}, so its steps run in or "
                    "beside an image whose env and tools the checks do not read"
                )
        for holder in [body, *(steps or ())]:
            if not isinstance(holder, dict):
                raise RewriteError(
                    f"{where}: a step of the job {job_id} is {holder!r}, not a "
                    "mapping, so what it runs cannot be read"
                )
            for key in ("env", "with"):
                value = holder.get(key)
                if value is not None and not isinstance(value, dict):
                    raise RewriteError(
                        f"{where}: the {key} of the job {job_id} or one of its steps "
                        f"is {value!r}, not a mapping, so the names it sets cannot "
                        "be read"
                    )
            holder_env = holder.get("env") or {}
            if "ASH_UVX_SOURCE" in holder_env:
                raise RewriteError(
                    f"{where}: the job {job_id} or one of its steps sets "
                    "ASH_UVX_SOURCE again, so its uvx calls may install an ASH other "
                    "than the one the inputs name"
                )
            _check_env_names(holder_env, f"the job {job_id} or one of its steps", where)
            if "shell" in holder:
                _check_shell(holder["shell"], f"the job {job_id}", where)
            script = _without_source_writer(holder)
            texts.append((f"a script of the job {job_id}", script, True))
            for key, place in (("with", "an input"), ("env", "an env value")):
                texts += [
                    (f"{place} in the job {job_id}", value, False)
                    for value in (holder.get(key) or {}).values()
                ]
    for place, value, script in texts:
        if not isinstance(value, str):
            continue
        found = _uvx_source_problem(value)
        if found is not None:
            line, kind = found
            raise RewriteError(
                f"{where}: `{line}`, in {place}, {_SOURCE_PROBLEMS[kind]}"
            )
        for call in _uv_calls(value):
            problem = _uv_call_problem(call)
            if problem is not None:
                wanted = "--from" if call.kind == "uvx" else "--with"
                raise RewriteError(
                    f"{where}: `{call.line.strip()}`, in {place}, {problem}, but "
                    "every uvx, uv tool run and uv run call in the scan workflow "
                    f'installs from {wanted} "${{ASH_UVX_SOURCE}}" alone, the source '
                    "the print reads"
                )
        if not script:
            continue
        problem = _scan_script_problem(value)
        if problem is not None:
            raise RewriteError(
                f"{where}: {problem}, in {place}, but the scan workflow runs "
                'ASH only through uvx --from "${ASH_UVX_SOURCE}", so this '
                "could run an ASH other than the one the print records"
            )
    checked_jobs = original_jobs if isinstance(original_jobs, dict) else parsed_jobs
    for job_id, body in checked_jobs.items():
        if not isinstance(body, dict):
            continue
        if "uses" in body:
            raise RewriteError(
                f"{where}: the job {job_id} uses {body['uses']}, a workflow whose "
                "steps the checks do not read"
            )
        for step in body.get("steps") or ():
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            name, at, pin = str(uses).rpartition("@")
            if uses is not None and not (
                at and name in _SCAN_ACTIONS and _ACTION_PIN.fullmatch(pin)
            ):
                raise RewriteError(
                    f"{where}: a step of the job {job_id} uses {uses}, an action other "
                    "than the ones the scan workflow uses, each at a full commit SHA, "
                    "so it could run code the checks do not read"
                )
    jobs = _mapping_value(root, "jobs")
    uvx_steps = []
    for key, job in jobs.value if isinstance(jobs, yaml.MappingNode) else ():
        steps = _mapping_value(job, "steps")
        for index, step in enumerate(
            steps.value if isinstance(steps, yaml.SequenceNode) else ()
        ):
            run = _mapping_value(step, "run")
            if not isinstance(run, yaml.ScalarNode):
                continue
            calls = [c for c in _uv_calls(str(run.value)) if c.kind == "uvx"]
            if calls:
                lines = [" ".join(calls[0].line.split())]
                reinstalls = any(_rebuilds(call) for call in calls)
                uvx_steps.append((str(key.value), steps, index, lines, reinstalls))
    if not uvx_steps:
        raise RewriteError(
            f'{where}: no step runs uvx --from "${{ASH_UVX_SOURCE}}", so no step can '
            "print the provenance of the ASH the workflow runs"
        )
    rebuilding = [found for found in uvx_steps if found[4]]
    if len(rebuilding) > 1:
        raise RewriteError(
            f"{where}: {len(rebuilding)} steps rebuild the environment of "
            "ASH_UVX_SOURCE with uvx --reinstall, so no one environment is the scan's "
            "to print"
        )
    job_id, steps, index, lines, reinstalls = (rebuilding or uvx_steps)[0]
    _, matrix = _job_of("github-actions", ["jobs", job_id], document)
    insertion = _step_after(
        text.split("\n"),
        steps,
        index,
        name=CALLED_PROVENANCE_STEP_NAME,
        commands=[direct_url_print_command(UVX_SOURCE_PYTHON)],
        rule="called-provenance",
        anchor=lines[0],
        job=job_id,
        matrix=matrix,
        condition=AFTER_THE_SCAN if reinstalls else None,
    )
    rewritten = _apply_insertions(text, [insertion], applied)
    new_steps = (_load(rewritten, where).get("jobs") or {}).get(job_id, {}).get("steps")
    names = [s.get("name") for s in new_steps or () if isinstance(s, dict)]
    if (
        names.count(CALLED_PROVENANCE_STEP_NAME) != 1
        or len(new_steps) <= index + 1
        or new_steps[index + 1].get("name") != CALLED_PROVENANCE_STEP_NAME
    ):
        raise RewriteError(
            f"{where}: the provenance step did not land right after the uvx step that "
            "builds the environment the scan runs in"
        )
    return RewriteResult(text=rewritten, applied=tuple(applied), original=original)


# ---------------------------------------------------------------------------
# The image GitLab's own-image example runs
# ---------------------------------------------------------------------------


def _docs_checks() -> Any:
    """scripts/docs_checks.py, loaded by path under the name every docs test shares."""
    name = "_ash_docs_checks"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, REPO_ROOT / "scripts" / "docs_checks.py"
    )
    if spec is None or spec.loader is None:
        raise RewriteError("cannot load scripts/docs_checks.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _single_default(
    defaults: Mapping[str, set[str | None]], name: str, dockerfile: Path
) -> str:
    values = {value for value in defaults.get(name, set()) if value is not None}
    if len(values) != 1:
        raise RewriteError(
            f"{dockerfile} declares {len(values)} default(s) for ARG {name}; the CI "
            "image is built from exactly one"
        )
    return values.pop()


def ci_image_build_argv(dockerfile: Path, *, tag: str) -> list[str]:
    """The ``docker build`` argv for the Dockerfile's ``ci`` stage, tagged ``tag``.

    The base is passed as ``BASE_IMAGE=<BASE_IMAGE without its tag>@<BASE_IMAGE_DIGEST>``,
    both from the Dockerfile's ARG defaults, so the build pulls the base by digest. The
    tag is dropped from the last path component only, so a registry port stays. Only
    the argv is built; nothing runs here.
    """
    if not tag or any(c.isspace() for c in tag):
        raise RewriteError(f"not an image tag: {tag!r}")
    dockerfile = Path(dockerfile)
    text = dockerfile.read_text(encoding="utf-8")
    defaults = _docs_checks().dockerfile_arg_defaults(text)
    digest = _single_default(defaults, "BASE_IMAGE_DIGEST", dockerfile)
    base = _single_default(defaults, "BASE_IMAGE", dockerfile)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise RewriteError(f"{dockerfile}: BASE_IMAGE_DIGEST is not sha256:<64 hex>")
    if "@" in base or "$" in base or any(c.isspace() for c in base):
        raise RewriteError(f"{dockerfile}: BASE_IMAGE {base!r} is not a literal name")
    if not re.search(r"(?im)^[ \t]*FROM[ \t]+\S+[ \t]+AS[ \t]+ci[ \t]*$", text):
        raise RewriteError(f"{dockerfile} has no stage named ci")
    path, slash, last = base.rpartition("/")
    repository = path + slash + last.partition(":")[0]
    return [
        "docker",
        "build",
        "--target",
        "ci",
        "-t",
        tag,
        "-f",
        str(dockerfile),
        "--build-arg",
        f"BASE_IMAGE={repository}@{digest}",
        str(dockerfile.parent),
    ]
