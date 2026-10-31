# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the docs say ASH does, held to the sentence that says it and the code that does it.

Why this exists. The docs checks hold names to the code: an option, a flag or a scanner a
page names must exist. They cannot tell whether a sentence about behavior is still true,
so a page could go on saying that a delivered config is refused, or that a flag has no
effect in container mode, after the code stopped doing it. The security and gate pages had
no pin that read the page at all.

Each test pins one claim, in two halves:

1. ``assert_on_page`` checks that the sentence is still on its page, with whitespace
   collapsed and link targets dropped, so rewrapping a paragraph changes nothing. When the
   sentence is gone, the failure names the page and the heading of the closest paragraph.
2. The test then probes the code that makes the sentence true, through ASH's public
   functions where they exist, patching only process boundaries: environment variables,
   the platform, sockets, the processes the code starts, and for container mode the
   container runtime.

So a test goes red when either side moves. When a page is reworded on purpose, update the
quote and check that the probe still tests what the page now says. When the code changes,
the page or the test is wrong, and the failure says which half.

Some claims describe behavior that lands in a change not merged yet. Their tests fail on a
tree without it: the page describes the merged behavior. Code those tests need is imported
inside each test, so a module that does not exist yet fails its tests and not the file.
A missing change is never skipped over. Where a page says different things for different
platforms, such as which sandbox backend ``--sandbox auto`` picks, the test asserts each
platform's claim on that platform; a cell whose scenario a platform cannot express (a
POSIX signal on Windows, a tool the host lacks) is skipped there with the reason named.

Runnable examples on the pages are the other kind of pin. concepts/trust-model.md runs a
delivered tree's refusal through the CLI that way.

To run this file against another tree's code, keep the repository's conftest from putting
this tree first on ``sys.path``:

    <code-tree>/.venv/bin/python -m pytest <docs-tree>/tests/unit/docs/test_page_claims.py \\
        --confcutdir <docs-tree>/tests/unit/docs -o addopts= -p no:cacheprovider
"""

from __future__ import annotations

import ast
import asyncio
import base64
import contextlib
import csv
import dataclasses
import difflib
import errno
import getpass
import hashlib
import http.client
import importlib
import inspect
import io
import itertools
import json
import logging
import os
import pkgutil
import platform
import queue
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import sysconfig
import tempfile
import textwrap
import threading
import time
import typing
import uuid
import zipfile
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
CONTENT = REPO_ROOT / "docs" / "content"

TRUST_MODEL = "concepts/trust-model.md"
MCP_SERVER = "how-to/mcp-server.md"
SET_THE_GATE = "how-to/set-the-gate.md"
EXIT_CODES = "reference/exit-codes.md"
STEERING_GUIDE = "docs/genai-steering-guide.md"
RUN_IN_A_CONTAINER = "how-to/run-in-a-container.md"
SCALE_LARGE_REPOS = "how-to/scale-large-repos.md"
SANDBOX = "concepts/sandbox.md"
CONFIGURE = "how-to/configure.md"

#: How a suppression's justification starts when the entry came from an MCP client.
CLIENT_MARK = "(ASH, client-supplied config)"

#: A Markdown link. Its text holds no ``[``, so a ``[`` earlier in the paragraph, as in
#: ```##[```, does not start one.
_LINK = re.compile(r"\[([^\[\]]*)\]\([^)\s]*\)")
_FENCE = re.compile(r"^\s*(```|~~~)")
_ANCHOR = re.compile(r"\{#[^}]*\}")


def _code_root() -> Path:
    """The checkout whose ``automated_security_helper`` the tests import.

    Pages come from this tree (``REPO_ROOT``), but a claim about a repository file such
    as pyproject.toml or a workflow is a claim about the code under test, which a
    cross-tree run imports from another checkout. An installed package has no
    pyproject.toml beside it, and then this tree's is the one that describes it.
    """
    import automated_security_helper

    root = Path(automated_security_helper.__file__).resolve().parents[1]
    return root if (root / "pyproject.toml").is_file() else REPO_ROOT


# --------------------------------------------------------------------------- #
# The page half
# --------------------------------------------------------------------------- #


def _normalize(text: str) -> str:
    """``text`` with link targets dropped and every run of whitespace one space."""
    return " ".join(_LINK.sub(r"\1", text).split())


def _paragraphs(text: str) -> Iterable[Tuple[int, str, str]]:
    """(first line, heading above it, normalized text) for each paragraph of a page.

    Blank lines separate paragraphs, and a fenced block is one paragraph, so a ``#``
    comment in a shell block is not taken for a heading.
    """
    heading = "(top of the page)"
    start, lines, fenced = 0, [], False
    for number, line in enumerate(text.splitlines(), 1):
        if _FENCE.match(line):
            fenced = not fenced
        if not fenced and line.startswith("#"):
            if lines:
                yield start, heading, _normalize(" ".join(lines))
                lines = []
            heading = _ANCHOR.sub("", line.lstrip("#")).strip()
            continue
        if not line.strip() and not fenced:
            if lines:
                yield start, heading, _normalize(" ".join(lines))
                lines = []
            continue
        if not lines:
            start = number
        lines.append(line)
    if lines:
        yield start, heading, _normalize(" ".join(lines))


def _closest_paragraph(text: str, sentence: str) -> Tuple[str, int]:
    """The heading over, and first line of, the paragraph sharing most text with ``sentence``."""
    best = (-1, "(top of the page)", 1)
    for start, heading, paragraph in _paragraphs(text):
        shared = (
            difflib.SequenceMatcher(None, paragraph, sentence, autojunk=False)
            .find_longest_match()
            .size
        )
        if shared > best[0]:
            best = (shared, heading, start)
    return best[1], best[2]


def assert_on_page(page: str, sentence: str) -> None:
    """Fail unless ``sentence`` is on ``docs/content/<page>``, both normalized.

    The failure names the page and the heading of the paragraph closest to the sentence,
    which is usually where it was reworded.
    """
    text = (CONTENT / page).read_text(encoding="utf-8")
    wanted = _normalize(sentence)
    if wanted in _normalize(text):
        return
    heading, line = _closest_paragraph(text, wanted)
    pytest.fail(
        f"docs/content/{page} no longer says what this test pins. The closest paragraph "
        f"is under {heading!r}, at line {line}. If the page changed on purpose, update the "
        f"quote here and check that the probe still tests what the page now says.\n"
        f"  pinned: {wanted}",
        pytrace=False,
    )


def _page_text(page: str) -> str:
    return (CONTENT / page).read_text(encoding="utf-8")


def _page_section(page: str, after: str, before: str) -> str:
    """The normalized text of ``page`` between the sentence ``after`` and ``before``.

    Both markers are pinned first: a reworded marker then fails with the
    page-and-heading message this module promises, not a bare ValueError from
    ``str.index``.
    """
    assert_on_page(page, after)
    assert_on_page(page, before)
    text = _normalize(_page_text(page))
    start = text.index(_normalize(after)) + len(_normalize(after))
    return text[start : text.index(_normalize(before), start)]


# --------------------------------------------------------------------------- #
# Shared probes
# --------------------------------------------------------------------------- #


def _uv_dirs(home: Path) -> Dict[str, str]:
    """uv's four directory settings, pointed under ``home``.

    uv reads each of them before the home directory, so values the environment
    already carries (a CI runner's tool-bin-dir, or ``_private_home``'s fixture
    values in a child that inherits them) would otherwise send uv's writes
    outside the home a test reads. Every place this file builds an environment
    takes the four from here, so they cannot drift apart again.
    """
    return {
        "UV_CACHE_DIR": str(home / ".cache" / "uv"),
        "UV_TOOL_DIR": str(home / ".local" / "share" / "uv" / "tools"),
        "UV_TOOL_BIN_DIR": str(home / ".local" / "bin"),
        "UV_PYTHON_INSTALL_DIR": str(home / ".local" / "share" / "uv" / "python"),
    }


def _aws_fence() -> Dict[str, str]:
    """Settings under which an AWS client fails before it sends anything: the
    instance metadata service off, no config or credentials file, and an
    endpoint that refuses the connection, on a host with credentials too."""
    return {
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "AWS_ENDPOINT_URL": "http://127.0.0.1:9",
    }


def _home_override(home: str) -> Dict[str, str]:
    """``HOME`` and ``USERPROFILE`` set to ``home``, for callers that override the
    home ``_ash_environment`` built.

    A usable override (an absolute path) is the child's own home, so uv's
    directories follow it; without that, everything the child's uv wrote would
    land under the replaced home. An unusable one (empty or relative) keeps the
    caller's uv directories: those stay under the containment home, an absolute
    place a child with that ``HOME`` could not derive, so a probe of an unusable
    home still writes nothing into the working directory.

    An unset home is not spelled here: a caller that means "no home variable at
    all" removes the variables instead (``_child_answer``), because ``str(None)``
    would hand the child the relative path named ``None``.
    """
    override = {"HOME": home, "USERPROFILE": home}
    if os.path.isabs(home):
        override.update(_uv_dirs(Path(home)))
    return override


@pytest.fixture(autouse=True)
def _private_home(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """A home directory of each test's own, however the file is run.

    ASH keeps per-user state under the home directory: install receipts in
    ``~/.ash/install-receipts``, the default ``~/.ash/bin``, caches. Code these tests
    run in this process reads ``Path.home()``, which is HOME on POSIX and USERPROFILE
    on Windows, so both point at an empty directory, and ``ASH_BIN_PATH`` and the XDG
    directories are unset, so nothing here can write to the real home. Child
    processes get a home of their own from ``_ash_environment`` as well.

    uv reads UV_CACHE_DIR and UV_TOOL_DIR before the home directory, and a test
    runner may point both at a home of its own, which it then checks for files a tool
    left (tests/unit/conftest.py on the code tiers). So both point into this home too,
    for this process and for every child that inherits its environment.
    """
    home = tmp_path_factory.mktemp("home")
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    for name in (
        "ASH_BIN_PATH",
        "XDG_BIN_HOME",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in _uv_dirs(home).items():
        monkeypatch.setenv(name, value)
    return home


@pytest.fixture
def mcp_workspace_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The MCP workspace root, named by ``ASH_MCP_WORKSPACE_ROOT``, with no ``ASH_CONFIG``.

    A file under it is an MCP-client file whether or not a server is running.
    """
    root = tmp_path / "mcp-workspace"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    return root


def _tree_with_config(parent: Path, config: Dict[str, Any] | str) -> Path:
    """A source tree under ``parent`` whose ``.ash/.ash.yaml`` holds ``config``."""
    tree = parent / "session" / "source"
    (tree / ".ash").mkdir(parents=True)
    text = (
        config if isinstance(config, str) else yaml.safe_dump(config, sort_keys=False)
    )
    (tree / ".ash" / ".ash.yaml").write_text(text, encoding="utf-8")
    return tree


def _document_setting(pointer: str, value: Any) -> Dict[str, Any]:
    """A config document that sets only the field at JSON ``pointer`` to ``value``."""
    document: Any = value
    for segment in reversed(pointer.strip("/").split("/")):
        document = {segment: document}
    return document


def _builtin_plugin_package() -> Any:
    """ASH's built-in plugin package, with every plugin group it ships loaded.

    A process whose first ASH import is a core module that the plugin modules import
    back loads the package with that group missing: the package records the
    ImportError in ``ASH_PLUGIN_LOAD_ERRORS``, and ``retry_failed_plugin_groups``,
    where it has one, loads the group again. Which test ran first in this process
    decides that, so the lists are read only after the retry, and an error that stays
    fails here instead of reading as plugins ASH does not ship.
    """
    from automated_security_helper.plugin_modules import ash_builtin

    retry = getattr(ash_builtin, "retry_failed_plugin_groups", None)
    if retry is not None:
        retry()
    assert not ash_builtin.ASH_PLUGIN_LOAD_ERRORS, ash_builtin.ASH_PLUGIN_LOAD_ERRORS
    return ash_builtin


def _shipped_plugin_configs(attribute: str) -> Dict[str, Any]:
    """{plugin name: its config model} for each plugin ASH's own plugin modules list.

    ``attribute`` is ``ASH_SCANNERS``, ``ASH_CONVERTERS`` or ``ASH_REPORTERS``, the lists
    each module under ``automated_security_helper.plugin_modules`` exports.
    """
    import automated_security_helper.plugin_modules as plugin_modules

    _builtin_plugin_package()
    found: Dict[str, Any] = {}
    for module_info in pkgutil.iter_modules(plugin_modules.__path__):
        module = importlib.import_module(
            f"{plugin_modules.__name__}.{module_info.name}"
        )
        for plugin in getattr(module, attribute, []):
            config_class = typing.get_args(plugin.model_fields["config"].annotation)[0]
            found[config_class.model_fields["name"].default] = config_class
    return found


def _shipped_plugin_options(attribute: str) -> Dict[str, Set[str]]:
    """{plugin name: its option names} for each plugin ``_shipped_plugin_configs`` finds."""
    found: Dict[str, Set[str]] = {}
    for name, config_class in _shipped_plugin_configs(attribute).items():
        options = config_class.model_fields["options"].annotation
        options = (typing.get_args(options) or (options,))[0]
        found[name] = set(options.model_fields)
    return found


def _ash_environment(cwd: Path, **env: str) -> Dict[str, str]:
    """The caller's environment with a private home directory under ``cwd``, no
    network installs, no ``ASH_CONFIG``, and ``env`` on top.

    uv's cache and tool directories point into the same home, replacing any the
    caller's environment carries (``_private_home`` points those at the fixture
    home): everything a child's uv writes lands under the child's own home, where
    the tests that read a run's home can see it. A caller that overrides ``HOME``
    on top of this environment goes through ``_home_override``, which keeps that
    promise for a usable override and says what an unusable one keeps."""
    home = cwd / "home"
    home.mkdir(exist_ok=True)
    environment = {
        **os.environ,
        "HOME": str(home),
        "USERPROFILE": str(home),
        "UV_OFFLINE": "1",
        "PIP_NO_INDEX": "1",
        **_uv_dirs(home),
    }
    for name in ("ASH_CONFIG", "XDG_BIN_HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"):
        environment.pop(name, None)
    return {**environment, **env}


def _ash(args: List[str], cwd: Path, **env: str) -> subprocess.CompletedProcess:
    """Run this interpreter's ``ash`` with a private home directory and no network installs."""
    return subprocess.run(
        [sys.executable, "-m", "automated_security_helper.cli.main", *args],
        cwd=cwd,
        env=_ash_environment(cwd, **env),
        capture_output=True,
        text=True,
        timeout=600,
    )


def _bash_argv(*words: str) -> List[str]:
    """``bash <words...>``, where the words name a script file to run, with the
    shell's own options before it.

    These tests also run inside a checkout whose tests/unit/conftest.py checks what
    each child process starts (the code tiers' real-program guard). That reader
    admits two forms: a shell running a script file it can resolve, and a directly
    started file whose basename a test's own mark names, however it runs once
    started: through its ``#!`` line on POSIX, or as the ``.cmd`` the mark names
    on Windows, where ``where="program"`` compares the basename with its
    extension (``_delivery_git_stand_in``). A ``-c`` string names nothing it can
    read, and a script handed to an interpreter is read as the interpreter, not
    the script. Every comment here that says "a test runner that checks what each
    child starts" means that conftest.
    """
    bash = shutil.which("bash")
    assert bash is not None, "these runs need bash"
    return [bash, *words]


def _step_script(tmp_path: Path, text: str, name: str = "step.sh") -> str:
    """``text`` written as a script file under ``tmp_path``, for ``_bash_argv``."""
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def _runnable_bash_script(path: Path) -> str:
    """``path``, checked to run as ``./<name>`` would: executable, with a ``#!``
    line that starts bash. ``bash <path>`` alone would hide a lost execute bit or
    a changed shebang that a user's own ``./<name>`` depends on."""
    assert os.access(path, os.X_OK), f"{path} has no execute bit, so ./ cannot run it"
    first_line = path.read_bytes().split(b"\n", 1)[0]
    assert first_line.startswith(b"#!") and b"bash" in first_line, (
        f"{path} does not start bash: {first_line!r}"
    )
    return str(path)


def _interpreter_launcher(directory: Path, name: str, script: Path) -> Path:
    """An executable ``name`` in ``directory`` that runs ``script`` with this
    interpreter: a ``#!/bin/sh`` + exec file on POSIX, a ``.cmd`` on Windows,
    where a ``#!`` line cannot run at all. One launcher shape for every
    stand-in, because a ``#!{sys.executable}`` line breaks on interpreter
    paths with whitespace or over a kernel's length limit. The paths are
    quoted (shell-quoted on POSIX, ``%`` doubled on Windows, the one expansion
    cmd performs inside quotes), so unusual directories stay literal. ``exec``
    is load-bearing: with the shell waiting, a child's signal death would
    reach the caller as the shell's plain exit of 128 plus the number, not as
    a signal."""
    if os.name == "nt":
        launcher = directory / f"{name}.cmd"
        interpreter = sys.executable.replace("%", "%%")
        target = str(script).replace("%", "%%")
        # `%*` goes through cmd's parser again, so an argument carrying cmd
        # metacharacters (& | > ^ %) would be reinterpreted. The stand-ins'
        # callers pass only plain names, flags and paths the tests made.
        # cmd.exe decodes the file in the console's code page, so the launcher
        # is written in the code page the console reports at write time, or
        # the OEM code page when there is no console (GetConsoleOutputCP
        # returns 0). A non-ASCII path (a non-ASCII username under the pytest
        # tmp root) then works wherever that code page can spell it; chcp
        # changing mid-test is the remaining, accepted gap. A path the code
        # page cannot spell is a host property, not a defect in the code under
        # test, so the cell skips with the reason instead of failing.
        import ctypes

        code_page = ctypes.windll.kernel32.GetConsoleOutputCP()  # type: ignore[attr-defined]
        encoding = f"cp{code_page}" if code_page else "oem"
        try:
            launcher.write_text(
                f'@"{interpreter}" "{target}" %*\r\n', encoding=encoding
            )
        except (UnicodeEncodeError, LookupError) as error:
            pytest.skip(
                f"the launcher's paths cannot be written in the console code "
                f"page ({encoding}): {error}"
            )
    else:
        launcher = directory / name
        launcher.write_text(
            "#!/bin/sh\n"
            f'exec {shlex.quote(sys.executable)} {shlex.quote(str(script))} "$@"\n',
            encoding="utf-8",
        )
        launcher.chmod(0o755)
    return launcher


def _child_containment(tmp_path: Path) -> Dict[str, str]:
    """Settings that keep a script child off the network, off AWS and out of the
    real home, for a child whose environment is built from nothing rather than
    from the test's own: a home of the test's own (without one, ``~`` and uv's
    directory lookup fall back to the password database's entry, the real home),
    uv offline with its cache and tool directories under that home, no credentials
    or config file, no instance metadata, and an AWS endpoint that refuses the
    connection. The steps these runs exercise read none of them; they are the
    child's containment."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "UV_OFFLINE": "1",
        "PIP_NO_INDEX": "1",
        **_uv_dirs(home),
        **_aws_fence(),
    }


def _output_tail(result: subprocess.CompletedProcess, lines: int = 25) -> str:
    return "\n".join((result.stdout + result.stderr).splitlines()[-lines:])


def _plugin_path(tmp_path: Path, module: str, text: str) -> str:
    """PYTHONPATH with a package ``module`` holding ``text`` first, then the caller's,
    for ``--ash-plugin-modules module``."""
    package = tmp_path / "plugins" / module
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(text, encoding="utf-8")
    return os.pathsep.join(
        p for p in (str(package.parent), os.environ.get("PYTHONPATH")) if p
    )


# --------------------------------------------------------------------------- #
# Delivered configs: what the default policy refuses and allows
# --------------------------------------------------------------------------- #

_DENIED_INTRO = (
    "With the default policy, a delivered config is refused as a whole, with `error_type` "
    "`config_field_denied` and a message naming each field, if it sets any of these to a "
    "value other than the server's own:"
)

#: Each item of mcp-server.md's list, as written, with the fields it names as JSON
#: pointers. Items that name an option for every scanner ("any scanner's ``offline``
#: option") get the shipped scanners that have it, in the test.
_DENIED_ITEMS: Dict[str, Tuple[str, ...]] = {
    "the gate: `fail_on_findings`, `fail_on_incomplete_scanners`, `content_db_staleness`, "
    "`content_db_staleness_overrides`, and `content_db_staleness_offline_image_default`": (
        "/fail_on_findings",
        "/fail_on_incomplete_scanners",
        "/content_db_staleness",
        "/content_db_staleness_overrides",
        "/content_db_staleness_offline_image_default",
    ),
    "scanner options that drop findings by rule ID, by a baseline, or by a whole category, "
    "such as `exclude_rule`, `config`, and `severity` of `opengrep` and `semgrep`, checkov's "
    "`frameworks`, cfn-lint's `ignore_checks`, detect-secrets' `baseline_file` and "
    "`scan_settings`, and trivy's `scanners` and `ignore_unfixed`": (
        "/scanners/opengrep/options/exclude_rule",
        "/scanners/opengrep/options/config",
        "/scanners/opengrep/options/severity",
        "/scanners/semgrep/options/exclude_rule",
        "/scanners/semgrep/options/config",
        "/scanners/semgrep/options/severity",
        "/scanners/checkov/options/frameworks",
        "/scanners/cfn-lint/options/ignore_checks",
        "/scanners/detect-secrets/options/baseline_file",
        "/scanners/detect-secrets/options/scan_settings",
        "/scanners/trivy/options/scanners",
        "/scanners/trivy/options/ignore_unfixed",
    ),
    "options that limit how much a scanner reads or reports, or that turn on its own "
    "network calls, such as ferret-scan's `finding_limit` and `recursive`, gitleaks' "
    "`max_target_megabytes`, and zizmor's `online_audits`": (
        "/scanners/ferret-scan/options/finding_limit",
        "/scanners/ferret-scan/options/recursive",
        "/scanners/gitleaks/options/max_target_megabytes",
        "/scanners/zizmor/options/online_audits",
    ),
    "any scanner's `offline` option": (),
    "options that name a scanner's own config file or another file or program its tool "
    "reads: every scanner's `config_file`, and others such as trivy's `ignore_file`, "
    "gitleaks' `baseline_path`, and actionlint's `shellcheck` and `pyflakes`": (
        "/scanners/trivy/options/ignore_file",
        "/scanners/gitleaks/options/baseline_path",
        "/scanners/actionlint/options/shellcheck",
        "/scanners/actionlint/options/pyflakes",
    ),
    "which version of a tool runs: any scanner's or the `jupyter` converter's "
    "`tool_version`, and opengrep's `version` and `sha256`": (
        "/converters/jupyter/options/tool_version",
        "/scanners/opengrep/options/version",
        "/scanners/opengrep/options/sha256",
    ),
    "any setting of the reporters that send findings off the host, `aws-security-hub`, "
    "`bedrock-summary-reporter`, `cloudwatch-logs`, and `s3`, their `enabled` included": (
        "/reporters/aws-security-hub/enabled",
        "/reporters/aws-security-hub/options/aws_region",
        "/reporters/aws-security-hub/options/aws_profile",
        "/reporters/aws-security-hub/options/account_id",
        "/reporters/bedrock-summary-reporter/enabled",
        "/reporters/bedrock-summary-reporter/options/aws_region",
        "/reporters/bedrock-summary-reporter/options/aws_profile",
        "/reporters/bedrock-summary-reporter/options/model_id",
        "/reporters/bedrock-summary-reporter/options/output_file",
        "/reporters/bedrock-summary-reporter/options/custom_prompt",
        "/reporters/cloudwatch-logs/enabled",
        "/reporters/cloudwatch-logs/options/log_group_name",
        "/reporters/s3/enabled",
        "/reporters/s3/options/aws_region",
        "/reporters/s3/options/aws_profile",
        "/reporters/s3/options/bucket_name",
        "/reporters/s3/options/key_prefix",
        "/reporters/s3/options/max_retries",
    ),
    "the `gitlab-sast` reporter's `exclude_suppressed`, which leaves suppressed findings "
    "out of its report": ("/reporters/gitlab-sast/options/exclude_suppressed",),
}

#: The options the list names for every scanner that has one.
_EVERY_SCANNERS_OPTION = ("offline", "config_file", "tool_version")

#: The reporters mcp-server.md says send findings off the host.
_OFF_HOST_REPORTERS = (
    "aws-security-hub",
    "bedrock-summary-reporter",
    "cloudwatch-logs",
    "s3",
)


def _client_value(field: str) -> Any:
    """A value for ``field`` that no trusted config has.

    ``true`` for the switches, since the list's own exceptions accept ``false``: an
    off-host reporter's ``enabled: false`` (the paragraph after the list), and
    ``exclude_suppressed: false``, which is the server's own.
    """
    return (
        True
        if field.rsplit("/", 1)[-1] in ("enabled", "exclude_suppressed")
        else "client-value"
    )


@pytest.mark.unit
def test_a_delivered_config_may_not_set_any_option_the_mcp_page_lists(
    mcp_workspace_root: Path,
) -> None:
    """mcp-server.md (What a delivered config cannot set), and trust-model.md (When a
    lower tier sets something it may not), which summarizes the same list.

    Every field the list names is written, with a value no trusted config has, into a
    file under the MCP workspace root, and the default policy must refuse each one. Items
    that say "any scanner's" or "every scanner's" are checked against every scanner ASH
    ships with that option, so a new scanner whose option the policy misses fails here.

    Every code span in the list must be a segment of a field checked here, so an option
    added to the page without a field here fails too. And a file that writes the
    server's own value for a gate setting is accepted, since only a different value is
    refused.
    """
    assert_on_page(MCP_SERVER, _DENIED_INTRO)
    for item in _DENIED_ITEMS:
        assert_on_page(MCP_SERVER, f"- {item}")
    assert_on_page(
        TRUST_MODEL,
        "By default the list covers the gate settings (`fail_on_findings`, "
        "`fail_on_incomplete_scanners`, `content_db_staleness` and its overrides, and "
        "`content_db_staleness_offline_image_default`), the scanner options that drop "
        "findings by rule ID, by a baseline, or by a whole category, options that limit how "
        "much a scanner reads or that turn on its own network calls, each scanner's "
        "`offline` option, each scanner's own config file, which version of a tool runs, "
        "every setting of the reporters that send findings off the host "
        "(`aws-security-hub`, `bedrock-summary-reporter`, `cloudwatch-logs`, and `s3`), "
        "their `enabled` included, and the `gitlab-sast` reporter's `exclude_suppressed`;",
    )
    assert_on_page(
        TRUST_MODEL,
        "If a delivered file sets any of them to a value other than the trusted one, ASH "
        "refuses the whole file rather than trimming it.",
    )

    from automated_security_helper.config.client_config_policy import (
        client_file_denials,
        rules_from,
    )
    from automated_security_helper.config.default_config import get_default_config

    trusted = get_default_config()
    rules = rules_from(trusted)
    delivered = mcp_workspace_root / "session" / "source" / ".ash" / ".ash.yaml"

    def refused(document: Dict[str, Any]) -> bool:
        return bool(
            client_file_denials(
                {delivered: document}, rules, scanned_root=delivered.parent.parent
            )
        )

    scanners = _shipped_plugin_options("ASH_SCANNERS")
    fields = [pointer for pointers in _DENIED_ITEMS.values() for pointer in pointers]
    fields += [
        f"/scanners/{scanner}/options/{option}"
        for scanner, options in sorted(scanners.items())
        for option in _EVERY_SCANNERS_OPTION
        if option in options
    ]
    allowed = [f for f in fields if not refused(_document_setting(f, _client_value(f)))]
    assert not allowed, (
        f"{MCP_SERVER} says a delivered config may not set these, and the default "
        f"policy lets it: {allowed}"
    )

    named = {segment for field in fields for segment in field.strip("/").split("/")}
    listed = _page_section(
        MCP_SERVER, _DENIED_INTRO, "`ash config init` writes the full default list"
    )
    unchecked = set(re.findall(r"`([^`]+)`", listed)) - named
    assert not unchecked, (
        f"{MCP_SERVER}'s list names {sorted(unchecked)}, which no field in this test "
        f"writes. Add the field to _DENIED_ITEMS."
    )

    own_values = trusted.model_dump(mode="json", by_alias=True)
    for gate in (
        "fail_on_findings",
        "fail_on_incomplete_scanners",
        "content_db_staleness",
    ):
        assert not refused({gate: own_values[gate]}), (
            f"a delivered config that writes the server's own {gate} is refused"
        )


@pytest.mark.unit
def test_a_delivered_config_may_still_disable_scanners_switch_reporters_and_raise_thresholds(
    mcp_workspace_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """trust-model.md (When a lower tier sets something it may not), and mcp-server.md
    (What a delivered config cannot set).

    A tree under the MCP workspace root resolves with these settings, as a CLI scan of
    it would, and each takes effect: a scanner off with a higher threshold, a higher
    global threshold, the local reporters ``html``, ``sarif`` and ``yaml`` switched, and
    ``github-ghas``'s ``exclude_suppressed`` turned off. ``gitlab-sast``'s
    ``exclude_suppressed`` is the local option the page excepts, and turning it on
    refuses the file, as turning ``cloudwatch-logs`` on does.

    An off-host reporter's ``enabled: false`` is accepted and changes nothing: each of
    the four runs as the server's config says, or by its own default where that config
    sets nothing. That is checked with no server config (``ASH_CONFIG`` unset), and with
    one that turns each on, so a ``false`` that took effect shows even for a reporter
    whose own default is off.
    """
    assert_on_page(
        TRUST_MODEL,
        "Under the default policy a delivered config can still disable scanners, turn the "
        "reporters that write only local files on or off and set their options, apart from "
        "`gitlab-sast`'s `exclude_suppressed`, and raise severity thresholds. It cannot "
        "turn a reporter that sends findings off the host on or off: its `enabled: false` "
        "for one of them is not refused, but it has no effect, and each runs as the "
        "server's config says, or by the reporter's own default where that config sets "
        "nothing.",
    )
    assert_on_page(
        TRUST_MODEL,
        "A config an MCP client delivers can also turn the reporters that write only local "
        "files on or off and set their options.",
    )
    assert_on_page(
        MCP_SERVER,
        "A delivered config can still turn the reporters that write only local files, "
        "such as `html`, `sarif`, and `yaml`, on or off and set their options, apart from "
        "`gitlab-sast`'s `exclude_suppressed`.",
    )
    assert_on_page(
        MCP_SERVER,
        "A delivered config cannot turn a reporter that sends findings off the host on or "
        "off. Its `enabled: false` for one of the four is not refused, but it has no "
        "effect: each runs as the server's config says, or by the reporter's own default "
        "where that config sets nothing.",
    )
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    tree = _tree_with_config(
        mcp_workspace_root,
        {
            "project_name": "delivered",
            "global_settings": {"severity_threshold": "HIGH"},
            "scanners": {
                "bandit": {
                    "enabled": False,
                    "options": {"severity_threshold": "CRITICAL"},
                }
            },
            "reporters": {
                "html": {"enabled": False},
                "sarif": {"enabled": False},
                "yaml": {"enabled": True},
                "github-ghas": {"options": {"exclude_suppressed": False}},
            },
        },
    )
    config = resolve_config(source_dir=tree)

    def reporter(name: str) -> Dict[str, Any]:
        return config.get_plugin_config(plugin_type="reporter", plugin_name=name)

    bandit = config.get_plugin_config(plugin_type="scanner", plugin_name="bandit")
    assert config.global_settings.severity_threshold == "HIGH"
    assert bandit["enabled"] is False
    assert bandit["options"]["severity_threshold"] == "CRITICAL"
    assert reporter("html")["enabled"] is False
    assert reporter("sarif")["enabled"] is False
    assert reporter("yaml")["enabled"] is True
    assert reporter("github-ghas")["options"]["exclude_suppressed"] is False

    for denied, match in (
        ({"cloudwatch-logs": {"enabled": True}}, "cloudwatch-logs"),
        (
            {"gitlab-sast": {"options": {"exclude_suppressed": True}}},
            "exclude_suppressed",
        ),
    ):
        refused = _tree_with_config(
            mcp_workspace_root / f"refused-{match}",
            {"project_name": "delivered", "reporters": denied},
        )
        with pytest.raises(ASHConfigFieldDeniedError, match=match):
            resolve_config(source_dir=refused)

    own_default = {
        name: model.model_fields["enabled"].default
        for name, model in _shipped_plugin_configs("ASH_REPORTERS").items()
    }

    def runs(resolved: Any) -> Dict[str, Any]:
        """Whether each off-host reporter runs with ``resolved``: its ``enabled``, or
        its own default where its section sets none."""
        return {
            name: (resolved.get_plugin_config("reporter", name) or {}).get(
                "enabled", own_default[name]
            )
            for name in _OFF_HOST_REPORTERS
        }

    def runs_after_delivered_off(parent: Path) -> Dict[str, Any]:
        return runs(
            resolve_config(
                source_dir=_tree_with_config(
                    parent,
                    {
                        "project_name": "delivered",
                        "reporters": {
                            n: {"enabled": False} for n in _OFF_HOST_REPORTERS
                        },
                    },
                )
            )
        )

    server_says = runs(get_default_config())
    found = runs_after_delivered_off(mcp_workspace_root / "no-server-config")
    assert found == server_says, (
        f"{MCP_SERVER} says a delivered enabled: false has no effect, and with no "
        f"server config the off-host reporters run as {found}, not by their own "
        f"defaults, {server_says}"
    )
    operator = mcp_workspace_root.parent / "server" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        yaml.safe_dump(
            {
                "project_name": "server",
                "reporters": {n: {"enabled": True} for n in _OFF_HOST_REPORTERS},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    found = runs_after_delivered_off(mcp_workspace_root / "server-turns-them-on")
    assert found == dict.fromkeys(_OFF_HOST_REPORTERS, True), (
        f"{MCP_SERVER} says a delivered enabled: false has no effect, and the off-host "
        f"reporters the server's config turns on run as {found}"
    )


@pytest.mark.parametrize(
    "config_text, under_the_root, outside_the_root",
    [
        # A reference without a default reads the variable, which the test sets
        # (configure.md), so outside the root it resolves; under the root it is
        # refused all the same.
        pytest.param(
            "project_name: ${ASH_PAGE_CLAIM_NAME}\n",
            3,
            "named-by-the-environment",
            id="reference",
        ),
        pytest.param(
            "project_name: ${ASH_PAGE_CLAIM_NAME:unset}\n",
            3,
            "named-by-the-environment",
            id="reference-with-default",
        ),
        pytest.param(
            "project_name: !ENV ${ASH_PAGE_CLAIM_NAME:unset}\n",
            3,
            "named-by-the-environment",
            id="env-tag",
        ),
        # The control: a plain config under the root scans. The tree holds nothing
        # detect-secrets reports, so the scan exits 0.
        pytest.param(
            "project_name: delivered\n",
            0,
            "delivered",
            id="control-a-plain-config-scans",
        ),
    ],
)
@pytest.mark.integration
def test_a_cli_scan_of_a_delivered_tree_refuses_a_config_that_reads_the_environment(
    tmp_path: Path,
    mcp_workspace_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_text: str,
    under_the_root: int,
    outside_the_root: str,
) -> None:
    """mcp-server.md (What a delivered config cannot set).

    ``ash scan`` of a tree under the MCP workspace root exits 3 when the tree's config
    holds a reference or an ``!ENV`` tag, and 0 when it holds neither, which shows the
    refusal is the reference's and not the root's. The same file in a tree outside the
    root resolves and reads the variable, so the refusal follows where the file is and
    not what it says.
    """
    assert_on_page(
        MCP_SERVER,
        "A file in which a plain value starts with a `${VAR}` or `${VAR:default}` "
        "reference, or that uses an `!ENV` tag, is refused:",
    )
    assert_on_page(
        CONFIGURE,
        "`${NAME}` without a default needs the variable: when it is not set, ASH refuses "
        "the config with exit 3 and names the variable.",
    )
    assert_on_page(
        MCP_SERVER,
        "The rule follows where the file is, so a CLI scan of a delivered tree refuses "
        "such a config too, with exit code 3.",
    )
    monkeypatch.setenv("ASH_PAGE_CLAIM_NAME", "named-by-the-environment")

    delivered = _tree_with_config(mcp_workspace_root, config_text)
    result = _ash(
        [
            "scan",
            "--source-dir",
            str(delivered),
            "--scanners",
            "detect-secrets",
            "--offline",
            "--no-progress",
        ],
        cwd=tmp_path,
    )
    assert result.returncode == under_the_root, (
        f"exit {result.returncode}, expected {under_the_root}:\n{_output_tail(result)}"
    )

    from automated_security_helper.config.resolve_config import resolve_config

    repository = _tree_with_config(tmp_path / "repository", config_text)
    assert resolve_config(source_dir=repository).project_name == outside_the_root


#: The trust page's example config: one sandbox grant, which only an operator-tier
#: file keeps, and a plugin module in ASH's plugin namespace that lives in the home
#: directory. A repository-written file may add only installed modules outside every
#: checkout, so with the home directory a checkout only an operator file keeps it.
_HOME_CHECKOUT_GRANT = "/opt/shared-rules"
_HOME_CHECKOUT_MODULE = "page_claims_ash_plugins"
_HOME_CHECKOUT_CONFIG = (
    f"project_name: app\nsandbox:\n  extra_read_paths:\n    - {_HOME_CHECKOUT_GRANT}\n"
    f"ash_plugin_modules:\n  - {_HOME_CHECKOUT_MODULE}\n"
)
_HOME_CHECKOUT_SENTENCE = (
    "If your home directory is itself a git checkout (a common dotfiles setup), the "
    "outermost checkout above a project under it is your home directory, so a scan of "
    "that project counts your whole home directory as the scanned tree."
)


def _home_with_a_project(tmp_path: Path, home_is_a_checkout: bool) -> Tuple[Path, Path]:
    """(the home directory, a project under it that is a checkout of its own)."""
    home = tmp_path / "home"
    project = home / "work" / "app"
    (project / ".git").mkdir(parents=True)
    if home_is_a_checkout:
        (home / ".git").mkdir()
    return home, project


@pytest.mark.parametrize(
    "home_is_a_checkout, config_under_home, module_in_home, grant_kept, module_kept",
    [
        pytest.param(
            True, True, True, False, False, id="a-config-under-a-home-checkout"
        ),
        pytest.param(
            True, True, False, False, True, id="a-module-installed-outside-is-kept"
        ),
        pytest.param(
            False, True, True, True, True, id="control-a-home-that-is-no-checkout"
        ),
        pytest.param(
            True, False, True, True, True, id="control-a-config-outside-the-home"
        ),
    ],
)
@pytest.mark.unit
def test_a_home_directory_checkout_makes_every_config_under_it_repository_tier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    home_is_a_checkout: bool,
    config_under_home: bool,
    module_in_home: bool,
    grant_kept: bool,
    module_kept: bool,
) -> None:
    """trust-model.md (How a file's tier is decided), and platform-teams.md (2. Write
    the operator config).

    A project that is a checkout of its own sits under the home directory, and the
    operator's config is in ``~/.config/ash``. It holds the page's sandbox grant and
    names a plugin module, in ASH's plugin namespace and importable, that lives in
    ``~/plugins``. The config is resolved for a scan of the project the way a scan
    resolves it. When the home directory is itself a checkout, the config is
    repository-tier: its grant is dropped, and so is the module, which it may not load
    from a checkout. The same config naming a module installed outside every checkout
    loses its grant and keeps the module. The controls keep both: a home directory
    that is no checkout, and the page's advice, a config outside the home directory,
    which names the module in the home checkout.

    A config file is repository-tier inside any git checkout, so this does not tell
    that rule apart from the scanned tree's. That the outermost checkout is the scanned
    tree is held by test_a_home_directory_checkout_makes_the_whole_home_the_scanned_tree.
    """
    assert_on_page(TRUST_MODEL, _HOME_CHECKOUT_SENTENCE)
    assert_on_page(
        TRUST_MODEL,
        "Every config file under your home directory, yours included, is then "
        "repository-tier for that scan. Keep your operator config outside it, for "
        "example under `/etc/ash`.",
    )
    assert_on_page(
        TRUST_MODEL,
        f"printf 'project_name: app\\nsandbox:\\n  extra_read_paths:\\n    - "
        f"{_HOME_CHECKOUT_GRANT}\\n' > ../ops/ash.yaml",
    )
    assert_on_page(
        _CONFIG_PLATFORM_PAGE,
        "Such a config can turn on plugin modules that are already installed outside "
        "every git checkout and the scanned directory, such as in site-packages. It "
        "can't load plugin code from the repository or any other checkout,",
    )
    from automated_security_helper.config.resolve_config import resolve_config

    home, project = _home_with_a_project(tmp_path, home_is_a_checkout)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    package = (home if module_in_home else tmp_path / "site") / "plugins"
    package = package / _HOME_CHECKOUT_MODULE
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(package.parent))
    config = (home / ".config" if config_under_home else tmp_path / "etc") / "ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_text(_HOME_CHECKOUT_CONFIG, encoding="utf-8")

    resolved = resolve_config(config_path=config, source_dir=project)
    where = f"{config} with home{' a checkout' if home_is_a_checkout else ''}"
    granted = [str(path) for path in resolved.sandbox.extra_read_paths]
    assert (_HOME_CHECKOUT_GRANT in granted) is grant_kept, (
        f"{where}: extra_read_paths {granted}"
    )
    modules = list(resolved.ash_plugin_modules or [])
    assert (_HOME_CHECKOUT_MODULE in modules) is module_kept, (
        f"{where}: ash_plugin_modules {modules}"
    )


@pytest.mark.parametrize(
    "home_is_a_checkout, honored",
    [
        pytest.param(True, False, id="a-home-checkout-is-the-scanned-tree"),
        pytest.param(False, True, id="control-a-home-that-is-no-checkout"),
    ],
)
@pytest.mark.unit
def test_a_home_directory_checkout_makes_the_whole_home_the_scanned_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    home_is_a_checkout: bool,
    honored: bool,
) -> None:
    """trust-model.md (How a file's tier is decided).

    A project that is a checkout of its own sits under the home directory. An operator
    config outside every checkout names a checkov config file kept in the home
    directory, outside the project. A tool file the operator names is refused only
    when it is inside the scanned tree, so whether checkov may be given it says what
    the scanned tree is: with the home directory a checkout, the outermost checkout
    above the project is the home directory, and the file is refused. The control is
    a home directory that is no checkout, where the scanned tree is the project's own
    checkout and the file is passed on. A rule that took the project's own checkout as
    the scanned tree would pass it on in both.
    """
    assert_on_page(TRUST_MODEL, _HOME_CHECKOUT_SENTENCE)
    from automated_security_helper.config.path_trust import honored_path
    from automated_security_helper.config.resolve_config import resolve_config

    home, project = _home_with_a_project(tmp_path, home_is_a_checkout)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    tool_file = home / "rules" / "checkov.yaml"
    tool_file.parent.mkdir()
    tool_file.write_text("framework: [terraform]\n", encoding="utf-8")
    operator = tmp_path / "etc" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        yaml.safe_dump(
            {
                "project_name": "app",
                "scanners": {"checkov": {"options": {"config_file": str(tool_file)}}},
            }
        ),
        encoding="utf-8",
    )

    resolved = resolve_config(config_path=operator, source_dir=project)
    given = honored_path(
        str(tool_file),
        source_dir=project,
        key="scanners.checkov.options.config_file",
        config=resolved,
    )
    assert (given is not None) is honored, (
        f"home{' a checkout' if home_is_a_checkout else ''}: checkov is given {given}"
    )


@pytest.mark.parametrize(
    "named_by, honored",
    [
        pytest.param("repository", False, id="the-projects-own-config-names-it"),
        pytest.param("ops-checkout", False, id="a-config-in-the-ops-checkout-names-it"),
        pytest.param("overrides", True, id="the-operator-names-it-with-overrides"),
        pytest.param(
            "operator-config",
            True,
            id="the-operator-names-it-in-a-config-outside-every-checkout",
        ),
    ],
)
@pytest.mark.unit
def test_who_names_a_tool_config_path_decides_where_it_may_be(
    tmp_path: Path, named_by: str, honored: bool
) -> None:
    """trust-model.md (What each tier may set; The scanned tree), and
    choose-scanners.md (Options only the operator can set).

    A checkov config file sits in a separate ops checkout, outside the scanned project,
    and the config is resolved for a scan of the project. A path that a config inside
    any git checkout names is refused anywhere in a checkout, so checkov is not given
    it when the project's own config names it, nor when a config beside it in the ops
    checkout does. A path the operator names, with ``--config-overrides`` or in a
    config outside every checkout, is refused only inside the scanned tree, which the
    ops checkout is not, so checkov is given it.
    """
    assert_on_page(
        TRUST_MODEL,
        "Honored. For some scanners the file may not be inside the scanned tree.",
    )
    assert_on_page(TRUST_MODEL, "Set these options from an operator source")
    assert_on_page(
        TRUST_MODEL,
        "A tool file you name as the operator, with `--config-overrides`, in a config "
        "file outside every git checkout and the scanned directory, or in an environment "
        "variable, is used unless it is inside the scanned tree and the scanner does not "
        "allow one there, so it may be in a checkout of your own, such as an ops "
        "repository. A tool file that any other config file names, one in an ops "
        "checkout included, or that ASH finds by name, is used only from outside every "
        "git checkout and the scanned directory.",
    )
    assert_on_page(
        "how-to/choose-scanners.md",
        "A config in an ops checkout of its own is not an operator source here.",
    )
    from automated_security_helper.config.path_trust import honored_path
    from automated_security_helper.config.resolve_config import resolve_config

    key = "scanners.checkov.options.config_file"
    tool_file = tmp_path / "ops" / "checkov.yaml"
    (tool_file.parent / ".git").mkdir(parents=True)
    tool_file.write_text("framework: [terraform]\n", encoding="utf-8")
    naming = {
        "project_name": "app",
        "scanners": {"checkov": {"options": {"config_file": str(tool_file)}}},
    }
    config_path: Optional[Path] = None
    overrides: List[str] = []
    if named_by == "repository":
        project = _tree_with_config(tmp_path / "project", naming)
    else:
        project = tmp_path / "project" / "session" / "source"
        project.mkdir(parents=True)
    if named_by == "ops-checkout":
        config_path = tool_file.parent / "ash.yaml"
    elif named_by == "operator-config":
        config_path = tmp_path / "etc" / "ash.yaml"
        config_path.parent.mkdir()
    elif named_by == "overrides":
        overrides = [f"{key}={tool_file}"]
    if config_path is not None:
        config_path.write_text(yaml.safe_dump(naming), encoding="utf-8")
    (project / ".git").mkdir()

    resolved = resolve_config(
        config_path=config_path, source_dir=project, config_overrides=overrides
    )
    given = honored_path(str(tool_file), source_dir=project, key=key, config=resolved)
    assert (given is not None) is honored, (
        f"named by the {named_by}: checkov is given {given}"
    )


AWS_PLUGINS = "plugins/aws.md"


@pytest.mark.parametrize(
    "setting, in_a_checkout",
    [
        pytest.param(
            "bucket_name", True, id="a-bucket-from-an-ops-checkout-is-ignored"
        ),
        pytest.param("bucket_name", False, id="control-a-bucket-from-outside-is-kept"),
        pytest.param("enabled", True, id="enabled-from-an-ops-checkout-is-ignored"),
        pytest.param("enabled", False, id="control-enabled-from-outside-is-kept"),
    ],
)
@pytest.mark.unit
def test_a_config_in_an_ops_checkout_cannot_set_the_aws_reporters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ash_log: List[logging.LogRecord],
    setting: str,
    in_a_checkout: bool,
) -> None:
    """trust-model.md (What each tier may set), and aws.md.

    The operator's ``--config`` sets the S3 reporter's bucket, or turns the reporter
    on, for a scan of a project that is a checkout. From a file in an ops checkout of
    its own, ASH must ignore the setting, with one warning that names the option and
    the file and gives the advice on keeping a setting: the bucket is not set, and the
    reporter keeps its own default ``enabled``. The control is the same file outside
    every git checkout, whose setting is kept, with no such warning.
    """
    assert_on_page(
        TRUST_MODEL,
        "A config you trust but keep in a git checkout of its own, such as an ops "
        "repository, cannot make the restricted settings below, because it is in a "
        "checkout.",
    )
    assert_on_page(
        TRUST_MODEL,
        "and whether each of these reporters runs | Honored | Replaced by the trusted "
        "value. |",
    )
    assert_on_page(
        AWS_PLUGINS,
        "When a config file inside any git checkout or the scanned directory sets one of "
        "these options, under any spelling of the reporter's section, ASH ignores it, logs "
        "a warning that names the option, and uses the operator's value.",
    )
    assert_on_page(
        AWS_PLUGINS,
        "A config file inside any git checkout or the scanned directory, an ops repository "
        "of your own included, turns none of them on or off: each keeps the operator's "
        "`enabled`, or its own default where the operator sets none, and a different "
        "value in the file is ignored with a warning",
    )
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    directory = tmp_path / ("ops" if in_a_checkout else "etc")
    directory.mkdir()
    if in_a_checkout:
        (directory / ".git").mkdir()
    section: Dict[str, Any] = (
        {"options": {"bucket_name": "page-claims-bucket"}}
        if setting == "bucket_name"
        else {"enabled": True}
    )
    operator = directory / "ash.yaml"
    operator.write_text(
        yaml.safe_dump({"project_name": "app", "reporters": {"s3": section}}),
        encoding="utf-8",
    )

    ash_log.clear()
    resolved = resolve_config(config_path=operator, source_dir=project)
    s3 = resolved.get_plugin_config("reporter", "s3") or {}
    own_default = (
        _shipped_plugin_configs("ASH_REPORTERS")["s3"].model_fields["enabled"].default
    )
    if setting == "bucket_name":
        value, wanted = (
            (s3.get("options") or {}).get("bucket_name"),
            "page-claims-bucket",
        )
    else:
        value, wanted = s3.get("enabled", own_default), True
        assert own_default is not True, (
            "s3 runs by its own default, so on shows nothing"
        )
    key = (
        "reporters.s3.options.bucket_name"
        if setting == "bucket_name"
        else ("reporters.s3.enabled")
    )
    warnings = [
        m
        for m in _messages(r for r in ash_log if r.levelno == logging.WARNING)
        if m.startswith("Ignoring ") and key in m.split(" from ", 1)[0]
    ]
    if in_a_checkout:
        assert value != wanted, f"{key} from an ops checkout took effect: {value!r}"
        assert len(warnings) == 1, warnings
        assert str(operator) in warnings[0] or operator.as_posix() in warnings[0], (
            warnings[0]
        )
        assert _KEEP_A_SETTING in warnings[0], warnings[0]
    else:
        assert value == wanted, (
            f"{key} from outside every checkout was not kept: {value!r}"
        )
        assert warnings == [], warnings


_AWS_PLUGIN_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"

#: aws.md's quote of what ash report prints for a config file that turns on and aims
#: the S3 reporter, the file being /etc/ash/ash.yaml.
_REPORT_IGNORES_THE_FILE = (
    "WARNING Ignoring reporters.s3.options.aws_region, reporters.s3.options.bucket_name, "
    "reporters.s3.enabled from /etc/ash/ash.yaml: ash report cannot tell that config "
    "from the scanned repository's own, since stored results do not record which tree "
    "was scanned, and these options choose whether findings are sent, where they are "
    "sent or written, and which credentials send them. To send findings off the host "
    "from ash report, pass each of these settings with --config-overrides instead."
)
_REPORT_REFUSES_THE_REPORTER = (
    "Error: reporter 's3' sends findings off the host and is not enabled. ash report "
    "takes whether it runs, and where it sends, from --config-overrides: pass "
    "--config-overrides reporters.s3.enabled=true and its destination options."
)
#: The settings of the S3 reporter that aws.md's example turns on, as overrides.
_S3_OVERRIDES = [
    "--config-overrides",
    "reporters.s3.enabled=true",
    "--config-overrides",
    "reporters.s3.options.aws_region=us-west-2",
    "--config-overrides",
    "reporters.s3.options.bucket_name=my-bucket",
]


def _no_aws_credentials_environment(cwd: Path, **env: str) -> Dict[str, str]:
    """``_ash_environment`` with no AWS credentials anywhere a child could find them:
    no AWS_* variables, no config or credentials file, the instance metadata
    service off, and an endpoint that refuses the connection, so an AWS client
    fails before it sends anything, on a host with credentials configured too."""
    environment = _ash_environment(cwd, **env)
    for name in [name for name in environment if name.startswith("AWS_")]:
        del environment[name]
    environment.update(_aws_fence())
    return environment


def _ash_with_no_aws_credentials(
    args: List[str], cwd: Path, **env: str
) -> subprocess.CompletedProcess:
    """``_ash`` in ``_no_aws_credentials_environment``."""
    return subprocess.run(
        [sys.executable, "-m", "automated_security_helper.cli.main", *args],
        cwd=cwd,
        env=_no_aws_credentials_environment(cwd, **env),
        capture_output=True,
        text=True,
        timeout=600,
    )


def _stored_scan(tmp_path: Path, *extra: str) -> Path:
    """The output directory of a one-shard detect-secrets scan of a one-file tree,
    with ``extra`` arguments, which ash report and ash merge read."""
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    output = tmp_path / "scan-output"
    result = _ash(
        [
            "scan",
            "--source-dir",
            str(tree),
            "--scanners",
            "detect-secrets",
            "--offline",
            "--no-progress",
            "--output-dir",
            str(output),
            "--shard-index",
            "0",
            "--shard-count",
            "1",
            *extra,
        ],
        cwd=tmp_path,
    )
    assert result.returncode == 0, _output_tail(result)
    return output


def _s3_config_file(tmp_path: Path) -> Path:
    """A config file outside every checkout that loads the AWS reporters and turns on
    and aims the S3 reporter, as aws.md's ash report section describes."""
    config = tmp_path / "etc" / "ash.yaml"
    config.parent.mkdir()
    config.write_text(
        yaml.safe_dump(
            {
                "project_name": "report",
                "ash_plugin_modules": [_AWS_PLUGIN_MODULE],
                "reporters": {
                    "s3": {
                        "enabled": True,
                        "options": {
                            "aws_region": "us-west-2",
                            "bucket_name": "my-bucket",
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return config


@pytest.mark.parametrize("named_by", ["--config", "ASH_CONFIG"])
@pytest.mark.integration
def test_ash_report_takes_no_aws_reporter_setting_from_a_config_file(
    tmp_path: Path, named_by: str
) -> None:
    """aws.md (Rendering a reporter from saved results).

    ``ash report --format s3`` runs over a stored scan, with no AWS credentials, and
    a config file outside every checkout, named by ``--config`` or ``ASH_CONFIG``,
    that loads the AWS reporters and turns on and aims the S3 reporter. It must print
    the warning and the refusal the page quotes, the file's path aside, and exit 1
    without trying to send: no upload error. That the refusal names a reporter, and
    not an unknown format, shows the file's other settings, its
    ``ash_plugin_modules``, still applied.
    """
    assert_on_page(
        AWS_PLUGINS,
        "The config file that `--config` or `ASH_CONFIG` names still applies its other "
        "settings. Its `enabled` and destination options for these reporters are ignored "
        "with a warning, and a reporter that `--config-overrides` does not turn on is "
        "refused with exit code 1.",
    )
    assert_on_page(
        AWS_PLUGINS, f"{_REPORT_IGNORES_THE_FILE} {_REPORT_REFUSES_THE_REPORTER}"
    )
    output = _stored_scan(tmp_path)
    config = _s3_config_file(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    named = ["--config", str(config)] if named_by == "--config" else []
    env = {"ASH_CONFIG": str(config)} if named_by == "ASH_CONFIG" else {}

    result = _ash_with_no_aws_credentials(
        ["report", "--format", "s3", *named, "--output-dir", str(output)],
        cwd=work,
        **env,
    )
    text = _squeezed(result.stdout + result.stderr)

    assert result.returncode == 1, _output_tail(result)
    assert any(
        _squeezed(
            _REPORT_IGNORES_THE_FILE.replace("WARNING ", "").replace(
                "/etc/ash/ash.yaml", spelling
            )
        )
        in text
        for spelling in _spellings(config)
    ), _output_tail(result)
    assert _squeezed(_REPORT_REFUSES_THE_REPORTER) in text, _output_tail(result)
    assert "uploading" not in text.lower(), _output_tail(result)


#: aws.md's paragraph on the pre-flight check ``ash report`` runs, and its quote of
#: the refusal it prints (Rendering a reporter from saved results).
_REPORT_RUNS_THE_PREFLIGHT = (
    "`ash report` runs the reporter's pre-flight check first, as a scan does. When the "
    "check refuses, for a missing setting or for credentials it cannot find, the "
    "reporter sends nothing, and `ash report` logs the reason and exits 1."
)
_REPORT_PREFLIGHT_REFUSED = (
    "Error: reporter 's3' cannot run: its dependency check refused. See the log above "
    "for the reason."
)


@pytest.mark.parametrize(
    "case", ["no-credentials", "no-region", "control-the-check-passes"]
)
@pytest.mark.integration
def test_ash_report_runs_an_aws_reporter_that_config_overrides_turn_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """aws.md (Rendering a reporter from saved results).

    The control for the test above: the same ``ash report --format s3``, with the
    package and the S3 reporter's settings given with ``--config-overrides`` alone, is
    not refused as a reporter that is not enabled, and runs the reporter's pre-flight
    check first. With no AWS credentials, or with no region, the check refuses: the
    reason is logged (for no region, the page's error), the command prints the page's
    refusal and exits 1, and nothing is uploaded. The control is a bucket on a moto
    server on loopback, with moto's test credentials and its endpoint, where the
    check passes, the object is uploaded, and the command exits 0.
    """
    assert_on_page(
        AWS_PLUGINS,
        "So `ash report` takes whether the reporter runs, and its destination options, "
        "from `--config-overrides` only:",
    )
    assert_on_page(AWS_PLUGINS, _REPORT_RUNS_THE_PREFLIGHT)
    assert_on_page(AWS_PLUGINS, _S3_HAS_NO_REGION)
    assert_on_page(AWS_PLUGINS, _REPORT_PREFLIGHT_REFUSED)
    output = _stored_scan(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    args = ["report", "--format", "s3", "--output-dir", str(output)]
    args += ["--config-overrides", f"ash_plugin_modules+=[{_AWS_PLUGIN_MODULE}]"]

    if case == "control-the-check-passes":
        with _moto_bucket(monkeypatch) as (endpoint, client, bucket):
            args += ["--config-overrides", "reporters.s3.enabled=true"]
            args += ["--config-overrides", "reporters.s3.options.aws_region=us-east-1"]
            args += ["--config-overrides", f"reporters.s3.options.bucket_name={bucket}"]
            result = subprocess.run(
                [sys.executable, "-m", "automated_security_helper.cli.main", *args],
                cwd=work,
                env=_moto_child_environment(work, endpoint),
                capture_output=True,
                text=True,
                timeout=600,
            )
            uploaded = client.list_objects_v2(Bucket=bucket).get("Contents", [])
        assert result.returncode == 0, _output_tail(result)
        assert len(uploaded) == 1, (uploaded, _output_tail(result))
        return

    if case == "no-credentials":
        args += _S3_OVERRIDES
        reason = "(s3 @ source)   Error when validating S3 access:"
    else:
        args += ["--config-overrides", "reporters.s3.enabled=true"]
        args += ["--config-overrides", "reporters.s3.options.bucket_name=my-bucket"]
        reason = _S3_HAS_NO_REGION
    result = _ash_with_no_aws_credentials(args, cwd=work)
    text = _squeezed(result.stdout + result.stderr)

    assert result.returncode == 1, _output_tail(result)
    assert _squeezed("sends findings off the host and is not enabled") not in text, (
        _output_tail(result)
    )
    assert _squeezed(reason) in text, _output_tail(result)
    assert _squeezed(_REPORT_PREFLIGHT_REFUSED) in text, _output_tail(result)
    assert "uploading" not in text.lower(), _output_tail(result)


@pytest.mark.parametrize(
    "overrides, sent",
    [
        pytest.param(False, False, id="the-files-settings-are-ignored"),
        pytest.param(True, True, id="control-the-overrides-turn-it-on"),
    ],
)
@pytest.mark.integration
def test_ash_merge_takes_no_aws_reporter_setting_from_its_config_file(
    tmp_path: Path, overrides: bool, sent: bool
) -> None:
    """aws.md (Rendering a reporter from saved results), and scale-large-repos.md.

    ``ash merge`` recombines a one-shard scan, with no AWS credentials and a
    ``--config`` file outside every checkout that loads the AWS reporters and turns on
    and aims the S3 reporter. It must warn that it ignores those settings, naming
    ``ash merge``, and the S3 reporter must not run: no attempt to reach S3. The
    control adds the S3 reporter's settings with ``--config-overrides``: no warning,
    and the reporter tries to reach S3, which fails with no credentials.
    """
    assert_on_page(
        AWS_PLUGINS,
        "`ash merge` holds its `--config` file to the same rule, since the shards do not "
        "record the tree either: the merged findings go off the host only with the "
        "reporter's `enabled` and destination options in `ash merge`'s "
        "`--config-overrides`, and the file's values are ignored with the same warning, "
        "naming `ash merge`.",
    )
    assert_on_page(
        SCALE_LARGE_REPOS,
        "The AWS reporters send the merged findings only with their `enabled` and "
        "destination options in `ash merge`'s `--config-overrides`, not from a config "
        "file",
    )
    output = _stored_scan(tmp_path)
    config = _s3_config_file(tmp_path)
    work = tmp_path / "work"
    work.mkdir()

    result = _ash_with_no_aws_credentials(
        [
            "merge",
            "--results",
            str(output / "ash_aggregated_results.json"),
            "--output-dir",
            str(tmp_path / "merged"),
            "--config",
            str(config),
            *(_S3_OVERRIDES if overrides else []),
        ],
        cwd=work,
    )
    text = _squeezed(result.stdout + result.stderr)
    warning = (
        "Ignoring reporters.s3.options.aws_region, reporters.s3.options.bucket_name, "
        "reporters.s3.enabled from {path}: ash merge cannot tell that config from the "
        "scanned repository's own, since the shards do not record which tree was "
        "scanned, and these options choose whether findings are sent"
    )

    assert result.returncode == 0, _output_tail(result)
    warned = any(
        _squeezed(warning.format(path=spelling)) in text
        for spelling in _spellings(config)
    )
    assert warned is not sent, _output_tail(result)
    assert (_squeezed("(s3 @ source)") in text) is sent, _output_tail(result)


@pytest.mark.parametrize(
    "named, formats, sent",
    [
        pytest.param(True, False, True, id="overrides-alone-with-the-package-named"),
        pytest.param(False, False, False, id="the-shards-package-is-not-loaded"),
        pytest.param(True, True, False, id="output-formats-stop-them"),
    ],
)
@pytest.mark.integration
def test_ash_merge_runs_the_aws_reporters_only_with_their_package_named_for_it(
    tmp_path: Path, named: bool, formats: bool, sent: bool
) -> None:
    """aws.md (Rendering a reporter from saved results), and scale-large-repos.md.

    A one-shard scan is made with the AWS reporters' package loaded, and ``ash
    merge`` recombines it with no AWS credentials, no ``--config`` file, and the S3
    reporter turned on and aimed with ``--config-overrides`` alone. With the package
    named for the merge too, the reporter must try to reach S3, which fails with no
    credentials. Without it, the package only the shards' scan loaded is not loaded,
    and nothing tries to reach S3; nor does anything with ``--output-formats sarif``.
    """
    assert_on_page(
        AWS_PLUGINS,
        "`ash merge` has these reporters only when the package is named for the merge "
        "itself, in its `--config` file's `ash_plugin_modules` or with "
        "`--config-overrides 'ash_plugin_modules+=[automated_security_helper.plugin_"
        "modules.ash_aws_plugins]'`: a package that only the shards' scan loaded is "
        "not loaded. It runs them only when `--output-formats` is not given.",
    )
    assert_on_page(
        SCALE_LARGE_REPOS,
        "Name their package for the merge too, with `--config` or "
        "`--config-overrides`, and leave out `--output-formats`, which stops them.",
    )
    load = ["--config-overrides", f"ash_plugin_modules+=[{_AWS_PLUGIN_MODULE}]"]
    output = _stored_scan(tmp_path, *load)
    work = tmp_path / "work"
    work.mkdir()

    result = _ash_with_no_aws_credentials(
        [
            "merge",
            "--results",
            str(output / "ash_aggregated_results.json"),
            "--output-dir",
            str(tmp_path / "merged"),
            *(load if named else []),
            *_S3_OVERRIDES,
            *(["--output-formats", "sarif"] if formats else []),
        ],
        cwd=work,
    )

    assert result.returncode == 0, _output_tail(result)
    text = _squeezed(result.stdout + result.stderr)
    assert (_squeezed("(s3 @ source)") in text) is sent, _output_tail(result)


#: aws.md's sentences on an enabled reporter that is missing a setting, and its quote
#: of the error for S3 with no region set.
_MISSING_SETTING_DOES_NOT_RUN = (
    "An enabled reporter that is missing a setting it needs does not run either, and "
    "ASH logs an error that names the setting and how to set it, once per run for each "
    "reporter and setting: the bucket for S3, the log group for CloudWatch Logs, and the "
    "region (`aws_region`, else `AWS_REGION` or `AWS_DEFAULT_REGION`) for S3, CloudWatch "
    "Logs, and Security Hub."
)
_S3_HAS_NO_REGION = (
    "ERROR    Reporter 's3' is enabled but does not run: no aws_region is set. Set it "
    "with --config-overrides reporters.s3.options.aws_region=<value>, or set "
    "AWS_REGION or AWS_DEFAULT_REGION in the environment, which is read only when no "
    "config sets aws_region."
)
_MISSING_SETTING_KEEPS_THE_EXIT_CODE = (
    "The exit code does not change, so check after each run that `reports/ash.s3.json` "
    "and `reports/ash.cwlog.json` exist."
)
_BEDROCK_REGION_DEFAULTS = (
    "Bedrock's region defaults to `us-east-1`, so it has no region only when a config "
    "sets `aws_region` to `null`."
)


@pytest.mark.parametrize(
    "reporter, given, missing",
    [
        pytest.param(
            "s3", {"bucket_name": "my-bucket"}, ["aws_region"], id="s3-no-region"
        ),
        pytest.param(
            "s3", {"aws_region": "us-west-2"}, ["bucket_name"], id="s3-no-bucket"
        ),
        pytest.param("s3", {}, ["aws_region", "bucket_name"], id="s3-neither"),
        pytest.param(
            "cloudwatch-logs",
            {"aws_region": "us-west-2"},
            ["log_group_name"],
            id="cloudwatch-logs-no-log-group",
        ),
        pytest.param(
            "cloudwatch-logs",
            {"log_group_name": "ash-findings"},
            ["aws_region"],
            id="cloudwatch-logs-no-region",
        ),
        pytest.param(
            "cloudwatch-logs",
            {},
            ["aws_region", "log_group_name"],
            id="cloudwatch-logs-neither",
        ),
        pytest.param(
            "aws-security-hub", {}, ["aws_region"], id="aws-security-hub-no-region"
        ),
        pytest.param(
            "bedrock-summary-reporter",
            {"aws_region": "null"},
            ["aws_region"],
            id="bedrock-region-set-to-null",
        ),
        pytest.param(
            "s3",
            {"aws_region": "us-west-2", "bucket_name": "my-bucket"},
            [],
            id="control-s3-both-set",
        ),
        pytest.param(
            "bedrock-summary-reporter", {}, [], id="control-bedrock-region-defaults"
        ),
    ],
)
@pytest.mark.integration
def test_an_enabled_aws_reporter_missing_a_setting_logs_an_error_naming_it(
    tmp_path: Path, reporter: str, given: Dict[str, str], missing: List[str]
) -> None:
    """aws.md (Load the package).

    A scan of a one-file tree loads the AWS reporters' package and turns on one AWS
    reporter with ``--config-overrides``, with no AWS credentials and no ``AWS_*``
    variables, so no region comes from the environment. For each setting it lacks,
    it must log one error naming the reporter, the setting and the override that sets
    it: for S3 with no region, the error the page quotes. A reporter lacking one must
    not run: nothing is logged under its ``(<reporter> @ source)`` prefix. The exit
    code must be 0, the scanned code's verdict, in every case. The controls name no
    missing setting: S3 with both settings, which runs and fails to upload with no
    credentials, and Bedrock with no region given, which defaults to us-east-1.
    """
    assert_on_page(AWS_PLUGINS, _MISSING_SETTING_DOES_NOT_RUN)
    assert_on_page(AWS_PLUGINS, _S3_HAS_NO_REGION)
    assert_on_page(AWS_PLUGINS, _MISSING_SETTING_KEEPS_THE_EXIT_CODE)
    assert_on_page(AWS_PLUGINS, _BEDROCK_REGION_DEFAULTS)
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    overrides = [
        f"ash_plugin_modules+=[{_AWS_PLUGIN_MODULE}]",
        f"reporters.{reporter}.enabled=true",
    ]
    overrides += [
        f"reporters.{reporter}.options.{name}={value}" for name, value in given.items()
    ]
    result = _ash_with_no_aws_credentials(
        [
            "scan",
            "--source-dir",
            str(tree),
            "--scanners",
            "detect-secrets",
            "--offline",
            "--no-progress",
            "--output-dir",
            str(tmp_path / "output"),
            *itertools.chain.from_iterable(
                ("--config-overrides", override) for override in overrides
            ),
        ],
        cwd=tmp_path,
    )
    text = _squeezed(result.stdout + result.stderr)

    assert result.returncode == 0, _output_tail(result)
    named = _squeezed("is enabled but does not run: no")
    assert text.count(named) == len(missing), _output_tail(result)
    for option in missing:
        if (reporter, option) == ("s3", "aws_region"):
            error = _S3_HAS_NO_REGION
        else:
            error = (
                f"ERROR    Reporter '{reporter}' is enabled but does not run: no "
                f"{option} is set. Set it with --config-overrides "
                f"reporters.{reporter}.options.{option}=<value>"
            )
        assert text.count(_squeezed(error)) == 1, _output_tail(result)
    ran = _squeezed(f"({reporter} @ source)") in text
    if missing:
        assert not ran, _output_tail(result)
    elif reporter == "s3":
        assert ran, _output_tail(result)


#: aws.md's sentence on what one run is, for the error of a missing setting.
_ONE_RUN_IS = (
    "A run is one `ash scan`, `ash report`, or `ash merge`, and a workspace run gives "
    "each error once for all its projects."
)
#: The settings that turn the S3 reporter on with its bucket and no region.
_S3_WITHOUT_A_REGION = [
    f"ash_plugin_modules+=[{_AWS_PLUGIN_MODULE}]",
    "reporters.s3.enabled=true",
    "reporters.s3.options.bucket_name=my-bucket",
]

#: Two scans one after the other in one process through the Python API, each with
#: the overrides given after the source and output directories. After each scan it
#: prints which run ended and its exit code, so each run's output can be read alone.
_TWO_RUNS = """\
import sys
from pathlib import Path

from automated_security_helper.interactions.run_ash_scan import run_ash_scan

source, output, overrides = sys.argv[1], sys.argv[2], sys.argv[3:]
for index in range(2):
    code = 0
    try:
        run_ash_scan(
            source_dir=source,
            output_dir=str(Path(output) / str(index)),
            scanners=["detect-secrets"],
            config_overrides=overrides,
            offline=True,
            progress=False,
            show_summary=False,
        )
    except SystemExit as stop:
        code = stop.code
    print(f"page-claims run {index} ended with {code}", flush=True)
"""


@pytest.mark.integration
def test_each_run_in_one_process_gives_the_error_for_a_missing_setting(
    tmp_path: Path,
) -> None:
    """aws.md (Load the package).

    Two scans run one after the other in one process through the Python API, as an
    MCP server runs its scans, each turning on the S3 reporter with a bucket and no
    region, with no AWS credentials and no ``AWS_*`` variables. Each run must exit 0
    and log the page's error for the missing region once: the second run gives it
    again, though the first already gave it in that process.
    """
    assert_on_page(AWS_PLUGINS, _MISSING_SETTING_DOES_NOT_RUN)
    assert_on_page(AWS_PLUGINS, _ONE_RUN_IS)
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            _TWO_RUNS,
            str(tree),
            str(tmp_path / "output"),
            *_S3_WITHOUT_A_REGION,
        ],
        cwd=tmp_path,
        env=_no_aws_credentials_environment(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=600,
    )
    tail = result.stdout[-4000:]

    first, ended, rest = result.stdout.partition("page-claims run 0 ended with 0\n")
    assert ended, tail
    second, ended, _ = rest.partition("page-claims run 1 ended with 0\n")
    assert ended, tail
    error = _squeezed(_S3_HAS_NO_REGION)
    counts = [_squeezed(first).count(error), _squeezed(second).count(error)]
    assert counts == [1, 1], tail


@pytest.mark.integration
def test_a_workspace_run_gives_the_error_for_a_missing_setting_once(
    tmp_path: Path,
) -> None:
    """aws.md (Load the package).

    A workspace scan of two projects turns on the S3 reporter with neither a bucket
    nor a region, with no AWS credentials and no ``AWS_*`` variables. Each project's
    report phase checks the reporter, and the run must log each of the two errors,
    the missing region and the missing bucket, once in all. Both projects must have
    been scanned, so both checked it, and the run must exit 0.
    """
    assert_on_page(AWS_PLUGINS, _MISSING_SETTING_DOES_NOT_RUN)
    assert_on_page(AWS_PLUGINS, _ONE_RUN_IS)
    workspace_dir = tmp_path / "ws"
    for name in ("api", "web"):
        (workspace_dir / name).mkdir(parents=True)
        (workspace_dir / name / "main.py").write_text("x = 1\n", encoding="utf-8")
    workspace = workspace_dir / "services.code-workspace"
    workspace.write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), "utf-8"
    )
    output = tmp_path / "ws-output"
    overrides = [
        f"ash_plugin_modules+=[{_AWS_PLUGIN_MODULE}]",
        "reporters.s3.enabled=true",
    ]
    result = _ash_with_no_aws_credentials(
        [
            *_CONFIG_SCAN,
            "--offline",
            "--workspace",
            str(workspace),
            "--output-dir",
            str(output),
            *itertools.chain.from_iterable(
                ("--config-overrides", override) for override in overrides
            ),
        ],
        cwd=tmp_path,
    )
    text = _squeezed(result.stdout + result.stderr)

    assert result.returncode == 0, _output_tail(result)
    scanned = sorted(
        path.parent.name
        for path in (output / "projects").glob("*/ash_aggregated_results.json")
    )
    assert scanned == ["api", "web"], _output_tail(result)
    region = _squeezed(_S3_HAS_NO_REGION)
    bucket = _squeezed(
        "ERROR    Reporter 's3' is enabled but does not run: no bucket_name is set."
    )
    assert [text.count(region), text.count(bucket)] == [1, 1], _output_tail(result)


_HONOR_IGNORE_FILES_ROW = (
    "| Whether the scanned repository's own `.gitignore` and `.ignore` files decide "
    "what is scanned, `honor_ignore_files` | Honored | Replaced by the trusted value. |"
)
_ARCHIVE_LIMITS_ROW = (
    "| The archive extraction limits, `max_members`, `max_member_bytes`, "
    "`max_total_bytes`, and `max_compression_ratio` under `converters.archive.options` "
    "| Honored | A value at or below the trusted one is kept; a higher one is replaced "
    "by the trusted value. |"
)
_ARCHIVE_LIMITS = (
    "max_members",
    "max_member_bytes",
    "max_total_bytes",
    "max_compression_ratio",
)


def _resolved_from_tier(tmp_path: Path, tier: str, document: Dict[str, Any]) -> Any:
    """``document`` resolved for a scan of a project that is a checkout: as the
    project's own ``.ash/.ash.yaml``, or as an operator config outside every
    checkout passed with ``--config``."""
    from automated_security_helper.config.resolve_config import resolve_config

    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    if tier == "repository":
        (project / ".ash").mkdir()
        (project / ".ash" / ".ash.yaml").write_text(
            yaml.safe_dump(document), encoding="utf-8"
        )
        return resolve_config(source_dir=project)
    operator = tmp_path / "etc" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(yaml.safe_dump(document), encoding="utf-8")
    return resolve_config(config_path=operator, source_dir=project)


@pytest.mark.parametrize(
    "tier, kept",
    [
        pytest.param("repository", False, id="a-repository-config-is-replaced"),
        pytest.param("operator", True, id="control-the-operator-config-is-kept"),
    ],
)
@pytest.mark.unit
def test_only_an_operator_config_chooses_honor_ignore_files(
    tmp_path: Path, tier: str, kept: bool
) -> None:
    """trust-model.md (What each tier may set).

    A config that sets ``honor_ignore_files: false`` is resolved for a scan of a
    project that is a checkout. As the project's own config it is replaced by the
    trusted value, the default ``true``. The control is the same document as an
    operator config outside every checkout, which keeps ``false``.
    """
    assert_on_page(TRUST_MODEL, _HONOR_IGNORE_FILES_ROW)
    from automated_security_helper.config.ash_config import AshConfig

    trusted = AshConfig().honor_ignore_files
    assert trusted is True
    resolved = _resolved_from_tier(
        tmp_path, tier, {"project_name": "app", "honor_ignore_files": False}
    )
    assert resolved.honor_ignore_files is (False if kept else trusted), (
        f"{tier}: honor_ignore_files {resolved.honor_ignore_files}"
    )


@pytest.mark.parametrize("option", _ARCHIVE_LIMITS)
@pytest.mark.parametrize(
    "tier, direction, kept",
    [
        pytest.param("repository", "lower", True, id="a-repository-lowers-it"),
        pytest.param("repository", "at", True, id="a-repository-repeats-it"),
        pytest.param("repository", "higher", False, id="a-repository-raises-it"),
        pytest.param("operator", "higher", True, id="control-the-operator-raises-it"),
    ],
)
@pytest.mark.unit
def test_a_repository_config_may_lower_an_archive_limit_but_not_raise_it(
    tmp_path: Path, option: str, tier: str, direction: str, kept: bool
) -> None:
    """trust-model.md (What each tier may set).

    A config sets one archive extraction limit below, at or above the trusted value,
    the default, and is resolved for a scan of a project that is a checkout. As the
    project's own config, a value at or below the default is kept and a higher one is
    replaced by the default. The control is an operator config outside every checkout,
    whose higher value is kept.
    """
    assert_on_page(TRUST_MODEL, _ARCHIVE_LIMITS_ROW)
    from automated_security_helper.config.ash_config import AshConfig

    trusted = getattr(AshConfig().converters.archive.options, option)
    value = {
        "lower": type(trusted)(trusted / 2),
        "at": trusted,
        "higher": type(trusted)(trusted * 2),
    }[direction]
    resolved = _resolved_from_tier(
        tmp_path,
        tier,
        {
            "project_name": "app",
            "converters": {"archive": {"options": {option: value}}},
        },
    )
    found = getattr(resolved.converters.archive.options, option)
    assert found == (value if kept else trusted), (
        f"{tier} {option}={value} (trusted {trusted}): resolved {found}"
    )


_PLUGINS_INDEX = "plugins/index.md"
_PLUGIN_NAMESPACE_SENTENCE = (
    "Every source, yours included, is held to ASH's plugin namespace: a module path "
    "that starts with `automated_security_helper.` or `ash_plugins`, or whose top-level "
    "package ends in `_ash_plugins`. A name outside it, ASH's plugin root itself, a "
    "namespace package, or a name that is not a dotted path of Python identifiers stops "
    "the scan with exit code 3 before anything is scanned, whatever its source, and so "
    "does a module you name that fails to import. A scan uses only the modules it names."
)


def _plugin_modules_dir(tmp_path: Path) -> Path:
    """A directory for ``PYTHONPATH`` holding an empty plugin package in the
    namespace, one that fails to import, and a namespace package (no ``__init__``)."""
    root = tmp_path / "plugin-modules"
    (root / "page_claims_ok_ash_plugins").mkdir(parents=True)
    (root / "page_claims_ok_ash_plugins" / "__init__.py").write_text(
        "", encoding="utf-8"
    )
    (root / "page_claims_broken_ash_plugins").mkdir()
    (root / "page_claims_broken_ash_plugins" / "__init__.py").write_text(
        "raise RuntimeError('page claims: this plugin module fails to import')\n",
        encoding="utf-8",
    )
    (root / "page_claims_ns_ash_plugins" / "inner").mkdir(parents=True)
    return root


@pytest.mark.parametrize(
    "source, name, expected",
    [
        pytest.param("flag", "page_claims_outside", 3, id="outside-the-namespace"),
        pytest.param(
            "flag", "automated_security_helper.plugin_modules", 3, id="the-plugin-root"
        ),
        pytest.param("flag", "page_claims_ns_ash_plugins", 3, id="a-namespace-package"),
        pytest.param("flag", "page-claims_ash_plugins", 3, id="not-a-dotted-path"),
        pytest.param(
            "flag", "page_claims_broken_ash_plugins", 3, id="it-fails-to-import"
        ),
        pytest.param("env", "page_claims_outside", 3, id="from-ASH_PLUGIN_MODULES"),
        pytest.param("config", "page_claims_outside", 3, id="from-an-operator-config"),
        pytest.param("overrides", "page_claims_outside", 3, id="from-config-overrides"),
        pytest.param("flag", "page_claims_ok_ash_plugins", 0, id="control-it-loads"),
    ],
)
@pytest.mark.integration
def test_every_source_of_plugin_modules_is_held_to_the_namespace_rule(
    tmp_path: Path, source: str, name: str, expected: int
) -> None:
    """plugins/index.md (Who may load plugin modules).

    ``ash scan`` of a clean tree with detect-secrets names one plugin module, from
    ``--ash-plugin-modules``, ``ASH_PLUGIN_MODULES``, an operator config outside every
    checkout, or ``--config-overrides``. A module outside the namespace, the plugin root
    itself, a namespace package, a name that is no dotted path of identifiers, and a
    module that fails to import must each stop the scan with exit code 3 before
    anything is scanned: no results file is written. The control is an empty plugin
    package in the namespace, with which the scan runs and exits 0.
    """
    assert_on_page(_PLUGINS_INDEX, _PLUGIN_NAMESPACE_SENTENCE)
    modules = _plugin_modules_dir(tmp_path)
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    args = [*_CONFIG_SCAN, "--offline", "--source-dir", str(source_dir)]
    args += ["--output-dir", str(output)]
    env = {
        "PYTHONPATH": os.pathsep.join(
            p for p in (str(modules), os.environ.get("PYTHONPATH")) if p
        )
    }
    if source == "flag":
        args += ["--ash-plugin-modules", name]
    elif source == "env":
        env["ASH_PLUGIN_MODULES"] = name
    elif source == "overrides":
        args += ["--config-overrides", f"ash_plugin_modules=[{name}]"]
    else:
        operator = tmp_path / "etc" / "ash.yaml"
        operator.parent.mkdir()
        operator.write_text(
            yaml.safe_dump({"project_name": "app", "ash_plugin_modules": [name]}),
            encoding="utf-8",
        )
        args += ["--config", str(operator)]

    result = _ash(args, cwd=tmp_path, **env)
    assert result.returncode == expected, (
        f"{source} {name}: exit {result.returncode}, expected {expected}:\n"
        f"{_output_tail(result)}"
    )
    scanned = (output / "ash_aggregated_results.json").is_file()
    assert scanned is (expected == 0), f"results written: {scanned}"
    if expected == 3:
        assert name in _normalize(result.stdout + result.stderr), _output_tail(result)


#: plugins/index.md (Package a third-party plugin): two plugins of one type with the
#: very same name are refused.
_SAME_NAME_IS_REFUSED = (
    "Two plugins of one type with the very same name, such as a subclass that keeps "
    "its base's config, are refused with exit 3 too, naming both classes and the "
    "modules that define them: a scan and a workspace scan refuse two such scanners, "
    "converters, or reporters, and `ash report` and `ash merge` refuse two such "
    "reporters."
)

#: plugins/index.md (Package a third-party plugin): give a plugin a name of its own.
_PLUGIN_NAME_OF_ITS_OWN = [
    (
        "ASH finds the section by the name with case, punctuation, and the words "
        "Scanner, Reporter, and Converter ignored, so give the plugin a name of its own: "
        "two plugins of one type whose names read as one that way would read each "
        "other's section, and are refused with exit 3, naming both plugins and the "
        "modules that define them: a scan and a workspace scan refuse two such scanners, "
        "converters, or reporters, and `ash report` and `ash merge` refuse two such "
        "reporters."
    ),
    (
        "A reporter named `csv_` is refused this way beside the built-in `csv`, and one "
        "named `S3` when the [AWS reporters](aws.md), among them `s3`, are loaded. `ash "
        "config validate` imports no plugin module, so it does not see this."
    ),
    _SAME_NAME_IS_REFUSED,
    "a different extension under the shared name is not enough.",
]

#: exit-codes.md's rows for two plugins whose names read as one: ash scan, a workspace
#: scan, ash merge, ash report, and ash config validate.
_NAME_CLASH_ROWS = [
    (
        "or two plugins of one type that the scan loads have the same name or names that "
        "read as one ([Package a third-party plugin](../plugins/index.md"
        "#package-a-third-party-plugin)) |"
    ),
    (
        "| 3 | A project's config, or the `--config` file, cannot be used or is invalid, "
        "as for a scan; or two plugins of one type that the scan loads have the same "
        "name or names that read as one, as for a scan. ASH detects this before it scans "
        "anything, also with `--dry-run`. |"
    ),
    (
        "| 3 | Two reporters that the merge loads have the same name or names that read as "
        "one, as for a scan |"
    ),
    (
        "or two reporters that the command loads have the same name or names that read "
        "as one, as for a scan |"
    ),
    "`validate` imports no plugin module, so two plugins whose names read as one pass it.",
]

#: A plugin module with one reporter named NAME, which writes ``page-claims-named``.
_NAMED_REPORTER_MODULE = """\
from typing import Literal

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class _Options(ReporterOptionsBase):
    pass


class NamedConfig(ReporterPluginConfigBase):
    name: Literal[NAME] = NAME
    extension: str = "page-claims-named.txt"
    enabled: bool = True
    options: _Options = _Options()


@ash_reporter_plugin
class NamedReporter(ReporterPluginBase[NamedConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = NamedConfig()
        super().model_post_init(context)

    def report(self, model):
        return "page-claims-named\\n"


ASH_REPORTERS = [NamedReporter]
"""

#: A plugin module with a subclass of the built-in csv reporter that keeps its config.
_CSV_SUBCLASS_MODULE = """\
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CsvReporter,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


@ash_reporter_plugin
class PageClaimsCsvReporter(CsvReporter):
    pass


ASH_REPORTERS = [PageClaimsCsvReporter]
"""

#: The same subclass with a config class of its own that keeps the name ``csv`` and
#: gives it another extension.
_CSV_SUBCLASS_OTHER_EXTENSION_MODULE = """\
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CSVReporterConfig,
    CsvReporter,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class CopyCsvConfig(CSVReporterConfig):
    extension: str = "copy.csv"


@ash_reporter_plugin
class PageClaimsCsvReporter(CsvReporter):
    config: CopyCsvConfig | None = None

    def model_post_init(self, context):
        if self.config is None:
            self.config = CopyCsvConfig()
        return super().model_post_init(context)


ASH_REPORTERS = [PageClaimsCsvReporter]
"""

_NAMES_MODULE = "page_claims_names_ash_plugins"
_CSV_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter"
)
_S3_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter"


@pytest.mark.parametrize(
    "command", ["scan", "workspace", "report", "merge", "validate-passes-it"]
)
@pytest.mark.parametrize(
    "plugin",
    [
        "csv_",
        "S3",
        "a-subclass-of-csv",
        "a-subclass-of-csv-with-another-extension",
        "control-a-name-of-its-own",
    ],
)
@pytest.mark.integration
def test_two_plugins_whose_names_read_as_one_are_refused_by_each_command(
    tmp_path: Path, command: str, plugin: str
) -> None:
    """plugins/index.md (Package a third-party plugin), and exit-codes.md (ash scan,
    Workspace mode, ash merge, ash report, ash config).

    A plugin module, loaded with ``--config-overrides``, adds a reporter named ``csv_``
    beside the built-in ``csv``, or one named ``S3`` with the AWS reporters loaded too.
    A scan, a workspace scan, ``ash report`` over a one-shard scan and ``ash merge`` of
    it must each exit 3 naming both reporters and their modules, and ``ash config
    validate`` of a config that loads the module must pass. ``ash report`` and ``ash
    merge`` run from an empty directory outside the trees, since they take the
    working directory as the scanned tree.

    A subclass of the csv reporter that keeps its config, or whose own config class
    gives the shared name another extension, has the very same name as the built-in:
    every command but ``ash config validate`` must exit 3 naming both classes and their
    modules, and not as names that read as one. The control is a reporter with a name
    of its own: every command exits 0, and its report is written, which shows the
    module was loaded.
    """
    for sentence in _PLUGIN_NAME_OF_ITS_OWN:
        assert_on_page(_PLUGINS_INDEX, sentence)
    for row in _NAME_CLASH_ROWS:
        assert_on_page(EXIT_CODES, row)
    if plugin == "a-subclass-of-csv":
        text = _CSV_SUBCLASS_MODULE
    elif plugin == "a-subclass-of-csv-with-another-extension":
        text = _CSV_SUBCLASS_OTHER_EXTENSION_MODULE
    else:
        own = "page-claims-own" if plugin == "control-a-name-of-its-own" else plugin
        text = _NAMED_REPORTER_MODULE.replace("NAME", repr(own))
    python_path = _plugin_path(tmp_path, _NAMES_MODULE, text)
    modules = [_AWS_PLUGIN_MODULE, _NAMES_MODULE] if plugin == "S3" else [_NAMES_MODULE]
    load = ["--config-overrides", f"ash_plugin_modules+=[{','.join(modules)}]"]
    work = tmp_path / "work"
    work.mkdir()
    named_report = None

    if command == "scan":
        tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
        output = tmp_path / "out"
        args = [*_CONFIG_SCAN, "--offline", "--source-dir", str(tree)]
        args += ["--output-dir", str(output), *load]
        named_report = output / "reports" / "ash.page-claims-named.txt"
    elif command == "workspace":
        project = tmp_path / "ws" / "api"
        project.mkdir(parents=True)
        (project / "main.py").write_text("x = 1\n", encoding="utf-8")
        workspace = tmp_path / "ws" / "services.code-workspace"
        workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), "utf-8")
        args = [*_CONFIG_SCAN, "--offline", "--workspace", str(workspace)]
        args += ["--output-dir", str(tmp_path / "ws-output"), *load]
    elif command == "report":
        output = _stored_scan(tmp_path)
        report_format = "page-claims-own" if plugin.endswith("own") else "sarif"
        args = ["report", "--format", report_format, "--output-dir", str(output)]
        args += load
    elif command == "merge":
        shard = _stored_scan(tmp_path)
        merged = tmp_path / "merged"
        args = ["merge", "--results", str(shard / "ash_aggregated_results.json")]
        args += ["--output-dir", str(merged), *load]
        named_report = merged / "reports" / "ash.page-claims-named.txt"
    else:
        config = tmp_path / "etc" / "ash.yaml"
        config.parent.mkdir()
        config.write_text(
            yaml.safe_dump({"project_name": "names", "ash_plugin_modules": modules}),
            encoding="utf-8",
        )
        args = ["config", "validate", "--config", str(config)]

    result = _ash(args, cwd=work, PYTHONPATH=python_path)
    text = _squeezed(result.stdout + result.stderr)

    if command == "validate-passes-it":
        assert result.returncode == 0, _output_tail(result)
        return
    if plugin in ("csv_", "S3"):
        builtin, module = (
            ("csv", _CSV_MODULE) if plugin == "csv_" else ("s3", _S3_MODULE)
        )
        assert result.returncode == 3, _output_tail(result)
        assert _squeezed(f"'{builtin}' ({module})") in text, _output_tail(result)
        assert _squeezed(f"'{plugin}' ({_NAMES_MODULE})") in text, _output_tail(result)
        return
    assert "readsasthesameplugin" not in text, _output_tail(result)
    if plugin.startswith("a-subclass-of-csv"):
        assert result.returncode == 3, _output_tail(result)
        builtin = _squeezed(f"'csv' (class CsvReporter in {_CSV_MODULE})")
        subclass = _squeezed(f"'csv' (class PageClaimsCsvReporter in {_NAMES_MODULE})")
        assert builtin in text, _output_tail(result)
        assert subclass in text, _output_tail(result)
        return
    assert result.returncode == 0, _output_tail(result)
    if command == "report":
        assert "page-claims-named" in result.stdout, _output_tail(result)
    elif named_report is not None:
        assert named_report.is_file(), _output_tail(result)


#: scale-large-repos.md (Workspace scans over MCP): the resolve tool's bullet.
_RESOLVE_DOES_NOT_CHECK_NAMES = (
    "- [`resolve_ash_workspace`](../reference/mcp-tools.md#resolve_ash_workspace) returns "
    "the plan, like `--dry-run`, except that it does not check plugin names: it runs in "
    "the server and scans nothing, so it imports no project's plugin module, and its "
    "response says `plugin_names_checked` false. `run_ash_workspace_scan` refuses two "
    "plugins whose names read as one before it scans anything, as `--dry-run` does."
)


#: Runs the resolve and scan MCP tools in a process of their own and prints what
#: they answered, plus whether argv[3]'s module was imported after the resolve
#: half; the scan half imports it on purpose, so nothing is recorded after it.
_RESOLVE_THEN_SCAN_WORKSPACE = """\
import asyncio
import json
import sys

from automated_security_helper.cli.mcp.workspace import (
    mcp_resolve_workspace,
    mcp_scan_workspace,
)

workspace, output, names_module = sys.argv[1], sys.argv[2], sys.argv[3]
answer = {}
answer["resolve"] = asyncio.run(mcp_resolve_workspace(workspace_file=workspace))
answer["resolve_imported"] = names_module in sys.modules
answer["scan"] = asyncio.run(
    mcp_scan_workspace(workspace_file=workspace, output_dir=output, offline=True)
)
print(json.dumps(answer, default=str))
"""


@pytest.mark.integration
def test_resolve_ash_workspace_does_not_check_plugin_names(tmp_path: Path) -> None:
    """scale-large-repos.md (Workspace scans over MCP).

    A one-project workspace whose project config loads a plugin module with a reporter
    named ``csv_``, beside the built-in ``csv``: ``ash scan --workspace --dry-run``
    exits 3 naming both reporters and their modules, while ``resolve_ash_workspace``
    succeeds, says ``plugin_names_checked`` false, and leaves the module unimported,
    judged inside the child process that ran it. The resolve response's plan must
    carry the project, read from the config file that names the module: without
    that, dropping the project would pass the same checks. The sentence's last
    claim is probed too: the workspace scan tool refuses the clash, naming both
    reporters, and writes nothing into its output directory.
    """
    assert_on_page(SCALE_LARGE_REPOS, _RESOLVE_DOES_NOT_CHECK_NAMES)
    module_text = _NAMED_REPORTER_MODULE.replace("NAME", repr("csv_"))
    python_path = _plugin_path(tmp_path, _NAMES_MODULE, module_text)
    project = tmp_path / "ws" / "api"
    (project / ".ash").mkdir(parents=True)
    (project / "main.py").write_text("x = 1\n", encoding="utf-8")
    (project / ".ash" / "ash.yaml").write_text(
        yaml.safe_dump({"project_name": "api", "ash_plugin_modules": [_NAMES_MODULE]}),
        encoding="utf-8",
    )
    workspace = tmp_path / "ws" / "services.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), "utf-8")
    work = tmp_path / "work"
    work.mkdir()

    dry_run = _ash(
        [*_CONFIG_SCAN, "--offline", "--workspace", str(workspace), "--dry-run"],
        cwd=work,
        PYTHONPATH=python_path,
    )
    text = _squeezed(dry_run.stdout + dry_run.stderr)
    assert dry_run.returncode == 3, _output_tail(dry_run)
    assert _squeezed(f"'csv' ({_CSV_MODULE})") in text, _output_tail(dry_run)
    assert _squeezed(f"'csv_' ({_NAMES_MODULE})") in text, _output_tail(dry_run)

    # Both MCP halves run in a child, as _ash runs scans. Running them in this
    # process is not cleanable: the decorator writes into process-wide plugin
    # registries, and resolution memos exist that never invalidate, so a restore
    # of the registration dicts either leaves a cached csv_ class behind or
    # passes vacuously when an earlier test already filled the memo. The child
    # takes the clash with it when it exits.
    output = tmp_path / "mcp-out"
    environment = _ash_environment(work, PYTHONPATH=python_path)
    for name in (
        "ASH_MCP_ALLOWED_ROOTS",
        "ASH_MCP_WORKSPACE_ROOT",
        "ASH_CONFIG",
        "ASH_PLUGIN_MODULES",
    ):
        environment.pop(name, None)
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            _RESOLVE_THEN_SCAN_WORKSPACE,
            str(workspace),
            str(output),
            _NAMES_MODULE,
        ],
        cwd=work,
        env=environment,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert child.returncode == 0, _output_tail(child)
    answer = json.loads(child.stdout.strip().splitlines()[-1])

    response = answer["resolve"]
    assert response.get("success") is True, response.get("error")
    assert response.get("plugin_names_checked") is False, response
    # "Leaves the module unimported": judged inside the child, right after the
    # resolve returned and before the scan half imported anything on purpose.
    assert answer["resolve_imported"] is False, answer
    # The positive control: the plan carries the project, read from the very
    # config file that names the plugin module. Without this, a resolve that
    # dropped the project or never read its config would pass the asserts above.
    projects = response.get("projects") or []
    assert [entry.get("project") for entry in projects] == ["api"], response
    config_source = str(projects[0].get("config_source") or "")
    assert config_source.replace("\\", "/").endswith("api/.ash/ash.yaml"), projects

    # The sentence's last claim: the scan tool refuses the clash before it
    # scans anything, naming both reporters and their modules.
    scan = answer["scan"]
    assert scan.get("success") is False, scan
    assert scan.get("exit_code") == 3, scan
    refusal = _squeezed(json.dumps(scan, default=str))
    assert _squeezed(f"'csv' ({_CSV_MODULE})") in refusal, scan
    assert _squeezed(f"'csv_' ({_NAMES_MODULE})") in refusal, scan
    # "Before it scans anything": no scan wrote results. The output tree's
    # directories may exist, since a build makes them before resolution.
    results = (
        list(output.rglob("ash_aggregated_results.json")) if output.exists() else []
    )
    assert not results, results


#: A plugin module with a scanner whose name reads as the built-in detect-secrets'.
_SCANNER_NAMED_AS_ONE_MODULE = """\
from typing import Literal

from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin


class AsOneScannerConfig(DetectSecretsScannerConfig):
    name: Literal["Detect_Secrets"] = "Detect_Secrets"


@ash_scanner_plugin
class PageClaimsAsOneScanner(DetectSecretsScanner):
    config: AsOneScannerConfig | None = None

    def model_post_init(self, context):
        if self.config is None:
            self.config = AsOneScannerConfig()
        return super().model_post_init(context)
"""

#: A plugin module with a converter whose name reads as the built-in archive converter's.
_CONVERTER_NAMED_AS_ONE_MODULE = """\
from typing import Literal

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
)
from automated_security_helper.plugins.decorators import ash_converter_plugin


class AsOneConverterConfig(ArchiveConverterConfig):
    name: Literal["Archive_"] = "Archive_"


@ash_converter_plugin
class PageClaimsAsOneConverter(ArchiveConverter):
    config: AsOneConverterConfig | None = None

    def model_post_init(self, context):
        if self.config is None:
            self.config = AsOneConverterConfig()
        return super().model_post_init(context)
"""


@pytest.mark.parametrize("command", ["scan", "report", "merge"])
@pytest.mark.parametrize("kind", ["scanner", "converter"])
@pytest.mark.integration
def test_two_scanners_or_converters_whose_names_read_as_one_are_refused_by_a_scan(
    tmp_path: Path, kind: str, command: str
) -> None:
    """plugins/index.md (Package a third-party plugin).

    A plugin module adds a scanner named ``Detect_Secrets`` beside the built-in
    ``detect-secrets``, or a converter named ``Archive_`` beside ``archive``. A scan
    must exit 3 naming both plugins and their modules. ``ash report`` over a one-shard
    scan, and ``ash merge`` of it, run reporters only: each must import the module and
    exit 0, with no such refusal.
    """
    assert_on_page(_PLUGINS_INDEX, _PLUGIN_NAME_OF_ITS_OWN[0])
    if kind == "scanner":
        text = _SCANNER_NAMED_AS_ONE_MODULE
        builtin = "'detect-secrets' (automated_security_helper.plugin_modules."
        builtin += "ash_builtin.scanners.detect_secrets_scanner)"
        named = f"'Detect_Secrets' ({_NAMES_MODULE})"
    else:
        text = _CONVERTER_NAMED_AS_ONE_MODULE
        builtin = "'archive' (automated_security_helper.plugin_modules."
        builtin += "ash_builtin.converters.archive_converter)"
        named = f"'Archive_' ({_NAMES_MODULE})"
    python_path = _plugin_path(tmp_path, _NAMES_MODULE, text)
    load = ["--config-overrides", f"ash_plugin_modules+=[{_NAMES_MODULE}]"]
    work = tmp_path / "work"
    work.mkdir()

    if command == "scan":
        tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
        args = [*_CONFIG_SCAN, "--offline", "--source-dir", str(tree)]
        args += ["--output-dir", str(tmp_path / "out"), *load]
    elif command == "report":
        output = _stored_scan(tmp_path)
        args = ["report", "--format", "sarif", "--output-dir", str(output), *load]
    else:
        shard = _stored_scan(tmp_path)
        args = ["merge", "--results", str(shard / "ash_aggregated_results.json")]
        args += ["--output-dir", str(tmp_path / "merged"), *load]

    result = _ash(args, cwd=work, PYTHONPATH=python_path)
    shown = _squeezed(result.stdout + result.stderr)

    if command == "scan":
        assert result.returncode == 3, _output_tail(result)
        assert _squeezed(builtin) in shown, _output_tail(result)
        assert _squeezed(named) in shown, _output_tail(result)
        return
    assert result.returncode == 0, _output_tail(result)
    assert "readsasthesameplugin" not in shown, _output_tail(result)
    imported = _squeezed(f"Importing additional plugin module: {_NAMES_MODULE}")
    assert imported in shown, _output_tail(result)


#: A plugin module with a subclass of the detect-secrets scanner that keeps its config.
_DETECT_SECRETS_SUBCLASS_MODULE = """\
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin


@ash_scanner_plugin
class PageClaimsDetectSecretsScanner(DetectSecretsScanner):
    pass


ASH_SCANNERS = [PageClaimsDetectSecretsScanner]
"""


@pytest.mark.integration
def test_a_scanner_subclass_of_the_same_name_is_refused_before_it_runs(
    tmp_path: Path,
) -> None:
    """plugins/index.md (Package a third-party plugin).

    A plugin module adds a subclass of the detect-secrets scanner that keeps its
    config, and a scan asks for detect-secrets. The two scanners have the very same
    name, so the scan must exit 3 naming both classes and their modules, before
    either runs: ash.log holds no detect-secrets failure and no results file is
    written.
    """
    assert_on_page(_PLUGINS_INDEX, _SAME_NAME_IS_REFUSED)
    python_path = _plugin_path(tmp_path, _NAMES_MODULE, _DETECT_SECRETS_SUBCLASS_MODULE)
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    output = tmp_path / "out"
    work = tmp_path / "work"
    work.mkdir()
    args = [*_CONFIG_SCAN, "--offline", "--source-dir", str(tree)]
    args += ["--output-dir", str(output)]
    args += ["--config-overrides", f"ash_plugin_modules+=[{_NAMES_MODULE}]"]

    result = _ash(args, cwd=work, PYTHONPATH=python_path)

    text = _squeezed(result.stdout + result.stderr)
    builtin = _squeezed(
        "'detect-secrets' (class DetectSecretsScanner in "
        "automated_security_helper.plugin_modules.ash_builtin.scanners."
        "detect_secrets_scanner)"
    )
    subclass = _squeezed(
        f"'detect-secrets' (class PageClaimsDetectSecretsScanner in {_NAMES_MODULE})"
    )
    assert result.returncode == 3, _output_tail(result)
    assert builtin in text, _output_tail(result)
    assert subclass in text, _output_tail(result)
    log = output / "ash.log"
    if log.is_file():
        failed = "Failed to execute detect-secrets scanner"
        assert failed not in log.read_text(encoding="utf-8"), _output_tail(result)
    assert not (output / "ash_aggregated_results.json").exists(), _output_tail(result)


#: plugins/index.md (Package a third-party plugin): how a subclass runs beside its
#: base, and the example that does it.
_SUBCLASS_BESIDE_ITS_BASE = [
    "One class selected twice is one plugin.",
    (
        "To run a subclass beside its base, give it a config class of its own with its "
        "own `name`, declare it as the subclass's `config` field, and build it in "
        "`model_post_init` when no config is given."
    ),
    (
        "A reporter subclass also needs its own `extension`; a different extension "
        "under the shared name is not enough."
    ),
    (
        "Two reporters with names of their own that write one report file are refused "
        "with exit 1 by a scan, a workspace scan, and `ash merge`, and without the "
        "`model_post_init` the subclass starts from its base's config and writes its "
        "base's file."
    ),
    "This reporter runs beside the built-in `csv` and writes `ash.copy.csv`:",
]

#: A plugin module that selects the built-in csv reporter's class again: it registers
#: the class with the decorator and lists it.
_CSV_SELECTED_AGAIN_MODULE = """\
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CsvReporter,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin

ash_reporter_plugin(CsvReporter)

ASH_REPORTERS = [CsvReporter]
"""


def _page_copy_csv_module() -> str:
    """The plugin module plugins/index.md shows after "writes `ash.copy.csv`:", as
    it is written there."""
    after = _page_text(_PLUGINS_INDEX).split("writes `ash.copy.csv`:", 1)[1]
    block = re.search(r"```python\n(.*?)```", after, re.DOTALL)
    assert block, "plugins/index.md shows no python block after its csv-copy sentence"
    return textwrap.dedent(block.group(1))


@pytest.mark.parametrize(
    "plugin, command",
    [
        *(
            ("the-page-s-reporter", command)
            for command in ("scan", "workspace", "report", "merge")
        ),
        *(
            (plugin, command)
            for plugin in ("its-name-with-csv-s-extension", "without-model-post-init")
            for command in ("scan", "workspace", "merge")
        ),
        *(
            ("control-the-built-in-class-selected-again", command)
            for command in ("scan", "workspace", "report", "merge")
        ),
    ],
)
@pytest.mark.integration
def test_a_reporter_subclass_runs_beside_its_base_as_the_page_shows(
    tmp_path: Path, plugin: str, command: str
) -> None:
    """plugins/index.md (Package a third-party plugin).

    The page's example module, loaded with ``--config-overrides``: a scan, a workspace
    scan and ``ash merge`` exit 0 and write both ``ash.csv`` and ``ash.copy.csv``, and
    ``ash report --format csv-copy`` exits 0 with a report. The same module without
    its own ``extension`` line, and without its ``model_post_init``, writes the
    built-in's file under its own name and under the built-in's: a scan, a workspace
    scan and ``ash merge`` exit 1 saying the csv reporter and that one would both
    write ``ash.csv``. The control is a module that registers and lists the built-in
    ``CsvReporter`` class again: one class selected twice is one plugin, so every
    command exits 0 and ``ash.csv`` is written.
    """
    for sentence in _SUBCLASS_BESIDE_ITS_BASE:
        assert_on_page(_PLUGINS_INDEX, sentence)
    page_module = _page_copy_csv_module()
    report_format, other = "csv-copy", None
    if plugin == "the-page-s-reporter":
        text = page_module
    elif plugin == "its-name-with-csv-s-extension":
        text = page_module.replace('    extension: str = "copy.csv"\n', "")
        assert text != page_module, page_module
        other = "csv-copy"
    elif plugin == "without-model-post-init":
        text = page_module.split("\n    def model_post_init", 1)[0] + "\n"
        assert text != page_module + "\n", page_module
        other = "csv"
    else:
        text, report_format = _CSV_SELECTED_AGAIN_MODULE, "csv"
    python_path = _plugin_path(tmp_path, _NAMES_MODULE, text)
    load = ["--config-overrides", f"ash_plugin_modules+=[{_NAMES_MODULE}]"]
    work = tmp_path / "work"
    work.mkdir()
    reports = None

    if command == "scan":
        tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
        output = tmp_path / "out"
        args = [*_CONFIG_SCAN, "--offline", "--source-dir", str(tree)]
        args += ["--output-dir", str(output), *load]
        reports = output / "reports"
    elif command == "workspace":
        project = tmp_path / "ws" / "api"
        project.mkdir(parents=True)
        (project / "main.py").write_text("x = 1\n", encoding="utf-8")
        workspace = tmp_path / "ws" / "services.code-workspace"
        workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), "utf-8")
        args = [*_CONFIG_SCAN, "--offline", "--workspace", str(workspace)]
        args += ["--output-dir", str(tmp_path / "ws-output"), *load]
        reports = tmp_path / "ws-output" / "reports"
    elif command == "report":
        output = _stored_scan(tmp_path)
        args = ["report", "--format", report_format, "--output-dir", str(output)]
        args += load
    else:
        shard = _stored_scan(tmp_path)
        merged = tmp_path / "merged"
        args = ["merge", "--results", str(shard / "ash_aggregated_results.json")]
        args += ["--output-dir", str(merged), *load]
        reports = merged / "reports"

    result = _ash(args, cwd=work, PYTHONPATH=python_path)
    text = _squeezed(result.stdout + result.stderr)

    if other is not None:
        both = f"The csv reporter and the {other} reporter would both write 'ash.csv'"
        assert result.returncode == 1, _output_tail(result)
        assert _squeezed(both) in text, _output_tail(result)
        return
    assert result.returncode == 0, _output_tail(result)
    if reports is None:
        assert result.stdout.strip(), _output_tail(result)
        return
    page = plugin == "the-page-s-reporter"
    assert (reports / "ash.csv").is_file(), _output_tail(result)
    assert (reports / "ash.copy.csv").is_file() is page, _output_tail(result)


#: An ASH plugin package whose scanner adds a line to the file PAGE_CLAIMS_MARKER
#: names each time it runs.
_COUNTED_PLUGIN = """\
import os
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin


class CountedScannerOptions(ScannerOptionsBase):
    pass


class CountedScannerConfig(ScannerPluginConfigBase):
    name: Literal["page-claims-counted"] = "page-claims-counted"
    enabled: bool = True
    options: Annotated[CountedScannerOptions, Field()] = CountedScannerOptions()


@ash_scanner_plugin
class CountedScanner(ScannerPluginBase[CountedScannerConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = CountedScannerConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError

    def scan(self, target, target_type, config: Any = None, *args, **kwargs):
        self._pre_scan(target, target_type, config)
        if target_type == "source":
            with open(os.environ["PAGE_CLAIMS_MARKER"], "a", encoding="utf-8") as f:
                f.write("ran\\n")
        self._post_scan(target, target_type)
        return {"findings": []}


ASH_SCANNERS = [CountedScanner]
"""

#: Two scans in one process through the Python API, the first naming the counted
#: plugin package and the second naming it or not; prints how often its scanner ran.
_TWO_SCANS = """\
import sys
from pathlib import Path

from automated_security_helper.interactions.run_ash_scan import run_ash_scan

source, output, marker, second_names_it = sys.argv[1:5]
for index, names in enumerate(
    (["page_claims_counted_ash_plugins"],
     ["page_claims_counted_ash_plugins"] if second_names_it == "yes" else [])
):
    try:
        run_ash_scan(
            source_dir=source,
            output_dir=str(Path(output) / str(index)),
            scanners=["detect-secrets", "page-claims-counted"],
            ash_plugin_modules=names,
            offline=True,
            progress=False,
            show_summary=False,
            quiet=True,
        )
    except SystemExit:
        pass
text = Path(marker).read_text("utf-8") if Path(marker).exists() else ""
print("runs:", text.count("ran"))
"""


@pytest.mark.parametrize(
    "second_names_it, runs",
    [
        pytest.param(False, 1, id="a-later-scan-that-does-not-name-it"),
        pytest.param(True, 2, id="control-a-later-scan-that-names-it"),
    ],
)
@pytest.mark.integration
def test_a_scan_uses_only_the_plugin_modules_it_names(
    tmp_path: Path, second_names_it: bool, runs: int
) -> None:
    """plugins/index.md (Who may load plugin modules).

    Two scans run in one process through the Python API, both selecting detect-secrets
    and a plugin scanner. The first names the plugin's package, which registers the
    scanner for the rest of the process. A second scan that does not name the package
    must not run that scanner, so it runs once in all. The control is a second scan
    that names it too, after which it has run twice.
    """
    assert_on_page(_PLUGINS_INDEX, _PLUGIN_NAMESPACE_SENTENCE)
    package = tmp_path / "plugin-modules" / "page_claims_counted_ash_plugins"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(_COUNTED_PLUGIN, encoding="utf-8")
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("x = 1\n", encoding="utf-8")
    marker = tmp_path / "counted.txt"
    env = _ash_environment(
        tmp_path,
        PAGE_CLAIMS_MARKER=str(marker),
        PYTHONPATH=os.pathsep.join(
            p for p in (str(package.parent), os.environ.get("PYTHONPATH")) if p
        ),
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            _TWO_SCANS,
            str(source_dir),
            str(tmp_path / "output"),
            str(marker),
            "yes" if second_names_it else "no",
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert f"runs: {runs}" in result.stdout, _output_tail(result)


# --------------------------------------------------------------------------- #
# Client-supplied suppressions in the results
# --------------------------------------------------------------------------- #

#: A delivered config with one of each kind of entry the client mark applies to.
_CLIENT_ENTRIES: Dict[str, Any] = {
    "project_name": "delivered",
    "global_settings": {
        "suppressions": [
            {"rule_id": "B602", "path": "app.py", "reason": "a delivered suppression"}
        ],
        "ignore_paths": [
            {"path": "vendor/lib.py", "reason": "a delivered ignore path"}
        ],
    },
    "scanners": {
        "bandit": {
            "options": {
                "excluded_paths": [{"path": "tests", "reason": "a delivered exclusion"}]
            }
        }
    },
}


def _bandit_finding(rule_id: str, uri: str) -> Dict[str, Any]:
    return {
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": f"{rule_id} in {uri}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1, "endLine": 1},
                }
            }
        ],
        "properties": {"scanner_name": "bandit"},
    }


def _suppressed_results(tree: Path):
    """bandit's findings in ``tree``, with the suppressions of ``tree``'s config applied.

    One finding per entry of ``_CLIENT_ENTRIES``: B602 in app.py for the suppression,
    B101 in vendor/lib.py for the ignore path, and B105 under tests/ for bandit's
    ``excluded_paths``. Returns the SARIF report and its plugin context.
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

    report = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "bandit"}},
                    "results": [
                        _bandit_finding("B602", "app.py"),
                        _bandit_finding("B101", "vendor/lib.py"),
                        _bandit_finding("B105", "tests/test_app.py"),
                    ],
                }
            ],
        }
    )
    context = PluginContext(
        source_dir=tree,
        output_dir=tree / ".ash" / "ash_output",
        config=resolve_config(source_dir=tree),
    )
    return apply_suppressions_to_sarif(report, context), context


def _client_supplied(suppression: Any) -> bool:
    properties = suppression.properties.model_dump() if suppression.properties else {}
    return properties.get("clientSupplied") is True


@pytest.mark.unit
def test_a_client_supplied_entry_is_marked_in_the_sarif_justification_and_kind(
    tmp_path: Path, mcp_workspace_root: Path
) -> None:
    """trust-model.md (Client-supplied suppressions and ignore paths).

    The entries come from a delivered tree's config, resolved as a scan resolves it, so
    the mark is ASH's own. The same config in a tree outside the MCP workspace root is
    the control: its entries are the repository's, unmarked, and its ignore path drops
    the finding.
    """
    assert_on_page(
        TRUST_MODEL,
        "the SARIF, where the suppression's justification starts with "
        "`(ASH, client-supplied config)` and, for a scanner exclusion, names the entry it "
        "came from, such as `scanners.bandit.options.excluded_paths entry 'tests'`, and its "
        "properties carry `clientSupplied: true`. A suppression entry has `kind: inSource`; "
        "an ignore path or scanner exclusion has `kind: external`;",
    )

    report, _ = _suppressed_results(
        _tree_with_config(mcp_workspace_root, _CLIENT_ENTRIES)
    )
    results = {result.ruleId: result for result in report.runs[0].results}
    expected = {
        "B602": ("inSource", "rule 'B602' in 'app.py'"),
        "B101": ("external", "ignore path 'vendor/lib.py'"),
        "B105": ("external", "scanners.bandit.options.excluded_paths entry 'tests'"),
    }
    for rule_id, (kind, names) in expected.items():
        assert rule_id in results, f"{rule_id} is missing from the results"
        [suppression] = results[rule_id].suppressions or [None]
        assert suppression is not None, f"{rule_id} is not suppressed"
        assert suppression.justification.startswith(CLIENT_MARK), (
            suppression.justification
        )
        assert names in suppression.justification, suppression.justification
        assert suppression.kind.value == kind, (rule_id, suppression.kind)
        assert _client_supplied(suppression), rule_id

    report, _ = _suppressed_results(
        _tree_with_config(tmp_path / "repository", _CLIENT_ENTRIES)
    )
    results = {result.ruleId: result for result in report.runs[0].results}
    assert "B101" not in results
    marked = [
        rule_id
        for rule_id, result in results.items()
        for suppression in result.suppressions or []
        if suppression.justification.startswith(CLIENT_MARK)
        or _client_supplied(suppression)
    ]
    assert not marked, f"a repository's own entries are marked as a client's: {marked}"


def _one(items: Iterable[Any], what: str) -> Any:
    found = list(items)
    assert len(found) == 1, f"expected one {what}, found {len(found)}"
    return found[0]


def _csv_justification(text: str) -> str:
    rows = csv.DictReader(io.StringIO(text))
    row = _one((r for r in rows if r["rule_id"] == "B602"), "CSV row for B602")
    return row["suppression_justification"]


def _flat_json_justification(text: str) -> str:
    findings = json.loads(text)["findings"]
    finding = _one((f for f in findings if f["rule_id"] == "B602"), "flat JSON finding")
    return finding["suppression_justification"]


def _junit_justification(text: str) -> str:
    from junitparser import JUnitXml, Skipped

    cases = [case for suite in JUnitXml.fromstring(text) for case in suite]
    case = _one((c for c in cases if c.classname == "B602"), "JUnit test case for B602")
    skipped = _one((r for r in case.result if isinstance(r, Skipped)), "<skipped>")
    return skipped.message


def _ocsf_justification(text: str) -> str:
    finding = _one(
        (f for f in json.loads(text) if "B602" in f["finding_info"]["title"]),
        "OCSF finding for B602",
    )
    return finding["status_detail"]


def _gitlab_vulnerability(text: str) -> List[Dict[str, Any]]:
    return [
        v
        for v in json.loads(text)["vulnerabilities"]
        if any(i.get("value") == "B602" for i in v.get("identifiers", []))
    ]


def _gitlab_justification(text: str) -> str:
    vulnerability = _one(_gitlab_vulnerability(text), "GitLab SAST vulnerability")
    assert vulnerability["severity"] == "Info", vulnerability["severity"]
    return vulnerability["solution"]


_REPORTERS = "automated_security_helper.plugin_modules.ash_builtin.reporters"


@pytest.mark.parametrize(
    "module, reporter, justification_in",
    [
        pytest.param("csv_reporter", "CsvReporter", _csv_justification, id="csv"),
        pytest.param(
            "flatjson_reporter",
            "FlatJSONReporter",
            _flat_json_justification,
            id="flat-json",
        ),
        pytest.param("html_reporter", "HtmlReporter", lambda text: text, id="html"),
        pytest.param(
            "junitxml_reporter", "JunitXmlReporter", _junit_justification, id="junit"
        ),
        pytest.param("ocsf_reporter", "OcsfReporter", _ocsf_justification, id="ocsf"),
        pytest.param(
            "gitlab_sast_reporter",
            "GitLabSASTReporter",
            _gitlab_justification,
            id="gitlab-sast",
        ),
    ],
)
@pytest.mark.unit
def test_the_reports_that_show_justifications_carry_the_client_mark(
    mcp_workspace_root: Path,
    module: str,
    reporter: str,
    justification_in: Callable[[str], str],
) -> None:
    """trust-model.md (Client-supplied suppressions and ignore paths).

    One delivered suppression, applied as a scan applies it, rendered by each reporter
    the sentence names. For JUnit the mark is in the ``<skipped>`` element; GitLab SAST
    keeps the finding at Info, and leaves it out when ``exclude_suppressed`` is set.
    """
    assert_on_page(
        TRUST_MODEL,
        "the reports that show suppression justifications: CSV and flat JSON, HTML, JUnit "
        "(`<skipped>`), OCSF, and GitLab SAST (which keeps suppressed findings at severity "
        "Info unless `exclude_suppressed` is set).",
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    report, context = _suppressed_results(
        _tree_with_config(mcp_workspace_root, _CLIENT_ENTRIES)
    )
    model = AshAggregatedResults()
    model.sarif = report
    reporter_class = getattr(
        importlib.import_module(f"{_REPORTERS}.{module}"), reporter
    )

    shown = justification_in(reporter_class(context=context).report(model))
    assert shown and CLIENT_MARK in shown, (
        f"{reporter} does not show the client mark: {str(shown)[:300]!r}"
    )

    if reporter == "GitLabSASTReporter":
        from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
            GitLabSASTReporterConfig,
            GitLabSASTReporterConfigOptions,
        )

        excluding = reporter_class(
            context=context,
            config=GitLabSASTReporterConfig(
                options=GitLabSASTReporterConfigOptions(exclude_suppressed=True)
            ),
        )
        assert _gitlab_vulnerability(excluding.report(model)) == []


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #

#: A fake container runtime. It records the command it was given, then writes the
#: results an inner scan would have written into the directory mounted at /out. When
#: the host hands the inner run an ID (``-e ASH_OUTER_RUN_ID``, with the value on the
#: command line through ``OCI_RUNNER_WRAPPER`` and in the environment otherwise), the
#: results record that the run with that ID completed, as the inner ASH records it.
_FAKE_RUNTIME = """\
import json, os, shutil, sys
from pathlib import Path

argv = sys.argv[1:]
Path({record!r}).write_text(json.dumps(argv), encoding="utf-8")
mounts = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--mount"]
out = next(
    dict(part.split("=", 1) for part in mount.split(",") if "=" in part)["source"]
    for mount in mounts
    if "destination=/out" in mount.split(",")
)
shutil.copytree({staged!r}, out, dirs_exist_ok=True)
named = [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == "-e"]
run_id = next(
    (
        value.split("=", 1)[1] if "=" in value else os.environ.get(value)
        for value in named
        if value.split("=", 1)[0] == "ASH_OUTER_RUN_ID"
    ),
    None,
)
if run_id:
    results = Path(out) / "ash_aggregated_results.json"
    data = json.loads(results.read_text(encoding="utf-8"))
    data["validation_checkpoints"] = [
        {{
            "type": "run_completed",
            "severity": "info",
            "message": "The run completed.",
            "metadata": {{"run_id": run_id}},
        }}
    ]
    results.write_text(json.dumps(data), encoding="utf-8")
"""


def _container_scan(
    tmp_path: Path, results: List[Dict[str, Any]], *args: str
) -> Tuple[subprocess.CompletedProcess, List[str] | None]:
    """``ash scan --mode container`` with ``args``, against the fake runtime.

    The runtime writes a results file holding ``results`` as bandit's, the way the
    inner scan would, so the host computes the verdict from them. Returns the CLI's
    result and the command the runtime was given, or None when the runtime never ran.
    ``--no-fail-on-incomplete-scanners`` because the staged results carry no scanner
    rows. The CLI wraps long log lines, so callers match output with ``_normalize``.
    """
    sarif = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "bandit"}}, "results": results}],
    }
    staged = tmp_path / "inner-results"
    (staged / "reports").mkdir(parents=True)
    (staged / "reports" / "ash.sarif").write_text(json.dumps(sarif), encoding="utf-8")
    (staged / "ash_aggregated_results.json").write_text(
        json.dumps({"sarif": sarif}), encoding="utf-8"
    )
    record = tmp_path / "inner-command.json"
    runtime = tmp_path / "fake_runtime.py"
    runtime.write_text(
        _FAKE_RUNTIME.format(record=str(record), staged=str(staged)), encoding="utf-8"
    )
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("import subprocess\n", encoding="utf-8")

    result = _ash(
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--oci-runner",
            sys.executable,
            "--source-dir",
            str(source),
            "--output-dir",
            str(tmp_path / "output"),
            "--no-fail-on-incomplete-scanners",
            "--offline",
            "--no-progress",
            *args,
        ],
        cwd=tmp_path,
        OCI_RUNNER_WRAPPER=shlex.join([sys.executable, str(runtime)]),
    )
    if not record.is_file():
        return result, None
    inner = json.loads(record.read_text(encoding="utf-8"))
    assert "ash" in inner, inner
    return result, inner


@pytest.mark.parametrize(
    "args, passed_in",
    [
        pytest.param(("--ignore-suppressions",), True, id="the-flag-reaches-the-scan"),
        pytest.param((), False, id="control-without-the-flag"),
    ],
)
@pytest.mark.integration
def test_ignore_suppressions_reaches_the_scan_inside_the_container(
    tmp_path: Path, args: Tuple[str, ...], passed_in: bool
) -> None:
    """set-the-gate.md (Who can change the gate), exit-codes.md (Container and Nix
    mode) and run-in-a-container.md (Mounts and network).

    ``ash scan --mode container`` runs against a fake container runtime
    (``OCI_RUNNER_WRAPPER``), which records the inner command and writes the results of
    a scan with one HIGH bandit finding. With ``--ignore-suppressions`` the inner command
    must carry the flag, so the scan inside does what a local scan with it does. The
    control is the same scan without the flag, whose inner command does not carry it;
    both fail on the finding, which shows the host read the results the runtime wrote.
    """
    assert_on_page(
        SET_THE_GATE,
        "In container mode it reaches the scan inside the container and works there as "
        "in a local scan.",
    )
    assert_on_page(
        EXIT_CODES,
        "`--ignore-suppressions` reaches the scan inside the container and works there as "
        "in a local scan.",
    )
    assert_on_page(
        RUN_IN_A_CONTAINER,
        "`--ignore-suppressions` reaches the scan inside and works there as in a local "
        "scan: it lifts suppressions and ignore paths for every scanner, and ASH's own "
        "output directory stays out of the results",
    )

    finding = _bandit_finding("B602", "app.py")
    finding["properties"]["issue_severity"] = "HIGH"
    result, inner = _container_scan(tmp_path, [finding], *args)

    assert inner is not None, f"the runtime was not run:\n{_output_tail(result)}"
    assert ("--ignore-suppressions" in inner) is passed_in, inner
    assert result.returncode == 2, (
        f"exit {result.returncode}, expected 2:\n{_output_tail(result)}"
    )


#: A fake container runtime that appends each command it is given to the JSON-lines
#: file ``record`` and does nothing else, for what the host passes it and whether the
#: host calls it at all.
_RECORDING_RUNTIME = """\
import json, sys

with open({record!r}, "a", encoding="utf-8") as calls:
    calls.write(json.dumps(sys.argv[1:]) + "\\n")
"""

#: A config that grants a network, turns honor_ignore_files off, and extends a base
#: beside it that grants a read path: settings only an operator's file may make.
_GRANTING_ROOT = {
    "project_name": "grants",
    "extends": "./base.yaml",
    "honor_ignore_files": False,
    "sandbox": {"network_scanners": ["grype"]},
}
_GRANTING_BASE = {"sandbox": {"extra_read_paths": ["/srv/ash/semgrep-rules"]}}


def _squeezed(text: str) -> str:
    """``text`` with no whitespace, for a message holding a path the console may have
    wrapped mid-word."""
    return "".join(text.split())


def _spellings(path: Path) -> Set[str]:
    """The ways ASH may write ``path`` in a message."""
    return {str(path), path.as_posix(), str(path.resolve()), path.resolve().as_posix()}


def _names(output: str, path: Path) -> bool:
    """Whether ``output`` names ``path``, written between quotes."""
    return any(
        _squeezed(f"'{spelling}'") in _squeezed(output) for spelling in _spellings(path)
    )


def _refused_operator_config(output: str) -> Optional[str]:
    """The refusal of an operator config in ``output``, from its first words to the
    advice it ends with, with no whitespace, or None."""
    squeezed = _squeezed(output)
    start = squeezed.find(_squeezed("The operator config '"))
    end = squeezed.find(_squeezed(_KEEP_A_SETTING), start)
    if start < 0 or end < 0:
        return None
    return squeezed[start : end + len(_squeezed(_KEEP_A_SETTING))]


def _ends_refused_operator_config(output: str, where: str, place: Path) -> bool:
    """Whether ``output`` holds the end of the refusal of an operator config built
    from a file in, or reached through a link in, ``place``, which the error calls
    ``where``: "the checkout", or "the scanned directory" for a workspace root in no
    checkout."""
    return any(
        _squeezed(
            f"Move the config, and every base it extends, outside {where} "
            f"'{spelling}'. {_KEEP_A_SETTING}"
        )
        in _squeezed(output)
        for spelling in _spellings(place)
    )


def _granting_config(directory: Path, checkout: bool = False) -> Path:
    """``directory/ash.yaml`` holding ``_GRANTING_ROOT``, with its base beside it, and
    ``directory`` a git checkout of its own if ``checkout``."""
    directory.mkdir(parents=True)
    if checkout:
        (directory / ".git").mkdir()
    (directory / "base.yaml").write_text(
        yaml.safe_dump(_GRANTING_BASE), encoding="utf-8"
    )
    config = directory / "ash.yaml"
    config.write_text(yaml.safe_dump(_GRANTING_ROOT), encoding="utf-8")
    return config


def _workspace_in_a_checkout(tmp_path: Path, checkout: bool = True) -> Path:
    """The workspace file of ``repo/ws``, inside the git checkout ``repo``, or in no
    checkout unless ``checkout``. It lists ``api``, which has no config of its own, and
    ``web``, which has one."""
    repo = tmp_path / "repo"
    repo.mkdir()
    if checkout:
        (repo / ".git").mkdir()
    root = repo / "ws"
    for name in ("api", "web"):
        (root / name).mkdir(parents=True)
        (root / name / "main.py").write_text("x = 1\n", encoding="utf-8")
    (root / "web" / ".ash").mkdir()
    (root / "web" / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump({"project_name": "web"}), encoding="utf-8"
    )
    workspace = root / "services.code-workspace"
    workspace.write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), encoding="utf-8"
    )
    return workspace


def _workspace_config_in(tmp_path: Path, workspace: Path, place: str) -> Path:
    """A ``--config`` for a scan of ``workspace``, at ``place``."""
    checkout = workspace.parent.parent
    if place == "another-checkout":
        return _granting_config(tmp_path / "ops", checkout=True)
    if place == "outside-every-checkout":
        return _granting_config(tmp_path / "etc")
    if place == "inside-the-workspace-root":
        return _granting_config(workspace.parent / "cfg")
    if place == "the-checkout-around-the-root":
        return _granting_config(checkout / "cfg")
    if place == "a-link-there-to-a-file-outside":
        outside = _granting_config(tmp_path / "etc")
        (checkout / "linked.yaml").symlink_to(outside)
        return checkout / "linked.yaml"
    if place == "reached-through-a-link-there":
        outside = _granting_config(tmp_path / "etc")
        (checkout / "etc-link").symlink_to(outside.parent, target_is_directory=True)
        return checkout / "etc-link" / "ash.yaml"
    if place == "a-link-outside-to-a-file-there":
        there = _granting_config(checkout / "cfg")
        (tmp_path / "links").mkdir()
        (tmp_path / "links" / "ash.yaml").symlink_to(there)
        return tmp_path / "links" / "ash.yaml"
    raise ValueError(place)


@pytest.mark.parametrize(
    "place, in_a_checkout, refused, marked",
    [
        pytest.param("another-checkout", True, False, True, id="another-checkout"),
        pytest.param(
            "outside-every-checkout",
            True,
            False,
            False,
            id="control-outside-every-checkout",
        ),
        *(
            pytest.param(place, True, True, False, id=f"refused-{name}")
            for place, name in (
                ("inside-the-workspace-root", "inside-the-workspace-root"),
                ("the-checkout-around-the-root", "in-the-checkout"),
                ("a-link-there-to-a-file-outside", "a-link-there-to-a-file-outside"),
                ("reached-through-a-link-there", "reached-through-a-link-there"),
                ("a-link-outside-to-a-file-there", "a-link-outside-to-a-file-there"),
            )
        ),
        pytest.param(
            "inside-the-workspace-root",
            False,
            True,
            False,
            id="refused-inside-a-workspace-root-in-no-checkout",
        ),
    ],
)
@pytest.mark.integration
def test_a_container_workspace_scan_marks_or_refuses_its_config_by_where_it_is(
    tmp_path: Path, place: str, in_a_checkout: bool, refused: bool, marked: bool
) -> None:
    """run-in-a-container.md (The config file), and scale-large-repos.md (Workspaces).

    ``ash scan --mode container --workspace`` runs against a fake container runtime
    that records each command it is given, for a workspace inside a git checkout and
    a ``--config`` that grants. A config in another checkout is mounted with its base
    and marked, so the scan inside limits it; one outside every checkout is mounted
    and not marked.

    These are refused with exit code 3 before the runtime is called at all, image build
    included: a config inside the workspace root, one in the checkout around the root,
    one named there that is a link, or is reached through one, to a file outside the
    checkout, a link outside every checkout to a file in it, and a config inside a
    workspace root that is in no checkout. The error must name the config and its base,
    say to move them outside the checkout, or outside the workspace root (which it
    calls the scanned directory) when that is in no checkout, and end with the advice
    the page quotes. It must be the error the same workspace scan gives in local mode.
    """
    assert_on_page(
        RUN_IN_A_CONTAINER,
        "For a file mounted from a git checkout, ASH tells the scan inside that a "
        "repository wrote it.",
    )
    assert_on_page(
        RUN_IN_A_CONTAINER,
        "A workspace scan does the same with a `--config` from another git checkout, "
        "such as an operations repository beside the workspace.",
    )
    assert_on_page(
        RUN_IN_A_CONTAINER,
        "A `--config` outside every checkout is the operator's. A `--config` in the "
        "workspace's tree, the git checkout around the workspace root, or the workspace "
        "root itself when it is in no checkout, is refused with exit code 3 before "
        "anything is built or mounted, as in a local workspace scan (Scan a "
        "multi-project workspace). That covers a file inside the workspace root, a file "
        "in the checkout outside the root, and a path that is a link, or is reached "
        "through one, into that tree or out of it. The error names each file, says to "
        "move the config and every base it extends outside the checkout, or outside the "
        f"workspace root when it is in no checkout, and ends `{_KEEP_A_SETTING}`",
    )
    assert_on_page(
        SCALE_LARGE_REPOS,
        "Container mode refuses it the same way, with the same error, before anything "
        "is built or mounted, a file under the workspace root included.",
    )
    workspace = _workspace_in_a_checkout(tmp_path, checkout=in_a_checkout)
    config = _workspace_config_in(tmp_path, workspace, place)
    record = tmp_path / "runtime-calls.jsonl"
    runtime = tmp_path / "recording_runtime.py"
    runtime.write_text(_RECORDING_RUNTIME.format(record=str(record)), encoding="utf-8")

    def scan(*mode: str) -> subprocess.CompletedProcess:
        return _ash(
            [
                "scan",
                *mode,
                "--workspace",
                str(workspace),
                "--config",
                str(config),
                "--output-dir",
                str(tmp_path / "output"),
                "--offline",
                "--no-progress",
            ],
            cwd=tmp_path,
            OCI_RUNNER_WRAPPER=shlex.join([sys.executable, str(runtime)]),
        )

    # A refusal must come before the image build, so only an allowed config skips it.
    result = scan(
        *("--mode", "container", "--oci-runner", sys.executable),
        *([] if refused else ["--no-build"]),
    )
    calls = _runtime_calls(record)
    output = _normalize(result.stdout + result.stderr)

    if refused:
        assert result.returncode == 3, (
            f"exit {result.returncode}, expected 3:\n{_output_tail(result)}"
        )
        assert calls == [], f"the runtime was called before the refusal: {calls}"
        for file in (config.resolve(), config.resolve().with_name("base.yaml")):
            assert _names(output, file), f"{file} is not named:\n{_output_tail(result)}"
        if in_a_checkout:
            where, place_path = "the checkout", workspace.parent.parent
        else:
            where, place_path = "the scanned directory", workspace.parent
        assert _ends_refused_operator_config(output, where, place_path), _output_tail(
            result
        )
        local = scan("--dry-run")
        assert local.returncode == 3, _output_tail(local)
        assert _refused_operator_config(output) == _refused_operator_config(
            local.stdout + local.stderr
        ), f"container:\n{_output_tail(result)}\nlocal:\n{_output_tail(local)}"
        return

    scans = [call for call in calls if "ash" in call]
    assert len(scans) == 1, f"expected one scan command, the runtime got {calls}"
    command = scans[0]
    inner = command[command.index("ash") :]
    mounts = [command[i + 1] for i, arg in enumerate(command[:-1]) if arg == "--mount"]
    config_mounts = sorted(
        m.split("destination=", 1)[1] for m in mounts if "destination=/ash-config" in m
    )
    assert inner[inner.index("--workspace") + 1] == "/src/services.code-workspace", (
        inner
    )
    assert inner[inner.index("--config") + 1] == "/ash-config/ash.yaml", inner
    assert ("--config-from-scanned-repository" in inner) is marked, inner
    assert config_mounts == [
        "/ash-config/ash.yaml,readonly",
        "/ash-config/base.yaml,readonly",
    ], mounts


@pytest.mark.parametrize(
    "marked, limited",
    [
        pytest.param(True, True, id="the-marked-copy-is-limited"),
        pytest.param(False, False, id="control-the-copy-without-the-mark"),
    ],
)
@pytest.mark.integration
def test_the_workspace_scan_inside_limits_a_marked_config_as_a_local_one_in_a_checkout(
    tmp_path: Path, marked: bool, limited: bool
) -> None:
    """run-in-a-container.md (The config file), and scale-large-repos.md (Workspaces).

    The scan inside the container is ASH in local mode, given the mounted copy of the
    ``--config`` at ``/ash-config``, outside every checkout, and the host's mark. So
    the same workspace dry run is made locally twice: with the file in another git
    checkout, and with a copy of it outside every checkout plus the mark, as the scan
    inside gets it. With the file's directory written the same way, the two must print
    the same plan and the same warnings, which drop the grants of the file and of its
    base, and honor_ignore_files, for every project. The control is the copy without
    the mark, which is the operator's: no warning names it.
    """
    assert_on_page(
        RUN_IN_A_CONTAINER,
        "The workspace scan inside limits that file, and every file it extends, for "
        "every project and for the plan, with the same settings dropped and the same "
        "warnings as a workspace scan in local mode.",
    )
    assert_on_page(
        SCALE_LARGE_REPOS,
        "Container mode gives your file the same tier: the host mounts a file from "
        "another git checkout and tells the workspace scan inside that a repository "
        "wrote it, and that scan limits the file, and every file it extends, for every "
        "project and for the plan, with the same warnings",
    )
    workspace = _workspace_in_a_checkout(tmp_path)

    def dry_run(config: Path, *mark: str) -> str:
        result = _ash(
            [
                "scan",
                "--workspace",
                str(workspace),
                "--config",
                str(config),
                *mark,
                "--dry-run",
                "--offline",
                "--no-progress",
                "--output-dir",
                str(tmp_path / f"output-{config.parent.name}"),
            ],
            cwd=tmp_path,
        )
        assert result.returncode == 0, _output_tail(result)
        output = _normalize(result.stdout + result.stderr)
        for spelling in (str(config.parent), config.parent.as_posix()):
            output = output.replace(spelling, "<config directory>")
        return output

    in_a_checkout = dry_run(_granting_config(tmp_path / "ops", checkout=True))
    copy = _granting_config(tmp_path / "ash-config")
    inside = dry_run(copy, *(["--config-from-scanned-repository"] if marked else []))
    assert "Ignoring sandbox.network_scanners, sandbox.extra_read_paths from" in (
        in_a_checkout
    ), in_a_checkout
    if limited:
        assert inside == in_a_checkout, "\n".join(
            difflib.unified_diff(
                in_a_checkout.split(". "), inside.split(". "), lineterm=""
            )
        )
    else:
        assert "from the config built on <config directory>" not in inside, inside
        assert "from <config directory>" not in inside, inside


def _runtime_calls(record: Path) -> List[Any]:
    """The calls a stand-in wrote to its ``record`` file, one line of JSON each: the
    command for ``_RECORDING_RUNTIME``, and arguments and ``ASH_CONFIG`` for
    ``_nix_stand_in``."""
    if not record.is_file():
        return []
    return [
        json.loads(line) for line in record.read_text(encoding="utf-8").splitlines()
    ]


def _make_unreadable(path: Path) -> None:
    """Write a config at ``path`` that this user cannot read."""
    if os.name != "nt" and os.geteuid() == 0:
        pytest.skip("root ignores file modes, so no file is unreadable to it")
    path.write_text("project_name: locked\n", encoding="utf-8")
    if os.name == "nt":
        # Everyone (S-1-1-0) denied reading the file's data.
        subprocess.run(
            ["icacls", str(path), "/deny", "*S-1-1-0:(R)"],
            check=True,
            capture_output=True,
        )
    else:
        path.chmod(0)
    with pytest.raises(PermissionError):
        path.read_bytes()


#: How the file ``ASH_CONFIG`` names is made for each way the pages say it can be
#: unusable, and a file that loads for the control.
_ASH_CONFIG_FILE: Dict[str, Callable[[Path], object]] = {
    "missing": lambda path: None,
    "not-a-file": lambda path: path.mkdir(),
    "unreadable": _make_unreadable,
    "unparsable": lambda path: path.write_text(
        "project_name: [unclosed\n", encoding="utf-8"
    ),
    "not-a-valid-config": lambda path: path.write_text(
        "project_name: x\nglobal_settings: 7\n", encoding="utf-8"
    ),
    "control-a-file-that-loads": lambda path: path.write_text(
        "project_name: env\n", encoding="utf-8"
    ),
}


def _nix_stand_in(tmp_path: Path, record: Path) -> Dict[str, str]:
    """The environment that puts a stand-in for ``nix`` first on PATH. It appends the
    arguments and the ``ASH_CONFIG`` it was given to ``record`` as a line of JSON and
    exits 97, so no shell starts. Nothing on Windows, which has no ``nix`` (install.md,
    Nix mode)."""
    if os.name == "nt":
        return {}
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    nix = bin_dir / "nix"
    nix.write_text(
        f"#!{sys.executable}\nimport json, os, sys\n"
        f"with open({str(record)!r}, 'a', encoding='utf-8') as calls:\n"
        "    calls.write(json.dumps({'argv': sys.argv[1:], "
        "'ASH_CONFIG': os.environ.get('ASH_CONFIG')}) + '\\n')\n"
        "sys.exit(97)\n",
        encoding="utf-8",
    )
    nix.chmod(0o755)
    return {"PATH": os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")])}


@pytest.mark.parametrize("mode", ["container", "nix"])
@pytest.mark.parametrize("state", list(_ASH_CONFIG_FILE))
@pytest.mark.integration
def test_an_unusable_ash_config_file_beside_a_valid_config_is_refused_on_the_host(
    tmp_path: Path, mode: str, state: str
) -> None:
    """run-in-a-container.md (The config file), trust-model.md (How the tier is
    decided), and install.md (Nix mode).

    ``ash scan --mode container`` (with the image build) and ``--mode nix`` run with a
    valid ``--config`` outside every checkout and ``ASH_CONFIG`` naming a file that is
    missing, a directory, unreadable, not YAML, or not a valid config. The host must
    refuse with exit code 3, an error naming that path, the previous run's output as
    it was, and no call to the container runtime or ``nix``, image build included:
    their stand-ins record each call. The control is a file that loads, with which the
    scan goes on to call them. On Windows there is no ``nix`` (install.md, Nix mode),
    so there the control is refused with exit code 1 and pointed at WSL2, and an
    unusable file must still be refused with 3 first.
    """
    assert_on_page(
        RUN_IN_A_CONTAINER,
        "An `ASH_CONFIG` file that is missing, cannot be read, does not parse, or is not "
        "a valid config stops the scan with exit code 3 on the host, before anything is "
        "built, run, mounted, or cleared, even when `--config` names a valid file.",
    )
    assert_on_page(
        TRUST_MODEL,
        "One that names a path that is not a file, a file that cannot be read, or a "
        "config that does not load stops a scan with exit code 3",
    )
    assert_on_page(
        INSTALL_PAGE,
        "A file that is missing, cannot be read, does not parse, or is not a valid config "
        "stops the scan with exit code 3 before the previous run's output is cleared, and "
        "that includes the file `ASH_CONFIG` names when `--config` names a valid one.",
    )
    broken = not state.startswith("control-")
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    config = _granting_config(tmp_path / "etc")
    env_config = tmp_path / "env" / "ash-env.yaml"
    env_config.parent.mkdir()
    _ASH_CONFIG_FILE[state](env_config)
    output = tmp_path / "output"
    output.mkdir()
    previous = output / "ash_aggregated_results.json"
    previous.write_text('{"previous": "run"}\n', encoding="utf-8")

    record = tmp_path / "runtime-calls.jsonl"
    env = {"ASH_CONFIG": str(env_config)}
    if mode == "container":
        runtime = tmp_path / "recording_runtime.py"
        runtime.write_text(
            _RECORDING_RUNTIME.format(record=str(record)), encoding="utf-8"
        )
        env["OCI_RUNNER_WRAPPER"] = shlex.join([sys.executable, str(runtime)])
        mode_args = ["--mode", "container", "--oci-runner", sys.executable]
    else:
        mode_args = ["--mode", "nix"]
        env.update(_nix_stand_in(tmp_path, record))

    result = _ash(
        [
            "scan",
            *mode_args,
            "--source-dir",
            str(source),
            "--config",
            str(config),
            "--output-dir",
            str(output),
            "--offline",
            "--no-progress",
        ],
        cwd=tmp_path,
        **env,
    )
    calls = _runtime_calls(record)
    text = result.stdout + result.stderr

    if broken:
        assert result.returncode == 3, (
            f"exit {result.returncode}, expected 3:\n{_output_tail(result)}"
        )
        assert calls == [], f"{mode} was started before the refusal: {calls}"
        assert any(
            _squeezed(spelling) in _squeezed(text)
            for spelling in _spellings(env_config)
        ), _output_tail(result)
        assert previous.read_text(encoding="utf-8") == '{"previous": "run"}\n'
        return
    if mode == "nix" and os.name == "nt":
        assert result.returncode == 1, _output_tail(result)
        assert "on Windows use WSL2" in _normalize(text), _output_tail(result)
        return
    assert calls, (
        f"{mode} was not started with a file that loads:\n{_output_tail(result)}"
    )


@pytest.mark.parametrize("which", ["named", "ash-config", "discovered"])
@pytest.mark.parametrize("state", list(_ASH_CONFIG_FILE))
@pytest.mark.integration
def test_a_nix_scan_resolves_its_config_on_the_host_before_the_shell_starts(
    tmp_path: Path, which: str, state: str
) -> None:
    """install.md (Nix mode).

    ``ash scan --mode nix`` of one directory runs with the file under test as:
    ``--config``, with ``ASH_CONFIG`` naming a file that loads beside it (named); the
    file ``ASH_CONFIG`` names with no ``--config``, beside a ``.ash.yaml`` in the
    directory that does not parse, which must not be read (ash-config); or a
    ``.ash.yaml`` in the directory with neither (discovered). That file is missing, a
    directory, unreadable, not YAML, or not a valid config. The host must refuse with
    exit code 3, naming that path, before the stand-in for ``nix`` is called, with the
    previous run's output as it was. A discovered name that is missing is no config at
    all, so that case is a control, as is a file that loads: the stand-in is then
    called once, with the caller's ``ASH_CONFIG`` in its environment, or none, and with
    ``--config`` only as named. On Windows, which has no ``nix``, a control is refused
    with exit code 1 and pointed at WSL2 instead.
    """
    assert_on_page(
        INSTALL_PAGE,
        "The scan inside the shell gets your environment, so it reads the file "
        "`ASH_CONFIG` names first, as a local scan does, and then the file `--config` "
        "names. With no `--config`, the file `ASH_CONFIG` names is the config too, and "
        "with neither, the scan uses the config file it discovers. In a scan of one "
        "directory, ASH resolves that config on the host before the shell starts. A file "
        "that is missing, cannot be read, does not parse, or is not a valid config stops "
        "the scan with exit code 3 before the previous run's output is cleared",
    )
    broken = not state.startswith("control-") and not (
        which == "discovered" and state == "missing"
    )
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    env_config = tmp_path / "env" / "ash-env.yaml"
    env_config.parent.mkdir()
    config = {
        "named": tmp_path / "cfg" / "ash.yaml",
        "ash-config": env_config,
        "discovered": source / ".ash.yaml",
    }[which]
    config.parent.mkdir(exist_ok=True)
    _ASH_CONFIG_FILE[state](config)
    if which == "named":
        env_config.write_text("project_name: env\n", encoding="utf-8")
    if which == "ash-config":
        (source / ".ash.yaml").write_text("project_name: [unclosed\n", encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()
    previous = output / "ash_aggregated_results.json"
    previous.write_text('{"previous": "run"}\n', encoding="utf-8")
    record = tmp_path / "nix-calls.jsonl"
    env = _nix_stand_in(tmp_path, record)
    if which != "discovered":
        env["ASH_CONFIG"] = str(env_config)

    result = _ash(
        [
            "scan",
            "--mode",
            "nix",
            "--source-dir",
            str(source),
            *(["--config", str(config)] if which == "named" else []),
            "--output-dir",
            str(output),
            "--offline",
            "--no-progress",
        ],
        cwd=tmp_path,
        **env,
    )
    calls = _runtime_calls(record)
    text = result.stdout + result.stderr

    if broken:
        assert result.returncode == 3, (
            f"exit {result.returncode}, expected 3:\n{_output_tail(result)}"
        )
        assert calls == [], f"nix was started before the refusal: {calls}"
        assert any(
            _squeezed(spelling) in _squeezed(text) for spelling in _spellings(config)
        ), _output_tail(result)
        assert previous.read_text(encoding="utf-8") == '{"previous": "run"}\n'
        return
    if os.name == "nt":
        assert result.returncode == 1, _output_tail(result)
        assert "on Windows use WSL2" in _normalize(text), _output_tail(result)
        return
    assert len(calls) == 1, (
        f"nix was called {len(calls)} times:\n{_output_tail(result)}"
    )
    assert calls[0]["ASH_CONFIG"] == env.get("ASH_CONFIG"), calls[0]
    argv = calls[0]["argv"]
    if which == "named":
        assert "--config" in argv and argv[argv.index("--config") + 1] == str(config), (
            argv
        )
    else:
        assert "--config" not in argv, argv


@pytest.mark.parametrize("command", [["scan"], []], ids=["ash-scan", "ash"])
@pytest.mark.parametrize("scan", ["one-directory", "workspace"])
@pytest.mark.parametrize(
    "place, marked",
    [
        pytest.param("another-checkout", True, id="in-another-checkout-marked"),
        pytest.param("the-scanned-checkout", True, id="in-the-scanned-checkout-marked"),
        pytest.param(
            "outside-every-checkout", False, id="control-outside-every-checkout"
        ),
    ],
)
@pytest.mark.integration
def test_container_mode_mounts_the_ash_config_file_and_marks_each_file_by_where_it_is(
    tmp_path: Path, command: List[str], scan: str, place: str, marked: bool
) -> None:
    """run-in-a-container.md (The config file).

    ``ash scan --mode container`` and ``ash --mode container`` run against a fake
    container runtime that records each command it is given, with a ``--config``
    outside every checkout and ``ASH_CONFIG`` naming a file that extends a base beside
    it. For a one-directory scan of a directory in a git checkout and a workspace scan
    in one, the file and its base must be mounted read-only under ``/ash-env-config``,
    and the scan inside must be passed ``--ash-config-from-host
    /ash-env-config/ash.yaml``. Each of the two files must be marked on its own with
    ``--config-file-from-scanned-repository`` when they are in another git checkout or
    in the scanned one, and neither when they are outside every checkout. ``--config``
    is marked in no case.
    """
    assert_on_page(
        RUN_IN_A_CONTAINER,
        "`ash scan --mode container` and `ash --mode container` mount that file, and each "
        "file it `extends`, read-only under `/ash-env-config`",
    )
    assert_on_page(
        RUN_IN_A_CONTAINER,
        "A file of that chain the host counts as written by a repository is marked for "
        "the scan inside, file by file.",
    )
    workspace = _workspace_in_a_checkout(tmp_path)
    checkout = workspace.parent.parent
    config = _granting_config(tmp_path / "etc-config")
    env_config = {
        "another-checkout": lambda: _granting_config(tmp_path / "ops", checkout=True),
        "the-scanned-checkout": lambda: _granting_config(checkout / "cfg"),
        "outside-every-checkout": lambda: _granting_config(tmp_path / "etc"),
    }[place]()
    record = tmp_path / "runtime-calls.jsonl"
    runtime = tmp_path / "recording_runtime.py"
    runtime.write_text(_RECORDING_RUNTIME.format(record=str(record)), encoding="utf-8")
    target = (
        ["--workspace", str(workspace)]
        if scan == "workspace"
        else ["--source-dir", str(workspace.parent / "api")]
    )

    _ash(
        [
            *command,
            "--mode",
            "container",
            "--no-build",
            "--oci-runner",
            sys.executable,
            *target,
            "--config",
            str(config),
            "--output-dir",
            str(tmp_path / "output"),
            "--offline",
            "--no-progress",
        ],
        cwd=tmp_path,
        ASH_CONFIG=str(env_config),
        OCI_RUNNER_WRAPPER=shlex.join([sys.executable, str(runtime)]),
    )
    scans = [call for call in _runtime_calls(record) if "ash" in call]
    assert len(scans) == 1, f"expected one scan command, the runtime got {scans}"
    scan_command = scans[0]
    inner = scan_command[scan_command.index("ash") :]
    mounts = [
        scan_command[i + 1]
        for i, arg in enumerate(scan_command[:-1])
        if arg == "--mount"
    ]
    env_mounts = sorted(
        m.split("destination=", 1)[1]
        for m in mounts
        if "destination=/ash-env-config" in m
    )
    file_marks = sorted(
        inner[i + 1]
        for i, arg in enumerate(inner[:-1])
        if arg == "--config-file-from-scanned-repository"
    )

    assert env_mounts == [
        "/ash-env-config/ash.yaml,readonly",
        "/ash-env-config/base.yaml,readonly",
    ], mounts
    assert "--ash-config-from-host" in inner, inner
    assert inner[inner.index("--ash-config-from-host") + 1] == (
        "/ash-env-config/ash.yaml"
    ), inner
    assert file_marks == (
        ["/ash-env-config/ash.yaml", "/ash-env-config/base.yaml"] if marked else []
    ), inner
    assert "--config-from-scanned-repository" not in inner, inner


@pytest.mark.integration
def test_the_scan_inside_reads_the_handed_over_file_as_its_ash_config(
    tmp_path: Path,
) -> None:
    """run-in-a-container.md (The config file).

    The scan inside the container is ASH in local mode, given the mounted copy of the
    ``--config``, marked as a repository's, and ``--ash-config-from-host``. A workspace
    dry run is made that way, with a ``--config`` that sets ``honor_ignore_files:
    true`` and a handed-over file that sets it to ``false``. The repository's value
    must be dropped for the handed-over file's, as on the host with ``ASH_CONFIG``
    naming that file: both print ``Using honor_ignore_files: false``. The ``--config``
    must still be the config, its ``project_name`` labelling the projects. The control
    is the same run with neither, which keeps the default and prints no such line.
    """
    assert_on_page(
        RUN_IN_A_CONTAINER,
        "Beside a `--config`, the file `ASH_CONFIG` names is still the trusted base, as "
        "in a local scan: ASH reads it first, and when the config is a repository's, "
        "takes from it the settings a repository may not choose (Configuration trust "
        "model).",
    )
    assert_on_page(
        RUN_IN_A_CONTAINER,
        "and the scan inside reads it as its `ASH_CONFIG`.",
    )
    workspace = _workspace_in_a_checkout(tmp_path)
    config = tmp_path / "ash-config" / "ash.yaml"
    config.parent.mkdir()
    config.write_text(
        yaml.safe_dump({"project_name": "inner", "honor_ignore_files": True}),
        encoding="utf-8",
    )
    env_config = tmp_path / "ash-env-config" / "ash.yaml"
    env_config.parent.mkdir()
    env_config.write_text(
        yaml.safe_dump({"project_name": "env", "honor_ignore_files": False}),
        encoding="utf-8",
    )

    def dry_run(*extra: str, **env: str) -> str:
        result = _ash(
            [
                "scan",
                "--workspace",
                str(workspace),
                "--config",
                str(config),
                "--config-from-scanned-repository",
                *extra,
                "--dry-run",
                "--offline",
                "--no-progress",
                "--output-dir",
                str(tmp_path / "output"),
            ],
            cwd=tmp_path,
            **env,
        )
        assert result.returncode == 0, _output_tail(result)
        return _normalize(result.stdout + result.stderr)

    handed = dry_run("--ash-config-from-host", str(env_config))
    on_the_host = dry_run(ASH_CONFIG=str(env_config))
    neither = dry_run()

    taken = "Using honor_ignore_files: false."
    assert taken in on_the_host, on_the_host
    assert taken in handed, handed
    assert "label: inner (api)" in handed, handed
    assert taken not in neither, neither


@pytest.mark.integration
def test_a_container_scan_marks_each_file_of_the_config_chain_on_its_own(
    tmp_path: Path, ash_log: List[logging.LogRecord]
) -> None:
    """run-in-a-container.md (The config file).

    ``ash scan --mode container`` of a directory in a git checkout runs against a fake
    container runtime that records each command it is given, with a ``--config``
    outside every checkout that grants grype a network and extends a base in the
    checkout, which grants a read path and turns honor_ignore_files off. The host must
    mark the base alone, with ``--config-file-from-scanned-repository``, and not the
    config. The scan inside, which reads the files mounted at ``/ash-config`` and holds
    the base's mark as ``cli/scan.py`` hands it over
    (``sandbox_grants.marked_files_repository_written``), must then resolve the config
    as the host's local scan does: the config's own network kept, the base's read path
    and honor_ignore_files dropped, with the same warnings, the paths aside. The control
    is the scan inside without the mark, which keeps the base's settings.
    """
    assert_on_page(
        RUN_IN_A_CONTAINER,
        "It marks each file of the chain on its own, so a config outside every checkout "
        "that extends a base in a git checkout keeps its own settings, as on the host, "
        "and the scan inside drops the same settings with the same warnings as a local "
        "scan.",
    )
    from automated_security_helper.config import sandbox_grants
    from automated_security_helper.config.resolve_config import resolve_config

    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    source = repo / "app"
    source.mkdir()
    (source / "main.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "ci").mkdir()
    (repo / "ci" / "base.yaml").write_text(
        yaml.safe_dump(
            {
                "honor_ignore_files": False,
                "sandbox": {"extra_read_paths": ["/srv/ash/base-rules"]},
            }
        ),
        encoding="utf-8",
    )
    # Beside the checkout, so the confinement root around it holds the base.
    config = tmp_path / "ash.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "project_name": "ops",
                "extends": "repo/ci/base.yaml",
                "sandbox": {"network_scanners": ["grype"]},
            }
        ),
        encoding="utf-8",
    )
    record = tmp_path / "runtime-calls.jsonl"
    runtime = tmp_path / "recording_runtime.py"
    runtime.write_text(_RECORDING_RUNTIME.format(record=str(record)), encoding="utf-8")

    _ash(
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--oci-runner",
            sys.executable,
            "--source-dir",
            str(source),
            "--config",
            str(config),
            "--output-dir",
            str(tmp_path / "output"),
            "--offline",
            "--no-progress",
        ],
        cwd=tmp_path,
        OCI_RUNNER_WRAPPER=shlex.join([sys.executable, str(runtime)]),
    )
    scans = [call for call in _runtime_calls(record) if "ash" in call]
    assert len(scans) == 1, f"expected one scan command, the runtime got {scans}"
    command = scans[0]
    inner = command[command.index("ash") :]
    file_marks = [
        inner[i + 1]
        for i, arg in enumerate(inner[:-1])
        if arg == "--config-file-from-scanned-repository"
    ]
    assert "--config-from-scanned-repository" not in inner, inner
    assert file_marks == ["/ash-config/repo/ci/base.yaml"], inner
    assert inner[inner.index("--config") + 1] == "/ash-config/ash.yaml", inner

    # What the scan inside sees: each file mounted under /ash-config, copied to the
    # same place under a directory in no checkout, and a source directory there.
    inside = tmp_path / "inside"
    for i, arg in enumerate(command[:-1]):
        if arg != "--mount" or "destination=/ash-config/" not in command[i + 1]:
            continue
        fields = dict(
            part.split("=", 1) for part in command[i + 1].split(",") if "=" in part
        )
        copy = inside / fields["destination"].lstrip("/")
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(fields["source"], copy)
    (inside / "src").mkdir()
    (inside / "src" / "main.py").write_text("x = 1\n", encoding="utf-8")
    copied_config = inside / "ash-config" / "ash.yaml"

    def resolved(config_path: Path, source_dir: Path, *marked: Path) -> Any:
        ash_log.clear()
        with (
            sandbox_grants.marked_files_repository_written(marked)
            if marked
            else contextlib.nullcontext()
        ):
            return resolve_config(config_path=config_path, source_dir=source_dir)

    def dropped(directory: Path) -> List[str]:
        warnings = []
        for message in _messages(r for r in ash_log if r.levelno == logging.WARNING):
            for spelling in sorted(_spellings(directory), key=len, reverse=True):
                message = message.replace(spelling, "<config directory>")
            if message.startswith("Ignoring "):
                warnings.append(message)
        return warnings

    on_the_host = resolved(config, source)
    host_warnings = dropped(tmp_path)
    in_the_container = resolved(
        copied_config,
        inside / "src",
        *(inside / mark.lstrip("/") for mark in file_marks),
    )
    container_warnings = dropped(inside / "ash-config")
    unmarked = resolved(copied_config, inside / "src")

    for config_seen in (on_the_host, in_the_container):
        assert config_seen.sandbox.network_scanners == ["grype"]
        assert config_seen.sandbox.extra_read_paths == []
        assert config_seen.honor_ignore_files is True
    assert any(
        w.startswith("Ignoring sandbox.extra_read_paths from") for w in host_warnings
    ), host_warnings
    assert container_warnings == host_warnings
    assert unmarked.sandbox.extra_read_paths == ["/srv/ash/base-rules"]
    assert unmarked.honor_ignore_files is False


@pytest.mark.parametrize(
    "in_a_checkout, final",
    [
        pytest.param(False, True, id="outside-every-checkout-its-grants-are-final"),
        pytest.param(True, False, id="control-in-an-ops-checkout-they-are-not"),
    ],
)
@pytest.mark.unit
def test_the_operators_workspace_config_is_final_over_a_projects_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, in_a_checkout: bool, final: bool
) -> None:
    """scale-large-repos.md (Workspaces).

    A workspace inside a git checkout has two projects: ``api`` with no config of its
    own, and ``web`` with its own ``.ash/.ash.yaml``, which sets a LOW threshold. The
    operator's ``--config`` sets a HIGH one, and grants grype a network and a read
    path, settings only an operator may make. The workspace is resolved as ``ash scan
    --workspace`` plans it, and each project's config is read where the planner
    resolves it. The operator's threshold is final for both projects, ``web``
    included. From a file outside every git checkout, so are both grants. The control
    is the same file in an ops checkout, which ASH treats as a repository's: its
    threshold is still final, and neither project gets the grants.

    This measures the plan's resolution only. The scan resolves each project again
    when it runs, from the same values (workspace/resolver.py), and that second
    resolution is not checked here.
    """
    assert_on_page(
        SCALE_LARGE_REPOS,
        "Each project uses its own ASH config file, with the file `--config` (or "
        "`ASH_CONFIG`) names layered over it: every setting your file makes is final for "
        "every project, and a project's own config fills only the settings yours leaves "
        "out.",
    )
    assert_on_page(
        SCALE_LARGE_REPOS,
        "Keep your file outside every git checkout: ASH treats a file inside one as "
        "written by a repository, so the settings only an operator may make, such as "
        "sandbox grants and the AWS reporters' destinations, are not final from it",
    )
    from automated_security_helper.workspace import resolver

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    workspace = _workspace_in_a_checkout(tmp_path)
    (workspace.parent / "web" / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(
            {"project_name": "web", "global_settings": {"severity_threshold": "LOW"}}
        ),
        encoding="utf-8",
    )
    directory = tmp_path / ("ops" if in_a_checkout else "etc")
    directory.mkdir()
    if in_a_checkout:
        (directory / ".git").mkdir()
    operator = directory / "ash.yaml"
    operator.write_text(
        yaml.safe_dump(
            {**_SANDBOX_GRANTS, "global_settings": {"severity_threshold": "HIGH"}}
        ),
        encoding="utf-8",
    )

    resolved: Dict[str, Any] = {}
    resolve = resolver.resolve_config

    def recorded(*args: Any, **kwargs: Any) -> Any:
        config = resolve(*args, **kwargs)
        resolved[Path(kwargs["source_dir"]).name] = config
        return config

    monkeypatch.setattr(resolver, "resolve_config", recorded)
    # As the CLI calls it for ``--workspace`` with ``--config``.
    resolver.resolve_workspace(workspace, default_config=operator)

    assert sorted(resolved) == ["api", "web"], sorted(resolved)
    granted = {
        project: (
            config.global_settings.severity_threshold,
            config.sandbox.network_scanners,
            [str(path) for path in config.sandbox.extra_read_paths],
        )
        for project, config in resolved.items()
    }
    wanted = (
        ("HIGH", ["grype"], ["/srv/ash/semgrep-rules"]) if final else ("HIGH", None, [])
    )
    assert granted == {"api": wanted, "web": wanted}, granted


def _trivy_finding(rule_id: str, level: str) -> Dict[str, Any]:
    """A trivy result at a SARIF ``level``, which ASH grades when it has no severity."""
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": rule_id},
        "properties": {"scanner_name": "trivy"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "requirements.txt"},
                    "region": {"startLine": 1},
                }
            }
        ],
    }


@pytest.mark.unit
def test_ash_passes_no_threshold_to_trivy_and_applies_it_after_the_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """set-the-gate.md (Severity thresholds).

    The built-in trivy scanner and trivy-repo are built the way the scan phase builds
    them, from the plugin config ``AshConfig.get_plugin_config`` gives each, with
    trivy's own threshold HIGH under a global LOW, and their trivy options are resolved
    without running trivy (``_execute_scan`` for trivy, ``_process_config_options``
    for trivy-repo, which overrides the scan itself). Neither carries ``--severity``;
    the control is that each scanner's config holds the HIGH. The threshold is then
    applied as the summary table and the exit code read it: of a MEDIUM and a CRITICAL
    trivy finding, both are counted and only the CRITICAL is actionable. Without
    trivy's own threshold, under a global MEDIUM, both are actionable, so the
    difference is trivy's threshold.
    """
    assert_on_page(
        SET_THE_GATE,
        "ASH does not pass a threshold to trivy, so trivy reports every finding it makes, "
        "for the built-in `trivy` scanner and for `trivy-repo` alike. ASH applies the "
        "threshold after the scan, as for every scanner, to the severity trivy gave each "
        "finding: a finding below it stays in the reports and in the summary table's "
        "severity columns, is not counted as actionable, and does not fail the scan.",
    )
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.scanner_statistics_calculator import (
        ScannerStatisticsCalculator,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
        TrivyScanner,
    )
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScanner,
    )
    from automated_security_helper.schemas.sarif_schema_model import SarifReport

    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"

    for name, scanner_class in (
        ("trivy", TrivyScanner),
        ("trivy-repo", TrivyRepoScanner),
    ):
        config = AshConfig(
            project_name="gate",
            global_settings={"severity_threshold": "LOW"},
            scanners={name: {"options": {"severity_threshold": "HIGH"}}},
        )
        scanner = scanner_class(
            config=config.get_plugin_config(plugin_type="scanner", plugin_name=name),
            context=PluginContext(
                source_dir=source,
                output_dir=output,
                work_dir=output / "converted",
                config=config,
            ),
        )
        assert scanner.config.options.severity_threshold == "HIGH", name
        if scanner_class is TrivyScanner:
            argv, _results_file, _env = scanner._execute_scan(source, "source", [])
        else:
            scanner._process_config_options()
            argv = [arg.key for arg in scanner.args.extra_args]
        assert argv and "--severity" not in argv, (name, argv)

    findings = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "trivy"}},
                    "results": [
                        _trivy_finding("CVE-0000-0001", "warning"),
                        _trivy_finding("CVE-0000-0002", "error"),
                    ],
                }
            ],
        }
    )
    for trivy_options, actionable in (({"severity_threshold": "HIGH"}, 1), ({}, 2)):
        model = AshAggregatedResults(
            ash_config=AshConfig(
                project_name="gate",
                global_settings={"severity_threshold": "MEDIUM"},
                scanners={"trivy": {"options": trivy_options}},
            )
        )
        model.sarif.merge_sarif_report(findings.model_copy(deep=True))
        row = ScannerStatisticsCalculator.extract_scanner_statistics(model)["trivy"]
        assert (row["total"], row["medium"], row["critical"]) == (2, 1, 1), row
        assert row["actionable"] == actionable, (trivy_options, row)


@pytest.mark.parametrize(
    "finding_severity, min_severity, verdict",
    [
        pytest.param("MEDIUM", "low", 2, id="medium-meets-low"),
        pytest.param("MEDIUM", "MEDIUM", 2, id="any-case"),
        pytest.param("MEDIUM", "high", 0, id="medium-does-not-meet-high"),
        pytest.param("HIGH", "critical", 2, id="critical-is-high"),
        pytest.param("MEDIUM", "critical", 0, id="medium-does-not-meet-critical"),
        pytest.param("MEDIUM", "none", 2, id="none-turns-it-off"),
        pytest.param("MEDIUM", "hihg", 5, id="another-value-is-a-usage-error"),
    ],
)
@pytest.mark.integration
def test_min_severity_decides_which_findings_fail_the_scan_and_refuses_another_value(
    tmp_path: Path, finding_severity: str, min_severity: str, verdict: int
) -> None:
    """set-the-gate.md (--min-severity) and exit-codes.md (the usage-error paragraph;
    ash scan, Examples).

    One unsuppressed bandit finding at the default MEDIUM threshold fails the thresholds,
    so ``--min-severity`` alone decides between 2 and 0. The results come from the fake
    container runtime, and the host computes the verdict from them, the way it does for
    a local scan. A value outside the choices exits 5 before any container runs.
    """
    assert_on_page(
        SET_THE_GATE,
        "`--min-severity` (`critical`, `high`, `medium`, `low`, or `none`, in any case; "
        "default `low`) is a second, scan-wide condition on the command line. A scan that "
        "fails its thresholds exits 2 only when at least one unsuppressed finding is at or "
        "above this severity; otherwise it exits 0. `critical` and `high` are equivalent, "
        "and `none` turns the condition off. Any other value is a usage error (exit 5).",
    )
    assert_on_page(
        EXIT_CODES,
        "A mistyped `--min-severity` value is a usage error, 5, and nothing is scanned:",
    )
    finding = _bandit_finding("B602", "app.py")
    finding["properties"]["issue_severity"] = finding_severity

    result, inner = _container_scan(tmp_path, [finding], "--min-severity", min_severity)

    assert result.returncode == verdict, (
        f"exit {result.returncode}, expected {verdict}:\n{_output_tail(result)}"
    )
    if verdict == 5:
        assert inner is None, "a usage error still started the container"
    else:
        assert inner is not None, f"the runtime was not run:\n{_output_tail(result)}"


@pytest.mark.parametrize(
    "sandbox_args, warned",
    [
        pytest.param(
            ("--config-overrides", "sandbox.mode=bwrap"),
            True,
            id="a-requested-sandbox-is-named",
        ),
        pytest.param((), False, id="control-no-sandbox-no-warning"),
    ],
)
@pytest.mark.integration
def test_container_mode_runs_the_scan_inside_unsandboxed_and_says_so(
    tmp_path: Path, sandbox_args: Tuple[str, ...], warned: bool
) -> None:
    """run-in-a-container.md (The scanner sandbox) and sandbox.md (What it does not do).

    The command the fake runtime is given ends its overrides with ``sandbox.mode=off``
    whatever was asked for. With ``sandbox.mode=bwrap`` from ``--config-overrides`` the
    host logs the warning the page quotes; with no sandbox asked for it logs none, which
    is the control. That an explicit ``--sandbox`` is refused before the container runs
    is the page's own runnable block.
    """
    assert_on_page(
        RUN_IN_A_CONTAINER,
        "The scan inside the container gets `sandbox.mode=off` as its last override, and "
        "`ash scan --mode container` logs a warning that names the mode, such as `The "
        "scanner sandbox (bwrap, from sandbox.mode in a config file, --config-overrides or "
        "the operator's config) is not applied in container mode`.",
    )
    assert_on_page(
        RUN_IN_A_CONTAINER,
        "With no sandbox asked for, or with `--no-run`, it logs no warning.",
    )
    assert_on_page(
        SANDBOX,
        "`ash scan --mode container` turns the sandbox off for the scan inside the "
        "container, and logs a warning when the sandbox was asked for; the container is "
        "the boundary there.",
    )

    result, inner = _container_scan(tmp_path, [], *sandbox_args)

    assert inner is not None, f"the runtime was not run:\n{_output_tail(result)}"
    overrides = [
        inner[i + 1] for i, arg in enumerate(inner) if arg == "--config-overrides"
    ]
    assert overrides and overrides[-1] == "sandbox.mode=off", inner
    warning = (
        "The scanner sandbox (bwrap, from sandbox.mode in a config file, "
        "--config-overrides or the operator's config) is not applied in container mode"
    )
    # The log wraps long lines; whitespace is collapsed before matching.
    output = _normalize(result.stdout + result.stderr)
    assert (warning in output) is warned, _output_tail(result)
    assert ("is not applied in container mode" in output) is warned, _output_tail(
        result
    )


def _secret_tree(parent: Path) -> Path:
    """A directory holding the docs fixture's app.py, which detect-secrets reports."""
    tree = parent / "source"
    tree.mkdir(parents=True)
    fixture = REPO_ROOT / "tests" / "test_data" / "docs_fixtures" / "sample-project"
    (tree / "app.py").write_text(
        (fixture / "app.py").read_text(encoding="utf-8"), encoding="utf-8"
    )
    return tree


@pytest.mark.parametrize(
    "name, text, verdict",
    [
        pytest.param("ash.yaml", "fail_on_findings: false\n", 0, id="control-it-loads"),
        pytest.param(
            "ash.yaml",
            "fail_on_findings: false\nglobal_settings: [unclosed\n",
            3,
            id="yaml-that-does-not-parse",
        ),
        pytest.param(
            "ash.json",
            '{"fail_on_findings": false,\n',
            3,
            id="json-that-does-not-parse",
        ),
        pytest.param("missing.yaml", None, 3, id="named-but-missing"),
        pytest.param(
            "ash.toml",
            "fail_on_findings = false\n[global_settings\n",
            3,
            id="toml-that-does-not-parse",
        ),
        pytest.param(
            "child.yaml",
            "extends: no-such-base.yaml\nfail_on_findings: false\n",
            3,
            id="extends-base-missing",
        ),
    ],
)
@pytest.mark.integration
def test_a_config_that_cannot_be_used_is_exit_3_in_any_format(
    tmp_path: Path, name: str, text: str | None, verdict: int
) -> None:
    """exit-codes.md (ash scan) and configure.md (Use a specific file).

    Each file sets ``fail_on_findings: false``, and the tree has a finding detect-secrets
    reports. A YAML, JSON or TOML file that does not parse, a named file that is
    missing, and a missing ``extends`` base must each stop the scan with exit 3. The
    control is a file that loads, which scans and exits 0, so the refusals are the
    files' and the 0 is the config's.
    """
    assert_on_page(
        EXIT_CODES,
        "Only a scan with no config file at all uses the default configuration. A config "
        "file that is named or found and cannot be used, in any format, is exit 3, and so "
        "is an `extends` base that is missing or does not parse.",
    )
    assert_on_page(
        CONFIGURE,
        "A scan uses the default configuration only when there is no config file at all.",
    )
    tree = _secret_tree(tmp_path)
    config = tmp_path / "configs" / name
    config.parent.mkdir()
    if text is not None:
        config.write_text(text, encoding="utf-8")

    result = _ash(
        [
            "scan",
            "--source-dir",
            str(tree),
            "--output-dir",
            str(tmp_path / "output"),
            "--config",
            str(config),
            "--scanners",
            "detect-secrets",
            "--offline",
            "--no-progress",
        ],
        cwd=tmp_path,
    )

    assert result.returncode == verdict, (
        f"exit {result.returncode}, expected {verdict}:\n{_output_tail(result)}"
    )


class _Records(logging.Handler):
    """Collects the records of the ASH logger, which does not propagate to caplog."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def ash_log() -> Iterator[List[logging.LogRecord]]:
    """The records ASH's logger emits while the test runs, at every level."""
    from automated_security_helper.utils.log import ASH_LOGGER

    handler = _Records()
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield handler.records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _messages(records: Iterable[logging.LogRecord]) -> List[str]:
    """Each record's message with its whitespace collapsed."""
    return [" ".join(record.getMessage().split()) for record in records]


@pytest.mark.parametrize(
    "transport",
    [
        pytest.param([], id="stdio"),
        pytest.param(
            ["--transport", "streamable-http", "--host", "127.0.0.1", "--port", "0"],
            id="streamable-http",
        ),
    ],
)
@pytest.mark.integration
def test_an_ash_config_that_names_no_loadable_file_stops_the_mcp_server_with_exit_3(
    tmp_path: Path, transport: List[str]
) -> None:
    """mcp-server.md (How the server runs scans; Environment variables the server
    reads).

    ``ash mcp`` runs with ``ASH_CONFIG`` naming a missing file, a directory, and a file
    that does not load, each with no client on standard input. Each must exit 3 before
    it serves anything, and the missing file's error must name the variable and the
    path. The controls, on stdio, are a file that loads and an empty value, which
    counts as unset: the server starts, and exits 0 once its input closes.
    """
    assert_on_page(
        MCP_SERVER,
        "It also exits with code 3 when `ASH_CONFIG` names no config file it can load.",
    )
    assert_on_page(
        MCP_SERVER,
        "When it names a path that is not a file, a file the server cannot read, or a "
        "config that does not load or validate, `ash mcp` refuses to start, on every "
        "transport, with exit code 3. An empty value counts as unset.",
    )
    assert_on_page(
        MCP_SERVER,
        "A missing `ASH_CONFIG` file stops the server before it serves anything, with an "
        "error that names the variable and the path:",
    )
    missing = tmp_path / "no-such-server.yaml"
    broken = tmp_path / "broken.yaml"
    broken.write_text("global_settings: [unclosed\n", encoding="utf-8")
    good = tmp_path / "server.yaml"
    good.write_text("project_name: the-servers-own\n", encoding="utf-8")

    def serve(value: str) -> Tuple[Optional[int], str]:
        """(exit code, standard error), or (None, ...) for an HTTP server that said it
        listens, which is then stopped."""
        process = _server_popen(
            [*_ASH_MODULE, "mcp", "--quiet", *transport],
            cwd=tmp_path,
            env=_ash_environment(tmp_path, ASH_CONFIG=value),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        lines = _Lines(process.stderr)
        listening = bool(transport) and lines.wait_for(_UVICORN_LISTENING) is not None
        if listening:
            process.kill()
        code = process.wait(timeout=_MCP_STOP_SECONDS)
        text = lines.text()
        if process.stderr:
            process.stderr.close()
        return (None if listening else code), text

    for value in (missing, tmp_path, broken):
        code, stderr = serve(str(value))
        assert code == 3, (value, code, stderr[-1500:])
    _code, stderr = serve(str(missing))
    named = _normalize(stderr)
    # The console may wrap the path mid-word, so it is looked for with no whitespace.
    assert "ASH_CONFIG" in named and any(
        _squeezed(spelling) in _squeezed(stderr) for spelling in _spellings(missing)
    ), named[-1500:]
    if transport:
        return
    for value in (str(good), ""):
        code, stderr = serve(value)
        assert code == 0, (value, code, stderr[-1500:])


#: A scanner plugin whose tool reports one rule it could not evaluate: an error-level
#: runtime notification tied to the rule, and no results. It keeps the tool's
#: notifications on the invocation ASH writes, as cdk-nag does.
_UNEVALUATING_PLUGIN = '''\
import sys
from typing import Literal

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.plugins.decorators import ash_scanner_plugin

WRITER = """
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "unevaluating", "rules": [{"id": "PAGE-CLAIM-1"}]}},
        "invocations": [{
            "executionSuccessful": True,
            "toolExecutionNotifications": [{
                "level": "error",
                "message": {"text": "rule PAGE-CLAIM-1 raised and reached no verdict"},
                "associatedRule": {"id": "PAGE-CLAIM-1"},
            }],
        }],
        "results": [],
    }],
}), encoding="utf-8")
"""


class UnevaluatingOptions(ScannerOptionsBase):
    pass


class UnevaluatingConfig(ScannerPluginConfigBase):
    name: Literal["unevaluating"] = "unevaluating"
    enabled: bool = True
    options: UnevaluatingOptions = UnevaluatingOptions()


@ash_scanner_plugin
class UnevaluatingScanner(ScannerPluginBase[UnevaluatingConfig]):
    command: str = sys.executable
    tool_type: ScannerToolType = ScannerToolType.SAST

    def model_post_init(self, context):
        if self.config is None:
            self.config = UnevaluatingConfig()
        super().model_post_init(context)

    def _execute_scan(self, target, target_type, global_ignore_paths):
        results_file = self.results_dir / target_type / "unevaluating.sarif"
        results_file.parent.mkdir(parents=True, exist_ok=True)
        return [self.command, "-c", WRITER, results_file.as_posix()], results_file, None

    def _invocation_extras(self, sarif_report, final_args, target):
        written = sarif_report.runs[0].invocations or []
        notes = [n for i in written for n in (i.toolExecutionNotifications or [])]
        return {"toolExecutionNotifications": notes}


ASH_SCANNERS = [UnevaluatingScanner]
'''


@pytest.mark.integration
def test_workspace_mode_does_not_check_for_rules_that_could_not_be_evaluated(
    tmp_path: Path,
) -> None:
    """exit-codes.md (ash scan; Workspace mode).

    A plugin scanner reports one rule it could not evaluate. Scanned alone, the project
    exits 1 and names the rule, which is the control: it shows the notification reaches
    the gate. Scanned as the one project of a workspace, the same project exits 0.
    """
    assert_on_page(EXIT_CODES, "| 1 | A rule could not be evaluated |")
    assert_on_page(
        EXIT_CODES,
        "Workspace mode does not check for rules that could not be evaluated.",
    )
    path = _plugin_path(tmp_path, "page_claim_scanners", _UNEVALUATING_PLUGIN)
    project = tmp_path / "workspace" / "api"
    project.mkdir(parents=True)
    (project / "main.py").write_text(
        'def handler():\n    return "ok"\n', encoding="utf-8"
    )
    workspace = tmp_path / "workspace" / "services.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    plugin_args = [
        "--ash-plugin-modules",
        "page_claim_scanners",
        "--scanners",
        "unevaluating",
    ]

    alone = _ash(
        [
            "scan",
            "--source-dir",
            str(project),
            "--output-dir",
            str(tmp_path / "alone"),
            *plugin_args,
            "--offline",
            "--no-progress",
        ],
        cwd=tmp_path,
        PYTHONPATH=path,
    )
    assert alone.returncode == 1, _output_tail(alone)
    assert "PAGE-CLAIM-1" in _normalize(alone.stdout + alone.stderr), _output_tail(
        alone
    )

    in_a_workspace = _ash(
        [
            "scan",
            "--workspace",
            str(workspace),
            "--output-dir",
            str(tmp_path / "workspace-output"),
            *plugin_args,
            "--offline",
            "--no-progress",
        ],
        cwd=tmp_path,
        PYTHONPATH=path,
    )
    assert in_a_workspace.returncode == 0, _output_tail(in_a_workspace)


# --------------------------------------------------------------------------- #
# MCP error types: the page half
# --------------------------------------------------------------------------- #

#: (error type, page, a sentence that names it). The values the MCP tools return are
#: held to the generated tool reference by its own check; this holds the prose to its
#: wording, so a rename on one side shows up on the other.
_ERROR_TYPE_SENTENCES = [
    (
        "output_dir_not_permitted",
        MCP_SERVER,
        (
            "If `.ash` or `.ash/ash_output` in the scanned directory is a symbolic link, "
            "`run_ash_scan` refuses before the scan starts, with `error_type` "
            "`output_dir_not_permitted`."
        ),
    ),
    (
        "output_dir_not_permitted",
        STEERING_GUIDE,
        (
            "| `output_dir_not_permitted` | `.ash` or `.ash/ash_output` in the project is a "
            "symbolic link. Ask the user to replace it with a directory. |"
        ),
    ),
    *(
        (
            error_type,
            MCP_SERVER,
            (
                "`run_ash_scan` also refuses before the scan starts when `source_dir` is a "
                "file, with `error_type` `source_dir_not_usable`, and when `.ash/ash_output` "
                "in it is a file or a directory the server cannot write, with `error_type` "
                "`output_dir_not_usable`."
            ),
        )
        for error_type in ("source_dir_not_usable", "output_dir_not_usable")
    ),
    *(
        (
            error_type,
            MCP_SERVER,
            (
                "A path that holds a NUL character is refused before the server looks it "
                "up, with `exit_code` 5: a `source_dir` is refused with "
                "`source_dir_not_usable`, and the `output_dir` of `run_ash_workspace_scan`, "
                "`get_scan_results`, `get_scan_summary` or `get_scan_result_paths` is "
                "refused with `output_dir_not_usable`."
            ),
        )
        for error_type in ("source_dir_not_usable", "output_dir_not_usable")
    ),
    ("config_field_denied", MCP_SERVER, _DENIED_INTRO),
    (
        "config_field_denied",
        MCP_SERVER,
        (
            "A file whose own `sandbox` section or `ash_plugin_modules` list asks for more in "
            "one of these ways is refused with `config_field_denied`, naming the setting;"
        ),
    ),
    (
        "config_field_denied",
        TRUST_MODEL,
        (
            "The error names each field, the MCP tools report it with "
            "`error_type: config_field_denied`, and on the CLI it is a configuration error "
            "(exit 3)."
        ),
    ),
    (
        "config_field_denied",
        STEERING_GUIDE,
        (
            "if it sets a field the server does not let clients set, such as "
            "`fail_on_findings`, the scan is refused with `error_type` `config_field_denied` "
            "and a message naming the field."
        ),
    ),
    (
        "config_field_denied",
        STEERING_GUIDE,
        (
            "| `config_field_denied` | A delivered config sets a field the server does not let "
            "clients set. Remove the field it names. |"
        ),
    ),
    (
        "config_policy_unreadable",
        MCP_SERVER,
        (
            "If the policy itself cannot be loaded, because the file `ASH_CONFIG` names exists "
            "but does not load, or has two sections that ASH reads as the same plugin, a config "
            "with an MCP-client file is refused with `config_policy_unreadable`."
        ),
    ),
    (
        "config_policy_unreadable",
        TRUST_MODEL,
        (
            "If the policy itself cannot be read, because the file `ASH_CONFIG` names exists "
            "but does not load, or has two sections that ASH reads as the same plugin, a config "
            "with an MCP-client file is refused with `config_policy_unreadable`."
        ),
    ),
    (
        "config_env_not_resolved",
        MCP_SERVER,
        (
            "`run_ash_scan` and `get_config`, with or without `raw`, return `error_type` "
            "`config_env_not_resolved`, and `run_ash_scan` does not start the scan; "
            "`validate_config` reports an error of that type."
        ),
    ),
    (
        "denied_by_runtime_policy",
        MCP_SERVER,
        (
            "`validate_config` reports each such field as an error of type "
            "`denied_by_runtime_policy`; for `config_content`, only when a remote client calls "
            "it."
        ),
    ),
]


@pytest.mark.parametrize(
    "error_type, page, sentence",
    _ERROR_TYPE_SENTENCES,
    ids=[f"{error}-{page.split('/')[-1]}" for error, page, _ in _ERROR_TYPE_SENTENCES],
)
@pytest.mark.unit
def test_the_pages_say_which_error_type_each_mcp_refusal_returns(
    error_type: str, page: str, sentence: str
) -> None:
    """mcp-server.md (How the server runs scans; What a delivered config cannot set);
    trust-model.md (When a lower tier sets something it may not); genai-steering-guide.md
    (When the server is remote; Errors).

    The page half of the claim only. That each value is one the MCP tools return is
    checked against the tools' own ``error_type`` literals, in the generated tool
    reference.
    """
    assert error_type in sentence
    assert_on_page(page, sentence)


# --------------------------------------------------------------------------- #
# Output files: what a scan writes, and how the results files are written
# --------------------------------------------------------------------------- #

_OUTPUTS_PAGE = "reference/output-files.md"
_OUTPUTS_REPORTER_PAGE = "plugins/write-a-reporter.md"

#: The docs examples' sample project: one hardcoded password, which detect-secrets
#: reports, so a detect-secrets scan of it exits 2.
_OUTPUTS_APP = (
    "import subprocess\n\n"
    'DATABASE_PASSWORD = "correct-horse-battery-staple-1234"\n\n\n'
    "def run(command):\n"
    "    return subprocess.call(command, shell=True)\n"
)
_OUTPUTS_CLEAN_APP = "print('hello')\n"


def _outputs_project(
    parent: Path, *, secret: bool = True, config: str | None = None
) -> Path:
    """A source tree under ``parent``: the sample's app.py, and ``config`` as its
    ``.ash/.ash.yaml`` when given."""
    source = parent / "source"
    source.mkdir(parents=True)
    (source / "app.py").write_text(
        _OUTPUTS_APP if secret else _OUTPUTS_CLEAN_APP, encoding="utf-8"
    )
    if config is not None:
        (source / ".ash").mkdir()
        (source / ".ash" / ".ash.yaml").write_text(config, encoding="utf-8")
    return source


def _outputs_scan(
    source: Path, *extra: str, scanners: str = "detect-secrets", **env: str
) -> subprocess.CompletedProcess:
    """``ash scan`` of ``source`` with the selected scanners, offline, run from its parent."""
    args = ["scan", "--source-dir", str(source), "--scanners", scanners]
    return _ash([*args, "--offline", "--no-progress", *extra], cwd=source.parent, **env)


def _outputs_dir(source: Path) -> Path:
    """The default output directory, ``<source-dir>/.ash/ash_output``."""
    return source / ".ash" / "ash_output"


def _outputs_results(source: Path) -> Dict[str, Any]:
    path = _outputs_dir(source) / "ash_aggregated_results.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def outputs_default_scan(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The output directory of one detect-secrets scan of the sample project."""
    source = _outputs_project(tmp_path_factory.mktemp("outputs-default-scan"))
    result = _outputs_scan(source)
    assert result.returncode == 2, (
        f"exit {result.returncode}, expected 2:\n{_output_tail(result)}"
    )
    return _outputs_dir(source)


def _outputs_layout() -> Tuple[List[str], List[str]]:
    """(top-level entries, entries of ``reports/``) of the tree in the Layout section."""
    section = _page_text(_OUTPUTS_PAGE).split("## Layout", 1)[1]
    block = section.split("```text", 1)[1].split("```", 1)[0]
    top: List[str] = []
    reports: List[str] = []
    for line in block.splitlines():
        entry = re.match(r"^[├└]── (\S+)", line)
        nested = re.match(r"^│   [├└]── (\S+)", line)
        if entry:
            top.append(entry.group(1))
        elif nested and top and top[-1] == "reports/":
            reports.append(nested.group(1))
    return top, reports


def _outputs_reports_table() -> List[Tuple[List[str], str, bool]]:
    """(files, reporter, enabled by default) for each row of the Reports table."""
    rows = _page_text(_OUTPUTS_PAGE).split("| File | Reporter | Enabled |", 1)[1]
    found = []
    for line in rows.splitlines()[2:]:
        if not line.startswith("|"):
            break
        files, reporter, enabled = (
            c.strip() for c in line.strip().strip("|").split("|")
        )
        assert enabled in ("yes", "no"), line
        name = re.search(r"\[`([^`]+)`\]", reporter)
        assert name, line
        found.append((re.findall(r"`([^`]+)`", files), name.group(1), enabled == "yes"))
    return found


def _outputs_reporter_files(plugin: type) -> Set[str]:
    """The files a reporter writes in ``reports/``: ``ash.<extension>`` (``ash.txt``
    without one), and each ``"ash.<name>"`` literal in its module, which is how a
    reporter names a file it writes beside its report."""
    config_class = typing.get_args(plugin.model_fields["config"].annotation)[0]
    extension = config_class().extension
    source = inspect.getsource(sys.modules[plugin.__module__])
    return {f"ash.{extension}" if extension else "ash.txt"} | set(
        re.findall(r"[\"'](ash\.[\w.\-]+)[\"']", source)
    )


@pytest.mark.integration
def test_a_default_scan_writes_the_files_and_reports_the_output_files_page_lists(
    outputs_default_scan: Path,
) -> None:
    """output-files.md (Layout; Reports).

    A detect-secrets scan of the sample project writes every top-level entry of the
    Layout tree, and ``reports/`` holds exactly the tree's report files, which are the
    Reports table's "yes" rows; its "no" rows (spdx and yaml) are not written. Which
    scanners ran changes ``scanners/`` but not ``reports/``. The table is also held to
    the code: it lists every built-in reporter once, with the file its extension
    names, any file its module names beside it, and its ``enabled`` default.
    """
    assert_on_page(
        _OUTPUTS_PAGE,
        "A scan of a project with Python, a CloudFormation template, and a GitHub Actions "
        "workflow, with every built-in scanner installed:",
    )
    assert_on_page(
        _OUTPUTS_PAGE,
        "`reports/` holds one file per enabled reporter, named `ash.<extension>`, or "
        "`ash.txt` for a reporter that declares no extension. The table lists the "
        "reporters ASH ships and whether each is enabled by default;",
    )
    from automated_security_helper.plugin_modules import ash_builtin

    top, listed = _outputs_layout()
    table = _outputs_reports_table()
    assert len(top) == 8 and len(listed) == 14 and len(table) == 15, (
        "the Layout tree or the Reports table no longer parses",
        top,
        listed,
        len(table),
    )

    for entry in top:
        path = outputs_default_scan / entry.rstrip("/")
        assert path.is_dir() if entry.endswith("/") else path.is_file(), entry
    written = sorted(p.name for p in (outputs_default_scan / "reports").iterdir())
    assert written == sorted(listed), set(written) ^ set(listed)
    for files, reporter, enabled in table:
        for name in files:
            assert (outputs_default_scan / "reports" / name).is_file() is enabled, (
                f"{reporter}: {name} is {'not ' if enabled else ''}written"
            )

    shipped = {}
    for plugin in ash_builtin.ASH_REPORTERS:
        config_class = typing.get_args(plugin.model_fields["config"].annotation)[0]
        shipped[config_class.model_fields["name"].default] = (plugin, config_class)
    listed_reporters = sorted(reporter for _, reporter, _ in table)
    assert listed_reporters == sorted(shipped), (
        "the Reports table and the built-in reporters differ: "
        f"{set(listed_reporters) ^ set(shipped)}"
    )
    for files, reporter, enabled in table:
        plugin, config_class = shipped[reporter]
        assert config_class.model_fields["enabled"].default is enabled, reporter
        assert files[0] == f"ash.{config_class().extension}", (reporter, files)
        assert set(files) <= _outputs_reporter_files(plugin), (reporter, files)


#: A file name ASH writes, as the pages write it: ``ash.sarif``, ``reports/ash.csv``,
#: ``.ash.yaml``.
_OUTPUTS_FILE_NAME = re.compile(r"(?<![\w.\-])(\.?ash\.[A-Za-z0-9][\w.\-]*[A-Za-z0-9])")

#: Repository files the pages name. By path: the test fixtures named ash.sarif must
#: not make a renamed report look like a file ASH has.
_OUTPUTS_REPOSITORY_FILES = (
    "Formula/ash.rb",
    "ash-agent-plugins/agentic-coding/plugins/mcpb/ash.mcpb",
)


def _outputs_known_file_names() -> Set[str]:
    """Every ``ash.*`` file name the code gives a file.

    Each reporter's files (built-in and plugin-module reporters), the logs
    (``<name>.log`` and ``<name>.log.jsonl``, named ``ash``), ``ash.txt`` for a
    reporter without an extension, the config file names ASH looks for, and the
    repository files above.
    """
    import automated_security_helper.plugin_modules as plugin_modules
    from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES

    known = {"ash.log", "ash.log.jsonl", "ash.txt", *ASH_CONFIG_FILE_NAMES}
    for module_info in pkgutil.iter_modules(plugin_modules.__path__):
        module = importlib.import_module(
            f"{plugin_modules.__name__}.{module_info.name}"
        )
        for plugin in getattr(module, "ASH_REPORTERS", []):
            known |= _outputs_reporter_files(plugin)
    for path in _OUTPUTS_REPOSITORY_FILES:
        assert (_code_root() / path).is_file(), f"{path} is not in the repository"
        known.add(Path(path).name)
    return known


def _outputs_prose_file_names(text: str) -> List[Tuple[int, str]]:
    """(line, name) for each ``ash.*`` file name outside the fenced blocks of ``text``."""
    found: List[Tuple[int, str]] = []
    fenced = False
    for number, line in enumerate(text.splitlines(), 1):
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            found += [(number, m.group(1)) for m in _OUTPUTS_FILE_NAME.finditer(line)]
    return found


@pytest.mark.unit
def test_every_report_file_name_the_pages_mention_is_one_ash_writes() -> None:
    """output-files.md (Reports), and every page that names an output file.

    Each ``ash.*`` file name in the prose of the site's pages, outside fenced blocks,
    must be one the code gives a file: a reporter's ``ash.<extension>`` or a file its
    module names, the logs, a config file name, a repository file the pages name, or
    the file of a reporter the same page's own example declares. So renaming a
    report's extension fails here wherever a page still uses the old name. The
    control is the matcher itself, on a line with a misspelled name and two real ones.
    """
    assert_on_page(
        _OUTPUTS_PAGE,
        "`reports/` holds one file per enabled reporter, named `ash.<extension>`, or "
        "`ash.txt` for a reporter that declares no extension.",
    )
    known = _outputs_known_file_names()
    sample = "`ash.sarf`, `.ash/ash_output/ash.log`, and `.ash.yaml`"
    assert [name for _, name in _outputs_prose_file_names(sample)] == [
        "ash.sarf",
        "ash.log",
        ".ash.yaml",
    ]
    assert "ash.sarf" not in known and {"ash.log", ".ash.yaml"} <= known

    checked, unknown = 0, []
    for page in sorted(CONTENT.rglob("*.md")):
        text = page.read_text(encoding="utf-8")
        declared = {
            f"ash.{extension}"
            for extension in re.findall(r'extension: str = "([^"]+)"', text)
        }
        for number, name in _outputs_prose_file_names(text):
            checked += 1
            if name not in known | declared:
                unknown.append(
                    f"{page.relative_to(CONTENT).as_posix()}:{number}: {name}"
                )
    assert checked > 100, f"only {checked} file names found; the matcher broke"
    assert not unknown, "no file ASH writes has these names:\n" + "\n".join(unknown)


_OUTPUTS_STALE = "left by an earlier run\n"
_OUTPUTS_WORKING_DIRS = ("analysis", "reports", "scanners", "converted")
_OUTPUTS_RESULT_FILES = (
    "ash_aggregated_results.json",
    "ash-ignore-report.txt",
    "ash-scan-set-files-list.txt",
)


def _outputs_plant_previous_run(output: Path) -> None:
    for directory in _OUTPUTS_WORKING_DIRS:
        (output / directory).mkdir(parents=True, exist_ok=True)
        (output / directory / "stale.txt").write_text(_OUTPUTS_STALE, encoding="utf-8")
    for name in (*_OUTPUTS_RESULT_FILES, "ash.log"):
        (output / name).write_text(_OUTPUTS_STALE, encoding="utf-8")


def _outputs_left_over(output: Path) -> List[str]:
    """What is still there of a planted previous run."""
    left = [
        f"{directory}/stale.txt"
        for directory in _OUTPUTS_WORKING_DIRS
        if (output / directory / "stale.txt").exists()
    ]
    return left + [
        name
        for name in (*_OUTPUTS_RESULT_FILES, "ash.log")
        if (output / name).is_file()
        and _OUTPUTS_STALE.strip() in (output / name).read_text(encoding="utf-8")
    ]


@pytest.mark.integration
def test_a_scan_replaces_everything_the_previous_run_left(tmp_path: Path) -> None:
    """output-files.md (Each scan replaces the last).

    A previous run is planted in the output directory: a file in each working
    directory, and old text in the three result files and ``ash.log``. A scan leaves
    none of it. A scan of the report phase alone (``--phases report``) does not build
    the scan set, so the two scan-set files it leaves absent were deleted, not
    overwritten. The control is ``--use-existing``, which the same section says leaves
    ``scanners/`` in place: a file planted there survives it.
    """
    assert_on_page(
        _OUTPUTS_PAGE,
        "Before a scan writes anything, ASH removes and recreates `analysis/`, `reports/`, "
        "`scanners/`, and `converted/`, and deletes `ash_aggregated_results.json`, "
        "`ash-ignore-report.txt`, and `ash-scan-set-files-list.txt`. `ash.log` is "
        "truncated when the logger opens it.",
    )
    assert_on_page(
        _OUTPUTS_PAGE,
        "leaves `scanners/` and the other files in place, and exits with the verdict of "
        "the stored results.",
    )

    full = _outputs_project(tmp_path / "full")
    _outputs_plant_previous_run(_outputs_dir(full))
    result = _outputs_scan(full)
    assert result.returncode == 2, _output_tail(result)
    assert _outputs_left_over(_outputs_dir(full)) == []

    report_only = _outputs_project(tmp_path / "report-only")
    _outputs_plant_previous_run(_outputs_dir(report_only))
    result = _outputs_scan(report_only, "--phases", "report")
    assert result.returncode == 0, _output_tail(result)
    assert _outputs_left_over(_outputs_dir(report_only)) == []
    for name in ("ash-ignore-report.txt", "ash-scan-set-files-list.txt"):
        assert not (_outputs_dir(report_only) / name).exists(), name

    (_outputs_dir(full) / "scanners" / "stale.txt").write_text(
        _OUTPUTS_STALE, encoding="utf-8"
    )
    result = _outputs_scan(full, "--use-existing")
    assert result.returncode == 2, _output_tail(result)
    assert _outputs_left_over(_outputs_dir(full)) == ["scanners/stale.txt"]


def _outputs_leaves(value: Any, path: str = "") -> Dict[str, Any]:
    """{JSON pointer: value} for every scalar in ``value``."""
    if isinstance(value, dict):
        items: Iterable[Tuple[Any, Any]] = value.items()
    elif isinstance(value, list):
        items = enumerate(value)
    else:
        return {path: value}
    leaves: Dict[str, Any] = {}
    for key, item in items:
        leaves.update(_outputs_leaves(item, f"{path}/{key}"))
    return leaves


@pytest.mark.integration
def test_the_sarif_member_writes_every_field_and_ash_sarif_leaves_out_what_ash_did_not_set(
    outputs_default_scan: Path,
) -> None:
    """output-files.md (SARIF).

    From one detect-secrets scan: each result in the ``sarif`` member of
    ``ash_aggregated_results.json`` has ``ruleIndex`` -1 and ``rule`` null, and the
    same result in ``reports/ash.sarif`` has neither. Every value
    ``reports/ash.sarif`` holds is the member's value at the same place, which is
    what makes them the same run written two ways; the control is that the report is
    not nearly empty, so that comparison is not made over nothing.
    """
    assert_on_page(
        _OUTPUTS_PAGE,
        "`reports/ash.sarif` and the `sarif` member of `ash_aggregated_results.json` hold "
        "the same SARIF 2.1.0 run, written two ways. The member writes every field of "
        'every result, defaults included, so its results show `"ruleIndex": -1`, and '
        '`"rule": null` unless the scanner gave one. `reports/ash.sarif` leaves out the '
        "fields ASH did not set, `ruleIndex` among them, and the empty ones,",
    )
    member = json.loads(
        (outputs_default_scan / "ash_aggregated_results.json").read_text(
            encoding="utf-8"
        )
    )["sarif"]
    report = json.loads(
        (outputs_default_scan / "reports" / "ash.sarif").read_text(encoding="utf-8")
    )
    in_member = member["runs"][0]["results"]
    in_report = report["runs"][0]["results"]
    assert in_member and len(in_member) == len(in_report), (in_member, in_report)
    for result in in_member:
        assert result["ruleIndex"] == -1 and result["rule"] is None, result
    for result in in_report:
        assert "ruleIndex" not in result and "rule" not in result, result

    member_leaves, report_leaves = _outputs_leaves(member), _outputs_leaves(report)
    assert len(report_leaves) > 20, "reports/ash.sarif is nearly empty"
    differ = {
        pointer: (member_leaves.get(pointer, "<absent>"), value)
        for pointer, value in report_leaves.items()
        if member_leaves.get(pointer, "<absent>") != value
    }
    assert not differ, f"(member, reports/ash.sarif) differ at: {differ}"


@pytest.mark.unit
def test_ash_sarif_points_each_result_at_its_rule_in_its_scanners_extension(
    tmp_path: Path,
) -> None:
    """output-files.md (SARIF).

    The aggregated SARIF is built as the scan engine builds it, by merging one bandit
    run whose driver defines two rules, saved as the engine saves the results, and
    rendered by the sarif reporter. The rendered result names its rule by extension
    and position; the saved member keeps ``rule`` null, which is the control that the
    reference is the report's and not the model's.
    """
    assert_on_page(_OUTPUTS_PAGE, "and adds each result's `rule` reference (below).")
    assert_on_page(
        _OUTPUTS_PAGE,
        "In `reports/ash.sarif`, a result whose rule its scanner's extension defines "
        "carries `rule`, as SARIF asks for rules defined in an extension: "
        "`rule.toolComponent` gives the extension's `name` and its `index` in "
        "`tool.extensions`, and `rule.index` is the rule's position in that extension's "
        "`rules`.",
    )
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
        SarifReporter,
    )
    from automated_security_helper.schemas.sarif_schema_model import SarifReport

    finding = {**_bandit_finding("B602", "app.py"), "ruleIndex": 1}
    bandit = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "bandit",
                            "rules": [{"id": "B101"}, {"id": "B602"}],
                        }
                    },
                    "results": [finding],
                }
            ],
        }
    )
    model = AshAggregatedResults()
    model.sarif.merge_sarif_report(bandit)
    model.save_model(tmp_path)
    saved = json.loads(
        (tmp_path / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    context = PluginContext(
        source_dir=tmp_path, output_dir=tmp_path, config=AshConfig(project_name="rules")
    )
    rendered = json.loads(SarifReporter(context=context).report(model))
    result = _one(rendered["runs"][0]["results"], "result in reports/ash.sarif")
    assert result.get("rule") == {
        "id": "B602",
        "index": 1,
        "toolComponent": {"name": "bandit", "index": 0},
    }, result
    assert "ruleIndex" not in result, result
    assert saved["sarif"]["runs"][0]["results"][0]["rule"] is None


#: A plugin module with a reporter that raises, listed before one that writes.
_OUTPUTS_FAILING_REPORTER = """\
from typing import Literal

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class _Options(ReporterOptionsBase):
    pass


class RaisesConfig(ReporterPluginConfigBase):
    name: Literal["page-claims-raises"] = "page-claims-raises"
    extension: str = "page-claims-raises.txt"
    enabled: bool = True
    options: _Options = _Options()


class WritesConfig(ReporterPluginConfigBase):
    name: Literal["page-claims-writes"] = "page-claims-writes"
    extension: str = "page-claims-writes.txt"
    enabled: bool = True
    options: _Options = _Options()


@ash_reporter_plugin
class RaisingReporter(ReporterPluginBase[RaisesConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = RaisesConfig()
        super().model_post_init(context)

    def report(self, model):
        raise RuntimeError("the page-claims reporter failed")


@ash_reporter_plugin
class WritingReporter(ReporterPluginBase[WritesConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = WritesConfig()
        super().model_post_init(context)

    def report(self, model):
        return "written\\n"


ASH_REPORTERS = [RaisingReporter, WritingReporter]
"""


@pytest.mark.parametrize(
    "secret, verdict",
    [
        pytest.param(True, 2, id="a-finding-still-fails-the-scan"),
        pytest.param(False, 0, id="no-finding-still-passes"),
    ],
)
@pytest.mark.integration
def test_a_reporter_that_fails_does_not_change_the_exit_code(
    tmp_path: Path, secret: bool, verdict: int
) -> None:
    """output-files.md (Reports) and write-a-reporter.md (What ASH does with the return
    value).

    A plugin module, loaded with ``--ash-plugin-modules``, has a reporter that raises
    and, after it, one that writes. The scan's exit code is the findings' verdict, 2
    with the sample's password and 0 without it; the error is in ash.log and the
    failing reporter's file is absent. The control is the second reporter's file: it
    shows the module was loaded and the report phase went on past the failure.
    """
    assert_on_page(
        _OUTPUTS_PAGE,
        "A reporter that fails logs an error and leaves its file out; it does not change "
        "the exit code.",
    )
    assert_on_page(
        _OUTPUTS_REPORTER_PAGE,
        "| raises an exception | the error is logged and the other reporters still run |",
    )
    assert_on_page(
        _OUTPUTS_REPORTER_PAGE,
        "None of these changes the scan's exit code, which is decided by the findings "
        "and by whether the scan was complete.",
    )
    source = _outputs_project(tmp_path, secret=secret)
    result = _outputs_scan(
        source,
        "--ash-plugin-modules",
        "page_claims_reporters_ash_plugins",
        PYTHONPATH=_plugin_path(
            tmp_path, "page_claims_reporters_ash_plugins", _OUTPUTS_FAILING_REPORTER
        ),
    )
    reports = _outputs_dir(source) / "reports"
    assert (reports / "ash.page-claims-writes.txt").is_file(), _output_tail(result)
    assert not (reports / "ash.page-claims-raises.txt").exists()
    log = (_outputs_dir(source) / "ash.log").read_text(encoding="utf-8")
    assert "the page-claims reporter failed" in log
    assert result.returncode == verdict, (
        f"exit {result.returncode}, expected {verdict}:\n{_output_tail(result)}"
    )


@pytest.mark.parametrize(
    "config, environment, expected",
    [
        pytest.param(
            "project_name: from-the-config\n",
            {"ASH_PROJECT_NAME": "from-the-environment"},
            "from-the-config",
            id="the-config-first",
        ),
        pytest.param(
            None,
            {"ASH_PROJECT_NAME": "from-the-environment"},
            "from-the-environment",
            id="then-the-environment",
        ),
        pytest.param(None, {}, "ash-scan", id="else-ash-scan"),
    ],
)
@pytest.mark.integration
def test_the_results_metadata_names_the_configured_project(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config: str | None,
    environment: Dict[str, str],
    expected: str,
) -> None:
    """output-files.md (``ash_aggregated_results.json``).

    ``metadata.project_name`` after a scan: the config's ``project_name`` when the
    tree's config sets one, even with ``ASH_PROJECT_NAME`` set; else that variable;
    else ``ash-scan``. Each case is the control for the others, since each gives a
    different name.
    """
    assert_on_page(
        _OUTPUTS_PAGE,
        "`project_name` (the config's `project_name`, else the `ASH_PROJECT_NAME` "
        "environment variable, else `ash-scan`)",
    )
    monkeypatch.delenv("ASH_PROJECT_NAME", raising=False)
    source = _outputs_project(tmp_path, config=config)
    result = _outputs_scan(source, **environment)
    assert result.returncode == 2, _output_tail(result)
    assert _outputs_results(source)["metadata"]["project_name"] == expected


#: A plugin module with a scanner whose tool is nowhere: it is MISSING in any scan
#: that selects it, on any machine.
_OUTPUTS_ABSENT_TOOL_SCANNER = """\
from typing import Literal

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.plugins.decorators import ash_scanner_plugin


class _Options(ScannerOptionsBase):
    pass


class AbsentToolConfig(ScannerPluginConfigBase):
    name: Literal["page-claims-absent-tool"] = "page-claims-absent-tool"
    enabled: bool = True
    options: _Options = _Options()


@ash_scanner_plugin
class AbsentToolScanner(ScannerPluginBase[AbsentToolConfig]):
    command: str = "page-claims-absent-tool"
    tool_type: ScannerToolType = ScannerToolType.SAST

    def model_post_init(self, context):
        if self.config is None:
            self.config = AbsentToolConfig()
        super().model_post_init(context)

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise AssertionError("the tool is absent, so the scan never runs it")


ASH_SCANNERS = [AbsentToolScanner]
"""


@pytest.mark.integration
def test_scanner_rows_say_whether_the_tool_was_found_was_left_out_and_how_it_exited(
    tmp_path: Path,
) -> None:
    """output-files.md (Scanner rows).

    One scan selects detect-secrets and a plugin scanner whose tool does not exist,
    so that row is MISSING wherever the test runs; bandit is left out by
    ``--scanners``. The MISSING row has ``dependencies_satisfied`` false, no exit
    code and a ``missing_reason``; bandit's has ``excluded`` true, no exit code and
    the reason ``--scanners`` gives. The control is detect-secrets' row, which ran:
    its tool was found, it was not left out, and it has an exit code.
    """
    for sentence in (
        "| `dependencies_satisfied` | `false` on a `MISSING` row. |",
        (
            "| `excluded` | `true` when the run left the scanner out: `--scanners`, "
            "`--exclude-scanners`, `enabled: false`, `--python-only`, the shard split, "
            "or a platform it does not support. |"
        ),
        (
            "| `exit_code` | The tool's exit code, the highest over the targets it ran "
            "on, or `null` when no tool ran: a `MISSING` or excluded scanner, one that "
            "had nothing to scan, or one that started no tool for its targets. |"
        ),
        (
            "| `missing_reason` | On a `MISSING` row, why: the tool that was not found "
            "and where ASH looked,"
        ),
        (
            "| `skipped_reason` | On a `SKIPPED` row, why: the option that left it out, "
            "such as `not named by --scanners`,"
        ),
    ):
        assert_on_page(_OUTPUTS_PAGE, sentence)
    source = _outputs_project(tmp_path)
    result = _outputs_scan(
        source,
        "--ash-plugin-modules",
        "page_claims_scanners",
        scanners="detect-secrets,page-claims-absent-tool",
        PYTHONPATH=_plugin_path(
            tmp_path, "page_claims_scanners", _OUTPUTS_ABSENT_TOOL_SCANNER
        ),
    )
    rows = _outputs_results(source)["scanner_results"]
    assert "page-claims-absent-tool" in rows, _output_tail(result)
    missing, bandit, ran = (
        rows["page-claims-absent-tool"],
        rows["bandit"],
        rows["detect-secrets"],
    )
    assert missing["status"] == "MISSING", missing
    assert missing["dependencies_satisfied"] is False, missing
    assert missing["excluded"] is False and missing["exit_code"] is None, missing
    assert "page-claims-absent-tool" in (missing.get("missing_reason") or ""), missing
    assert bandit["status"] == "SKIPPED" and bandit["excluded"] is True, bandit
    assert bandit["exit_code"] is None, bandit
    assert bandit.get("skipped_reason") == "not named by --scanners", bandit
    assert ran["dependencies_satisfied"] is True and ran["excluded"] is False, ran
    assert isinstance(ran["exit_code"], int), ran


# --------------------------------------------------------------------------- #
# Config checks, content database bounds, offline mode, and how a scan ends
# --------------------------------------------------------------------------- #

_OFFLINE_PAGE = "how-to/run-offline.md"
_OFFLINE_CDB_PAGE = "concepts/content-databases.md"
_CONFIG_LOCAL_PAGE = "getting-started/local.md"
_CONFIG_AGENTS_PAGE = "getting-started/agents.md"
_CONFIG_PLATFORM_PAGE = "getting-started/platform-teams.md"

#: A line detect-secrets reports as SECRET-SECRET-KEYWORD, the finding the pages scan for.
_CONFIG_SECRET = 'DATABASE_PASSWORD = "correct-horse-battery-staple-1234"\n'

#: The scan the pages run: detect-secrets only, which ships with ASH and needs no network.
_CONFIG_SCAN = ["scan", "--scanners", "detect-secrets", "--no-progress"]


def _config_scan_tree(parent: Path, files: Dict[str, str]) -> Path:
    """A source tree ``parent/source`` holding ``files`` (relative path: text)."""
    tree = parent / "source"
    tree.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (tree / name).parent.mkdir(parents=True, exist_ok=True)
        (tree / name).write_text(text, encoding="utf-8")
    return tree


def _config_scan_log(tree: Path) -> str:
    """The ash.log a scan of ``tree`` wrote into its default output directory."""
    log = tree / ".ash" / "ash_output" / "ash.log"
    return log.read_text(encoding="utf-8", errors="replace") if log.is_file() else ""


def _config_heredoc(page: str, target: str) -> str:
    """The text a ``cat > <target> <<'EOF'`` block on ``page`` writes, as written."""
    text = _page_text(page)
    opener = f"cat > {target} <<'EOF'\n"
    start = text.index(opener) + len(opener)
    return text[start : text.index("\nEOF", start)] + "\n"


def _config_yaml_block(page: str, heading: str) -> str:
    """The first ``yaml`` block under ``heading`` on ``page``, as written."""
    text = _page_text(page)
    start = text.index("```yaml\n", text.index(heading)) + len("```yaml\n")
    return text[start : text.index("```", start)]


# --------------------------------------------------------------------------- #
# ash config validate
# --------------------------------------------------------------------------- #

_CONFIG_VALIDATE_ROWS = (
    "| `ash config validate` | 0 | A scan accepts the config, apart from the options of "
    "plugins loaded from `ash_plugin_modules`, which only a scan checks. Warnings may be "
    "printed, for example for a missing `project_name`, which a scan does not need, or "
    "for an ignore or suppression path that names an existing directory and matches no "
    "file in it ([Check a config](../how-to/configure.md#check)). | "
    "| | 1 | No config file is found in the source directory and none is named: "
    "`validate` says so, and that a scan of that directory uses the default "
    "configuration. Also when an error occurred. | "
    "| | 3 | The named config path does not exist, is a directory, or cannot be read. A "
    "scan refuses the config: it does not parse, it or an override does not validate "
    "(one plugin's section written under two spellings included), its `extends` chain "
    "does not resolve, or `ash_plugin_modules` names a module a scan refuses. "
    "`validate` imports no plugin module, so two plugins whose names read as one pass "
    "it. |"
)

#: configure.md (Check a config): which checks take --config-overrides, and in what order.
_CHECK_TAKES_OVERRIDES = (
    "`validate` and `get` also take `--config-overrides` and check the config with them "
    "applied, as a scan given the same overrides does. An override does not make a file "
    "that a scan refuses valid: the file is checked on its own before the overrides "
    "apply."
)

_CONFIG_ACCEPTED = "project_name: demo\nglobal_settings:\n  severity_threshold: HIGH\n"


@pytest.mark.parametrize(
    "files, args, verdict, scan_refuses, shown",
    [
        pytest.param(
            {"ash.yaml": _CONFIG_ACCEPTED},
            ["--config", "ash.yaml"],
            0,
            False,
            ["Configuration is valid! A scan accepts it."],
            id="control-a-config-a-scan-accepts",
        ),
        pytest.param(
            {"ash.yaml": "global_settings:\n  severity_threshold: HIGH\n"},
            ["--config", "ash.yaml"],
            0,
            False,
            ["project_name", "Configuration is valid! A scan accepts it."],
            id="no-project-name-is-only-a-warning",
        ),
        pytest.param(
            {
                "ash.yaml": "project_name: demo\nglobal_settings:\n  severity_threshold: high\n"
            },
            ["--config", "ash.yaml"],
            3,
            True,
            ["global_settings.severity_threshold"],
            id="a-value-that-does-not-validate",
        ),
        pytest.param(
            {"ash.yaml": _CONFIG_ACCEPTED},
            [
                "--config",
                "ash.yaml",
                "--config-overrides",
                "global_settings.severity_threshold=high",
            ],
            3,
            True,
            ["global_settings.severity_threshold"],
            id="an-override-that-does-not-validate",
        ),
        pytest.param(
            {
                "ash.yaml": "project_name: demo\nglobal_settings:\n  severity_threshold: high\n"
            },
            [
                "--config",
                "ash.yaml",
                "--config-overrides",
                "global_settings.severity_threshold=HIGH",
            ],
            3,
            True,
            ["global_settings.severity_threshold"],
            id="an-override-does-not-make-a-refused-file-valid",
        ),
        pytest.param(
            {"ash.yaml": _CONFIG_ACCEPTED},
            [
                "--config",
                "ash.yaml",
                "--config-overrides",
                "global_settings.severity_threshold=LOW",
            ],
            0,
            False,
            ["Configuration is valid! A scan accepts it."],
            id="control-an-override-that-validates",
        ),
        pytest.param(
            {
                "ash.yaml": "project_name: demo\nash_plugin_modules:\n"
                "  - not_a_plugin_namespace_module\n"
            },
            ["--config", "ash.yaml"],
            3,
            None,
            ["ash_plugin_modules", "not_a_plugin_namespace_module"],
            id="a-plugin-module-name-a-scan-refuses",
        ),
        pytest.param(
            {"ash.yaml": "extends: ./no-such-base.yaml\nproject_name: demo\n"},
            ["--config", "ash.yaml"],
            3,
            True,
            [],
            id="an-extends-chain-that-does-not-resolve",
        ),
        pytest.param(
            {"ash.yaml": "global_settings: [unclosed\n"},
            ["--config", "ash.yaml"],
            3,
            True,
            [],
            id="a-file-that-does-not-parse",
        ),
        pytest.param(
            {}, ["--config", "no-such-config.yaml"], 3, None, [], id="a-missing-path"
        ),
        pytest.param(
            {".ash/.ash.yaml": _CONFIG_ACCEPTED},
            ["--config", ".ash"],
            3,
            None,
            [],
            id="a-path-that-is-a-directory",
        ),
        pytest.param(
            {},
            [],
            1,
            None,
            ["No config file found", "uses the default configuration"],
            id="no-config-file-found",
        ),
    ],
)
@pytest.mark.integration
def test_config_validate_exits_with_the_code_a_scan_would_give_the_config(
    tmp_path: Path,
    files: Dict[str, str],
    args: List[str],
    verdict: int,
    scan_refuses: bool | None,
    shown: List[str],
) -> None:
    """exit-codes.md (ash config) and configure.md (Check a config).

    ``ash config validate`` runs on each config the table's rows describe and must exit
    as the row says, naming what it refuses. Where a scan reads the file, the file is
    also resolved the way a scan resolves it, and a scan refuses it exactly when
    validate exits 3, a file that does not parse included, and a file whose invalid
    value an override would replace. A plugin module name is checked by the scan
    before it resolves the config, so that case is not resolved here. The controls are
    a config a scan accepts, with and without an override that validates, which exit 0.
    """
    assert_on_page(EXIT_CODES, _CONFIG_VALIDATE_ROWS)
    assert_on_page(CONFIGURE, _CHECK_TAKES_OVERRIDES)
    assert_on_page(
        EXIT_CODES,
        "The named config path is the one `--config`, `ASH_CONFIG`, or the path argument "
        "of `get`, `update`, and `validate-plugin-dependencies` gives.",
    )
    tree = _config_scan_tree(tmp_path, files)
    result = _ash(["config", "validate", *args], cwd=tree)
    output = result.stdout + result.stderr
    assert result.returncode == verdict, (
        f"exit {result.returncode}, expected {verdict}:\n{_output_tail(result)}"
    )
    for text in shown:
        assert text in output, f"{text!r} is not in the output:\n{_output_tail(result)}"

    if scan_refuses is None:
        return
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    overrides = (
        args[args.index("--config-overrides") + 1 :]
        if "--config-overrides" in args
        else []
    )
    try:
        resolve_config(
            config_path=tree / args[1], source_dir=tree, config_overrides=overrides
        )
        refused = False
    except ASHConfigValidationError:
        refused = True
    assert refused is scan_refuses, (
        f"a scan {'refuses' if refused else 'accepts'} this config"
    )


@pytest.mark.parametrize(
    "command, verdict",
    [
        pytest.param("validate", 3, id="validate-applies-it"),
        pytest.param("get", 3, id="get-applies-it"),
        pytest.param("lint", None, id="lint-has-no-such-option"),
    ],
)
@pytest.mark.integration
def test_validate_and_get_take_config_overrides_and_lint_does_not(
    tmp_path: Path, command: str, verdict: int | None
) -> None:
    """configure.md (Check a config).

    Given an override that does not validate, ``validate`` and ``get`` apply it and
    exit 3, and ``lint``, which has no ``--config-overrides``, refuses the option as
    unknown. The usage error's code is pinned with the other usage errors, so only
    a failing exit is asserted for it here. The control is each command on the same
    file with no override, which exits 0.
    """
    assert_on_page(CONFIGURE, _CHECK_TAKES_OVERRIDES)
    tree = _config_scan_tree(tmp_path, {"ash.yaml": _CONFIG_ACCEPTED})
    control = _ash(["config", command, "--config", "ash.yaml"], cwd=tree)
    assert control.returncode == 0, _output_tail(control)

    result = _ash(
        [
            "config",
            command,
            "--config",
            "ash.yaml",
            "--config-overrides",
            "global_settings.severity_threshold=high",
        ],
        cwd=tree,
    )
    output = result.stdout + result.stderr
    if verdict is None:
        assert result.returncode not in (0, 3), _output_tail(result)
        assert "No such option: --config-overrides" in output, _output_tail(result)
        return
    assert result.returncode == verdict, (
        f"exit {result.returncode}, expected {verdict}:\n{_output_tail(result)}"
    )
    assert "global_settings.severity_threshold" in output, _output_tail(result)


#: exit-codes.md (ash config): an ASH_CONFIG that names no file, beside a named file.
_A_MISSING_ASH_CONFIG_BESIDE_A_NAMED_FILE = (
    "An `ASH_CONFIG` that names a file that does not exist exits 3 from `get`, "
    "`validate`, `lint`, and `validate-plugin-dependencies` even when `--config` or the "
    "path argument names a file that loads, since a scan refuses that pair too."
)
#: configure.md (Check a config): the same, for the three check commands.
_CHECK_REFUSES_A_MISSING_ASH_CONFIG = (
    "An `ASH_CONFIG` that names a file that does not exist makes each of them exit 3, "
    "also beside a `--config` file that loads, as it stops a scan."
)


@pytest.mark.parametrize(
    "ash_config",
    ["no-such-config.yaml", None],
    ids=["a-missing-ash-config", "control-no-ash-config"],
)
@pytest.mark.parametrize(
    "command, named_by",
    [
        pytest.param("get", "path", id="get-path-argument"),
        pytest.param("get", "--config", id="get-config-option"),
        pytest.param("validate", "--config", id="validate"),
        pytest.param("lint", "--config", id="lint"),
        pytest.param(
            "validate-plugin-dependencies", "path", id="validate-plugin-dependencies"
        ),
        pytest.param(
            "validate-plugin-dependencies",
            "nothing",
            id="validate-plugin-dependencies-no-path",
        ),
    ],
)
@pytest.mark.integration
def test_config_commands_refuse_an_ash_config_naming_no_file_beside_one_that_loads(
    tmp_path: Path, command: str, named_by: str, ash_config: Optional[str]
) -> None:
    """exit-codes.md (ash config) and configure.md (Check a config).

    Each command is given ``named.yaml``, the file exit-codes.md's example writes, by
    ``--config`` or as its path argument, with ``ASH_CONFIG`` naming a file that does
    not exist. Each must exit 3. The control is the same command with no
    ``ASH_CONFIG``: the named file loads, and the command exits 0.
    ``validate-plugin-dependencies`` also runs with no path, where no config file is
    found: it exits 3 for the ``ASH_CONFIG``, and its control exits 1, as it does
    when there is no config to resolve.
    """
    assert_on_page(EXIT_CODES, _A_MISSING_ASH_CONFIG_BESIDE_A_NAMED_FILE)
    if command in ("get", "validate", "lint"):
        assert_on_page(CONFIGURE, _CHECK_REFUSES_A_MISSING_ASH_CONFIG)
    tree = _config_scan_tree(tmp_path, {"named.yaml": "project_name: payments-api\n"})
    named = {
        "path": ["named.yaml"],
        "--config": ["--config", "named.yaml"],
        "nothing": [],
    }[named_by]
    env = {} if ash_config is None else {"ASH_CONFIG": ash_config}

    result = _ash(["config", command, *named], cwd=tree, **env)

    expected = (1 if named_by == "nothing" else 0) if ash_config is None else 3
    assert result.returncode == expected, (
        f"exit {result.returncode}, expected {expected}:\n{_output_tail(result)}"
    )


# --------------------------------------------------------------------------- #
# A scan in which no selected scanner had a file to scan
# --------------------------------------------------------------------------- #

#: troubleshoot.md's quote of the error for bandit with no Python file to scan.
_NOTHING_TO_SCAN = (
    "No selected scanner had a file to scan: bandit was SKIPPED with nothing to scan, "
    "so this run has shown the target to be neither clean nor dirty. To accept a run "
    "that scanned nothing, set fail_on_incomplete_scanners: false or pass "
    "--no-fail-on-incomplete-scanners."
)
#: troubleshoot.md's quote of the error for detect-secrets under ignore_paths '**'.
_NOTHING_TO_SCAN_IGNORED = (
    "No selected scanner had a file to scan: detect-secrets was SKIPPED with nothing to "
    "scan, so this run has shown the target to be neither clean nor dirty. The config's "
    "global_settings.ignore_paths ('**') leaves every path it matches out of what the "
    "scanners read, which can leave them nothing to scan; narrow it to have those files "
    "scanned. To accept a run that scanned nothing, set fail_on_incomplete_scanners: "
    "false or pass --no-fail-on-incomplete-scanners."
)


def _ignoring(*patterns: str) -> Dict[str, Any]:
    """A project config whose global_settings.ignore_paths holds ``patterns``."""
    return {
        "project_name": "nothing-to-scan",
        "global_settings": {
            "ignore_paths": [{"path": p, "reason": "page claim"} for p in patterns]
        },
    }


def _scan_with_nothing_to_scan(
    tmp_path: Path,
    files: Dict[str, str],
    scanners: str,
    config: Optional[Dict[str, Any]] = None,
    *extra: str,
) -> Tuple[subprocess.CompletedProcess, Dict[str, str]]:
    """``ash scan --scanners <scanners>`` of a tree holding ``files``, with ``config``
    as its own ``.ash/.ash.yaml``: the result, and each scanner's status in the
    results file."""
    tree = _config_scan_tree(tmp_path, files)
    if config is not None:
        (tree / ".ash").mkdir()
        (tree / ".ash" / ".ash.yaml").write_text(yaml.safe_dump(config), "utf-8")
    result = _ash(
        [
            "scan",
            "--source-dir",
            str(tree),
            "--scanners",
            scanners,
            "--offline",
            "--no-progress",
            *extra,
        ],
        cwd=tmp_path,
    )
    results = tree / ".ash" / "ash_output" / "ash_aggregated_results.json"
    statuses = (
        {
            name: entry.get("status")
            for name, entry in (
                json.loads(results.read_text("utf-8")).get("scanner_results") or {}
            ).items()
        }
        if results.is_file()
        else {}
    )
    return result, statuses


@pytest.mark.parametrize(
    "files, scanners, config, error",
    [
        pytest.param(
            {},
            "detect-secrets",
            None,
            _NOTHING_TO_SCAN.replace("bandit was", "detect-secrets was"),
            id="an-empty-tree",
        ),
        pytest.param(
            {"app.py": "x = 1\n"},
            "detect-secrets",
            _ignoring("**"),
            _NOTHING_TO_SCAN_IGNORED,
            id="ignore-paths-match-everything",
        ),
        pytest.param(
            {},
            "cdk-nag,detect-secrets",
            None,
            _NOTHING_TO_SCAN.replace("bandit was", "cdk-nag, detect-secrets were"),
            id="two-scanners-named",
        ),
        pytest.param(
            {"app.py": "x = 1\n"},
            "detect-secrets",
            _ignoring("**", "a/**", "b/**", "c/**", "d/**"),
            _NOTHING_TO_SCAN_IGNORED.replace(
                "('**')", "('**', 'a/**', 'b/**' and 2 more)"
            ),
            id="three-patterns-and-a-count",
        ),
    ],
)
@pytest.mark.integration
def test_a_scan_whose_scanners_had_nothing_to_scan_exits_1_and_says_why(
    tmp_path: Path,
    files: Dict[str, str],
    scanners: str,
    config: Optional[Dict[str, Any]],
    error: str,
) -> None:
    """troubleshoot.md (No selected scanner had a file to scan), and exit-codes.md.

    ``ash scan`` runs offline with ``--scanners`` naming scanners that have nothing to
    read: detect-secrets in an empty tree, cdk-nag and detect-secrets in an empty tree,
    and detect-secrets under a project config whose global_settings.ignore_paths
    matches every path, with one pattern and with five. Each must exit 1 with every
    selected scanner SKIPPED and the error the page quotes, with the page's scanner
    names replaced by these: naming the scanners, and for ignore_paths showing its
    first three patterns with a count of the others. It is not the "Scan ran no
    scanners:" error.

    The page's example names bandit, but offline a bandit the host has not installed
    is MISSING, not SKIPPED, so the cells name scanners that come with ASH:
    detect-secrets runs in ASH's own process, and cdk-nag with the cdk extra and node,
    which CI's unit-test job has.
    """
    assert_on_page(
        "how-to/troubleshoot.md",
        "Symptom: the scan exits 1 with no findings, every selected scanner is SKIPPED, "
        "and the error names the scanners that had nothing to scan:",
    )
    assert_on_page("how-to/troubleshoot.md", _NOTHING_TO_SCAN)
    assert_on_page(
        "how-to/troubleshoot.md",
        "When the config sets `global_settings.ignore_paths`, the error also shows its "
        "first three patterns, with a count of any others, and suggests narrowing them:",
    )
    assert_on_page("how-to/troubleshoot.md", _NOTHING_TO_SCAN_IGNORED)
    assert_on_page(
        EXIT_CODES,
        "no scanner ran (every selected scanner was SKIPPED, also when none of them had "
        "a file to scan)",
    )
    if "cdk-nag" in scanners:
        assert shutil.which("node"), "cdk-nag needs node on PATH, as CI's job has it"
    result, statuses = _scan_with_nothing_to_scan(tmp_path, files, scanners, config)
    output = _normalize(result.stdout + result.stderr)

    assert result.returncode == 1, (
        f"exit {result.returncode}, expected 1:\n{_output_tail(result)}"
    )
    for name in scanners.split(","):
        assert statuses.get(name) == "SKIPPED", statuses
    assert error in output, _output_tail(result)
    assert "Scan ran no scanners" not in output, _output_tail(result)


@pytest.mark.integration
def test_a_scan_that_had_nothing_to_scan_exits_0_when_incomplete_scans_are_accepted(
    tmp_path: Path,
) -> None:
    """troubleshoot.md (No selected scanner had a file to scan), and exit-codes.md.

    The detect-secrets scan of a tree whose ignore_paths match every path is made
    with ``--no-fail-on-incomplete-scanners``: it must exit 0, with detect-secrets
    still SKIPPED. The control is the same scan without the option, which exits 1.
    """
    assert_on_page(
        "how-to/troubleshoot.md",
        "To accept such a scan, pass `--no-fail-on-incomplete-scanners` or set "
        "`fail_on_incomplete_scanners: false`; it then exits 0.",
    )
    assert_on_page(
        EXIT_CODES,
        "With `fail_on_incomplete_scanners` off, also an incomplete scan, including one "
        "in which no selected scanner had a file to scan.",
    )
    accepted, statuses = _scan_with_nothing_to_scan(
        tmp_path / "accepted",
        {"app.py": "x = 1\n"},
        "detect-secrets",
        _ignoring("**"),
        "--no-fail-on-incomplete-scanners",
    )
    assert accepted.returncode == 0, _output_tail(accepted)
    assert statuses.get("detect-secrets") == "SKIPPED", statuses
    control, _ = _scan_with_nothing_to_scan(
        tmp_path / "control", {"app.py": "x = 1\n"}, "detect-secrets", _ignoring("**")
    )
    assert control.returncode == 1, _output_tail(control)


@pytest.mark.integration
def test_a_scan_whose_scanners_were_all_turned_off_reports_scan_ran_no_scanners(
    tmp_path: Path,
) -> None:
    """troubleshoot.md (No selected scanner had a file to scan).

    ``--scanners detect-secrets`` with detect-secrets turned off by an override, in a
    tree with a file it would read, leaves every scanner SKIPPED for another reason
    than having nothing to scan. The scan must exit 1 with "Scan ran no scanners:"
    and each scanner's status, and not with the nothing-to-scan error.
    """
    assert_on_page(
        "how-to/troubleshoot.md",
        "A run whose scanners were all SKIPPED for another reason, such as a "
        "`--scanners` name that matches no scanner on this platform, or every selected "
        "scanner turned off in the configuration, reports `Scan ran no scanners:` "
        "instead, with each scanner and its status;",
    )
    result, statuses = _scan_with_nothing_to_scan(
        tmp_path,
        {"app.py": "x = 1\n"},
        "detect-secrets",
        None,
        "--config-overrides",
        "scanners.detect-secrets.enabled=false",
    )
    output = _normalize(result.stdout + result.stderr)

    assert result.returncode == 1, _output_tail(result)
    assert statuses.get("detect-secrets") == "SKIPPED", statuses
    assert "Scan ran no scanners: " in output, _output_tail(result)
    assert "detect-secrets (SKIPPED)" in output, _output_tail(result)
    assert "No selected scanner had a file to scan" not in output, _output_tail(result)


# --------------------------------------------------------------------------- #
# A wrong suppression field in the agents tutorial
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "change, verdict, named",
    [
        pytest.param(
            None, 0, "Configuration is valid! A scan accepts it.", id="as-written"
        ),
        pytest.param(("expiration:", "expiry:"), 3, "'expiry'", id="a-misspelled-key"),
        pytest.param(
            ("line_start: 6", 'line_start: "six"'), 3, "line_start", id="a-wrong-value"
        ),
        pytest.param(
            (
                '      reason: "MD5 builds a cache key; it does not protect anything"\n',
                "",
            ),
            3,
            "reason",
            id="a-missing-required-field",
        ),
    ],
)
@pytest.mark.integration
def test_config_validate_names_a_wrong_suppression_field_and_exits_3(
    tmp_path: Path, change: Tuple[str, str] | None, verdict: int, named: str
) -> None:
    """agents.md (8. Draft a suppression).

    The tutorial's ``.ashrc.yaml``, read from its ``cat`` block, is checked with
    ``ash config validate`` as written and with one field broken in each way the
    sentence lists; the misspelling is the one the page's ``sed`` makes. Each broken
    file must exit 3 and name the field, and a scan, resolving the same file, must
    refuse it too. The file as written is the control: it exits 0, with the warning
    about ``project_name``.
    """
    assert_on_page(
        _CONFIG_AGENTS_PAGE,
        "It checks the config a scan of the project would use, the way the scan loads it, "
        "and ends with `Configuration is valid! A scan accepts it.` It may also warn that "
        "`project_name` is not set, which a scan accepts. A wrong value, a missing required "
        "field such as `reason`, or a misspelled key such as `expiry` for `expiration` "
        "makes it name the field and exit with code 3:",
    )
    assert_on_page(
        _CONFIG_AGENTS_PAGE, "sed 's/expiration:/expiry:/' .ashrc.yaml > typo.yaml"
    )
    text = _config_heredoc(_CONFIG_AGENTS_PAGE, ".ashrc.yaml")
    if change is not None:
        assert change[0] in text, f"the tutorial's file has no {change[0]!r}"
        text = text.replace(change[0], change[1])
    tree = _config_scan_tree(tmp_path, {".ashrc.yaml": text})

    result = _ash(["config", "validate"], cwd=tree)
    output = result.stdout + result.stderr
    assert result.returncode == verdict, (
        f"exit {result.returncode}, expected {verdict}:\n{_output_tail(result)}"
    )
    assert named in output, f"{named!r} is not in the output:\n{_output_tail(result)}"
    if change is None:
        assert "project_name" in output, _output_tail(result)

    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    try:
        resolve_config(source_dir=tree)
        refused = False
    except ASHConfigValidationError:
        refused = True
    assert refused is (verdict == 3), (
        f"a scan {'refuses' if refused else 'accepts'} the file validate exited "
        f"{result.returncode} for"
    )


# --------------------------------------------------------------------------- #
# Expiration dates in a config file
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "page, heading, written",
    [
        pytest.param(
            _CONFIG_LOCAL_PAGE,
            "## 7. Suppress the false positive",
            '"2027-04-30"',
            id="a-suppression",
        ),
        pytest.param(
            _OFFLINE_PAGE,
            "## Allow a stale database",
            '"2027-06-30"',
            id="a-staleness-override",
        ),
    ],
)
@pytest.mark.parametrize(
    "quoted, verdict",
    [
        pytest.param(True, 0, id="control-quoted"),
        pytest.param(False, 3, id="unquoted"),
    ],
)
@pytest.mark.integration
def test_an_unquoted_expiration_date_makes_ash_refuse_the_whole_config(
    tmp_path: Path, page: str, heading: str, written: str, quoted: bool, verdict: int
) -> None:
    """local.md (7. Suppress the false positive) and run-offline.md (Allow a stale
    database).

    The config block each page shows, read from the page, is the repository's
    ``.ashrc.yaml`` for a detect-secrets scan of a tree with no findings. With the date
    unquoted, the scan must refuse the file with exit 3. The control is the block as
    written, which scans with exit 0, so the refusal is the date's.
    """
    assert_on_page(
        _CONFIG_LOCAL_PAGE,
        "Keep the date in quotes: unquoted, YAML reads it as a date rather than text, and "
        "ASH rejects the whole file with exit code 3.",
    )
    assert_on_page(
        _OFFLINE_PAGE,
        "Quote the date: an unquoted date makes the whole config invalid.",
    )
    block = _config_yaml_block(page, heading)
    assert f"expiration: {written}" in block, block
    text = block if quoted else block.replace(written, written.strip('"'))
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n", ".ashrc.yaml": text})

    result = _ash([*_CONFIG_SCAN, "--source-dir", str(tree)], cwd=tmp_path)
    assert result.returncode == verdict, (
        f"exit {result.returncode}, expected {verdict}:\n{_output_tail(result)}"
    )


@pytest.mark.unit
def test_a_suppression_whose_expiration_date_has_passed_is_accepted_and_does_nothing(
    tmp_path: Path,
) -> None:
    """local.md (7. Suppress the false positive).

    The tutorial's suppression, with its date moved into the past, is resolved as a
    scan resolves it and applied to the finding it names, B324 in app.py. The config
    must be accepted and the finding left unsuppressed. The control is the same entry
    dated a year from today, which suppresses the finding.
    """
    assert_on_page(
        _CONFIG_LOCAL_PAGE,
        "A date in the past is accepted, and the suppression then does nothing.",
    )
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

    block = _config_yaml_block(_CONFIG_LOCAL_PAGE, "## 7. Suppress the false positive")
    assert 'expiration: "2027-04-30"' in block, block
    next_year = (date.today() + timedelta(days=365)).isoformat()
    for when, suppressed in (("2020-01-01", False), (next_year, True)):
        tree = _tree_with_config(tmp_path / when, block.replace("2027-04-30", when))
        report = SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "bandit"}},
                        "results": [_bandit_finding("B324", "app.py")],
                    }
                ],
            }
        )
        context = PluginContext(
            source_dir=tree,
            output_dir=tree / ".ash" / "ash_output",
            config=resolve_config(source_dir=tree),
        )
        [result] = apply_suppressions_to_sarif(report, context).runs[0].results
        assert bool(result.suppressions) is suppressed, (
            f"expiration {when}: suppressions {result.suppressions!r}"
        )


# --------------------------------------------------------------------------- #
# Which config file ash.log names
# --------------------------------------------------------------------------- #

_CONFIG_LOG_PREFIX = "Using ASH configuration from "
_CONFIG_LOG_LINE = re.compile(re.escape(_CONFIG_LOG_PREFIX) + r"(.+?)\s*$")


@pytest.mark.parametrize(
    "given, verdict",
    [
        pytest.param("operator", 2, id="the-operator-config"),
        pytest.param("repository", 0, id="the-repository-config"),
        pytest.param("missing", 3, id="a-named-config-that-does-not-load"),
        pytest.param(None, 2, id="control-no-config"),
    ],
)
@pytest.mark.integration
def test_ash_log_names_the_config_file_once_the_scan_has_loaded_it(
    tmp_path: Path, given: str | None, verdict: int
) -> None:
    """platform-teams.md (3. Check that a repository cannot change the gate).

    A repository with one hardcoded password is scanned from its own directory, as the
    page scans it: with the tutorial's operator config passed with ``--config``, then
    with only the repository's own ``.ashrc.yaml``. Both are reached through a symbolic
    link to their directory, and the shell's ``PWD`` names the repository through its
    link. ``.ash/ash_output/ash.log`` must hold a ``Using ASH configuration from`` line
    for the file and no line naming another one, and the scan must exit as the page
    says. The operator's file is named as ``--config`` named it, links and all, which
    the page's ``grep -F`` with ``$OPERATOR_CONFIG`` looks for. The repository's file,
    which ASH found, is named by its resolved path, every link followed, which the
    page's ``grep -F`` with ``pwd -P`` looks for. A ``--config`` naming a file that does
    not exist is refused with exit 3 (exit-codes.md) and never loads, so no such line
    names it. The control is a scan with no config at all, whose log names no config
    file.
    """
    assert_on_page(
        _CONFIG_PLATFORM_PAGE,
        "Once the scan has loaded a config file, `.ash/ash_output/ash.log` names it in a "
        "`Using ASH configuration from` line. A file you name with `--config` appears as "
        "you named it:",
    )
    assert_on_page(
        _CONFIG_PLATFORM_PAGE,
        'grep -F "Using ASH configuration from $OPERATOR_CONFIG" .ash/ash_output/ash.log',
    )
    assert_on_page(
        _CONFIG_PLATFORM_PAGE,
        "`ash.log` now names the repository's file. A file ASH finds on its own appears "
        "by its resolved path, with every symbolic link followed, so the check uses "
        "`pwd -P`:",
    )
    assert_on_page(
        _CONFIG_PLATFORM_PAGE,
        'grep -F "Using ASH configuration from $(pwd -P)/.ashrc.yaml" '
        ".ash/ash_output/ash.log",
    )
    assert_on_page(
        _CONFIG_PLATFORM_PAGE,
        "The scan exits 0 although the finding is still there.",
    )
    assert_on_page(
        _CONFIG_PLATFORM_PAGE, "printf 'fail_on_findings: false\\n' > .ashrc.yaml"
    )
    files = {"app.py": _CONFIG_SECRET}
    if given == "repository":
        files[".ashrc.yaml"] = "fail_on_findings: false\n"
    tree = _config_scan_tree(tmp_path / "real", files)
    (tmp_path / "link").symlink_to(tree.parent, target_is_directory=True)
    linked_tree = tmp_path / "link" / tree.name
    args = list(_CONFIG_SCAN)
    operator = tmp_path / "ash-operator" / "ash.yaml"
    operator.parent.mkdir()
    (tmp_path / "operator-link").symlink_to(operator.parent, target_is_directory=True)
    if given == "operator":
        operator.write_text(
            _config_heredoc(_CONFIG_PLATFORM_PAGE, '"$OPERATOR_CONFIG"'),
            encoding="utf-8",
        )
    named_config = tmp_path / "operator-link" / operator.name
    if given in ("operator", "missing"):
        args += ["--config", str(named_config)]

    # From the repository's directory, as the page runs it, with the private home
    # directory beside the repository rather than inside it.
    result = subprocess.run(
        [sys.executable, "-m", "automated_security_helper.cli.main", *args],
        cwd=linked_tree,
        env=_ash_environment(tmp_path, PWD=str(linked_tree)),
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == verdict, (
        f"exit {result.returncode}, expected {verdict}:\n{_output_tail(result)}"
    )
    log = _config_scan_log(tree)
    named = [
        match.group(1)
        for match in map(_CONFIG_LOG_LINE.search, log.splitlines())
        if match
    ]
    if given in (None, "missing"):
        assert named == [], named
        if given is None:
            assert log, f"no ash.log was written:\n{_output_tail(result)}"
        return
    assert named, f"no {_CONFIG_LOG_PREFIX!r} line in ash.log:\n{log[-2000:]}"
    if given == "operator":
        expected, how = named_config, "as --config named it"
    else:
        expected, how = (tree / ".ashrc.yaml").resolve(), "by its resolved path"
    assert all(Path(path) == expected for path in named), (
        f"ash.log names {named}, not {expected} {how}"
    )
    assert "Configuration file not found" not in log


# --------------------------------------------------------------------------- #
# Offline mode
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value, offline",
    [
        pytest.param("YES", True, id="YES"),
        pytest.param("TRUE", True, id="TRUE"),
        pytest.param("1", True, id="1"),
        pytest.param("NO", False, id="control-NO"),
        pytest.param("0", False, id="control-0"),
        pytest.param(None, False, id="control-unset"),
    ],
)
@pytest.mark.unit
def test_ash_offline_turns_offline_mode_on_for_yes_true_and_1(
    monkeypatch: pytest.MonkeyPatch, value: str | None, offline: bool
) -> None:
    """run-offline.md (Turn on offline mode).

    ``is_offline_mode()``, which every scanner and tool install asks, is read with each
    spelling the table's row gives in ``ASH_OFFLINE``. The controls are ``NO``, ``0``
    and the variable unset, which leave ASH online.
    """
    assert_on_page(
        _OFFLINE_PAGE,
        "| `ASH_OFFLINE=YES` (also `TRUE` or `1`) in the environment | Every ASH run that "
        "inherits it.",
    )
    from automated_security_helper.core.constants import is_offline_mode

    if value is None:
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
    else:
        monkeypatch.setenv("ASH_OFFLINE", value)
    assert is_offline_mode() is offline


#: Grype's offline warning when the cache it would read is missing, with the
#: directory it names in between (plugin_modules/ash_builtin/scanners/grype_scanner.py,
#: ``_check_offline_cache``). The whole shape, so a warning about a directory that
#: exists but holds no database cannot stand in for it.
_OFFLINE_GRYPE_WARNING = re.compile(
    r"Grype offline mode: the database directory .+ does not exist"
)


@pytest.mark.parametrize(
    "flag, value, warned",
    [
        pytest.param(True, None, True, id="the-offline-flag"),
        pytest.param(False, "TRUE", True, id="ASH_OFFLINE-TRUE"),
        pytest.param(False, "1", True, id="ASH_OFFLINE-1"),
        pytest.param(False, "NO", False, id="control-online"),
    ],
)
@pytest.mark.integration
def test_an_offline_scan_logs_a_warning_for_a_scanner_whose_cache_is_not_set_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    flag: bool,
    value: str | None,
    warned: bool,
) -> None:
    """run-offline.md (Turn on offline mode).

    A repository with a hardcoded password is scanned with the page's ``ash scan
    --offline --scanners detect-secrets``, and with ``ASH_OFFLINE`` set to ``TRUE`` or
    ``1`` instead of the flag, with no grype cache configured: ``GRYPE_DB_CACHE_DIR``
    is unset and the run's private home (``_ash_environment``; ``LOCALAPPDATA`` is
    pointed under it too, the Windows default) holds no grype database, so the cache
    grype would read does not exist. Each must exit 2 and log grype's offline warning
    in ash.log. The control is an online scan, which exits 2 and logs no such warning.
    """
    assert_on_page(
        _OFFLINE_PAGE,
        "This scan runs offline as usual; in a repository with a hardcoded password it "
        "exits 2. The log also shows a warning for each scanner whose offline cache is not "
        "set up, such as `Grype offline mode: the database directory <path> does not "
        "exist`, naming the cache grype would read (`GRYPE_DB_CACHE_DIR`, else grype's "
        "default cache directory).",
    )
    assert_on_page(_OFFLINE_PAGE, "ash scan --offline --scanners detect-secrets")
    monkeypatch.delenv("GRYPE_DB_CACHE_DIR", raising=False)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    tree = _config_scan_tree(tmp_path, {"app.py": _CONFIG_SECRET})
    args = [*_CONFIG_SCAN, "--source-dir", str(tree), *(["--offline"] if flag else [])]
    env = {"LOCALAPPDATA": str(tmp_path / "home" / "AppData" / "Local")}
    if value:
        env["ASH_OFFLINE"] = value

    result = _ash(args, cwd=tmp_path, **env)
    assert result.returncode == 2, (
        f"exit {result.returncode}, expected 2:\n{_output_tail(result)}"
    )
    assert bool(_OFFLINE_GRYPE_WARNING.search(_config_scan_log(tree))) is warned, (
        f"the grype warning is {'missing from' if warned else 'in'} ash.log"
    )


# --------------------------------------------------------------------------- #
# Content database bounds
# --------------------------------------------------------------------------- #

#: (page, the table's header row, the column naming the database, the bound's column).
_OFFLINE_BOUND_TABLES = (
    (_OFFLINE_PAGE, "| Database | Name in the config | Bound |", 1, 2),
    (_OFFLINE_CDB_PAGE, "| Database | Read by | Age bound |", 0, 2),
)

_OFFLINE_AMOUNT = re.compile(r"(\d+)\s*(hour|day)s?\b")


def _offline_table(page: str, header: str) -> List[List[str]]:
    """The body rows of the table on ``page`` whose header row starts with ``header``."""
    lines = _page_text(page).splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(header))
    rows = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        rows.append([cell.strip() for cell in line.strip().strip("|").split("|")])
    return rows


def _offline_database(cell: str) -> str:
    return _one(re.findall(r"`([a-z0-9-]+)`", cell), f"database name in {cell!r}")


def _offline_bound(cell: str) -> timedelta:
    """``120 hours``, ``5 days (120 hours)``: every amount in the cell, which must agree."""
    amounts = {
        timedelta(**{f"{unit}s": int(n)}) for n, unit in _OFFLINE_AMOUNT.findall(cell)
    }
    return _one(amounts, f"bound in {cell!r}")


@pytest.mark.unit
def test_each_content_database_is_held_to_the_age_bound_the_pages_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run-offline.md (Refresh cadence) and content-databases.md (Which scanners use
    one).

    Both tables are read from the pages. Each database must be one ASH declares, with
    the stated bound, and the scan-time check must hold it there: a database read as
    built an hour inside the bound is fresh and one an hour past it is stale, also with
    ``GRYPE_DB_MAX_ALLOWED_BUILT_AGE`` set to something longer. grype's and trivy's
    status commands are answered at the process boundary, ``spawn_run``, which also
    shows the check runs the commands the page names; the rulesets are directories
    with ``.ash-rules-fetched-at``. The fresh reading is the control: a check that
    called every database stale would fail it.
    """
    assert_on_page(
        _OFFLINE_PAGE, "The bounds are fixed in the code; no setting changes them."
    )
    assert_on_page(
        _OFFLINE_CDB_PAGE,
        "The bounds are fixed: no config key, variable, or flag changes them.",
    )
    from automated_security_helper.utils import content_db_staleness
    from automated_security_helper.utils.content_databases import (
        CONTENT_DATABASES,
        RULESET_FETCHED_AT_FILE,
        get,
    )

    stated: Dict[str, timedelta] = {}
    for page, header, name_column, bound_column in _OFFLINE_BOUND_TABLES:
        rows = _offline_table(page, header)
        names = [_offline_database(row[name_column]) for row in rows]
        assert sorted(names) == sorted(e.name for e in CONTENT_DATABASES), (
            f"{page} lists {sorted(names)}"
        )
        for name, row in zip(names, rows):
            bound = _offline_bound(row[bound_column])
            assert stated.setdefault(name, bound) == bound, (name, page)
            assert get(name).max_age == bound, (
                f"{page} says {name} is held to {bound}; ASH declares {get(name).max_age}"
            )
    age_read_from = {
        _offline_database(row[0]): row[4]
        for row in _offline_table(
            _OFFLINE_CDB_PAGE, "| Database | Read by | Age bound |"
        )
    }
    #: What each probe reads its build time from, as the "Age read from" column names it.
    read_field = {"grype-db": "`built`", "trivy-db": "`VulnerabilityDB.UpdatedAt`"}
    for name, field in read_field.items():
        assert field in age_read_from[name], (name, age_read_from[name])
    assert RULESET_FETCHED_AT_FILE in age_read_from["semgrep-offline-rules"], (
        age_read_from
    )

    now = datetime.now(timezone.utc)
    commands: List[List[str]] = []
    built_at: Dict[str, datetime] = {}

    def answer(args: List[str], **kwargs: Any) -> subprocess.CompletedProcess:
        commands.append(list(args))
        stamp = built_at["now"].strftime("%Y-%m-%dT%H:%M:%S.123456789Z")
        if args[1:3] == ["db", "status"]:
            payload: Dict[str, Any] = {"built": stamp, "valid": True}
        else:
            payload = {"VulnerabilityDB": {"UpdatedAt": stamp}}
        return subprocess.CompletedProcess(
            args, 0, stdout=json.dumps(payload), stderr=""
        )

    monkeypatch.setattr(content_db_staleness, "spawn_run", answer)
    monkeypatch.setenv("GRYPE_DB_MAX_ALLOWED_BUILT_AGE", "480h")
    for name, bound in sorted(stated.items()):
        for offset, stale in ((-timedelta(hours=1), False), (timedelta(hours=1), True)):
            built = now - (bound + offset)
            built_at["now"] = built
            cache = tmp_path / f"{name}-{int(built.timestamp())}"
            cache.mkdir()
            (cache / "rules.yaml").write_text("rules: []\n", encoding="utf-8")
            (cache / RULESET_FETCHED_AT_FILE).write_text(
                built.strftime("%Y-%m-%dT%H:%M:%SZ"), encoding="utf-8"
            )
            context = content_db_staleness.ProbeContext(
                env=dict(os.environ),
                executable=name.split("-")[0],
                cache_dir=str(cache),
            )
            commands.clear()
            record = content_db_staleness.measure(get(name), context, "fail", now)
            assert record.error is None, (name, record.error)
            assert record.stale is stale, (
                f"{name} built {bound + offset} ago: stale={record.stale}, expected {stale}"
            )
            if name in read_field:
                [command] = commands
                named = re.findall(r"`((?:grype|trivy) [^`]+)`", age_read_from[name])
                assert any(" ".join(command).startswith(c) for c in named), (
                    f"the check ran {command}; the page names {named}"
                )
            else:
                assert not commands, commands


def _offline_shipped_scanner_classes() -> Dict[str, Any]:
    """{scanner name: plugin class} for the scanners ASH's plugin modules ship."""
    import automated_security_helper.plugin_modules as plugin_modules

    found: Dict[str, Any] = {}
    for module_info in pkgutil.iter_modules(plugin_modules.__path__):
        module = importlib.import_module(
            f"{plugin_modules.__name__}.{module_info.name}"
        )
        for plugin in getattr(module, "ASH_SCANNERS", []):
            config_class = typing.get_args(plugin.model_fields["config"].annotation)[0]
            found[config_class.model_fields["name"].default] = plugin
    return found


@pytest.mark.unit
def test_the_content_database_table_names_the_scanners_that_read_each_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """content-databases.md (Which scanners use one).

    Each scanner the Read by column names is built the way the scan phase builds it
    and asked which databases it reads, online and with ``ASH_OFFLINE=YES``. It must
    read its row's database offline, and online too unless the row says offline only;
    and the scanners the column names must be all the scanners ASH declares for that
    database. The online reading is the control for "offline only".

    A scanner that reads a rule cache from a directory the environment names (the
    grep family's ``cache_dir_env_var``) declares the database only when the offline
    scan read that cache: with none it declines and reads nothing, and a scan of
    the operator's own rules or of bare patterns reads no cache either. So the
    offline build of such a scanner is given a cache the way the offline image
    ships one, a directory outside the scanned tree holding one rules file, and
    the question is asked of that build.
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.utils.content_databases import (
        RULESET_FETCHED_AT_FILE,
        get,
    )

    rows = _offline_table(_OFFLINE_CDB_PAGE, "| Database | Read by | Age bound |")
    shipped = _offline_shipped_scanner_classes()
    config = AshConfig(project_name="readers")
    (tmp_path / "source").mkdir()

    def _rule_cache(reader: str) -> Path:
        cache = tmp_path / "rule-cache" / reader
        cache.mkdir(parents=True, exist_ok=True)
        (cache / "rules.yaml").write_text(
            "rules:\n  - id: placeholder\n    languages: [python]\n"
            "    message: m\n    severity: INFO\n    pattern: $X == $X\n",
            encoding="utf-8",
        )
        # Stamped now: the table has an age bound, and a fixed date would cross it
        # one day with no code change.
        (cache / RULESET_FETCHED_AT_FILE).write_text(
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ\n"),
            encoding="utf-8",
        )
        return cache

    for row in rows:
        name, cell = _offline_database(row[0]), row[1]
        offline_only = cell.endswith(", offline only")
        readers = [r.strip() for r in cell.removesuffix(", offline only").split(",")]
        entry = get(name)
        declared = (entry.scanner, *getattr(entry, "also_read_by", ()))
        assert sorted(readers) == sorted(declared), (
            f"the page says {readers} read {name}; ASH declares {list(declared)}"
        )
        for reader in readers:
            assert reader in shipped, f"{reader} is not a scanner ASH ships"
            for offline in (False, True):
                # One environment per pass: the rule cache an offline pass points
                # a reader at must not reach the next pass, whose online build is
                # the control that the online reader declares no such database.
                with monkeypatch.context() as pass_env:
                    if offline:
                        pass_env.setenv("ASH_OFFLINE", "YES")
                    else:
                        pass_env.delenv("ASH_OFFLINE", raising=False)

                    def _build():
                        context = PluginContext(
                            source_dir=tmp_path / "source",
                            output_dir=tmp_path / "output",
                            work_dir=tmp_path / "output" / "converted",
                            config=config,
                        )
                        return shipped[reader](
                            config=config.get_plugin_config(
                                plugin_type="scanner", plugin_name=reader
                            ),
                            context=context,
                        )

                    scanner = _build()
                    cache_env = getattr(scanner, "cache_dir_env_var", None)
                    if callable(cache_env):
                        # Set for the online build too, so the control varies only
                        # ASH_OFFLINE: a scanner that declared the database whenever
                        # its cache variable was set, online as well, would otherwise
                        # pass the online control.
                        pass_env.setenv(cache_env(), str(_rule_cache(reader)))
                        scanner = _build()
                    reads = [e.name for e in scanner.content_databases_in_use()]
                expected = offline or not offline_only
                assert (name in reads) is expected, (
                    f"{reader} {'offline' if offline else 'online'} reads {reads}"
                )


# --------------------------------------------------------------------------- #
# Ctrl-C
# --------------------------------------------------------------------------- #

_INTERRUPT_SENT = "page-claims: SIGINT sent at"
_INTERRUPT_SENT_AT = re.compile(re.escape(_INTERRUPT_SENT) + r" ([0-9.]+)")

#: What a scan prints when Ctrl-C ends it, as exit-codes.md quotes it.
_SCAN_INTERRUPTED = (
    "ASH scan interrupted before it finished: there is no verdict, and the output "
    "directory may hold partial results."
)
_SCAN_CTRL_C_ROW = (
    "| 130 | Interrupted with Ctrl-C, in every mode, container and Nix mode included. "
    f"ASH prints `{_SCAN_INTERRUPTED}` on stderr, and no results table and no line "
    "saying the scan completed, in the console or in the scan's log file. Container and "
    "Nix mode first give the runtime or the Nix shell time to stop ([Container and Nix "
    "mode](#container)). |"
)
_CHILD_CTRL_C_ROW = (
    "| 130 | Interrupted with Ctrl-C. Outside Windows, ASH passes the interrupt to the "
    "container runtime or the Nix shell, unless the terminal already delivered it there, "
    "waits up to 5 seconds for it to stop, and then kills it; a second Ctrl-C during the "
    "wait kills it at once. On Windows, a Ctrl-C typed in the console reaches the "
    "container runtime as well, and ASH waits up to 5 seconds for it to stop, as above; "
    "without a console, ASH ends the runtime at once. A scan prints the interrupted-scan "
    "message above. `ash "
    "build-image` prints `ASH build-image interrupted before it finished.`, and, without "
    "`--no-run`, adds `: there is no verdict, and the output directory may hold partial "
    "results` before the period. |"
)
#: The row's "up to 5 seconds".
_INTERRUPT_GRACE_SECONDS = 5

#: What a finished scan prints, none of which an interrupted one may print: the
#: verdict line, the results table and the lines saying the scan completed.
_SCAN_FINISHED_TEXT = (
    "Exiting due to",
    "Results Summary",
    "Completed in",
    "ASH Security Scan completed",
)

#: ``ash`` with the arguments after the first, run as ``python -m`` runs it. The first
#: is a JSON object. Its ``waits`` are (file, text) pairs: once each file holds its
#: text, in turn, a thread sends SIGINT, which is what Ctrl-C does, and says so on
#: stderr first with the time. SIGINT goes to the process alone, as ``kill -INT`` or a
#: CI job's cancel sends it. Windows cannot send SIGINT to a process from outside it,
#: and os.kill there ends the process instead, so on Windows the thread raises it in
#: the process with raise_signal. With a ``terminal`` (POSIX), the process first makes
#: that terminal its controlling terminal in a session of its own, with its process
#: group in the foreground, and SIGINT goes to the whole group, as a terminal's Ctrl-C
#: reaches every process in it. SIGINT is first set to raise KeyboardInterrupt, as
#: Python sets it in a process started from a terminal: a shell starts a background
#: job with SIGINT ignored, and a test run started that way would pass that on. With
#: ``ignore_sigint``, SIGINT is set to be ignored instead, as that shell sets it.
#:
#: With ``windows`` ("console" or "no-console"), ASH's subprocess_utils runs as on
#: Windows, as tests/utils/windows_console.py stands it in: a module-local ``os``
#: named "nt" (``os.name`` itself is left alone, since pathlib reads it), and
#: ``_has_a_console`` answering for the case. A Windows console sends a Ctrl-C to
#: every process attached to it, which no platform here can do for a test, so with
#: a ``console_file`` each Ctrl-C also appends a line to it, and the stand-in for the
#: runtime takes each new line as the Ctrl-C the console sent it.
_INTERRUPTED_ASH = """\
import json, os, runpy, signal, sys, threading, time
from pathlib import Path

control = json.loads(sys.argv[1])
signal.signal(
    signal.SIGINT,
    signal.SIG_IGN if control.get("ignore_sigint") else signal.default_int_handler,
)
if control.get("ignore_sighup"):
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
if control.get("windows"):
    from automated_security_helper.utils import subprocess_utils

    class WindowsOs:
        name = "nt"

        def __getattr__(self, attribute):
            if attribute in ("tcgetpgrp", "getpgrp", "getpgid", "killpg", "setsid"):
                raise AttributeError(attribute)
            return getattr(os, attribute)

    console = control["windows"] == "console"
    subprocess_utils.os = WindowsOs()
    subprocess_utils._has_a_console = lambda: console
if control["terminal"]:
    import fcntl, termios

    os.setsid()
    terminal = os.open(control["terminal"], os.O_RDWR | os.O_NOCTTY)
    fcntl.ioctl(terminal, termios.TIOCSCTTY, 0)
    os.dup2(terminal, 0)
    os.close(terminal)
    # Already so on Linux and macOS once the terminal is the controlling one; SIGTTOU
    # is ignored so that a system where it is not cannot stop this process here.
    stop_on_output = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    os.tcsetpgrp(0, os.getpgrp())
    signal.signal(signal.SIGTTOU, stop_on_output)


def interrupt():
    for watched, ready in control["waits"]:
        watched = Path(watched)
        while ready not in (
            watched.read_text("utf-8", "replace") if watched.is_file() else ""
        ):
            time.sleep(0.05)
        print({sent!r}, time.monotonic(), file=sys.stderr, flush=True)
        if control.get("console_file"):
            with open(control["console_file"], "a", encoding="utf-8") as console_file:
                console_file.write("ctrl-c\\n")
        if control["terminal"]:
            os.killpg(os.getpgrp(), signal.SIGINT)
        elif os.name == "nt":
            signal.raise_signal(signal.SIGINT)
        else:
            os.kill(os.getpid(), signal.SIGINT)


threading.Thread(target=interrupt, daemon=True).start()
sys.argv = ["ash", *sys.argv[2:]]
runpy.run_module("automated_security_helper.cli.main", run_name="__main__", alter_sys=True)
"""

#: A stand-in for the container runtime or for ``nix``. Called without ``wait_on`` in
#: its arguments it exits 0 at once. Called with it, it logs that it started and
#: waits, logging each SIGINT it gets and that it is alive every 0.1 s. Once it has
#: one SIGINT, ``stops`` takes 2 seconds to clean up (longer than Python's own 0.25 s,
#: inside the page's 5), logs CLEAN and exits 130; ``stays`` keeps running. It logs
#: ``orphaned`` and exits when ASH is gone without stopping it, and ``deadline`` after
#: two minutes. Each log line is the event and the time. With a ``console`` file, each
#: line added to it counts as one more SIGINT, the Ctrl-C a Windows console sends.
_INTERRUPT_STAND_IN = """\
import os, signal, sys, time
from pathlib import Path

log, wait_on, behavior = Path({log!r}), {wait_on!r}, {behavior!r}
console = Path({console!r}) if {console!r} else None


def note(text):
    with log.open("a", encoding="utf-8") as handle:
        handle.write(f"{{text}} {{time.monotonic():.3f}}\\n")


if wait_on not in sys.argv[1:]:
    sys.exit(0)
parent = os.getppid()
interrupts = []


def interrupted(signum, frame):
    interrupts.append(signum)
    note("INT")


signal.signal(signal.SIGINT, interrupted)
note("started")
deadline = time.monotonic() + 120
from_console = 0
while time.monotonic() < deadline:
    if console is not None and console.is_file():
        sent = len(console.read_text(encoding="utf-8").splitlines())
        while from_console < sent:
            from_console += 1
            interrupted(signal.SIGINT, None)
    if os.getppid() != parent:
        note("orphaned")
        sys.exit(0)
    if interrupts and behavior == "stops":
        time.sleep(2)
        note("CLEAN")
        sys.exit(130)
    note("alive")
    time.sleep(0.1)
note("deadline")
"""


def _interrupt_stand_in(
    tmp_path: Path, wait_on: str, behavior: str, console: Optional[Path] = None
) -> Tuple[Path, Path]:
    """(the stand-in script, the log it writes) for ``wait_on`` and ``behavior``, with
    the Windows console stood in by ``console`` when it is given."""
    log = tmp_path / "stand-in.log"
    script = tmp_path / "stand_in.py"
    script.write_text(
        _INTERRUPT_STAND_IN.format(
            log=str(log),
            wait_on=wait_on,
            behavior=behavior,
            console=str(console) if console is not None else "",
        ),
        encoding="utf-8",
    )
    return script, log


def _stand_in_events(log: Path) -> List[Tuple[str, float]]:
    """(event, time) for each line of a stand-in's log, once the log has settled.

    A stand-in that ASH left running notices within 0.1 s that ASH is gone and logs
    ``orphaned``, which can be just after ASH exits, so the log is read once it has
    not changed for a second, within a minute.
    """
    deadline = time.monotonic() + 60
    size, unchanged_since = -1, time.monotonic()
    while time.monotonic() < deadline:
        now_size = log.stat().st_size if log.is_file() else -1
        if now_size != size:
            size, unchanged_since = now_size, time.monotonic()
        elif time.monotonic() - unchanged_since >= 1:
            break
        time.sleep(0.05)
    if not log.is_file():
        return []
    lines = log.read_text(encoding="utf-8").splitlines()
    return [(event, float(at)) for event, at in (line.split() for line in lines)]


def _assert_ended_at_once(events: List[Tuple[str, float]], sent_at: float) -> None:
    """The Windows branch: the runtime got no interrupt and was ended at once, its last
    sign of life less than half the page's 5-second wait after the SIGINT."""
    happened = [event for event, _ in events if event != "alive"]
    assert happened == ["started"], (
        f"the runtime was not ended at once without the interrupt: {happened}"
    )
    last_sign_of_life = max(at for _, at in events)
    assert last_sign_of_life - sent_at < _INTERRUPT_GRACE_SECONDS / 2, (
        f"the runtime ran {last_sign_of_life - sent_at:.1f} s after the interrupt"
    )


def _interrupt_scan(
    mode: str,
    tmp_path: Path,
    source: Path,
    behavior: str,
    console: Optional[Path] = None,
) -> Tuple[List[str], Tuple[Path, str], Dict[str, str], Optional[Path]]:
    """(``ash`` arguments, (the file to watch, the text that means the scan is under
    way), environment, the stand-in's log) for an interrupted scan of ``source``.

    Local mode is watched through ash.log until detect-secrets starts, and has no
    stand-in. Container and Nix mode run the stand-in with ``behavior``, watched through
    its log: the container runtime's ``run`` is the stand-in through
    ``OCI_RUNNER_WRAPPER``, and ``nix``'s ``develop`` is the stand-in first on PATH. A
    ``console`` file stands in for a Windows console for the container runtime.
    """
    output = tmp_path / "output"
    args = [*_CONFIG_SCAN, "--offline", "--source-dir", str(source)]
    args += ["--output-dir", str(output)]
    if mode == "local":
        return args, (output / "ash.log", "Running scanner: detect-secrets"), {}, None
    if mode == "container":
        script, log = _interrupt_stand_in(tmp_path, "run", behavior, console)
        args += ["--mode", "container", "--no-build", "--oci-runner", sys.executable]
        wrapper = shlex.join([sys.executable, str(script)])
        return args, (log, "started"), {"OCI_RUNNER_WRAPPER": wrapper}, log
    script, log = _interrupt_stand_in(tmp_path, "develop", behavior)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    nix = bin_dir / "nix"
    nix.write_text(f"#!{sys.executable}\n{script.read_text('utf-8')}", encoding="utf-8")
    nix.chmod(0o755)
    path = os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")])
    return [*args, "--mode", "nix"], (log, "started"), {"PATH": path}, log


def _interrupter(
    waits: List[Tuple[Path, str]],
    terminal: Optional[str] = None,
    ignore_sigint: bool = False,
    windows: Optional[str] = None,
    console: Optional[Path] = None,
    ignore_sighup: bool = False,
) -> List[str]:
    """The interpreter command line that runs ``ash`` as ``_INTERRUPTED_ASH`` runs it,
    before the ``ash`` arguments."""
    control = {
        "waits": [[str(f), text] for f, text in waits],
        "terminal": terminal,
        "ignore_sigint": ignore_sigint,
        "ignore_sighup": ignore_sighup,
        "windows": windows,
        "console_file": str(console) if console is not None else None,
    }
    return [
        sys.executable,
        "-c",
        _INTERRUPTED_ASH.format(sent=_INTERRUPT_SENT),
        json.dumps(control),
    ]


def _run_interrupted(
    tmp_path: Path,
    args: List[str],
    waits: List[Tuple[Path, str]],
    env: Dict[str, str],
    terminal: Optional[str] = None,
    windows: Optional[str] = None,
    console: Optional[Path] = None,
) -> subprocess.CompletedProcess:
    """``ash <args>``, sent SIGINT once each of ``waits`` is met (``_INTERRUPTED_ASH``),
    as on Windows with ``windows``, and with ``console`` standing in for its console.

    Standard input is the null device unless ``terminal`` names one, so whether the
    interrupt came from a terminal does not depend on how the test run was started.
    """
    return subprocess.run(
        [*_interrupter(waits, terminal, windows=windows, console=console), *args],
        cwd=tmp_path,
        env=_ash_environment(tmp_path, **env),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=600,
    )


#: (mode, how the stand-in behaves, whether a terminal delivers the interrupt, how many
#: SIGINTs ASH gets, and None outside Windows, else whether a console is attached)
#: for each interrupted scan. The Windows cases run on every platform, stood in for.
_INTERRUPTED_SCANS = [
    pytest.param("local", None, False, 1, None, id="local"),
    *(
        pytest.param(mode, behavior, terminal, count, None, id=f"{mode}-{name}")
        for mode in ("container", "nix")
        for behavior, terminal, count, name in (
            ("stops", False, 1, "passed-on-with-time-to-stop"),
            ("stays", False, 1, "killed-after-the-wait"),
            ("stays", False, 2, "a-second-ctrl-c-kills-at-once"),
            ("stops", True, 1, "a-terminal-ctrl-c-is-not-passed-on-again"),
        )
    ),
    *(
        pytest.param("container", behavior, False, count, windows, id=f"windows-{name}")
        for behavior, count, windows, name in (
            ("stops", 1, "console", "console-ctrl-c-with-time-to-stop"),
            ("stays", 1, "console", "console-ctrl-c-killed-after-the-wait"),
            ("stays", 2, "console", "console-second-ctrl-c-kills-at-once"),
            ("stops", 1, "no-console", "no-console-ended-at-once"),
        )
    ),
]


@pytest.mark.parametrize(
    "mode, behavior, terminal, interrupts, windows", _INTERRUPTED_SCANS
)
@pytest.mark.integration
def test_ctrl_c_ends_a_scan_with_exit_code_130_in_every_mode(
    tmp_path: Path,
    mode: str,
    behavior: Optional[str],
    terminal: bool,
    interrupts: int,
    windows: Optional[str],
) -> None:
    """exit-codes.md (ash scan; Container and Nix mode).

    ``ash scan`` of a tree with 201 files that hold secrets runs in a child process,
    which gets SIGINT while it is scanning: in local mode once detect-secrets starts,
    and in container and Nix mode once the stand-in for the container runtime or
    ``nix`` has started. It must exit 130, print the interrupted-scan message on
    stderr, and print no verdict, results table or line saying the scan completed, in
    its output or in ash.log. The control is that the signal went while the child was
    still scanning: the line it writes first is in its output, and an ``ash`` that let
    the scan run on would end with the scan's own verdict, ``Exiting due to``.

    In container and Nix mode, with SIGINT sent to ASH alone, the stand-in must get it
    once from ASH: one that stops within 2 seconds must be let finish (``CLEAN``), and
    one that does not stop must be killed within the page's 5 seconds, with 30 more for
    a loaded machine, not left running (``orphaned``) or running to its own two-minute
    deadline. A second SIGINT once the stand-in has the first must kill it at once:
    the stand-in's last sign of life is less than half the wait after the second
    SIGINT, where a wait of the full 5 seconds would leave it alive longer. With the
    interrupt from a terminal (POSIX: a terminal of the test's own, SIGINT to the
    foreground process group), the stand-in already has it and must get it once, not
    again from ASH.

    The Windows cases run on every platform, with ASH's subprocess_utils as on Windows
    and a console attached or not (``_INTERRUPTED_ASH``). With a console, the console
    sends the stand-in the Ctrl-C itself, and ASH must not end it: one that stops
    within 2 seconds is let finish, one that does not is killed after the wait, and a
    second Ctrl-C during the wait kills it at once. With no console, the stand-in must
    get no interrupt and stop living within half the wait. On Windows itself the other
    container cases run as the no-console one, since no terminal or POSIX signal can
    reach the runtime there. Nix mode runs on Linux and macOS, and on Windows only
    inside WSL2 (install.md, Nix mode). Native Windows has no ``nix`` to interrupt, so
    there each Nix case holds what the pages say happens instead: the scan is refused
    with exit 1 and pointed at WSL2.
    """
    assert_on_page(EXIT_CODES, _SCAN_CTRL_C_ROW)
    assert_on_page(EXIT_CODES, _CHILD_CTRL_C_ROW)
    files = {"app.py": _CONFIG_SECRET}
    files.update(
        {
            f"bulk/module_{i}.py": f'TOKEN_{i} = "a8f3e9d1c7b6{i:08d}f0e1d2c3b4a5"\n'
            for i in range(200)
        }
    )
    source = _config_scan_tree(tmp_path, files)
    if mode == "nix" and os.name == "nt":
        assert_on_page(
            INSTALL_PAGE,
            "It needs Nix with flakes enabled, on Linux or macOS (on Windows, inside "
            "WSL2).",
        )
        assert_on_page(EXIT_CODES, "| 1 | Nix mode: `nix` is not installed |")
        refused = _ash(
            [*_CONFIG_SCAN, "--offline", "--source-dir", str(source), "--mode", "nix"],
            cwd=tmp_path,
        )
        assert refused.returncode == 1, _output_tail(refused)
        assert "on Windows use WSL2" in _normalize(refused.stdout + refused.stderr), (
            _output_tail(refused)
        )
        return
    if os.name == "nt" and mode == "container" and windows is None:
        windows, interrupts, terminal = "no-console", 1, False
    console = tmp_path / "console" if windows == "console" else None
    args, first_wait, env, stand_in_log = _interrupt_scan(
        mode, tmp_path, source, behavior or "stops", console
    )
    ended_at_once = windows == "no-console"
    waits = [first_wait]
    if interrupts == 2:
        assert stand_in_log is not None
        waits.append((stand_in_log, "INT"))
    if terminal:
        import pty

        controller, terminal_end = pty.openpty()
        try:
            result = _run_interrupted(
                tmp_path, args, waits, env, terminal=os.ttyname(terminal_end)
            )
        finally:
            os.close(terminal_end)
            os.close(controller)
    else:
        result = _run_interrupted(
            tmp_path, args, waits, env, windows=windows, console=console
        )
    ended = time.monotonic()

    output = _normalize(result.stdout + result.stderr)
    sent = [float(at) for at in _INTERRUPT_SENT_AT.findall(result.stderr)]
    assert len(sent) == interrupts, (
        f"{len(sent)} of {interrupts} SIGINTs sent; the scan ended before "
        f"{waits[len(sent)][1]!r} was in {waits[len(sent)][0].name}:\n"
        f"{_output_tail(result)}"
    )
    assert result.returncode == 130, (
        f"exit {result.returncode}, expected 130:\n{_output_tail(result)}"
    )
    assert _SCAN_INTERRUPTED in _normalize(result.stderr), _output_tail(result)
    log_file = tmp_path / "output" / "ash.log"
    logged = log_file.read_text("utf-8", "replace") if log_file.is_file() else ""
    for text in _SCAN_FINISHED_TEXT:
        assert text not in output, f"{text!r} after SIGINT:\n{_output_tail(result)}"
        assert text not in logged, f"{text!r} in ash.log after SIGINT"
    if stand_in_log is None:
        return

    events = _stand_in_events(stand_in_log)
    happened = [event for event, _ in events if event != "alive"]
    assert "orphaned" not in happened and "deadline" not in happened, (
        f"ASH left the stand-in running: {happened}"
    )
    if ended_at_once:
        _assert_ended_at_once(events, sent[0])
        return
    if behavior == "stops":
        assert happened == ["started", "INT", "CLEAN"], (
            f"the stand-in did not get the interrupt once and the time to stop: "
            f"{happened}"
        )
        return
    if windows == "console" and interrupts == 2:
        # The console sends the second Ctrl-C to the stand-in too, if it is still
        # running when it comes.
        assert happened[:2] == ["started", "INT"] and set(happened[2:]) <= {"INT"}, (
            happened
        )
    else:
        assert happened == ["started", "INT"], happened
    last_sign_of_life = max(at for _, at in events)
    if interrupts == 1:
        got_it = next(at for event, at in events if event == "INT")
        assert last_sign_of_life - got_it < _INTERRUPT_GRACE_SECONDS + 30, (
            f"the stand-in ran {last_sign_of_life - got_it:.1f} s after the interrupt"
        )
        assert ended - got_it < _INTERRUPT_GRACE_SECONDS + 30, (
            f"ASH ran {ended - got_it:.1f} s after the interrupt"
        )
    else:
        assert last_sign_of_life - sent[1] < _INTERRUPT_GRACE_SECONDS / 2, (
            f"the stand-in ran {last_sign_of_life - sent[1]:.1f} s after the second "
            f"SIGINT"
        )


_BUILD_ONLY_INTERRUPTED = "ASH build-image interrupted before it finished."
_BUILD_AND_SCAN_INTERRUPTED = (
    "ASH build-image interrupted before it finished: there is no verdict, and the output "
    "directory may hold partial results."
)


@pytest.mark.parametrize(
    "no_run, message, windows",
    [
        pytest.param(True, _BUILD_ONLY_INTERRUPTED, None, id="build-only"),
        pytest.param(False, _BUILD_AND_SCAN_INTERRUPTED, None, id="build-and-scan"),
        pytest.param(
            True, _BUILD_ONLY_INTERRUPTED, "console", id="windows-console-build-only"
        ),
        pytest.param(
            True,
            _BUILD_ONLY_INTERRUPTED,
            "no-console",
            id="windows-no-console-build-only",
        ),
    ],
)
@pytest.mark.integration
def test_ctrl_c_ends_ash_build_image_with_exit_code_130(
    tmp_path: Path, no_run: bool, message: str, windows: Optional[str]
) -> None:
    """exit-codes.md (Container and Nix mode).

    ``ash build-image`` runs in a child process against a stand-in container runtime
    (``OCI_RUNNER_WRAPPER``) whose ``build`` waits, and gets SIGINT once the build has
    started. It must exit 130 and print the page's message on stderr, with the scan's
    ending only without ``--no-run``. Outside Windows the runtime must get the interrupt
    and the time to stop (``stops``: 2 seconds). The Windows cases run on every
    platform, stood in for as in the scan's: with a console the runtime gets the
    console's Ctrl-C and the time to stop, and with none it gets no interrupt and is
    ended at once. On Windows itself the other cases run as the no-console one.
    """
    assert_on_page(EXIT_CODES, _CHILD_CTRL_C_ROW)
    if os.name == "nt" and windows is None:
        windows = "no-console"
    console = tmp_path / "console" if windows == "console" else None
    script, log = _interrupt_stand_in(tmp_path, "build", "stops", console)
    args = ["build-image", "--oci-runner", sys.executable, "--offline"]
    if no_run:
        args.append("--no-run")
    wrapper = shlex.join([sys.executable, str(script)])
    result = _run_interrupted(
        tmp_path,
        args,
        [(log, "started")],
        {"OCI_RUNNER_WRAPPER": wrapper},
        windows=windows,
        console=console,
    )
    assert _INTERRUPT_SENT in result.stderr, (
        f"the build ended before the runtime started:\n{_output_tail(result)}"
    )
    assert result.returncode == 130, (
        f"exit {result.returncode}, expected 130:\n{_output_tail(result)}"
    )
    stderr = _normalize(result.stderr)
    assert message in stderr, _output_tail(result)
    if no_run:
        assert "verdict" not in stderr, _output_tail(result)
    events = _stand_in_events(log)
    if windows == "no-console":
        sent = [float(at) for at in _INTERRUPT_SENT_AT.findall(result.stderr)]
        _assert_ended_at_once(events, sent[0])
        return
    happened = [event for event, _ in events if event != "alive"]
    assert happened == ["started", "INT", "CLEAN"], (
        f"the runtime did not get the interrupt once and the time to stop: {happened}"
    )


# --------------------------------------------------------------------------- #
# The MCP server's command line
# --------------------------------------------------------------------------- #

_MCP_EXITS_FOR_REFUSED_OPTIONS = (
    "`ash mcp` exits with code 5 for an unknown option, a value of the wrong type, options "
    "that cannot be combined, or an `ASH_MCP_TRANSPORT` that names no transport, and with "
    "code 3 when a `--profile` file does not load, is kept inside the MCP workspace root "
    "where a client could have supplied it (a config the server wrote there itself is "
    "fine), or sits inside a git checkout under a scan root `ASH_MCP_ALLOWED_ROOTS` grants, "
    "or when an HTTP transport cannot listen on its address."
)
_MCP_EXITS_WHEN_THE_SERVER_FAILS = (
    "It exits with code 1 when the MCP package is missing or the server fails, and prints "
    "the error to standard error even with `--quiet`."
)
_MCP_EXITS_ON_CTRL_C = (
    "Ctrl-C stops the server, and `ash mcp` exits with code 130 on every transport."
)
_MCP_STDIO_EXITS_0 = (
    "A stdio server exits with code 0 when the client closes the connection, and, on "
    "Linux and macOS, when it gets SIGTERM or SIGHUP."
)
#: exit-codes.md's ``ash mcp`` row for 0.
_MCP_EXIT_0_ROW = (
    "| 0 | The stdio transport's input closed, also while the server was writing to it; "
    "or the server was stopped with SIGTERM or SIGHUP: a stdio server on Linux and macOS, "
    "or an HTTP server with SIGHUP |"
)
_MCP_WINDOWS_CTRL_C_WAITS_FOR_THE_CLIENT = (
    "Ctrl-C there ends a stdio server with 130 only once the client has closed the "
    "connection."
)
_MCP_HTTP_ON_SIGTERM = (
    "An HTTP server that gets SIGTERM ends with the signal, which a shell reports as code "
    "143."
)
_MCP_NO_SIGTERM_ON_WINDOWS = (
    "On Windows the server sets up no SIGTERM handling: a client or supervisor that ends "
    "the process ends it at once, with the exit code that the ending process sets, and "
    "the running scans are not stopped first."
)


def _as_a_shell_reports_it(code: Optional[int]) -> Optional[int]:
    """A process's exit as a POSIX shell reports it: 128 plus the signal for one a
    signal ended, which ``subprocess`` reports as the negative signal number."""
    return 128 - code if code is not None and code < 0 else code


#: An MCP ``initialize`` request, as a client sends it first.
_MCP_INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "ash-page-claims", "version": "0"},
    },
}


class _CliResult(typing.NamedTuple):
    exit_code: int
    output: str


@pytest.fixture
def _mcp_cli(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Iterator[Callable[..., Any]]:
    """Run ``ash mcp`` in this process, with serving replaced by a recorder.

    Serving is the process boundary: stdio would read this process's standard input,
    and HTTP would bind a port. ``invoke(*args, **env)`` returns the exit code and
    what the command printed, and what was served, as ``("stdio", None)`` or
    ``("http", app)``. The profile registry the command fills is put back afterwards.

    The command runs as ``CliRunner.invoke`` runs it, through the click command's
    ``main`` in standalone mode, and its output is read with ``capsys``. Not through
    ``CliRunner``: with pytest's live logging on, a record logged during ``invoke``
    reassigns ``sys.stdout``, which finalizes the runner's own stream wrapper and
    closes the buffer it reads back (``_keep_live_logging_off_the_ash_logger`` in
    tests/conftest.py explains the mechanism). ``ash mcp`` logs through loggers
    other than ``ash``, so in the repository's own test run every invocation after
    the first failed with ``ValueError: I/O operation on closed file``.
    """
    import automated_security_helper.cli.mcp as mcp_cli
    import automated_security_helper.cli.mcp_server as mcp_server
    from automated_security_helper.cli.main import app
    from automated_security_helper.cli.mcp import profile_registry
    from typer.main import get_command

    for name in ("ASH_LOG_TO_STDERR", "ASH_MCP_TRANSPORT", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    served: List[Tuple[str, Any]] = []
    monkeypatch.setattr(
        mcp_server, "run_mcp_server", lambda *a, **k: served.append(("stdio", None))
    )
    monkeypatch.setattr(
        mcp_cli, "_run_uvicorn", lambda app, **kwargs: served.append(("http", app))
    )
    profiles = profile_registry.get_profile_registry()
    command = get_command(app)

    def invoke(*args: str, **env: str) -> Tuple[_CliResult, list]:
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        capsys.readouterr()
        try:
            command.main(args=["mcp", *args], prog_name="ash", standalone_mode=True)
            code = 0
        except SystemExit as stopped:
            # As CliRunner reads it: None is success, a message is failure.
            code = stopped.code
            if code is None:
                code = 0
            elif not isinstance(code, int):
                code = 1
        printed = capsys.readouterr()
        return _CliResult(code, printed.out + printed.err), served

    # The command can set variables in this process's environment for the rest of
    # its life, as ``ash mcp`` sets ASH_LOG_TO_STDERR on some trees; a later test's
    # child would inherit them. monkeypatch only undoes what it set itself.
    environment = dict(os.environ)
    yield invoke
    profile_registry.set_profile_registry(profiles)
    for name in set(os.environ) - set(environment):
        del os.environ[name]
    os.environ.update(environment)


def _mcp_child_env(cwd: Path) -> Dict[str, str]:
    """``_ash_environment`` without ``ASH_MCP_TRANSPORT``, for an ``ash mcp`` child."""
    environment = _ash_environment(cwd)
    environment.pop("ASH_MCP_TRANSPORT", None)
    return environment


def _mcp_run(argv: List[str], cwd: Path) -> subprocess.CompletedProcess:
    """Run ``argv`` (an interpreter command line) with no client on standard input."""
    return subprocess.run(
        argv,
        cwd=cwd,
        env=_mcp_child_env(cwd),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=300,
    )


_ASH_MODULE = [sys.executable, "-m", "automated_security_helper.cli.main"]


@pytest.mark.parametrize(
    "options, expected, env",
    [
        pytest.param(["--no-such-option"], 5, {}, id="unknown-option"),
        pytest.param(["--port", "not-a-number"], 5, {}, id="value-of-the-wrong-type"),
        pytest.param(
            ["--transport", "sse", "--stateless-http"],
            5,
            {},
            id="stateless-http-on-sse",
        ),
        pytest.param(
            ["--auth-header-name", "X-ASH-Token"], 5, {}, id="auth-header-name-alone"
        ),
        pytest.param(["--quiet", "--verbose"], 5, {}, id="quiet-with-verbose"),
        pytest.param(["--profile", "strict"], 3, {}, id="profile-spec-without-equals"),
        pytest.param(
            ["--profile", "strict={missing}"], 3, {}, id="profile-file-missing"
        ),
        pytest.param(
            ["--profile", "strict={unknown_key}"], 3, {}, id="profile-with-unknown-key"
        ),
        pytest.param(
            ["--profile", "strict={in_workspace}"],
            3,
            {"ASH_MCP_WORKSPACE_ROOT": "{workspace_root}"},
            id="profile-inside-the-mcp-workspace-root",
        ),
        pytest.param(
            ["--profile", "strict={in_checkout}"],
            3,
            {"ASH_MCP_ALLOWED_ROOTS": "{scan_root}"},
            id="profile-in-a-checkout-under-a-scan-root",
        ),
        pytest.param(
            ["--profile", "strict={server_written}"],
            0,
            {"ASH_MCP_WORKSPACE_ROOT": "{workspace_root}"},
            id="control-a-config-the-server-wrote-in-the-workspace-root",
        ),
        pytest.param(
            ["--profile", "strict={good}"], 0, {}, id="control-a-profile-that-loads"
        ),
        pytest.param(
            [
                "--transport",
                "streamable-http",
                "--stateless-http",
                "--auth-header-name",
                "X-ASH-Token",
                "--auth-header-value",
                "value",
            ],
            0,
            {},
            id="control-options-that-combine",
        ),
    ],
)
@pytest.mark.unit
def test_ash_mcp_refuses_options_with_the_exit_code_the_mcp_page_gives(
    _mcp_cli: Callable[..., Any],
    tmp_path: Path,
    options: List[str],
    expected: int,
    env: Dict[str, str],
) -> None:
    """mcp-server.md (How the server runs scans).

    Each command line runs through the ``ash`` app with serving replaced, and must exit
    with the code the paragraph gives without starting a server. The controls are a
    profile that loads, a profile the server itself wrote in a session's ``config/``
    directory under the workspace root, and options that combine, which start one.
    The two placements the paragraph refuses are built as named: a profile under a
    session's ``source/`` below the MCP workspace root, and one inside a directory
    holding a ``.git`` entry under a root ``ASH_MCP_ALLOWED_ROOTS`` grants; ``env``
    names the variable each placement is judged against.
    """
    from automated_security_helper.cli.mcp.profile_registry import (
        SESSION_CONFIG_FILENAME,
    )
    from automated_security_helper.cli.mcp.sandbox import CONFIG_DIR_NAME

    assert_on_page(MCP_SERVER, _MCP_EXITS_FOR_REFUSED_OPTIONS)
    workspace_root = tmp_path / "mcp-workspaces"
    session_dir = workspace_root / "a-session"
    (session_dir / "source").mkdir(parents=True)
    (session_dir / CONFIG_DIR_NAME).mkdir()
    scan_root = tmp_path / "scan-root"
    checkout = scan_root / "repo"
    (checkout / ".git").mkdir(parents=True)
    files = {
        "missing": tmp_path / "absent.yaml",
        "unknown_key": tmp_path / "unknown-key.yaml",
        "good": tmp_path / "good.yaml",
        "in_workspace": session_dir / "source" / "strict.yaml",
        "in_checkout": checkout / "strict.yaml",
        "server_written": session_dir / CONFIG_DIR_NAME / SESSION_CONFIG_FILENAME,
    }
    files["unknown_key"].write_text(
        "project_name: p\nno_such_top_level_key: 1\n", encoding="utf-8"
    )
    for name in ("good", "in_workspace", "in_checkout", "server_written"):
        files[name].write_text("project_name: p\n", encoding="utf-8")
    places = {"workspace_root": workspace_root, "scan_root": scan_root}
    args = [option.format(**files) for option in options]

    result, served = _mcp_cli(
        *args, **{name: value.format(**places) for name, value in env.items()}
    )
    assert result.exit_code == expected, (
        f"ash mcp {shlex.join(args)} exited {result.exit_code}, expected {expected}:\n"
        f"{result.output[-1500:]}"
    )
    assert bool(served) == (expected == 0), served


def _mcp_cannot_listen(
    cwd: Path, monkeypatch: pytest.MonkeyPatch, mcp_cli
) -> Tuple[int, str]:
    # The test holds a loopback port, listening, for as long as the server runs, so
    # the server's bind on it is refused by the operating system whatever else the
    # host runs. Exclusive on Windows, where SO_REUSEADDR, which uvicorn sets, would
    # otherwise let the server bind it too.
    with socket.socket() as held:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            held.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        held.bind(("127.0.0.1", 0))
        held.listen()
        port = held.getsockname()[1]
        result = _mcp_run(
            [
                *_ASH_MODULE,
                "mcp",
                "--quiet",
                "--transport",
                "streamable-http",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            cwd,
        )
    return result.returncode, result.stderr


def _mcp_package_missing(
    cwd: Path, monkeypatch: pytest.MonkeyPatch, mcp_cli
) -> Tuple[int, str]:
    # A child interpreter in which the MCP SDK cannot be imported.
    driver = (
        "import sys\n"
        "sys.modules['mcp'] = None\n"
        "from automated_security_helper.cli.main import app\n"
        "sys.argv = ['ash', 'mcp', '--quiet']\n"
        "app()\n"
    )
    result = _mcp_run([sys.executable, "-c", driver], cwd)
    return result.returncode, result.stderr


def _mcp_server_fails(
    cwd: Path, monkeypatch: pytest.MonkeyPatch, mcp_cli
) -> Tuple[int, str]:
    # A mount path without a leading slash fails when the server builds its HTTP app,
    # before it listens.
    result = _mcp_run(
        [
            *_ASH_MODULE,
            "mcp",
            "--quiet",
            "--transport",
            "streamable-http",
            "--mount-path",
            "mcp",
        ],
        cwd,
    )
    return result.returncode, result.stderr


def _mcp_client_closes(
    cwd: Path, monkeypatch: pytest.MonkeyPatch, mcp_cli
) -> Tuple[int, str]:
    result = _mcp_run([*_ASH_MODULE, "mcp", "--quiet"], cwd)
    assert result.stdout == "", f"the server wrote to stdout: {result.stdout[:300]!r}"
    return result.returncode, result.stderr


@pytest.mark.parametrize(
    "case, expected, on_stderr",
    [
        pytest.param(_mcp_cannot_listen, 3, None, id="http-transport-cannot-listen"),
        pytest.param(
            _mcp_package_missing,
            1,
            "MCP dependencies are not available",
            id="mcp-package-missing",
        ),
        pytest.param(
            _mcp_server_fails, 1, "Routed paths must start with '/'", id="server-fails"
        ),
        pytest.param(_mcp_client_closes, 0, None, id="stdio-client-closes"),
    ],
)
@pytest.mark.integration
def test_ash_mcp_exit_code_when_the_server_cannot_start_or_its_client_leaves(
    _mcp_cli: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: Callable[..., Tuple[int, str]],
    expected: int,
    on_stderr: Optional[str],
) -> None:
    """mcp-server.md (How the server runs scans).

    The HTTP port is one the test holds, the MCP SDK is made unimportable in a child
    interpreter, the server is given a mount path it cannot route, and a stdio client
    closes standard input at once. Each must end with the code the paragraph gives, and
    a failure must reach standard error under ``--quiet``. The stdio case is the
    control for the others: the same command with a client that leaves exits 0.
    """
    assert_on_page(MCP_SERVER, _MCP_EXITS_FOR_REFUSED_OPTIONS)
    assert_on_page(MCP_SERVER, _MCP_EXITS_WHEN_THE_SERVER_FAILS)
    assert_on_page(MCP_SERVER, _MCP_STDIO_EXITS_0)
    code, stderr = case(tmp_path, monkeypatch, _mcp_cli)
    assert code == expected, f"exit {code}, expected {expected}:\n{stderr[-1500:]}"
    if on_stderr is not None:
        assert on_stderr in " ".join(stderr.split()), stderr[-1500:]


#: Runs ``argv[2:]`` with SIGTERM as its parent-death signal (Linux ``prctl``), so a
#: server whose test worker is killed ends with it rather than run on under init.
#: ``argv[1]`` is the parent's pid: a parent that died before the signal was set is
#: caught by the check after it.
_PARENT_DEATH_LAUNCHER = """\
import ctypes, os, signal, sys
ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM)
if os.getppid() != int(sys.argv[1]):
    sys.exit(1)
os.execvp(sys.argv[2], sys.argv[2:])
"""

#: The server children the running test started; ``_reap_server_children`` ends them.
_SERVER_CHILDREN: List[subprocess.Popen] = []

#: How long a server start is tried when the operating system answers that it cannot
#: make a process now (``EAGAIN``). A macOS runner refused a start for longer than two
#: seconds while sibling tests held their servers, and those servers end only when
#: their tests do, so the bound is a time budget and not a count of attempts: the
#: start is tried again until ``_START_WINDOW_SECONDS`` have passed since the first
#: attempt, which lets the sibling tests end. The pause after the first refusal is
#: ``_START_PAUSE_SECONDS`` and each later pause is that much longer, up to
#: ``_START_PAUSE_CAP_SECONDS``: 0.5, 1.0, 1.5, 2.0, 2.0 seconds and so on.
_START_WINDOW_SECONDS = 60.0
_START_PAUSE_SECONDS = 0.5
_START_PAUSE_CAP_SECONDS = 2.0


def _eagain_note(attempts: int, waited: float) -> str:
    """What the last refusal says about the host: how many starts were refused over
    how many seconds, the process limit the host reports, the processor count and the
    platform. Nothing here starts a process, because a new process is what the host
    refused."""
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
        limit = f"RLIMIT_NPROC soft={soft} hard={hard}"
    except (ImportError, AttributeError, ValueError, OSError):
        limit = "RLIMIT_NPROC unavailable"
    return (
        f"the host refused to make a new process {attempts} times over "
        f"{waited:.1f} seconds (EAGAIN); {limit}; cpu_count={os.cpu_count()}; "
        f"platform={sys.platform}"
    )


def _popen_after_eagain(
    argv: List[str],
    kwargs: Dict[str, Any],
    *,
    popen: Optional[Callable[..., Any]] = None,
    pause: Optional[Callable[[float], None]] = None,
    clock: Optional[Callable[[], float]] = None,
) -> Any:
    """``popen(argv, **kwargs)``, tried again when the operating system refuses to make
    a process for now.

    A macOS runner answered ``BlockingIOError: [Errno 35] Resource temporarily
    unavailable`` from ``fork_exec`` for a server start on some jobs and not on others
    running the same test, so the refusal is a property of the host at that moment and
    not of the call. Only ``EAGAIN`` is tried again, with a growing pause, until
    ``_START_WINDOW_SECONDS`` have passed since the first attempt. The last refusal is
    raised with a note saying how many starts were refused and what limit the host
    reports (``_eagain_note``), and any other error (a missing program, a refused
    argument) is raised unchanged at the first attempt. On Python 3.10, which has no
    exception notes, the last refusal is raised as a new ``BlockingIOError`` with the
    same errno and the note in its message, chained from the refusal.

    ``popen``, ``pause`` and ``clock`` default to ``subprocess.Popen``, ``time.sleep``
    and ``time.monotonic``, looked up when called, and are parameters so a test can
    answer the start, skip the pause and move the clock.
    """
    now = clock or time.monotonic
    started = now()
    attempt = 0
    while True:
        attempt += 1
        try:
            return (popen or subprocess.Popen)(argv, **kwargs)
        except BlockingIOError as refused:
            if refused.errno != errno.EAGAIN:
                raise
            waited = now() - started
            if waited >= _START_WINDOW_SECONDS:
                note = _eagain_note(attempt, waited)
                if hasattr(refused, "add_note"):
                    refused.add_note(note)
                    raise
                raise BlockingIOError(
                    refused.errno, f"{refused.strerror}; {note}"
                ) from refused
        (pause or time.sleep)(
            min(_START_PAUSE_SECONDS * attempt, _START_PAUSE_CAP_SECONDS)
        )


def _server_popen(argv: List[str], **kwargs: Any) -> subprocess.Popen:
    """``subprocess.Popen(argv, **kwargs)`` for a server child that must not outlive
    its test: in a session of its own on POSIX, so its process group can be ended
    whole; with SIGTERM as its parent-death signal on Linux; and ended with its group
    when the test ends, whatever the outcome (``_reap_server_children``).

    The parent-death signal fires when the thread that started the child exits, not
    only the process, so call this from the test's own thread, never from a helper
    thread that ends before the server should.
    """
    if sys.platform == "linux":
        argv = [
            sys.executable,
            "-I",
            "-c",
            _PARENT_DEATH_LAUNCHER,
            str(os.getpid()),
            *argv,
        ]
    if os.name != "nt":
        kwargs["start_new_session"] = True
    process = _popen_after_eagain(argv, kwargs)
    _SERVER_CHILDREN.append(process)
    return process


def _end_server_child(process: subprocess.Popen) -> None:
    """End ``process`` and the rest of its process group, and reap it.

    On POSIX the group is ended only while its leader is unreaped. The group is the
    server's own session, so its id is the server's pid, which an unreaped leader,
    a zombie included, still holds. Once the leader is reaped the number is free, and
    on a shared host another session's group leader can be given it. So a process
    left in the group of a server the test reaped itself is not ended here.
    """
    if os.name != "nt":
        # ``returncode`` is read rather than ``poll()``ed: poll would reap the leader.
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGKILL)
    elif process.poll() is None:
        process.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=30)


@pytest.fixture(autouse=True)
def _reap_server_children() -> Iterator[None]:
    """End every server child the test started with ``_server_popen``, after the
    test, passed or failed."""
    yield
    while _SERVER_CHILDREN:
        _end_server_child(_SERVER_CHILDREN.pop())


def _eagain() -> BlockingIOError:
    """The error a host gives when it cannot make a process now."""
    return BlockingIOError(errno.EAGAIN, "Resource temporarily unavailable")


def _fake_popen(
    outcomes: List[Any],
) -> Tuple[Callable[..., Any], List[Tuple[List[str], Dict[str, Any]]]]:
    """A stand-in for ``subprocess.Popen`` that answers each call with the next
    outcome, raising it when it is an exception, and the calls it received. No process
    starts."""
    calls: List[Tuple[List[str], Dict[str, Any]]] = []

    def popen(argv: List[str], **kwargs: Any) -> Any:
        calls.append((argv, kwargs))
        outcome = outcomes[len(calls) - 1]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    return popen, calls


class _FakeTime:
    """A clock that moves only when the retry pauses, and the pauses it was asked
    for. Nothing sleeps."""

    def __init__(self) -> None:
        self.now = 0.0
        self.pauses: List[float] = []

    def clock(self) -> float:
        return self.now

    def pause(self, seconds: float) -> None:
        self.pauses.append(seconds)
        self.now += seconds


@pytest.mark.unit
def test_a_server_start_the_host_refuses_twice_is_made_a_third_time() -> None:
    """Two ``EAGAIN`` answers are waited out with a growing pause, and the third
    attempt's process is the result. Each attempt gets the same arguments. The clock
    stays inside the window, so the retry does not give up."""
    started = object()
    popen, calls = _fake_popen([_eagain(), _eagain(), started])
    pauses: List[float] = []
    result = _popen_after_eagain(
        ["server", "--quiet"],
        {"cwd": "here"},
        popen=popen,
        pause=pauses.append,
        clock=lambda: 0.0,
    )
    assert result is started
    assert calls == [(["server", "--quiet"], {"cwd": "here"})] * 3, calls
    assert pauses == pytest.approx([0.5, 1.0]), pauses


@pytest.mark.unit
def test_a_server_start_the_host_always_refuses_raises_the_last_refusal() -> None:
    """The retry gives up once the window is spent on the injected clock: the pauses
    grow by half a second to the cap and stay there, there is no pause after the last
    attempt, and the error raised is the last refusal itself with a note naming the
    process limit (a chained ``BlockingIOError`` with the note in its message on
    Python 3.10, which has no exception notes)."""
    refusals = [_eagain() for _ in range(200)]
    popen, calls = _fake_popen(list(refusals))
    fake = _FakeTime()
    with pytest.raises(BlockingIOError) as raised:
        _popen_after_eagain(
            ["server"], {}, popen=popen, pause=fake.pause, clock=fake.clock
        )
    pauses = fake.pauses
    assert pauses[:5] == pytest.approx([0.5, 1.0, 1.5, 2.0, 2.0]), pauses
    assert set(pauses[3:]) == {_START_PAUSE_CAP_SECONDS}, pauses
    assert sum(pauses) >= _START_WINDOW_SECONDS, pauses
    assert sum(pauses[:-1]) < _START_WINDOW_SECONDS, pauses
    assert len(calls) == len(pauses) + 1, (len(calls), len(pauses))
    error = raised.value
    assert error.errno == errno.EAGAIN
    if hasattr(error, "add_note"):
        assert error is refusals[len(calls) - 1]
        text = "\n".join(error.__notes__)
    else:
        assert error.__cause__ is refusals[len(calls) - 1]
        text = str(error)
    assert "RLIMIT_NPROC" in text, text
    assert f"{len(calls)} times" in text, text


@pytest.mark.unit
def test_a_server_start_the_host_refuses_for_ten_seconds_is_made_when_it_allows_one() -> (
    None
):
    """A host that refuses for ten seconds and then allows a start gives the process:
    the retry waits the ten seconds out, on the injected clock and without a real
    pause, and does not give up at the old two-second mark."""
    started = object()
    fake = _FakeTime()
    calls: List[float] = []

    def popen(argv: List[str], **kwargs: Any) -> Any:
        calls.append(fake.now)
        if fake.now < 10.0:
            raise _eagain()
        return started

    result = _popen_after_eagain(
        ["server"], {}, popen=popen, pause=fake.pause, clock=fake.clock
    )
    assert result is started
    assert fake.pauses == pytest.approx([0.5, 1.0, 1.5, 2.0, 2.0, 2.0, 2.0]), (
        fake.pauses
    )
    assert len(calls) == len(fake.pauses) + 1, calls
    assert calls[-1] >= 10.0 > calls[-2], calls


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(FileNotFoundError(errno.ENOENT, "no such program"), id="missing"),
        pytest.param(PermissionError(errno.EACCES, "not executable"), id="denied"),
        pytest.param(
            BlockingIOError(errno.EBADF, "not an EAGAIN answer"), id="other-errno"
        ),
    ],
)
@pytest.mark.unit
def test_a_server_start_failing_for_another_reason_is_not_tried_again(
    error: OSError,
) -> None:
    """Only ``EAGAIN`` is waited out: a program that is not there, one that cannot run,
    and a ``BlockingIOError`` with another errno each raise at the first attempt, with
    no pause."""
    popen, calls = _fake_popen([error, object()])
    pauses: List[float] = []
    with pytest.raises(OSError) as raised:
        _popen_after_eagain(["server"], {}, popen=popen, pause=pauses.append)
    assert raised.value is error
    assert len(calls) == 1, calls
    assert pauses == []


@pytest.mark.unit
def test_a_server_start_made_by_the_helper_the_tests_use_goes_through_the_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_server_popen``, which every server start in this file uses, starts through
    ``_popen_after_eagain`` and keeps the child for ``_reap_server_children``."""
    started = object()
    seen: List[Tuple[List[str], Dict[str, Any]]] = []

    def answer(argv: List[str], kwargs: Dict[str, Any]) -> Any:
        seen.append((argv, dict(kwargs)))
        return started

    monkeypatch.setattr(sys.modules[__name__], "_popen_after_eagain", answer)
    try:
        assert _server_popen(["server", "--quiet"], cwd="here") is started
        assert _SERVER_CHILDREN[-1] is started
    finally:
        # The stand-in is not a process: keep it from the reaper that follows.
        with contextlib.suppress(ValueError):
            _SERVER_CHILDREN.remove(started)
    assert len(seen) == 1, seen
    argv, kwargs = seen[0]
    assert argv[-2:] == ["server", "--quiet"], argv
    assert kwargs["cwd"] == "here"
    if os.name != "nt":
        assert kwargs["start_new_session"] is True, kwargs


def _mcp_serving_stdio(
    cwd: Path, command: Optional[List[str]] = None
) -> subprocess.Popen:
    """A stdio ``ash mcp`` that has answered a client's ``initialize``.

    ``command`` is the interpreter command line that runs it, ``ash mcp --quiet`` by
    default.
    """
    process = _server_popen(
        command or [*_ASH_MODULE, "mcp", "--quiet"],
        cwd=cwd,
        env=_mcp_child_env(cwd),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write((json.dumps(_MCP_INITIALIZE) + "\n").encode("utf-8"))
    process.stdin.flush()
    answers: "queue.Queue[bytes]" = queue.Queue()
    threading.Thread(
        target=lambda: answers.put(process.stdout.readline()), daemon=True
    ).start()
    try:
        answer = json.loads(answers.get(timeout=_MCP_CHILD_SECONDS))
    except Exception:
        process.kill()
        raise
    assert answer.get("id") == 1 and "result" in answer, answer
    return process


#: How long a server child may take to start, and to exit once told to stop.
#: Generous on purpose: these run beside 48 test workers on a host whose load average
#: reaches 400, and a deadline only bounds a hang, so a long one costs nothing when
#: the server is quick. Stopping is shorter, because a server that is still running
#: two minutes after the signal is the failure the stop tests look for.
_MCP_CHILD_SECONDS = 300
_MCP_STOP_SECONDS = 120


class _Lines:
    """Every line a child's pipe gives, read on a thread of its own, so the pipe never
    fills and blocks the child, and a test can wait for one line."""

    def __init__(self, pipe: Any) -> None:
        self.lines: List[str] = []
        self._new: "queue.Queue[Optional[str]]" = queue.Queue()
        self._reader = threading.Thread(target=self._read, args=(pipe,), daemon=True)
        self._reader.start()

    def _read(self, pipe: Any) -> None:
        for raw in iter(pipe.readline, b""):
            line = raw.decode("utf-8", "replace")
            self.lines.append(line)
            self._new.put(line)
        self._new.put(None)

    def wait_for(self, pattern: "re.Pattern[str]") -> Optional["re.Match[str]"]:
        """The first match of ``pattern`` in a new line, or None at the end of the
        pipe or after ``_MCP_CHILD_SECONDS``."""
        deadline = time.monotonic() + _MCP_CHILD_SECONDS
        while (remaining := deadline - time.monotonic()) > 0:
            try:
                line = self._new.get(timeout=remaining)
            except queue.Empty:
                return None
            if line is None:
                return None
            match = pattern.search(line)
            if match:
                return match
        return None

    def text(self) -> str:
        self._reader.join(timeout=30)
        return "".join(self.lines)


def _mcp_stopped(
    process: subprocess.Popen, stop: Callable[[], None], stderr: Optional[_Lines] = None
) -> Tuple[int, str]:
    """(exit code, standard error) of ``process`` once ``stop`` has been called on it.

    The control is asserted first: the server is still running just before ``stop``.
    Standard input stays open until it has exited, so a client leaving cannot be what
    stopped it. ``stderr`` is the reader already draining the child's standard error,
    if there is one.
    """
    try:
        assert process.poll() is None, "the server stopped before it was signaled"
        stop()
        code = process.wait(timeout=_MCP_STOP_SECONDS)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=30)
        for stream in (process.stdin, process.stdout):
            if stream:
                stream.close()
        if stderr is not None:
            text = stderr.text()
        else:
            text = (
                process.stderr.read().decode("utf-8", "replace")
                if process.stderr
                else ""
            )
        if process.stderr:
            process.stderr.close()
    return code, text


@pytest.mark.parametrize("name", ["SIGTERM", "SIGHUP"])
@pytest.mark.integration
def test_ash_mcp_on_stdio_exits_0_on_sigterm_or_sighup(
    tmp_path: Path, name: str
) -> None:
    """mcp-server.md (How the server runs scans; Run over stdio), and exit-codes.md
    (ash mcp).

    A stdio server answers a client's ``initialize``, and then gets SIGTERM or SIGHUP
    while the client still holds standard input open. On Linux and macOS it must exit
    0. On Windows the server handles no SIGTERM, so the process ends with the code the
    process ending it sets: ``Popen.send_signal(SIGTERM)`` is ``TerminateProcess`` with
    code 1 there; and Windows has no SIGHUP, so that case holds that the signal does not
    exist. The control is the same server still running just before the signal.
    """
    assert_on_page(MCP_SERVER, _MCP_STDIO_EXITS_0)
    assert_on_page(MCP_SERVER, _MCP_NO_SIGTERM_ON_WINDOWS)
    assert_on_page(EXIT_CODES, _MCP_EXIT_0_ROW)
    if os.name == "nt" and name == "SIGHUP":
        assert not hasattr(signal, "SIGHUP")
        return
    expected = 1 if os.name == "nt" else 0
    process = _mcp_serving_stdio(tmp_path)
    code, stderr = _mcp_stopped(
        process, lambda: process.send_signal(getattr(signal, name))
    )
    assert code == expected, (
        f"{name}: exit {code}, expected {expected}:\n{stderr[-1500:]}"
    )


@pytest.mark.integration
def test_ctrl_c_stops_a_stdio_mcp_server_with_exit_code_130(tmp_path: Path) -> None:
    """mcp-server.md (How the server runs scans), and exit-codes.md (ash mcp).

    A stdio server answers a client's ``initialize`` and then gets SIGINT, which is
    what Ctrl-C sends, while the client still holds standard input open. It must exit
    130. The server runs as ``_INTERRUPTED_ASH`` runs it, which sends the signal once
    the test writes the file it watches. The control is the same server still running
    just before the signal. On Windows the server exits only once the client has closed
    the connection, so there the client closes standard input once the signal is sent,
    and the exit must still be 130.
    """
    assert_on_page(MCP_SERVER, _MCP_EXITS_ON_CTRL_C)
    assert_on_page(EXIT_CODES, _MCP_WINDOWS_CTRL_C_WAITS_FOR_THE_CLIENT)
    go = tmp_path / "interrupt-now.txt"
    process = _mcp_serving_stdio(
        tmp_path, [*_interrupter([(go, "now")]), "mcp", "--quiet"]
    )
    lines = _Lines(process.stderr)

    def interrupt() -> None:
        go.write_text("now", encoding="utf-8")
        if os.name == "nt":
            assert lines.wait_for(re.compile(re.escape(_INTERRUPT_SENT))) is not None
            assert process.stdin is not None
            process.stdin.close()

    code, stderr = _mcp_stopped(process, interrupt, lines)
    assert _INTERRUPT_SENT in stderr, stderr[-1500:]
    assert code == 130, f"Ctrl-C: exit {code}, expected 130:\n{stderr[-1500:]}"


#: The line uvicorn logs once it listens, with the port it bound.
_UVICORN_LISTENING = re.compile(r"Uvicorn running on http://127\.0\.0\.1:(\d+)")


def _mcp_http_server(
    cwd: Path,
    command: List[str],
    transport: str = "streamable-http",
    env: Optional[Dict[str, str]] = None,
    options: Iterable[str] = (),
) -> Tuple[subprocess.Popen, int, _Lines]:
    """An HTTP ``ash mcp`` on loopback, streamable HTTP unless ``transport`` names
    ``sse``, once it says it listens: the process, its port, and the reader of its
    standard error.

    ``command`` is the interpreter command line before ``mcp``, ``options`` more
    ``ash mcp`` options, and ``env`` its environment, ``_mcp_child_env`` unless
    given. The server binds port 0, so the operating system gives it a free port and
    no other test can take that port between a choice and the bind; the port is read
    from uvicorn's ``Uvicorn running on`` line, which it logs even under ``--quiet``.
    Only 127.0.0.1 is bound. The server ends with its test, whatever the outcome
    (``_server_popen``).
    """
    process = _server_popen(
        [
            *command,
            "mcp",
            "--quiet",
            "--transport",
            transport,
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            *options,
        ],
        cwd=cwd,
        env=env if env is not None else _mcp_child_env(cwd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    stderr = _Lines(process.stderr)
    listening = stderr.wait_for(_UVICORN_LISTENING)
    if listening is None:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=30)
        raise AssertionError(
            f"the HTTP server did not say it listens within {_MCP_CHILD_SECONDS} s "
            f"(exit {process.returncode}):\n{stderr.text()[-1500:]}"
        )
    port = int(listening.group(1))
    with socket.create_connection(("127.0.0.1", port), timeout=30):
        pass
    return process, port, stderr


@pytest.mark.integration
def test_ctrl_c_stops_an_http_mcp_server_with_exit_code_130(tmp_path: Path) -> None:
    """mcp-server.md (How the server runs scans).

    A streamable-HTTP server on a loopback port gets SIGINT once it says it listens,
    and must exit 130. It runs as ``_INTERRUPTED_ASH`` runs it, which sends the signal
    once the test writes the file it watches. The control is the same server still
    running just before the signal.
    """
    assert_on_page(MCP_SERVER, _MCP_EXITS_ON_CTRL_C)
    go = tmp_path / "interrupt-now.txt"
    process, _port, lines = _mcp_http_server(tmp_path, _interrupter([(go, "now")]))
    code, stderr = _mcp_stopped(
        process, lambda: go.write_text("now", encoding="utf-8"), lines
    )
    assert _INTERRUPT_SENT in stderr, stderr[-1500:]
    assert code == 130, f"Ctrl-C: exit {code}, expected 130:\n{stderr[-1500:]}"


@pytest.mark.integration
def test_sigterm_ends_an_http_mcp_server_with_the_signal(tmp_path: Path) -> None:
    """mcp-server.md (How the server runs scans; Run over stdio).

    A streamable-HTTP server on a loopback port gets SIGTERM once the port accepts
    connections. Outside Windows a shell must report 143, 128 + 15, and the server
    must end with the signal rather than exit with 143 itself: ``subprocess`` reports
    -15. On Windows the server handles no SIGTERM, so it ends with the code the process
    ending it sets, 1 for ``Popen.send_signal``. The control is the same server still
    running just before the signal.
    """
    assert_on_page(MCP_SERVER, _MCP_HTTP_ON_SIGTERM)
    assert_on_page(MCP_SERVER, _MCP_NO_SIGTERM_ON_WINDOWS)
    assert_on_page(
        EXIT_CODES,
        "| 143 | An HTTP server was stopped with SIGTERM: the HTTP server ends the "
        "process with the signal, which a shell reports as 128 + 15 |",
    )
    expected = 1 if os.name == "nt" else 128 + signal.SIGTERM
    process, _port, lines = _mcp_http_server(tmp_path, list(_ASH_MODULE))
    code, stderr = _mcp_stopped(
        process, lambda: process.send_signal(signal.SIGTERM), lines
    )
    reported = _as_a_shell_reports_it(code)
    assert reported == expected, (
        f"SIGTERM: a shell reports {reported} (exit {code}), expected {expected}:\n"
        f"{stderr[-1500:]}"
    )
    if os.name != "nt":
        assert code == -signal.SIGTERM, (
            f"SIGTERM: exit {code}, where the signal itself ends the server:\n"
            f"{stderr[-1500:]}"
        )


@pytest.mark.integration
def test_sighup_stops_an_http_mcp_server_which_then_exits_0(tmp_path: Path) -> None:
    """mcp-server.md (How the server runs scans).

    A streamable-HTTP server on a loopback port gets SIGHUP once the port accepts
    connections, and must exit 0, as a server asked to stop does, rather than end with
    the signal, as an unhandled SIGHUP ends a process. The control is the same server
    still running just before the signal. Windows has no SIGHUP, so there the case holds
    that the signal does not exist.
    """
    assert_on_page(MCP_SERVER, _MCP_SIGHUP)
    assert_on_page(EXIT_CODES, _MCP_EXIT_0_ROW)
    if os.name == "nt":
        assert not hasattr(signal, "SIGHUP")
        return
    process, _port, lines = _mcp_http_server(tmp_path, list(_ASH_MODULE))
    code, stderr = _mcp_stopped(
        process, lambda: process.send_signal(signal.SIGHUP), lines
    )
    assert code == 0, f"SIGHUP: exit {code}, expected 0:\n{stderr[-1500:]}"


#: A test module for the cell below. Its first test starts an HTTP ``ash mcp`` with
#: ``_mcp_http_server`` and fails, or, with KILL true, kills its own pytest process;
#: its second test checks that the first one's server is gone.
_A_SERVER_AND_A_FAILING_CELL = """\
import importlib.util
import os
import signal
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location("page_claims_under_test", {claims!r})
claims = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(claims)
_reap_server_children = claims._reap_server_children
PIDS = Path({pids!r})


def test_1_a_cell_that_starts_a_server_and_fails(tmp_path):
    process, _port, _lines = claims._mcp_http_server(tmp_path, list(claims._ASH_MODULE))
    PIDS.write_text(str(process.pid), encoding="utf-8")
    if {kill!r}:
        os.kill(os.getpid(), signal.SIGKILL)
    raise AssertionError("this cell fails on purpose")


def test_2_its_server_is_gone():
    pid = int(PIDS.read_text(encoding="utf-8"))
    assert not claims._process_alive(pid), f"the server {{pid}} outlived its test"
"""


@pytest.mark.parametrize(
    "ending",
    [
        "a-cell-that-fails",
        *(["a-worker-that-is-killed"] if sys.platform == "linux" else []),
    ],
)
@pytest.mark.integration
def test_no_mcp_server_outlives_the_cell_that_started_it(
    tmp_path: Path, ending: str
) -> None:
    """The guard on the servers this file starts (``_server_popen``).

    A pytest session in a child process runs a module whose first cell starts an HTTP
    ``ash mcp`` with ``_mcp_http_server`` and then fails on purpose. Its second cell
    must find that server gone: ``_reap_server_children`` ends it at the first cell's
    teardown. On Linux, the other case kills the child pytest itself while the server
    runs, as a worker killed by a timeout is: the server must end within
    ``_MCP_STOP_SECONDS`` on the parent-death signal. Either way this test ends a
    server it finds still running.
    """
    pids = tmp_path / "server.pid"
    module = tmp_path / "test_a_server_and_a_failing_cell.py"
    module.write_text(
        _A_SERVER_AND_A_FAILING_CELL.format(
            claims=str(Path(__file__).resolve()),
            pids=str(pids),
            kill=ending == "a-worker-that-is-killed",
        ),
        encoding="utf-8",
    )
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(module),
                "-p",
                "no:cacheprovider",
                "-o",
                "addopts=",
                "-q",
                "--rootdir",
                str(tmp_path),
                "--confcutdir",
                str(tmp_path),
                "--basetemp",
                str(tmp_path / "inner"),
            ],
            cwd=tmp_path,
            env=_ash_environment(tmp_path),
            capture_output=True,
            text=True,
            timeout=900,
        )
        assert pids.is_file(), _output_tail(result)
        pid = int(pids.read_text(encoding="utf-8"))
        if ending == "a-cell-that-fails":
            assert result.returncode == 1, _output_tail(result)
            assert "1 failed, 1 passed" in result.stdout, _output_tail(result)
            return
        assert result.returncode == -signal.SIGKILL, _output_tail(result)
        deadline = time.monotonic() + _MCP_STOP_SECONDS
        while _process_alive(pid):
            assert time.monotonic() < deadline, f"the server {pid} outlived its worker"
            time.sleep(0.1)
    finally:
        if pids.is_file():
            _end_leftover_server(int(pids.read_text(encoding="utf-8")), tmp_path)


def _end_leftover_server(pid: int, root: Path) -> None:
    """End the MCP server ``pid`` that a child pytest under ``root`` started, if it is
    still running, on Linux; elsewhere do nothing.

    The pid was never this process's child, so it may be free or another process's
    by now. It is held through a pidfd, which stays with the process it was opened
    for, and signalled only when ``/proc/<pid>/cwd`` resolves under ``root`` and its
    command line holds ``mcp``. Off Linux nothing is signalled: the killed-worker case
    runs only on Linux, and in the other case the child's own fixture ended the
    server.
    """
    if sys.platform != "linux":
        return
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        try:
            cwd = Path(os.readlink(f"/proc/{pid}/cwd")).resolve()
            argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        except OSError:
            return
        if not cwd.is_relative_to(root.resolve()) or b"mcp" not in argv:
            return
        with contextlib.suppress(ProcessLookupError):
            signal.pidfd_send_signal(fd, signal.SIGKILL)
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    "child", ["reaped-by-the-test", *(["control-unreaped"] if os.name != "nt" else [])]
)
@pytest.mark.integration
def test_ending_a_server_child_signals_its_group_only_while_its_leader_is_unreaped(
    monkeypatch: pytest.MonkeyPatch, child: str
) -> None:
    """The guard on ``_end_server_child``.

    A server child the test has already waited for has given up its pid, which may
    now lead another session's process group: ending it must signal no group. The
    control is a child still running, whose group is ended with SIGKILL.
    """
    calls: List[Tuple[int, int]] = []
    real_killpg = getattr(os, "killpg", None)

    def recording_killpg(pid: int, sig: int) -> None:
        calls.append((pid, sig))
        assert real_killpg is not None
        real_killpg(pid, sig)

    monkeypatch.setattr(os, "killpg", recording_killpg, raising=False)
    code = "pass" if child == "reaped-by-the-test" else "import time; time.sleep(60)"
    process = _server_popen([sys.executable, "-I", "-c", code])
    if child == "reaped-by-the-test":
        process.wait(timeout=60)

    _end_server_child(process)

    if child == "reaped-by-the-test":
        assert calls == [], calls
        return
    assert calls == [(process.pid, signal.SIGKILL)], calls
    assert process.returncode == -signal.SIGKILL, process.returncode


@pytest.mark.parametrize(
    "where",
    (
        ["outside-the-root", "under-the-root"]
        if sys.platform == "linux"
        else ["off-linux-nothing-is-signaled"]
    ),
)
@pytest.mark.integration
def test_a_leftover_server_is_ended_only_when_it_runs_under_the_root(
    tmp_path: Path, where: str
) -> None:
    """The guard on ``_end_leftover_server``.

    A child whose command line holds ``mcp`` runs with its working directory outside
    the root, or under it. Only the one under the root may be ended; the other must
    still be running after the call, and is then ended through its own handle. Off
    Linux nothing is signalled.
    """
    root = tmp_path / "root"
    cwd = root / "inner" if where == "under-the-root" else tmp_path / "elsewhere"
    cwd.mkdir(parents=True)
    # The child says it is ready once it runs its own command line in its own
    # directory, which is what the helper reads.
    ready = "import sys, time; print('ready', flush=True); time.sleep(60)"
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", ready, "mcp"], cwd=cwd, stdout=subprocess.PIPE
    )
    try:
        assert child.stdout is not None and child.stdout.readline() == b"ready\n"
        _end_leftover_server(child.pid, root)
        if where == "under-the-root":
            assert child.wait(timeout=60) == -signal.SIGKILL, child.returncode
        else:
            # A SIGKILL ends it within milliseconds, so 3 s still running is enough.
            with pytest.raises(subprocess.TimeoutExpired):
                child.wait(timeout=3)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=60)
        if child.stdout:
            child.stdout.close()


#: The sentences on how a server stops, and what its stopped scans leave.
_MCP_SIGHUP = (
    "SIGHUP stops an HTTP server the way SIGTERM does, and `ash mcp` then exits with "
    "code 0."
)
_MCP_STOPPED_BY_A_SIGNAL = (
    "When the client closes the connection, or, on Linux and macOS, the server gets "
    "SIGTERM, SIGHUP, or Ctrl-C, it cancels every running scan as `cancel_scan` would"
)
_MCP_STOPS_WITH_THE_CONNECTION_OPEN = (
    "SIGTERM, SIGHUP, and Ctrl-C stop the server this way even while the client keeps "
    "the connection open, and it exits with code 0 for SIGTERM and SIGHUP and 130 for "
    "Ctrl-C."
)
_MCP_KEEPS_IGNORING_SIGINT = (
    "On every transport, a server started with SIGINT ignored, as a non-interactive "
    "shell starts a background job, keeps ignoring it, so a Ctrl-C meant for the job in "
    "the foreground does not stop it."
)
_MCP_KEEPS_IGNORING_SIGHUP = (
    "A server started with SIGHUP ignored, as `nohup` starts one, keeps ignoring that "
    "too, and outlives the terminal it was started from. SIGTERM still stops either."
)
_MCP_STOPPED_SCAN_OUTPUT = (
    "A scan that stops in time leaves its output directory as `cancel_scan` does: "
    "previous results are put back, and with none, what the scan wrote before it "
    "stopped stays."
)
_MCP_STOPPED_SCAN_LOGS = (
    "Its log, `ash.log`, stays either way, and an `ash.log.jsonl` already there is "
    "left as it was."
)
_MCP_WINDOWS_LEAVES_RESULTS_HELD = (
    "Their previous results stay in `.ash_previous_results` the same way."
)
_MCP_WINDOWS_CTRL_C = (
    "Ctrl-C there does not reach the scanners' tools, which run in process groups of "
    "their own, but the server stops its scans as it does when the client leaves. It "
    "exits, with code 130, only once the client has closed the connection, because the "
    "MCP SDK reads standard input on a thread that Ctrl-C cannot interrupt."
)
_CANCEL_PUTS_BACK = (
    "When the output directory held a previous scan's results, they are put back in "
    "place of every result the canceled scan wrote; its log, `ash.log`, stays, and an "
    "`ash.log.jsonl` already there is left as it was."
)
_CANCEL_LEAVES = (
    "With no previous results, what the scan wrote before it stopped stays, except "
    "that a cancel during the report phase removes the reports that phase wrote and "
    "every other file a reporter wrote beside them, `reports/ash.unused-suppressions.md` "
    "included."
)
MCP_TOOLS = "reference/mcp-tools.md"

#: An ASH plugin package, in ASH's plugin namespace, for the stop tests. Its scanner
#: writes a file into its results directory and then runs a stand-in tool, a child
#: process that records its pid and waits two minutes unless told to return, so the
#: scan stays in the scan phase until it is stopped. Its reporter returns a short
#: report; when told to, it first says it started and waits for the test to say go.
#: The control directory PAGE_CLAIMS_CONTROL names holds the files that tell them.
#: The scanner's ``marker`` option, when a config sets it, is written to ``marker.txt``
#: there, so a test can read the value the scan was given.
_MCP_STOP_PLUGIN = '''\
import os, sys, time
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field

from automated_security_helper.base.options import (
    ReporterOptionsBase,
    ScannerOptionsBase,
)
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.plugins.decorators import (
    ash_reporter_plugin,
    ash_scanner_plugin,
)

CONTROL = Path(os.environ["PAGE_CLAIMS_CONTROL"])
TOOL = """\\
import os, sys, time
from pathlib import Path

control = Path(sys.argv[1])
(control / "tool.pid").write_text(str(os.getpid()), encoding="utf-8")
if not (control / "tool-returns").exists():
    time.sleep(120)
"""


class StopScannerOptions(ScannerOptionsBase):
    marker: str = ""


class StopScannerConfig(ScannerPluginConfigBase):
    name: Literal["page-claims-stop"] = "page-claims-stop"
    enabled: bool = True
    options: Annotated[StopScannerOptions, Field()] = StopScannerOptions()


@ash_scanner_plugin
class StopScanner(ScannerPluginBase[StopScannerConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = StopScannerConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError

    def scan(self, target, target_type, config: Any = None, *args, **kwargs):
        self._pre_scan(target, target_type, config)
        if self.config.options.marker:
            (CONTROL / "marker.txt").write_text(
                self.config.options.marker, encoding="utf-8"
            )
        if target_type == "source":
            results = Path(self.results_dir)
            results.mkdir(parents=True, exist_ok=True)
            (results / "partial.txt").write_text("before the stop", encoding="utf-8")
            self._run_subprocess(
                [sys.executable, "-c", TOOL, str(CONTROL)],
                results_dir=str(results),
                stdout_preference="none",
                stderr_preference="none",
            )
        self._post_scan(target, target_type)
        return {"findings": []}


class StopReporterOptions(ReporterOptionsBase):
    pass


class StopReporterConfig(ReporterPluginConfigBase):
    name: Literal["page-claims-stop-reporter"] = "page-claims-stop-reporter"
    extension: str = "page-claims.txt"
    enabled: bool = True
    options: Annotated[StopReporterOptions, Field()] = StopReporterOptions()


@ash_reporter_plugin
class StopReporter(ReporterPluginBase[StopReporterConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = StopReporterConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:
        if (CONTROL / "reporter-waits").exists():
            (CONTROL / "reporter.started").write_text("started", encoding="utf-8")
            deadline = time.monotonic() + 120
            while not (CONTROL / "go").exists() and time.monotonic() < deadline:
                time.sleep(0.05)
        return "page claims report"


ASH_SCANNERS = [StopScanner]
ASH_REPORTERS = [StopReporter]
'''
_MCP_STOP_MODULE = "page_claims_stop_ash_plugins"

#: The previous scan's results, set out in a project's output directory before a scan.
_MCP_PREVIOUS_RESULTS = {
    "reports/ash.sarif": '{"previous": "sarif"}',
    "ash_aggregated_results.json": '{"previous": "results"}',
}
#: A previous scan's log, beside its results: what a stopped scan logged must stay,
#: not this. An MCP scan writes ``ash.log`` and no ``ash.log.jsonl``, so only
#: ``ash.log`` has a stopped scan's own content to check.
_MCP_PREVIOUS_LOGS = {"ash.log": "page-claims: the previous scan's log\n"}
#: An ``ash.log.jsonl`` in the output directory before the scan, with or without
#: previous results: a stopped or canceled scan must leave it as it was.
_MCP_JSONL_LOG = ("ash.log.jsonl", '{"page-claims": "an earlier JSON log"}\n')


def _process_alive(pid: int) -> bool:
    """Whether a process with ``pid`` is still running."""
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            status = ctypes.c_ulong()
            kernel32.GetExitCodeProcess(handle, ctypes.byref(status))
            return status.value == 259
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class _McpStopSetup(typing.NamedTuple):
    project: Path
    output: Path
    control: Path
    env: Dict[str, str]


def _mcp_stop_setup(tmp_path: Path, previous: bool) -> _McpStopSetup:
    """A project to scan, with the previous results in its output directory or not,
    and the environment for an ``ash mcp`` that scans it with the stop plugin only.

    The operator config the server reads (``ASH_CONFIG``, outside every checkout)
    turns off every built-in scanner and names the plugin package, which is first on
    ``PYTHONPATH``.
    """
    from automated_security_helper.config.ash_config import AshConfig

    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = project / ".ash" / "ash_output"
    if previous:
        for name, text in {**_MCP_PREVIOUS_RESULTS, **_MCP_PREVIOUS_LOGS}.items():
            (output / name).parent.mkdir(parents=True, exist_ok=True)
            (output / name).write_text(text, encoding="utf-8")
    output.mkdir(parents=True, exist_ok=True)
    (output / _MCP_JSONL_LOG[0]).write_text(_MCP_JSONL_LOG[1], encoding="utf-8")
    control = tmp_path / "control"
    control.mkdir()
    plugins = tmp_path / "plugins" / _MCP_STOP_MODULE
    plugins.mkdir(parents=True)
    (plugins / "__init__.py").write_text(_MCP_STOP_PLUGIN, encoding="utf-8")
    builtin = AshConfig().scanners.model_dump(by_alias=True)
    operator = tmp_path / "etc" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        yaml.safe_dump(
            {
                "project_name": "page-claims-stop",
                "ash_plugin_modules": [_MCP_STOP_MODULE],
                "scanners": {name: {"enabled": False} for name in builtin},
            }
        ),
        encoding="utf-8",
    )
    env = _mcp_child_env(tmp_path)
    env.update(
        {
            "ASH_CONFIG": str(operator),
            "ASH_MCP_ALLOWED_ROOTS": str(tmp_path),
            "PAGE_CLAIMS_CONTROL": str(control),
            "PYTHONPATH": os.pathsep.join(
                p for p in (str(plugins.parent), os.environ.get("PYTHONPATH")) if p
            ),
        }
    )
    return _McpStopSetup(project=project, output=output, control=control, env=env)


class _McpStdioClient:
    """A stdio ``ash mcp`` child and the client end of its connection, which stays open
    until the test closes it. ``call`` sends a JSON-RPC request and returns the answer
    with its id; a reader thread takes every line, so the pipe never fills."""

    def __init__(self, command: List[str], cwd: Path, env: Dict[str, str]) -> None:
        self.process = _server_popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.stderr = _Lines(self.process.stderr)
        self._answers: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self._id = 0
        try:
            self.call("initialize", _MCP_INITIALIZE["params"])
            self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        except BaseException:
            self.close()
            raise

    def _read(self) -> None:
        assert self.process.stdout is not None
        for raw in iter(self.process.stdout.readline, b""):
            try:
                message = json.loads(raw)
            except ValueError:
                continue
            if isinstance(message, dict) and "id" in message:
                self._answers.put(message)
        self._answers.put(None)

    def _send(self, message: Dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        self.process.stdin.flush()

    def call(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self._id += 1
        self._send(
            {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        )
        deadline = time.monotonic() + _MCP_CHILD_SECONDS
        while (remaining := deadline - time.monotonic()) > 0:
            answer = self._answers.get(timeout=remaining)
            if answer is None:
                raise AssertionError(
                    f"the server closed stdout before answering {method}:\n"
                    f"{''.join(self.stderr.lines)[-1500:]}"
                )
            if answer.get("id") == self._id:
                return answer
        raise AssertionError(f"no answer to {method} in {_MCP_CHILD_SECONDS} s")

    def tool(self, name: str, **arguments: Any) -> Dict[str, Any]:
        answer = self.call("tools/call", {"name": name, "arguments": arguments})
        assert "result" in answer, answer
        return answer["result"]["structuredContent"]["result"]

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=30)
        for stream in (self.process.stdin, self.process.stdout):
            if stream:
                stream.close()


def _wait_for_file(path: Path, what: str) -> None:
    deadline = time.monotonic() + _MCP_CHILD_SECONDS
    while not path.exists():
        assert time.monotonic() < deadline, f"{what} never happened"
        time.sleep(0.05)


def _wait_until_stopped(pid: int, held: Path) -> None:
    """Until the stand-in tool with ``pid`` is gone and nothing is set aside in
    ``held``: the scan has stopped and put back what it was going to put back."""
    deadline = time.monotonic() + _MCP_STOP_SECONDS
    while _process_alive(pid) or held.exists():
        assert time.monotonic() < deadline, (
            f"the scan had not stopped {_MCP_STOP_SECONDS} s after the cancel: "
            f"tool alive {_process_alive(pid)}, {held.name} there {held.exists()}"
        )
        time.sleep(0.1)


def _wait_until_settled(directory: Path) -> None:
    """Until no file under ``directory`` has appeared, gone or changed for two seconds,
    within ``_MCP_STOP_SECONDS``: what a stopped scan leaves is read once it is final."""

    def snapshot() -> Set[Tuple[str, int, int]]:
        found = set()
        for path in directory.rglob("*") if directory.exists() else []:
            try:
                status = path.stat()
            except OSError:
                continue
            found.add((path.as_posix(), status.st_size, status.st_mtime_ns))
        return found

    deadline = time.monotonic() + _MCP_STOP_SECONDS
    last, since = snapshot(), time.monotonic()
    while time.monotonic() - since < 2:
        assert time.monotonic() < deadline, f"{directory} kept changing"
        time.sleep(0.1)
        now = snapshot()
        if now != last:
            last, since = now, time.monotonic()


def _kill_stand_in(control: Path) -> None:
    pid_file = control / "tool.pid"
    if pid_file.exists():
        pid = int(pid_file.read_text(encoding="utf-8"))
        if _process_alive(pid):
            os.kill(pid, signal.SIGKILL if hasattr(signal, "SIGKILL") else 9)


def _assert_the_scans_logs_stayed(output: Path) -> None:
    """The stopped scan's own ``ash.log`` is in ``output``, not a previous scan's, and
    the ``ash.log.jsonl`` that was there before the scan is as it was."""
    for name, previous in _MCP_PREVIOUS_LOGS.items():
        log = output / name
        assert log.is_file(), f"the stopped scan's {name} did not stay"
        assert log.read_text(encoding="utf-8", errors="replace") != previous, (
            f"{name} is the previous scan's, put back over the stopped scan's"
        )
    jsonl = output / _MCP_JSONL_LOG[0]
    assert jsonl.is_file(), f"{_MCP_JSONL_LOG[0]} was removed"
    assert jsonl.read_text(encoding="utf-8") == _MCP_JSONL_LOG[1], (
        f"{_MCP_JSONL_LOG[0]} was changed"
    )


def _assert_previous_results_back(output: Path) -> None:
    found = {
        name: (output / name).read_text(encoding="utf-8")
        if (output / name).is_file()
        else None
        for name in _MCP_PREVIOUS_RESULTS
    }
    assert found == _MCP_PREVIOUS_RESULTS, (
        f"the previous results were not put back: {found}"
    )
    assert not list(output.glob("scanners/page-claims-stop/**/partial.txt")), (
        "the stopped scan's own file stayed beside the previous results"
    )


def _assert_previous_results_intact(output: Path) -> None:
    """The previous results of a server that was ended at once are intact, in one of
    the states the product allows: still held in ``.ash_previous_results``, halfway
    back in ``.ash_previous_results.restoring`` (a restore renames the held set there
    and moves the entries back from it), or put back where they were, each entry as
    the setup wrote it. Which one is a race between the scan unwinding and the exit."""
    found = {
        name: (output / name).read_text(encoding="utf-8")
        if (output / name).is_file()
        else None
        for name in _MCP_PREVIOUS_RESULTS
    }
    states = []
    if (output / ".ash_previous_results").is_dir():
        states.append("held")
    if (output / ".ash_previous_results.restoring").is_dir():
        states.append("halfway back")
    if found == _MCP_PREVIOUS_RESULTS:
        states.append("put back")
    assert states, (
        "the previous results are in none of the states the product allows (held, "
        f"halfway back, put back): found {found}, the output directory holds "
        f"{sorted(entry.name for entry in output.iterdir())}"
    )


@pytest.mark.parametrize("stop", ["sigterm", "sighup", "ctrl-c"])
@pytest.mark.e2e
def test_a_signal_stops_a_stdio_scan_while_the_client_keeps_the_connection_open(
    tmp_path: Path, stop: str
) -> None:
    """mcp-server.md (Run over stdio).

    A stdio server, its client holding standard input open throughout, starts a scan of
    a project whose output directory holds a previous scan's results and logs. The scan
    runs a plugin scanner whose tool waits two minutes. Once the tool runs, the server
    gets SIGTERM, SIGHUP, or SIGINT, which is what Ctrl-C sends. On Linux and macOS it
    must cancel the scan and exit, 0 for SIGTERM and SIGHUP and 130 for Ctrl-C: the
    tool is stopped, the previous results are back in place of what the scan wrote, and
    the scan's own ``ash.log`` stays, and the ``ash.log.jsonl`` that was there before
    the scan is left as it was. The control is the scan under way, its tool running,
    just before the signal.

    On Windows the server handles no SIGTERM, so ``send_signal`` there ends it at once
    with code 1, the scan is not stopped first, and its previous results stay set aside
    in ``.ash_previous_results``; and there is no SIGHUP, which that case holds. Ctrl-C
    there stops the scans as the client leaving does, and the server exits only once
    the client has closed the connection, so there the client closes standard input
    once the signal is sent, and the exit must be 130 with the results put back.
    """
    assert_on_page(MCP_SERVER, _MCP_STOPPED_BY_A_SIGNAL)
    assert_on_page(MCP_SERVER, _MCP_STOPS_WITH_THE_CONNECTION_OPEN)
    assert_on_page(MCP_SERVER, _MCP_STOPPED_SCAN_OUTPUT)
    assert_on_page(MCP_SERVER, _MCP_STOPPED_SCAN_LOGS)
    assert_on_page(MCP_SERVER, _MCP_NO_SIGTERM_ON_WINDOWS)
    assert_on_page(MCP_SERVER, _MCP_WINDOWS_LEAVES_RESULTS_HELD)
    assert_on_page(MCP_SERVER, _MCP_WINDOWS_CTRL_C)
    if os.name == "nt" and stop == "sighup":
        assert not hasattr(signal, "SIGHUP")
        return
    setup = _mcp_stop_setup(tmp_path, previous=True)
    go = tmp_path / "interrupt-now.txt"
    command = (
        [*_interrupter([(go, "now")]), "mcp", "--quiet"]
        if stop == "ctrl-c"
        else [*_ASH_MODULE, "mcp", "--quiet"]
    )
    client = _McpStdioClient(command, setup.project, setup.env)
    try:
        begun = client.tool("run_ash_scan", source_dir=str(setup.project))
        assert begun.get("success") is True, begun
        _wait_for_file(setup.control / "tool.pid", "the scanner's tool starting")
        pid = int((setup.control / "tool.pid").read_text(encoding="utf-8"))
        assert client.process.poll() is None and _process_alive(pid)
        if stop == "ctrl-c":
            go.write_text("now", encoding="utf-8")
            if os.name == "nt":
                sent = client.stderr.wait_for(re.compile(re.escape(_INTERRUPT_SENT)))
                assert sent is not None, "".join(client.stderr.lines)[-1500:]
                assert client.process.stdin is not None
                client.process.stdin.close()
        else:
            client.process.send_signal(getattr(signal, stop.upper()))
        code = client.process.wait(timeout=_MCP_STOP_SECONDS)
        stderr = client.stderr.text()
        if os.name == "nt" and stop == "sigterm":
            assert code == 1, f"exit {code}, expected 1:\n{stderr[-1500:]}"
            assert (setup.output / ".ash_previous_results").is_dir(), (
                "the previous results were not left set aside"
            )
            return
        expected = 130 if stop == "ctrl-c" else 0
        assert code == expected, f"exit {code}, expected {expected}:\n{stderr[-1500:]}"
        _wait_until_stopped(pid, setup.output / ".ash_previous_results")
        _assert_previous_results_back(setup.output)
        _assert_the_scans_logs_stayed(setup.output)
    finally:
        client.close()
        _kill_stand_in(setup.control)


@pytest.mark.parametrize("ignored", ["SIGINT", "SIGHUP"])
@pytest.mark.parametrize("transport", ["stdio", "streamable-http", "sse"])
@pytest.mark.e2e
def test_an_mcp_server_started_with_a_signal_ignored_keeps_ignoring_it(
    tmp_path: Path, transport: str, ignored: str
) -> None:
    """mcp-server.md (Run over stdio; How the server runs scans).

    A server on each transport starts with SIGINT ignored, as a non-interactive shell
    starts a background job, or with SIGHUP ignored, as ``nohup`` starts a command, and
    gets that signal once it serves. It must keep serving: a stdio server answers the
    next request, an HTTP server still accepts a connection, and either is still running
    five seconds later, where a server that stopped on the signal exits at once. SIGTERM
    must then still stop it: a stdio server exits 0, and an HTTP server ends with the
    signal. The control for SIGINT is that it was sent, as the server's standard error
    says. SIGINT reaches the server as ``_INTERRUPTED_ASH`` sends it; SIGHUP comes from
    the test.

    Windows has no SIGHUP, so those cases hold that the signal does not exist; and the
    server there handles no SIGTERM, which ends it at once with code 1.
    """
    assert_on_page(MCP_SERVER, _MCP_KEEPS_IGNORING_SIGINT)
    assert_on_page(MCP_SERVER, _MCP_KEEPS_IGNORING_SIGHUP)
    assert_on_page(MCP_SERVER, _MCP_HTTP_ON_SIGTERM)
    assert_on_page(MCP_SERVER, _MCP_NO_SIGTERM_ON_WINDOWS)
    if os.name == "nt" and ignored == "SIGHUP":
        assert not hasattr(signal, "SIGHUP")
        return
    go = tmp_path / "interrupt-now.txt"
    command = _interrupter(
        [(go, "now")] if ignored == "SIGINT" else [],
        ignore_sigint=ignored == "SIGINT",
        ignore_sighup=ignored == "SIGHUP",
    )
    sent_line = re.compile(re.escape(_INTERRUPT_SENT))
    if transport == "stdio":
        client = _McpStdioClient(
            [*command, "mcp", "--quiet"], tmp_path, _mcp_child_env(tmp_path)
        )
        process, lines = client.process, client.stderr
    else:
        process, port, lines = _mcp_http_server(tmp_path, command, transport)
    try:
        if ignored == "SIGINT":
            go.write_text("now", encoding="utf-8")
            assert lines.wait_for(sent_line) is not None, "".join(lines.lines)[-1500:]
        else:
            process.send_signal(signal.SIGHUP)
        if transport == "stdio":
            listed = client.call("tools/list", {})
            assert "result" in listed, listed
        else:
            with socket.create_connection(("127.0.0.1", port), timeout=30):
                pass
        with pytest.raises(subprocess.TimeoutExpired):
            process.wait(timeout=5)
        process.send_signal(signal.SIGTERM)
        code = process.wait(timeout=_MCP_STOP_SECONDS)
        if os.name == "nt":
            expected = 1
        else:
            expected = 0 if transport == "stdio" else 128 + signal.SIGTERM
        reported = _as_a_shell_reports_it(code)
        assert reported == expected, (
            f"SIGTERM after an ignored {ignored}: a shell reports {reported} (exit "
            f"{code}), expected {expected}:\n{''.join(lines.lines)[-1500:]}"
        )
        if os.name != "nt" and transport != "stdio":
            assert code == -signal.SIGTERM, (
                f"SIGTERM after an ignored {ignored}: exit {code}, where the signal "
                f"itself ends the server:\n{''.join(lines.lines)[-1500:]}"
            )
    finally:
        if transport == "stdio":
            client.close()
        elif process.poll() is None:
            process.kill()
            process.wait(timeout=30)


@pytest.mark.parametrize(
    "previous, phase",
    [
        pytest.param(True, "scan", id="previous-results-are-put-back"),
        pytest.param(False, "scan", id="with-none-earlier-output-stays"),
        pytest.param(False, "report", id="a-report-phase-cancel-removes-its-reports"),
    ],
)
@pytest.mark.e2e
def test_a_cancelled_mcp_scan_leaves_its_output_directory_as_the_pages_say(
    tmp_path: Path, previous: bool, phase: str
) -> None:
    """mcp-tools.md (cancel_scan), and mcp-server.md (Run over stdio).

    A stdio server starts a scan of a project, with or without a previous scan's
    results in its output directory, and the client cancels it with ``cancel_scan``.
    In the scan phase the cancel lands while the plugin scanner's tool runs, after the
    scanner wrote ``partial.txt``: with previous results, they must be back in place of
    every result the scan wrote, and the scan's own ``ash.log`` must stay, not the
    previous scan's; with none, ``partial.txt`` must stay. In the report phase
    the cancel lands while the plugin reporter, which runs after ASH's own, waits: the
    reports that phase wrote must be gone, ``reports/ash.unused-suppressions.md``, which
    its reporter writes beside them, with them. In every case the scan's ``ash.log`` must stay, and an
    ``ash.log.jsonl`` that was there before the scan must be left as it was. The
    control in each case is the scan under way when the cancel is sent, and for the
    report phase that ASH's reports were written by then.
    """
    assert_on_page(MCP_TOOLS, _CANCEL_PUTS_BACK)
    assert_on_page(MCP_TOOLS, _CANCEL_LEAVES)
    assert_on_page(MCP_SERVER, _MCP_STOPPED_SCAN_OUTPUT)
    setup = _mcp_stop_setup(tmp_path, previous=previous)
    if phase == "report":
        (setup.control / "tool-returns").write_text("", encoding="utf-8")
        (setup.control / "reporter-waits").write_text("", encoding="utf-8")
    client = _McpStdioClient([*_ASH_MODULE, "mcp", "--quiet"], setup.project, setup.env)
    try:
        begun = client.tool("run_ash_scan", source_dir=str(setup.project))
        assert begun.get("success") is True, begun
        reports = setup.output / "reports"
        if phase == "report":
            _wait_for_file(setup.control / "reporter.started", "the plugin reporter")
            written = sorted(p.name for p in reports.iterdir())
            assert "ash.sarif" in written and "ash.unused-suppressions.md" in written, (
                written
            )
        else:
            _wait_for_file(setup.control / "tool.pid", "the scanner's tool starting")
        pid = int((setup.control / "tool.pid").read_text(encoding="utf-8"))
        cancelled = client.tool("cancel_scan", scan_id=begun["scan_id"])
        assert cancelled.get("success") is True, cancelled
        (setup.control / "go").write_text("", encoding="utf-8")
        _wait_until_stopped(pid, setup.output / ".ash_previous_results")
        deadline = time.monotonic() + _MCP_STOP_SECONDS
        while True:
            progress = client.tool("get_scan_progress", scan_id=begun["scan_id"])
            if progress.get("is_complete") and progress.get("end_time"):
                break
            assert time.monotonic() < deadline, progress
            time.sleep(0.25)
        assert progress.get("status") == "cancelled", progress
        _wait_until_settled(setup.output)
    finally:
        client.close()
        _kill_stand_in(setup.control)

    _assert_the_scans_logs_stayed(setup.output)
    if previous:
        _assert_previous_results_back(setup.output)
    elif phase == "scan":
        partial = list(setup.output.glob("scanners/page-claims-stop/**/partial.txt"))
        assert partial, "what the scan wrote before it stopped did not stay"
    else:
        left = sorted(p.name for p in reports.iterdir()) if reports.is_dir() else []
        assert left == [], f"after a report-phase cancel, reports/ holds {left}"


#: mcp-server.md's paragraph on how an HTTP server stops (Run over streamable HTTP).
_HTTP_STOPS = (
    "Ctrl-C, SIGTERM, or SIGHUP stops an HTTP server: it stops its running scans and "
    "their scanners' tools, and `ash mcp` exits with code 130 for Ctrl-C and 0 for "
    "SIGHUP, or ends by SIGTERM, which a shell reports as code 143."
)
_HTTP_WAITS_FOR_OPEN_REQUESTS = (
    "Before it stops the scans, the server waits for the requests clients still hold "
    "open, for at most 5 seconds, and then cancels them."
)
_HTTP_STOP_FITS_THE_GRACE = (
    "The wait is bounded so that the whole stop fits inside the grace period a service "
    "manager gives before it sends SIGKILL, such as the 10 seconds `docker stop` waits "
    "by default"
)
_HTTP_SECOND_CTRL_C = (
    "A second Ctrl-C during the wait ends the server at once, with code 130. It kills "
    "the scanners' tools without waiting for the scans, and previous results a scan had "
    "not put back stay in `.ash_previous_results`, where the next MCP scan of that "
    "directory takes them back."
)
#: The page's "at most 5 seconds", and the 10 seconds ``docker stop`` waits, inside
#: which the whole stop fits.
_HTTP_DRAIN_SECONDS = 5
_DOCKER_STOP_GRACE_SECONDS = 10


class _McpHttpClient:
    """The client end of one session with a streamable-HTTP ``ash mcp`` on loopback.

    Each request is a connection of its own, closed once it is answered, so that none
    of this client's requests is left open for the server's stop to wait on. ``tool``
    calls a tool and returns its result. The server answers with a JSON body or with an
    event stream, whose ``data`` lines are read for the answer.

    A stateful server issues the session's id on ``initialize``. A stateless server
    started with ``--trust-upstream-session-id`` issues none and takes the
    ``Mcp-Session-Id`` the client sends as the session, the way a platform in front
    of ASH would set it; ``session_id`` is that header, sent on every request from
    ``initialize`` on.
    """

    def __init__(self, port: int, session_id: Optional[str] = None) -> None:
        self.port = port
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if session_id is not None:
            self.headers["mcp-session-id"] = session_id
        answer, response = self._post(_MCP_INITIALIZE)
        assert "result" in answer, answer
        if session_id is None:
            session = response.getheader("mcp-session-id")
            assert session, "the server gave the session no id"
            self.headers["mcp-session-id"] = session
        self.headers["mcp-protocol-version"] = answer["result"]["protocolVersion"]
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self._id = _MCP_INITIALIZE["id"]

    def _post(
        self, message: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], http.client.HTTPResponse]:
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=_MCP_CHILD_SECONDS
        )
        try:
            connection.request(
                "POST", "/mcp", body=json.dumps(message), headers=self.headers
            )
            response = connection.getresponse()
            body = response.read().decode("utf-8", "replace")
        finally:
            connection.close()
        method = message["method"]
        if "id" not in message:
            assert response.status == 202, f"{method}: HTTP {response.status}: {body}"
            return {}, response
        assert response.status == 200, f"{method}: HTTP {response.status}: {body}"
        if (response.getheader("content-type") or "").startswith("text/event-stream"):
            payloads = [
                line[len("data:") :]
                for line in body.splitlines()
                if line.startswith("data:")
            ]
        else:
            payloads = [body]
        for payload in payloads:
            answer = json.loads(payload)
            if isinstance(answer, dict) and answer.get("id") == message["id"]:
                return answer, response
        raise AssertionError(f"no answer to {method} in:\n{body[-1500:]}")

    def tool(self, name: str, **arguments: Any) -> Dict[str, Any]:
        self._id += 1
        call = {"name": name, "arguments": arguments}
        answer, _response = self._post(
            {"jsonrpc": "2.0", "id": self._id, "method": "tools/call", "params": call}
        )
        assert "result" in answer, answer
        return answer["result"]["structuredContent"]["result"]


def _hold_a_request_open(client: _McpHttpClient) -> socket.socket:
    """A connection with a ``tools/list`` request in ``client``'s session that the
    server has begun and the client never finishes.

    The request asks for ``100 Continue`` before its body, which uvicorn sends once
    the app reads the body, so the answer shows the server has the request under way.
    The body is never sent: the request stays open until the server cancels it or the
    test closes the connection.
    """
    body = json.dumps({"jsonrpc": "2.0", "id": "held", "method": "tools/list"})
    head = [
        "POST /mcp HTTP/1.1",
        f"Host: 127.0.0.1:{client.port}",
        *(f"{name}: {value}" for name, value in client.headers.items()),
        f"Content-Length: {len(body)}",
        "Expect: 100-continue",
    ]
    held = socket.create_connection(
        ("127.0.0.1", client.port), timeout=_MCP_CHILD_SECONDS
    )
    try:
        held.sendall(("\r\n".join(head) + "\r\n\r\n").encode("ascii"))
        answer = b""
        while b"\r\n\r\n" not in answer:
            chunk = held.recv(4096)
            assert chunk, f"the server closed the request it was to hold: {answer!r}"
            answer += chunk
        assert answer.startswith(b"HTTP/1.1 100 "), answer
    except BaseException:
        held.close()
        raise
    return held


def _gone_soon(pid: int) -> bool:
    """Whether the process with ``pid`` is gone within two seconds: time for the
    process that ends it, or the one that inherits it, to reap it."""
    deadline = time.monotonic() + 2
    while _process_alive(pid):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.05)
    return True


@pytest.mark.parametrize(
    "stop, held_open",
    [
        pytest.param("ctrl-c", True, id="ctrl-c"),
        pytest.param("sigterm", True, id="sigterm"),
        pytest.param("sighup", True, id="sighup"),
        pytest.param("second-ctrl-c", True, id="a-second-ctrl-c-during-the-wait"),
        pytest.param("ctrl-c", False, id="control-no-request-open"),
    ],
)
@pytest.mark.e2e
def test_an_http_mcp_server_waits_at_most_5_seconds_for_open_requests_when_it_stops(
    tmp_path: Path, stop: str, held_open: bool
) -> None:
    """mcp-server.md (Run over streamable HTTP).

    A streamable-HTTP server starts a scan of a project whose output directory holds a
    previous scan's results, and the plugin scanner's tool runs. A second connection
    then holds a request open: the server has begun it, and its body never comes. The
    server gets Ctrl-C, SIGTERM, or SIGHUP. Halfway through the page's 5 seconds it
    must still be running, and so must the tool, since the scans stop only after the
    wait. It must exit no sooner than 5 seconds after the signal, the request still
    open, and within the 10 seconds ``docker stop`` waits: 130 for Ctrl-C, 0 for
    SIGHUP, and for SIGTERM ended by the signal, which a shell reports as 143. By then
    the tool must be gone, and the scan, stopped in time, must have put the previous
    results back, with its own ``ash.log`` beside them.

    With a second Ctrl-C a second after the first, the server must exit with 130
    within half the wait of it, before the 5 seconds are up. The tool must be gone.
    The second Ctrl-C does not wait for the scans, and the page says: "previous
    results a scan had not put back stay in `.ash_previous_results`". A scan that
    unwound first may have put them back, or be halfway through, so they must be
    intact in one of three states: still held, halfway back in
    ``.ash_previous_results.restoring``, or put back where they were. The next MCP scan
    of that directory, over stdio and canceled while its tool runs, must then put
    those results back, as it puts back previous results it found in place.

    With no request open, the control, Ctrl-C must end the server sooner than 5
    seconds after the signal: the wait is for the open requests. The control in every
    case is the scan under way, its tool running and the request held, just before the
    signal. Ctrl-C reaches the server as ``_INTERRUPTED_ASH`` sends it.

    Windows has no SIGHUP, which that case holds, and the server there handles no
    SIGTERM, so that case must end at once with code 1, as ``Popen.send_signal`` ends
    it.
    """
    assert_on_page(MCP_SERVER, _HTTP_STOPS)
    assert_on_page(MCP_SERVER, _HTTP_WAITS_FOR_OPEN_REQUESTS)
    assert_on_page(MCP_SERVER, _HTTP_STOP_FITS_THE_GRACE)
    assert_on_page(MCP_SERVER, _HTTP_SECOND_CTRL_C)
    assert_on_page(MCP_SERVER, _MCP_NO_SIGTERM_ON_WINDOWS)
    if os.name == "nt" and stop == "sighup":
        assert not hasattr(signal, "SIGHUP")
        return
    setup = _mcp_stop_setup(tmp_path, previous=True)
    held_dir = setup.output / ".ash_previous_results"
    go = tmp_path / "interrupt-now.txt"
    if stop == "second-ctrl-c":
        command = _interrupter([(go, "first"), (go, "second")])
    elif stop == "ctrl-c":
        command = _interrupter([(go, "first")])
    else:
        command = list(_ASH_MODULE)
    process, port, lines = _mcp_http_server(setup.project, command, env=setup.env)
    held: Optional[socket.socket] = None
    try:
        client = _McpHttpClient(port)
        begun = client.tool("run_ash_scan", source_dir=str(setup.project))
        assert begun.get("success") is True, begun
        _wait_for_file(setup.control / "tool.pid", "the scanner's tool starting")
        pid = int((setup.control / "tool.pid").read_text(encoding="utf-8"))
        if held_open:
            held = _hold_a_request_open(client)
        assert process.poll() is None and _process_alive(pid)
        if stop in ("ctrl-c", "second-ctrl-c"):
            go.write_text("first", encoding="utf-8")
            sent = lines.wait_for(_INTERRUPT_SENT_AT)
            assert sent is not None, "".join(lines.lines)[-1500:]
            signaled = float(sent.group(1))
        else:
            signaled = time.monotonic()
            process.send_signal(getattr(signal, stop.upper()))
        if os.name == "nt" and stop == "sigterm":
            code = process.wait(timeout=_MCP_STOP_SECONDS)
            assert code == 1, f"SIGTERM on Windows: exit {code}, expected 1"
            return

        def running_until(moment: float, what: str) -> None:
            with pytest.raises(subprocess.TimeoutExpired):
                process.wait(timeout=max(0.0, moment - time.monotonic()))
            assert _process_alive(pid), f"the scan's tool was stopped {what}"

        def exit_by(moment: float, what: str) -> Tuple[int, float]:
            try:
                code = process.wait(timeout=max(0.0, moment - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise AssertionError(
                    f"the server was still running {what}:\n"
                    f"{''.join(lines.lines)[-1500:]}"
                ) from None
            return code, time.monotonic()

        if stop == "second-ctrl-c":
            running_until(signaled + 1, "before the second Ctrl-C")
            go.write_text("first second", encoding="utf-8")
            again = lines.wait_for(_INTERRUPT_SENT_AT)
            assert again is not None, "".join(lines.lines)[-1500:]
            forced = float(again.group(1))
            code, ended = exit_by(
                forced + _HTTP_DRAIN_SECONDS / 2,
                f"{_HTTP_DRAIN_SECONDS / 2} s after the second Ctrl-C",
            )
            assert code == 130, f"exit {code}, expected 130:\n{lines.text()[-1500:]}"
            assert ended < signaled + _HTTP_DRAIN_SECONDS, (
                f"the server exited {ended - signaled:.1f} s after the first Ctrl-C, "
                "once the wait was over, not at the second"
            )
            assert _gone_soon(pid), "the scan's tool outlived the server"
            _assert_previous_results_intact(setup.output)
        else:
            if held_open:
                running_until(
                    signaled + _HTTP_DRAIN_SECONDS / 2, "before the wait was over"
                )
            code, ended = exit_by(
                signaled + _DOCKER_STOP_GRACE_SECONDS,
                f"{_DOCKER_STOP_GRACE_SECONDS} s after the signal",
            )
            waited = ended - signaled
            if held_open:
                assert waited >= _HTTP_DRAIN_SECONDS, (
                    f"the server exited {waited:.1f} s after the signal, with a "
                    "request still open: it did not wait for the request"
                )
            else:
                assert waited < _HTTP_DRAIN_SECONDS, (
                    f"with no request open, the server exited {waited:.1f} s after "
                    "the signal"
                )
            expected = {"ctrl-c": 130, "sighup": 0, "sigterm": 128 + 15}[stop]
            reported = _as_a_shell_reports_it(code)
            assert reported == expected, (
                f"{stop}: a shell reports {reported} (exit {code}), expected "
                f"{expected}:\n{lines.text()[-1500:]}"
            )
            if stop == "sigterm":
                assert code == -signal.SIGTERM, f"exit {code}, not ended by SIGTERM"
            assert _gone_soon(pid), "the scan's tool outlived the server"
            assert not held_dir.exists(), "the previous results are still held"
            _assert_previous_results_back(setup.output)
            _assert_the_scans_logs_stayed(setup.output)
            return
    finally:
        if held is not None:
            held.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=30)
        _kill_stand_in(setup.control)

    (setup.control / "tool.pid").unlink()
    nextscan = _McpStdioClient(
        [*_ASH_MODULE, "mcp", "--quiet"], setup.project, setup.env
    )
    try:
        begun = nextscan.tool("run_ash_scan", source_dir=str(setup.project))
        assert begun.get("success") is True, begun
        _wait_for_file(setup.control / "tool.pid", "the next scan's tool starting")
        pid = int((setup.control / "tool.pid").read_text(encoding="utf-8"))
        cancelled = nextscan.tool("cancel_scan", scan_id=begun["scan_id"])
        assert cancelled.get("success") is True, cancelled
        _wait_until_stopped(pid, held_dir)
    finally:
        nextscan.close()
        _kill_stand_in(setup.control)
    _assert_previous_results_back(setup.output)


#: mcp-server.md on values a config reads from the environment, which the server's
#: answers to a client never carry.
_GET_CONFIG_SHOWS_NO_ENV_VALUE = (
    "`get_config` never returns a value that a config read from the environment, since "
    "the server's environment is not the client's. The resolved config shows such a "
    "value as `<from ${VAR}>`, and with `raw` the reference appears as the file wrote it."
)
_PROFILE_COPY_HOLDS_THE_REFERENCE = (
    "The copy of a profile the server writes into a session's workspace holds each "
    "value the profile read from the environment as the profile's file wrote it, not "
    "the value. A scan under the profile still uses the value from the server's "
    "environment, also when the client changed the profile."
)
#: A variable a config may read (ASH_ names), and the value the server's environment
#: gives it.
_ENV_PROBE = "ASH_PAGE_CLAIMS_ENV"
_ENV_PROBE_VALUE = "page-claims-environment-value-7d41"


@pytest.mark.parametrize(
    "written, resolved, raw",
    [
        pytest.param(
            f"${{{_ENV_PROBE}:unset}}",
            f"<from ${{{_ENV_PROBE}:unset}}>",
            f"${{{_ENV_PROBE}:unset}}",
            id="a-reference-with-a-default",
        ),
        pytest.param(
            f"!ENV ${{{_ENV_PROBE}}}",
            f"<from ${{{_ENV_PROBE}}}>",
            f"${{{_ENV_PROBE}}}",
            id="an-env-tag",
        ),
    ],
)
@pytest.mark.e2e
def test_get_config_shows_a_value_read_from_the_environment_as_its_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    written: str,
    resolved: str,
    raw: str,
) -> None:
    """mcp-server.md (What a delivered config cannot set).

    A repository's config sets ``project_name`` from a variable that the server's
    environment holds. A stdio server's ``get_config`` of that file must show the
    resolved ``project_name`` as ``<from ${VAR}>`` and, with ``raw``, as the reference
    the file wrote, and neither answer may hold the value. The control is the same
    file resolved as a scan resolves it, with the variable set: ``project_name`` is
    the value, so the config does read it.
    """
    assert_on_page(MCP_SERVER, _GET_CONFIG_SHOWS_NO_ENV_VALUE)
    from automated_security_helper.config.resolve_config import resolve_config

    repo = tmp_path / "repo"
    (repo / ".ash").mkdir(parents=True)
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    config = repo / ".ash" / ".ash.yaml"
    config.write_text(f"project_name: {written}\n", encoding="utf-8")
    monkeypatch.setenv(_ENV_PROBE, _ENV_PROBE_VALUE)
    control = resolve_config(config_path=config, source_dir=repo)
    assert control.project_name == _ENV_PROBE_VALUE, control.project_name

    env = {**_mcp_child_env(tmp_path), _ENV_PROBE: _ENV_PROBE_VALUE}
    client = _McpStdioClient([*_ASH_MODULE, "mcp", "--quiet"], repo, env)
    try:
        shown = client.tool("get_config", config_path=str(config))
        shown_raw = client.tool("get_config", config_path=str(config), raw=True)
    finally:
        client.close()

    assert shown.get("project_name") == resolved, shown
    assert shown_raw.get("project_name") == raw, shown_raw
    for answer in (shown, shown_raw):
        assert _ENV_PROBE_VALUE not in json.dumps(answer), answer


def _profile_reading_the_environment(setup: _McpStopSetup) -> Path:
    """A profile file: the stop tests' operator config, with the stop scanner's
    ``marker`` read from the environment and runtime overrides allowed for
    ``global_settings.severity_threshold``."""
    operator = yaml.safe_load(Path(setup.env["ASH_CONFIG"]).read_text("utf-8"))
    operator["scanners"]["page-claims-stop"] = {"options": {"marker": "__MARKER__"}}
    operator["global_settings"] = {
        "mcp": {
            "runtime_overrides": {
                "enabled": True,
                "allowed_paths": ["/global_settings/severity_threshold"],
            }
        }
    }
    profile = Path(setup.env["ASH_CONFIG"]).parent / "profile.yaml"
    profile.write_text(
        yaml.safe_dump(operator).replace("__MARKER__", f"!ENV ${{{_ENV_PROBE}}}"),
        encoding="utf-8",
    )
    return profile


@pytest.mark.parametrize("changed", [False, True], ids=["as-registered", "changed"])
@pytest.mark.e2e
def test_a_sessions_profile_copy_holds_the_reference_and_its_scan_the_value(
    tmp_path: Path, changed: bool
) -> None:
    """mcp-server.md (Config profiles).

    A stdio server is started with a profile that sets the stop scanner's ``marker``
    from a variable the server's environment holds, and the client selects it, as
    registered or changed with a ``patch_ops`` operation on another setting. The copy
    the server writes for the session must hold the reference, not the value. A scan
    under the profile must then be given the value: the scanner writes the marker it
    got. The control is that the selection and the scan succeed.
    """
    assert_on_page(MCP_SERVER, _PROFILE_COPY_HOLDS_THE_REFERENCE)
    setup = _mcp_stop_setup(tmp_path, previous=False)
    (setup.control / "tool-returns").write_text("", encoding="utf-8")
    profile = _profile_reading_the_environment(setup)
    env = {**setup.env, _ENV_PROBE: _ENV_PROBE_VALUE}
    command = [*_ASH_MODULE, "mcp", "--quiet", "--profile", f"page-claims={profile}"]
    change = (
        {
            "patch_ops": [
                {
                    "op": "replace",
                    "path": "/global_settings/severity_threshold",
                    "value": "LOW",
                }
            ]
        }
        if changed
        else {}
    )
    client = _McpStdioClient(command, setup.project, env)
    try:
        selected = client.tool("select_profile", profile_name="page-claims", **change)
        assert selected.get("success") is True, selected
        copy = Path(selected["config_path"]).read_text(encoding="utf-8")
        begun = client.tool("run_ash_scan", source_dir=str(setup.project))
        assert begun.get("success") is True, begun
        deadline = time.monotonic() + _MCP_STOP_SECONDS
        while True:
            progress = client.tool("get_scan_progress", scan_id=begun["scan_id"])
            if progress.get("is_complete") and progress.get("end_time"):
                break
            assert time.monotonic() < deadline, progress
            time.sleep(0.25)
    finally:
        client.close()
        _kill_stand_in(setup.control)

    assert _ENV_PROBE_VALUE not in copy, copy
    assert f"${{{_ENV_PROBE}}}" in copy, copy
    marker = setup.control / "marker.txt"
    assert marker.is_file(), f"the scan did not run the scanner: {progress}"
    assert marker.read_text(encoding="utf-8") == _ENV_PROBE_VALUE


#: mcp-server.md on the TTL sweep of session workspaces and the lock it shares with
#: other servers.
_BUSY_WHILE_THE_SWEEP_REMOVES = (
    "`set_source_zip_chunk` and `select_profile` are refused with `error_type` "
    "`session_workspace_busy` while an HTTP server removes the workspace of a session for "
    "being unused longer than `--session-workspace-ttl`. The upload and the bound profile "
    "are removed with the workspace, so the client selects the profile again and sends "
    "the upload again from chunk 0. A session whose SSE event stream is open is kept "
    "until it ends; see [Clean up](#clean-up)."
)
_SWEEP_LOCK_WAIT_IS_BOUNDED = (
    "Servers that share one workspace root take a lock under the root before a sweep "
    "removes a session. A sweep that cannot take that lock within about a second, "
    "because another server holds it, removes nothing more and leaves the remaining "
    "sessions to its next sweep, so another server cannot hold up a stop signal."
)
_SWEEP_COVERS_THE_ENDS_IT_CANNOT_SEE = (
    "It also removes a workspace nobody used for `--session-workspace-ttl` seconds, 86400 "
    "(24 hours) by default, which covers sessions whose end it cannot see, such as every "
    "stateless one."
)
_AN_IDLE_STATEFUL_SESSION_IS_SWEPT = (
    "A stateful session nobody has used for that long is removed like any other, whether "
    "or not the server has seen it end: the MCP SDK drops an idle stateful session without "
    "telling the server, so the server cannot keep it on that account. Only a session whose "
    "SSE event stream is still open is kept whatever its age, and the sweep marks that "
    "workspace used so another server sharing the root keeps it too. On a stateful server "
    "that stream is the session's standalone `GET` stream."
)
_AN_EXPIRED_STATEFUL_SESSION_IS_REFUSED = (
    "A stateful session the sweep removes is ended: its next request names no session the "
    "server holds, so the tools that need a session refuse it with `error_type` "
    "`session_identity_required` and say that the session expired, and the client opens a "
    "new session with `initialize`."
)
#: The sweep's "about a second", and the TTL the sweep tests give the server.
_SWEEP_LOCK_WAIT_SECONDS = 1
_SWEEP_TTL_SECONDS = 1
#: The sessions the sweep tests name on a stateless server, where the client's
#: ``Mcp-Session-Id`` is the session (``--trust-upstream-session-id``). A stateless
#: server holds no session as issued, so the sweep is what ends them, which is the
#: page's reason for the sweep. The ids are path components (``validated_path_component``).
_STALE_SESSION = "page-claims-stale"
_SWEEPING_SESSION = "page-claims-sweeper"

#: Another server sharing the workspace root, as far as the sweep can tell: a process
#: that holds the lock the servers share until the file it watches appears, or a
#: minute has passed. It prints ``held`` once it holds it.
_ANOTHER_SERVERS_LOCK = """\
import sys, time
from pathlib import Path

lock, release = Path(sys.argv[1]), Path(sys.argv[2])
lock.parent.mkdir(parents=True, exist_ok=True)
handle = open(lock, "a+b")
if sys.platform == "win32":
    import msvcrt

    handle.seek(0)
    msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
else:
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
print("held", flush=True)
deadline = time.monotonic() + 60
while not release.exists() and time.monotonic() < deadline:
    time.sleep(0.05)
"""


@contextlib.contextmanager
def _another_servers_lock(root: Path, tmp_path: Path) -> Iterator[None]:
    """The workspace root's sweep lock, held by another process while in use."""
    from automated_security_helper.cli.mcp import sessions

    lock = root / sessions.SCAN_PRESENCE_DIR / sessions._SCAN_PRESENCE_LOCK
    release = tmp_path / "release-the-lock"
    holder = subprocess.Popen(
        [sys.executable, "-c", _ANOTHER_SERVERS_LOCK, str(lock), str(release)],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "held"
        yield
    finally:
        release.write_text("", encoding="utf-8")
        holder.wait(timeout=90)
        if holder.stdout:
            holder.stdout.close()


def _sweep_server(
    tmp_path: Path, command: Optional[List[str]] = None, *, stateless: bool = False
) -> Tuple[subprocess.Popen, int, _Lines, Path, Path]:
    """A streamable-HTTP server whose session workspaces go stale after
    ``_SWEEP_TTL_SECONDS``, with a profile registered: the process, its port, the
    reader of its standard error, the workspace root, and the profile.

    ``stateless`` starts it with ``--stateless-http --trust-upstream-session-id``: it
    issues no session and holds none, and the client's ``Mcp-Session-Id`` names the
    session, so a session unused past the TTL is the sweep's to remove. A stateful
    server (the default) holds the sessions it has issued and not seen end, and
    keeps none of them on that account: an idle one is swept like any other, and
    the server ends it (the idle stateful test below).

    Two servers started from one ``tmp_path`` share the workspace root.
    """
    root = tmp_path / "workspaces"
    profile = tmp_path / "profile.yaml"
    profile.write_text("project_name: page-claims-sweep\n", encoding="utf-8")
    env = {**_mcp_child_env(tmp_path), "ASH_MCP_WORKSPACE_ROOT": str(root)}
    options = [
        "--session-workspace-ttl",
        str(_SWEEP_TTL_SECONDS),
        "--profile",
        f"page-claims={profile}",
    ]
    if stateless:
        options += ["--stateless-http", "--trust-upstream-session-id"]
    process, port, lines = _mcp_http_server(
        tmp_path, command or list(_ASH_MODULE), env=env, options=options
    )
    return process, port, lines, root, profile


def _session_with_a_workspace(
    port: int, upload_id: str, session_id: Optional[str] = None
) -> _McpHttpClient:
    """A session that has bound the profile and sent the first chunk of an upload, so
    its workspace holds both. ``session_id`` is the client's own id on a stateless
    server; a stateful server issues one."""
    client = _McpHttpClient(port, session_id)
    chunk = base64.b64encode(_delivery_zip({"app.py": b"x = 1\n"})).decode("ascii")
    sent = client.tool(
        "set_source_zip_chunk",
        upload_id=upload_id,
        sequence=0,
        data_b64=chunk,
        last=False,
    )
    assert sent.get("success") is True, sent
    bound = client.tool("select_profile", profile_name="page-claims")
    assert bound.get("success") is True, bound
    return client


def _workspace(root: Path, client: _McpHttpClient) -> Path:
    return root / client.headers["mcp-session-id"]


def _start_a_session_in_the_background(
    port: int, session_id: Optional[str] = None
) -> Tuple[threading.Thread, Dict]:
    """A new session's ``initialize``, on a thread: the request that sets off a sweep
    that is due. The result holds the seconds it took, or the error it raised.
    ``session_id`` is the new session's own id on a stateless server."""
    result: Dict[str, Any] = {}

    def run() -> None:
        started = time.monotonic()
        try:
            _McpHttpClient(port, session_id)
        except BaseException as error:  # reported by the test
            result["error"] = error
        result["seconds"] = time.monotonic() - started

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, result


def _stop_server(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.kill()
        process.wait(timeout=30)


@pytest.mark.parametrize("tool", ["set_source_zip_chunk", "select_profile"])
@pytest.mark.e2e
def test_a_session_write_during_the_sweeps_wait_for_the_lock_is_accepted(
    tmp_path: Path, tool: str
) -> None:
    """mcp-server.md (Clean up).

    A stateless streamable-HTTP server with a one-second ``--session-workspace-ttl``
    has a session that bound a profile and sent an upload's first chunk; the session
    then goes unused past the TTL. Stateless, because the server holds no session as
    issued, so the sweep is what ends an unused one; a stateful server's idle session
    is swept the same way (the idle stateful test below). Another server holds the lock a
    sweep takes before it removes a session. The sweep that a new session's first
    request sets off waits for that lock holding no session: the lock is taken
    before any session is, so a ``set_source_zip_chunk`` or a ``select_profile`` the
    stale session sends during the wait must be accepted, and answered while the
    sweep is still waiting, which the sweep's request still being open when the
    write returns shows. The sweep then gives the lock up within about a second and
    removes nothing, so the stale session's workspace is still there once the sweep
    has returned.

    Two tells say the write landed during the wait and not around it: the request
    that set off the sweep is still open when the write returns (the sweep did not
    give up before the write, and the wait did not block the server's loop until
    the sweep returned), and that request took about the page's second (the sweep
    waited for the lock at all).

    The page's ``session_workspace_busy`` refusal is the removal window, which opens
    only once the lock is held; no deterministic probe of it from outside the
    server exists, so the in-process test below holds the remover open and pins it.
    """
    assert_on_page(MCP_SERVER, _SWEEP_LOCK_WAIT_IS_BOUNDED)
    assert_on_page(MCP_SERVER, _BUSY_WHILE_THE_SWEEP_REMOVES)
    process, port, lines, root, _profile = _sweep_server(tmp_path, stateless=True)
    try:
        stale = _session_with_a_workspace(port, "page-claims-upload", _STALE_SESSION)
        workspace = _workspace(root, stale)
        assert workspace.is_dir()
        with _another_servers_lock(root, tmp_path):
            time.sleep(_SWEEP_TTL_SECONDS + 1.5)
            sweeping, result = _start_a_session_in_the_background(
                port, _SWEEPING_SESSION
            )
            time.sleep(0.3)
            if tool == "set_source_zip_chunk":
                chunk = base64.b64encode(b"more").decode("ascii")
                accepted = stale.tool(
                    tool,
                    upload_id="page-claims-upload",
                    sequence=1,
                    data_b64=chunk,
                    last=True,
                )
            else:
                accepted = stale.tool(tool, profile_name="page-claims")
            assert sweeping.is_alive(), (
                "the request that set off the sweep was answered before the stale "
                "session's write returned, so the write did not land during the wait"
            )
            sweeping.join(timeout=_SWEEP_LOCK_WAIT_SECONDS + 3)
            assert not sweeping.is_alive(), (
                "the request that set off the sweep was not answered within "
                f"{_SWEEP_LOCK_WAIT_SECONDS + 3} s while another server held the lock"
            )
            assert "error" not in result, result
            assert result["seconds"] >= _SWEEP_LOCK_WAIT_SECONDS * 0.8, (
                f"the request that set off the sweep took {result['seconds']:.2f} s, "
                "so the sweep did not wait for the lock"
            )
            assert workspace.is_dir(), f"the sweep removed {workspace} without the lock"
    finally:
        _stop_server(process)

    assert accepted.get("success") is True, accepted


@pytest.mark.unit
def test_a_session_write_while_the_sweep_removes_its_workspace_is_refused_as_busy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """mcp-server.md (Deliver source to the server).

    The page's ``session_workspace_busy`` refusal, in process: a session workspace
    nobody has used for longer than the TTL is the sweep's to remove, the sweep
    takes the session and starts the removal, and a ``set_source_zip_chunk`` for
    that session sent while the removal runs is refused with that ``error_type``
    (``sessions.writing_session_state``, the hold ``set_source_zip_chunk`` and
    ``select_profile`` take). The remover is held open on an event, so the window
    the server tests above cannot time is open when the write comes. The control
    is the same chunk once the sweep has returned: accepted, the upload starting
    again from chunk 0 in a new workspace, as the page says.
    """
    assert_on_page(MCP_SERVER, _BUSY_WHILE_THE_SWEEP_REMOVES)
    from automated_security_helper.cli.mcp import sessions, source_delivery
    from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

    root = tmp_path / "workspaces"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()
    try:
        sandbox = mark_session_workspace(root / _STALE_SESSION)
        (sandbox / "source").mkdir()
        (sandbox / "source" / "app.py").write_text("x = 1\n", encoding="utf-8")
        then = time.time() - 3600
        for path in (sandbox, *sandbox.iterdir()):
            os.utime(path, (then, then))

        removing = threading.Event()
        release = threading.Event()
        # The delete of the tree the sweep renamed aside. The sweep holds the
        # session (try_begin_sweep) from its last look at the age until that
        # delete is done, so a write meets the hold while this is open; the
        # stale session has a workspace, so the sweep does not take the
        # removal that has no guard (_remove_session_state).
        real_remove = sessions._remove_set_aside_tree

        def held_remove(doomed: Optional[Path]) -> None:
            removing.set()
            assert release.wait(timeout=30), "the test never released the remover"
            real_remove(doomed)

        monkeypatch.setattr(sessions, "_remove_set_aside_tree", held_remove)
        removed: List[str] = []
        sweep = threading.Thread(
            target=lambda: removed.extend(
                sessions.sweep_stale_workspaces(_SWEEP_TTL_SECONDS)
            ),
            daemon=True,
        )
        sweep.start()
        assert removing.wait(timeout=30), "the sweep never reached the removal"
        chunk = base64.b64encode(b"more").decode("ascii")
        try:
            with pytest.raises(sessions.SessionWorkspaceBusyError) as refused:
                source_delivery.set_source_zip_chunk(
                    "page-claims-upload",
                    0,
                    chunk,
                    True,
                    workspace_root=root,
                    session_id=_STALE_SESSION,
                )
        finally:
            release.set()
            sweep.join(timeout=30)
        assert not sweep.is_alive(), "the sweep did not return once released"
        assert refused.value.error_type == "session_workspace_busy"
        assert removed == [_STALE_SESSION], removed
        assert not sandbox.exists(), f"the sweep left {sandbox}"

        accepted = source_delivery.set_source_zip_chunk(
            "page-claims-upload",
            0,
            chunk,
            True,
            workspace_root=root,
            session_id=_STALE_SESSION,
        )
        assert accepted["received"] == len(b"more"), accepted
    finally:
        sessions.reset_default_registry_for_tests()
        sessions._ended_while_scanning.clear()


@pytest.mark.e2e
def test_a_removed_workspace_takes_the_upload_and_the_bound_profile_with_it(
    tmp_path: Path,
) -> None:
    """mcp-server.md (Deliver source to the server; Clean up).

    On a stateless streamable-HTTP server, whose sessions it does not hold, a session
    binds a profile and sends an upload's first chunk, then goes unused past the
    one-second TTL, and a new session's first request sets off the sweep, with no
    other server holding its lock. The stale session's workspace, with the profile's
    copy, must be gone. The upload must be gone with it: its next chunk is refused,
    and the upload sent again from chunk 0 is accepted. Selecting the profile again
    must succeed and write its copy again. The control is the workspace, the copy and
    the upload's first chunk all there before the sweep. A session a stateful server
    still holds as issued but that went idle is swept too (the idle stateful test
    below).
    """
    assert_on_page(MCP_SERVER, _BUSY_WHILE_THE_SWEEP_REMOVES)
    assert_on_page(MCP_SERVER, _SWEEP_COVERS_THE_ENDS_IT_CANNOT_SEE)
    process, port, lines, root, _profile = _sweep_server(tmp_path, stateless=True)
    chunk = base64.b64encode(_delivery_zip({"app.py": b"x = 1\n"})).decode("ascii")
    try:
        stale = _session_with_a_workspace(port, "page-claims-upload", _STALE_SESSION)
        workspace = _workspace(root, stale)
        copies = list(workspace.rglob("ash.yaml"))
        assert copies, f"no copy of the profile in {workspace}"
        time.sleep(_SWEEP_TTL_SECONDS + 1.5)
        _McpHttpClient(port, _SWEEPING_SESSION)
        assert not workspace.exists(), f"the sweep left {workspace}"
        next_chunk = stale.tool(
            "set_source_zip_chunk",
            upload_id="page-claims-upload",
            sequence=1,
            data_b64=chunk,
            last=True,
        )
        again = stale.tool(
            "set_source_zip_chunk",
            upload_id="page-claims-upload",
            sequence=0,
            data_b64=chunk,
            last=True,
        )
        rebound = stale.tool("select_profile", profile_name="page-claims")
    finally:
        _stop_server(process)

    assert next_chunk.get("success") is False, next_chunk
    assert again.get("success") is True, again
    assert rebound.get("success") is True, rebound
    assert Path(rebound["config_path"]).is_file(), rebound


@pytest.mark.parametrize(
    "check", ["removes-nothing-more-until-its-next-sweep", "ctrl-c-is-not-held-up"]
)
@pytest.mark.e2e
def test_a_sweep_waits_about_a_second_for_the_lock_another_server_holds(
    tmp_path: Path, check: str
) -> None:
    """mcp-server.md (Clean up).

    Two sessions of a stateless streamable-HTTP server with a one-second
    ``--session-workspace-ttl`` go unused past the TTL while another process holds
    the lock the sweep takes before it removes a session. A new session's first
    request sets off the sweep. Stateless, so the server holds neither session and
    the sweep is what removes them once the lock is free.

    Removes nothing more: that request must be answered within the page's second plus
    three, and both stale workspaces must stay. Once the lock is free, the next sweep,
    set off by another new session past the TTL, must remove them both; that is the
    control that the sweep removes them at all.

    Ctrl-C is not held up: the server gets Ctrl-C while the sweep waits, and must
    exit within the 10 seconds ``docker stop`` waits, the lock still held. Ctrl-C
    reaches it as ``_INTERRUPTED_ASH`` sends it. The exit code is not this test's:
    the stop tests above pin it.
    """
    assert_on_page(MCP_SERVER, _SWEEP_LOCK_WAIT_IS_BOUNDED)
    go = tmp_path / "interrupt-now.txt"
    command = _interrupter([(go, "now")]) if check == "ctrl-c-is-not-held-up" else None
    process, port, lines, root, _profile = _sweep_server(
        tmp_path, command, stateless=True
    )
    try:
        stale = [
            _session_with_a_workspace(port, f"upload-{n}", f"{_STALE_SESSION}-{n}")
            for n in (1, 2)
        ]
        workspaces = [_workspace(root, client) for client in stale]
        with _another_servers_lock(root, tmp_path):
            time.sleep(_SWEEP_TTL_SECONDS + 1.5)
            sweeping, result = _start_a_session_in_the_background(
                port, f"{_SWEEPING_SESSION}-1"
            )
            if check == "ctrl-c-is-not-held-up":
                time.sleep(0.3)
                go.write_text("now", encoding="utf-8")
                sent = lines.wait_for(_INTERRUPT_SENT_AT)
                assert sent is not None, "".join(lines.lines)[-1500:]
                signaled = float(sent.group(1))
                try:
                    process.wait(
                        timeout=max(
                            0.0,
                            signaled + _DOCKER_STOP_GRACE_SECONDS - time.monotonic(),
                        )
                    )
                except subprocess.TimeoutExpired:
                    raise AssertionError(
                        f"the server was still running {_DOCKER_STOP_GRACE_SECONDS} s "
                        "after Ctrl-C while the sweep waited for the lock"
                    ) from None
                return
            sweeping.join(timeout=_SWEEP_LOCK_WAIT_SECONDS + 3)
            assert not sweeping.is_alive(), (
                f"the request that set off the sweep was not answered within "
                f"{_SWEEP_LOCK_WAIT_SECONDS + 3} s while another server held the lock"
            )
            assert "error" not in result, result
            for workspace in workspaces:
                assert workspace.is_dir(), f"the sweep removed {workspace}"
        time.sleep(_SWEEP_TTL_SECONDS + 1.5)
        _McpHttpClient(port, f"{_SWEEPING_SESSION}-2")
        for workspace in workspaces:
            assert not workspace.exists(), f"the next sweep left {workspace}"
    finally:
        _stop_server(process)


@pytest.mark.e2e
def test_an_idle_stateful_session_is_swept_past_the_ttl(tmp_path: Path) -> None:
    """mcp-server.md (Clean up).

    A stateful streamable-HTTP server with a one-second ``--session-workspace-ttl``
    issues a session that binds the profile and sends an upload's first chunk, then
    goes unused past the TTL; a new session's first request sets off the sweep. The
    server still holds the first session as issued (it never saw a ``DELETE``), and
    that keeps nothing: the SDK drops an idle stateful session without telling the
    server, so a session kept for being issued stayed until shutdown. The workspace
    and the profile's copy are gone, and the server has ended the session with them:
    the upload's next chunk and a ``select_profile`` on that session are refused with
    ``session_identity_required`` and an error that says the session expired, instead
    of running unbound. A new session's first chunk and its ``select_profile`` are
    accepted, so the client starts again from chunk 0 under the new session. Together
    with the stateless case above, the idle session is swept whichever mode issued it.
    """
    assert_on_page(MCP_SERVER, _AN_IDLE_STATEFUL_SESSION_IS_SWEPT)
    assert_on_page(MCP_SERVER, _AN_EXPIRED_STATEFUL_SESSION_IS_REFUSED)
    process, port, lines, root, _profile = _sweep_server(tmp_path)
    chunk = base64.b64encode(_delivery_zip({"app.py": b"x = 1\n"})).decode("ascii")
    try:
        held = _session_with_a_workspace(port, "page-claims-upload")
        workspace = _workspace(root, held)
        copies = list(workspace.rglob("ash.yaml"))
        assert copies, f"no copy of the profile in {workspace}"
        time.sleep(_SWEEP_TTL_SECONDS + 1.5)
        _McpHttpClient(port)
        assert not workspace.exists(), f"the sweep kept the idle session's {workspace}"
        assert not any(copy.exists() for copy in copies), (
            f"a copy stayed in {workspace}"
        )
        next_chunk = held.tool(
            "set_source_zip_chunk",
            upload_id="page-claims-upload",
            sequence=1,
            data_b64=chunk,
            last=True,
        )
        reselected = held.tool("select_profile", profile_name="page-claims")
        # The control: the same two calls under a session opened now.
        fresh = _session_with_a_workspace(port, "page-claims-upload")
        fresh_workspace = _workspace(root, fresh)
    finally:
        _stop_server(process)

    assert next_chunk.get("success") is False, next_chunk
    assert next_chunk.get("error_type") == "session_identity_required", next_chunk
    assert "expired" in next_chunk.get("error", ""), next_chunk
    assert reselected.get("error_type") == "session_identity_required", reselected
    assert fresh_workspace != workspace
    assert fresh_workspace.is_dir(), f"the new session has no {fresh_workspace}"


@pytest.mark.e2e
def test_a_previous_servers_workspace_is_swept_once_nobody_holds_it(
    tmp_path: Path,
) -> None:
    """mcp-server.md (Clean up).

    A stateful server issues a session that binds the profile and sends an upload's
    first chunk, and is then killed without ending the session, so its workspace stays
    under the root. A second server on the same root, with a one-second
    ``--session-workspace-ttl``, holds no such session, so a new session's first
    request past the TTL must sweep the workspace: the end the first server could not
    see is the sweep's to cover. The control is the workspace there before the second
    server's sweep.
    """
    assert_on_page(MCP_SERVER, _SWEEP_COVERS_THE_ENDS_IT_CANNOT_SEE)
    first, port, lines, root, _profile = _sweep_server(tmp_path)
    try:
        orphaned = _session_with_a_workspace(port, "page-claims-upload")
        workspace = _workspace(root, orphaned)
        assert workspace.is_dir()
    finally:
        _stop_server(first)
    assert workspace.is_dir(), f"killing the server removed {workspace}"
    second, port, lines, root, _profile = _sweep_server(tmp_path)
    try:
        time.sleep(_SWEEP_TTL_SECONDS + 1.5)
        _McpHttpClient(port)
        assert not workspace.exists(), f"the second server's sweep left {workspace}"
    finally:
        _stop_server(second)


@pytest.mark.parametrize(
    "value, expected",
    [
        pytest.param("streamable_http", 5, id="misspelled"),
        pytest.param("websocket", 5, id="no-such-transport"),
        pytest.param("http", 5, id="the-pages-example"),
        pytest.param("sse", 0, id="control-a-transport-it-names"),
        pytest.param(" Streamable-HTTP ", 0, id="case-and-whitespace-ignored"),
    ],
)
@pytest.mark.unit
def test_ash_mcp_refuses_an_ash_mcp_transport_that_names_no_transport(
    _mcp_cli: Callable[..., Any], value: str, expected: int
) -> None:
    """mcp-server.md (How the server runs scans; Run over streamable HTTP).

    ``ash mcp`` runs with the variable set and serving replaced. A value that names no
    transport, the page's own ``http`` among them, must exit 5 without starting a
    server. The controls are transports the variable may name, one written in another
    case with spaces around it, which start one.
    """
    assert_on_page(MCP_SERVER, _MCP_EXITS_FOR_REFUSED_OPTIONS)
    assert_on_page(
        MCP_SERVER,
        "Always set `ASH_MCP_TRANSPORT` to the transport you serve, `streamable-http` or "
        "`sse`. ASH ignores the value's case and surrounding whitespace. A value that "
        "names no transport, one other than `stdio`, `streamable-http`, or `sse`, makes "
        "`ash mcp` exit with code 5 before it starts:",
    )
    assert_on_page(MCP_SERVER, "ASH_MCP_TRANSPORT=http ash mcp")
    assert_on_page(MCP_SERVER, "`ash mcp` does not set the variable for you.")
    result, served = _mcp_cli("--quiet", ASH_MCP_TRANSPORT=value)
    assert result.exit_code == expected, (
        f"ASH_MCP_TRANSPORT={value}: exit {result.exit_code}, expected {expected}:\n"
        f"{result.output[-1500:]}"
    )
    assert bool(served) == (expected == 0), served


# --------------------------------------------------------------------------- #
# The MCP server's Host header allowlist
# --------------------------------------------------------------------------- #


def _mcp_statuses(app: Any, host_headers: Iterable[str]) -> Dict[str, int]:
    """{Host header: status} of an ``initialize`` request sent with each Host header.

    One client per app, since its lifespan starts the session manager, which runs once
    per app. The Host header is set explicitly: the test client otherwise sends its
    own placeholder name.
    """
    from starlette.testclient import TestClient

    statuses: Dict[str, int] = {}
    with TestClient(app, base_url="http://placeholder.invalid") as client:
        for host in host_headers:
            statuses[host] = client.post(
                "/mcp",
                json=_MCP_INITIALIZE,
                headers={
                    "Host": host,
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            ).status_code
    return statuses


#: Where a case's command line takes the page's own ``--host``, read by
#: ``_mcp_page_host``. Serving is replaced, so nothing binds it.
_PAGE_HOST = "<the --host of the page's command>"


def _mcp_page_host() -> str:
    """The ``--host`` of the command under mcp-server.md's Serve clients on another
    host, the address the page has a server listen on for clients elsewhere."""
    section = _page_text(MCP_SERVER).split("### Serve clients on another host", 1)[1]
    block = section.split("```bash\n", 1)[1].split("```", 1)[0]
    return _one(re.findall(r"--host (\S+)", block), "--host in the page's command")


@pytest.mark.parametrize(
    "options, expected",
    [
        pytest.param(
            ["--host", _PAGE_HOST, "--allowed-host", "ash.example.com"],
            {
                "ash.example.com": 200,
                "ASH.example.com": 421,
                "ash.example.com:8443": 421,
                "127.0.0.1:8000": 421,
                "localhost:8000": 421,
                "[::1]:8000": 421,
            },
            id="exact-name-case-and-port",
        ),
        pytest.param(
            ["--host", _PAGE_HOST, "--allowed-host", "ash.example.com:*"],
            {"ash.example.com:8443": 200, "ash.example.com": 421},
            id="any-port-but-not-none",
        ),
        pytest.param(
            [
                "--host",
                _PAGE_HOST,
                "--allowed-host",
                "ash.example.com",
                "--allowed-host",
                "ash.example.com:*",
            ],
            {
                "ash.example.com": 200,
                "ash.example.com:8443": 200,
                "other.example.com": 421,
            },
            id="repeated",
        ),
        pytest.param(
            ["--host", "127.0.0.1", "--allowed-host", "ash.example.com"],
            {"ash.example.com": 200, "127.0.0.1:8000": 421},
            id="loopback-behind-a-proxy",
        ),
        pytest.param(
            ["--host", "127.0.0.1"],
            {"127.0.0.1:8000": 200, "localhost:8000": 200, "ash.example.com": 421},
            id="control-loopback-without-the-option",
        ),
        pytest.param(
            ["--host", _PAGE_HOST],
            {"ASH.example.com": 200, "other.example.com": 200},
            id="control-the-page-host-without-the-option",
        ),
    ],
)
@pytest.mark.unit
def test_allowed_host_accepts_exactly_the_host_headers_the_mcp_page_says(
    _mcp_cli: Callable[..., Any], options: List[str], expected: Dict[str, int]
) -> None:
    """mcp-server.md (Serve clients on another host).

    The app ``ash mcp --transport streamable-http`` would serve is taken from the
    command, without binding a port, and sent an ``initialize`` request with each Host
    header: 200 is accepted and 421 refused. The non-loopback cases listen where the
    page's own command does, on its ``--host``. The controls are the same server
    without the option, which accepts the loopback names on loopback and any name on
    the page's address, so the refusals come from the option.
    """
    assert_on_page(
        MCP_SERVER,
        "If the proxy forwards the client's Host header, pass `--allowed-host` with that "
        "name even when the server listens on loopback.",
    )
    assert_on_page(
        MCP_SERVER,
        "It names the Host header values the server accepts, which protects against DNS "
        "rebinding. The option can be repeated. Each value must match the Host header "
        "exactly, including case and any port the client sends. A value ending in `:*` "
        "matches that name with any port, but not the name without one; list both if "
        "clients send either. Once you pass the option, the loopback names are accepted "
        "only if you list them too.",
    )
    assert_on_page(
        MCP_SERVER, "Always pass `--allowed-host` with a non-loopback `--host`."
    )
    host = _mcp_page_host()
    assert host not in ("127.0.0.1", "localhost", "::1"), (
        f"the page's command listens on loopback ({host}), not for another host"
    )
    options = [host if option == _PAGE_HOST else option for option in options]
    result, served = _mcp_cli(
        "--transport", "streamable-http", "--stateless-http", "--quiet", *options
    )
    assert result.exit_code == 0, result.output[-1500:]
    [(kind, app)] = served
    assert kind == "http"
    assert _mcp_statuses(app, expected) == expected


# --------------------------------------------------------------------------- #
# MCP source delivery
# --------------------------------------------------------------------------- #

_DELIVERY_SESSION = "page-claims-session"


class _DeliveryContext:
    """The parts of an MCP tool context the delivery tools read, for one session."""

    def __init__(self, session_id: str) -> None:
        self.headers = {"mcp-session-id": session_id}

    async def error(self, *args: Any, **kwargs: Any) -> None:
        return None

    async def info(self, *args: Any, **kwargs: Any) -> None:
        return None


@pytest.fixture
def _delivery_workspace(
    mcp_workspace_root: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    """The MCP workspace root, cleared afterwards."""
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    yield mcp_workspace_root
    from automated_security_helper.cli.mcp.source_delivery import clear_source

    clear_source(_DELIVERY_SESSION, workspace_root=mcp_workspace_root)


def _delivery_tool(tool: str, **arguments: Any) -> Dict[str, Any]:
    """Call an MCP delivery tool the way the server does, for this file's session."""
    from automated_security_helper.cli import mcp_server

    return asyncio.run(
        getattr(mcp_server, tool)(_DeliveryContext(_DELIVERY_SESSION), **arguments)
    )


def _delivery_zip(entries: Dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _delivery_send(data: bytes, upload_id: str) -> Dict[str, Any]:
    return _delivery_tool(
        "set_source_zip_chunk",
        upload_id=upload_id,
        sequence=0,
        data_b64=base64.b64encode(data).decode("ascii"),
        last=True,
    )


def _delivery_finalize(data: bytes, upload_id: str) -> Dict[str, Any]:
    return _delivery_tool(
        "set_source_zip_finalize",
        upload_id=upload_id,
        expected_sha256=hashlib.sha256(data).hexdigest(),
    )


def _delivery_deliver(entries: Dict[str, bytes], upload_id: str) -> Dict[str, Any]:
    data = _delivery_zip(entries)
    sent = _delivery_send(data, upload_id)
    assert sent["success"] is True, sent
    return _delivery_finalize(data, upload_id)


@pytest.mark.parametrize(
    "second, replaced",
    [
        # Refused by the member checks, before anything is extracted.
        pytest.param({"../escape.py": b"x\n"}, False, id="refused-member"),
        # Passes the member checks and fails while extracting: a file, then a
        # directory with the same name.
        pytest.param(
            {"clash": b"file\n", "clash/inner.py": b"x\n"}, False, id="extraction-fails"
        ),
        pytest.param({"app/main.py": b"second\n"}, True, id="control-a-good-zip"),
    ],
)
@pytest.mark.unit
def test_a_zip_that_fails_to_extract_leaves_the_delivered_tree(
    _delivery_workspace: Path, second: Dict[str, bytes], replaced: bool
) -> None:
    """mcp-server.md (Deliver source to the server).

    A tree is delivered through the MCP tools, then a second zip that is refused or
    fails while extracting, and the first tree must be there as it was. The control is
    a good second zip, which replaces the tree, leaving none of the first one's files.
    """
    assert_on_page(
        MCP_SERVER,
        "- A new zip is extracted beside the old tree and replaces it only when "
        "extraction succeeds.",
    )
    first = _delivery_deliver(
        {"app/main.py": b"first\n", "app/old.py": b"old\n"}, "first"
    )
    assert first["success"] is True, first
    source = Path(first["source_dir"])

    after = _delivery_deliver(second, "second")
    assert after["success"] is replaced, after
    if replaced:
        assert (source / "app" / "main.py").read_bytes() == b"second\n"
        assert not (source / "app" / "old.py").exists()
    else:
        assert (source / "app" / "main.py").read_bytes() == b"first\n"
        assert sorted(p.name for p in (source / "app").iterdir()) == [
            "main.py",
            "old.py",
        ]
        assert sorted(p.name for p in source.iterdir()) == ["app"]


#: A host the clones name, listed in ``ASH_MCP_GIT_ALLOWED_HOSTS``. ``.invalid`` never
#: resolves, so no clone can reach a network even if the stand-in were not used.
_DELIVERY_GIT_HOST = "git.example.invalid"

#: A stand-in for git: it records each command, and for a clone writes one file into
#: the target, the last argument.
_DELIVERY_GIT_STAND_IN = """\
import json, sys
from pathlib import Path

with open({log!r}, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\\n")
if "clone" in sys.argv:
    Path(sys.argv[-1], "cloned.txt").write_text("cloned\\n", encoding="utf-8")
"""


def _delivery_git_stand_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Tuple[str, Path]:
    """(a URL on an allowed host, the stand-in's log) for ``set_source_git``.

    The host is allowed through ``ASH_MCP_GIT_ALLOWED_HOSTS``, and git is the stand-in,
    as the program source delivery runs as git (``_GIT_ARGV``).
    """
    from automated_security_helper.cli.mcp import source_delivery

    log = tmp_path / "git-calls.jsonl"
    script = tmp_path / "git_stand_in.py"
    script.write_text(_DELIVERY_GIT_STAND_IN.format(log=str(log)), encoding="utf-8")
    # One launcher shape for every stand-in (_interpreter_launcher): the file
    # the delivery starts is the launcher itself, the form the test's mark
    # names, on POSIX and Windows alike, with no interpreter-form fallback.
    stand_in = _interpreter_launcher(tmp_path, "git_stand_in", script)
    monkeypatch.setattr(source_delivery, "_GIT_ARGV", (str(stand_in),))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", _DELIVERY_GIT_HOST)
    return f"https://{_DELIVERY_GIT_HOST}/team/app.git", log


@pytest.mark.allow_real_program(
    "git_stand_in.cmd" if os.name == "nt" else "git_stand_in",
    where="tmp",
    reason="the test's own stand-in for git, which the source delivery starts "
    "with the environment it builds for git; it runs the recording Python "
    "script with this interpreter (through cmd on Windows), writes one file, "
    "and starts nothing beyond that",
)
@pytest.mark.unit
def test_while_a_scan_of_the_session_runs_delivery_is_refused_and_chunks_accepted(
    _delivery_workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """mcp-server.md (Deliver source to the server).

    The session's scan lock is held as a running scan holds it, and the MCP tools are
    called for that session: a chunk is accepted, and finalizing, a clone from an
    allowed https host and clearing the source are each refused with the error type
    the page names, with git never run and the delivered tree as it was. git is a
    stand-in that records its commands. The control is the same calls once the lock is
    released, which deliver, clone through the stand-in and clear.
    """
    assert_on_page(
        MCP_SERVER,
        "While a scan of a session runs, `clear_source`, `set_source_git`, and "
        "`set_source_zip_finalize` are refused with `error_type` `source_delivery_busy`, "
        "because each would remove or replace the tree the scan is reading.",
    )
    assert_on_page(
        MCP_SERVER, "Chunks are still accepted, because they land beside the tree."
    )
    from automated_security_helper.cli.mcp.sessions import get_default_registry

    url, git_calls = _delivery_git_stand_in(tmp_path, monkeypatch)
    data = _delivery_zip({"app/main.py": b"during the scan\n"})
    first = _delivery_deliver({"app/main.py": b"before the scan\n"}, "before")
    assert first["success"] is True, first

    with get_default_registry().get_or_create(_DELIVERY_SESSION).lock:
        chunk = _delivery_send(data, "during")
        refused = {
            "set_source_zip_finalize": _delivery_finalize(data, "during"),
            "set_source_git": _delivery_tool("set_source_git", url=url),
            "clear_source": _delivery_tool("clear_source"),
        }

    assert chunk["success"] is True, chunk
    for tool, answer in refused.items():
        assert answer["success"] is False, (tool, answer)
        assert answer.get("error_type") == "source_delivery_busy", (tool, answer)
    assert not git_calls.exists(), git_calls.read_text(encoding="utf-8")
    assert (Path(first["source_dir"]) / "app" / "main.py").read_bytes() == (
        b"before the scan\n"
    )

    after = _delivery_finalize(data, "during")
    assert after["success"] is True, after
    assert (Path(after["source_dir"]) / "app" / "main.py").read_bytes() == (
        b"during the scan\n"
    )
    cloned = _delivery_tool("set_source_git", url=url)
    assert cloned["success"] is True, cloned
    assert (Path(cloned["source_dir"]) / "cloned.txt").is_file(), cloned
    assert url in git_calls.read_text(encoding="utf-8")
    cleared = _delivery_tool("clear_source")
    assert cleared["success"] is True, cleared


# --------------------------------------------------------------------------- #
# The scanner sandbox
# --------------------------------------------------------------------------- #

_SANDBOX_HOW_TO = "docs/scanner-sandbox.md"

_SANDBOX_MODES_SENTENCE = (
    "The values are `off`, `auto`, `bwrap`, `firejail`, `landlock`, and `sandbox-exec`, "
    'lowercase. Quote `"off"`. YAML reads an unquoted `off` as the boolean false, which a '
    "scan refuses with exit code 3:"
)


def _sandbox_config_file(parent: Path, mode_line: str) -> Path:
    path = parent / "ash-sandbox-mode.yaml"
    path.write_text(
        f"project_name: sandbox-mode\nsandbox:\n  {mode_line}\n", encoding="utf-8"
    )
    return path


@pytest.mark.parametrize(
    "mode_line, expected",
    [
        pytest.param("mode: off", 3, id="unquoted-off"),
        pytest.param("mode: AUTO", 3, id="not-lowercase"),
        pytest.param('mode: "off"', 0, id="control-quoted-off"),
    ],
)
@pytest.mark.integration
def test_an_unquoted_off_sandbox_mode_makes_a_scan_exit_3(
    tmp_path: Path, mode_line: str, expected: int
) -> None:
    """scanner-sandbox.md (Turn it on in a config file).

    The modes the page lists must be the ones the config model allows. A detect-secrets
    scan run with a config file whose ``sandbox.mode`` is an unquoted ``off`` or not
    lowercase must exit 3. The control is the same file with ``"off"`` quoted, which
    scans a tree with nothing to find and exits 0.
    """
    assert_on_page(_SANDBOX_HOW_TO, _SANDBOX_MODES_SENTENCE)
    from automated_security_helper.config.ash_config import SandboxConfig

    allowed = typing.get_args(SandboxConfig.model_fields["mode"].annotation)
    listed = re.findall(r"`([^`]+)`", _SANDBOX_MODES_SENTENCE.split(", lowercase")[0])
    assert list(allowed) == listed, (allowed, listed)

    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    result = _ash(
        [
            "scan",
            "--config",
            str(_sandbox_config_file(tmp_path, mode_line)),
            "--source-dir",
            str(source),
            "--output-dir",
            str(tmp_path / "output"),
            "--scanners",
            "detect-secrets",
            "--offline",
            "--no-progress",
        ],
        cwd=tmp_path,
    )
    assert result.returncode == expected, (
        f"{mode_line}: exit {result.returncode}, expected {expected}:\n{_output_tail(result)}"
    )


@pytest.mark.parametrize(
    "mode_line, expected",
    [
        pytest.param("mode: off", 3, id="unquoted-off"),
        pytest.param('mode: "off"', 0, id="control-quoted-off"),
    ],
)
@pytest.mark.integration
def test_ash_config_validate_gives_an_unquoted_off_sandbox_mode_the_scan_verdict(
    tmp_path: Path, mode_line: str, expected: int
) -> None:
    """scanner-sandbox.md (Turn it on in a config file).

    ``ash config validate`` of a config file whose ``sandbox.mode`` is an unquoted
    ``off`` must exit 3, as the scan does. The control is the same file with ``"off"``
    quoted, which validates with 0. Both files set ``project_name``, so the verdict is
    the mode's.
    """
    assert_on_page(_SANDBOX_HOW_TO, _SANDBOX_MODES_SENTENCE)
    assert_on_page(
        _SANDBOX_HOW_TO,
        "`ash config validate` gives the same verdict, with the same exit code:",
    )
    result = _ash(
        [
            "config",
            "validate",
            "--config",
            str(_sandbox_config_file(tmp_path, mode_line)),
        ],
        cwd=tmp_path,
    )
    assert result.returncode == expected, (
        f"{mode_line}: exit {result.returncode}, expected {expected}:\n{_output_tail(result)}"
    )


#: The messages in the table under "When a scanner cannot be sandboxed".
_SANDBOX_FIX_TABLE = (
    "bwrap is not installed (install the 'bubblewrap' package)",
    "bwrap cannot create a sandbox here (...)",
    "bwrap cannot apply the Unix-socket filter in its sandbox (...)",
    "Landlock is not available (...)",
    "Landlock ABI <n> is below 3 (Linux 6.2), ...",
    "firejail is not installed",
    "firejail ran a test command without a sandbox (...)",
    "sandbox-exec is not present (it has been removed from this macOS)",
    "--sandbox auto found no working sandbox (...)",
    "no scanner sandbox is available on Windows; ...",
    "<name>: the config names this scanner '<name>', but its own name is '<other>'",
    "<scanner> cannot be sandboxed as requested: ...",
    "the results directory path <path> is a symlink, ...",
    "a scanner tried to start a shell command, which the sandbox does not wrap",
)

_SANDBOX_WILD = object()


def _sandbox_table_messages() -> List[str]:
    """The first cell of each row of the page's Message | Fix table."""
    lines = _page_text(_SANDBOX_HOW_TO).splitlines()
    start = lines.index("| Message | Fix |")
    messages = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        cell = line.split("|")[1].strip()
        assert cell.startswith("`") and cell.endswith("`"), line
        messages.append(cell[1:-1])
    return messages


def _sandbox_message_sources() -> List[Path]:
    """The modules that build the messages: the sandbox package and the spawn helper."""
    import automated_security_helper

    package = Path(automated_security_helper.__file__).resolve().parent
    return sorted((package / "utils" / "sandbox").glob("*.py")) + [
        package / "utils" / "subprocess_utils.py"
    ]


@lru_cache(maxsize=None)
def _sandbox_code_strings(
    sources: Tuple[Path, ...],
) -> Tuple[Tuple[str, Tuple[object, ...]], ...]:
    """(file name, parts) of every string those modules build.

    A part is literal text, or ``_SANDBOX_WILD`` for a ``{...}`` field. Pieces joined
    with ``+`` are one string, as Python joins them.
    """

    def parts_of(node: ast.AST) -> Optional[List[object]]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, ast.JoinedStr):
            return [
                value.value if isinstance(value, ast.Constant) else _SANDBOX_WILD
                for value in node.values
            ]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = parts_of(node.left), parts_of(node.right)
            if left is None and right is None:
                return None
            return (left or [_SANDBOX_WILD]) + (right or [_SANDBOX_WILD])
        return None

    found = []
    for path in sources:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            parts = parts_of(node)
            if parts:
                found.append((path.name, tuple(parts)))
    return tuple(found)


def _sandbox_sample(message: str) -> str:
    """The message as text a built string must start with.

    ``<...>`` becomes ``X``, ``(...)`` becomes ``(X)``, and a trailing ``...`` ends
    the sample, since the page cuts the message there.
    """
    sample = re.sub(r"<[^>]+>", "X", message.replace("(...)", "(X)"))
    return sample.removesuffix("...")


def _sandbox_literal_cover(sample: str, parts: Tuple[object, ...]) -> int:
    """How much of ``sample`` a string built from ``parts`` matches literally, or -1.

    -1 when no string the parts can build starts with ``sample``. A field matches one
    or more characters, which do not count, so ``f"{error}"`` covers nothing.
    """

    @lru_cache(maxsize=None)
    def cover(i: int, j: int) -> int:
        if i == len(sample):
            return 0
        if j == len(parts):
            return -1
        part = parts[j]
        if part is _SANDBOX_WILD:
            return max(
                (cover(k, j + 1) for k in range(i + 1, len(sample) + 1)), default=-1
            )
        n = min(len(part), len(sample) - i)
        if sample[i : i + n] != part[:n]:
            return -1
        if n < len(part):
            return n
        rest = cover(i + n, j + 1)
        return -1 if rest < 0 else n + rest

    return cover(0, 0)


def _sandbox_where(message: str) -> List[str]:
    """The modules with a string that starts like ``message`` and matches most of it."""
    sample = _sandbox_sample(message)
    wanted = 0.8 * (len(sample) - sample.count("X"))
    strings = _sandbox_code_strings(tuple(_sandbox_message_sources()))
    return sorted(
        {
            name
            for name, parts in strings
            if _sandbox_literal_cover(sample, parts) >= wanted
        }
    )


@pytest.mark.unit
def test_the_sandbox_fix_table_lists_messages_the_code_gives() -> None:
    """scanner-sandbox.md (When a scanner cannot be sandboxed).

    The table's messages must be the ones this test lists, and each must start a
    string the sandbox modules build, with the page's ``<...>``, ``(...)`` and ``...``
    and the code's ``{...}`` fields matching any text. The control is a reworded
    message, which matches nothing.
    """
    assert _sandbox_table_messages() == list(_SANDBOX_FIX_TABLE)
    for message in _SANDBOX_FIX_TABLE:
        assert_on_page(_SANDBOX_HOW_TO, f"| `{message}` |")
    missing = [message for message in _SANDBOX_FIX_TABLE if not _sandbox_where(message)]
    assert not missing, f"no string in the sandbox modules starts like: {missing}"
    assert _sandbox_where("bwrap is not installed (install the 'bwrap' package)") == []


@pytest.fixture
def _sandbox_fresh_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Forget the backends this process resolved and the programs it looked up.

    Both are cached per process, so a probe made under another test's PATH or platform
    would answer this one.
    """
    from automated_security_helper.utils import subprocess_utils
    from automated_security_helper.utils.sandbox import scope

    monkeypatch.setattr(scope, "_resolved", {})
    if hasattr(subprocess_utils, "_find_executable_cache"):
        monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})


def _sandbox_path_with(directory: Path, names: Iterable[str]) -> str:
    """``directory``, holding an executable file for each name, as the whole PATH.

    No file is run: the tests answer process starts themselves.
    """
    directory.mkdir()
    for name in names:
        for file_name in (name, f"{name}.exe"):
            program = directory / file_name
            program.write_bytes(b"")
            program.chmod(0o755)
    return str(directory)


def _sandbox_processes_exit(
    monkeypatch: pytest.MonkeyPatch, code: int, stderr: str = ""
) -> List[List[str]]:
    """Every process started with ``subprocess.run`` exits ``code`` without running."""
    started: List[List[str]] = []

    def run(argv: Any, *args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        started.append(list(argv))
        return subprocess.CompletedProcess(argv, code, "", stderr)

    monkeypatch.setattr(subprocess, "run", run)
    return started


@pytest.mark.parametrize(
    "system, path_programs, pinned, expected",
    [
        pytest.param(
            "Linux",
            (),
            [
                "| `bwrap is not installed (install the 'bubblewrap' package)` |",
                "| `firejail is not installed` |",
                "| `Landlock is not available (...)` |",
                "| `--sandbox auto found no working sandbox (...)` |",
            ],
            {
                "bwrap": "bwrap is not installed (install the 'bubblewrap' package)",
                "firejail": "firejail is not installed",
                "landlock": "Landlock is not available (",
                "auto": "--sandbox auto found no working sandbox (bwrap: bwrap is not installed",
            },
            id="linux-with-nothing-installed",
        ),
        pytest.param(
            "Linux",
            ("bwrap",),
            ["| `bwrap cannot create a sandbox here (...)` |"],
            {
                "bwrap": "bwrap cannot create a sandbox here (exit 1: bwrap: No permissions"
            },
            id="linux-bwrap-without-user-namespaces",
        ),
        pytest.param(
            "Darwin",
            (),
            ["| `sandbox-exec is not present (it has been removed from this macOS)` |"],
            {
                "sandbox-exec": (
                    "sandbox-exec is not present (it has been removed from this macOS)"
                )
            },
            id="macos-without-sandbox-exec",
        ),
        pytest.param(
            "Windows",
            (),
            [
                "| `no scanner sandbox is available on Windows; ...` |",
                (
                    "no scanner sandbox is available on Windows; run ASH under WSL2 and "
                    "use --sandbox bwrap there, or use --mode container"
                ),
                "A named backend reports `<backend> is not available on Windows` instead.",
            ],
            {
                "auto": "no scanner sandbox is available on Windows; run ASH under WSL2 and "
                "use --sandbox bwrap there, or use --mode container",
                "bwrap": "bwrap is not available on Windows",
            },
            id="windows",
        ),
    ],
)
@pytest.mark.unit
def test_the_sandbox_backend_probes_give_the_fix_table_messages(
    _sandbox_fresh_probes: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    system: str,
    path_programs: Tuple[str, ...],
    pinned: List[str],
    expected: Dict[str, str],
) -> None:
    """scanner-sandbox.md (When a scanner cannot be sandboxed; Set up a backend).

    Each mode is resolved the way a scan resolves it, with the platform, PATH, and
    every process the probes start set by the test: each process exits 1 with the
    stderr bwrap gives where user namespaces are off, and ``/usr/bin/sandbox-exec`` is
    absent. Each reason must start with the page's message. The Windows case is also
    the control that no probe starts a process on a platform its backend does not
    support.
    """
    for sentence in pinned:
        assert_on_page(_SANDBOX_HOW_TO, sentence)
    from automated_security_helper.utils.sandbox import scope
    from automated_security_helper.utils.sandbox.policy import SandboxUnavailable

    monkeypatch.setattr(platform, "system", lambda: system)
    monkeypatch.setenv("PATH", _sandbox_path_with(tmp_path / "path", path_programs))
    started = _sandbox_processes_exit(
        monkeypatch, 1, "bwrap: No permissions to create new namespace"
    )
    real_exists = Path.exists
    monkeypatch.setattr(
        Path,
        "exists",
        lambda self, *a, **k: (
            False
            if self.as_posix() == "/usr/bin/sandbox-exec"
            else real_exists(self, *a, **k)
        ),
    )

    for mode, reason in expected.items():
        with pytest.raises(SandboxUnavailable) as refused:
            scope.resolve_backend(mode)
        assert str(refused.value).startswith(reason), (mode, str(refused.value))
    if system == "Windows":
        assert started == [], f"a probe started a process on Windows: {started}"


_SANDBOX_GRANTS = {
    "project_name": "grants",
    "sandbox": {
        "network_scanners": ["grype"],
        "extra_read_paths": ["/srv/ash/semgrep-rules"],
    },
}


@pytest.mark.unit
def test_a_config_in_any_checkout_cannot_grant_and_the_warning_names_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ash_log: List[logging.LogRecord]
) -> None:
    """scanner-sandbox.md (Who may grant), sandbox.md (Grants, and who may make them),
    and platform-teams.md (2. Write the operator config).

    Configs that grant a network and a read path are resolved the way a scan of a
    project resolves them, and each warning that drops grants must name the file it
    drops them from. A repository config inside the scanned checkout loses both grants
    and keeps the network list as a limit. So does the same file in a separate ops
    checkout passed as the operator's config, since a file inside any git checkout is
    repository-written. The control is the same file outside every checkout, which
    keeps both grants and logs no warning. A root file there that grants the network
    itself and extends a base inside a checkout keeps only its own grant, and the
    warning names the base.
    """
    assert_on_page(
        _SANDBOX_HOW_TO,
        "A root config file inside the scanned tree, by the file's own path, its resolved "
        "path, or any symbolic link it passes through, cannot grant.",
    )
    assert_on_page(
        _SANDBOX_HOW_TO,
        "Nor can a root config file in any other git checkout, meaning a directory at or "
        "above it holds a `.git` directory or file, such as an ops or dotfiles repository "
        "you name with `--config`",
    )
    assert_on_page(
        SANDBOX,
        "A config file inside any git checkout, the scanned one or a separate one such as "
        "an ops or dotfiles repository, or inside the scanned directory, cannot grant, "
        "whether it is the file you name or a base it extends.",
    )
    assert_on_page(
        _SANDBOX_HOW_TO,
        "A base cannot grant when it is inside any git checkout, the scanned one or a "
        "separate one, or inside the scanned tree, and ASH names that base in a warning.",
    )
    assert_on_page(
        _CONFIG_PLATFORM_PAGE,
        "ASH treats a config file inside any git checkout, or inside the directory it "
        "scans, as written by a repository, even when you name it with `--config`",
    )
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "source"
    source.mkdir()

    def grants_of(
        config_path: Optional[Path], source_dir: Path
    ) -> Tuple[Any, List[str]]:
        ash_log.clear()
        resolved = resolve_config(config_path=config_path, source_dir=source_dir)
        warnings = [m for m in _messages(ash_log) if m.startswith("Ignoring sandbox.")]
        return resolved.sandbox, warnings

    repository = _tree_with_config(tmp_path / "repository", _SANDBOX_GRANTS)
    (repository / ".git").mkdir()
    in_repository = repository / ".ash" / ".ash.yaml"
    ops = tmp_path / "ops" / "ash.yaml"
    (ops.parent / ".git").mkdir(parents=True)
    ops.write_text(yaml.safe_dump(_SANDBOX_GRANTS), encoding="utf-8")
    for config_path, source_dir, named in (
        (None, repository, in_repository),
        (ops, source, ops),
    ):
        sandbox, warnings = grants_of(config_path, source_dir)
        assert len(warnings) == 1 and named.as_posix() in warnings[0], (
            f"{named}: {warnings}"
        )
        assert sandbox.network_scanners is None, (named, sandbox.network_scanners)
        assert list(sandbox.extra_read_paths) == [], (named, sandbox.extra_read_paths)
        assert sandbox.network_limit == ["grype"], (named, sandbox.network_limit)

    outside = tmp_path / "etc" / "ash.yaml"
    outside.parent.mkdir()
    outside.write_text(yaml.safe_dump(_SANDBOX_GRANTS), encoding="utf-8")
    sandbox, warnings = grants_of(outside, source)
    assert warnings == []
    assert sandbox.network_scanners == ["grype"]
    assert list(sandbox.extra_read_paths) == ["/srv/ash/semgrep-rules"]

    # A base has to sit in the root file's own directory, so the checkout it is in is
    # one inside that directory.
    base = outside.parent / "ops" / "base.yaml"
    (base.parent / ".git").mkdir(parents=True)
    base.write_text(
        yaml.safe_dump({"sandbox": {"extra_read_paths": ["/srv/ash/semgrep-rules"]}}),
        encoding="utf-8",
    )
    outside.write_text(
        yaml.safe_dump(
            {
                "project_name": "grants",
                "extends": "./ops/base.yaml",
                "sandbox": {"network_scanners": ["grype"]},
            }
        ),
        encoding="utf-8",
    )
    sandbox, warnings = grants_of(outside, source)
    assert len(warnings) == 1 and base.as_posix() in warnings[0], warnings
    assert sandbox.network_scanners == ["grype"]
    assert list(sandbox.extra_read_paths) == []


#: trust-model.md's quote of the warning for a repository config at
#: /work/repo/.ash/.ash.yaml that grants grype a network and a read path.
_DROPPED_GRANTS_WARNING = (
    "Ignoring sandbox.network_scanners, sandbox.extra_read_paths from "
    "/work/repo/.ash/.ash.yaml: that config is inside a git checkout or the scanned tree, "
    "or was delivered by an MCP client. A network_scanners list there still removes "
    "network from scanners it does not name, and a sandbox mode there still applies when "
    "nothing else turns the sandbox on. To keep a setting, move the file outside every "
    "git checkout, or pass the setting with --config-overrides. A file inside the scanned "
    "directory has to move out of it as well."
)

#: The advice in that quote, which every such warning ends with or follows with a hint.
_KEEP_A_SETTING = (
    "To keep a setting, move the file outside every git checkout, or pass the setting with "
    "--config-overrides. A file inside the scanned directory has to move out of it as well."
)


def _repository_warnings(
    tmp_path: Path,
    ash_log: List[logging.LogRecord],
    document: Dict[str, Any],
    quoted: str,
) -> List[str]:
    """The warnings a scan of a checkout logs when its own ``.ash/.ash.yaml`` holds
    ``document``, with the file's path written as ``quoted``."""
    ash_log.clear()
    resolved = _resolved_from_tier(tmp_path, "repository", document)
    assert resolved is not None
    config = tmp_path / "project" / ".ash" / ".ash.yaml"
    warnings = []
    for message in _messages(r for r in ash_log if r.levelno == logging.WARNING):
        for spelling in {str(config.resolve()), str(config), config.as_posix()}:
            message = message.replace(spelling, quoted)
        warnings.append(message)
    return warnings


@pytest.mark.unit
def test_the_dropped_grants_warning_reads_as_the_pages_quote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ash_log: List[logging.LogRecord]
) -> None:
    """trust-model.md (When a lower tier sets something it may not), scanner-sandbox.md
    (Who may grant), and troubleshoot.md (A setting in the repository's config file is
    ignored).

    A checkout's own config that grants grype a network and a read path is resolved
    the way a scan of it resolves it, and the one warning about it must read as the two
    pages quote it, with the file's path written as each page writes it. A config that
    grants only the network gets the warning troubleshoot.md starts to quote.
    """
    assert_on_page(TRUST_MODEL, _DROPPED_GRANTS_WARNING)
    assert_on_page(
        _SANDBOX_HOW_TO,
        "WARNING "
        + _DROPPED_GRANTS_WARNING.replace("/work/repo/", "/home/me/src/app/"),
    )
    troubleshoot = (
        "Ignoring sandbox.network_scanners from /home/me/repo/.ash/.ash.yaml: that config "
        "is inside a git checkout or the scanned tree, or was delivered by an MCP client."
    )
    assert_on_page("how-to/troubleshoot.md", f"{troubleshoot} ...")
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    both = _repository_warnings(
        tmp_path / "both", ash_log, _SANDBOX_GRANTS, "/work/repo/.ash/.ash.yaml"
    )
    dropped = [w for w in both if w.startswith("Ignoring sandbox.")]
    assert dropped == [_DROPPED_GRANTS_WARNING], dropped

    network = _repository_warnings(
        tmp_path / "network",
        ash_log,
        {"project_name": "grants", "sandbox": {"network_scanners": ["grype"]}},
        "/home/me/repo/.ash/.ash.yaml",
    )
    dropped = [w for w in network if w.startswith("Ignoring sandbox.")]
    assert len(dropped) == 1 and dropped[0].startswith(troubleshoot), dropped


@pytest.mark.parametrize(
    "document, ignoring",
    [
        pytest.param(
            {"sandbox": {"network_scanners": ["grype"]}},
            "Ignoring sandbox.network_scanners from",
            id="sandbox-grants",
        ),
        pytest.param(
            {"ash_plugin_modules": ["page_claims_missing_ash_plugins"]},
            "Ignoring ash_plugin_modules entries 'page_claims_missing_ash_plugins'",
            id="plugin-modules",
        ),
        pytest.param(
            {
                "scanners": {
                    "detect-secrets": {
                        "options": {
                            "scan_settings": {
                                "filters_used": [
                                    {
                                        "path": "detect_secrets.filters.common."
                                        "is_ignored_due_to_verification_policies",
                                        "min_level": 2,
                                    }
                                ]
                            }
                        }
                    }
                }
            },
            "Ignoring scanners.detect-secrets.options.scan_settings entries",
            id="detect-secrets-verification",
        ),
        pytest.param(
            {"honor_ignore_files": False},
            "Ignoring honor_ignore_files from",
            id="honor-ignore-files",
        ),
        pytest.param(
            {"converters": {"archive": {"options": {"max_members": 10_000_000}}}},
            "Ignoring converters.archive.options.max_members",
            id="archive-limit-raised",
        ),
    ],
)
@pytest.mark.unit
def test_every_warning_that_ignores_a_repository_setting_says_how_to_keep_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ash_log: List[logging.LogRecord],
    document: Dict[str, Any],
    ignoring: str,
) -> None:
    """trust-model.md (Why the repository tier exists).

    A checkout's own config that sets one thing only the operator may set is resolved
    the way a scan of it resolves it. The one warning that ignores the setting must name
    the file and give the advice the page's quoted warning gives, which is the page's
    "pass it with --config-overrides, or move it to a config file outside every git
    checkout and outside the scanned directory".
    """
    assert_on_page(
        TRUST_MODEL,
        "When ASH ignores a setting from such a file, it names the file in a warning that "
        "says how to keep the setting: pass it with `--config-overrides`, or move it to a "
        "config file outside every git checkout and outside the scanned directory.",
    )
    assert _KEEP_A_SETTING in _DROPPED_GRANTS_WARNING
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    warnings = _repository_warnings(
        tmp_path, ash_log, {"project_name": "app", **document}, "<the file>"
    )
    ignored = [w for w in warnings if w.startswith(ignoring)]
    assert len(ignored) == 1, f"expected one warning starting {ignoring!r}: {warnings}"
    assert "<the file>" in ignored[0], ignored[0]
    assert _KEEP_A_SETTING in ignored[0], ignored[0]


@pytest.mark.unit
def test_the_warning_for_an_aws_reporter_a_repository_turns_on_reads_as_quoted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ash_log: List[logging.LogRecord]
) -> None:
    """aws.md (the warning for a reporter setting a repository's config cannot make).

    A checkout's own config that sets ``reporters.aws-security-hub.enabled: true`` is
    resolved the way a scan of it resolves it, and the one warning about it must read
    as the page quotes it, with the file's path written as the page writes it.
    """
    quoted = (
        "Ignoring reporters.aws-security-hub.enabled from /home/me/repo/.ash/.ash.yaml: "
        "that config is inside a git checkout or the scanned tree, or was delivered by "
        "an MCP client, and these options choose whether findings are sent, where they "
        f"are sent or written, and which credentials send them. {_KEEP_A_SETTING}"
    )
    assert_on_page(AWS_PLUGINS, quoted)
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    warnings = _repository_warnings(
        tmp_path,
        ash_log,
        {
            "project_name": "app",
            "reporters": {"aws-security-hub": {"enabled": True}},
        },
        "/home/me/repo/.ash/.ash.yaml",
    )
    ignored = [w for w in warnings if w.startswith("Ignoring reporters.")]
    assert ignored == [quoted], ignored


_SANDBOX_BACKEND_LINE = "Scanner sandbox: using bwrap (--sandbox auto)"
_SANDBOX_SCANNER_LINE = "Scanner sandbox: detect-secrets on source runs under bwrap"

#: (the backend ``--sandbox auto`` picks, the sentence that says so) for each
#: platform, as ``platform.system()`` names it. Windows has no backend.
_SANDBOX_AUTO: Dict[str, Tuple[Optional[str], str]] = {
    "Linux": (
        "bwrap",
        (
            "`auto` uses the first backend that can start a sandbox on this machine: on "
            "Linux `bwrap`, then `firejail`, then `landlock`; on macOS `sandbox-exec`."
        ),
    ),
    "Darwin": (
        "sandbox-exec",
        (
            "`sandbox-exec` ships with macOS at `/usr/bin/sandbox-exec`; there is "
            "nothing to install. `--sandbox auto` uses it."
        ),
    ),
    "Windows": (
        None,
        (
            "There is no sandbox backend on Windows. With `--sandbox auto`, every "
            "scanner is reported `MISSING` with:"
        ),
    ),
}
_SANDBOX_WINDOWS_MESSAGE = (
    "no scanner sandbox is available on Windows; run ASH under WSL2 and use --sandbox "
    "bwrap there, or use --mode container"
)


def _sandbox_lines(backend: str) -> Tuple[str, str]:
    """The lines the page shows, for ``backend``: the scan's, then detect-secrets'."""
    return (
        _SANDBOX_BACKEND_LINE.replace("bwrap", backend),
        _SANDBOX_SCANNER_LINE.replace("bwrap", backend),
    )


@pytest.mark.parametrize("system", sorted(_SANDBOX_AUTO))
@pytest.mark.unit
def test_resolving_the_sandbox_backend_logs_the_backend_auto_picks_on_each_platform(
    _sandbox_fresh_probes: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ash_log: List[logging.LogRecord],
    system: str,
) -> None:
    """scanner-sandbox.md (Turn the sandbox on for one scan; Set up a backend).

    ``auto`` is resolved as each platform resolves it, with the platform set by the
    test: on Linux with a ``bwrap`` on PATH, on macOS with ``/usr/bin/sandbox-exec``
    present, and every process the probes start answered with exit 0. The log must
    name the backend the page says ``auto`` picks there, and the requested mode, as
    the page's sample does. Windows is refused with the page's message and logs no
    backend. The control, on Linux, is nothing on PATH and every probe failing, which
    logs no backend.
    """
    backend, sentence = _SANDBOX_AUTO[system]
    assert_on_page(
        _SANDBOX_HOW_TO,
        "The scan output and `ash.log` say which backend ran each scanner:",
    )
    assert_on_page(_SANDBOX_HOW_TO, f"INFO {_SANDBOX_BACKEND_LINE}")
    assert_on_page(_SANDBOX_HOW_TO, sentence)
    from automated_security_helper.utils.sandbox import scope
    from automated_security_helper.utils.sandbox.policy import SandboxUnavailable

    def backend_lines() -> List[str]:
        return [m for m in _messages(ash_log) if m.startswith("Scanner sandbox: using")]

    monkeypatch.setattr(platform, "system", lambda: system)
    on_path = ("bwrap",) if system == "Linux" else ()
    monkeypatch.setenv("PATH", _sandbox_path_with(tmp_path / "path", on_path))
    _sandbox_processes_exit(monkeypatch, 0)
    real_exists = Path.exists
    monkeypatch.setattr(
        Path,
        "exists",
        lambda self, *a, **k: (
            self.as_posix() == "/usr/bin/sandbox-exec" or real_exists(self, *a, **k)
        ),
    )
    if backend is None:
        assert_on_page(_SANDBOX_HOW_TO, _SANDBOX_WINDOWS_MESSAGE)
        with pytest.raises(SandboxUnavailable) as refused:
            scope.resolve_backend("auto")
        assert str(refused.value).startswith(_SANDBOX_WINDOWS_MESSAGE), refused.value
        assert backend_lines() == []
        return
    assert scope.resolve_backend("auto").name == backend
    assert backend_lines() == [_sandbox_lines(backend)[0]], _messages(ash_log)
    if system != "Linux":
        return

    monkeypatch.setattr(scope, "_resolved", {})
    ash_log.clear()
    monkeypatch.setenv("PATH", _sandbox_path_with(tmp_path / "empty", ()))
    _sandbox_processes_exit(monkeypatch, 1)
    with pytest.raises(SandboxUnavailable):
        scope.resolve_backend("auto")
    assert backend_lines() == []


@pytest.mark.integration
def test_a_sandboxed_scan_logs_each_scanners_backend_and_records_the_requested_mode(
    tmp_path: Path,
) -> None:
    """scanner-sandbox.md (Turn the sandbox on for one scan; Set up a backend) and
    sandbox.md (What fails closed).

    ``ash scan --sandbox auto`` of one file runs as this platform runs it. On Linux a
    stand-in ``bwrap`` first on PATH accepts every call and runs nothing; on macOS
    the scan uses the real ``/usr/bin/sandbox-exec``. There ``ash.log`` must name the
    backend the page says ``auto`` picks, for the scan and for detect-secrets. On
    Windows detect-secrets must be ``MISSING``, with the page's message in ash.log.
    Everywhere the results must record ``auto``, and never the backend. The control is
    the same scan without ``--sandbox``, which logs no backend and records ``off``.
    """
    system = platform.system()
    backend, sentence = _SANDBOX_AUTO[system]
    assert_on_page(_SANDBOX_HOW_TO, sentence)
    assert_on_page(_SANDBOX_HOW_TO, f"INFO {_SANDBOX_BACKEND_LINE}")
    assert_on_page(_SANDBOX_HOW_TO, f"INFO {_SANDBOX_SCANNER_LINE}")
    assert_on_page(
        _SANDBOX_HOW_TO,
        "The results record the mode you asked for (`ash_config.sandbox.mode` in "
        "`ash_aggregated_results.json`), not the backend that ran.",
    )
    assert_on_page(
        SANDBOX,
        "Which backend a scan used is written to `ash.log`; the results record only the "
        "requested mode, in `ash_config.sandbox.mode`.",
    )
    stand_ins = tmp_path / "stand-ins"
    stand_ins.mkdir()
    if system == "Linux":
        bwrap = stand_ins / "bwrap"
        bwrap.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        bwrap.chmod(0o755)
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")

    def scan(output: str, *options: str) -> Tuple[List[str], str, Dict[str, Any]]:
        result = _ash(
            [
                "scan",
                "--source-dir",
                str(source),
                "--output-dir",
                str(tmp_path / output),
                "--scanners",
                "detect-secrets",
                "--offline",
                "--no-progress",
                *options,
            ],
            cwd=tmp_path,
            PATH=os.pathsep.join([str(stand_ins), os.environ.get("PATH", "")]),
        )
        log = tmp_path / output / "ash.log"
        assert log.is_file(), _output_tail(result)
        text = log.read_text(encoding="utf-8")
        lines = [
            line.split("\t")[-1].strip()
            for line in text.splitlines()
            if "Scanner sandbox: " in line
        ]
        results = json.loads(
            (tmp_path / output / "ash_aggregated_results.json").read_text(
                encoding="utf-8"
            )
        )
        return lines, _normalize(text), results

    lines, log, results = scan("sandboxed", "--sandbox", "auto")
    assert results["ash_config"]["sandbox"]["mode"] == "auto"
    if backend is None:
        assert_on_page(_SANDBOX_HOW_TO, _SANDBOX_WINDOWS_MESSAGE)
        row = results["scanner_results"]["detect-secrets"]
        assert row["status"] == "MISSING", row
        assert _SANDBOX_WINDOWS_MESSAGE in log, lines
        assert not [line for line in lines if line.startswith("Scanner sandbox: using")]
    else:
        for line in _sandbox_lines(backend):
            assert line in lines, lines
        assert backend not in json.dumps(results), (
            "the results name the backend that ran"
        )

    lines, _log, results = scan("unsandboxed")
    assert lines == []
    assert results["ash_config"]["sandbox"]["mode"] == "off"


# --------------------------------------------------------------------------- #
# Container image: the CI variables do not choose the image stage
# --------------------------------------------------------------------------- #

#: The sentence that names the CI variables that do not change the image stage.
_CI_ENV_SENTENCE: Tuple[str, str] = (
    RUN_IN_A_CONTAINER,
    (
        "The CI variables `CI`, `IsCI`, `ISCI`, and `CODEBUILD_BUILD_ID` do not change "
        "the stage."
    ),
)

#: Sentences that tell a CI job to ask for the root image itself.
_ROOT_JOB_SENTENCES: List[Tuple[str, str]] = [
    (
        "getting-started/platform-teams.md",
        (
            "If the rebuild runs in a CI job that runs as root, as AWS CodeBuild and "
            "container-based GitLab and Jenkins jobs do, pass `--build-target ci`: ASH "
            "refuses to build the non-root image as UID 0."
        ),
    ),
    (
        "faq.md",
        (
            "`--build-target ci` builds the image that runs as root, which a job running "
            "as root needs."
        ),
    ),
    (
        "how-to/troubleshoot.md",
        (
            "A `non-root` build that would give its user UID 0 or GID 0, as a job "
            "running as root does, stops with exit code 3 before anything is built: pass "
            "`--build-target ci` there."
        ),
    ),
    (
        "how-to/ci/other-ci.md",
        (
            "A job that runs as root, as AWS CodeBuild and container-based jobs do, needs "
            "`--build-target ci`: ASH refuses to build the non-root image, whose user "
            "would get UID 0."
        ),
    ),
]

#: Variables other CI services set. None of them may select the root image, which holds
#: "none of these" even against a marker read outside the container module.
_CI_ENV_OTHER_SERVICES = (
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "TF_BUILD",
    "JENKINS_URL",
    "BUILDKITE",
    "CIRCLECI",
    "TRAVIS",
    "BITBUCKET_BUILD_NUMBER",
    "CODEBUILD_BUILD_ARN",
)

#: Variables the container module reads that the probe clears but never sets.
_CI_ENV_NOT_SET = {
    "OCI_RUNNER_WRAPPER": "the probe's own container runtime",
    "ASH_BASE_OCI_LAYOUT": "the build refuses any value but <layout dir>@sha256:<64 hex>",
}

#: A fake container runtime that records the command it was given and succeeds.
_CI_ENV_RECORDING_RUNTIME = """\
import json, sys
from pathlib import Path

Path({record!r}).write_text(json.dumps(sys.argv[1:]), encoding="utf-8")
"""


def _ci_env_named(sentence: str) -> Set[str]:
    """The variables a sentence names: its ``env -u`` names, else its capitalized spans."""
    unset = re.findall(r"-u ([A-Za-z_]\w*)", sentence)
    if unset:
        return set(unset)
    return set(re.findall(r"`([A-Z][A-Za-z0-9_]*)`", sentence))


def _ci_env_module_reads(module: Any) -> Set[str]:
    """The environment variables ``module`` reads by a literal name.

    Covers ``os.environ.get``, ``os.getenv``, ``os.environ[...]`` and ``in os.environ``.
    A read whose name is not a literal fails here, since the probe could not set it.
    """

    def is_environ(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "environ"
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
        )

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    names: Set[str] = set()
    unresolved: List[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            getter = node.func.attr == "get" and is_environ(node.func.value)
            getenv = (
                node.func.attr == "getenv"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
            )
            if not (getter or getenv):
                continue
            key = node.args[0] if node.args else None
        elif isinstance(node, ast.Subscript) and is_environ(node.value):
            key = node.slice
        elif (
            isinstance(node, ast.Compare)
            and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops)
            and any(is_environ(c) for c in node.comparators)
        ):
            key = node.left
        else:
            continue
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            names.add(key.value)
        else:
            unresolved.append(node.lineno)
    assert not unresolved, (
        f"{module.__name__} reads the environment by a computed name at lines "
        f"{unresolved}; the probe cannot set those"
    )
    return names


@pytest.mark.unit
def test_the_ci_variables_do_not_choose_the_image_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run-in-a-container.md (Root and non-root images), and the pages that tell a CI
    job to ask for the root image itself: platform-teams.md (5. Plan content database
    refresh), faq.md (Is there a container image?), troubleshoot.md (The container image
    does not build) and other-ci.md (Local mode or container mode).

    The image build runs in-process against a fake container runtime
    (``OCI_RUNNER_WRAPPER``) that records the build command, once with each candidate
    set alone, to ``true`` and to ``false``: every variable the container module reads
    by name, the page's variables, and the markers other CI services set. Asked for
    ``--build-target non-root``, and, off Windows, for no stage, every build targets
    ``non-root``. The control asks for ``--build-target ci`` with none of them set and
    must target ``ci``, so the probe can see a root build. That a
    ``--custom-containerfile`` builds ``ci``, and that a ``non-root`` build as UID 0 is
    refused, are held by the container entrypoint's unit tests.
    """
    page, sentence = _CI_ENV_SENTENCE
    assert_on_page(page, sentence)
    for page, root_job in _ROOT_JOB_SENTENCES:
        assert_on_page(page, root_job)
    markers = _ci_env_named(sentence)
    assert len(markers) >= 2, f"the page names no CI variables: {sentence!r}"

    from automated_security_helper.core.enums import BuildTarget
    from automated_security_helper.interactions import run_ash_container as container
    from automated_security_helper.utils import subprocess_utils

    # The build may ask the host its UID and GID by starting `id`. The probe
    # passes --container-uid/--container-gid, so the answer is never used for the
    # stage choice this measures. The stand-ins answer the module's own lookup
    # functions, and the run_command wrapper answers an `id` started through
    # subprocess_utils.run_command, the way those lookups start programs. An `id`
    # started around that seam would still be a real program: this fences the
    # module's lookup paths, it does not prove no path could start one.
    real_run_command = subprocess_utils.run_command

    def _run_command_answering_id(command, *args, **kwargs):
        if command and Path(command[0]).name == "id":
            return subprocess.CompletedProcess(command, 0, stdout="1000\n", stderr="")
        return real_run_command(command, *args, **kwargs)

    # hasattr-guarded like the uv pins: the code tiers differ here, and a tree
    # without these functions still gets its `id` answered by the wrapper below.
    for lookup in ("get_host_uid", "get_host_gid"):
        if hasattr(subprocess_utils, lookup):
            monkeypatch.setattr(subprocess_utils, lookup, lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "run_command", _run_command_answering_id)

    read = _ci_env_module_reads(container)
    cleared = read | markers | set(_CI_ENV_OTHER_SERVICES)
    candidates = sorted(cleared - set(_CI_ENV_NOT_SET))
    # With a revision named, the build takes the Dockerfile beside a pyproject.toml in
    # the working directory however ASH is installed, checkout or not.
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'x'\n", encoding="utf-8"
    )
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.chdir(tmp_path)
    runs = itertools.count()

    def build_target(
        name: str | None, value: str = "true", requested: BuildTarget | None = None
    ) -> str:
        for variable in cleared:
            monkeypatch.delenv(variable, raising=False)
        if name is not None:
            monkeypatch.setenv(name, value)
        number = next(runs)
        record = tmp_path / f"build-command-{number}.json"
        runtime = tmp_path / f"runtime-{number}.py"
        runtime.write_text(
            _CI_ENV_RECORDING_RUNTIME.format(record=str(record)), encoding="utf-8"
        )
        monkeypatch.setenv(
            "OCI_RUNNER_WRAPPER", shlex.join([sys.executable, str(runtime)])
        )
        result = container.run_ash_container(
            source_dir=str(source),
            output_dir=str(tmp_path / "output"),
            build=True,
            run=False,
            oci_runner=sys.executable,
            build_target=requested,
            ash_revision_to_install="main",
            container_uid="1000",
            container_gid="1000",
            quiet=True,
        )
        assert record.is_file(), f"no image build ran with {name} set: {result!r}"
        argv = json.loads(record.read_text(encoding="utf-8"))
        return argv[argv.index("--target") + 1]

    assert build_target(None, requested=BuildTarget.CI) == "ci", (
        "asked for --build-target ci, ASH built another stage"
    )
    # No requirement that a lookup happened: a build given explicit ids may skip
    # it, and the stand-ins above answer the module's lookup paths, so a lookup
    # that does happen starts no `id` program through them either way.
    requests = [BuildTarget.NON_ROOT] + ([None] if os.name != "nt" else [])
    root = sorted(
        (name, value, getattr(requested, "value", "no --build-target"))
        for name in candidates
        for value in ("true", "false")
        for requested in requests
        if build_target(name, value, requested) == "ci"
    )
    assert not root, f"ASH builds the root ci stage with these set: {root}"


# --------------------------------------------------------------------------- #
# Scanner tools: the ones ASH installs with uv
# --------------------------------------------------------------------------- #

#: Sentences that list the built-in scanners ASH installs with uv.
_UV_SCANNER_SENTENCES: List[Tuple[str, str]] = [
    (
        "how-to/install.md",
        "ASH installs bandit, checkov, and semgrep with uv.",
    ),
    (
        "how-to/install.md",
        (
            "Either way, ASH installs bandit, checkov, and semgrep with "
            "the environment's own `uv`."
        ),
    ),
    (
        "getting-started/index.md",
        (
            "Without them, an online scan with the sandbox off installs bandit, "
            "checkov, and semgrep itself, with the `uv` installed with "
            "ASH."
        ),
    ),
    (
        "docs/advanced-usage.md",
        (
            "| bandit, checkov, semgrep | same name | ASH installs them "
            "with `uv tool` during a scan, or `ash dependencies install` does it ahead "
            "of time |"
        ),
    ),
    (
        "how-to/ci/github-actions.md",
        (
            "bandit, checkov, and semgrep need no input: ASH installs "
            "them from PyPI with `uv tool install` during the scan."
        ),
    ),
]

#: Sentences that list them with the jupyter converter's nbconvert.
_UV_TOOL_SENTENCES: List[Tuple[str, str]] = [
    (
        "how-to/install.md",
        "`uv tool uninstall bandit checkov semgrep nbconvert`.",
    ),
    (
        "docs/advanced-usage.md",
        (
            "installs bandit, checkov, semgrep, and nbconvert with "
            "`uv tool install`, within each scanner's accepted version range."
        ),
    ),
    (
        "docs/advanced-usage.md",
        (
            "When bandit, checkov, semgrep, or nbconvert is not "
            "available, ASH installs it with `uv tool install` during the scan, and the "
            "scan takes longer."
        ),
    ),
    (
        "docs/advanced-usage.md",
        (
            "The `uv tool install`, `uv tool run`, and `uv tool list` commands that ASH "
            "runs for bandit, checkov, semgrep, and nbconvert get no "
            "such flag."
        ),
    ),
    (
        "concepts/scanning-untrusted-code.md",
        (
            "A missing Python tool (bandit, checkov, semgrep, and "
            "nbconvert for the notebook converter) is installed at scan time with "
            "`uv tool install`"
        ),
    ),
]


def _instantiated_plugins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attribute: str
) -> List[Tuple[str, Any]]:
    """(plugin module, plugin) for each plugin ``attribute`` lists in ASH's own plugin
    modules, each built with its default config, as ``ash dependencies install`` builds
    them."""
    import automated_security_helper.plugin_modules as plugin_modules
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    # Building a uv-tool plugin asks uv for the installed version: keep that off
    # the network. The uv directories need no setting here: _private_home already
    # points them into this process's home, the one convention for in-process uv
    # reads in this file (_ash_environment carries the same shape to children).
    monkeypatch.setenv("UV_OFFLINE", "1")
    context = PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "output" / "converted",
        config=AshConfig(project_name="page-claims"),
    )
    found = []
    for module_info in pkgutil.iter_modules(plugin_modules.__path__):
        module = importlib.import_module(
            f"{plugin_modules.__name__}.{module_info.name}"
        )
        for plugin in getattr(module, attribute, []):
            found.append((module_info.name, plugin(context=context)))
    return found


def _uv_package(spec: str) -> str:
    """The package of a uv requirement such as ``bandit[sarif,toml]>=1.7.0,<2.0.0``."""
    return re.split(r"[\[<>=!~ ]", spec, maxsplit=1)[0]


def _uv_installed_package(argv: List[str]) -> str:
    """The package a ``uv tool install`` command installs, past its options."""
    words = iter(argv[3:])
    for word in words:
        if word in ("--python", "-p"):
            next(words, None)
        elif not word.startswith("-"):
            return _uv_package(word)
    raise AssertionError(f"no package in {argv}")


def _uv_documented_names() -> Set[str]:
    """Every plugin and uv package the generated scanner and converter references name.

    A tool a page lists is recognized from these whether or not the code under test
    has it, so a scanner missing from the code is a difference and not a skipped word.
    """
    names: Set[str] = set()
    for page in ("reference/scanners.md", "reference/converters.md"):
        text = _page_text(page)
        names |= set(re.findall(r"^\| \[`([\w-]+)`\]\(#", text, flags=re.MULTILINE))
        names |= {
            _uv_package(spec)
            for spec in re.findall(r"`uv tool install` on first use \(`([^`]+)`", text)
        }
    return names


def _uv_listed(sentence: str, names: Set[str]) -> Set[str]:
    return {w for w in re.findall(r"[a-z][a-z0-9-]*[a-z0-9]", sentence) if w in names}


@pytest.mark.unit
def test_the_pages_list_the_tools_ash_installs_with_uv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """install.md (Install with pipx; Install with pip; Uninstall), index.md (Connect an
    AI agent), advanced-usage.md (How ASH gets each tool;
    Install tools with ``ash dependencies install``; Installs during a scan; uv
    settings), scanning-untrusted-code.md (What leaves the machine during a scan) and
    github-actions.md (Inputs of run-ash-security-scan.yml).

    Each built-in scanner and converter is built with its default config, and the
    packages of the ``uv tool install`` commands it gives ``ash dependencies install``
    are its uv tools. A scanner list must name exactly the built-in scanners that have
    one; a list with nbconvert must name every package. A page's names are read against
    the generated scanner and converter references as well as the code, so a scanner the
    code lacks counts. The control is that the code installs at least one scanner with
    uv and that each sentence lists at least three names.
    """
    for page, sentence in _UV_SCANNER_SENTENCES + _UV_TOOL_SENTENCES:
        assert_on_page(page, sentence)
    from automated_security_helper.cli.dependencies import (
        get_architecture,
        get_platform,
    )

    uv: Dict[str, str] = {}
    names = _uv_documented_names()
    for attribute in ("ASH_SCANNERS", "ASH_CONVERTERS"):
        for module, plugin in _instantiated_plugins(tmp_path, monkeypatch, attribute):
            if module != "ash_builtin":
                continue
            names.add(plugin.config.name)
            for argv in plugin.get_installation_commands(
                get_platform(), get_architecture()
            ):
                if list(argv[:3]) == ["uv", "tool", "install"]:
                    uv[_uv_installed_package(list(argv))] = plugin.config.name
    names |= set(uv)
    scanners = {package for package, plugin in uv.items() if package == plugin}
    assert scanners, "no built-in scanner installs with uv: the probe found nothing"
    for page, sentence in _UV_SCANNER_SENTENCES:
        listed = _uv_listed(sentence, names)
        assert len(listed) >= 3, (page, listed)
        assert listed == scanners, (
            f"{page} lists {sorted(listed)}; the built-in scanners that install with "
            f"uv are {sorted(scanners)}"
        )
    for page, sentence in _UV_TOOL_SENTENCES:
        listed = _uv_listed(sentence, names)
        assert listed == set(uv), (
            f"{page} lists {sorted(listed)}; ASH's built-in plugins install "
            f"{sorted(uv)} with uv"
        )


# --------------------------------------------------------------------------- #
# Where ASH looks for a tool: only an executable file counts
# --------------------------------------------------------------------------- #

ADVANCED_USAGE = "docs/advanced-usage.md"
OTHER_CI = "how-to/ci/other-ci.md"

_ONLY_AN_EXECUTABLE_COUNTS = (
    "Only an executable file counts. In each of these directories, a file of the "
    "tool's name without the execute bit, or a directory of that name, is skipped and "
    "the search goes on; on Windows, the name's suffix decides instead."
)
_ASH_REMEMBERS_EACH_ANSWER = (
    "ASH remembers a path it finds, for the current `PATH` and `ASH_BIN_PATH`, and "
    "looks again when either changes, or when that file has been removed or has lost "
    "its execute bit."
)
_A_MISS_IS_LOOKED_FOR_AGAIN = (
    "A tool it does not find is looked for again on every lookup, so one installed "
    "after a lookup missed it is found by the next."
)
_A_UV_RUN_TOOL_KEEPS_ITS_FILE = (
    "For a tool ASH runs with `uv tool run`, such as bandit, the file found first, "
    "`uv` or the tool's own program, stays the one used: when it is removed, ASH logs "
    "an error naming it and counts the tool as missing, and looks for another copy "
    "only when `PATH` or `ASH_BIN_PATH` changes."
)
_RESTORE_THE_EXECUTE_BITS = (
    "Restore the cache with the files' execute bits: `ash dependencies install` "
    "downloads a binary there again if it has lost its execute bit, and a scan run "
    "without that step skips it."
)


def _unique_tool() -> str:
    """A tool name no directory on this host holds, and no earlier lookup in this
    process asked for, so ASH has no answer remembered for it."""
    return f"page-claims-tool-{uuid.uuid4().hex[:12]}"


def _place_tool(directory: Path, name: str, kind: str) -> Path:
    """``directory``/``name`` as ``kind``: an executable file (``exec``), a file
    without the execute bit (``noexec``), or a directory (``dir``). On Windows the
    name gets ``.exe``, the suffix that makes it a candidate there."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (f"{name}.exe" if os.name == "nt" else name)
    if kind == "dir":
        path.mkdir()
        return path
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755 if kind == "exec" else 0o644)
    return path


def _same_file(found: Optional[str], expected: Optional[Path]) -> bool:
    if found is None or expected is None:
        return found is None and expected is None
    return os.path.normcase(os.path.abspath(found)) == os.path.normcase(
        os.path.abspath(expected)
    )


@pytest.mark.parametrize(
    "layout",
    [
        pytest.param(
            [("path-1", "noexec"), ("path-2", "exec")],
            id="a-path-file-without-the-execute-bit",
        ),
        pytest.param(
            [("path-1", "dir"), ("path-2", "exec")], id="a-path-directory-of-that-name"
        ),
        pytest.param(
            [("path-1", "noexec"), ("bin", "exec")],
            id="the-search-goes-on-from-path-to-ash-bin-path",
        ),
        pytest.param([("bin", "noexec")], id="an-ash-bin-path-file-without-the-bit"),
        pytest.param([("bin", "dir")], id="an-ash-bin-path-directory-of-that-name"),
        pytest.param([("bin", "exec")], id="control-an-executable-in-ash-bin-path"),
    ],
)
@pytest.mark.unit
def test_only_an_executable_file_counts_where_ash_looks_for_a_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: List[Tuple[str, str]]
) -> None:
    """advanced-usage.md (Where ASH looks for a tool).

    A tool no other directory holds is placed, as an executable file, a file without
    the execute bit or a directory of its name, in two directories on ``PATH`` and in
    ``ASH_BIN_PATH``, and ASH's lookup is asked for it. Outside Windows the answer
    must be the first executable file in the page's order, ``PATH`` before
    ``ASH_BIN_PATH``, or none: a file without the bit and a directory are passed
    over. On Windows the suffix decides, so there the answer is the first file of
    that name whatever its mode, and a directory still never counts. The control is
    the executable in ``ASH_BIN_PATH``, found.
    """
    assert_on_page(ADVANCED_USAGE, _ONLY_AN_EXECUTABLE_COUNTS)
    from automated_security_helper.utils.subprocess_utils import find_executable

    name = _unique_tool()
    placed = {
        where: _place_tool(tmp_path / where, name, kind) for where, kind in layout
    }
    path_dirs = [tmp_path / "path-1", tmp_path / "path-2"]
    for directory in path_dirs:
        directory.mkdir(exist_ok=True)
    monkeypatch.setenv("PATH", os.pathsep.join(str(d) for d in path_dirs))
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    counts = ("exec", "noexec") if os.name == "nt" else ("exec",)
    expected = next((placed[where] for where, kind in layout if kind in counts), None)

    found = find_executable(name)

    assert _same_file(found, expected), f"found {found}, expected {expected}"


@pytest.mark.parametrize(
    "change",
    [
        "control-nothing-changes",
        "ash-bin-path-changes",
        "path-changes",
        "the-file-is-removed",
        "the-file-loses-its-execute-bit",
    ],
)
@pytest.mark.unit
def test_ash_remembers_a_tool_for_path_and_ash_bin_path_and_looks_again_when_they_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """advanced-usage.md (Where ASH looks for a tool).

    ASH's lookup finds a tool in ``ASH_BIN_PATH``, with nothing of its name on
    ``PATH``. Then one thing changes and it is asked again. With nothing changed but
    an executable of the name added to the directory on ``PATH``, which would come
    first in a fresh search, it must give the remembered answer: the control that
    answers are remembered. With ``ASH_BIN_PATH`` naming another directory that holds
    the tool, or ``PATH`` naming one, it must answer from there. With the file
    removed, or its execute bit taken away, it must find nothing. On Windows there is
    no execute bit, so there the file that lost it is still found.
    """
    assert_on_page(ADVANCED_USAGE, _ASH_REMEMBERS_EACH_ANSWER)
    from automated_security_helper.utils.subprocess_utils import find_executable

    name = _unique_tool()
    first = _place_tool(tmp_path / "bin", name, "exec")
    (tmp_path / "path-1").mkdir()
    monkeypatch.setenv("PATH", str(tmp_path / "path-1"))
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    found = find_executable(name)
    assert _same_file(found, first), f"the first lookup found {found}"

    expected: Optional[Path]
    if change == "control-nothing-changes":
        _place_tool(tmp_path / "path-1", name, "exec")
        expected = first
    elif change == "ash-bin-path-changes":
        expected = _place_tool(tmp_path / "bin-2", name, "exec")
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin-2"))
    elif change == "path-changes":
        expected = _place_tool(tmp_path / "path-2", name, "exec")
        monkeypatch.setenv("PATH", str(tmp_path / "path-2"))
    elif change == "the-file-is-removed":
        first.unlink()
        expected = None
    else:
        first.chmod(0o644)
        expected = first if os.name == "nt" else None

    found = find_executable(name)

    assert _same_file(found, expected), (
        f"after {change}: found {found}, expected {expected}"
    )


@pytest.mark.parametrize(
    "installed",
    [True, False],
    ids=["installed-after-the-miss", "control-not-installed"],
)
@pytest.mark.unit
def test_ash_looks_again_for_a_tool_it_did_not_find(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, installed: bool
) -> None:
    """advanced-usage.md (Where ASH looks for a tool).

    ASH's lookup is asked for a tool that neither ``PATH`` nor ``ASH_BIN_PATH`` holds,
    and finds nothing. Then the tool is installed into ``ASH_BIN_PATH``, with nothing
    else changed and no cache cleared, and it is asked again: it must find the tool,
    so the miss was not remembered. The control installs nothing, and the second
    lookup must find nothing either.
    """
    assert_on_page(ADVANCED_USAGE, _A_MISS_IS_LOOKED_FOR_AGAIN)
    from automated_security_helper.utils.subprocess_utils import find_executable

    name = _unique_tool()
    for directory in ("path-1", "bin"):
        (tmp_path / directory).mkdir()
    monkeypatch.setenv("PATH", str(tmp_path / "path-1"))
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    assert find_executable(name) is None, "the first lookup found a tool not placed"

    expected = _place_tool(tmp_path / "bin", name, "exec") if installed else None
    found = find_executable(name)

    assert _same_file(found, expected), f"found {found}, expected {expected}"


def _place_stand_in(directory: Path, name: str) -> Path:
    """A program ``name`` in ``directory`` that exits 0 whatever it is given: a shell
    script with the execute bit, and on Windows ``name.cmd``, which the lookup takes
    for ``name`` by its suffix and which Windows runs through cmd.exe."""
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        path = directory / f"{name}.cmd"
        path.write_text("@exit /b 0\n", encoding="utf-8")
        return path
    path = directory / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _normcase_names(message: str, path: Path) -> bool:
    """Whether ``message`` names ``path``, compared as the platform compares paths."""
    return os.path.normcase(str(path)) in os.path.normcase(message)


@pytest.mark.parametrize(
    "change",
    [
        "control-nothing-changes",
        "uv-removed",
        "uv-removed-and-path-changes",
        "own-program-removed",
    ],
)
@pytest.mark.unit
def test_a_uv_run_tool_keeps_the_file_it_found_first(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ash_log: List[logging.LogRecord],
    change: str,
) -> None:
    """advanced-usage.md (Where ASH looks for a tool).

    A stand-in ``uv`` on ``PATH`` passes the version check, so ASH answers that a
    tool runs with ``uv tool run``. With nothing changed it must give that answer
    again: the control. With that ``uv`` removed and another placed in
    ``ASH_BIN_PATH``, where a fresh search would find it, ASH must answer that the
    tool cannot run and log an error naming the removed file. With ``PATH`` then
    naming a directory that holds another ``uv``, it must run the tool again, with
    that ``uv``: removing it too must make the tool unable to run. With no ``uv``
    and the tool's own program on ``PATH``, ASH runs that program, and
    once it is removed, with another copy in ``ASH_BIN_PATH``, the same holds.
    The stand-ins are shell scripts, and ``.cmd`` files on Windows.
    """
    assert_on_page(ADVANCED_USAGE, _A_UV_RUN_TOOL_KEEPS_ITS_FILE)
    from automated_security_helper.utils import uv_tool_runner
    from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command

    # The lookup under test is PATH and ASH_BIN_PATH, which the test owns. A build
    # that ships its own uv beside the interpreter would answer from there instead,
    # and probe the tool with the real uv; so would a lookup that searches the
    # interpreter's own directory whatever PATH says. Each pin is applied where the
    # build has the symbol, records its calls, and is asserted consulted below
    # where this cell's lookups must reach it: a pin that silently stopped being
    # read would otherwise leave the real lookup in play, which is what it exists
    # to prevent.
    from automated_security_helper.utils import subprocess_utils

    pins_consulted: Set[str] = set()

    def _pinned_bundled_uv() -> None:
        pins_consulted.add("bundled")
        return None

    def _pinned_own_dirs() -> List[Path]:
        pins_consulted.add("own-dirs")
        return []

    bundled_pinned = hasattr(uv_tool_runner, "bundled_uv_executable")
    if bundled_pinned:
        monkeypatch.setattr(uv_tool_runner, "bundled_uv_executable", _pinned_bundled_uv)
    own_dirs_pinned = hasattr(subprocess_utils, "own_environment_dirs")
    if own_dirs_pinned:
        monkeypatch.setattr(subprocess_utils, "own_environment_dirs", _pinned_own_dirs)
    # A build that renamed one lookup seam but kept the other is drift this cell
    # must not paper over: with a uv beside the interpreter, the now-unpinned
    # seam would answer for real while the consulted checks below stay quiet. A
    # build with neither symbol never had these seams (the code tiers differ
    # here, and one ships a uv in its venv), and there the asserts below are
    # the net: after a removal the command must be None, which a uv answering
    # from beside the interpreter breaks loudly.
    if bundled_pinned != own_dirs_pinned:
        beside_interpreter = os.pathsep.join(
            {str(Path(sys.executable).parent), sysconfig.get_path("scripts")}
        )
        shipped = shutil.which("uv", path=beside_interpreter)
        assert shipped is None, (
            f"one pin point is gone (bundled={bundled_pinned}, "
            f"own-dirs={own_dirs_pinned}) and this build ships uv at {shipped}: "
            "re-point the pins at the renamed lookup"
        )

    name = _unique_tool()
    own = change == "own-program-removed"
    stem = name if own else "uv"
    first = _place_stand_in(tmp_path / "path-1", stem)
    (tmp_path / "bin").mkdir()
    monkeypatch.setenv("PATH", str(tmp_path / "path-1"))
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))

    def runs(command: Optional[List[str]]) -> bool:
        """Whether ``command`` runs the tool: its own program, or through uv."""
        if own:
            return (
                command is not None
                and len(command) == 1
                and _same_file(command[0], first)
            )
        return command == ["uv", "tool", "run", name]

    assert runs(get_uv_tool_command(name)), "the stand-in was not taken"
    # The consulted checks: this lookup always asks for the bundled uv first, and
    # with no uv on PATH (the own-program case) it reaches the interpreter's own
    # directories. A pin these lookups no longer read is a silent miss.
    if bundled_pinned:
        assert "bundled" in pins_consulted, "the bundled-uv pin was not consulted"
    if own_dirs_pinned and own:
        assert "own-dirs" in pins_consulted, "the own-directories pin was not consulted"

    expected_to_run = True
    if change != "control-nothing-changes":
        first.unlink()
        _place_stand_in(tmp_path / "bin", stem)
        expected_to_run = False
    if change == "uv-removed-and-path-changes":
        second = _place_stand_in(tmp_path / "path-2", "uv")
        monkeypatch.setenv("PATH", str(tmp_path / "path-2"))
        expected_to_run = True

    command = get_uv_tool_command(name)

    if expected_to_run:
        assert runs(command), f"after {change}: {command} does not run the tool"
    else:
        assert command is None, f"after {change}: {command}, expected None"
    errors = _messages(r for r in ash_log if r.levelno >= logging.ERROR)
    named = [m for m in errors if _normcase_names(m, first)]
    if change == "uv-removed-and-path-changes":
        # The command found for the new PATH starts path-2's uv: without it, the
        # tool cannot run either.
        second.unlink()
        assert get_uv_tool_command(name) is None, (
            "the command did not start path-2's uv"
        )
        errors = _messages(r for r in ash_log if r.levelno >= logging.ERROR)
        assert [m for m in errors if _normcase_names(m, second)], (
            f"no error named {second}"
        )
    if not expected_to_run:
        assert named, f"no error named {first}: {_messages(ash_log)}"
    else:
        assert not named, f"an error named {first}: {named}"


@pytest.mark.parametrize(
    "mode", ["lost-its-execute-bit", "control-executable"], ids=lambda mode: mode
)
@pytest.mark.unit
def test_dependencies_install_downloads_a_binary_again_that_lost_its_execute_bit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    """other-ci.md (Local mode).

    A pinned tool's binary is in ``ASH_BIN_PATH``, its bytes those the pin names, with
    or without its execute bit. ``ash dependencies install`` asks, before it runs a
    pinned install, whether the binary there is already the pinned one, and skips
    the download only when it is. Without the execute bit the answer must be no, so
    it downloads the binary again, and the lookup a scan makes for the tool must not
    answer that file, so a scan skips it. The control is the same binary executable:
    the install is skipped and a scan finds the file.

    The test cannot hold a pinned release binary, so the tool's pinned digest is
    replaced by the digest of a stand-in file; everything else is the real pinned
    asset of the first downloadable tool with an executable digest. On Windows there
    is no execute bit, so both cases must find the file.
    """
    assert_on_page(OTHER_CI, _RESTORE_THE_EXECUTE_BITS)
    from automated_security_helper.cli.dependencies import (
        get_architecture,
        get_platform,
    )
    from automated_security_helper.utils import download_utils, tool_downloads
    from automated_security_helper.utils.subprocess_utils import (
        find_executable_for_scan,
    )

    target, arch = get_platform(), get_architecture()
    real = None
    for tool in tool_downloads.downloadable_tools():
        try:
            asset = tool_downloads.get_tool_asset(tool, target, arch)
        except tool_downloads.ToolNotProvisionableError:
            continue
        if asset.executable_digest is not None:
            real = asset
            break
    assert real is not None, f"no pinned tool with an executable digest on {target}"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    binary = bin_dir / real.install_as
    binary.write_bytes(b"#!/bin/sh\nexit 0\n")
    binary.chmod(0o755 if mode == "control-executable" else 0o644)
    stand_in = dataclasses.replace(
        real, executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest()
    )
    monkeypatch.setattr(
        tool_downloads,
        "get_tool_asset",
        lambda tool, platform_, arch_: stand_in if tool == real.tool else None,
    )
    (tmp_path / "path").mkdir()
    (tmp_path / "tree").mkdir()
    monkeypatch.setenv("PATH", str(tmp_path / "path"))
    monkeypatch.setenv("ASH_BIN_PATH", str(bin_dir))
    install = download_utils.create_pinned_tool_install_command(
        real.tool, target, arch, str(bin_dir)
    )

    present = download_utils.pinned_install_already_satisfied(list(install.args))
    looked_up = find_executable_for_scan(real.tool, tmp_path / "tree")

    kept = mode == "control-executable" or os.name == "nt"
    if kept:
        assert present is not None and Path(present.path) == binary, present
        assert _same_file(looked_up, binary), looked_up
    else:
        assert present is None, (
            f"{binary} has no execute bit, and was taken as installed: {present}"
        )
        assert looked_up is None or not _same_file(looked_up, binary), looked_up


TRIVY_PLUGIN = "docs/plugins/community/trivy-plugin.md"


@pytest.mark.parametrize(
    "layout",
    [
        pytest.param(
            [("path-1", "noexec"), ("path-2", "exec")],
            id="a-trivy-without-the-bit-first-on-path",
        ),
        pytest.param([("bin", "noexec")], id="a-trivy-without-the-bit-in-ash-bin-path"),
        pytest.param([("bin", "exec")], id="control-an-executable-trivy"),
    ],
)
@pytest.mark.unit
def test_trivy_repo_counts_only_an_executable_trivy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: List[Tuple[str, str]]
) -> None:
    """trivy-plugin.md (the tool search).

    ``trivy`` is placed on ``PATH`` and in ``ASH_BIN_PATH`` as an executable file or a
    file without the execute bit, and the trivy-repo scanner, built as a scan builds
    it, checks its dependency. The lookup it makes must not answer a file without the
    bit: with an executable after it on ``PATH``, it must answer that one and the
    check pass; with only the file without the bit, it must answer another trivy the
    host has, or none, and the check must agree. On Windows the suffix decides, so
    there ``trivy.exe`` counts whatever its mode. The control is the executable
    ``trivy`` in ``ASH_BIN_PATH``, found.
    """
    assert_on_page(
        TRIVY_PLUGIN,
        "Only an executable file counts ([Where ASH looks for a tool]"
        "(../../advanced-usage.md#where-ash-looks-for-a-tool)).",
    )
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScanner,
    )
    from automated_security_helper.utils.subprocess_utils import find_executable

    placed = {
        where: _place_tool(tmp_path / where, "trivy", kind) for where, kind in layout
    }
    path_dirs = [tmp_path / "path-1", tmp_path / "path-2"]
    for directory in path_dirs:
        directory.mkdir(exist_ok=True)
    monkeypatch.setenv("PATH", os.pathsep.join(str(d) for d in path_dirs))
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    scanner = TrivyRepoScanner(
        context=PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "output",
            work_dir=tmp_path / "output" / "converted",
            config=AshConfig(project_name="page-claims"),
        )
    )

    satisfied = scanner.validate_plugin_dependencies()
    found = find_executable("trivy")

    counts = ("exec", "noexec") if os.name == "nt" else ("exec",)
    expected = next((placed[where] for where, kind in layout if kind in counts), None)
    if expected is not None:
        assert _same_file(found, expected), f"found {found}, expected {expected}"
    else:
        skipped = [placed[where] for where, _kind in layout]
        assert not any(_same_file(found, path) for path in skipped), found
    assert satisfied is (found is not None), (satisfied, found)


# --------------------------------------------------------------------------- #
# Suppression paths that name a directory
# --------------------------------------------------------------------------- #

SUPPRESSIONS_CONCEPT = "concepts/suppressions.md"
SUPPRESS_FINDINGS = "how-to/suppress-findings.md"

_A_SUPPRESSION_SLASH_IS_LITERAL = (
    "A trailing slash is literal, unlike in an ignore path, so `tests/` matches no "
    "finding, and neither does a bare directory name such as `tests`; `tests/**/*` "
    "matches the files below the directory."
)
_THE_SCAN_WARNS_ABOUT_A_SLASH = (
    "A trailing slash is literal, unlike in an ignore path: `tests/` matches no "
    "finding, and the scan warns that it matched nothing and gives `tests/**/*`, the "
    "pattern for the files under the directory."
)
_CHECKS_REPORT_A_DIRECTORY = (
    "When the directory exists in the scanned directory, `ash config validate` and "
    "`ash config lint` warn about either one with that pattern and exit 0."
)
_VALIDATE_ROW_ON_A_DIRECTORY = (
    "An ignore path that names an existing directory with neither a trailing `/` nor "
    "`**`, and a suppression path that names one without `**`, are warnings too, since "
    "a scan accepts them; the warning gives the pattern for every file inside, "
    "`<dir>/` for an ignore path and `<dir>/**/*` for a suppression path"
)
#: configure.md (Check a config): the directory the checks judge a config against.
_CHECKS_USE_THE_SOURCE_DIR = (
    "`--source-dir` (or `ASH_SOURCE_DIR`; by default the current directory) for the "
    "directory a scan would scan. An `ASH_CONFIG` that names a file that does not exist "
    "makes each of them exit 3, also beside a `--config` file that loads, as it stops a "
    "scan. Each finds the config there and holds its `extends` "
    "chain to the bounds a scan of that directory sets ([Share settings with "
    "`extends`](#extends)), and `validate` and `lint` match ignore and suppression "
    "paths against it."
)


def _suppressed_by_file(output: Path) -> Dict[str, bool]:
    """{file: whether its findings are all suppressed} from a scan's ``ash.sarif``."""
    sarif = json.loads((output / "reports" / "ash.sarif").read_text(encoding="utf-8"))
    found: Dict[str, List[bool]] = {}
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            location = result["locations"][0]["physicalLocation"]["artifactLocation"]
            name = Path(location["uri"]).as_posix()
            found.setdefault(name, []).append(bool(result.get("suppressions")))
    return {name: all(flags) for name, flags in found.items()}


@pytest.mark.integration
def test_a_suppression_path_ending_in_a_slash_suppresses_nothing_and_the_scan_says_so(
    tmp_path: Path,
) -> None:
    """suppressions.md (How a suppression matches), and suppress-findings.md.

    A tree with a hardcoded password in ``build/app.py``, ``lib/app.py`` and
    ``tests/app.py`` is scanned with three suppressions: ``build/``, ``lib/**`` and
    ``tests/**/*``. The finding in ``build/`` must be reported unsuppressed, and the
    scan must warn that the suppression with path ``build/`` matched no finding and
    give ``build/**/*``. The control is the other two, which suppress their findings,
    and no such warning for them.
    """
    assert_on_page(SUPPRESSIONS_CONCEPT, _A_SUPPRESSION_SLASH_IS_LITERAL)
    assert_on_page(SUPPRESS_FINDINGS, _THE_SCAN_WARNS_ABOUT_A_SLASH)
    tree = _config_scan_tree(
        tmp_path,
        {f"{name}/app.py": _CONFIG_SECRET for name in ("build", "lib", "tests")},
    )
    (tree / ".ash").mkdir()
    (tree / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(
            {
                "project_name": "page-claims",
                "global_settings": {
                    "suppressions": [
                        {"path": path, "reason": "page claims"}
                        for path in ("build/", "lib/**", "tests/**/*")
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "output"
    result = _ash(
        [
            *_CONFIG_SCAN,
            "--offline",
            "--source-dir",
            str(tree),
            "--output-dir",
            str(output),
        ],
        cwd=tmp_path,
    )
    text = _squeezed(result.stdout + result.stderr + _config_scan_log(tree))
    log = output / "ash.log"
    text += (
        _squeezed(log.read_text(encoding="utf-8", errors="replace"))
        if log.is_file()
        else ""
    )

    suppressed = _suppressed_by_file(output)
    assert suppressed.get("build/app.py") is False, (suppressed, _output_tail(result))
    assert suppressed.get("lib/app.py") is True, suppressed
    assert suppressed.get("tests/app.py") is True, suppressed
    warning = (
        "The suppression with path 'build/' matched no finding: a suppression path "
        "ending in '/' matches only that literal path"
    )
    assert _squeezed(warning) in text, _output_tail(result)
    assert _squeezed("write 'build/**/*'") in text, _output_tail(result)
    for path in ("lib/**", "tests/**/*"):
        assert _squeezed(f"The suppression with path '{path}'") not in text


@pytest.mark.parametrize("command", ["validate", "lint"])
@pytest.mark.parametrize(
    "paths, errors",
    [
        pytest.param(
            ("vendor", "tests", "build/"),
            ["Use 'vendor/'", "Use 'tests/**/*'", "Use 'build/**/*'"],
            id="each-names-an-existing-directory",
        ),
        pytest.param(
            ("vendor/", "tests/**/*", "build/**/*"),
            [],
            id="control-each-names-its-files",
        ),
    ],
)
@pytest.mark.integration
def test_config_checks_warn_and_exit_0_on_a_path_that_names_an_existing_directory(
    tmp_path: Path, command: str, paths: Tuple[str, str, str], errors: List[str]
) -> None:
    """configure.md (Check a config), suppress-findings.md, and exit-codes.md.

    A repository has the directories ``vendor``, ``tests`` and ``build``, and its config
    ignores the first and suppresses the other two. Written ``vendor``, ``tests`` and
    ``build/``, ``ash config validate`` and ``ash config lint`` must exit 0 and give
    each path's pattern as a warning: ``vendor/`` for the ignore path, ``tests/**/*``
    and ``build/**/*`` for the suppression paths. The control is the same config
    written with those patterns, which both commands accept with exit 0 and no such
    warning.
    """
    assert_on_page(CONFIGURE, _VALIDATE_ROW_ON_A_DIRECTORY)
    assert_on_page(SUPPRESS_FINDINGS, _CHECKS_REPORT_A_DIRECTORY)
    assert_on_page(
        EXIT_CODES,
        "or for an ignore or suppression path that names an existing directory and "
        "matches no file in it ([Check a config](../how-to/configure.md#check)). |",
    )
    ignored, *suppressed = paths
    tree = _config_scan_tree(
        tmp_path, {f"{name}/app.py": "x = 1\n" for name in ("vendor", "tests", "build")}
    )
    (tree / ".ash").mkdir()
    (tree / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(
            {
                "project_name": "page-claims",
                "global_settings": {
                    "ignore_paths": [{"path": ignored, "reason": "page claims"}],
                    "suppressions": [
                        {"path": path, "reason": "page claims"} for path in suppressed
                    ],
                },
            }
        ),
        encoding="utf-8",
    )

    result = _ash(["config", command], cwd=tree)
    text = _squeezed(result.stdout + result.stderr)

    assert result.returncode == 0, _output_tail(result)
    for advice in errors:
        assert _squeezed(advice) in text, _output_tail(result)
    if not errors:
        assert "pointstoadirectory" not in text, _output_tail(result)


#: suppressions.md (How a suppression matches) and suppress-findings.md on how a
#: suppression path matches.
_SUPPRESSION_PATHS_MATCH_CASE_SENSITIVELY = [
    (
        SUPPRESSIONS_CONCEPT,
        (
            "Paths are matched relative to the scanned directory and case-sensitively, "
            "so `tests/**` does not match `Tests/`, and a path that starts with `./` "
            "matches nothing."
        ),
    ),
    (
        SUPPRESS_FINDINGS,
        "Paths match case-sensitively: `tests/**` does not match `Tests/`.",
    ),
    (
        SUPPRESS_FINDINGS,
        (
            "A path that starts with `./` matches nothing, and neither does an empty "
            "path, `.` or `./`."
        ),
    ),
]


@pytest.mark.parametrize(
    "path, suppresses",
    [
        pytest.param("tests/**", False, id="another-case"),
        pytest.param("./Tests/secret.py", False, id="a-leading-dot-slash"),
        pytest.param("", False, id="empty"),
        pytest.param(".", False, id="a-dot"),
        pytest.param("./", False, id="a-dot-slash"),
        pytest.param("Tests/**", True, id="control-the-same-case"),
        pytest.param("Tests/secret.py", True, id="control-the-file-as-named"),
    ],
)
@pytest.mark.integration
def test_a_suppression_path_matches_case_sensitively_and_not_with_a_leading_dot(
    tmp_path: Path, path: str, suppresses: bool
) -> None:
    """suppressions.md (How a suppression matches) and suppress-findings.md.

    A tree with a hardcoded password in ``Tests/secret.py`` is scanned with one
    suppression. ``tests/**`` (another case), ``./Tests/secret.py``, an empty path,
    ``.`` and ``./`` must leave the finding unsuppressed. The controls, ``Tests/**``
    and ``Tests/secret.py``, must suppress it.
    """
    for page, sentence in _SUPPRESSION_PATHS_MATCH_CASE_SENSITIVELY:
        assert_on_page(page, sentence)
    tree = _config_scan_tree(tmp_path, {"Tests/secret.py": _CONFIG_SECRET})
    (tree / ".ash").mkdir()
    (tree / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(
            {
                "project_name": "page-claims",
                "global_settings": {
                    "suppressions": [{"path": path, "reason": "page claims"}]
                },
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "output"
    result = _ash(
        [
            *_CONFIG_SCAN,
            "--offline",
            "--source-dir",
            str(tree),
            "--output-dir",
            str(output),
        ],
        cwd=tmp_path,
    )

    suppressed = _suppressed_by_file(output)
    assert suppressed.get("Tests/secret.py") is suppresses, (
        suppressed,
        _output_tail(result),
    )


#: suppress-findings.md and configure.md's validate row (Check a config) on the
#: warnings for a path that matches nothing.
_CHECKS_WARN_ABOUT_A_PATH_THAT_MATCHES_NOTHING = [
    (
        SUPPRESS_FINDINGS,
        (
            "They warn in the same way, saying what to write instead, about a path that "
            "starts with `./` (`./src/app.py` is `src/app.py`) and about an empty path or "
            "`.`. A path whose leading names match the tree only in another case "
            "(`tests/**` against `Tests/`) gets a warning that names the tree's spelling "
            "and says that patterns match case-sensitively."
        ),
    ),
    (
        CONFIGURE,
        (
            "So is a path that matches nothing because it starts with `./` (`./src` is "
            "`src/`) or is empty or `.`, and the warning says what to write instead. A "
            "path that matches the tree only in another case (`tests/**` against "
            "`Tests/`) gets a warning that names the tree's spelling and says that "
            "patterns match case-sensitively"
        ),
    ),
]


@pytest.mark.parametrize("command", ["validate", "lint"])
@pytest.mark.parametrize(
    "setting, path, advice",
    [
        pytest.param(
            "suppressions", "./src/app.py", "'src/app.py'", id="sup-dot-slash"
        ),
        pytest.param("suppressions", "", None, id="sup-empty"),
        pytest.param("suppressions", ".", None, id="sup-dot"),
        pytest.param("suppressions", "tests/**", "'Tests/'", id="sup-another-case"),
        pytest.param("ignore_paths", "./src", "'src/'", id="ignore-dot-slash"),
        pytest.param("ignore_paths", "", None, id="ignore-empty"),
        pytest.param("ignore_paths", ".", None, id="ignore-dot"),
        pytest.param("ignore_paths", "tests/**", "'Tests/'", id="ignore-another-case"),
        pytest.param("suppressions", "Tests/**", "", id="control-sup-same-case"),
        pytest.param("ignore_paths", "src/**", "", id="control-ignore-a-glob"),
    ],
)
@pytest.mark.integration
def test_config_checks_warn_and_exit_0_on_a_path_that_matches_nothing(
    tmp_path: Path, command: str, setting: str, path: str, advice: Optional[str]
) -> None:
    """suppress-findings.md and configure.md (Check a config).

    A repository has ``src/app.py`` and ``Tests/secret.py``, and its config has one
    ignore or suppression path. For ``./src/app.py``, ``./src``, an empty path, ``.``
    and ``tests/**`` (the tree has ``Tests/``), ``ash config validate`` and ``ash
    config lint`` must exit 0 with a warning that names the path, and say what to
    write instead as far as the pages give it: the path without ``./``, and the name
    the tree has in its own case. The controls, ``Tests/**`` and ``src/**``, give no
    such warning.
    """
    for page, sentence in _CHECKS_WARN_ABOUT_A_PATH_THAT_MATCHES_NOTHING:
        assert_on_page(page, sentence)
    tree = _config_scan_tree(
        tmp_path, {"src/app.py": "x = 1\n", "Tests/secret.py": "x = 1\n"}
    )
    (tree / ".ash").mkdir()
    (tree / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(
            {
                "project_name": "page-claims",
                "global_settings": {setting: [{"path": path, "reason": "page claims"}]},
            }
        ),
        encoding="utf-8",
    )

    result = _ash(["config", command], cwd=tree)
    text = _squeezed(result.stdout + result.stderr)

    assert result.returncode == 0, _output_tail(result)
    if advice == "":
        assert _squeezed("Path '") not in text, _output_tail(result)
        return
    warning = text.split(_squeezed(f"Path '{path}'"), 1)
    assert len(warning) == 2, _output_tail(result)
    if advice is not None:
        assert _squeezed(advice) in warning[1][:300], _output_tail(result)


def _source_dir_tree(parent: Path) -> Dict[str, Path]:
    """Directories for the --source-dir checks.

    ``repo`` holds a discovered config and a ``vendor`` directory; ``bounded`` holds a
    config in ``config/`` whose base is in ``shared/``, beside it; ``plain`` has no
    config and no ``vendor``; ``operator`` holds a config outside every repository
    that ignores ``vendor`` and has a ``vendor`` directory of its own; ``elsewhere``
    is an empty working directory.
    """
    paths = {
        name: parent / name
        for name in ("repo", "bounded", "plain", "operator", "elsewhere")
    }
    files = {
        "repo/.ash/.ash.yaml": "project_name: demo\n",
        "repo/vendor/a.txt": "x\n",
        "bounded/config/ash.yaml": "extends: ../shared/base.yaml\nproject_name: demo\n",
        "bounded/shared/base.yaml": "fail_on_findings: false\n",
        "plain/app.py": "x = 1\n",
        "operator/op.yaml": "project_name: demo\nglobal_settings:\n  ignore_paths:\n"
        "    - path: vendor\n      reason: page claims\n",
        "operator/vendor/a.txt": "x\n",
        "elsewhere/.keep": "",
    }
    for name, text in files.items():
        (parent / name).parent.mkdir(parents=True, exist_ok=True)
        (parent / name).write_text(text, encoding="utf-8")
    return paths


@pytest.mark.parametrize("command", ["validate", "lint", "get"])
@pytest.mark.integration
def test_config_checks_judge_a_config_against_the_source_dir(
    tmp_path: Path, command: str
) -> None:
    """configure.md (Check a config).

    From an empty working directory, each check must find ``repo``'s config when
    ``--source-dir`` or ``ASH_SOURCE_DIR`` names ``repo``, and no config without
    either (validate and lint exit 1 for that; get prints the defaults). A config in
    ``bounded/config/`` whose base is in ``bounded/shared/`` is inside the scanned
    directory with ``--source-dir bounded`` and loads, while from ``elsewhere`` it is
    outside it and its base is refused (exit 3), as a scan bounds it. validate and lint
    must warn about the operator config's ``vendor`` when the source directory has a
    ``vendor`` directory and not when only the config's own directory has one.
    """
    assert_on_page(CONFIGURE, _CHECKS_USE_THE_SOURCE_DIR)
    paths = _source_dir_tree(tmp_path)
    elsewhere = paths["elsewhere"]

    def check(*args: str, **env: str) -> subprocess.CompletedProcess:
        return _ash(["config", command, *args], cwd=elsewhere, **env)

    repo_config = (paths["repo"] / ".ash" / ".ash.yaml").as_posix()
    for result in (
        check("--source-dir", str(paths["repo"])),
        check(ASH_SOURCE_DIR=str(paths["repo"])),
    ):
        assert result.returncode == 0, _output_tail(result)
        if command == "get":
            assert "project_name: demo" in result.stdout, _output_tail(result)
        else:
            assert repo_config in result.stdout + result.stderr, _output_tail(result)

    control = check()
    if command == "get":
        assert control.returncode == 0, _output_tail(control)
        assert "project_name: demo" not in control.stdout, _output_tail(control)
    else:
        assert control.returncode == 1, _output_tail(control)
        assert "No config file found" in control.stdout + control.stderr

    bounded = str(paths["bounded"] / "config" / "ash.yaml")
    inside = check("--config", bounded, "--source-dir", str(paths["bounded"]))
    assert inside.returncode == 0, _output_tail(inside)
    outside = check("--config", bounded)
    assert outside.returncode == 3, _output_tail(outside)

    if command == "get":
        return
    operator = str(paths["operator"] / "op.yaml")
    with_vendor = check("--config", operator, "--source-dir", str(paths["repo"]))
    without_vendor = check("--config", operator, "--source-dir", str(paths["plain"]))
    assert with_vendor.returncode == 0, _output_tail(with_vendor)
    assert without_vendor.returncode == 0, _output_tail(without_vendor)
    advice = _squeezed("Path 'vendor' points to a directory but matches no file in it")
    assert advice in _squeezed(with_vendor.stdout + with_vendor.stderr), _output_tail(
        with_vendor
    )
    assert advice not in _squeezed(without_vendor.stdout + without_vendor.stderr), (
        _output_tail(without_vendor)
    )


# --------------------------------------------------------------------------- #
# An output directory reached through a link
# --------------------------------------------------------------------------- #

OUTPUT_FILES = "reference/output-files.md"

#: The pages' rows and sentences on a link at or in the output directory.
_LINKED_OUTPUT_SENTENCES = [
    (
        EXIT_CODES,
        (
            "| 3 | Refused before writing: the output directory, a directory on the way "
            "to it, or a directory or fixed-name file ASH writes in it, such as "
            "`reports` or `ash.log`, is a link ([Output files](output-files.md#links)). "
            "An output directory that is a symlink, or that a symlink below the source "
            "directory leads to, is refused this way in every mode, `--mode container` "
            "(also with `--no-run`) and `--mode nix` included, and before the check that "
            "the directory can be written, so nothing is made and the link's target keeps "
            "its entries. |"
        ),
    ),
    (
        EXIT_CODES,
        (
            "| 1 | A report file a reporter is about to write, such as "
            "`reports/ash.sarif`, is a link ([Output files](output-files.md#links)) |"
        ),
    ),
    (
        EXIT_CODES,
        (
            "| 3 | The output directory, a directory on the way to it, or a directory "
            "ASH writes in it, such as `reports`, is a link ([Output files]"
            "(output-files.md#links)) |"
        ),
    ),
    (
        EXIT_CODES,
        (
            "a report file it is about to write, such as `reports/ash.sarif`, is a link "
            "([Output files](output-files.md#links)) |"
        ),
    ),
    (
        EXIT_CODES,
        (
            "| 3 | The output directory, a directory on the way to it, or `reports` in "
            "it is a link ([Output files](output-files.md#links)) |"
        ),
    ),
    (
        OUTPUT_FILES,
        (
            "The check runs before anything is written or deleted, in every run mode "
            "and whatever the sandbox mode, and also in `ash report` and `ash merge`. "
            "The command exits 3:"
        ),
    ),
    (
        OUTPUT_FILES,
        (
            "In an `ash --workspace` scan, a link at `projects` or `.workspace-spool` "
            "stops the whole run this way before any project starts."
        ),
    ),
    (
        OUTPUT_FILES,
        (
            "This applies to scans in every run mode, including `--use-existing` and "
            "workspace scans, and to `ash merge`."
        ),
    ),
]


def _finished_scan(tmp_path: Path) -> Tuple[Path, Path]:
    """(the tree, the output directory) of a finished scan of a one-file tree."""
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    output = tmp_path / "scan-output"
    result = _ash(
        [
            *_CONFIG_SCAN,
            "--offline",
            "--source-dir",
            str(tree),
            "--output-dir",
            str(output),
        ],
        cwd=tmp_path,
    )
    assert result.returncode == 0, _output_tail(result)
    return tree, output


def _link_into(link: Path, target: Path) -> Path:
    """``link`` made a symbolic link to ``target``, an empty directory or file made
    for it; the target is returned so the test can see nothing was written there."""
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_dir() and not link.is_symlink():
        shutil.rmtree(link)
    elif link.exists() or link.is_symlink():
        link.unlink()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.suffix:
        target.write_bytes(b"")
    else:
        target.mkdir()
    link.symlink_to(target, target_is_directory=not target.suffix)
    return target


def _untouched(target: Path) -> bool:
    if target.is_dir():
        return not any(target.iterdir())
    return target.stat().st_size == 0


@pytest.mark.parametrize(
    "command, link, code",
    [
        pytest.param("scan", "the-output-directory", 3, id="scan-output-directory"),
        pytest.param("scan", ".ash", 3, id="scan-a-linked-dot-ash-on-the-way"),
        pytest.param("scan", "reports", 3, id="scan-reports"),
        pytest.param("scan", "ash.log", 3, id="scan-ash-log"),
        pytest.param("workspace", "projects", 3, id="workspace-projects"),
        pytest.param("merge", "the-output-directory", 3, id="merge-output-directory"),
        pytest.param("report", "the-output-directory", 3, id="report-output-directory"),
        pytest.param("report", "reports", 3, id="report-reports"),
        pytest.param("use-existing", "reports/ash.sarif", 1, id="use-existing-sarif"),
        pytest.param("merge", "reports/ash.sarif", 1, id="merge-sarif"),
    ],
)
@pytest.mark.integration
def test_a_link_at_or_in_the_output_directory_stops_the_run_with_the_pages_code(
    tmp_path: Path, command: str, link: str, code: int
) -> None:
    """exit-codes.md (ash scan, ash merge, ash report), and output-files.md (Links).

    Each command runs with a symbolic link where it would write: the output directory
    itself, ``.ash`` on the way to a scan's default output directory, ``reports``,
    ``ash.log``, a workspace scan's ``projects``, or ``reports/ash.sarif``, which a
    reporter is about to write. It must exit with the page's code, 3 for a link the
    check before writing finds and 1 for a report file, and say the path is a symlink;
    nothing may be written through the link. The control is each command's run without
    the link, which exits 0.
    """
    for page, sentence in _LINKED_OUTPUT_SENTENCES:
        assert_on_page(page, sentence)
    elsewhere = tmp_path / "elsewhere"
    args: List[str] = []

    def run() -> subprocess.CompletedProcess:
        return _ash(args, cwd=tmp_path)

    if command == "workspace":
        project = tmp_path / "ws" / "api"
        project.mkdir(parents=True)
        (project / "main.py").write_text("x = 1\n", encoding="utf-8")
        workspace = tmp_path / "ws" / "services.code-workspace"
        workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), "utf-8")
        output = tmp_path / "ws-output"
        args = [*_CONFIG_SCAN, "--offline", "--workspace", str(workspace)]
        args += ["--output-dir", str(output)]
        assert run().returncode == 0
        target = _link_into(output / "projects", elsewhere / "projects")
    elif command == "scan":
        tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
        output = tree / ".ash" / "ash_output" if link == ".ash" else tmp_path / "out"
        args = [*_CONFIG_SCAN, "--offline", "--source-dir", str(tree)]
        if link != ".ash":
            args += ["--output-dir", str(output)]
        assert run().returncode == 0
        where = {
            "the-output-directory": output,
            ".ash": tree / ".ash",
            "reports": output / "reports",
            "ash.log": output / "ash.log",
        }[link]
        target = _link_into(where, elsewhere / where.name.lstrip("."))
    elif command == "use-existing":
        tree, output = _finished_scan(tmp_path)
        args = [*_CONFIG_SCAN, "--use-existing", "--source-dir", str(tree)]
        args += ["--output-dir", str(output)]
        assert run().returncode == 0
        target = _link_into(output / "reports" / "ash.sarif", elsewhere / "ash.sarif")
    elif command == "merge":
        shard = _stored_scan(tmp_path)
        output = tmp_path / "merged"
        args = ["merge", "--results", str(shard / "ash_aggregated_results.json")]
        args += ["--output-dir", str(output)]
        assert run().returncode == 0
        where = output if link == "the-output-directory" else output / link
        target = _link_into(where, elsewhere / where.name)
    else:
        _tree, output = _finished_scan(tmp_path)
        args = ["report", "--format", "sarif", "--output-dir", str(output)]
        assert run().returncode == 0
        if link == "the-output-directory":
            real = tmp_path / "scan-output-real"
            output.rename(real)
            output.symlink_to(real, target_is_directory=True)
            target = real
            before = sorted(p.as_posix() for p in real.rglob("*"))
        else:
            target = _link_into(output / "reports", elsewhere / "reports")

    result = run()
    text = _squeezed(result.stdout + result.stderr)

    assert result.returncode == code, (
        f"exit {result.returncode}:\n{_output_tail(result)}"
    )
    assert "isasymlink" in text, _output_tail(result)
    if command == "report" and link == "the-output-directory":
        after = sorted(p.as_posix() for p in target.rglob("*"))
        assert after == before, "ash report wrote into the linked output directory"
    else:
        assert _untouched(target), f"{target} was written through the link"


#: exit-codes.md, Container and Nix mode: the output directory a container scan refuses.
_CONTAINER_LINKED_OUTPUT = (
    "or the output directory is a symlink, or a symlink below the source directory leads "
    "to it (such as a committed `.ash` link, for the default `.ash/ash_output`), as in every "
    "mode ([`ash scan`](#scan)). Nothing is created or mounted, also "
    "with `--no-run`. `./ash` and `Invoke-ASH` refuse the same output directory with exit "
    "3 |"
)
#: run-in-a-container.md (Mounts and network): the same refusal, for a container scan.
_CONTAINER_SCAN_REFUSES_A_LINKED_OUTPUT = (
    "An output directory that is a symlink, or that a symlink below the source "
    "directory leads to, such as a committed `.ash` link for the default "
    "`.ash/ash_output`, stops `ash scan --mode container` and `ash build-image` with exit "
    "code 3 ([Exit codes](../reference/exit-codes.md#container)), because the scan "
    "inside the container would write wherever the link points. The refusal comes before "
    "a container runtime is looked up, with `--no-run` too, so nothing is built, "
    "created, or mounted."
)

#: A container runtime stand-in's recorded script: it records each command it is
#: given and fails. Run through _interpreter_launcher, never a ``#!`` naming this
#: interpreter, whose path can hold whitespace or outrun a kernel's limit.
_LOGGING_RUNTIME = """\
import json, sys
with open({log!r}, "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv) + "\\n")
sys.exit(97)
"""


def _runtime_stand_in(stand_ins: Path, name: str, calls: Path) -> Path:
    """A ``name`` stand-in in ``stand_ins`` that records its argv to ``calls`` and
    fails: one recorded script per name, started through the same launcher shape
    as every other stand-in."""
    script = stand_ins / f"record-{name}.py"
    script.write_text(_LOGGING_RUNTIME.format(log=str(calls)), encoding="utf-8")
    return _interpreter_launcher(stand_ins, name, script)


def _no_container_runtime(parent: Path) -> Tuple[Dict[str, str], Path]:
    """The environment for a run that must not reach a real container runtime, and
    the file that records any runtime call: ``OCI_RUNNER`` names one that does not
    exist, and PATH starts with stand-ins for docker, podman, finch and nerdctl that
    record what they are given and fail."""
    stand_ins = parent / "runtime-stand-ins"
    stand_ins.mkdir()
    calls = parent / "runtime-calls.log"
    for name in ("docker", "podman", "finch", "nerdctl"):
        _runtime_stand_in(stand_ins, name, calls)
    env = {
        "OCI_RUNNER": str(parent / "no-such-runtime" / "docker"),
        "PATH": os.pathsep.join([str(stand_ins), os.environ.get("PATH", "")]),
    }
    return env, calls


@pytest.mark.parametrize(
    "command, link",
    [
        pytest.param(
            "container-scan", "the-output-directory", id="scan-output-dir-link"
        ),
        pytest.param("container-scan", ".ash", id="scan-dot-ash-link"),
        pytest.param("container-scan-no-run", ".ash", id="scan-no-run-dot-ash-link"),
        pytest.param("container-scan", "control-no-link", id="scan-control-no-link"),
        pytest.param("build-image-no-run", ".ash", id="build-image-dot-ash-link"),
        pytest.param("build-image-no-run", "control-no-link", id="build-image-control"),
        pytest.param("build-image", ".ash", id="build-image-run-dot-ash-link"),
        pytest.param("build-image", "control-no-link", id="build-image-run-control"),
    ],
)
@pytest.mark.integration
def test_container_mode_refuses_a_linked_output_directory_before_it_runs_anything(
    tmp_path: Path, command: str, link: str
) -> None:
    """exit-codes.md (Container and Nix mode), and run-in-a-container.md (Mounts and
    network) for the scan and for ``ash build-image`` that runs its scan.

    ``ash scan --mode container`` runs on a tree whose output directory is a symlink, or
    whose ``.ash`` is a symlink on the way to the default ``.ash/ash_output``, also
    with ``--no-run``, and ``ash build-image`` runs on the second, with and without
    ``--no-run``. Each names a container runtime that does not exist, also in
    ``OCI_RUNNER``, so looking it up would fail with exit 1, and runs with logging
    stand-ins for the runtimes first on PATH, none of which may be called. Each must
    exit 3 and refuse the output directory, which shows the refusal came before the
    runtime was looked up, and write nothing through the link. The control has no
    link: it gets past that check and stops at the runtime, with another code and no
    refusal of the output directory.
    """
    assert_on_page(EXIT_CODES, _CONTAINER_LINKED_OUTPUT)
    if command != "build-image-no-run":
        assert_on_page(RUN_IN_A_CONTAINER, _CONTAINER_SCAN_REFUSES_A_LINKED_OUTPUT)
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    runner = str(tmp_path / "no-such-runtime" / "docker")
    # build-image builds from the working directory; scan is told it. A UID and GID
    # that are not root keep the non-root image's own refusal of root out of the way.
    if command.startswith("container-scan"):
        args = ["scan", "--mode", "container", "--offline", "--source-dir", str(tree)]
    else:
        args = (
            ["build-image", "--no-run"]
            if command.endswith("-no-run")
            else ["build-image"]
        )
    if command == "container-scan-no-run":
        args.append("--no-run")
    args += [
        "--oci-runner",
        runner,
        "--container-uid",
        "1000",
        "--container-gid",
        "1000",
    ]
    target = None
    if link == "the-output-directory":
        output = tmp_path / "out"
        target = _link_into(output, tmp_path / "elsewhere" / "out")
        args += ["--output-dir", str(output)]
    elif link == ".ash":
        target = _link_into(tree / ".ash", tmp_path / "elsewhere" / "ash")
    runtime_env, runtime_calls = _no_container_runtime(tmp_path)

    result = _ash(args, cwd=tree, **runtime_env)
    text = _squeezed(result.stdout + result.stderr)

    assert not runtime_calls.exists(), runtime_calls.read_text(encoding="utf-8")
    if target is None:
        assert result.returncode != 3, _output_tail(result)
        assert "Refusingtheoutputdirectory" not in text, _output_tail(result)
        return
    assert result.returncode == 3, _output_tail(result)
    assert "Refusingtheoutputdirectory" in text, _output_tail(result)
    assert _untouched(target), f"{target} was written through the link"


#: exit-codes.md (ash scan): a linked output directory is refused in every mode, and
#: before the check that the directory can be written.
_LINKED_OUTPUT_IN_EVERY_MODE = (
    "An output directory that is a symlink, or that a symlink below the source "
    "directory leads to, is refused this way in every mode, `--mode container` (also "
    "with `--no-run`) and `--mode nix` included, and before the check that the "
    "directory can be written, so nothing is made and the link's target keeps its "
    "entries."
)

#: The mtime a link's target is given before a run, in ns: far enough in the past that
#: a file made and removed there moves it.
_LONG_AGO_NS = 1_000_000_000 * 1_000_000_000

#: {mode: the arguments that choose it}: ``ash`` with and without its ``scan``
#: subcommand, and, on POSIX, ./ash.
_LINK_CHECK_MODES = {
    "local": ["scan", "--scanners", "detect-secrets"],
    "no-subcommand": ["--scanners", "detect-secrets"],
    "container": ["scan", "--mode", "container", "--no-build"],
    "container-no-run": ["scan", "--mode", "container", "--no-run"],
    "nix": ["scan", "--mode", "nix"],
    **(
        {"dot-ash": ["--no-build"], "dot-ash-no-run": ["--no-build", "--no-run"]}
        if os.name != "nt"
        else {}
    ),
}


def _directory_state(directory: Path) -> Tuple[List[str], int]:
    """(the names in ``directory``, its mtime in ns)."""
    return sorted(os.listdir(directory)), directory.stat().st_mtime_ns


@pytest.mark.parametrize("link", ["the-output-directory", ".ash", "control-no-link"])
@pytest.mark.parametrize("mode", list(_LINK_CHECK_MODES))
@pytest.mark.integration
def test_a_linked_output_directory_is_refused_in_every_mode_before_the_write_check(
    tmp_path: Path, mode: str, link: str
) -> None:
    """exit-codes.md (ash scan; Container and Nix mode for ./ash).

    A scan runs in each mode the page names, also as ``ash`` with no subcommand and,
    on POSIX, as ./ash with and without ``--no-run``, with ``--output-dir`` a symbolic
    link to a directory outside the source, or with ``.ash`` a link below the source
    on the way to the default ``.ash/ash_output``. The directory the scan would write
    in through the link holds a file and has an mtime long past: the check that the
    directory can be written makes a file there and removes it, which moves the mtime.
    Each run must exit 3, say the path is a symlink, and leave that directory with the
    same entries and mtime. Container mode and ./ash name a runtime that does not
    exist, in ``OCI_RUNNER``, and the runtimes and ``nix`` have logging stand-ins first
    on PATH; none may be called. The control is a real output directory with the same
    entry and mtime: the run gets past the link check, and its mtime moves, which
    shows the probe sees a file made there.
    """
    assert_on_page(EXIT_CODES, _LINKED_OUTPUT_IN_EVERY_MODE)
    if mode.startswith("dot-ash"):
        assert_on_page(EXIT_CODES, _CONTAINER_LINKED_OUTPUT)
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    if mode.startswith("dot-ash"):
        args = _bash_argv(
            _runnable_bash_script(_code_root() / "ash"), *_LINK_CHECK_MODES[mode]
        )
    else:
        args = [*_LINK_CHECK_MODES[mode], "--offline", "--no-progress"]
    args += ["--source-dir", str(tree)]
    if link == ".ash":
        watched = elsewhere / "ash_output"
        watched.mkdir()
        (tree / ".ash").symlink_to(elsewhere, target_is_directory=True)
    else:
        output = tmp_path / "out"
        if link == "the-output-directory":
            watched = elsewhere
            output.symlink_to(elsewhere, target_is_directory=True)
        else:
            watched = output
            output.mkdir()
        args += ["--output-dir", str(output)]
    (watched / "kept.txt").write_text("kept\n", encoding="utf-8")
    os.utime(watched, ns=(_LONG_AGO_NS, _LONG_AGO_NS))
    before = _directory_state(watched)
    runtime_env, runtime_calls = _no_container_runtime(tmp_path)
    _runtime_stand_in(tmp_path / "runtime-stand-ins", "nix", runtime_calls)
    if mode.startswith("container"):
        args += ["--oci-runner", runtime_env["OCI_RUNNER"]]
        args += ["--container-uid", "1000", "--container-gid", "1000"]

    if mode.startswith("dot-ash"):
        # ./ash is run as the shell script it is, with this interpreter's directory on
        # PATH after the stand-ins, as a checkout with ASH installed has it.
        stand_ins, rest = runtime_env["PATH"].split(os.pathsep, 1)
        environment = _ash_environment(tree, **runtime_env)
        environment["PATH"] = os.pathsep.join(
            [stand_ins, str(Path(sys.executable).parent), rest]
        )
        result = subprocess.run(
            args,
            cwd=tree,
            env=environment,
            capture_output=True,
            text=True,
            timeout=600,
        )
    else:
        result = _ash(args, cwd=tree, **runtime_env)
    text = _squeezed(result.stdout + result.stderr)

    if link == "control-no-link":
        assert result.returncode != 3, _output_tail(result)
        assert "isasymlink" not in text, _output_tail(result)
        assert _directory_state(watched)[1] != before[1], (
            f"the control's mtime did not move:\n{_output_tail(result)}"
        )
        return
    assert not runtime_calls.exists(), runtime_calls.read_text(encoding="utf-8")
    assert result.returncode == 3, _output_tail(result)
    assert "symlink" in text, _output_tail(result)
    assert _directory_state(watched) == before, (
        f"{watched} changed: {before} -> {_directory_state(watched)}"
    )


#: choose-scanners.md's bullet on an unknown name in --scanners or --exclude-scanners.
_AN_UNMATCHED_SCANNERS_NAME_IS_RECORDED = (
    "When some match, the scan runs those, and the results record the names that "
    "matched nothing in `metadata.requested_scanners_not_run` ([Output files]"
    "(../reference/output-files.md)); the console summary lists them after the scanner "
    "table, as in `Requested but not run: trivyy (no registered scanner has this "
    "name)`. An unknown name in `--exclude-scanners` excludes nothing, and a warning "
    "names it; the scan still runs, and the results do not record the name."
)
#: output-files.md's entry for the field.
_REQUESTED_SCANNERS_NOT_RUN_FIELD = (
    "`requested_scanners_not_run` (the names in `--scanners` or `ASH_SCANNERS` that "
    "matched no scanner, or `null` when every name matched or no list was given; `ash "
    "merge` records the names of all the shards)"
)


def _built_in_scanner_names() -> Set[str]:
    from automated_security_helper.plugin_modules import ash_builtin

    return {
        typing.get_args(plugin.model_fields["config"].annotation)[0]
        .model_fields["name"]
        .default
        for plugin in ash_builtin.ASH_SCANNERS
    }


@pytest.mark.parametrize(
    "case",
    [
        "a-scanners-name-matches-nothing",
        "an-ASH_SCANNERS-name-matches-nothing",
        "an-exclude-scanners-name-matches-nothing",
        "every-name-matches",
        "no-list",
    ],
)
@pytest.mark.integration
def test_a_scanners_name_that_matched_no_scanner_is_recorded_and_listed(
    tmp_path: Path, case: str
) -> None:
    """choose-scanners.md (Choose the scanners), and output-files.md (the results
    file's metadata).

    A scan of a one-file tree asks for ``detect-secrets`` and ``nosuchscanner``, with
    ``--scanners`` or ``ASH_SCANNERS``: it must run detect-secrets, record
    ``["nosuchscanner"]`` in ``metadata.requested_scanners_not_run``, and print the
    page's line after the scanner table. With ``nosuchscanner`` in
    ``--exclude-scanners`` instead, a warning names it and the field is null; so it
    is when every name matches, and when no list is given (every other built-in
    scanner excluded).
    """
    assert_on_page("how-to/choose-scanners.md", _AN_UNMATCHED_SCANNERS_NAME_IS_RECORDED)
    assert_on_page(OUTPUT_FILES, _REQUESTED_SCANNERS_NOT_RUN_FIELD)
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    output = tmp_path / "out"
    args = ["scan", "--offline", "--no-progress", "--source-dir", str(tree)]
    args += ["--output-dir", str(output)]
    env: Dict[str, str] = {}
    if case == "a-scanners-name-matches-nothing":
        args += ["--scanners", "detect-secrets,nosuchscanner"]
    elif case == "an-ASH_SCANNERS-name-matches-nothing":
        env["ASH_SCANNERS"] = "detect-secrets,nosuchscanner"
    elif case == "an-exclude-scanners-name-matches-nothing":
        args += ["--scanners", "detect-secrets", "--exclude-scanners", "nosuchscanner"]
    elif case == "every-name-matches":
        args += ["--scanners", "detect-secrets"]
    else:
        others = sorted(_built_in_scanner_names() - {"detect-secrets"})
        args += ["--exclude-scanners", ",".join(others)]

    result = _ash(args, cwd=tmp_path, **env)
    document = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    lines = [line.strip() for line in result.stdout.splitlines()]
    listed = [
        i
        for i, line in enumerate(lines)
        if line.startswith("Requested but not run: nosuchscanner")
    ]

    assert result.returncode == 0, _output_tail(result)
    assert document["scanner_results"]["detect-secrets"]["status"] == "PASSED"
    recorded = document["metadata"]["requested_scanners_not_run"]
    if case.endswith("name-matches-nothing") and "exclude" not in case:
        assert recorded == ["nosuchscanner"], recorded
        assert lines[listed[0]] == (
            "Requested but not run: nosuchscanner (no registered scanner has this name)"
        ), _output_tail(result)
        table_end = max(i for i, line in enumerate(lines) if line.startswith("└"))
        assert listed[0] > table_end, _output_tail(result, 40)
        return
    assert recorded is None, recorded
    assert listed == [], _output_tail(result)
    if "exclude" in case:
        warning = "No registered scanner matches excluded nosuchscanner, so nothing is "
        warning += "excluded for it."
        assert _squeezed(warning) in _squeezed(result.stdout + result.stderr), (
            _output_tail(result)
        )


@pytest.mark.integration
def test_ash_merge_records_every_shards_scanners_names_that_matched_nothing(
    tmp_path: Path,
) -> None:
    """output-files.md (the results file's metadata).

    Two shards of a one-file tree, one asking for ``detect-secrets,nosuchA`` and the
    other for ``detect-secrets,nosuchB``, are merged from an empty directory outside
    the trees. The merged results must record ``["nosuchA", "nosuchB"]``. The control
    is each shard's own record, which holds only its name.
    """
    assert_on_page(OUTPUT_FILES, _REQUESTED_SCANNERS_NOT_RUN_FIELD)
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    shards = []
    for index, unknown in enumerate(["nosuchA", "nosuchB"]):
        output = tmp_path / f"shard-{index}"
        result = _ash(
            [
                "scan",
                "--offline",
                "--no-progress",
                "--source-dir",
                str(tree),
                "--output-dir",
                str(output),
                "--scanners",
                f"detect-secrets,{unknown}",
                "--shard-index",
                str(index),
                "--shard-count",
                "2",
            ],
            cwd=tmp_path,
        )
        assert result.returncode == 0, _output_tail(result)
        shard = output / "ash_aggregated_results.json"
        record = json.loads(shard.read_text(encoding="utf-8"))["metadata"]
        assert record["requested_scanners_not_run"] == [unknown], record
        shards.append(shard)
    work = tmp_path / "work"
    work.mkdir()
    merged = tmp_path / "merged"

    args = ["merge", "--output-dir", str(merged)]
    for shard in shards:
        args += ["--results", str(shard)]

    result = _ash(args, cwd=work)

    assert result.returncode == 0, _output_tail(result)
    document = json.loads(
        (merged / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    assert document["metadata"]["requested_scanners_not_run"] == [
        "nosuchA",
        "nosuchB",
    ], document["metadata"]["requested_scanners_not_run"]


#: run-in-a-container.md: the scan options ``ash build-image`` refuses.
_BUILD_IMAGE_TAKES_NO_SCAN_OPTION = (
    "It takes no `--source-dir`, `--output-dir`, or other scan option: an argument its "
    "help does not list stops it with exit code 5 before anything is built, so use "
    "`ash scan --mode container` to choose the directories."
)


def _tree_entries(root: Path) -> Dict[str, int]:
    """{path under ``root``: modification time in ns} for everything under it."""
    return {
        path.relative_to(root).as_posix(): path.lstat().st_mtime_ns
        for path in root.rglob("*")
    }


@pytest.mark.parametrize("no_run", [False, True], ids=["build-and-run", "no-run"])
@pytest.mark.parametrize(
    "option",
    [
        pytest.param(["--output-dir", "out"], id="output-dir"),
        pytest.param(["--source-dir", "src"], id="source-dir"),
        pytest.param(["--scanners", "bandit"], id="a-scan-option"),
        pytest.param(["--json"], id="json"),
        pytest.param([], id="control-no-scan-option"),
    ],
)
@pytest.mark.integration
def test_ash_build_image_refuses_a_scan_option_with_exit_5_before_it_builds(
    tmp_path: Path, option: List[str], no_run: bool
) -> None:
    """run-in-a-container.md (Scan in container mode).

    ``ash build-image`` with ``--output-dir``, ``--source-dir``, ``--scanners`` or
    ``--json``, none of which its command declares, with and without ``--no-run``. It
    names a container runtime that does not exist, also in ``OCI_RUNNER``, so a lookup
    would exit 1, and runs with logging stand-ins for the runtimes first on PATH. Each
    exits 5, so it stopped before the runtime was looked up; no stand-in was called,
    and the tree it runs in, the directory it was given and ``.ash`` are as they were.
    The control gives no scan option: it gets past the arguments and stops at the
    runtime lookup, with exit 1 and ``Unable to resolve an OCI runner``.
    """
    assert_on_page(RUN_IN_A_CONTAINER, _BUILD_IMAGE_TAKES_NO_SCAN_OPTION)
    import typer

    from automated_security_helper.cli.main import app

    declared = {
        name
        for parameter in typer.main.get_command(app).commands["build-image"].params
        for name in parameter.opts
    }
    for name in ("--source-dir", "--output-dir", "--scanners", "--json", "--no-run"):
        assert (name in declared) is (name == "--no-run"), (name, sorted(declared))
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    (tree / "src").mkdir()
    # _ash gives the run a home directory in the tree; anything written there counts.
    (tree / "home").mkdir()
    before = _tree_entries(tree)
    runner = str(tmp_path / "no-such-runtime" / "docker")
    args = ["build-image", "--oci-runner", runner]
    args += ["--container-uid", "1000", "--container-gid", "1000"]
    if no_run:
        args.append("--no-run")
    runtime_env, runtime_calls = _no_container_runtime(tmp_path)

    result = _ash([*args, *option], cwd=tree, **runtime_env)

    assert not runtime_calls.exists(), runtime_calls.read_text(encoding="utf-8")
    if not option:
        # Past the arguments: the runtime lookup is what stops it.
        assert result.returncode == 1, _output_tail(result)
        assert _squeezed("Unable to resolve an OCI runner") in _squeezed(
            result.stdout + result.stderr
        ), _output_tail(result)
        return
    assert result.returncode == 5, _output_tail(result)
    assert _tree_entries(tree) == before, set(_tree_entries(tree)) ^ set(before)


#: run-in-a-container.md (Mounts and network): a directory a local scan refuses.
_CONTAINER_REFUSES_WHAT_A_LOCAL_SCAN_REFUSES = (
    "A source or output directory that a local scan refuses, such as a source directory "
    "that does not exist or an output directory that cannot be created, stops "
    "`ash scan --mode container` with exit code 5, also with `--no-run`, and with the "
    "line a local scan prints ([Exit codes](../reference/exit-codes.md#scan)). `./ash` "
    "refuses them as well: it prints the line after `ERROR: ` and exits 5."
)

#: {case: (the directories a scan is given, the path its refusal names)}.
_UNUSABLE_DIRECTORIES = {
    "a-missing-source-dir": (["--source-dir", "no-such-dir"], "no-such-dir"),
    "a-source-dir-that-is-a-file": (["--source-dir", "afile"], "afile"),
    "an-output-dir-that-is-a-file": (
        ["--source-dir", ".", "--output-dir", "afile"],
        "afile",
    ),
    "an-output-dir-under-a-file": (
        ["--source-dir", ".", "--output-dir", "afile/out"],
        "afile/out",
    ),
}


@pytest.mark.parametrize(
    "runner",
    ["container", "container-no-run", *(["dot-ash"] if os.name != "nt" else [])],
)
@pytest.mark.parametrize("case", list(_UNUSABLE_DIRECTORIES))
@pytest.mark.integration
def test_container_mode_and_dot_ash_refuse_a_directory_a_local_scan_refuses(
    tmp_path: Path, case: str, runner: str
) -> None:
    """run-in-a-container.md (Mounts and network).

    A source directory that does not exist or is a file, and an output directory that
    is a file or would be made under one. A local scan of each runs first and must
    exit 5; its one line naming the path is the line ``ash scan --mode container``,
    with and without ``--no-run``, must print, and ``./ash`` (POSIX) after
    ``ERROR: ``, each with exit 5. Every run names a container runtime that does not
    exist, in ``OCI_RUNNER`` and with ``--oci-runner``, so a lookup would exit 1, with
    logging stand-ins for the runtimes first on PATH, none of which may be called.
    """
    assert_on_page(RUN_IN_A_CONTAINER, _CONTAINER_REFUSES_WHAT_A_LOCAL_SCAN_REFUSES)
    tree = _config_scan_tree(
        tmp_path, {"app.py": "x = 1\n", "afile": "not a directory\n"}
    )
    directories, named = _UNUSABLE_DIRECTORIES[case]
    runtime_env, runtime_calls = _no_container_runtime(tmp_path)
    scan = ["scan", *directories, "--scanners", "detect-secrets", "--offline"]

    local = _ash([*scan, "--no-progress"], cwd=tree, **runtime_env)
    assert local.returncode == 5, _output_tail(local)
    lines = [
        line.strip()
        for line in (local.stdout + local.stderr).splitlines()
        if named in line
    ]
    assert len(lines) == 1, f"the local scan's refusal is not one line: {lines}"

    if runner == "dot-ash":
        # ./ash is run as the shell script it is, with this interpreter's directory on
        # PATH after the stand-ins, as a checkout with ASH installed has it.
        stand_ins, rest = runtime_env["PATH"].split(os.pathsep, 1)
        environment = _ash_environment(tree, **runtime_env)
        environment["PATH"] = os.pathsep.join(
            [stand_ins, str(Path(sys.executable).parent), rest]
        )
        result = subprocess.run(
            _bash_argv(
                _runnable_bash_script(_code_root() / "ash"), *directories, "--offline"
            ),
            cwd=tree,
            env=environment,
            capture_output=True,
            text=True,
            timeout=600,
        )
        expected = f"ERROR: {lines[0]}"
    else:
        args = ["scan", "--mode", "container", *directories, "--offline"]
        args += ["--oci-runner", runtime_env["OCI_RUNNER"]]
        args += ["--container-uid", "1000", "--container-gid", "1000"]
        if runner == "container-no-run":
            args.append("--no-run")
        result = _ash(args, cwd=tree, **runtime_env)
        expected = lines[0]

    assert not runtime_calls.exists(), runtime_calls.read_text(encoding="utf-8")
    assert result.returncode == 5, _output_tail(result)
    shown = [line.strip() for line in (result.stdout + result.stderr).splitlines()]
    assert expected in shown, f"{expected!r} is not printed:\n{_output_tail(result)}"


# --------------------------------------------------------------------------- #
# What ASH records of a config that reads the environment
# --------------------------------------------------------------------------- #

GLOSSARY = "concepts/glossary.md"
HOW_ASH_WORKS = "concepts/how-ash-works.md"

#: The reference the configs below write, to ``_ENV_PROBE``.
_REFERENCE = f"${{{_ENV_PROBE}}}"
#: A second variable a config may read, for ``severity_threshold``.
_SEVERITY_PROBE = "ASH_PAGE_CLAIMS_SEVERITY"

#: The pages' sentences on what records a reference instead of the value it read.
_RECORD_SENTENCES = [
    (
        CONFIGURE,
        (
            "The scan runs with the values. What ASH records of the config holds each "
            "reference as the file wrote it instead: the `ash_config` in the scan's "
            "results (`ash_aggregated_results.json`) and in the merged results, the "
            "results' metadata where it names a config value (a `scanners` key in "
            "`expected_scanners`), what an off-host reporter sends, and what "
            "`ash config get` prints."
        ),
    ),
    (
        OUTPUT_FILES,
        (
            "| `ash_config` | The configuration the scan resolved, after overrides and "
            "trust rules. A value or key a config file read from the environment is "
            "recorded as the reference the file wrote, here and in "
            "`metadata.expected_scanners`"
        ),
    ),
    (
        CONFIGURE,
        (
            "`ash config get` loads the file with the variable read, and prints the "
            "reference, not the value:"
        ),
    ),
    (
        CONFIGURE,
        (
            "| `ash config get` | Loads the file the same way and prints the resolved "
            "config, with each value read from the environment shown as the reference "
            "the file wrote."
        ),
    ),
    (
        GLOSSARY,
        (
            "It holds the resolved configuration, with each value read from the "
            "environment recorded as its reference, a status row per scanner and "
            "converter, and the aggregated SARIF, and every reporter renders it."
        ),
    ),
    (
        HOW_ASH_WORKS,
        (
            "the resolved configuration the scan used, with each value a config file "
            "read from the environment recorded as the reference the file wrote"
        ),
    ),
]
_UNSET_AND_EMPTY_ARE_RECORDED = (
    "A reference whose variable is not set is recorded as the default the file wrote, "
    "and one that resolves to nothing as null."
)
_S3_OBJECT_HOLDS_THE_REFERENCE = (
    "In the configuration and the metadata, a value or key a config file read from the "
    "environment is the reference the file wrote"
)
#: A config that reads ``project_name`` and a ``scanners`` key from ``_ENV_PROBE``.
#: The scanner is left off, and still listed in ``metadata.expected_scanners``.
_PROJECT_AND_SCANNER_FROM_THE_ENVIRONMENT = (
    f"project_name: {_REFERENCE}\nscanners:\n  {_REFERENCE}:\n    enabled: false\n"
)
#: The pages' sentences and rows on ash merge and ash report reading a record.
_READING_A_RECORD_SENTENCES = [
    (
        CONFIGURE,
        (
            "`ash merge` and `ash report` read the recorded config and do not read the "
            "environment for a reference in it. A text field such as `project_name` "
            "keeps the reference as its value. A field that takes a fixed choice, a "
            "boolean, or a number, such as `severity_threshold`, cannot hold one: the "
            "command warns that the field reads as its default, then exits 3 naming the "
            "field and the reference, until you supply the field with "
            "`--config-overrides` or in the file `--config` names."
        ),
    ),
    (
        SCALE_LARGE_REPOS,
        (
            "A value the shards' configuration read from the environment is recorded as "
            "its reference, and `ash merge` does not read the environment for it: a "
            "field that takes a fixed choice, a boolean, or a number, such as "
            "`severity_threshold`, cannot hold the reference, so the merge exits 3 "
            "naming the field until you supply it with `--config-overrides` or in the "
            "file `--config` names"
        ),
    ),
    (
        SCALE_LARGE_REPOS,
        (
            "| 3 | A fixed-choice, boolean, or number field the shards' configuration "
            "read from the environment, which the command line does not supply. "
            "Nothing was merged. |"
        ),
    ),
    (
        EXIT_CODES,
        (
            "| 3 | The configuration recorded in the shards reads a field that takes a "
            "fixed choice, a boolean, or a number from the environment, and neither "
            "`--config-overrides` nor the file `--config` names supplies the field"
        ),
    ),
    (
        EXIT_CODES,
        (
            "or the configuration recorded in the results reads a field that takes a "
            "fixed choice, a boolean, or a number from the environment, and neither "
            "`--config-overrides` nor `--config` supplies the field;"
        ),
    ),
]
_A_FAILED_PATCH_ENTRY_IS_NAMED = (
    "The error for an operation that fails names the file, the entry's place in "
    "`patch`, its op, and its path, and not its value."
)


def _operator_config(tmp_path: Path, text: str, name: str = "ash.yaml") -> Path:
    """A config file holding ``text`` outside the scanned tree, as an operator's."""
    config = tmp_path / "operator" / name
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(text, encoding="utf-8")
    return config


def _scan_with_config(tmp_path: Path, config: Path) -> Path:
    """The output directory of a one-shard detect-secrets scan of a one-file tree with
    ``config``, in this process's environment; the scan must exit 0."""
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    output = tmp_path / "scan-output"
    args = [*_CONFIG_SCAN, "--offline", "--source-dir", str(tree)]
    args += ["--output-dir", str(output), "--config", str(config)]
    args += ["--shard-index", "0", "--shard-count", "1"]
    result = _ash(args, cwd=tmp_path)
    assert result.returncode == 0, _output_tail(result)
    return output


def _recorded_config(results: Path) -> Dict[str, Any]:
    """The ``ash_config`` of the results file ``results``."""
    return json.loads(results.read_text(encoding="utf-8"))["ash_config"]


def _assert_the_file_reads_the_variable(config: Path) -> None:
    """The control: ``config``, ``_PROJECT_AND_SCANNER_FROM_THE_ENVIRONMENT``,
    resolved as a scan resolves it with ``_ENV_PROBE`` set, has the variable's value
    as its ``project_name`` and as a ``scanners`` key."""
    from automated_security_helper.config.resolve_config import resolve_config

    resolved = resolve_config(config_path=config, source_dir=config.parent)
    assert resolved.project_name == _ENV_PROBE_VALUE, resolved.project_name
    scanners = resolved.model_dump(by_alias=True)["scanners"]
    assert _ENV_PROBE_VALUE in scanners, sorted(scanners)


def _assert_a_record_of_the_config(record: Dict[str, Any], where: str) -> None:
    """``record``, a dump of results, holds the references the config wrote, in its
    ``ash_config`` and its ``metadata.expected_scanners``, and nowhere the value."""
    assert record["ash_config"]["project_name"] == _REFERENCE, where
    assert _REFERENCE in record["ash_config"]["scanners"], where
    assert _REFERENCE in record["metadata"]["expected_scanners"], where
    assert _ENV_PROBE_VALUE not in json.dumps(record, default=str), (
        f"{where} holds the value"
    )


@pytest.mark.parametrize("record", ["results", "merged-results", "config-get"])
@pytest.mark.integration
def test_what_ash_records_of_a_config_holds_the_reference_and_not_the_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, record: str
) -> None:
    """configure.md (Read values from the environment; Check a config), output-files.md
    (`ash_aggregated_results.json`), glossary.md (Aggregated results), and
    how-ash-works.md (The results model).

    An operator's config file sets ``project_name`` and names a scanner, left off,
    from a variable the environment holds. The scan's results, and the results ``ash
    merge`` writes from them, must hold both as the references the file wrote: in
    their ``ash_config``, and the scanner in ``metadata.expected_scanners``. ``ash
    config get`` must print both so. None of them may hold the value anywhere. The
    control is the same file resolved as a scan resolves it, which has the value in
    both places, so the file does read the variable.
    """
    for page, sentence in _RECORD_SENTENCES:
        assert_on_page(page, sentence)
    config = _operator_config(tmp_path, _PROJECT_AND_SCANNER_FROM_THE_ENVIRONMENT)
    monkeypatch.setenv(_ENV_PROBE, _ENV_PROBE_VALUE)
    _assert_the_file_reads_the_variable(config)

    if record == "config-get":
        result = _ash(["config", "get", "--config", str(config)], cwd=tmp_path)
        assert result.returncode == 0, _output_tail(result)
        printed = [line.rstrip() for line in result.stdout.splitlines()]
        assert f"project_name: {_REFERENCE}" in printed, result.stdout
        assert f"  {_REFERENCE}:" in printed, result.stdout
        assert _ENV_PROBE_VALUE not in result.stdout + result.stderr, (
            "ash config get printed the value"
        )
        return
    results = _scan_with_config(tmp_path, config) / "ash_aggregated_results.json"
    if record == "merged-results":
        merged = tmp_path / "merged"
        result = _ash(
            ["merge", "--results", str(results), "--output-dir", str(merged)],
            cwd=tmp_path,
        )
        assert result.returncode == 0, _output_tail(result)
        results = merged / "ash_aggregated_results.json"
    _assert_a_record_of_the_config(
        json.loads(results.read_text(encoding="utf-8")), results.name
    )


@pytest.mark.parametrize(
    "variable, recorded",
    [
        pytest.param(
            _ENV_PROBE_VALUE,
            f"${{{_ENV_PROBE}:page-claims-default}}",
            id="set-records-the-reference",
        ),
        pytest.param(None, "page-claims-default", id="unset-records-the-default"),
        pytest.param("", None, id="empty-records-null"),
    ],
)
@pytest.mark.integration
def test_a_reference_is_recorded_only_where_it_read_a_value(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    variable: Optional[str],
    recorded: Optional[str],
) -> None:
    """configure.md (Read values from the environment).

    An operator's config file sets the S3 reporter's ``bucket_name``, which may be
    null, to a reference with a default, and leaves the reporter off. With the
    variable set, the scan's results record the reference; with it unset, the
    default the file wrote; and with it set to an empty string, which resolves to
    nothing, null.
    """
    assert_on_page(CONFIGURE, _UNSET_AND_EMPTY_ARE_RECORDED)
    config = _operator_config(
        tmp_path,
        "reporters:\n  s3:\n    options:\n"
        f"      bucket_name: ${{{_ENV_PROBE}:page-claims-default}}\n",
    )
    if variable is None:
        monkeypatch.delenv(_ENV_PROBE, raising=False)
    else:
        monkeypatch.setenv(_ENV_PROBE, variable)

    results = _scan_with_config(tmp_path, config) / "ash_aggregated_results.json"

    s3 = _recorded_config(results)["reporters"]["s3"]
    assert s3["options"]["bucket_name"] == recorded, s3


@contextlib.contextmanager
def _moto_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Tuple[str, Any, str]]:
    """A moto server on loopback holding one new bucket, as (its endpoint URL, an S3
    client for it, the bucket's name). This process is fenced off from any real AWS
    account first: no ``AWS_PROFILE``, no config or credentials file, and no instance
    metadata, so moto's test credentials are the only ones the client finds."""
    import boto3
    from moto.server import ThreadedMotoServer

    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", os.devnull)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", os.devnull)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    server.start()
    try:
        host, port = server.get_host_and_port()
        endpoint = f"http://{host}:{port}"
        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
        )
        bucket = f"page-claims-{uuid.uuid4().hex[:12]}"
        client.create_bucket(Bucket=bucket)
        yield endpoint, client, bucket
    finally:
        server.stop()


def _moto_child_environment(cwd: Path, endpoint: str) -> Dict[str, str]:
    """``_no_aws_credentials_environment`` with moto's test credentials and its
    ``endpoint``, and a proxy that refuses every host but loopback, so a child's AWS
    client reaches the moto server and nothing else."""
    env = _no_aws_credentials_environment(cwd)
    env.update(
        AWS_ACCESS_KEY_ID="testing",
        AWS_SECRET_ACCESS_KEY="testing",
        AWS_ENDPOINT_URL=endpoint,
        HTTPS_PROXY="http://127.0.0.1:9",
        NO_PROXY="127.0.0.1",
    )
    return env


@pytest.mark.integration
def test_the_s3_reporter_sends_a_value_read_from_the_environment_as_its_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """configure.md (Read values from the environment) and aws.md (What each reporter
    sends: `s3`).

    A scan with an operator's config file that sets ``project_name`` and names a
    scanner, left off, from a variable the environment holds turns on the S3 reporter
    for a bucket on a moto server on loopback. The scan has moto's test credentials
    and its endpoint, and a proxy that refuses anything else. The object it uploads
    must hold both as the references the file wrote, in its configuration and the
    scanner in its metadata, and must not hold the value anywhere. The controls are
    the same file resolved as a scan resolves it, which has the value in both places,
    and the object, which must have been uploaded.
    """
    assert_on_page(CONFIGURE, _RECORD_SENTENCES[0][1])
    assert_on_page(AWS_PLUGINS, _S3_OBJECT_HOLDS_THE_REFERENCE)
    config = _operator_config(tmp_path, _PROJECT_AND_SCANNER_FROM_THE_ENVIRONMENT)
    monkeypatch.setenv(_ENV_PROBE, _ENV_PROBE_VALUE)
    _assert_the_file_reads_the_variable(config)

    with _moto_bucket(monkeypatch) as (endpoint, client, bucket):
        env = _moto_child_environment(tmp_path, endpoint)
        overrides = [
            f"ash_plugin_modules+=[{_AWS_PLUGIN_MODULE}]",
            "reporters.s3.enabled=true",
            "reporters.s3.options.aws_region=us-east-1",
            f"reporters.s3.options.bucket_name={bucket}",
        ]
        tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
        args = [*_CONFIG_SCAN, "--offline", "--source-dir", str(tree)]
        args += ["--output-dir", str(tmp_path / "out"), "--config", str(config)]
        for override in overrides:
            args += ["--config-overrides", override]
        result = subprocess.run(
            [sys.executable, "-m", "automated_security_helper.cli.main", *args],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
        assert result.returncode == 0, _output_tail(result)
        keys = [
            item["Key"]
            for item in client.list_objects_v2(Bucket=bucket).get("Contents", [])
        ]
        assert len(keys) == 1, (keys, _output_tail(result))
        body = client.get_object(Bucket=bucket, Key=keys[0])["Body"].read()

    _assert_a_record_of_the_config(json.loads(body), "the uploaded object")


#: The pages' sentences on the reports a scan writes itself, which the record does
#: not cover.
_THE_SCANS_REPORTS_SHOW_THE_VALUES = [
    (
        CONFIGURE,
        (
            "The reports the scan writes are built from the values, and the record "
            "does not cover them: the reports a scan writes itself, such as `ash.html`, "
            "show the values. So do not read secrets into the config."
        ),
    ),
    (
        HOW_ASH_WORKS,
        (
            "The scan's own reports, such as `ash.html`, are built with the values a "
            "config read from the environment, where the file records the references."
        ),
    ),
]


@pytest.mark.parametrize(
    "written", ["from-the-environment", "control-the-literal-value"]
)
@pytest.mark.integration
def test_the_html_report_a_scan_writes_is_built_from_the_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, written: str
) -> None:
    """configure.md (Read values from the environment) and how-ash-works.md (The
    results model).

    A scan with an operator's config file that names a scanner, left off, from a
    variable the environment holds writes ``reports/ash.html``, which lists the
    expected scanners: it must name the scanner by the value. The results file the
    same scan writes must hold the reference instead, and not the value, so the
    report is built from the values while the record is not. The control is the same
    config with the value written in it: ash.html and the results file both hold it.
    """
    for page, sentence in _THE_SCANS_REPORTS_SHOW_THE_VALUES:
        assert_on_page(page, sentence)
    if written == "from-the-environment":
        config = _operator_config(tmp_path, _PROJECT_AND_SCANNER_FROM_THE_ENVIRONMENT)
        monkeypatch.setenv(_ENV_PROBE, _ENV_PROBE_VALUE)
        _assert_the_file_reads_the_variable(config)
    else:
        config = _operator_config(
            tmp_path,
            _PROJECT_AND_SCANNER_FROM_THE_ENVIRONMENT.replace(
                _REFERENCE, _ENV_PROBE_VALUE
            ),
        )
        monkeypatch.delenv(_ENV_PROBE, raising=False)

    output = _scan_with_config(tmp_path, config)

    html = (output / "reports" / "ash.html").read_text(encoding="utf-8")
    assert _ENV_PROBE_VALUE in html, "ash.html does not show the value"
    results = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    if written == "from-the-environment":
        _assert_a_record_of_the_config(results, "ash_aggregated_results.json")
    else:
        listed = results["metadata"]["expected_scanners"]
        assert _ENV_PROBE_VALUE in listed, listed


@pytest.mark.parametrize("supplied", ["nothing", "config-overrides", "config"])
@pytest.mark.parametrize("command", ["merge", "report"])
@pytest.mark.integration
def test_merge_and_report_exit_3_for_a_recorded_reference_a_field_cannot_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str, supplied: str
) -> None:
    """configure.md (Read values from the environment), scale-large-repos.md (Split a
    scan across runners), and exit-codes.md (`ash merge`, `ash report`).

    A one-shard scan's config reads ``project_name`` and ``severity_threshold`` from
    the environment, so its results record both references. ``ash merge`` and ``ash
    report`` then run with both variables still set. Supplying nothing, each must
    warn that ``severity_threshold`` reads as its default and exit 3 naming the field
    and its reference, so neither reads the environment for it. With the field in
    ``--config-overrides`` or in the file ``--config`` names, each must exit 0, and
    the merged results must keep ``project_name``'s reference as its value.
    """
    for page, sentence in _READING_A_RECORD_SENTENCES:
        assert_on_page(page, sentence)
    config = _operator_config(
        tmp_path,
        f"project_name: {_REFERENCE}\n"
        f"global_settings:\n  severity_threshold: ${{{_SEVERITY_PROBE}}}\n",
    )
    monkeypatch.setenv(_ENV_PROBE, _ENV_PROBE_VALUE)
    monkeypatch.setenv(_SEVERITY_PROBE, "MEDIUM")
    output = _scan_with_config(tmp_path, config)
    merged = tmp_path / "merged"
    if command == "merge":
        args = ["merge", "--results", str(output / "ash_aggregated_results.json")]
        args += ["--output-dir", str(merged)]
    else:
        args = ["report", "--format", "markdown", "--output-dir", str(output)]
    if supplied == "config-overrides":
        args += ["--config-overrides", "global_settings.severity_threshold=MEDIUM"]
    elif supplied == "config":
        supplying = _operator_config(
            tmp_path, "global_settings:\n  severity_threshold: MEDIUM\n", "supply.yaml"
        )
        args += ["--config", str(supplying)]

    result = _ash(args, cwd=tmp_path)
    text = _squeezed(result.stdout + result.stderr)

    reference = f"${{{_SEVERITY_PROBE}}}"
    if supplied == "nothing":
        assert result.returncode == 3, _output_tail(result)
        warning = (
            f"The recorded configuration holds {reference} for "
            "global_settings.severity_threshold, a value the scan read from the "
            "environment, and the field cannot hold a reference, so it reads as its "
            "default."
        )
        assert _squeezed(warning) in text, _output_tail(result)
        named = f"global_settings.severity_threshold holds {reference}"
        assert _squeezed(named) in text, _output_tail(result)
        return
    assert result.returncode == 0, _output_tail(result)
    if command == "merge":
        recorded = _recorded_config(merged / "ash_aggregated_results.json")
        assert recorded["project_name"] == _REFERENCE, recorded["project_name"]


@pytest.mark.parametrize("command", ["scan", "validate"])
@pytest.mark.parametrize(
    "operation, named",
    [
        pytest.param(
            {"op": "test", "path": "/project_name"},
            "the value at '/project_name' does not equal the value the test op gives",
            id="a-test-that-fails",
        ),
        pytest.param(
            {"op": "replace", "path": "/fail_on_findings"},
            "(replace at '/fail_on_findings') failed",
            id="a-replace-of-a-key-no-file-set",
        ),
    ],
)
@pytest.mark.integration
def test_a_failed_patch_entry_is_named_by_its_file_place_op_and_path(
    tmp_path: Path, command: str, operation: Dict[str, str], named: str
) -> None:
    """configure.md (Share settings with `extends`).

    An operator's config file holds a ``patch`` whose first entry succeeds and whose
    second fails: a ``test`` of a value the file does not hold, or a ``replace`` of a
    key no file set. A scan and ``ash config validate`` with that file must fail with
    an error that names the file, entry 1, its op and its path, and the error must not
    hold the entry's value. The scan must exit 3; the code ``validate`` gives is
    pinned by test_config_validate_exits_with_the_code_a_scan_would_give_the_config.
    """
    assert_on_page(CONFIGURE, _A_FAILED_PATCH_ENTRY_IS_NAMED)
    value = "page-claims-patch-entry-value-3e9a"
    config = _operator_config(
        tmp_path,
        yaml.safe_dump(
            {
                "project_name": "page-claims",
                "patch": [
                    {"op": "test", "path": "/project_name", "value": "page-claims"},
                    {**operation, "value": value},
                ],
            }
        ),
    )
    if command == "scan":
        tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
        args = [*_CONFIG_SCAN, "--offline", "--source-dir", str(tree)]
        args += ["--output-dir", str(tmp_path / "out"), "--config", str(config)]
    else:
        args = ["config", "validate", "--config", str(config)]

    result = _ash(args, cwd=tmp_path)
    text = _squeezed(result.stdout + result.stderr)

    if command == "scan":
        assert result.returncode == 3, _output_tail(result)
    else:
        assert result.returncode != 0, _output_tail(result)
    place = _squeezed(f"'patch' entry 1 in {config.as_posix()}")
    assert place in text, _output_tail(result)
    assert _squeezed(named) in text, _output_tail(result)
    assert value not in text, _output_tail(result)


#: configure.md (Share settings with `extends`): how a plugin's section is found.
_A_SECTION_IS_FOUND_BY_THE_PLUGINS_NAME = (
    "A plugin's section is found by the plugin's name with case, punctuation, and the "
    "words Scanner, Reporter, and Converter ignored, so `CSV`, `CsvReporter`, and `csv` "
    "name one reporter, and `DetectSecretsScanner` names `detect-secrets`."
)
#: The same paragraph, on a child's spelling of a section its base writes.
_A_CHILDS_SPELLING_IS_THAT_SECTION = (
    "A child's spelling of a section the base writes another way is that section: the "
    "merged config holds it under a built-in plugin's own name (`csv`), and otherwise "
    "under the child's spelling."
)
#: The same paragraph, on a file that writes two spellings.
_TWO_SPELLINGS_ARE_REFUSED = (
    "A file that writes two such spellings, such as `detect-secrets` and "
    "`DETECT_SECRETS`, is refused with exit 3 by a scan and by `ash config validate`, "
    "which name both spellings and none of their values."
)
#: exit-codes.md's ash scan row and ash config row on that refusal.
_TWO_SPELLINGS_ROWS = [
    (
        "and so does one plugin's section written under two spellings, such as "
        "`detect-secrets` and `DETECT_SECRETS`"
    ),
    (
        "it or an override does not validate (one plugin's section written under two "
        "spellings included)"
    ),
]
#: configure.md's patch paragraph and overrides bullet on a plugin's section.
_PATCH_PATHS_MATCH_A_SECTION = (
    "In a `patch` path, a key spelled with `-` and the same key spelled with `_` are "
    "one key, and a plugin's section is matched as its name is: `/reporters/CSV/enabled` "
    "and `/scanners/detect_secrets/enabled` reach the `csv` and `detect-secrets` "
    "sections."
)
_OVERRIDES_MATCH_A_SECTION = (
    "a key reaches a plugin's section the way a section's name is matched, so "
    "`reporters.CSV.enabled` sets the `csv` section's."
)


def _enabled(resolved: Any, kind: str, name: str) -> Any:
    """``enabled`` in the section ``AshConfig.get_plugin_config`` finds for ``name``."""
    found = resolved.get_plugin_config(kind, name)
    if hasattr(found, "model_dump"):
        found = found.model_dump(by_alias=True)
    return (found or {}).get("enabled")


@pytest.mark.parametrize(
    "kind, written, name",
    [
        pytest.param("reporter", "CSV", "csv", id="CSV"),
        pytest.param("reporter", "CsvReporter", "csv", id="CsvReporter"),
        pytest.param("reporter", "csv", "csv", id="csv"),
        pytest.param(
            "scanner",
            "DetectSecretsScanner",
            "detect-secrets",
            id="DetectSecretsScanner",
        ),
        pytest.param("reporter", None, "csv", id="control-no-section"),
    ],
)
@pytest.mark.unit
def test_a_plugins_section_is_found_by_its_name_whatever_the_spelling(
    tmp_path: Path, kind: str, written: Optional[str], name: str
) -> None:
    """configure.md (Share settings with `extends`).

    An operator config writes ``enabled: false`` under one spelling of a plugin's
    section, and is resolved as a scan resolves it. The section the plugin lookup
    finds by the plugin's own name must hold it. The control writes no section, so the
    lookup finds the plugin on, which shows the spellings are what turned it off.
    """
    assert_on_page(CONFIGURE, _A_SECTION_IS_FOUND_BY_THE_PLUGINS_NAME)
    from automated_security_helper.config.resolve_config import resolve_config

    document: Dict[str, Any] = {"project_name": "spellings"}
    if written is not None:
        document[f"{kind}s"] = {written: {"enabled": False}}
    config = _operator_config(tmp_path, yaml.safe_dump(document))
    source = tmp_path / "source"
    source.mkdir()

    resolved = resolve_config(config_path=config, source_dir=source)

    assert _enabled(resolved, kind, name) is (written is None), (written, name)


@pytest.mark.parametrize("child_writes", [True, False], ids=["child", "control-base"])
@pytest.mark.unit
def test_a_childs_spelling_of_a_section_its_base_writes_is_that_section(
    tmp_path: Path, child_writes: bool
) -> None:
    """configure.md (Share settings with `extends`).

    A base writes ``csv`` and a third-party ``page-claims-x`` section with ``enabled:
    false``; the operator config that extends it writes ``CSV`` and ``PageClaimsX`` with
    ``enabled: true``. The merged config must hold the built-in plugin's section under
    ``csv`` and the other under ``PageClaimsX``, one key each, and the lookup must find
    both on. The control's child writes neither, and the lookup finds the base's off.
    """
    assert_on_page(CONFIGURE, _A_CHILDS_SPELLING_IS_THAT_SECTION)
    from automated_security_helper.config.resolve_config import resolve_config

    off = {"csv": {"enabled": False}, "page-claims-x": {"enabled": False}}
    _operator_config(
        tmp_path,
        yaml.safe_dump({"project_name": "base", "reporters": off}),
        name="base.yaml",
    )
    child: Dict[str, Any] = {"extends": "./base.yaml"}
    if child_writes:
        child["reporters"] = {
            "CSV": {"enabled": True},
            "PageClaimsX": {"enabled": True},
        }
    config = _operator_config(tmp_path, yaml.safe_dump(child))
    source = tmp_path / "source"
    source.mkdir()

    resolved = resolve_config(config_path=config, source_dir=source)
    held = sorted(
        key
        for key in resolved.model_dump(by_alias=True)["reporters"]
        if key.lower().replace("-", "") in ("csv", "pageclaimsx")
    )

    if child_writes:
        assert held == ["PageClaimsX", "csv"], held
    else:
        assert held == ["csv", "page-claims-x"], held
    assert _enabled(resolved, "reporter", "csv") is child_writes
    assert _enabled(resolved, "reporter", "page-claims-x") is child_writes


@pytest.mark.parametrize("command", ["scan", "validate"])
@pytest.mark.parametrize("spellings", [2, 1], ids=["two-spellings", "control-one"])
@pytest.mark.integration
def test_a_file_that_writes_two_spellings_of_a_section_is_refused(
    tmp_path: Path, command: str, spellings: int
) -> None:
    """configure.md (Share settings with `extends`), and exit-codes.md (ash scan, ash
    config).

    An operator config writes detect-secrets' section as ``detect-secrets`` and as
    ``DETECT_SECRETS``, the second with a ``baseline_file`` value. A scan and ``ash
    config validate`` with that file must exit 3, naming both spellings and not the
    value. The control writes ``DETECT_SECRETS`` alone, which both accept.
    """
    assert_on_page(CONFIGURE, _TWO_SPELLINGS_ARE_REFUSED)
    for row in _TWO_SPELLINGS_ROWS:
        assert_on_page(EXIT_CODES, row)
    value = "page-claims-spelling-value-7c41.json"
    sections: Dict[str, Any] = {"DETECT_SECRETS": {"enabled": True}}
    if spellings == 2:
        sections = {
            "detect-secrets": {"enabled": True},
            "DETECT_SECRETS": {"enabled": True, "options": {"baseline_file": value}},
        }
    config = _operator_config(
        tmp_path, yaml.safe_dump({"project_name": "spellings", "scanners": sections})
    )
    if command == "scan":
        tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
        args = [*_CONFIG_SCAN, "--offline", "--source-dir", str(tree)]
        args += ["--output-dir", str(tmp_path / "out"), "--config", str(config)]
    else:
        args = ["config", "validate", "--config", str(config)]

    result = _ash(args, cwd=tmp_path)
    text = _squeezed(result.stdout + result.stderr)

    if spellings == 1:
        assert result.returncode == 0, _output_tail(result)
        return
    assert result.returncode == 3, _output_tail(result)
    assert _squeezed("'DETECT_SECRETS' and 'detect-secrets'") in text, _output_tail(
        result
    )
    assert value not in result.stdout + result.stderr, _output_tail(result)


@pytest.mark.parametrize(
    "how", ["patch", "overrides", "control-neither"], ids=lambda how: how
)
@pytest.mark.unit
def test_patch_paths_and_overrides_reach_a_section_as_its_name_is_matched(
    tmp_path: Path, how: str
) -> None:
    """configure.md (Share settings with `extends`; Override settings for one run).

    A base turns csv and detect-secrets on under their own names. The config that
    extends it patches ``/reporters/CSV/enabled`` and
    ``/scanners/detect_secrets/enabled`` to false, or the base alone is resolved with
    ``--config-overrides reporters.CSV.enabled=false``. The lookup must find what each
    turned off. The control does neither, and finds both on.
    """
    assert_on_page(CONFIGURE, _PATCH_PATHS_MATCH_A_SECTION)
    assert_on_page(CONFIGURE, _OVERRIDES_MATCH_A_SECTION)
    from automated_security_helper.config.resolve_config import resolve_config

    base = _operator_config(
        tmp_path,
        yaml.safe_dump(
            {
                "project_name": "base",
                "reporters": {"csv": {"enabled": True}},
                "scanners": {"detect-secrets": {"enabled": True}},
            }
        ),
        name="base.yaml",
    )
    config, overrides = base, []
    if how == "patch":
        config = _operator_config(
            tmp_path,
            yaml.safe_dump(
                {
                    "extends": "./base.yaml",
                    "patch": [
                        {
                            "op": "replace",
                            "path": "/reporters/CSV/enabled",
                            "value": False,
                        },
                        {
                            "op": "replace",
                            "path": "/scanners/detect_secrets/enabled",
                            "value": False,
                        },
                    ],
                }
            ),
        )
    elif how == "overrides":
        overrides = ["reporters.CSV.enabled=false"]
    source = tmp_path / "source"
    source.mkdir()

    resolved = resolve_config(
        config_path=config, source_dir=source, config_overrides=overrides
    )

    assert _enabled(resolved, "reporter", "csv") is (how == "control-neither")
    assert _enabled(resolved, "scanner", "detect-secrets") is (how != "patch")


#: configure.md (Share settings with `extends`): a recorded config with two spellings.
_A_RECORDED_CONFIG_IS_READ_NOT_REFUSED = (
    "A config that a results file recorded is read, not refused, by `ash report` and "
    "`ash merge`: of two such spellings in it, they read the one that the scan which "
    "recorded it read, and when the spelling not read sets a value the read one does "
    "not, a warning names the spellings and the one read, never a value."
)


@pytest.mark.parametrize("command", ["report", "merge"])
@pytest.mark.parametrize(
    "recorded",
    ["CSV-sets-other-values", "control-CSV-agrees", "control-one-spelling"],
)
@pytest.mark.integration
def test_report_and_merge_read_a_recorded_section_as_the_recording_scan_read_it(
    tmp_path: Path, command: str, recorded: str
) -> None:
    """configure.md (Share settings with `extends`).

    A one-shard scan's results record the csv reporter's section as ``csv``, and the
    test adds a second spelling, ``CSV``, that turns csv off and gives it another
    extension. ``ash report --format csv`` and ``ash merge`` of those results, run
    from an empty directory outside the trees, must exit 0 and warn, naming ``'csv'
    and 'CSV'`` and that ``'csv'`` is read, without the extension's value; ``ash
    merge`` writes ``reports/ash.csv``, the section the scan read. The controls
    record a ``CSV`` that agrees with ``csv``, and no second spelling: no warning.
    """
    assert_on_page(CONFIGURE, _A_RECORDED_CONFIG_IS_READ_NOT_REFUSED)
    output = _stored_scan(tmp_path)
    results = output / "ash_aggregated_results.json"
    document = json.loads(results.read_text(encoding="utf-8"))
    reporters = document["ash_config"]["reporters"]
    value = "page-claims-recorded-value-5b2e.csv"
    if recorded == "CSV-sets-other-values":
        reporters["CSV"] = {"enabled": False, "extension": value}
    elif recorded == "control-CSV-agrees":
        reporters["CSV"] = dict(reporters["csv"])
    results.write_text(json.dumps(document), encoding="utf-8")
    work = tmp_path / "work"
    work.mkdir()
    merged = tmp_path / "merged"
    if command == "report":
        args = ["report", "--format", "csv", "--output-dir", str(output)]
    else:
        args = ["merge", "--results", str(results), "--output-dir", str(merged)]

    result = _ash(args, cwd=work)
    text = _squeezed(result.stdout + result.stderr)
    warning = _squeezed(
        "The recorded configuration's reporters section holds 'csv' and 'CSV' for one "
        "plugin; the scan that recorded it read 'csv', so that is read here, not 'CSV'."
    )

    assert result.returncode == 0, _output_tail(result)
    if command == "merge":
        written = sorted(p.name for p in (merged / "reports").iterdir())
        assert "ash.csv" in written, written
        assert value not in " ".join(written), written
    assert (warning in text) is (recorded == "CSV-sets-other-values"), _output_tail(
        result
    )
    assert value not in result.stdout + result.stderr, _output_tail(result)


# --------------------------------------------------------------------------- #
# A client's runtime change to a profile
# --------------------------------------------------------------------------- #

#: mcp-server.md's bullet on what a client's runtime change cannot do to a reporter
#: that sends findings off the host (Config profiles).
_A_RUNTIME_CHANGE_LEAVES_OFF_HOST_REPORTERS = (
    "Such a change cannot turn a reporter that sends findings off the host on or off "
    "either. Turning one on, removing its section, or setting any of its options is "
    "refused. Its `enabled: false` for one of the four is not refused, but it has no "
    "effect: each runs as the profile says, and sends where the profile says."
)
_PROFILE_NAME = "page-claims"


def _profile_sending_to(directory: Path, bucket: str, **extra: Any) -> Path:
    """A profile file in ``directory`` that loads the AWS reporters' package, turns S3
    on for ``bucket``, runs detect-secrets alone, and lets a client change what is
    under ``/reporters`` and ``severity_threshold``, with ``extra`` top-level keys."""
    from automated_security_helper.config.ash_config import AshConfig

    builtin = AshConfig().scanners.model_dump(by_alias=True)
    document = {
        "project_name": "page-claims",
        "ash_plugin_modules": [_AWS_PLUGIN_MODULE],
        "global_settings": {
            "mcp": {
                "runtime_overrides": {
                    "enabled": True,
                    "allowed_paths": [
                        "/reporters/**",
                        "/global_settings/severity_threshold",
                    ],
                }
            }
        },
        "scanners": {name: {"enabled": name == "detect-secrets"} for name in builtin},
        "reporters": {
            "s3": {
                "enabled": True,
                "options": {"aws_region": "us-east-1", "bucket_name": bucket},
            }
        },
        **extra,
    }
    directory.mkdir(parents=True, exist_ok=True)
    profile = directory / "profile.yaml"
    profile.write_text(yaml.safe_dump(document), encoding="utf-8")
    return profile


def _a_workspace_of_one_project(parent: Path) -> Path:
    """A ``.code-workspace`` file with one project, ``api``, holding one file."""
    (parent / "ws" / "api").mkdir(parents=True)
    (parent / "ws" / "api" / "main.py").write_text("x = 1\n", encoding="utf-8")
    workspace = parent / "ws" / "services.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), "utf-8")
    return workspace


def _finished_mcp_scan(client: "_McpStdioClient", project: Path) -> Dict[str, Any]:
    """The last progress of a ``run_ash_scan`` of ``project`` that has finished."""
    begun = client.tool("run_ash_scan", source_dir=str(project))
    assert begun.get("success") is True, begun
    deadline = time.monotonic() + _MCP_STOP_SECONDS
    while True:
        progress = client.tool("get_scan_progress", scan_id=begun["scan_id"])
        if progress.get("is_complete") and progress.get("end_time"):
            return progress
        assert time.monotonic() < deadline, progress
        time.sleep(0.25)


@pytest.mark.parametrize(
    "how, change, accepted",
    [
        pytest.param(
            "patch_ops",
            [
                {
                    "op": "add",
                    "path": "/reporters/cloudwatch-logs",
                    "value": {"enabled": True},
                }
            ],
            False,
            id="patch-ops-turning-one-on",
        ),
        pytest.param(
            "patch_ops",
            [{"op": "remove", "path": "/reporters/s3"}],
            False,
            id="patch-ops-removing-its-section",
        ),
        pytest.param(
            "patch_ops",
            [
                {
                    "op": "replace",
                    "path": "/reporters/s3/options/bucket_name",
                    "value": "page-claims-elsewhere",
                }
            ],
            False,
            id="patch-ops-setting-an-option",
        ),
        pytest.param(
            "override_yaml",
            {"cloudwatch-logs": {"enabled": True}},
            False,
            id="override-yaml-turning-one-on",
        ),
        pytest.param(
            "config_overrides",
            ["reporters.cloudwatch-logs.enabled=true"],
            False,
            id="config-overrides-turning-one-on",
        ),
        pytest.param(
            "config_overrides",
            ["reporters.s3.options.bucket_name=page-claims-elsewhere"],
            False,
            id="config-overrides-setting-an-option",
        ),
        pytest.param(
            "patch_ops",
            [{"op": "replace", "path": "/reporters/s3/enabled", "value": False}],
            True,
            id="patch-ops-enabled-false-has-no-effect",
        ),
        pytest.param(
            "config_overrides",
            ["reporters.s3.enabled=false"],
            True,
            id="config-overrides-enabled-false-is-not-refused",
        ),
        pytest.param(
            "patch_ops",
            [
                {
                    "op": "replace",
                    "path": "/global_settings/severity_threshold",
                    "value": "LOW",
                }
            ],
            True,
            id="control-another-change-is-accepted",
        ),
    ],
)
@pytest.mark.e2e
def test_a_clients_runtime_change_cannot_turn_an_off_host_reporter_on_or_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    how: str,
    change: Any,
    accepted: bool,
) -> None:
    """mcp-server.md (Config profiles).

    A stdio server is started with a profile that turns S3 on for a bucket on a moto
    server on loopback and lets a client change what is under ``/reporters``. A
    client's change through ``select_profile``'s ``patch_ops`` or ``override_yaml``,
    or ``resolve_ash_workspace``'s ``config_overrides``, that turns an off-host
    reporter on, removes its section, or sets one of its options must be refused.
    ``enabled: false`` for S3 must not be refused, and must have no effect: a scan
    under the changed profile still uploads to the profile's bucket. The control is a
    change to ``severity_threshold``, which the same policy accepts.
    """
    assert_on_page(MCP_SERVER, _A_RUNTIME_CHANGE_LEAVES_OFF_HOST_REPORTERS)
    with _moto_bucket(monkeypatch) as (endpoint, client, bucket):
        profile = _profile_sending_to(tmp_path / "operator", bucket)
        env = _moto_child_environment(tmp_path, endpoint)
        env.pop("ASH_MCP_TRANSPORT", None)
        command = [*_ASH_MODULE, "mcp", "--quiet"]
        command += ["--profile", f"{_PROFILE_NAME}={profile}"]
        project = tmp_path / "project"
        project.mkdir()
        (project / "app.py").write_text("x = 1\n", encoding="utf-8")
        server = _McpStdioClient(command, project, env)
        try:
            if how == "config_overrides":
                answer = server.tool(
                    "resolve_ash_workspace",
                    workspace_file=str(_a_workspace_of_one_project(tmp_path)),
                    config_overrides=change,
                    profile=_PROFILE_NAME,
                )
            elif how == "override_yaml":
                document = yaml.safe_load(profile.read_text(encoding="utf-8"))
                document["reporters"].update(change)
                answer = server.tool(
                    "select_profile",
                    profile_name=_PROFILE_NAME,
                    override_yaml=yaml.safe_dump(document),
                )
            else:
                answer = server.tool(
                    "select_profile", profile_name=_PROFILE_NAME, patch_ops=change
                )
            assert (answer.get("success") is True) is accepted, answer
            if (
                accepted
                and how == "patch_ops"
                and change[0]["path"].startswith("/reporters/s3")
            ):
                progress = _finished_mcp_scan(server, project)
                uploaded = client.list_objects_v2(Bucket=bucket).get("Contents", [])
                assert len(uploaded) == 1, (progress, uploaded)
        finally:
            server.close()


#: mcp-server.md's sentence on how a refused change is reported (Config profiles).
_A_REFUSED_CHANGE_IS_REPORTED_WITHOUT_ITS_VALUE = (
    "A change that is refused, or that does not apply, is reported without its value: "
    "by its op and path, or, when an `override_yaml` does not parse or validate or a "
    "`config_overrides` entry leaves the config invalid, by the problem and where it "
    "is (the parser's position, the field, or the key)."
)
#: A value only the client sends, in the change it asks for.
_CLIENT_VALUE = "page-claims-client-value-51b9"


def _profile_reading_a_value(directory: Path) -> Path:
    """A profile file in ``directory`` whose ``project_name`` is read from
    ``_ENV_PROBE`` and which lets a client change ``project_name`` and what is under
    ``/global_settings``, except ``ignore_paths``."""
    directory.mkdir(parents=True, exist_ok=True)
    profile = directory / "profile.yaml"
    profile.write_text(
        f"project_name: {_REFERENCE}\n"
        + yaml.safe_dump(
            {
                "global_settings": {
                    "mcp": {
                        "runtime_overrides": {
                            "enabled": True,
                            "allowed_paths": ["/project_name", "/global_settings/**"],
                            "denied_paths": ["/global_settings/ignore_paths"],
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return profile


@pytest.mark.parametrize(
    "how, change, named",
    [
        pytest.param(
            "patch_ops",
            [{"op": "test", "path": "/project_name", "value": _CLIENT_VALUE}],
            "'test' at '/project_name'",
            id="a-test-that-fails",
        ),
        pytest.param(
            "patch_ops",
            [
                {
                    "op": "replace",
                    "path": "/global_settings/page_claims_missing/member",
                    "value": _CLIENT_VALUE,
                }
            ],
            "'replace' at '/global_settings/page_claims_missing/member'",
            id="a-missing-member",
        ),
        pytest.param(
            "patch_ops",
            [
                {
                    "op": "add",
                    "path": "/global_settings/ignore_paths/-",
                    "value": _CLIENT_VALUE,
                }
            ],
            "'add' at '/global_settings/ignore_paths/-'",
            id="an-add-that-is-denied",
        ),
        pytest.param(
            "patch_ops",
            [{"op": "add", "path": "/scanners/bandit", "value": _CLIENT_VALUE}],
            "'add' at '/scanners/bandit'",
            id="a-path-not-allowed",
        ),
        pytest.param(
            "patch_ops",
            [{"op": "copy", "path": "/project_name", "value": _CLIENT_VALUE}],
            "'copy' at '/project_name'",
            id="a-malformed-op",
        ),
        pytest.param(
            "override_yaml",
            {"ignore_paths": [{"path": _CLIENT_VALUE, "reason": "page claims"}]},
            "'/global_settings/ignore_paths",
            id="an-override-that-is-denied",
        ),
        pytest.param(
            "override_yaml",
            "project_name: [" + _CLIENT_VALUE + "\n",
            "override_yaml parse error",
            id="an-override-that-does-not-parse",
        ),
        pytest.param(
            "override_yaml",
            "global_settings:\n  severity_threshold: " + _CLIENT_VALUE + "\n",
            "severity_threshold",
            id="an-override-that-does-not-validate",
        ),
        pytest.param(
            "config_overrides",
            ["global_settings.severity_threshold=" + _CLIENT_VALUE],
            "'global_settings.severity_threshold'",
            id="config-overrides-leaving-the-config-invalid",
        ),
    ],
)
@pytest.mark.e2e
def test_a_refused_runtime_change_is_reported_without_its_value(
    tmp_path: Path, how: str, change: Any, named: str
) -> None:
    """mcp-server.md (Config profiles).

    A stdio server is started with a profile that reads ``project_name`` from a
    variable the server's environment holds and lets a client change some of what is
    under ``/global_settings``. Each change the client asks for here is refused, or
    does not apply: a ``patch_ops`` test that fails, a member that is missing, an add
    that is denied, a path that is not allowed, and an op that is not one ASH takes;
    an ``override_yaml`` that is denied, does not parse, or does not validate; and a
    ``config_overrides`` entry that leaves the config invalid. Each reply must say it
    failed and name the op and path, or the problem and where it is, and must hold
    neither the value the client sent nor the value the server read. The control is
    that the server did read the value: the same profile resolved with the variable
    set has it as its ``project_name``.
    """
    assert_on_page(MCP_SERVER, _A_REFUSED_CHANGE_IS_REPORTED_WITHOUT_ITS_VALUE)
    profile = _profile_reading_a_value(tmp_path / "operator")
    env = {**_mcp_child_env(tmp_path), _ENV_PROBE: _ENV_PROBE_VALUE}
    from automated_security_helper.config.resolve_config import resolve_config

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv(_ENV_PROBE, _ENV_PROBE_VALUE)
        control = resolve_config(config_path=profile, source_dir=profile.parent)
    assert control.project_name == _ENV_PROBE_VALUE, control.project_name

    command = [*_ASH_MODULE, "mcp", "--quiet"]
    command += ["--profile", f"{_PROFILE_NAME}={profile}"]
    server = _McpStdioClient(command, tmp_path, env)
    try:
        if how == "config_overrides":
            answer = server.tool(
                "resolve_ash_workspace",
                workspace_file=str(_a_workspace_of_one_project(tmp_path)),
                config_overrides=change,
                profile=_PROFILE_NAME,
            )
        else:
            if isinstance(change, dict):
                # The profile as written, with the client's change to its
                # global_settings on top, so the change is the only difference the
                # server checks.
                document = yaml.safe_load(profile.read_text(encoding="utf-8"))
                document["global_settings"].update(change)
                change = yaml.safe_dump(document)
            answer = server.tool(
                "select_profile", profile_name=_PROFILE_NAME, **{how: change}
            )
    finally:
        server.close()

    reply = json.dumps(answer)
    assert answer.get("success") is False, answer
    assert named in reply, answer
    assert _CLIENT_VALUE not in reply, answer
    assert _ENV_PROBE_VALUE not in reply, answer


#: mcp-server.md's sentence on a profile that holds a value read from the
#: environment inside a longer string (Config profiles).
_A_VALUE_INSIDE_A_LONGER_STRING_IS_REFUSED = (
    "A profile in which such a value is part of a longer string, such as a relative "
    "path that ASH takes from the profile's directory (`${VAR}/bandit.yaml`), can't be "
    "written to a session with its reference, so `select_profile`, and a workspace "
    "scan's `profile`, refuse it without naming the value."
)
#: A client change the profile below allows.
_ADD_AN_IGNORE_PATH = [
    {
        "op": "add",
        "path": "/global_settings/ignore_paths/-",
        "value": {"path": "mine", "reason": "page claims"},
    }
]


def _profile_anchoring_a_value(directory: Path) -> Path:
    """A profile file in ``directory`` whose bandit config file and a sandbox read
    grant are paths under ``_ENV_PROBE``'s value, and which lets a client add to
    ``ignore_paths``."""
    directory.mkdir(parents=True, exist_ok=True)
    profile = directory / "profile.yaml"
    profile.write_text(
        "project_name: page-claims\n"
        "scanners:\n"
        "  bandit:\n"
        "    options:\n"
        f"      config_file: {_REFERENCE}/bandit.yaml\n"
        "sandbox:\n"
        "  extra_read_paths:\n"
        f"    - {_REFERENCE}/read\n"
        + yaml.safe_dump(
            {
                "global_settings": {
                    "mcp": {
                        "runtime_overrides": {
                            "enabled": True,
                            "allowed_paths": ["/global_settings/ignore_paths/-"],
                            "denied_paths": [],
                            "replace_default_denied_paths": True,
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return profile


def _files_holding(root: Path, text: str) -> List[str]:
    """The files under ``root`` whose bytes hold ``text``."""
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and text.encode("utf-8") in path.read_bytes()
    )


@pytest.mark.parametrize(
    "how, value",
    [
        pytest.param("select_profile", "relative", id="select-profile"),
        pytest.param(
            "select_profile_with_patch_ops",
            "relative",
            id="select-profile-with-patch-ops",
        ),
        pytest.param("workspace_scan", "relative", id="a-workspace-scan-with-it"),
        pytest.param("select_profile", "absolute", id="control-an-absolute-value"),
    ],
)
@pytest.mark.e2e
def test_a_profile_holding_an_environment_value_inside_a_path_is_refused_without_it(
    tmp_path: Path, how: str, value: str
) -> None:
    """mcp-server.md (Config profiles).

    A stdio server is started with a profile whose bandit config file and sandbox
    read grant are ``${VAR}/bandit.yaml`` and ``${VAR}/read``, with the variable a
    relative path, so the profile holds the value inside a longer path.
    ``select_profile``, with and without ``patch_ops``, and ``run_ash_workspace_scan``
    with the profile must refuse it, the reply must not hold the value, and no file
    under the test's directory, the session workspace and the server's home among
    them, may hold it. The control is the same profile with an absolute value, which
    is a whole path the reference stands for: ``select_profile`` binds it.
    """
    assert_on_page(MCP_SERVER, _A_VALUE_INSIDE_A_LONGER_STRING_IS_REFUSED)
    profile = _profile_anchoring_a_value(tmp_path / "operator")
    held = (
        _ENV_PROBE_VALUE
        if value == "relative"
        else str(tmp_path / "absolute" / _ENV_PROBE_VALUE)
    )
    env = {**_mcp_child_env(tmp_path), _ENV_PROBE: held}
    command = [*_ASH_MODULE, "mcp", "--quiet"]
    command += ["--profile", f"{_PROFILE_NAME}={profile}"]
    server = _McpStdioClient(command, tmp_path, env)
    try:
        if how == "workspace_scan":
            answer = server.tool(
                "run_ash_workspace_scan",
                workspace_file=str(_a_workspace_of_one_project(tmp_path)),
                profile=_PROFILE_NAME,
            )
        elif how == "select_profile_with_patch_ops":
            answer = server.tool(
                "select_profile",
                profile_name=_PROFILE_NAME,
                patch_ops=_ADD_AN_IGNORE_PATH,
            )
        else:
            answer = server.tool("select_profile", profile_name=_PROFILE_NAME)
    finally:
        server.close()

    if value == "absolute":
        assert answer.get("success") is True, answer
        return
    assert answer.get("success") is False, answer
    assert _ENV_PROBE_VALUE not in json.dumps(answer), answer
    assert _files_holding(tmp_path, _ENV_PROBE_VALUE) == []


@pytest.mark.parametrize(
    "how",
    [
        pytest.param("select_profile", id="select-profile"),
        pytest.param(
            "select_profile_with_patch_ops", id="select-profile-with-patch-ops"
        ),
        pytest.param("workspace_scan", id="a-workspace-scan-with-it"),
    ],
)
@pytest.mark.e2e
def test_a_refused_profile_leaves_no_file_holding_the_environment_value(
    tmp_path: Path, how: str
) -> None:
    """mcp-server.md (Config profiles). The planted control for the refusal above.

    The same server and profile, bound the same ways, with the answer's
    ``success`` left unread: the refusal must come before the write, so a
    refusal that had already written the session's copy fails here. A file
    holding the value is planted first, and the scan for it must find that one
    file, so an empty answer afterwards is not a scan that cannot see.
    """
    assert_on_page(MCP_SERVER, _A_VALUE_INSIDE_A_LONGER_STRING_IS_REFUSED)
    planted = tmp_path / "planted-control.txt"
    planted.write_text(_ENV_PROBE_VALUE, encoding="utf-8")
    assert _files_holding(tmp_path, _ENV_PROBE_VALUE) == [planted.name]
    planted.unlink()
    profile = _profile_anchoring_a_value(tmp_path / "operator")
    env = {**_mcp_child_env(tmp_path), _ENV_PROBE: _ENV_PROBE_VALUE}
    command = [*_ASH_MODULE, "mcp", "--quiet"]
    command += ["--profile", f"{_PROFILE_NAME}={profile}"]
    server = _McpStdioClient(command, tmp_path, env)
    try:
        if how == "workspace_scan":
            answer = server.tool(
                "run_ash_workspace_scan",
                workspace_file=str(_a_workspace_of_one_project(tmp_path)),
                profile=_PROFILE_NAME,
            )
        elif how == "select_profile_with_patch_ops":
            answer = server.tool(
                "select_profile",
                profile_name=_PROFILE_NAME,
                patch_ops=_ADD_AN_IGNORE_PATH,
            )
        else:
            answer = server.tool("select_profile", profile_name=_PROFILE_NAME)
    finally:
        server.close()

    assert _ENV_PROBE_VALUE not in json.dumps(answer), answer
    assert _files_holding(tmp_path, _ENV_PROBE_VALUE) == []


@pytest.mark.e2e
def test_a_workspace_scan_refuses_a_value_inside_a_path_under_the_select_profile_error_type(
    tmp_path: Path,
) -> None:
    """mcp-server.md (Config profiles).

    The page names one refusal for ``select_profile`` and a workspace scan's
    ``profile``, so a client that branches on ``error_type`` reads one spelling
    from either tool: ``environment_value_in_longer_string``, not the name of the
    exception class. The reply still must not hold the value.
    """
    assert_on_page(MCP_SERVER, _A_VALUE_INSIDE_A_LONGER_STRING_IS_REFUSED)
    profile = _profile_anchoring_a_value(tmp_path / "operator")
    env = {**_mcp_child_env(tmp_path), _ENV_PROBE: _ENV_PROBE_VALUE}
    command = [*_ASH_MODULE, "mcp", "--quiet"]
    command += ["--profile", f"{_PROFILE_NAME}={profile}"]
    server = _McpStdioClient(command, tmp_path, env)
    try:
        answer = server.tool(
            "run_ash_workspace_scan",
            workspace_file=str(_a_workspace_of_one_project(tmp_path)),
            profile=_PROFILE_NAME,
        )
    finally:
        server.close()

    assert answer.get("success") is False, answer
    assert answer["error_type"] == "environment_value_in_longer_string", answer
    assert _ENV_PROBE_VALUE not in json.dumps(answer), answer


# --------------------------------------------------------------------------- #
# A value read from the environment in a message
# --------------------------------------------------------------------------- #

#: configure.md's paragraph on how messages show a value read from the environment
#: (Check a config).
_MESSAGES_SHOW_A_VALUE_AS_A_MARKER = (
    "In the messages of the `ash config` commands, and of a scan that refuses a "
    "config, a value that a reference read from the environment is shown as "
    "`<value>` where the message quotes it, however short the value is, so the "
    "commands do not print what the variable holds. A value that a field taking a "
    "fixed choice, a boolean, or a number refuses is not quoted at all: the message "
    "names the field and what it takes."
)


@pytest.mark.parametrize("command", ["config-validate", "config-get", "scan"])
@pytest.mark.parametrize(
    "value", [_ENV_PROBE_VALUE, "Zq"], ids=["a-long-value", "a-two-character-value"]
)
@pytest.mark.parametrize(
    "config, shown",
    [
        pytest.param(
            f"project_name: page-claims\nextends: {_REFERENCE}\n",
            "'extends: <value>'",
            id="a-base-the-message-quotes",
        ),
        pytest.param(
            f"project_name: page-claims\nglobal_settings:\n"
            f"  severity_threshold: {_REFERENCE}\n",
            "global_settings.severity_threshold",
            id="a-fixed-choice-field",
        ),
        pytest.param(
            f"project_name: page-claims\nfail_on_findings: {_REFERENCE}\n",
            "fail_on_findings",
            id="a-boolean-field",
        ),
    ],
)
@pytest.mark.integration
def test_a_message_never_prints_a_value_read_from_the_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    value: str,
    config: str,
    shown: str,
) -> None:
    """configure.md (Check a config).

    An operator's config file reads a value from the environment where it cannot
    be used: as the path of a base that does not exist, as ``severity_threshold``,
    a field that takes a fixed choice, and as ``fail_on_findings``, a boolean. With
    a long value and with a two-character one, ``ash config validate``, ``ash
    config get`` and a scan must refuse the file, and none may print the value. A
    message that quotes the base must show it as ``<value>``; one about a field
    must name the field and what it takes, and quote nothing, ``<value>`` included.
    A scan and ``ash config get`` exit 3; the code ``validate`` gives is pinned by
    test_config_validate_exits_with_the_code_a_scan_would_give_the_config.
    """
    assert_on_page(CONFIGURE, _MESSAGES_SHOW_A_VALUE_AS_A_MARKER)
    file = _operator_config(tmp_path, config)
    monkeypatch.setenv(_ENV_PROBE, value)
    if command == "scan":
        tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
        args = [*_CONFIG_SCAN, "--offline", "--source-dir", str(tree)]
        args += ["--output-dir", str(tmp_path / "out"), "--config", str(file)]
    else:
        args = ["config", command.removeprefix("config-"), "--config", str(file)]

    result = _ash(args, cwd=tmp_path)
    text = _squeezed(result.stdout + result.stderr)

    if command == "config-validate":
        assert result.returncode != 0, _output_tail(result)
    else:
        assert result.returncode == 3, _output_tail(result)
    assert value not in text, _output_tail(result)
    assert _squeezed(shown) in text, _output_tail(result)
    if shown.startswith("'extends"):
        return
    assert "<value>" not in text, _output_tail(result)
    takes = (
        "Input should be 'ALL', 'LOW', 'MEDIUM', 'HIGH' or 'CRITICAL'"
        if "severity" in shown
        else "Input should be a valid boolean"
    )
    assert _squeezed(takes) in text, _output_tail(result)


# --------------------------------------------------------------------------- #
# A changed-files scan and a submodule moved to another commit
# --------------------------------------------------------------------------- #

#: scale-large-repos.md's sentence on a submodule a change moves (Gate on the files a
#: change touches).
_A_MOVED_SUBMODULE_COUNTS_AS_CHANGED = (
    "When the change moves a submodule to another commit, `git diff` lists only the "
    "submodule's path, and every file inside the submodule counts as changed."
)


def _git(cwd: Path, *args: str) -> str:
    """``git args`` in ``cwd``, with no global or system config, a fixed identity, and
    local file URLs allowed for ``submodule add``; returns standard output."""
    environment = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=page-claims",
            "-c",
            "user.email=page-claims@example.invalid",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "protocol.file.allow=always",
            *args,
        ],
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result.stdout


@pytest.mark.integration
def test_a_changed_files_scan_counts_every_file_in_a_moved_submodule_as_changed(
    tmp_path: Path,
) -> None:
    """scale-large-repos.md (Gate on the files a change touches).

    A repository has the sample's ``app.py``, with a detect-secrets finding, and a
    submodule ``sub`` whose ``lib.py`` has another. A branch moves ``sub`` to the next
    commit of its own repository, which changes only ``sub/notes.txt``, and touches no
    other file. ``git diff --name-only main...HEAD`` must list only ``sub``. A scan
    with ``--changed-files-only --base-ref main`` must keep the finding in the
    unchanged ``sub/lib.py`` and drop the one in ``app.py``, and exit 2 for it. The
    control is detect-secrets' own output under ``scanners/``, which still has the
    finding in ``app.py``.
    """
    assert_on_page(SCALE_LARGE_REPOS, _A_MOVED_SUBMODULE_COUNTS_AS_CHANGED)
    origin = tmp_path / "sub-origin"
    origin.mkdir()
    _git(origin, "init", "-q")
    (origin / "lib.py").write_text(_OUTPUTS_APP, encoding="utf-8")
    (origin / "notes.txt").write_text("first\n", encoding="utf-8")
    _git(origin, "add", ".")
    _git(origin, "commit", "-q", "-m", "first")
    first = _git(origin, "rev-parse", "HEAD").strip()
    (origin / "notes.txt").write_text("first\nsecond\n", encoding="utf-8")
    _git(origin, "commit", "-q", "-am", "second")
    second = _git(origin, "rev-parse", "HEAD").strip()

    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    (repository / "app.py").write_text(_OUTPUTS_APP, encoding="utf-8")
    _git(repository, "submodule", "add", "-q", str(origin), "sub")
    _git(repository / "sub", "checkout", "-q", first)
    _git(repository, "add", ".")
    _git(repository, "commit", "-q", "-m", "app and sub")
    _git(repository, "switch", "-q", "-c", "move-sub")
    _git(repository / "sub", "checkout", "-q", second)
    _git(repository, "add", "sub")
    _git(repository, "commit", "-q", "-m", "move sub")
    listed = _git(repository, "diff", "--name-only", "main...HEAD").split()
    assert listed == ["sub"], listed

    output = tmp_path / "out"
    result = _ash(
        [
            *_CONFIG_SCAN,
            "--offline",
            "--source-dir",
            str(repository),
            "--output-dir",
            str(output),
            "--changed-files-only",
            "--base-ref",
            "main",
        ],
        cwd=tmp_path,
    )

    def finding_files(sarif: Path) -> List[str]:
        document = json.loads(sarif.read_text(encoding="utf-8"))
        return sorted(
            location["physicalLocation"]["artifactLocation"]["uri"]
            for run in document["runs"]
            for finding in run.get("results", [])
            for location in finding.get("locations", [])[:1]
        )

    assert result.returncode == 2, _output_tail(result)
    scanned = finding_files(
        output / "scanners" / "detect-secrets" / "source" / "results_sarif.sarif"
    )
    assert "app.py" in scanned, scanned
    files = finding_files(output / "reports" / "ash.sarif")
    assert files and all(name.endswith("sub/lib.py") for name in files), files


# --------------------------------------------------------------------------- #
# The AWS variables a container scan passes in
# --------------------------------------------------------------------------- #

#: aws.md's sentences on what a container scan passes in (Destinations and
#: credentials).
_A_CONTAINER_SCAN_PASSES_NO_CREDENTIALS = (
    "In container mode, the scan runs inside the container, and the host's credential "
    "files and credential variables, such as `AWS_ACCESS_KEY_ID`, are not passed in"
)
_A_CONTAINER_SCAN_PASSES_THE_AWS_SETTINGS = (
    "`AWS_REGION`, `AWS_DEFAULT_REGION`, and `AWS_PROFILE` are passed in only when "
    "your own config file reads them and they are set"
)
#: A config that reads the three AWS settings, and two names no config may read.
_A_CONFIG_READING_THE_AWS_VARIABLES = (
    "reporters:\n"
    "  s3:\n"
    "    options:\n"
    "      aws_region: ${AWS_REGION:us-east-1}\n"
    "      aws_profile: ${AWS_PROFILE:}\n"
    "      bucket_name: ${AWS_ACCESS_KEY_ID:page-claims-bucket}\n"
    "  cloudwatch-logs:\n"
    "    options:\n"
    "      aws_region: ${AWS_DEFAULT_REGION:us-east-1}\n"
    "      log_group_name: ${AWS_SHARED_CREDENTIALS_FILE:page-claims-group}\n"
)


@pytest.mark.parametrize(
    "where, profile, passed",
    [
        pytest.param(
            "the-operators-config",
            None,
            ["AWS_DEFAULT_REGION", "AWS_REGION"],
            id="the-operators-config-with-aws-profile-unset",
        ),
        pytest.param(
            "the-operators-config",
            "page-claims-profile",
            ["AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_REGION"],
            id="the-operators-config-with-all-three-set",
        ),
        pytest.param(
            "a-config-in-the-tree", "page-claims-profile", [], id="a-config-in-the-tree"
        ),
    ],
)
@pytest.mark.unit
def test_a_container_scan_passes_only_the_aws_settings_the_operators_config_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    where: str,
    profile: Optional[str],
    passed: List[str],
) -> None:
    """aws.md (Destinations and credentials).

    A config file reads ``AWS_REGION``, ``AWS_DEFAULT_REGION`` and ``AWS_PROFILE``,
    and writes ``AWS_ACCESS_KEY_ID`` and ``AWS_SHARED_CREDENTIALS_FILE`` references
    too, all set in the environment but ``AWS_PROFILE`` in one case. As the
    operator's ``--config``, outside the scanned tree, the variables a container
    scan passes in (``run_ash_container.operator_environment_names``) must be the
    settings that are set, and the env file a wrapped runner reads must hold just
    those values. The same file inside the scanned tree must pass in none of them.
    No credential variable is ever passed. No image is built or run.
    """
    assert_on_page(AWS_PLUGINS, _A_CONTAINER_SCAN_PASSES_NO_CREDENTIALS)
    assert_on_page(AWS_PLUGINS, _A_CONTAINER_SCAN_PASSES_THE_AWS_SETTINGS)
    from automated_security_helper.interactions import run_ash_container as container

    source = tmp_path / "source"
    (source / ".ash").mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    if where == "a-config-in-the-tree":
        config = source / ".ash" / ".ash.yaml"
        config.write_text(_A_CONFIG_READING_THE_AWS_VARIABLES, encoding="utf-8")
    else:
        config = _operator_config(tmp_path, _A_CONFIG_READING_THE_AWS_VARIABLES)
    set_here = {
        "AWS_REGION": "us-west-2",
        "AWS_DEFAULT_REGION": "eu-west-1",
        "AWS_ACCESS_KEY_ID": "page-claims-access-key-id",
        "AWS_SHARED_CREDENTIALS_FILE": str(tmp_path / "credentials"),
    }
    if profile is not None:
        set_here["AWS_PROFILE"] = profile
    for name, value in set_here.items():
        monkeypatch.setenv(name, value)
    if profile is None:
        monkeypatch.delenv("AWS_PROFILE", raising=False)

    names = container.operator_environment_names(str(config), None, source)

    assert names == passed, names
    if not names:
        return
    directory, env_file = container._write_env_file(
        names, dict(os.environ), "docker", source, tmp_path / "output"
    )
    try:
        written = env_file.read_text(encoding="utf-8").splitlines()
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    assert written == [f"{name}={set_here[name]}" for name in passed], written


# --------------------------------------------------------------------------- #
# A relative path from the environment: the bin directory and the runtime
# --------------------------------------------------------------------------- #

#: advanced-usage.md's step 2 of where ASH looks for a tool, and its sentence on a
#: relative ``--bin-path`` (Install tools with `ash dependencies install`).
_A_RELATIVE_ASH_BIN_PATH_IS_NOT_USED = (
    "The directory in `ASH_BIN_PATH`, or `~/.ash/bin` if it is not set or is empty. "
    "This is where `ash dependencies install` puts tools, so you do not need to add it "
    "to `PATH`. A `~` at the start of the value is expanded. A relative `ASH_BIN_PATH` "
    "is not used: ASH logs a warning that names it and uses `~/.ash/bin`, for lookups "
    "and for `ash dependencies install` alike."
)
#: The same step's sentences on the home directory those need.
_THE_BIN_DIRECTORY_NEEDS_A_USABLE_HOME = (
    "`~/.ash/bin`, and a `~` in `ASH_BIN_PATH`, need a usable home directory: `HOME` "
    "when it is set to an absolute path, or, when `HOME` is not set, the home in your "
    "passwd entry if that is absolute (on Windows, the profile directory). With `HOME` "
    "empty or relative, or unset with no absolute home in the passwd entry, ASH logs a "
    "warning and uses nothing under `~`, so this step uses only an absolute "
    "`ASH_BIN_PATH`."
)
_A_RELATIVE_BIN_PATH_OPTION = (
    "A relative `--bin-path` is read against the directory you run the command in."
)
#: advanced-usage.md (Install tools with `ash dependencies install`) and exit-codes.md's
#: row for code 3 of `ash dependencies install`, on installing with no usable home.
_NO_USABLE_HOME_INSTALLS_NOTHING = [
    (
        ADVANCED_USAGE,
        (
            "The command records each install in a receipt under `~/.ash`, which a "
            "later install checks the tool against, so with no usable home directory it "
            "installs nothing, even with `--bin-path`, and exits with code 3, saying why."
        ),
    ),
    (
        EXIT_CODES,
        (
            "or there is no usable home directory, so nowhere to keep install receipts, "
            "whatever `--bin-path` says: `HOME` is empty or relative, or unset with no "
            "absolute home in the passwd entry. Nothing is installed"
        ),
    ),
]
#: run-in-a-container.md's paragraph on the runtime's value (Choose the container
#: runtime).
_HOW_THE_RUNTIME_VALUE_IS_READ = [
    (
        "Each of these takes a command name or an absolute path, and so does the "
        "`oci_runner` of a `--cli-json-input` document, which ASH reads as if you had "
        "typed it as `--oci-runner`."
    ),
    (
        "A `~` or `~user` at the start is expanded, so `~/bin/docker` names "
        "`$HOME/bin/docker`; in `OCI_RUNNER_WRAPPER` that applies to the first word."
    ),
    (
        "A `$` in the document's value is not expanded, so `$HOME/bin/docker` there is "
        "a relative path."
    ),
    (
        "With no usable home directory (`HOME` empty or relative, or unset with no "
        "absolute home in the passwd entry), a value that starts with `~/` is not used: "
        "ASH logs a warning about `HOME` and picks a runtime as if none were named, or, "
        "for the wrapper, starts the runtime without one."
    ),
    (
        "A relative path with a directory part, such as `bin/docker`, is read against "
        "the directory you run ASH in when you pass it to `--oci-runner` or give it in "
        "the document. In `OCI_RUNNER` it is not run: ASH logs a warning and picks a "
        "runtime as if none were named. As the first word of `OCI_RUNNER_WRAPPER` it is "
        "not used either, and the runtime starts without a wrapper, with a warning."
    ),
]


def _warns_naming(text: str, variable: str, value: str) -> bool:
    """Whether ``text`` holds a warning that names ``variable`` and its ``value``,
    quoted, which is as much as the pages say of the warning."""
    pattern = re.escape(variable) + r"[^']{0,40}" + re.escape(repr(value))
    return re.search(pattern, _squeezed(text)) is not None


def _warns_about_home(text: str) -> bool:
    """Whether ``text`` holds a warning about ``HOME``, which is as much as the pages
    say of it."""
    return "HOMEis" in _squeezed(text)


def _home_setting(kind: str, home: Path) -> Optional[str]:
    """``HOME`` for a child process: ``home``, empty, a relative path, or unset (None),
    when the passwd entry's home directory is the one used."""
    return {"absolute": str(home), "empty": "", "relative": "relhome", "unset": None}[
        kind
    ]


#: Looks each tool named on the command line up as a scan does, in a process whose
#: environment the test sets, and prints a JSON object of what it found.
_LOOK_UP_TOOLS = """\
import json, sys

from automated_security_helper.utils.subprocess_utils import find_executable

print(json.dumps({name: find_executable(name) for name in sys.argv[1:]}))
"""

#: Asks for the runtime and the wrapper as a container scan does, with the runtime
#: from OCI_RUNNER and as typed on the command line, and prints them as JSON.
_RESOLVE_THE_RUNTIME = """\
import json, os

from automated_security_helper.interactions import run_ash_container as container

print(json.dumps({
    "environment": container.oci_runner_for_this_run(os.environ["OCI_RUNNER"], True),
    "typed": container.oci_runner_for_this_run(os.environ["OCI_RUNNER"], False),
    "wrapper": container._get_oci_wrapper_prefix(),
}))
"""


def _child_answer(
    script: str, cwd: Path, home: Optional[str], args: List[str], **env: str
) -> Tuple[Any, str]:
    """``script`` run by this interpreter in ``cwd`` with ``home`` as its ``HOME``
    (unset for None) and ``env`` on top: (the JSON it printed, its standard error)."""
    environment = _ash_environment(cwd)
    if home is None:
        # Unset means the login database decides, which is POSIX's passwd entry.
        # The skip is here, not a per-cell mark, so every cell that passes None
        # is covered: on Windows ~ would be rebuilt from HOMEDRIVE+HOMEPATH and
        # reach the real profile.
        if os.name == "nt":
            pytest.skip(
                "an unset home on Windows is rebuilt from HOMEDRIVE+HOMEPATH, "
                "the real profile"
            )
        for name in ("HOME", "USERPROFILE"):
            environment.pop(name, None)
    else:
        environment.update(_home_override(home))
    for name in ("ASH_BIN_PATH", "OCI_RUNNER", "OCI_RUNNER_WRAPPER"):
        environment.pop(name, None)
    environment.update(env)
    # On the final environment, after the caller's overrides: a str(None) home
    # from any route would hand the child the relative path named "None".
    assert "None" not in (environment.get("HOME"), environment.get("USERPROFILE")), (
        "an unset home leaked into the child as the string 'None'"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, *args],
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, _output_tail(result)
    return json.loads(result.stdout.strip().splitlines()[-1]), result.stderr


@pytest.mark.parametrize(
    "value, home_kind, holder",
    [
        pytest.param("rel-bin", "absolute", "default", id="a-relative-value"),
        pytest.param(
            "~/tilde-bin", "absolute", "tilde", id="a-value-starting-with-tilde"
        ),
        pytest.param("", "absolute", "default", id="an-empty-value-counts-as-unset"),
        pytest.param(
            "ABSOLUTE", "absolute", "absolute", id="control-an-absolute-value"
        ),
        pytest.param("", "relative", None, id="a-relative-home-gives-no-default"),
        pytest.param(
            "~/tilde-bin", "relative", None, id="a-tilde-value-a-relative-home"
        ),
        pytest.param("", "empty", None, id="an-empty-home-gives-no-default"),
        pytest.param(
            "ABSOLUTE", "relative", "absolute", id="an-absolute-value-a-relative-home"
        ),
        pytest.param(
            "ABSOLUTE", "empty", "absolute", id="an-absolute-value-an-empty-home"
        ),
    ],
)
@pytest.mark.integration
def test_a_relative_ash_bin_path_is_not_used_and_the_default_bin_directory_is(
    tmp_path: Path, value: str, home_kind: str, holder: Optional[str]
) -> None:
    """advanced-usage.md (Where ASH looks for a tool).

    One tool is placed in each directory ``ASH_BIN_PATH`` could mean: ``rel-bin``
    under the working directory, ``tilde-bin`` under the home directory, an absolute
    directory, and ``~/.ash/bin``; with a relative ``HOME``, also ``tilde-bin`` and
    ``.ash/bin`` under the directory it names. A process with ``ASH_BIN_PATH`` set to
    each value looks them all up as a scan does. With an absolute ``HOME`` it must find
    only the tool in the directory the page names: ``~/.ash/bin`` for a relative or
    empty value, the home directory's for one starting with ``~``, and the absolute
    one's for the control. With ``HOME`` empty or relative it must find nothing under
    ``~``, only the tool of an absolute value, and log a warning about ``HOME`` when it
    needed the home directory. With an absolute ``HOME``, only the relative value is
    warned about, by a warning that names it, which is all the page says of the
    warnings.
    """
    assert_on_page(ADVANCED_USAGE, _A_RELATIVE_ASH_BIN_PATH_IS_NOT_USED)
    assert_on_page(ADVANCED_USAGE, _THE_BIN_DIRECTORY_NEEDS_A_USABLE_HOME)
    home, cwd = tmp_path / "home", tmp_path / "cwd"
    directories = {
        "relative": cwd / "rel-bin",
        "tilde": home / "tilde-bin",
        "absolute": tmp_path / "absolute-bin",
        "default": home / ".ash" / "bin",
        "tilde-under-a-relative-home": cwd / "relhome" / "tilde-bin",
        "default-under-a-relative-home": cwd / "relhome" / ".ash" / "bin",
    }
    tools = {where: _unique_tool() for where in directories}
    for where, directory in directories.items():
        _place_tool(directory, tools[where], "exec")
    if value == "ABSOLUTE":
        value = str(directories["absolute"])

    found, stderr = _child_answer(
        _LOOK_UP_TOOLS,
        cwd,
        _home_setting(home_kind, home),
        list(tools.values()),
        ASH_BIN_PATH=value,
    )

    answered = {where for where, name in tools.items() if found[name] is not None}
    assert answered == ({holder} if holder else set()), found
    if holder:
        assert _same_file(found[tools[holder]], directories[holder] / tools[holder])
    if home_kind == "absolute":
        relative = value == "rel-bin"
        assert _warns_naming(stderr, "ASH_BIN_PATH", value) is relative, stderr
        assert not _warns_about_home(stderr), stderr
    elif holder is None:
        assert _warns_about_home(stderr), stderr


@pytest.mark.parametrize("given", ["option", "environment"])
@pytest.mark.integration
def test_ash_dependencies_install_reads_a_relative_bin_path_where_it_was_typed(
    tmp_path: Path, given: str
) -> None:
    """advanced-usage.md (Where ASH looks for a tool; Install tools with `ash
    dependencies install`).

    ``ash dependencies install`` runs in a working directory with no network, for a
    tool name no plugin has, so it installs nothing after it names its target. With
    ``--bin-path rel-bin`` it must target ``rel-bin`` under the working directory.
    With ``ASH_BIN_PATH=rel-bin`` instead it must warn and target ``~/.ash/bin``, and
    must not create ``rel-bin``. Neither page says the target is created when nothing
    is installed in it, so whether it exists afterwards is not checked.
    """
    assert_on_page(ADVANCED_USAGE, _A_RELATIVE_ASH_BIN_PATH_IS_NOT_USED)
    assert_on_page(ADVANCED_USAGE, _A_RELATIVE_BIN_PATH_OPTION)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    home = cwd / "home"
    args = ["dependencies", "install", "--tool", _unique_tool()]
    env: Dict[str, str] = {}
    if given == "option":
        args += ["--bin-path", "rel-bin"]
    else:
        env["ASH_BIN_PATH"] = "rel-bin"

    result = _ash(args, cwd=cwd, **env)
    # Without the side bars of the panel the target is printed in.
    text = _squeezed(result.stdout + result.stderr).replace("│", "")

    target = cwd / "rel-bin" if given == "option" else home / ".ash" / "bin"
    assert _squeezed(f"Target bin path: {target}") in text, _output_tail(result)
    if given == "environment":
        assert _warns_naming(text, "ASH_BIN_PATH", "rel-bin"), _output_tail(result)
        assert not (cwd / "rel-bin").exists(), "a relative ASH_BIN_PATH was created"


@pytest.mark.parametrize(
    "home_kind, bin_path",
    [
        pytest.param("empty", False, id="an-empty-home"),
        pytest.param("relative", False, id="a-relative-home"),
        pytest.param("empty", True, id="an-empty-home-with-bin-path"),
        pytest.param("relative", True, id="a-relative-home-with-bin-path"),
        pytest.param("absolute", True, id="control-an-absolute-home-with-bin-path"),
    ],
)
@pytest.mark.integration
def test_ash_dependencies_install_installs_nothing_without_a_usable_home(
    tmp_path: Path, home_kind: str, bin_path: bool
) -> None:
    """advanced-usage.md (Install tools with `ash dependencies install`) and
    exit-codes.md (`ash dependencies install`).

    ``ash dependencies install`` runs with ``HOME`` empty or relative, with and without
    an absolute ``--bin-path``, for a tool name no plugin has. It must exit 3, say why
    (the install receipts it cannot keep), and create no bin directory. The control has
    an absolute ``HOME``: the install goes on to name its target and does not exit 3.
    """
    for page, sentence in _NO_USABLE_HOME_INSTALLS_NOTHING:
        assert_on_page(page, sentence)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    target = tmp_path / "abs-bin"
    args = ["dependencies", "install", "--tool", _unique_tool()]
    if bin_path:
        args += ["--bin-path", str(target)]
    env = _home_override(_home_setting(home_kind, cwd / "home") or "")

    result = _ash(args, cwd=cwd, **env)
    text = _squeezed(result.stdout + result.stderr).replace("│", "")

    if home_kind == "absolute":
        assert result.returncode != 3, _output_tail(result)
        assert _squeezed(f"Target bin path: {target}") in text, _output_tail(result)
        return
    assert result.returncode == 3, _output_tail(result)
    assert _squeezed("install receipt") in text, _output_tail(result)
    assert _squeezed("Target bin path") not in text, _output_tail(result)
    assert not target.exists(), "a bin directory was made with no usable home"
    assert not (cwd / "relhome").exists(), "something was made under a relative HOME"


#: exit-codes.md, `ash dependencies install`: a selection it cannot install.
_DEPENDENCIES_BAD_SELECTION_ROW = (
    "| | 2 | A `--tool` name matches no plugin, or names a plugin of a type that "
    "`--plugin-type` leaves out; or a `--plugin-type` is not `converter`, `scanner`, or "
    "`reporter`. ASH names the tool or the type, installs nothing, and starts no "
    "program. |"
)
_DEPENDENCIES_BAD_SELECTION_INTRO = (
    "Two `ash dependencies install` selections exit 2 instead: a `--tool` name that it "
    "has no plugin for, or whose plugin type `--plugin-type` leaves out, and a "
    "`--plugin-type` other than `converter`, `scanner`, or `reporter`."
)


@pytest.mark.parametrize(
    "case",
    [
        "a-tool-no-plugin-has",
        "a-known-tool-beside-an-unknown-one",
        "a-type-left-out",
        "a-plugin-type-there-is-not",
    ],
)
@pytest.mark.integration
def test_ash_dependencies_install_exits_2_on_a_tool_it_cannot_select(
    tmp_path: Path, case: str
) -> None:
    """exit-codes.md (the usage-error paragraph; `ash dependencies install`).

    ``ash dependencies install`` is given a ``--tool`` name no plugin has, alone and
    beside ``grype``, ``--tool grype`` with ``--plugin-type reporter``, which leaves
    scanners out, or a ``--plugin-type`` that is no plugin type. Each must exit 2,
    name the tool or the type it cannot select, say nothing was installed, and keep
    no install receipt. The dependencies snapshot
    (test_snapshot_dependencies_install.py) pins exit 2 for the mixed selection too.
    """
    assert_on_page(EXIT_CODES, _DEPENDENCIES_BAD_SELECTION_ROW)
    assert_on_page(EXIT_CODES, _DEPENDENCIES_BAD_SELECTION_INTRO)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    tool = _unique_tool()
    selection = {
        "a-tool-no-plugin-has": ["--tool", tool],
        "a-known-tool-beside-an-unknown-one": ["--tool", "grype", "--tool", tool],
        "a-type-left-out": ["--plugin-type", "reporter", "--tool", "grype"],
        "a-plugin-type-there-is-not": ["--plugin-type", "nosuch"],
    }[case]
    args = ["dependencies", "install", "--bin-path", str(tmp_path / "bin"), *selection]

    result = _ash(args, cwd=cwd)
    text = _squeezed(result.stdout + result.stderr).replace("│", "")

    assert result.returncode == 2, _output_tail(result)
    named = {
        "a-type-left-out": "grype is a scanner plugin",
        "a-plugin-type-there-is-not": "Unknown plugin type(s): nosuch",
    }.get(case, f"Unknown tool(s): {tool}")
    assert _squeezed(named) in text, _output_tail(result)
    assert _squeezed("Nothing installed") in text, _output_tail(result)
    receipts = cwd / "home" / ".ash" / "install-receipts"
    assert not receipts.exists() or not any(receipts.iterdir()), "a receipt was kept"


#: ``ash dependencies install`` in a child whose every process start is refused and
#: recorded, so nothing runs whatever is on PATH. Prints the exit code and the starts.
_INSTALL_STARTS_CODE = (
    "import json, os, subprocess, sys\n"
    "starts = []\n"
    "def refused(*args, **kwargs):\n"
    "    argv = args[1] if args and isinstance(args[0], subprocess.Popen) else args\n"
    "    starts.append([argv] if isinstance(argv, (str, bytes)) else "
    "[os.fsdecode(a) for a in argv])\n"
    "    raise OSError('no process is started in this test')\n"
    "subprocess.Popen._execute_child = refused\n"
    "os.system = os.posix_spawn = os.posix_spawnp = refused\n"
    "os.execv = os.execve = os.execvp = os.execvpe = refused\n"
    "from typer.testing import CliRunner\n"
    "from automated_security_helper.cli.dependencies import dependencies_app\n"
    "r = CliRunner().invoke(dependencies_app, sys.argv[1:])\n"
    "print(json.dumps({'code': r.exit_code, 'starts': starts}))"
)


@pytest.mark.parametrize(
    "case",
    [
        "a-tool-no-plugin-has",
        "a-known-tool-beside-an-unknown-one",
        "a-type-left-out",
        "a-plugin-type-there-is-not",
        "control-a-tool-it-installs",
    ],
)
@pytest.mark.integration
def test_ash_dependencies_install_starts_no_program_for_a_tool_it_cannot_select(
    tmp_path: Path, case: str
) -> None:
    """exit-codes.md (`ash dependencies install`): a refused selection starts nothing.

    The install runs in a child whose every process start is refused and recorded.
    Each selection the row refuses must exit 2 with no start: no uv, and no tool's
    version probe while the plugins are built. The control, ``--tool bandit``, must
    start uv for its install, so the recorder is seen to catch a start.
    """
    assert_on_page(EXIT_CODES, _DEPENDENCIES_BAD_SELECTION_ROW)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    tool = _unique_tool()
    selection = {
        "a-tool-no-plugin-has": ["--tool", tool],
        "a-known-tool-beside-an-unknown-one": ["--tool", "grype", "--tool", tool],
        "a-type-left-out": ["--plugin-type", "reporter", "--tool", "grype"],
        "a-plugin-type-there-is-not": ["--plugin-type", "nosuch"],
        "control-a-tool-it-installs": ["--tool", "bandit"],
    }[case]
    args = ["--bin-path", str(tmp_path / "bin"), *selection]

    result = subprocess.run(
        [sys.executable, "-c", _INSTALL_STARTS_CODE, *args],
        cwd=cwd,
        env=_ash_environment(cwd),
        capture_output=True,
        text=True,
        timeout=600,
    )

    assert result.returncode == 0, _output_tail(result)
    out = json.loads(result.stdout.strip().splitlines()[-1])
    if case == "control-a-tool-it-installs":
        assert any(argv and Path(argv[0]).stem == "uv" for argv in out["starts"]), out
        return
    assert out["code"] == 2, out
    assert out["starts"] == [], out["starts"]


ADVANCED_USAGE = "docs/advanced-usage.md"

#: advanced-usage.md on a ``--tool`` name ASH does not know.
_AN_UNKNOWN_TOOL_EXITS_2 = (
    "An unknown name stops the command with exit code 2: it names the unknown tool and "
    "lists the ones it knows, installs nothing, and starts no program."
)


@pytest.mark.integration
def test_ash_dependencies_install_names_an_unknown_tool_and_lists_the_ones_it_knows(
    tmp_path: Path,
) -> None:
    """advanced-usage.md (Install tools with ``ash dependencies install``).

    The page's doctest command after the sentence, ``ash dependencies install --tool
    gryp``, run in a working directory of its own with a private home. It must exit
    with the doctest's 2, name ``gryp`` as unknown, list the tools it knows, among
    them ``grype`` and ``syft`` from the page's own example and not ``gryp``, and
    install nothing: no file under the home's ``.ash``, where the bin directory and
    the install receipts are. Run again where every process start is refused and
    recorded (``_INSTALL_STARTS_CODE``, whose control is the test above), it exits 2
    with no start.
    """
    assert_on_page(ADVANCED_USAGE, _AN_UNKNOWN_TOOL_EXITS_2)
    text = _page_text(ADVANCED_USAGE)
    sentence = re.search(
        r"\s+".join(re.escape(word) for word in _AN_UNKNOWN_TOOL_EXITS_2.split()), text
    )
    assert sentence is not None, _AN_UNKNOWN_TOOL_EXITS_2
    doctest = _DOCTEST_RUN.match(text[sentence.end() :].lstrip())
    assert doctest is not None, "no doctest block right after the sentence"
    assert doctest[1] == "2", doctest[0]
    command = shlex.split(doctest[2])
    assert command[:3] == ["ash", "dependencies", "install"], command
    unknown = command[command.index("--tool") + 1]
    cwd = tmp_path / "cwd"
    cwd.mkdir()

    result = _ash(command[1:], cwd=cwd)
    shown = _squeezed(result.stdout + result.stderr).replace("│", "")

    assert result.returncode == 2, _output_tail(result)
    assert _squeezed(f"Unknown tool(s): {unknown}") in shown, _output_tail(result)
    listed = re.search(r"Available:([a-z0-9,\-]+)", shown)
    assert listed is not None, _output_tail(result)
    names = set(listed[1].split(","))
    assert {"grype", "syft"} <= names and unknown not in names, sorted(names)
    ash_home = cwd / "home" / ".ash"
    assert [p for p in ash_home.rglob("*") if p.is_file()] == [], "a file was installed"

    started = subprocess.run(
        [sys.executable, "-c", _INSTALL_STARTS_CODE, *command[3:]],
        cwd=cwd,
        env=_ash_environment(cwd),
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert started.returncode == 0, _output_tail(started)
    out = json.loads(started.stdout.strip().splitlines()[-1])
    assert out["code"] == 2, out
    assert out["starts"] == [], out["starts"]


@pytest.mark.parametrize(
    "runner, wrapper, home_kind, expected",
    [
        pytest.param(
            "bin/docker",
            "bin/sudo -n",
            "absolute",
            {"environment": None, "typed": "CWD/bin/docker", "wrapper": []},
            id="relative-paths",
        ),
        pytest.param(
            "~/bin/docker",
            "~/bin/sudo -n",
            "absolute",
            {
                "environment": "HOME/bin/docker",
                "typed": "HOME/bin/docker",
                "wrapper": ["HOME/bin/sudo", "-n"],
            },
            id="a-leading-tilde",
        ),
        pytest.param(
            "~USER/bin/docker",
            "~USER/bin/sudo -n",
            "absolute",
            {
                "environment": "USERHOME/bin/docker",
                "typed": "USERHOME/bin/docker",
                "wrapper": ["USERHOME/bin/sudo", "-n"],
            },
            id="a-leading-tilde-user",
        ),
        pytest.param(
            "~/bin/docker",
            "~/bin/sudo -n",
            "unset",
            {
                "environment": "USERHOME/bin/docker",
                "typed": "USERHOME/bin/docker",
                "wrapper": ["USERHOME/bin/sudo", "-n"],
            },
            id="a-leading-tilde-home-unset-uses-the-passwd-home",
        ),
        pytest.param(
            "~/bin/docker",
            "~/bin/sudo -n",
            "empty",
            {"environment": None, "typed": None, "wrapper": []},
            id="a-leading-tilde-an-empty-home",
        ),
        pytest.param(
            "~/bin/docker",
            "~/bin/sudo -n",
            "relative",
            {"environment": None, "typed": None, "wrapper": []},
            id="a-leading-tilde-a-relative-home",
        ),
        pytest.param(
            "podman",
            "sudo -n",
            "absolute",
            {"environment": "podman", "typed": "podman", "wrapper": ["sudo", "-n"]},
            id="control-command-names",
        ),
        pytest.param(
            "ABSOLUTE",
            "ABSOLUTE -n",
            "absolute",
            {
                "environment": "ABSOLUTE",
                "typed": "ABSOLUTE",
                "wrapper": ["ABSOLUTE", "-n"],
            },
            id="control-absolute-paths",
        ),
    ],
)
@pytest.mark.integration
def test_a_relative_container_runtime_path_is_read_only_where_it_was_typed(
    tmp_path: Path, runner: str, wrapper: str, home_kind: str, expected: Dict[str, Any]
) -> None:
    """run-in-a-container.md (Choose the container runtime).

    A process asks for the container runtime as a container scan does, from
    ``OCI_RUNNER`` and as typed after ``--oci-runner``, and for the wrapper from
    ``OCI_RUNNER_WRAPPER``. A relative path with a directory part must be read
    against the working directory when typed, and from ``OCI_RUNNER`` must not be
    used, so a runtime is picked as if none were named; as the wrapper's first word
    it must not be used either, so there is no wrapper. Each relative value gets a
    warning that names it. A leading ``~`` must name the home directory, ``HOME``'s or,
    with ``HOME`` unset, the passwd entry's, and a leading ``~user`` that user's. With
    ``HOME`` empty or relative a ``~/`` value must not be used, with a warning about
    ``HOME`` and none about a relative path. A command name and an absolute path are
    used as given, with no warning.
    """
    for sentence in _HOW_THE_RUNTIME_VALUE_IS_READ:
        assert_on_page(RUN_IN_A_CONTAINER, sentence)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    home = tmp_path / "home"
    absolute = str(tmp_path / "absolute" / "docker")
    user = getpass.getuser()
    # The passwd entry's home directory, which ``~user`` names, and ``~`` too when
    # HOME is unset.
    user_home = (
        os.path.expanduser(f"~{user}")
        if os.name == "nt"
        else importlib.import_module("pwd").getpwnam(user).pw_dir
    )
    runner = runner.replace("ABSOLUTE", absolute).replace("USER", user)
    wrapper = wrapper.replace("ABSOLUTE", absolute).replace("USER", user)
    expected = json.loads(
        json.dumps(expected)
        .replace("CWD", str(cwd))
        .replace("ABSOLUTE", absolute)
        .replace("USERHOME", user_home)
        .replace("HOME", str(home))
    )

    answer, stderr = _child_answer(
        _RESOLVE_THE_RUNTIME,
        cwd,
        _home_setting(home_kind, home),
        [],
        OCI_RUNNER=runner,
        OCI_RUNNER_WRAPPER=wrapper,
    )

    assert answer == expected, answer
    relative = runner.startswith("bin/")
    first_word = shlex.split(wrapper)[0]
    assert _warns_naming(stderr, "OCI_RUNNER", runner) is relative, stderr
    assert _warns_naming(stderr, "OCI_RUNNER_WRAPPER", first_word) is relative, stderr
    assert _warns_about_home(stderr) is (home_kind in ("empty", "relative")), stderr


#: A container runtime that records the path it was run as, then fails.
_RECORDING_RUNTIME_SCRIPT = (
    '#!/bin/sh\nprintf \'%s\\n\' "$0" >> "$RUNTIME_RECORD"\nexit 1\n'
)


@pytest.mark.parametrize(
    "document, home_kind, runs",
    [
        pytest.param({"oci_runner": "bin/docker"}, "absolute", "cwd", id="relative"),
        pytest.param({"oci_runner": "~/bin/docker"}, "absolute", "home", id="tilde"),
        pytest.param(
            {"oci_runner": "$HOME/bin/docker"},
            "absolute",
            "cwd-dollar",
            id="a-dollar-is-not-expanded",
        ),
        pytest.param(
            {"oci_runner": "~/bin/docker"},
            "empty",
            "path",
            id="tilde-with-an-empty-home",
        ),
        pytest.param({}, "absolute", "path", id="control-no-runner-named"),
    ],
)
@pytest.mark.integration
def test_a_documents_oci_runner_is_read_as_typed(
    tmp_path: Path, document: Dict[str, str], home_kind: str, runs: str
) -> None:
    """run-in-a-container.md (Choose the container runtime).

    ``ash scan --mode container --no-build`` runs with a ``--cli-json-input`` document
    that sets ``oci_runner``. A runtime that records the path it ran as stands at each
    place the value could mean: ``bin/docker`` under the working directory and under
    the home directory, ``$HOME/bin/docker`` under the working directory, taken
    literally, and finch on ``PATH``, which a scan picks when no runtime is named. A
    relative value must run the working directory's, ``~/`` the home directory's, and
    ``$HOME/...`` the literal one under the working directory. With ``HOME`` empty, a
    ``~/`` value must not be used: the scan runs finch from ``PATH``, as with no
    runtime named (the control), and logs a warning about ``HOME``. Windows has no
    shell for the recording runtime, so there only the pages are checked.
    """
    for sentence in _HOW_THE_RUNTIME_VALUE_IS_READ:
        assert_on_page(RUN_IN_A_CONTAINER, sentence)
    if os.name == "nt":
        return
    cwd, home, on_path = tmp_path / "cwd", tmp_path / "home", tmp_path / "path"
    places = {
        "cwd": cwd / "bin" / "docker",
        "home": home / "bin" / "docker",
        "cwd-dollar": cwd / "$HOME" / "bin" / "docker",
        "path": on_path / "finch",
    }
    for runtime in [*places.values(), *(on_path / n for n in ("docker", "nerdctl"))]:
        runtime.parent.mkdir(parents=True, exist_ok=True)
        runtime.write_text(_RECORDING_RUNTIME_SCRIPT, encoding="utf-8")
        runtime.chmod(0o755)
    (cwd / "source").mkdir()
    input_document = tmp_path / "input.json"
    input_document.write_text(json.dumps(document), encoding="utf-8")
    record = tmp_path / "ran.txt"

    result = _ash(
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--cli-json-input",
            str(input_document),
            "--source-dir",
            str(cwd / "source"),
            "--output-dir",
            str(tmp_path / "output"),
            "--offline",
            "--no-progress",
        ],
        cwd=cwd,
        **_home_override(_home_setting(home_kind, home) or ""),
        PATH=f"{on_path}{os.pathsep}{os.environ.get('PATH', '')}",
        RUNTIME_RECORD=str(record),
    )

    ran = set(record.read_text(encoding="utf-8").split()) if record.exists() else set()
    assert ran == {str(places[runs])}, (ran, _output_tail(result))
    assert _warns_about_home(result.stdout + result.stderr) is (home_kind == "empty"), (
        _output_tail(result)
    )


# --------------------------------------------------------------------------- #
# Installing ASH: Python versions, extras, and the CI install matrix
# --------------------------------------------------------------------------- #

INSTALL_PAGE = "how-to/install.md"


def _install_project() -> Dict[str, Any]:
    """[project] of the code under test's pyproject.toml."""
    text = (_code_root() / "pyproject.toml").read_text(encoding="utf-8")
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10
        import toml

        return toml.loads(text)["project"]
    return tomllib.loads(text)["project"]


def _install_supported_minors() -> List[int]:
    """The Python 3 minor versions requires-python allows."""
    from packaging.specifiers import SpecifierSet

    allowed = SpecifierSet(_install_project()["requires-python"])
    return [m for m in range(40) if allowed.contains(f"3.{m}", prereleases=True)]


@pytest.mark.unit
def test_every_python_range_the_pages_give_is_requires_python() -> None:
    """install.md (Requirements; Install with pip), and every other page that gives a
    range of Python versions.

    Each "Python 3.A to 3.B" on any page must be exactly the minor versions the code's
    requires-python allows. The control is that requires-python allows a contiguous
    range and that the pages give at least three ranges. A ``--python`` in an install
    command is held to requires-python by the docs gate's install-command check.
    """
    assert_on_page(
        INSTALL_PAGE,
        "- Python 3.10 to 3.14. uv and pipx can fetch a matching Python for you.",
    )
    assert_on_page(INSTALL_PAGE, "Use any Python 3.10 to 3.14 in place of 3.12.")
    minors = _install_supported_minors()
    assert minors and minors == list(range(minors[0], minors[-1] + 1)), minors
    ranges = [
        (str(page.relative_to(CONTENT)), int(match[1]), int(match[2]))
        for page in sorted(CONTENT.rglob("*.md"))
        for match in re.finditer(
            r"Python 3\.(\d+) to 3\.(\d+)", page.read_text(encoding="utf-8")
        )
    ]
    assert len(ranges) >= 3, ranges
    wrong = [r for r in ranges if (r[1], r[2]) != (minors[0], minors[-1])]
    assert not wrong, (
        f"requires-python {_install_project()['requires-python']} allows "
        f"3.{minors[0]} to 3.{minors[-1]}; these pages give other ranges: {wrong}"
    )


#: The language a ``symbols`` grammar is for, by its package.
_INSTALL_GRAMMARS = {
    "Python": "tree-sitter-python",
    "JavaScript": "tree-sitter-javascript",
    "TypeScript": "tree-sitter-typescript",
    "Java": "tree-sitter-java",
}


def _install_extras_table() -> Dict[str, str]:
    """{extra: its Adds cell} from the table in install.md's Extras section."""
    section = _page_text(INSTALL_PAGE).split("\n## Extras", 1)[1].split("\n## ", 1)[0]
    rows = {}
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("|") and len(cells) == 3:
            if re.fullmatch(r"`[\w-]+`", cells[0]):
                rows[cells[0].strip("`")] = cells[1]
    return rows


@pytest.mark.unit
def test_the_extras_table_lists_each_extra_and_what_it_adds() -> None:
    """install.md (Extras).

    The table's extras must be [project.optional-dependencies] of the code's
    pyproject.toml, both ways. The ``cdk`` row's packages must be that extra's packages,
    and the ``symbols`` row's languages must be its tree-sitter grammars, beside
    ``tree-sitter`` itself. The control is that both rows are found. Extras named in
    install commands are held by the docs gate's install-command check.
    """
    assert_on_page(
        INSTALL_PAGE,
        "| `cdk` | `aws-cdk-lib`, `cdk-nag`, `constructs` | the cdk-nag scanner, which "
        "also needs Node.js |",
    )
    assert_on_page(
        INSTALL_PAGE,
        "| `symbols` | tree-sitter grammars for Python, JavaScript, TypeScript, and Java |",
    )
    extras = {
        name: {_uv_package(dep).lower() for dep in deps}
        for name, deps in (
            _install_project().get("optional-dependencies") or {}
        ).items()
    }
    table = _install_extras_table()
    assert {"cdk", "symbols"} <= set(table), table
    assert set(table) == set(extras), (
        f"the Extras table lists {sorted(table)}; pyproject.toml has {sorted(extras)}"
    )
    assert set(re.findall(r"`([^`]+)`", table["cdk"])) == extras["cdk"], (
        table["cdk"],
        sorted(extras["cdk"]),
    )
    languages = set(
        re.findall(r"\b(Python|JavaScript|TypeScript|Java)\b", table["symbols"])
    )
    grammars = {p for p in extras["symbols"] if p.startswith("tree-sitter-")}
    assert {_INSTALL_GRAMMARS[name] for name in languages} == grammars, (
        sorted(languages),
        sorted(grammars),
    )
    assert "tree-sitter" in extras["symbols"], sorted(extras["symbols"])


def _install_matrix(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every job of ``workflow`` that a matrix with a ``method`` key expands to."""
    rows: List[Dict[str, Any]] = []
    for job in workflow["jobs"].values():
        matrix = (job.get("strategy") or {}).get("matrix")
        if not isinstance(matrix, dict) or "method" not in matrix:
            continue
        assert "include" not in matrix, "expand matrix include entries here first"
        keys = [k for k in matrix if k != "exclude"]
        combos = [
            dict(zip(keys, v)) for v in itertools.product(*(matrix[k] for k in keys))
        ]
        excluded = matrix.get("exclude") or []
        rows += [
            c
            for c in combos
            if not any(all(c.get(k) == v for k, v in e.items()) for e in excluded)
        ]
    return rows


@pytest.mark.unit
def test_ci_installs_ash_on_the_pythons_and_runners_the_page_names() -> None:
    """install.md (Requirements).

    The install-methods workflow's matrix, with its excludes applied, must run pip and
    pipx on every Python requires-python allows and uvx on the one version the sentence
    names, each on Ubuntu x86-64 and arm64, Windows and a macOS runner, and on no Intel
    macOS runner. macos-15 and macos-latest are GitHub's Apple silicon labels. The
    control is that the matrix holds all three methods.
    """
    sentence = (
        "CI installs ASH with pip and pipx on Python 3.10 to 3.14 and with uvx on 3.12, "
        "on Ubuntu (x86-64 and arm64), macOS on Apple silicon, and Windows."
    )
    assert_on_page(INSTALL_PAGE, sentence)
    [uvx_python] = re.findall(r"with uvx on (3\.\d+)", sentence)
    workflow = yaml.safe_load(
        (_code_root() / ".github" / "workflows" / "ash-install-methods.yml").read_text(
            encoding="utf-8"
        )
    )
    rows = _install_matrix(workflow)
    supported = [f"3.{m}" for m in _install_supported_minors()]
    by_method = {
        method: [r for r in rows if r.get("method") == method]
        for method in ("pip", "pipx", "uvx")
    }
    assert all(by_method.values()), {m: len(r) for m, r in by_method.items()}
    for method in ("pip", "pipx"):
        pythons = sorted({r["python-version"] for r in by_method[method]})
        assert pythons == supported, (method, pythons, supported)
    assert {r["python-version"] for r in by_method["uvx"]} == {uvx_python}
    for method, method_rows in by_method.items():
        oses = {r["os"] for r in method_rows}
        assert {"ubuntu-latest", "ubuntu-24.04-arm", "windows-latest"} <= oses, oses
        assert oses & {"macos-latest", "macos-15"}, (method, oses)
        assert not {o for o in oses if re.search(r"intel|large|macos-1[0-3]$", o)}, oses


# --------------------------------------------------------------------------- #
# Scanner coverage
# --------------------------------------------------------------------------- #

COVERAGE_PAGE = "reference/coverage.md"
SCANNERS_PAGE = "reference/scanners.md"


def _coverage_table(page: str, heading: str) -> List[Dict[str, str]]:
    """The rows of the first table after the line starting with ``heading``, keyed by
    header cell, with links unwrapped."""
    lines = _page_text(page).splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(heading))
    table: List[List[str]] = []
    for line in lines[start + 1 :]:
        if line.startswith("|"):
            cells = line.strip().strip("|").split("|")
            table.append([_LINK.sub(r"\1", c).strip() for c in cells])
        elif table:
            break
    return [dict(zip(table[0], row)) for row in table[2:]]


def _coverage_names(cell: str) -> Set[str]:
    """The scanner names in a cell; parentheses and items of several words dropped."""
    text = re.sub(r"\([^()]*\)", "", cell).replace("`", "")
    return {
        item.strip()
        for item in re.split(r",|\band\b", text)
        if re.fullmatch(r"\s*[a-z0-9-]+\s*", item)
    }


@pytest.mark.unit
def test_the_coverage_tables_name_every_shipped_scanner_by_where_it_comes_from(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """coverage.md (By stack; By scanner).

    The By stack table's built-in column must name exactly the scanners in ASH's
    built-in plugin module and its community column exactly the scanners of the
    community plugin modules, and the By scanner table must have one row for each
    shipped scanner. The control is that both columns and the table are non-empty.
    """
    assert_on_page(
        COVERAGE_PAGE,
        "| What your repository has | Built-in scanners | Community plugins |",
    )
    assert_on_page(
        COVERAGE_PAGE,
        "| Scanner | Type | What it reads | `--python-only` | `--mode precommit` |",
    )
    shipped = {
        plugin.config.name: module == "ash_builtin"
        for module, plugin in _instantiated_plugins(
            tmp_path, monkeypatch, "ASH_SCANNERS"
        )
    }
    by_stack = _coverage_table(COVERAGE_PAGE, "## By stack")
    built_in = set().union(*(_coverage_names(r["Built-in scanners"]) for r in by_stack))
    community = set().union(
        *(_coverage_names(r["Community plugins"]) for r in by_stack)
    )
    by_scanner = [r["Scanner"] for r in _coverage_table(COVERAGE_PAGE, "## By scanner")]
    assert built_in and community and by_scanner
    expected_built_in = {name for name, builtin in shipped.items() if builtin}
    expected_community = set(shipped) - expected_built_in
    assert built_in == expected_built_in, (
        f"By stack names as built-in but ASH does not ship built in: "
        f"{sorted(built_in - expected_built_in)}; ships built in but By stack does not "
        f"name: {sorted(expected_built_in - built_in)}"
    )
    assert community == expected_community, (
        f"By stack names as community: {sorted(community - expected_community)} more, "
        f"{sorted(expected_community - community)} fewer than the community modules ship"
    )
    assert sorted(by_scanner) == sorted(shipped), (
        f"By scanner rows {sorted(set(by_scanner) ^ set(shipped))} differ from the "
        f"shipped scanners (or a row is repeated)"
    )


@pytest.mark.unit
def test_the_coverage_table_columns_match_each_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """coverage.md (By scanner) and scanners.md (Scanners reference), whose generated
    table also says which scanners run with ``--python-only``.

    Each shipped scanner is built with its default config. For every By scanner row,
    the scanner must ship; Type must be its ``tool_type``; ``--python-only`` must be its
    ``is_python_only()``; and ``--mode precommit`` must be whether precommit mode adds
    it, with five rows marked yes. The scanners reference's ``--python-only`` column
    must agree as well. The control is the five precommit rows.
    """
    assert_on_page(
        COVERAGE_PAGE,
        "`--python-only` runs only the scanners marked yes and reports the rest "
        "`SKIPPED`, whether or not their tools are installed.",
    )
    assert_on_page(
        COVERAGE_PAGE,
        "`--mode precommit` runs the five scanners marked yes, plus any you name with "
        "`--scanners`.",
    )
    assert_on_page(
        SCANNERS_PAGE,
        "`--python-only` keeps a scanner when its `is_python_only()` is true",
    )
    from automated_security_helper.interactions.run_ash_scan import (
        PRECOMMIT_MODE_SCANNERS,
    )

    plugins = {
        plugin.config.name: plugin
        for _, plugin in _instantiated_plugins(tmp_path, monkeypatch, "ASH_SCANNERS")
    }
    rows = _coverage_table(COVERAGE_PAGE, "## By scanner")
    wrong = []
    for row in rows:
        plugin = plugins.get(row["Scanner"])
        if plugin is None:
            wrong.append((row["Scanner"], "is not a scanner ASH ships"))
            continue
        tool_type = str(getattr(plugin.tool_type, "value", plugin.tool_type))
        if row["Type"].lower() != tool_type.lower():
            wrong.append((row["Scanner"], "Type", row["Type"], tool_type))
        flags = [
            ("--python-only", row["`--python-only`"], plugin.is_python_only()),
            (
                "--mode precommit",
                row["`--mode precommit`"],
                row["Scanner"] in PRECOMMIT_MODE_SCANNERS,
            ),
        ]
        for column, page, code in flags:
            if (page == "yes") != code:
                wrong.append((row["Scanner"], column, page, code))
    for row in _coverage_table(SCANNERS_PAGE, "# Scanners reference"):
        name = row["Scanner"].strip("`")
        page = row["Runs with `--python-only`"]
        if name in plugins and (page == "yes") != plugins[name].is_python_only():
            wrong.append((name, f"{SCANNERS_PAGE} --python-only", page))
    assert not wrong, wrong
    marked = [r["Scanner"] for r in rows if r["`--mode precommit`"] == "yes"]
    assert len(marked) == 5 == len(PRECOMMIT_MODE_SCANNERS), (
        marked,
        PRECOMMIT_MODE_SCANNERS,
    )


# --------------------------------------------------------------------------- #
# The CI tutorial and the scan workflow
# --------------------------------------------------------------------------- #

CI_TUTORIAL = "getting-started/ci.md"


def _workflow_load(rel: str) -> Dict[str, Any]:
    return yaml.safe_load((_code_root() / rel).read_text(encoding="utf-8"))


def _workflow_inputs(workflow: Dict[str, Any]) -> Dict[str, Any]:
    triggers = workflow.get("on", workflow.get(True)) or {}  # PyYAML reads on: as True
    return (triggers.get("workflow_call") or {}).get("inputs") or {}


def _workflow_value(value: Any, inputs: Dict[str, Any], given: Dict[str, Any]) -> Any:
    """``value`` with a whole-value ``${{ inputs.<name> }}`` resolved: the caller's
    ``with:`` value, else the input's default."""
    match = re.fullmatch(r"\$\{\{\s*inputs\.([\w-]+)\s*\}\}", str(value))
    if not match:
        return value
    return given.get(match[1], (inputs.get(match[1]) or {}).get("default"))


def _workflow_called(uses: str) -> str:
    """The repository path a ``uses: <owner>/<repo>/<path>@<ref>`` line calls."""
    return uses.split("@", 1)[0].split("/", 2)[2]


def _workflow_page_jobs() -> Tuple[Tuple[str, Dict[str, Any]], Dict[str, Any]]:
    """(the scan job's id and body, the SARIF job's body) from the tutorial's blocks."""
    text = _page_text(CI_TUTORIAL)
    blocks = [
        b
        for b in (
            yaml.safe_load(t) for t in re.findall(r"```yaml\n(.*?)```", text, re.DOTALL)
        )
        if isinstance(b, dict)
    ]
    workflow = _one((b for b in blocks if "jobs" in b), "workflow block")
    scan = _one(workflow["jobs"].items(), "job in the workflow block")
    sarif = _one(
        (
            job
            for b in blocks
            for job in b.values()
            if isinstance(job, dict) and "upload-ash-sarif.yml" in str(job.get("uses"))
        ),
        "SARIF upload job",
    )
    return scan, sarif


@pytest.mark.unit
def test_the_ci_tutorial_names_the_job_check_and_artifact_ci_creates() -> None:
    """ci.md (2. Open a pull request and watch the scan; 4. Upload results to code
    scanning; 5. See a finding on a pull request).

    The workflows the tutorial's own blocks call are read from the code: the check name
    GitHub shows is the caller's job id and the called job's name; the JUnit check is
    the ``check_name`` of the report step, which runs by default; the artifact is the
    upload step's name, and the SARIF job downloads the same name, each with an
    ``${{ inputs.* }}`` value resolved from the block's ``with:`` or the input's
    default. The control is that the tutorial's blocks yield one scan job and one SARIF
    job that call workflows in this repository.
    """
    assert_on_page(
        CI_TUTORIAL,
        "Under **Checks**, the job **ash / SAST, SCA, and IaC Scan** starts.",
    )
    assert_on_page(
        CI_TUTORIAL,
        "- A check run named **ASH Scan JUnit Test Report**, which lists each actionable "
        "finding as a failed test.",
    )
    assert_on_page(
        CI_TUTORIAL,
        "- An artifact named `ash_output` with every report, including `ash.html`.",
    )
    assert_on_page(
        CI_TUTORIAL,
        "This job downloads the `ash_output` artifact and uploads `ash.ghas.sarif` to "
        "code scanning.",
    )
    assert_on_page(
        CI_TUTORIAL,
        "- The **ASH Scan JUnit Test Report** check is red and names the finding.",
    )
    (caller, job), sarif_job = _workflow_page_jobs()
    scan = _workflow_load(_workflow_called(job["uses"]))
    inputs, given = _workflow_inputs(scan), job.get("with") or {}
    shown = {f"{caller} / {j.get('name', jid)}" for jid, j in scan["jobs"].items()}
    assert "ash / SAST, SCA, and IaC Scan" in shown, shown

    steps = [s for j in scan["jobs"].values() for s in j.get("steps", [])]
    checks = {
        _workflow_value(s["with"]["check_name"], inputs, given)
        for s in steps
        if "check_name" in (s.get("with") or {})
    }
    assert checks == {"ASH Scan JUnit Test Report"}, checks
    assert (
        _workflow_value("${{ inputs.collect-junit-xml-report }}", inputs, given) is True
    )
    uploads = {
        _workflow_value(s["with"].get("name"), inputs, given)
        for s in steps
        if "actions/upload-artifact" in str(s.get("uses"))
    }
    assert uploads == {"ash_output"}, uploads

    sarif = _workflow_load(_workflow_called(sarif_job["uses"]))
    sarif_inputs, sarif_given = _workflow_inputs(sarif), sarif_job.get("with") or {}
    downloads = set()
    for step in (s for j in sarif["jobs"].values() for s in j.get("steps", [])):
        if "actions/download-artifact" not in str(step.get("uses")):
            continue
        by_id = "artifact-id != ''" in str(step.get("if", ""))
        if by_id and not sarif_given.get("artifact-id"):
            continue  # the step for a caller that passes the scan's artifact ID
        name = (step.get("with") or {}).get("name")
        downloads.add(_workflow_value(name, sarif_inputs, sarif_given))
    assert downloads == {"ash_output"}, downloads


@pytest.mark.unit
def test_the_ci_tutorial_lists_the_install_inputs_and_their_defaults() -> None:
    """ci.md (1. Add the workflow).

    The tools the sentence lists must be exactly the scan workflow's ``install-*``
    inputs, and each input's default must be true. The control is that the sentence
    lists at least four tools.
    """
    sentence = (
        "The workflow installs the tools that scanners on by default need from the "
        "runner: grype, syft, opengrep, cfn-nag, actionlint, cfn-guard, gitleaks, and "
        "trivy. Each has an `install-*` input that defaults to `true`."
    )
    assert_on_page(CI_TUTORIAL, sentence)
    tools = sentence.split(":", 1)[1].split(".", 1)[0]
    listed = set(re.findall(r"[a-z][a-z-]*[a-z]", tools)) - {"and"}
    assert len(listed) >= 4, listed
    inputs = _workflow_inputs(
        _workflow_load(".github/workflows/run-ash-security-scan.yml")
    )
    defaults = {
        name[len("install-") :]: spec.get("default")
        for name, spec in inputs.items()
        if name.startswith("install-")
    }
    assert set(defaults) == listed, (
        f"the sentence lists {sorted(listed)}; the workflow's install-* inputs are "
        f"{sorted(defaults)}"
    )
    not_true = {f"install-{t}": d for t, d in defaults.items() if d is not True}
    assert not not_true, f"these install-* inputs do not default to true: {not_true}"


GITHUB_ACTIONS = "how-to/ci/github-actions.md"

#: (an error github-actions.md quotes, the id of the step that makes the check, and
#: the input the message names when the step checks every string input in one loop).
_INPUT_CHECK_ERRORS: List[Tuple[str, str, Optional[str]]] = [
    (
        (
            "the ash-args input holds a line break, another control character or the "
            "legacy command marker, so it is refused without being printed. A block "
            "scalar of one line is fine; more than one line is refused."
        ),
        "inputs",
        "ash-args",
    ),
    (
        "the ash-args input is only a line feed; leave it empty instead.",
        "inputs",
        "ash-args",
    ),
    (
        (
            "ash-repo must be owner/name: letters, digits, '.', '_' and '-', one '/' "
            "between them."
        ),
        "ash-pin",
        None,
    ),
    (
        (
            "ash-version is not a branch, tag or commit name: it is empty, starts with "
            "'-', or holds a space or a control character."
        ),
        "ash-pin",
        None,
    ),
    (
        (
            "config-ref is not a branch, tag or commit name: it starts with '-', or holds "
            "a space or a control character."
        ),
        "config-ref",
        None,
    ),
]


@pytest.mark.parametrize(
    "quote, step_id, input_name",
    [
        pytest.param(*entry, id=f"{entry[1]}-{index}")
        for index, entry in enumerate(_INPUT_CHECK_ERRORS)
    ],
)
@pytest.mark.unit
def test_each_quoted_input_check_error_is_the_workflows_own(
    quote: str, step_id: str, input_name: Optional[str]
) -> None:
    """github-actions.md (How the workflow checks its inputs), and ci.md (Read the
    result).

    Each error the page quotes must be one that the scan workflow's step making the
    check prints as ``::error::``. The step that checks every string input names the
    input with ``${name//_/-}``, from its ``INPUT_<NAME>`` variable, so for a quote
    from that step the input's name is written in, and the step must read the input
    as that variable.
    """
    assert_on_page(GITHUB_ACTIONS, f"`{quote}`")
    if quote.startswith("the ash-args input holds"):
        assert_on_page(CI_TUTORIAL, f"An error such as `{quote}`")
    workflow = _workflow_load(".github/workflows/run-ash-security-scan.yml")
    steps = [
        step
        for job in (workflow.get("jobs") or {}).values()
        for step in job.get("steps") or []
    ]
    step = next((s for s in steps if s.get("id") == step_id), None)
    assert step is not None, f"the scan workflow has no step with id {step_id!r}"
    errors = re.findall(r'echo "::error::(.*)"\s*$', step.get("run", ""), re.MULTILINE)
    if input_name is not None:
        variable = "INPUT_" + input_name.upper().replace("-", "_")
        assert (step.get("env") or {}).get(variable) == (
            f"${{{{ inputs.{input_name} }}}}"
        ), f"step {step_id!r} does not read {input_name} as {variable}"
        errors = [error.replace("${name//_/-}", input_name) for error in errors]
    assert quote in errors, f"step {step_id!r} prints none of the quote: {errors}"


#: (an ash-args value, whether the input check refuses it) for each kind of value
#: github-actions.md and ci.md say it refuses, and two it lets through.
_INPUT_CHECK_VALUES = [
    pytest.param("--offline\r--debug", True, id="a-carriage-return"),
    pytest.param("--offline\n--debug", True, id="a-line-feed-inside"),
    pytest.param("--offline\n\n", True, id="two-trailing-line-feeds"),
    pytest.param("--offline\x07", True, id="another-c0-control"),
    pytest.param("--offline\x85", True, id="a-c1-control"),
    pytest.param("--offline\N{LINE SEPARATOR}--debug", True, id="a-line-separator"),
    pytest.param(
        "--offline\N{PARAGRAPH SEPARATOR}--debug", True, id="a-paragraph-separator"
    ),
    pytest.param("--offline ##[warning]x", True, id="the-legacy-marker"),
    pytest.param("--offline\n", False, id="control-one-trailing-line-feed"),
    pytest.param("--output-dir café/ü", False, id="control-other-non-ascii-text"),
]


@pytest.mark.parametrize("value, refused", _INPUT_CHECK_VALUES)
@pytest.mark.integration
def test_the_input_check_refuses_each_value_the_page_names_in_any_locale(
    tmp_path: Path, value: str, refused: bool
) -> None:
    """github-actions.md (How the workflow checks its inputs), and ci.md (Read the
    result).

    The scan workflow's first step, run with bash as the Linux runner runs it, is
    given ``ash-args`` holding a carriage return, a line feed inside it, two trailing
    line feeds, a C0 or a C1 control character, U+2028, U+2029, or ``##[``. It must
    refuse each with exit 1 and the quoted error, without printing the value or
    writing it as an output, and the same in the C locale as in a UTF-8 one. The
    controls, one trailing line feed and other non-ASCII text, pass, with the value
    written as the output, its line feed dropped. On Windows, which has no runner of
    this step, the step's text must make the same check: the C locale, and the byte
    patterns of each kind of value.
    """
    assert_on_page(
        GITHUB_ACTIONS,
        "The step then refuses a value that holds a carriage return, a line feed, "
        "another control character, a Unicode line or paragraph separator, or `##[`, so "
        "a value of more than one line, or one that ends in two line feeds, is refused. "
        "It checks the value byte by byte, so the answer does not depend on the "
        "runner's locale.",
    )
    assert_on_page(
        CI_TUTORIAL,
        "means the input it names holds more than one line, another control character, "
        "a Unicode line or paragraph separator, or `##[`, and the job stopped before it "
        "installed anything.",
    )
    workflow = _workflow_load(".github/workflows/run-ash-security-scan.yml")
    step = next(
        step
        for job in (workflow.get("jobs") or {}).values()
        for step in job.get("steps") or []
        if step.get("id") == "inputs"
    )
    script = step["run"]
    if os.name == "nt":
        assert "export LC_ALL=C" in script, script
        for pattern in (
            "[[:cntrl:]]",
            "$'\\xc2'[$'\\x80'-$'\\x9f']",
            "$'\\xe2\\x80'[$'\\xa8\\xa9']",
            "'##['",
        ):
            assert pattern in script, f"the check has no {pattern}"
        return

    script_path = _step_script(tmp_path, script)
    for locale_name in ("C", "C.UTF-8"):
        output = tmp_path / f"output-{locale_name}"
        output.write_text("", encoding="utf-8")
        result = subprocess.run(
            _bash_argv(script_path),
            env={
                "PATH": os.environ.get("PATH", ""),
                "LC_ALL": locale_name,
                "GITHUB_OUTPUT": str(output),
                "INPUT_ASH_ARGS": value,
                **_child_containment(tmp_path),
            },
            capture_output=True,
            timeout=60,
        )
        stdout = result.stdout.decode("utf-8", "replace")
        written = output.read_text(encoding="utf-8", errors="replace")
        if refused:
            assert result.returncode == 1, (locale_name, result.returncode, stdout)
            assert stdout.startswith(f"::error::{_INPUT_CHECK_ERRORS[0][0]}"), (
                locale_name,
                stdout,
            )
            assert "--offline" not in stdout, (locale_name, stdout)
            assert "ash_args=" not in written, (locale_name, written)
        else:
            assert result.returncode == 0, (locale_name, stdout, result.stderr)
            assert f"ash_args={value.rstrip(chr(10))}\n" in written, (
                locale_name,
                written,
            )


#: How the scan workflow's helper makes the token, and prints the stop and resume
#: lines, as the page's own steps must too.
_TOKEN_COMMAND = "od -An -N16 -tx1 /dev/urandom | tr -d ' \\n'"
_STOP_LINE = "printf '::stop-commands::%s\\n'"
_RESUME_LINE = "printf '\\n::%s::\\n'"
_PLAIN_STEPS_STOP = (
    "Each step that runs `uv` or `ash` stops workflow commands around it, as the "
    "reusable workflow does"
)
#: A ``uv`` or ``ash`` command in a step's script, ``"$(uv tool dir --bin)/ash"``
#: included.
_TOOL_COMMAND = re.compile(r"\b(?:ash|uv)(?=[\s\"])")
#: A GitHub Actions block of a page, as the docs runner marks it.
_GITHUB_ACTIONS_BLOCK = re.compile(
    r"<!-- doctest: config kind=github-actions[^>]*-->\n```yaml\n(.*?)```", re.DOTALL
)
#: The steps of each page that run ``uv`` or ``ash``, in page order.
_PAGES_STEPS_THAT_RUN_A_TOOL = {
    GITHUB_ACTIONS: [
        "Install ASH",
        "Install scanner tools",
        "Run ASH",
        "Install scanner tools",
        "Run ASH",
        "Run ASH",
    ],
    SCALE_LARGE_REPOS: [
        "Install ASH and the scanner tools",
        "Scan one shard",
        "Install ASH",
        "Merge the shards",
    ],
}


def _named_runs(node: Any) -> Iterator[Tuple[str, str]]:
    """The name and ``run`` script of every step under ``node`` that has a script."""
    if isinstance(node, dict):
        if isinstance(node.get("run"), str):
            yield str(node.get("name", "")), node["run"]
        for value in node.values():
            yield from _named_runs(value)
    elif isinstance(node, list):
        for value in node:
            yield from _named_runs(value)


def _runs_of_steps_named(node: Any, prefix: str) -> Iterator[str]:
    """The ``run`` scripts of every step under ``node`` whose name starts with
    ``prefix``."""
    return (run for name, run in _named_runs(node) if name.startswith(prefix))


def _commands_acted_on(output: str) -> List[str]:
    """The workflow commands a runner acts on in a step's ``output``: the lines that
    start with ``::``, outside a ``::stop-commands::<token>`` ... ``::<token>::``
    window. A carriage return ends a line, as it does for the runner."""
    acted: List[str] = []
    token: Optional[str] = None
    for line in output.replace("\r", "\n").split("\n"):
        if token is not None:
            if line == f"::{token}::":
                token = None
            continue
        if line.startswith("::stop-commands::"):
            token = line[len("::stop-commands::") :]
        elif line.startswith("::"):
            acted.append(line)
    return acted


@pytest.mark.parametrize(
    "stopped", [True, False], ids=["as-the-page-writes-it", "control-without-the-stop"]
)
@pytest.mark.integration
def test_the_pages_ash_steps_stop_workflow_commands_as_the_scan_workflow_does(
    tmp_path: Path, stopped: bool
) -> None:
    """github-actions.md (Write the steps yourself, Cache tools and databases, and Scan
    only the files a pull request changes) and scale-large-repos.md (Sharding in
    GitHub Actions).

    Every GitHub Actions block of every page is read. Each step that runs ``uv`` or
    ``ash`` makes its token, and prints its stop and resume lines, the way the scan
    workflow's helper does, with every ``uv`` and ``ash`` command between the two; the
    two pages hold the steps named in _PAGES_STEPS_THAT_RUN_A_TOOL, and
    github-actions.md's one other ``run`` step writes the date to GITHUB_OUTPUT and
    prints nothing. Each step is run with ``bash -e``, as a GitHub runner runs a step,
    with a ``uv`` and an ``ash`` on PATH that print a workflow command on stdout and
    another on stderr and exit 2, as a scan with findings does. The runner must act on
    neither, and the step must exit 2 without adding to GITHUB_PATH. Each is also run
    with tools that succeed: it exits 0, and a step that adds uv's tool directory to
    GITHUB_PATH adds it. The control drops the stop line, and the runner then acts on
    both. Windows has no runner for these steps, so there only the forms are checked.
    """
    assert_on_page(GITHUB_ACTIONS, _PLAIN_STEPS_STOP)
    import yaml

    workflow = _workflow_load(".github/workflows/run-ash-security-scan.yml")
    helper = "\n".join(_runs_of_steps_named(workflow, "Write the one_line helper"))
    for form in (_TOKEN_COMMAND, _STOP_LINE, _RESUME_LINE):
        assert form in helper, f"the scan workflow's helper no longer has {form}"

    steps: Dict[str, List[Tuple[str, str]]] = {}
    for page_path in sorted(CONTENT.rglob("*.md")):
        page = page_path.relative_to(CONTENT).as_posix()
        text = page_path.read_text(encoding="utf-8")
        blocks = _GITHUB_ACTIONS_BLOCK.findall(text)
        unmarked = text.count("runs-on:") - sum(b.count("runs-on:") for b in blocks)
        assert unmarked == 0, f"{page} has a workflow block not marked github-actions"
        for body in blocks:
            steps.setdefault(page, []).extend(_named_runs(yaml.safe_load(body)))
    wrapped = [
        (page, name, run)
        for page, page_steps in steps.items()
        for name, run in page_steps
        if _TOOL_COMMAND.search(run)
    ]
    assert {
        page: [name for step_page, name, _ in wrapped if step_page == page]
        for page in {page for page, _, _ in wrapped}
    } == _PAGES_STEPS_THAT_RUN_A_TOOL, wrapped
    assert [
        name for name, run in steps[GITHUB_ACTIONS] if not _TOOL_COMMAND.search(run)
    ] == ["Today's date, for the grype database cache key"], steps[GITHUB_ACTIONS]
    for page, name, script in wrapped:
        for form in (_TOKEN_COMMAND, _STOP_LINE, _RESUME_LINE):
            assert form in script, f"{page}: {name} has no {form}"
        tools = [match.start() for match in _TOOL_COMMAND.finditer(script)]
        stop, resume = script.index(_STOP_LINE), script.index(_RESUME_LINE)
        assert stop < tools[0] and tools[-1] < resume, (page, name, script)
    # The form run_step resolves: a step that runs ash before uv's tool directory
    # is on PATH names it through the directory uv answers.
    assert any('"$(uv tool dir --bin)/ash"' in script for _, _, script in wrapped), [
        name for _, name, _ in wrapped
    ]
    if os.name == "nt":
        return

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    tool_dir = 'if [ "$1 $2" = "tool dir" ]; then echo "${STUB_BIN}"; exit 0; fi\n'
    for tool, first in (("ash", ""), ("uv", tool_dir)):
        stub = bin_dir / tool
        stub.write_text(
            "#!/bin/sh\n"
            f"{first}"
            "echo '::error::from the tool on stdout'\n"
            "echo '::warning::from the tool on stderr' >&2\n"
            'exit "${STUB_STATUS}"\n',
            encoding="utf-8",
        )
        stub.chmod(0o755)
    github_path = tmp_path / "github_path"

    def run_step(script: str, status: int) -> Tuple[int, List[str]]:
        # The steps' command substitution in command position, resolved to the
        # answer the uv stub would print, before the run: a static reader of what
        # the step starts cannot evaluate a `$(...)` it would exec, and bash with
        # these stubs resolves it to exactly this. The literal form is pinned by
        # the `assert any(...)` above the stubs, so a step that stops using it
        # fails there, not here.
        script = script.replace('"$(uv tool dir --bin)/ash"', f'"{bin_dir}/ash"')
        result = subprocess.run(
            _bash_argv("-e", _step_script(tmp_path, script)),
            cwd=tmp_path,
            env={
                "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                "BASE_REF": "main",
                "SHARD": "0",
                "INSTALL_SPEC": "automated-security-helper",
                "GITHUB_PATH": str(github_path),
                "RUNNER_TEMP": str(runner_temp),
                "STUB_BIN": str(bin_dir),
                "STUB_STATUS": str(status),
                **_child_containment(tmp_path),
            },
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.stderr == "", (result.stdout, result.stderr)
        return result.returncode, _commands_acted_on(result.stdout)

    for page, name, script in wrapped:
        run = script if stopped else script.replace(_STOP_LINE, ":")
        returncode, acted = run_step(run, 2)
        assert returncode == 2, (page, name, returncode, acted)
        assert not github_path.exists(), (page, name)
        if stopped:
            assert acted == [], (page, name, acted)
        else:
            assert "::error::from the tool on stdout" in acted, (page, name, acted)
            assert "::warning::from the tool on stderr" in acted, (page, name, acted)
    if stopped:
        for page, name, script in wrapped:
            assert run_step(script, 0) == (0, []), (page, name)
            if "GITHUB_PATH" in script:
                added = github_path.read_text(encoding="utf-8")
                assert added == f"{bin_dir}\n", (page, name, added)
                github_path.unlink()


#: github-actions.md's sentences on how the scan job runs each tool (How the workflow
#: checks its inputs).
_A_TOOLS_OUTPUT_IS_SHOWN_AS_TEXT = [
    (
        "Before each one, the step prints `::stop-commands::` with a new random token, "
        "and after it, on a line of its own, the token, also when the step is cancelled"
    ),
    (
        "A file name or a finding's text from the scanned tree in their output is then "
        "shown as text, not read as a command."
    ),
    (
        "When no random token can be read, the command does not run, and the step logs "
        "the error:"
    ),
    "`no random token could be read for stop-commands, so the command did not run`",
]
_NO_TOKEN_ERROR = (
    "::error::no random token could be read for stop-commands, so the command did not "
    "run"
)
#: A tool whose output comes from the scanned tree: a file name on stdout and a
#: finding's text on stderr, with no final line feed, each read as a command if the
#: runner reads it. It records that it ran, or that it started and then waits.
_TREE_TOOL = (
    "#!/bin/sh\n"
    "printf '%s\\n' '::error file=src/a.py::a file name from the scanned tree'\n"
    "printf '%s' '::warning::a finding from the scanned tree' >&2\n"
    ': > "${TOOL_MARK}"\n'
    'if [ -n "${TOOL_WAITS:-}" ]; then exec sleep 60; fi\n'
)
_AFTER_THE_COMMAND = "::notice::the step goes on after the command"


@pytest.mark.parametrize(
    "case",
    [
        "a-tool-printing-commands",
        "control-the-tool-run-without-it",
        "a-new-token-for-each-command",
        "cancelled-with-sigint",
        "cancelled-with-sigterm",
        "no-random-token",
    ],
)
@pytest.mark.integration
def test_the_scan_job_shows_what_a_tool_prints_as_text(
    tmp_path: Path, case: str
) -> None:
    """github-actions.md (How the workflow checks its inputs).

    The scan workflow's step that writes its helper is run as the runner runs it, and a
    step then runs a tool through ``with_commands_stopped``, which the job runs every
    tool through. The tool prints lines from the scanned tree that read as commands,
    the second with no final line feed. The runner must act on neither, and must act
    on a command the step prints after the tool, so the token follows on a line of its
    own. Two tools in one step must each get a new token. A step that gets SIGINT or
    SIGTERM while the tool runs must still print the token, and the runner then acts on
    nothing the tool printed. With no random token (``od`` fails), the tool must not
    run and the runner must act on the quoted error. The control runs the tool without
    the helper, and the runner acts on its line. Windows has no runner for the helper,
    so there only the error's text is checked.
    """
    for sentence in _A_TOOLS_OUTPUT_IS_SHOWN_AS_TEXT:
        assert_on_page(GITHUB_ACTIONS, sentence)
    workflow = _workflow_load(".github/workflows/run-ash-security-scan.yml")
    definer = "\n".join(_runs_of_steps_named(workflow, "Write the one_line helper"))
    if os.name == "nt":
        assert f"'%s\\n' \"{_NO_TOKEN_ERROR}\"" in definer, definer
        return

    runner_temp, tools, no_od = (
        tmp_path / "runner",
        tmp_path / "bin",
        tmp_path / "no-od",
    )
    for directory in (runner_temp, tools, no_od):
        directory.mkdir()
    subprocess.run(
        _bash_argv("-e", _step_script(tmp_path, definer, name="definer.sh")),
        env={
            "PATH": os.environ.get("PATH", ""),
            "RUNNER_TEMP": str(runner_temp),
            **_child_containment(tmp_path),
        },
        check=True,
        timeout=60,
    )
    (tools / "tool").write_text(_TREE_TOOL, encoding="utf-8")
    (no_od / "od").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    for stub in (tools / "tool", no_od / "od"):
        stub.chmod(0o755)
    mark = tmp_path / "the-tool-ran"
    path = f"{tools}{os.pathsep}{os.environ.get('PATH', '')}"
    if case == "no-random-token":
        path = f"{no_od}{os.pathsep}{path}"
    load = '. "${RUNNER_TEMP}/ash-one-line.sh"\n'
    script = {
        "a-tool-printing-commands": f"{load}with_commands_stopped tool\n",
        "control-the-tool-run-without-it": "tool\n",
        "a-new-token-for-each-command": (
            f"{load}with_commands_stopped tool\nwith_commands_stopped tool\n"
        ),
        "no-random-token": f'{load}with_commands_stopped tool\necho "status=$?"\n',
    }.get(case, f"{load}with_commands_stopped tool\n")
    if not case.startswith("cancelled"):
        script += f"echo '{_AFTER_THE_COMMAND}'\n"
    step = subprocess.Popen(
        _bash_argv(_step_script(tmp_path, script)),
        cwd=tmp_path,
        env={
            "PATH": path,
            "RUNNER_TEMP": str(runner_temp),
            "TOOL_MARK": str(mark),
            **({"TOOL_WAITS": "1"} if case.startswith("cancelled") else {}),
            **_child_containment(tmp_path),
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        if case.startswith("cancelled"):
            deadline = time.monotonic() + 30
            while not mark.exists() and step.poll() is None:
                assert time.monotonic() < deadline, "the tool never started"
                time.sleep(0.05)
            step.send_signal(
                signal.SIGINT if case == "cancelled-with-sigint" else signal.SIGTERM
            )
        output, _ = step.communicate(timeout=60)
    finally:
        if step.poll() is None:
            os.killpg(step.pid, signal.SIGKILL)
            step.wait()
    acted = _commands_acted_on(output)
    from_the_tree = [line for line in acted if "from the scanned tree" in line]
    tokens = re.findall(r"^::stop-commands::(.*)$", output, re.MULTILINE)

    if case == "control-the-tool-run-without-it":
        assert "::error file=src/a.py::a file name from the scanned tree" in acted, (
            acted
        )
        return
    if case == "no-random-token":
        assert not mark.exists(), "the tool ran without a token"
        assert acted == [_NO_TOKEN_ERROR, _AFTER_THE_COMMAND], output
        assert "status=1" in output, output
        return
    assert mark.exists(), output
    assert from_the_tree == [], output
    assert tokens and all(re.fullmatch(r"[0-9a-f]{32}", t) for t in tokens), output
    for token in tokens:
        assert f"\n::{token}::\n" in output, (
            f"no line of its own holds {token}: {output}"
        )
    if case == "a-new-token-for-each-command":
        assert len(tokens) == 2 and tokens[0] != tokens[1], tokens
    if not case.startswith("cancelled"):
        assert acted == [_AFTER_THE_COMMAND], output


_SETUP_UV_VERSION_NOTE = (
    "`version: latest` installs the newest uv, as the reusable workflow does"
)


def _steps_using(node: Any, action: str) -> Iterator[Dict[str, Any]]:
    """Every step under ``node`` whose ``uses`` names ``action``, at any ref."""
    if isinstance(node, dict):
        if str(node.get("uses", "")).startswith(f"{action}@"):
            yield node
        for value in node.values():
            yield from _steps_using(value, action)
    elif isinstance(node, list):
        for value in node:
            yield from _steps_using(value, action)


@pytest.mark.unit
def test_the_pages_setup_uv_steps_pin_the_uv_version_the_scan_workflow_pins() -> None:
    """github-actions.md (Write the steps yourself) and scale-large-repos.md (Sharding
    in GitHub Actions).

    Every ``astral-sh/setup-uv`` step in the GitHub Actions blocks of every page sets
    ``version`` to what the scan workflow's setup-uv step sets, so a
    ``required-version`` in the scanned repository's uv.toml or pyproject.toml does not
    choose the uv the job installs ASH with. The workflow's step must set one, and the
    pages hold three such steps: the plain job's, and the shard and merge jobs'.
    """
    import yaml

    assert_on_page(GITHUB_ACTIONS, _SETUP_UV_VERSION_NOTE)
    workflow = _workflow_load(".github/workflows/run-ash-security-scan.yml")
    pinned = {
        (step.get("with") or {}).get("version")
        for step in _steps_using(workflow, "astral-sh/setup-uv")
    }
    assert len(pinned) == 1 and None not in pinned, pinned
    (version,) = pinned
    found = []
    for page_path in sorted(CONTENT.rglob("*.md")):
        page = page_path.relative_to(CONTENT).as_posix()
        text = page_path.read_text(encoding="utf-8")
        for body in _GITHUB_ACTIONS_BLOCK.findall(text):
            for step in _steps_using(yaml.safe_load(body), "astral-sh/setup-uv"):
                found.append((page, (step.get("with") or {}).get("version")))
    assert found == [
        (GITHUB_ACTIONS, version),
        (SCALE_LARGE_REPOS, version),
        (SCALE_LARGE_REPOS, version),
    ], (version, found)


#: github-actions.md's sentence on the scan workflow at v3.7.0 and v3.7.1 (Inputs of
#: run-ash-security-scan.yml).
_THE_WORKFLOW_AT_EARLIER_RELEASES = (
    "The workflow at v3.7.0 and v3.7.1 has fewer inputs: no `config-ref`, "
    "`config-ref-missing`, or `skip-unknown-tools`, and of the `install-*` inputs only "
    "`install-grype`, `install-syft`, and `install-opengrep`, which default to `false` "
    "there."
)
_INPUTS_AN_EARLIER_RELEASE_LACKS = (
    "config-ref",
    "config-ref-missing",
    "skip-unknown-tools",
)


@pytest.mark.parametrize("tag", ["v3.7.0", "v3.7.1", "control-this-tree"])
@pytest.mark.integration
def test_the_scan_workflow_at_v3_7_0_and_v3_7_1_has_the_inputs_the_page_names(
    tag: str,
) -> None:
    """github-actions.md (Inputs of run-ash-security-scan.yml).

    run-ash-security-scan.yml is read from the repository at each tag the page names,
    with ``git show``. It must have none of ``config-ref``, ``config-ref-missing`` and
    ``skip-unknown-tools``, and its only ``install-*`` inputs must be
    ``install-grype``, ``install-syft`` and ``install-opengrep``, each defaulting to
    false. The control is the workflow under test, which has the three inputs and more
    than three ``install-*`` inputs, so the inputs are read where they are. A clone
    without the tag fails the test by name, since CI's unit-test job fetches the
    release tags for it.
    """
    assert_on_page(GITHUB_ACTIONS, _THE_WORKFLOW_AT_EARLIER_RELEASES)
    path = ".github/workflows/run-ash-security-scan.yml"
    if tag.startswith("control"):
        inputs = _workflow_inputs(_workflow_load(path))
        assert set(_INPUTS_AN_EARLIER_RELEASE_LACKS) <= set(inputs), sorted(inputs)
        installs = [n for n in inputs if n.startswith("install-")]
        assert len(installs) > 3, installs
        return
    has_tag = subprocess.run(
        [
            "git",
            "-C",
            str(REPO_ROOT),
            "rev-parse",
            "--verify",
            "--quiet",
            f"refs/tags/{tag}",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if has_tag.returncode != 0:
        pytest.fail(
            f"the tag {tag} is not in this clone; CI's unit-test job fetches the release "
            "tags, and a local clone needs them too (git fetch --tags)",
            pytrace=False,
        )
    shown = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "show", f"{tag}:{path}"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert shown.returncode == 0, shown.stderr
    inputs = _workflow_inputs(yaml.safe_load(shown.stdout))
    assert not set(_INPUTS_AN_EARLIER_RELEASE_LACKS) & set(inputs), sorted(inputs)
    installs = {
        n: s.get("default") for n, s in inputs.items() if n.startswith("install-")
    }
    assert installs == {
        "install-grype": False,
        "install-syft": False,
        "install-opengrep": False,
    }, installs


def _install_input_steps(workflow: Dict[str, Any], name: str) -> List[Dict[str, Any]]:
    """The scan job's steps that run only when input ``name`` is true: their ``if:``
    names ``inputs.<name>``."""
    return [
        step
        for job in (workflow.get("jobs") or {}).values()
        for step in job.get("steps") or []
        if re.search(rf"\binputs\.{re.escape(name)}\b", str(step.get("if", "")))
    ]


def _tools_a_step_installs(step: Dict[str, Any], name: str) -> Set[str]:
    """The ``--tool`` names a step passes to ``ash dependencies install`` when input
    ``name`` is true: written in its script, or set from the input in its ``env``."""
    tools = set(re.findall(r"--tool\s+([a-z][a-z-]*)", str(step.get("run", ""))))
    for value in (step.get("env") or {}).values():
        match = re.fullmatch(
            rf"\$\{{\{{\s*inputs\.{re.escape(name)}\s*&&\s*'([a-z-]+)'\s*\|\|\s*''\s*\}}\}}",
            str(value),
        )
        if match:
            tools.add(match[1])
    return tools


@pytest.mark.unit
def test_each_install_input_row_names_the_tool_the_input_installs() -> None:
    """github-actions.md (Inputs of run-ash-security-scan.yml).

    The download table names, for each ``install-*`` input, what it downloads. Its
    rows must be the scan workflow's ``install-*`` inputs, and each row's first item
    must be the tool the input installs: the ``--tool`` that the steps run only for
    that input pass to ``ash dependencies install``, one ASH pins a release of
    (``TOOL_VERSIONS``), or for cfn-nag, the step that installs the gems its
    Gemfile.lock pins. The cfn-guard row's rules must be the rules directory the
    workflow sets only with ``install-cfn-guard``. The sizes come from release assets
    and databases outside the repository, so they are not checked.
    """
    assert_on_page(
        GITHUB_ACTIONS,
        "For the versions ASH pins, each one downloads:",
    )
    from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

    workflow = _workflow_load(".github/workflows/run-ash-security-scan.yml")
    rows = {
        row["Input"].strip("`"): row["Downloads"]
        for row in _coverage_table(GITHUB_ACTIONS, "Each install runs on every run")
    }
    inputs = {n for n in _workflow_inputs(workflow) if n.startswith("install-")}
    assert set(rows) == inputs, (sorted(rows), sorted(inputs))
    for name, downloads in rows.items():
        steps = _install_input_steps(workflow, name)
        assert steps, f"no step runs only with {name}"
        first = downloads.split(",", 1)[0].strip()
        if name == "install-cfn-nag":
            assert first == "Ruby", downloads
            assert any("Gemfile.lock" in str(s.get("run", "")) for s in steps), (
                f"no {name} step installs from Gemfile.lock"
            )
            continue
        installed = set().union(*(_tools_a_step_installs(s, name) for s in steps))
        assert installed == {first}, (name, first, installed)
        assert first in TOOL_VERSIONS, (first, sorted(TOOL_VERSIONS))
    rules = [
        value
        for job in (workflow.get("jobs") or {}).values()
        for step in job.get("steps") or []
        for key, value in (step.get("env") or {}).items()
        if key == "ASH_CFN_GUARD_RULES_DIR"
    ]
    assert "its rules" in rows["install-cfn-guard"], rows["install-cfn-guard"]
    assert rules and all("inputs.install-cfn-guard" in str(v) for v in rules), rules


# --------------------------------------------------------------------------- #
# read-results.md: ash report
# --------------------------------------------------------------------------- #

READ_RESULTS = "how-to/read-results.md"

#: read-results.md on where ``ash report`` writes its log.
_REPORT_LOG_TO_STDERR = (
    "`ash report` writes its log to standard error, so standard output holds the report "
    "alone."
)

#: read-results.md on where ``ash report`` looks for the results file.
_REPORT_LOOKS_IN = (
    "ASH looks for the results file in `.ash/ash_output` and `ash_output` under that "
    "directory, and in the directory itself, and reports on the one it finds:"
)

#: read-results.md on ``ash report`` with no results file to read.
_REPORT_NO_RESULTS = (
    "A missing results file prints `No scan results found:` with the paths it checked, "
    "and exits 1."
)

#: read-results.md on which paths that message names.
_REPORT_NO_RESULTS_NAMES = (
    "With `--output-dir` or `ASH_OUTPUT_DIR` the message names the three paths ASH "
    "looked in (`none of … exists`); otherwise it names "
    "`.ash/ash_output/ash_aggregated_results.json` under the current directory, in full "
    "(`… does not exist`)."
)

#: read-results.md on a results file in more than one of the places searched.
_REPORT_MORE_THAN_ONE = (
    "When more than one of the three holds a results file, ASH prints "
    "`More than one scan results file found:` with each path, reports on none, and "
    "exits 5."
)

#: read-results.md on ``ash report --format`` with a name no reporter has.
_REPORT_UNKNOWN_FORMAT = (
    "An unknown format is refused before the results are read: ASH prints `Error: "
    "Reporter plugin '<name>' not found.` and the reporter names, and exits 5."
)

#: A doctest marker, and the bash block under it.
_DOCTEST_RUN = re.compile(
    r"<!-- doctest: run expect-exit=(\d+) -->\n```bash\n(.*?)```", re.DOTALL
)


def _saved_results(output_dir: Path, paths: Iterable[str] = ()) -> Path:
    """``output_dir`` holding a stored scan, as a scan leaves it: an
    ``ash_aggregated_results.json`` for a scan with the default configuration, with
    one critical detect-secrets finding in each of ``paths``."""
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.unified_metrics import (
        populate_metrics_from_unified_source,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.schemas.sarif_schema_model import (
        ArtifactLocation,
        Location,
        Message,
        Message1,
        PhysicalLocation,
        PhysicalLocation2,
        PropertyBag,
        Region,
        Result,
    )

    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = [
        Result(
            ruleId="SECRET-PROBE",
            message=Message(root=Message1(text=f"Secret detected in file '{path}'")),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(
                        root=PhysicalLocation2(
                            artifactLocation=ArtifactLocation(uri=path),
                            region=Region(startLine=1, endLine=1),
                        )
                    )
                )
            ],
            properties=PropertyBag.model_validate(
                {"scanner_name": "detect-secrets", "issue_severity": "CRITICAL"}
            ),
        )
        for path in paths
    ]
    populate_metrics_from_unified_source(model).save_model(output_dir)
    return output_dir


def _results_files_looked_for(output_dir: Path) -> List[str]:
    """The results files ``_REPORT_LOOKS_IN`` names under ``output_dir``, as ASH
    writes a path."""
    return [
        (output_dir / ".ash" / "ash_output" / "ash_aggregated_results.json").as_posix(),
        (output_dir / "ash_output" / "ash_aggregated_results.json").as_posix(),
        (output_dir / "ash_aggregated_results.json").as_posix(),
    ]


def _built_in_reporter_names() -> Set[str]:
    return {
        typing.get_args(plugin.model_fields["config"].annotation)[0]
        .model_fields["name"]
        .default
        for plugin in _builtin_plugin_package().ASH_REPORTERS
    }


@pytest.mark.parametrize(
    "report_format, log_option, level",
    [
        pytest.param("sarif", [], "INFO", id="sarif"),
        pytest.param("flat-json", [], "INFO", id="flat-json"),
        pytest.param("sarif", ["--debug"], "DEBUG", id="sarif-debug"),
    ],
)
@pytest.mark.integration
def test_ash_report_writes_its_log_to_stderr_and_only_the_report_to_stdout(
    tmp_path: Path, report_format: str, log_option: List[str], level: str
) -> None:
    """read-results.md (Print a report in the terminal with ``ash report``).

    ``ash report`` over a stored scan, in a JSON format, at the default log level and
    with ``--debug``. Standard output parses as one JSON document, so no log line is in
    it. The control is the log itself: lines at the level asked for are on standard
    error.
    """
    assert_on_page(READ_RESULTS, _REPORT_LOG_TO_STDERR)
    output = _saved_results(tmp_path / "ash_output")

    result = _ash(
        ["report", "--format", report_format, "--output-dir", str(output), *log_option],
        cwd=tmp_path,
    )

    assert result.returncode == 0, _output_tail(result)
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        pytest.fail(
            f"standard output is not the report alone ({error}):\n{result.stdout[:2000]}",
            pytrace=False,
        )
    if report_format == "sarif":
        assert document["version"] == "2.1.0", document.get("version")
    assert level in result.stderr, result.stderr[-2000:]


#: read-results.md and exit-codes.md (ash report) on what ``ash report`` creates with
#: no results, and on an output directory it cannot search, enter or look up.
_REPORT_CREATES_NOTHING = (
    "`ash report` creates nothing then, and an output directory under a directory it "
    "cannot search counts as missing."
)
_REPORT_REFUSES_AN_UNENTERABLE_DIR = (
    "An output directory that exists but cannot be entered is refused with exit 5, "
    "`Output directory cannot be entered:` and the path as given."
)
_REPORT_REFUSES_A_FILE_OR_A_NUL = (
    "So is an output directory that is a file, `Output directory is not a directory:`, "
    "and a path the system cannot look up, such as one holding a NUL character, "
    "`Output directory is not a valid path:`. None of these refusals creates anything."
)
#: exit-codes.md (ash report), the code 1 row: no results is a state problem, the
#: code ``--use-existing`` gives a scan for the same reason, not a usage error.
_REPORT_NO_RESULTS_CODE_1_ROW = (
    "| 1 | No results to report on (no `ash_aggregated_results.json` in any of the "
    "places an output directory is searched, and an output directory under a "
    "directory ASH cannot search counts as one with none; nothing is created, and "
    "the same code `--use-existing` gives a scan for the same reason);"
)
_REPORT_NO_RESULTS_ROWS = [
    (
        "| 5 | A results file in more than one of the places "
        "an output directory is searched (nothing is created);"
    ),
    (
        "an output directory that exists but cannot be entered (`Output directory "
        "cannot be entered:` and the path as given); any other usage error |"
    ),
    (
        "an output directory that is a file (`Output directory is not a directory:`), "
        "or a path the system cannot look up, such as one holding a NUL character "
        "(`Output directory is not a valid path:`), each with the path as given;"
    ),
]

#: Wide enough that no message here is wrapped, so a path in it is matched whole.
_UNWRAPPED = {"COLUMNS": "4096"}

#: ``ash report --output-dir out<NUL>dir``, which no command line can carry: the child
#: sets its own arguments and runs the console entry point, as ``ash`` does.
_REPORT_WITH_A_NUL_IN_THE_OUTPUT_DIR = (
    "import sys\n"
    "from automated_security_helper.cli.entrypoint import main\n"
    "sys.argv = ['ash', 'report', '--output-dir', 'out\\x00dir']\n"
    "main()\n"
)

#: Whether a directory without search permission stops this process entering it:
#: permission bits do not stop root, and Windows has no search bit.
_SEARCH_BIT_HOLDS = os.name != "nt" and os.geteuid() != 0


@contextlib.contextmanager
def _without_search_permission(directory: Path) -> Iterator[None]:
    """``directory`` with mode 0o600 inside the block, and 0o700 after it."""
    directory.chmod(0o600)
    try:
        yield
    finally:
        directory.chmod(0o700)


@pytest.mark.parametrize(
    "where",
    [
        "working-directory",
        "empty-output-dir",
        "missing-output-dir",
        "ash-output-dir-variable",
        *(["under-an-unsearchable-directory"] if _SEARCH_BIT_HOLDS else []),
    ],
)
@pytest.mark.integration
def test_ash_report_with_no_results_file_names_the_paths_it_checked_and_exits_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    """read-results.md (Print a report in the terminal with ``ash report``), and
    exit-codes.md (ash report).

    ``ash report`` with no results file: from an empty working directory with no
    output directory named, with ``--output-dir`` naming an empty directory, one that
    does not exist, or (where the search bit holds) one under a directory without
    search permission, and with ``ASH_OUTPUT_DIR`` naming one that does not exist.
    Each exits 1, the code the page gives for no results to report on (a state
    problem, the same code ``--use-existing`` gives a scan), not the usage error 5
    the page gives a results file found in more than one place. With no output
    directory named it prints ``No scan results found:``,
    ``.ash/ash_output/ash_aggregated_results.json`` under the working directory in
    full, and ``does not exist``, and names neither of the other two files an output
    directory is searched for. Otherwise it prints ``none of`` the three files the
    page says it looks for under the output directory, in its order, and ``exists``.
    Nothing is created anywhere under the test's directory.
    """
    assert_on_page(READ_RESULTS, _REPORT_NO_RESULTS)
    assert_on_page(READ_RESULTS, _REPORT_NO_RESULTS_NAMES)
    assert_on_page(READ_RESULTS, _REPORT_LOOKS_IN)
    assert_on_page(READ_RESULTS, _REPORT_CREATES_NOTHING)
    assert_on_page(EXIT_CODES, _REPORT_NO_RESULTS_CODE_1_ROW)
    monkeypatch.delenv("ASH_OUTPUT_DIR", raising=False)
    cwd = tmp_path / "work"
    cwd.mkdir()
    (cwd / "home").mkdir()
    locked = tmp_path / "locked"
    args: List[str] = []
    env: Dict[str, str] = {}
    if where == "working-directory":
        output_dir = cwd.resolve() / ".ash" / "ash_output"
    elif where == "under-an-unsearchable-directory":
        locked.mkdir()
        output_dir = locked / "out"
        args = ["--output-dir", str(output_dir)]
    elif where == "ash-output-dir-variable":
        output_dir = tmp_path / "missing-output-dir"
        env = {"ASH_OUTPUT_DIR": str(output_dir)}
    else:
        output_dir = tmp_path / where
        if where == "empty-output-dir":
            output_dir.mkdir()
        args = ["--output-dir", str(output_dir)]
    before = _tree_entries(tmp_path)

    if where == "under-an-unsearchable-directory":
        with _without_search_permission(locked):
            result = _ash(["report", *args], cwd=cwd, **_UNWRAPPED)
    else:
        result = _ash(["report", *args], cwd=cwd, **_UNWRAPPED, **env)

    shown = result.stdout + result.stderr
    after = _tree_entries(tmp_path)
    assert result.returncode == 1, _output_tail(result)
    assert set(after) == set(before), set(after) ^ set(before)
    searched = _results_files_looked_for(output_dir)
    if where == "working-directory":
        named, other = searched[2], searched[:2]
        message = f"No scan results found: {named} does not exist."
    else:
        named, other = ", ".join(searched), []
        message = f"No scan results found: none of {named} exists."
    assert message in shown, f"{message!r} is not printed:\n{_output_tail(result)}"
    for path in other:
        assert path not in shown, f"{path} is named:\n{_output_tail(result)}"


@pytest.mark.parametrize(
    "given",
    [
        *(["relative", "absolute"] if _SEARCH_BIT_HOLDS else []),
        "control-an-enterable-directory",
    ],
)
@pytest.mark.integration
def test_ash_report_refuses_an_output_directory_it_cannot_enter_with_exit_5(
    tmp_path: Path, given: str
) -> None:
    """read-results.md (Print a report in the terminal with ``ash report``), and
    exit-codes.md (ash report).

    ``ash report`` with ``--output-dir`` naming a directory that exists without search
    permission, given relative to the working directory or as an absolute path, where
    the search bit holds. It must exit 5 and print ``Output directory cannot be
    entered:`` with the path as given, and create nothing. The control is the same
    directory with search permission: it is no refusal, and the run exits 1 for its
    missing results, saying so.
    """
    assert_on_page(READ_RESULTS, _REPORT_REFUSES_AN_UNENTERABLE_DIR)
    assert_on_page(EXIT_CODES, _REPORT_NO_RESULTS_ROWS[1])
    cwd = tmp_path / "work"
    cwd.mkdir()
    (cwd / "home").mkdir()
    directory = cwd / "out"
    directory.mkdir()
    named = "out" if given == "relative" else str(directory)
    before = _tree_entries(tmp_path)

    if given == "control-an-enterable-directory":
        result = _ash(["report", "--output-dir", named], cwd=cwd, **_UNWRAPPED)
    else:
        with _without_search_permission(directory):
            result = _ash(["report", "--output-dir", named], cwd=cwd, **_UNWRAPPED)

    shown = result.stdout + result.stderr
    after = _tree_entries(tmp_path)
    assert set(after) == set(before), set(after) ^ set(before)
    control = given == "control-an-enterable-directory"
    # The control is no refusal: its missing results exit 1, the code the page gives
    # for no results to report on.
    assert result.returncode == (1 if control else 5), _output_tail(result)
    if control:
        assert "No scan results found: none of " in shown, _output_tail(result)
        assert "cannot be entered" not in shown, _output_tail(result)
        return
    assert f"Output directory cannot be entered: {named}" in shown, _output_tail(result)
    assert "No scan results found" not in shown, _output_tail(result)


@pytest.mark.parametrize(
    "given", ["a-file", "a-nul-in-the-path", "control-a-directory"]
)
@pytest.mark.integration
def test_ash_report_refuses_a_file_or_a_nul_as_output_directory_with_exit_5(
    tmp_path: Path, given: str
) -> None:
    """read-results.md (Print a report in the terminal with ``ash report``), and
    exit-codes.md (ash report).

    ``ash report`` with ``--output-dir`` naming a regular file, and naming a path with
    a NUL character in it, which the child passes to ASH's console entry point itself
    since no command line can carry one. Each must exit 5, print its refusal with the
    path as given (the NUL shown as ``\\x00``, never written raw), print no
    ``No scan results found``, and create nothing. The control names a directory: it is
    no refusal, and the run exits 1 for its missing results, saying so.
    """
    assert_on_page(READ_RESULTS, _REPORT_REFUSES_A_FILE_OR_A_NUL)
    assert_on_page(EXIT_CODES, _REPORT_NO_RESULTS_ROWS[2])
    cwd = tmp_path / "work"
    cwd.mkdir()
    (cwd / "home").mkdir()
    (cwd / "a-file").write_text("", encoding="utf-8")
    (cwd / "a-directory").mkdir()
    before = _tree_entries(tmp_path)

    if given == "a-nul-in-the-path":
        result = subprocess.run(
            [sys.executable, "-c", _REPORT_WITH_A_NUL_IN_THE_OUTPUT_DIR],
            cwd=cwd,
            env=_ash_environment(cwd, **_UNWRAPPED),
            capture_output=True,
            text=True,
            timeout=600,
        )
        refusal = "Output directory is not a valid path: out\\x00dir"
    else:
        named = "a-file" if given == "a-file" else "a-directory"
        result = _ash(["report", "--output-dir", named], cwd=cwd, **_UNWRAPPED)
        refusal = f"Output directory is not a directory: {named}"

    shown = result.stdout + result.stderr
    after = _tree_entries(tmp_path)
    assert set(after) == set(before), set(after) ^ set(before)
    control = given == "control-a-directory"
    # The control is no refusal: its missing results exit 1, the code the page gives
    # for no results to report on.
    assert result.returncode == (1 if control else 5), _output_tail(result)
    assert "\x00" not in shown, _output_tail(result)
    if control:
        assert "No scan results found: none of " in shown, _output_tail(result)
        assert "Output directory is not" not in shown, _output_tail(result)
        return
    assert refusal in shown, f"{refusal!r} is not printed:\n{_output_tail(result)}"
    assert "No scan results found" not in shown, _output_tail(result)


@pytest.mark.parametrize("places", ["two-places", "control-one-place"])
@pytest.mark.integration
def test_ash_report_with_results_in_two_places_reports_on_none_and_exits_5(
    tmp_path: Path, places: str
) -> None:
    """read-results.md (Print a report in the terminal with ``ash report``), and
    exit-codes.md (ash report).

    ``ash report --output-dir`` with a stored scan both in ``.ash/ash_output`` under
    the output directory and in the directory itself. It must exit 5, print ``More than
    one scan results file found:`` with both files in the order they are searched,
    write no report to standard output, and create nothing. The control has the
    stored scan in the directory itself only: ASH reports on it and exits 0.
    """
    assert_on_page(READ_RESULTS, _REPORT_MORE_THAN_ONE)
    assert_on_page(READ_RESULTS, _REPORT_LOOKS_IN)
    assert_on_page(EXIT_CODES, _REPORT_NO_RESULTS_ROWS[0])
    cwd = tmp_path / "work"
    cwd.mkdir()
    (cwd / "home").mkdir()
    output_dir = tmp_path / "out"
    _saved_results(output_dir, ["src/settings.py"])
    if places == "two-places":
        _saved_results(output_dir / ".ash" / "ash_output", ["src/settings.py"])
    before = _tree_entries(tmp_path)

    result = _ash(["report", "--output-dir", str(output_dir)], cwd=cwd, **_UNWRAPPED)

    if places == "control-one-place":
        assert result.returncode == 0, _output_tail(result)
        assert "src/settings.py" in result.stdout, _output_tail(result)
        assert "More than one" not in result.stderr, _output_tail(result)
        return
    after = _tree_entries(tmp_path)
    searched = _results_files_looked_for(output_dir)
    found = f"More than one scan results file found: {searched[0]}, {searched[2]}."
    assert result.returncode == 5, _output_tail(result)
    assert found in result.stderr, f"{found!r} is not printed:\n{_output_tail(result)}"
    assert result.stdout == "", result.stdout[:2000]
    assert set(after) == set(before), set(after) ^ set(before)


@pytest.mark.parametrize(
    "results", ["no-results-file", "unreadable-results-file", "a-results-file"]
)
@pytest.mark.integration
def test_ash_report_refuses_an_unknown_format_before_it_reads_the_results(
    tmp_path: Path, results: str
) -> None:
    """read-results.md (Print a report in the terminal with ``ash report``).

    The page's doctest command, ``ash report --format nosuch``, run where the results
    file is missing, where it holds no JSON, and where it holds a stored scan. Each
    exits 5 with the refusal and the names of ASH's reporters, and prints neither
    ``No scan results found`` nor a load error, so the results were not read: read
    first, the first would print the no-results refusal and the second the load
    error.
    """
    assert_on_page(READ_RESULTS, _REPORT_UNKNOWN_FORMAT)
    text = _page_text(READ_RESULTS)
    sentence = re.search(
        r"\s+".join(re.escape(word) for word in _REPORT_UNKNOWN_FORMAT.split()), text
    )
    assert sentence is not None, _REPORT_UNKNOWN_FORMAT
    doctest = _DOCTEST_RUN.match(text[sentence.end() :].lstrip())
    assert doctest is not None, "no doctest block right after the sentence"
    assert doctest[1] == "5", doctest[0]
    command = shlex.split(doctest[2])
    assert command[:2] == ["ash", "report"] and "--format" in command, command
    name = command[command.index("--format") + 1]
    cwd = tmp_path / "work"
    cwd.mkdir()
    output = cwd / ".ash" / "ash_output"
    if results == "unreadable-results-file":
        output.mkdir(parents=True)
        (output / "ash_aggregated_results.json").write_text(
            "not json\n", encoding="utf-8"
        )
    elif results == "a-results-file":
        _saved_results(output)

    result = _ash(command[1:], cwd=cwd)

    shown = result.stdout + result.stderr
    assert result.returncode == 5, _output_tail(result)
    assert f"Error: Reporter plugin '{name}' not found." in shown, _output_tail(result)
    assert "No scan results found" not in shown, _output_tail(result)
    assert "Error loading results file" not in shown, _output_tail(result)
    listed = set(re.findall(r"^\s*- (\S+)\s*$", shown, re.MULTILINE))
    assert listed == _built_in_reporter_names(), listed ^ _built_in_reporter_names()


#: read-results.md on what ``ash report`` writes to a pipe and to a terminal.
_REPORT_AS_WRITTEN_OR_RENDERED = (
    "Apart from that, the output on a pipe is the reporter's output as the reporter "
    "wrote it, not wrapped or styled. On a terminal with color, JSON is indented and "
    "Markdown is rendered."
)

#: ``ash report`` run through the console scripts' entry point, keeping what the
#: reporter returned: each built-in reporter's ``report`` is wrapped to record its
#: return value, which it passes on unchanged, and the values are written as JSON to
#: the file ``argv[1]`` names when the process exits. The rest of argv is ash's.
_RECORDING_REPORT = """
import atexit, json, sys
from automated_security_helper.plugin_modules import ash_builtin

recorded = []

def recording(report):
    def wrapper(self, model):
        document = report(self, model)
        recorded.append(document)
        return document
    return wrapper

for plugin in ash_builtin.ASH_REPORTERS:
    if "report" in vars(plugin):
        plugin.report = recording(plugin.report)

def write_record(path=sys.argv[1]):
    with open(path, "w", encoding="utf-8") as record:
        json.dump(recorded, record)

atexit.register(write_record)
sys.argv = ["ash", *sys.argv[2:]]
from automated_security_helper.cli.entrypoint import main
main()
"""

#: A scanned file whose finding's lines are longer than a terminal's 80 columns.
_LONG_PATH = "src/" + "a-directory-with-a-long-name/" * 4 + "settings.py"

#: Variables that change how a terminal or color is detected, or that a CI runner
#: sets; each run here starts without them.
_TERMINAL_VARIABLES = (
    "NO_COLOR",
    "FORCE_COLOR",
    "CLICOLOR_FORCE",
    "TTY_COMPATIBLE",
    "TTY_INTERACTIVE",
    "TERM",
    "COLUMNS",
    "LINES",
    "GITHUB_ACTIONS",
    "TF_BUILD",
    "TEAMCITY_VERSION",
)

#: CSI sequences: color codes and cursor moves.
_CSI_SEQUENCE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _json_strings(value: Any) -> Iterator[str]:
    """Every string in a parsed JSON value, depth first: where the terminal cells
    look for a scanned name once JSON's own escapes are decoded."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _json_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _json_strings(item)


def _report_through(
    sink: str, args: List[str], workdir: Path, **env: str
) -> Tuple[int, bytes, str, List[str]]:
    """``ash report`` with ``args``, its standard output a regular file, a pipe or, for
    ``terminal`` (POSIX), a terminal of the test's own, 80 columns wide. (exit status,
    standard output, standard error, the documents the reporter returned)."""
    record = workdir / "reporter-output.json"
    stderr_path = workdir / "stderr.txt"
    environment = _ash_environment(workdir)
    for name in _TERMINAL_VARIABLES:
        environment.pop(name, None)
    if sink == "terminal":
        environment["TERM"] = "xterm-256color"
    environment.update(env)
    argv = [sys.executable, "-c", _RECORDING_REPORT, str(record), "report", *args]
    if sink == "file":
        stdout_path = workdir / "stdout.txt"
        with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
            done = subprocess.run(
                argv,
                cwd=workdir,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=600,
            )
        returncode, out = done.returncode, stdout_path.read_bytes()
    elif sink == "pipe":
        with open(stderr_path, "wb") as stderr:
            done = subprocess.run(
                argv,
                cwd=workdir,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=stderr,
                timeout=600,
            )
        returncode, out = done.returncode, done.stdout
    else:
        import fcntl
        import pty
        import select
        import struct
        import termios

        controller, terminal = pty.openpty()
        fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        with open(stderr_path, "wb") as stderr:
            process = subprocess.Popen(
                argv,
                cwd=workdir,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=terminal,
                stderr=stderr,
            )
        os.close(terminal)
        chunks: List[bytes] = []
        deadline = time.monotonic() + 600
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([controller], [], [], 5)
                if not ready:
                    if process.poll() is not None:
                        break
                    continue
                try:
                    chunk = os.read(controller, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(controller)
        returncode, out = process.wait(timeout=60), b"".join(chunks)
    documents = (
        json.loads(record.read_text(encoding="utf-8")) if record.is_file() else []
    )
    return returncode, out, stderr_path.read_text("utf-8", "replace"), documents


#: (where standard output goes, how color is turned off, format, what is expected).
_REPORT_OUTPUT_CELLS = [
    pytest.param("pipe", "color-on", fmt, "as-written", id=f"pipe-{fmt}")
    for fmt in ("markdown", "html", "text", "csv", "sarif", "flat-json")
]
if os.name != "nt":
    _REPORT_OUTPUT_CELLS += [
        # The page's sentence covers a pipe and a color terminal only. These
        # cells pin unclaimed behavior: a terminal without color writes the
        # document as the reporter wrote it, which a change should surface here
        # rather than silently.
        pytest.param("terminal", how, fmt, "as-written", id=f"terminal-{how}-{fmt}")
        for how in ("no-color", "NO_COLOR")
        for fmt in ("markdown", "html", "text", "csv", "sarif", "flat-json")
    ] + [
        # sarif for JSON: the flat-json reporter writes its document indented already.
        pytest.param("terminal", "color-on", fmt, "pretty", id=f"terminal-color-{fmt}")
        for fmt in ("markdown", "sarif")
    ]


@pytest.mark.parametrize("sink, how, report_format, expected", _REPORT_OUTPUT_CELLS)
@pytest.mark.integration
def test_ash_report_writes_the_reporters_output_unless_a_color_terminal_renders_it(
    tmp_path: Path, sink: str, how: str, report_format: str, expected: str
) -> None:
    """read-results.md (Print a report in the terminal with ``ash report``).

    ``ash report`` over a stored scan whose finding's lines are longer than 80
    columns, to a pipe and, on POSIX, to an 80-column terminal of the test's own,
    with ``--no-color``, with ``NO_COLOR`` set, and with color on. The child records
    the document the reporter returned in the same run, so the comparison holds
    for the reports stamped with the time they are rendered.

    On a pipe, standard output is that document byte for byte, so it is neither
    wrapped nor styled. On a terminal with color, JSON is the same value indented,
    where the reporter wrote it on one line, and Markdown is rendered: none of its
    heading lines is left as written. The page claims only those two: the
    terminal-no-color and terminal-NO_COLOR cells pin unclaimed behavior (the
    document as written, each line feed as CR LF) so a change surfaces here, and
    they fall if the pages ever state something else.
    """
    assert_on_page(READ_RESULTS, _REPORT_AS_WRITTEN_OR_RENDERED)
    workdir = tmp_path / "work"
    workdir.mkdir()
    output = _saved_results(tmp_path / "ash_output", paths=[_LONG_PATH])
    # The log is the test above's claim; here only the report is written.
    args = [
        "--format",
        report_format,
        "--output-dir",
        str(output),
        "--log-level",
        "ERROR",
    ]
    env: Dict[str, str] = {}
    if how == "no-color":
        args.append("--no-color")
    elif how == "NO_COLOR":
        env["NO_COLOR"] = "1"

    returncode, out, stderr, documents = _report_through(sink, args, workdir, **env)

    assert returncode == 0, stderr[-2000:]
    assert len(documents) == 1, (
        f"{len(documents)} documents recorded:\n{stderr[-2000:]}"
    )
    document = documents[0]
    if expected == "as-written":
        wanted = document.encode("utf-8")
        if sink == "terminal":
            wanted = wanted.replace(b"\n", b"\r\n")
        assert out == wanted, (
            "standard output is not the reporter's document:\n"
            + "".join(
                difflib.unified_diff(
                    document.splitlines(True),
                    out.decode("utf-8", "replace").splitlines(True),
                    "document",
                    "stdout",
                    n=1,
                )
            )[:3000]
        )
        # The control for "not wrapped": a line of the document is wider than the
        # terminal and the console width.
        assert max(map(len, document.splitlines())) > 80, report_format
        return
    shown = _CSI_SEQUENCE.sub("", out.decode("utf-8")).replace("\r\n", "\n")
    if report_format == "markdown":
        headings = re.findall(r"^#{1,6} (.+)$", document, re.MULTILINE)
        assert headings, document[:2000]
        assert not re.findall(r"^#{1,6} \S", shown, re.MULTILINE), shown[:3000]
        assert "ASH Security Scan Report" in shown, shown[:3000]
        return
    # The control: the reporter wrote the JSON on one line.
    assert "\n  " not in document, document[:500]
    assert "\n  " in shown, shown[:2000]
    assert json.loads(shown) == json.loads(document)


#: read-results.md on the report a regular file gets.
_REPORT_TO_A_FILE_AS_WRITTEN = (
    "To get the report exactly as the reporter wrote it, command lines included, "
    "redirect standard output to a file, as in the command above: ASH then writes the "
    "reporter's output unchanged, so the command above writes a SARIF file."
)
#: read-results.md on a report's CI command lines on a pipe.
_REPORT_CHANGES_COMMAND_LINES_ON_A_PIPE = (
    "On a pipe, ASH changes every line of the report that a CI system (GitHub Actions, "
    "Azure Pipelines, or TeamCity) would read as a command, so that none of them runs, "
    "whether or not a CI variable is set."
)
#: read-results.md on the same, on a terminal.
_REPORT_CHANGES_COMMAND_LINES_ON_A_CI_TERMINAL = (
    "On a terminal it changes those lines when `GITHUB_ACTIONS`, `TF_BUILD`, or "
    "`TEAMCITY_VERSION` is set."
)
#: read-results.md on ASH's own messages.
_ASH_MESSAGES_CHANGED_EVEN_IN_A_FILE = (
    "ASH's own messages, such as a refusal that quotes a path, have their CI command "
    "lines changed the same way even when they go to a file; only the report itself is "
    "written to a file as is."
)

#: Scanned file names holding the command forms GitHub Actions, Azure Pipelines and
#: TeamCity read: ``::`` starting a line (plain, after spaces, after a tab), and
#: ``##[error]``, ``##vso[`` and ``##teamcity[`` anywhere in one.
_CI_COMMAND_NAMES = [
    "notes\n::add-mask::x.txt",
    "notes\n    ::add-mask::y.txt",
    "notes\n\t::add-mask::t.txt",
    "a ##[error]e.txt",
    "a ##vso[task.setvariable variable=z]1.txt",
    "a ##teamcity[message text='m']2.txt",
]

#: A line a CI runner reads as a command, once color codes are dropped: one that
#: starts, after whitespace, with ``::``, or that holds ``##``, an optional name and
#: ``[``.
_CI_COMMAND_LINE = re.compile(r"^\s*::|##[A-Za-z]*\[")


def _ci_command_lines(text: str) -> List[str]:
    """The lines of ``text`` a CI runner reads as a command."""
    return [
        line
        for line in re.split(r"\r\n|\r|\n", text)
        if _CI_COMMAND_LINE.search(_CSI_SEQUENCE.sub("", line))
    ]


#: (where standard output goes, the CI variable set, what the report must be).
_CI_COMMAND_CELLS = [
    pytest.param("file", {}, "as-written", id="file"),
    pytest.param(
        "file", {"GITHUB_ACTIONS": "true"}, "as-written", id="file-GITHUB_ACTIONS"
    ),
    pytest.param("pipe", {}, "changed", id="pipe"),
    pytest.param(
        "pipe", {"GITHUB_ACTIONS": "true"}, "changed", id="pipe-GITHUB_ACTIONS"
    ),
]
if os.name != "nt":
    _CI_COMMAND_CELLS += [
        pytest.param("terminal", {name: value}, "changed", id=f"terminal-{name}")
        for name, value in (
            ("GITHUB_ACTIONS", "true"),
            ("TF_BUILD", "True"),
            ("TEAMCITY_VERSION", "2025.07"),
        )
    ]


@pytest.mark.parametrize("report_format", ["text", "markdown", "sarif"])
@pytest.mark.parametrize("sink, env, expected", _CI_COMMAND_CELLS)
@pytest.mark.integration
def test_ash_report_writes_ci_command_lines_as_written_only_to_a_file(
    tmp_path: Path,
    sink: str,
    env: Dict[str, str],
    expected: str,
    report_format: str,
) -> None:
    """read-results.md (Print a report in the terminal with ``ash report``).

    ``ash report`` over a stored scan whose file names hold every CI command form,
    with the child recording the document the reporter returned in the same run. To a
    regular file, with and without ``GITHUB_ACTIONS``, standard output is that document
    byte for byte, command lines included. To a pipe, with and without
    ``GITHUB_ACTIONS``, and, on POSIX, to a terminal with ``GITHUB_ACTIONS``,
    ``TF_BUILD`` or ``TEAMCITY_VERSION`` set, no line of it is one a runner reads as a
    command, and the names are still there. The control is the document itself: the
    reporter wrote command lines into it. A terminal with no CI variable is no page
    claim and has no case here.
    """
    assert_on_page(READ_RESULTS, _REPORT_TO_A_FILE_AS_WRITTEN)
    assert_on_page(READ_RESULTS, _REPORT_CHANGES_COMMAND_LINES_ON_A_PIPE)
    if sink == "terminal":
        assert_on_page(READ_RESULTS, _REPORT_CHANGES_COMMAND_LINES_ON_A_CI_TERMINAL)
    workdir = tmp_path / "work"
    workdir.mkdir()
    output = _saved_results(tmp_path / "ash_output", paths=_CI_COMMAND_NAMES)
    args = [
        "--format",
        report_format,
        "--output-dir",
        str(output),
        "--log-level",
        "ERROR",
    ]

    returncode, out, stderr, documents = _report_through(sink, args, workdir, **env)

    assert returncode == 0, stderr[-2000:]
    assert len(documents) == 1, (
        f"{len(documents)} documents recorded:\n{stderr[-2000:]}"
    )
    document = documents[0]
    assert _ci_command_lines(document), document[:2000]
    if expected == "as-written":
        assert out == document.replace("\n", os.linesep).encode("utf-8"), out.decode(
            "utf-8", "replace"
        )[:2000]
        return
    shown = _CSI_SEQUENCE.sub("", out.decode("utf-8", "replace"))
    assert "add-mask" in shown and "teamcity" in shown, shown[:2000]
    assert _ci_command_lines(shown) == [], _ci_command_lines(shown)


#: read-results.md on a JSON report's CI command forms on a pipe.
_A_JSON_REPORT_STILL_PARSES = (
    "A JSON report has the `#` of a `##name[` form written as JSON's own escape for it, "
    "so it parses to the same document."
)


@pytest.mark.parametrize("report_format", ["sarif", "flat-json"])
@pytest.mark.integration
def test_a_json_report_on_a_pipe_parses_to_the_reporters_document(
    tmp_path: Path, report_format: str
) -> None:
    """read-results.md (Print a report in the terminal with ``ash report``).

    ``ash report`` in a JSON format, over a stored scan whose file names hold
    ``##[error]``, ``##vso[`` and ``##teamcity[``, to a pipe. Standard output must hold
    no line a CI runner reads as a command, and must parse to the document the
    reporter returned in the same run. The control is that document: it holds the
    command forms.
    """
    assert_on_page(READ_RESULTS, _REPORT_CHANGES_COMMAND_LINES_ON_A_PIPE)
    assert_on_page(READ_RESULTS, _A_JSON_REPORT_STILL_PARSES)
    workdir = tmp_path / "work"
    workdir.mkdir()
    output = _saved_results(tmp_path / "ash_output", paths=_CI_COMMAND_NAMES)
    args = [
        "--format",
        report_format,
        "--output-dir",
        str(output),
        "--log-level",
        "ERROR",
    ]

    returncode, out, stderr, documents = _report_through("pipe", args, workdir)

    assert returncode == 0, stderr[-2000:]
    assert len(documents) == 1, (
        f"{len(documents)} documents recorded:\n{stderr[-2000:]}"
    )
    document = documents[0]
    assert _ci_command_lines(document), document[:2000]
    shown = out.decode("utf-8")
    assert _ci_command_lines(shown) == [], _ci_command_lines(shown)
    assert json.loads(shown) == json.loads(document), shown[:2000]
    # The page names the mechanism: JSON never escapes `#` on its own, so the
    # `#` must be ASH's.
    assert "\\u0023" in shown, shown[:2000]


#: read-results.md on what a terminal shows of the characters it acts on.
_A_TERMINAL_SHOWS_CONTROLS_AS_ESCAPES = (
    "On a terminal, with or without color, no character a terminal acts on is written "
    "as it is: it is shown as an escape, such as `\\x1b` for an escape character in a "
    "file name, or in a JSON report as JSON's own escape, such as `\\u001b`. Rendered "
    "Markdown leaves such characters out."
)
#: A scanned file name holding an escape character and a bell: a terminal would read
#: them as a sequence that sets its title, one no console styling writes.
_ESCAPE_IN_A_NAME = "title\x1b]0;page-claims\x07.txt"


@pytest.mark.skipif(os.name == "nt", reason="the test's own terminal is a POSIX pty")
@pytest.mark.parametrize(
    "how, report_format, shown_as",
    [
        pytest.param(
            "no-color", "text", "\\x1b]0;page-claims\\x07", id="no-color-text"
        ),
        pytest.param(
            "no-color", "markdown", "\\x1b]0;page-claims\\x07", id="no-color-markdown"
        ),
        pytest.param(
            "color-on", "text", "\\x1b]0;page-claims\\x07", id="color-on-text"
        ),
        pytest.param(
            "no-color", "sarif", "\\u001b]0;page-claims\\u0007", id="no-color-json"
        ),
        pytest.param(
            "color-on", "sarif", "\\u001b]0;page-claims\\u0007", id="color-on-json"
        ),
        pytest.param("color-on", "markdown", None, id="color-on-rendered-markdown"),
    ],
)
@pytest.mark.integration
def test_a_terminal_shows_the_characters_it_acts_on_as_escapes(
    tmp_path: Path, how: str, report_format: str, shown_as: Optional[str]
) -> None:
    """read-results.md (Print a report in the terminal with ``ash report``).

    ``ash report`` over a stored scan whose file name holds an escape character, ``]0;``
    and a bell, to a terminal of the test's own, with ``--no-color`` and with color on.
    No escape character may start ``]0;`` and no bell may be written. A text or Markdown
    report must show the two as ``\\x1b`` and ``\\x07``, and a JSON report as JSON's
    ``\\u001b`` and ``\\u0007``; rendered Markdown shows neither. The control is the
    document the reporter returned: it holds the raw characters.
    """
    assert_on_page(READ_RESULTS, _A_TERMINAL_SHOWS_CONTROLS_AS_ESCAPES)
    workdir = tmp_path / "work"
    workdir.mkdir()
    output = _saved_results(tmp_path / "ash_output", paths=[_ESCAPE_IN_A_NAME])
    args = [
        "--format",
        report_format,
        "--output-dir",
        str(output),
        "--log-level",
        "ERROR",
    ]
    if how == "no-color":
        args.append("--no-color")

    returncode, out, stderr, documents = _report_through("terminal", args, workdir)

    assert returncode == 0, stderr[-2000:]
    assert len(documents) == 1, (
        f"{len(documents)} documents recorded:\n{stderr[-2000:]}"
    )
    document = documents[0]
    if report_format == "sarif":
        # The reporter's JSON holds the name as JSON escapes: look in its strings.
        document = "\n".join(_json_strings(json.loads(document)))
    assert "\x1b]0;page-claims\x07" in document, repr(document[:2000])
    shown = out.decode("utf-8", "replace")
    # Rendered Markdown's own links are OSC 8 sequences, so only the name's are looked for.
    assert "\x1b]0;" not in shown and "\x07" not in shown, repr(shown[:2000])
    plain = _CSI_SEQUENCE.sub("", shown)
    if shown_as is None:
        # "rendered Markdown shows neither": not the escape, and not the bell.
        assert "page-claims" in plain, repr(plain[:2000])
        assert "\\x1b" not in plain and "\\x07" not in plain, repr(plain[:2000])
    else:
        assert shown_as in plain, repr(plain[:2000])


#: A scanned file name holding a C1 control (CSI, U+009B). JSON mandates escaping
#: only the C0 range, so a serializer writing with ``ensure_ascii`` off emits a C1
#: raw; an escape shown on a terminal is therefore ASH's own, where the C0 cells
#: cannot tell ASH's escaping from the serializer's.
_C1_IN_A_NAME = "csi\u009bselect.txt"


@pytest.mark.skipif(os.name == "nt", reason="the test's own terminal is a POSIX pty")
@pytest.mark.parametrize("how", ["no-color", "color-on"])
@pytest.mark.integration
def test_a_c1_control_in_a_name_is_escaped_in_a_json_report(
    tmp_path: Path, how: str
) -> None:
    """read-results.md (Print a report in the terminal with ``ash report``).

    ``ash report --format sarif`` over a stored scan whose file name holds U+009B,
    the one-byte CSI, to a terminal. The raw character may not be written; the
    shown JSON holds it as JSON's own escape. The control is the document the
    reporter returned: its raw text holds the character unescaped and no
    ``\\u009b`` spelling, so the escape the terminal shows is ASH's own.
    """
    assert_on_page(READ_RESULTS, _A_TERMINAL_SHOWS_CONTROLS_AS_ESCAPES)
    workdir = tmp_path / "work"
    workdir.mkdir()
    output = _saved_results(tmp_path / "ash_output", paths=[_C1_IN_A_NAME])
    args = ["--format", "sarif", "--output-dir", str(output), "--log-level", "ERROR"]
    if how == "no-color":
        args.append("--no-color")

    returncode, out, stderr, documents = _report_through("terminal", args, workdir)

    assert returncode == 0, stderr[-2000:]
    assert len(documents) == 1, (
        f"{len(documents)} documents recorded:\n{stderr[-2000:]}"
    )

    # The comment on _C1_IN_A_NAME holds only if the reporter wrote the C1 raw:
    # a serializer escaping it itself (ensure_ascii, say) would put the same
    # ``\\u009b`` in the document, and a pass-through terminal would satisfy the
    # shown-text assert below with ASH having escaped nothing. So the control is
    # the raw document text, not the parsed strings, which read the same either
    # way once JSON's escapes are decoded.
    assert "\u009b" in documents[0], repr(documents[0][:2000])
    assert "\\u009b" not in documents[0], repr(documents[0][:2000])
    document = "\n".join(_json_strings(json.loads(documents[0])))
    assert "\u009b" in document, repr(document[:2000])
    shown = out.decode("utf-8", "replace")
    assert "\u009b" not in shown, repr(shown[:2000])
    plain = _CSI_SEQUENCE.sub("", shown)
    assert "\\u009b" in plain, repr(plain[:2000])


@pytest.mark.parametrize(
    "sink, env",
    [
        pytest.param("file", {}, id="file"),
        pytest.param("file", {"GITHUB_ACTIONS": "true"}, id="file-GITHUB_ACTIONS"),
        pytest.param("pipe", {}, id="pipe"),
        pytest.param("pipe", {"GITHUB_ACTIONS": "true"}, id="pipe-GITHUB_ACTIONS"),
        *(
            [
                pytest.param(
                    "terminal", {"GITHUB_ACTIONS": "true"}, id="terminal-GITHUB_ACTIONS"
                )
            ]
            if os.name != "nt"
            else []
        ),
    ],
)
@pytest.mark.integration
def test_ash_report_refusing_a_path_writes_no_ci_command_line_even_to_a_file(
    tmp_path: Path, sink: str, env: Dict[str, str]
) -> None:
    """read-results.md (Print a report in the terminal with ``ash report``).

    ``ash report --config`` naming a file that does not exist, whose name holds a line
    feed and ``::add-mask::``, then ``##vso[``. The refusal quotes the path, and to a
    regular file, a pipe, or a terminal with ``GITHUB_ACTIONS`` set, no line of what
    the command writes is one a runner reads as a command. The control is the quote:
    the path's text is in the output.
    """
    assert_on_page(READ_RESULTS, _ASH_MESSAGES_CHANGED_EVEN_IN_A_FILE)
    workdir = tmp_path / "work"
    workdir.mkdir()
    output = _saved_results(tmp_path / "ash_output")
    config = "missing\n::add-mask::c ##vso[task.complete]v.yaml"

    returncode, out, stderr, _ = _report_through(
        sink, ["--config", config, "--output-dir", str(output)], workdir, **env
    )

    shown = _CSI_SEQUENCE.sub("", out.decode("utf-8", "replace") + stderr)
    assert returncode != 0, shown[-2000:]
    assert "add-mask" in shown and "task.complete" in shown, shown[-2000:]
    assert _ci_command_lines(shown) == [], _ci_command_lines(shown)


#: exit-codes.md (ash scan, ash merge) on an output directory that holds a NUL.
_NUL_OUTPUT_DIR = [
    (
        "or it is not a valid path because it holds a NUL character, which a "
        "`--cli-json-input` document can carry and a command line cannot;"
    ),
    "- `Output directory is not a valid path: <path>`",
    (
        "A NUL character in the path is shown as `\\x00`, as in `Output directory is not "
        "a valid path: out\\x00dir`."
    ),
    (
        "or it is not a valid path because it holds a NUL character, which a "
        "`--cli-json-input` document can carry. The merge prints"
    ),
]
_NUL_OUTPUT_DIR_REFUSAL = "Output directory is not a valid path: out\\x00dir"


@pytest.mark.parametrize("command", ["scan", "merge"])
@pytest.mark.integration
def test_an_output_directory_holding_a_nul_is_refused_with_exit_5(
    tmp_path: Path, command: str
) -> None:
    """exit-codes.md (ash scan, its output-directory lines, and ash merge).

    A command line cannot carry a NUL, so a ``--cli-json-input`` document gives
    ``output_dir`` as ``out``, a NUL, then ``dir``. ``ash scan`` must print the refusal
    on standard error and ``ash merge`` on standard output, with the NUL shown as
    ``\\x00``, exit 5, and create nothing in the working directory. ``ash merge``
    merges a one-shard scan, so it reaches its output-directory check.
    """
    for sentence in _NUL_OUTPUT_DIR:
        assert_on_page(EXIT_CODES, sentence)
    work = tmp_path / "work"
    work.mkdir()
    document = tmp_path / "input.json"
    document.write_text(json.dumps({"output_dir": "out\x00dir"}), encoding="utf-8")
    if command == "scan":
        tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
        args = [*_CONFIG_SCAN, "--offline", "--source-dir", str(tree)]
    else:
        shard = _stored_scan(tmp_path)
        args = ["merge", "--results", str(shard / "ash_aggregated_results.json")]

    result = _ash([*args, "--cli-json-input", str(document)], cwd=work)

    stream = result.stderr if command == "scan" else result.stdout
    assert result.returncode == 5, _output_tail(result)
    assert _NUL_OUTPUT_DIR_REFUSAL in stream, _output_tail(result)
    assert "\x00" not in result.stdout + result.stderr, _output_tail(result)
    made = sorted(p.name for p in work.iterdir() if p.name != "home")  # _ash's home
    assert made == [], _output_tail(result)


#: exit-codes.md (ash scan) on a source directory that holds a NUL.
_NUL_SOURCE_DIR = [
    (
        "the source directory (`--source-dir` or `ASH_SOURCE_DIR`) does not exist, is not "
        "a directory, cannot be entered, or is not a valid path because it holds a NUL "
        "character;"
    ),
    "- `Source directory is not a valid path: <path>`",
    "`--mode container` refuses the same directories, also with `--no-run`.",
]


@pytest.mark.parametrize(
    "source_dir, mode, refusal",
    [
        pytest.param(
            "src\x00dir",
            "local",
            "Source directory is not a valid path: src\\x00dir",
            id="a-nul-local",
        ),
        pytest.param(
            "src\x00dir",
            "container",
            "Source directory is not a valid path: src\\x00dir",
            id="a-nul-container-no-run",
        ),
        pytest.param(
            "missing",
            "local",
            "Source directory does not exist: missing",
            id="control-a-source-that-is-not-there",
        ),
    ],
)
@pytest.mark.integration
def test_a_source_directory_holding_a_nul_is_refused_with_exit_5(
    tmp_path: Path, source_dir: str, mode: str, refusal: str
) -> None:
    """exit-codes.md (ash scan: code 5's source-directory clause and the refusal lines).

    A command line cannot carry a NUL, so a ``--cli-json-input`` document gives
    ``source_dir`` as ``src``, a NUL, then ``dir``. ``ash scan`` must print the page's
    "is not a valid path" line on standard error, with the NUL shown as ``\\x00``,
    exit 5, and create neither the output directory nor anything in the working
    directory, in local mode and in ``--mode container --no-run``. The control, a
    source directory that does not exist, keeps its own line.
    """
    for sentence in _NUL_SOURCE_DIR:
        assert_on_page(EXIT_CODES, sentence)
    work = tmp_path / "work"
    work.mkdir()
    output = tmp_path / "out"
    document = tmp_path / "input.json"
    document.write_text(json.dumps({"source_dir": source_dir}), encoding="utf-8")
    args = [*_CONFIG_SCAN, "--offline", "--mode", mode, "--output-dir", str(output)]
    if mode == "container":
        args.append("--no-run")

    result = _ash([*args, "--cli-json-input", str(document)], cwd=work)

    assert result.returncode == 5, _output_tail(result)
    assert refusal in result.stderr, _output_tail(result)
    assert "\x00" not in result.stdout + result.stderr, _output_tail(result)
    assert not output.exists(), _output_tail(result)
    made = sorted(p.name for p in work.iterdir() if p.name != "home")  # _ash's home
    assert made == [], _output_tail(result)


#: exit-codes.md (ash config update): what a --set it cannot apply does.
_CONFIG_UPDATE_SET = [
    "or `--dry-run` was given with `--set` values it can apply",
    (
        "a `--set` value does not parse (no `=`, or nothing before it), starts with a "
        "top-level key the configuration does not have, or leaves a config a scan would "
        "refuse. `update` prints `Not updating <file>: ...` and leaves the file unchanged, "
        "also with `--dry-run`, and applies no other `--set` given with it."
    ),
    (
        "A top-level key may be written with `-` for `_`, as in a config file, so "
        "`--set fail-on-findings=false` sets `fail_on_findings`"
    ),
]


@pytest.mark.parametrize(
    "sets, refused",
    [
        pytest.param(["fail_on_findings"], True, id="no-equals"),
        pytest.param(["=false"], True, id="an-empty-key"),
        pytest.param(["fail_on_finding=false"], True, id="an-unknown-top-level-key"),
        pytest.param(
            ["fail_on_finding=false", "--dry-run"],
            True,
            id="an-unknown-key-with-dry-run",
        ),
        pytest.param(
            ["global_settings.severity_threshold=BOGUS"],
            True,
            id="a-value-the-schema-refuses",
        ),
        pytest.param(
            ["fail_on_findings=false", "fail_on_finding=false"],
            True,
            id="one-bad-of-two-applies-neither",
        ),
        pytest.param(["fail-on-findings=false"], False, id="the-dash-form-is-applied"),
        pytest.param(
            ["fail_on_findings=false"], False, id="control-a-set-it-can-apply"
        ),
    ],
)
@pytest.mark.integration
def test_config_update_writes_nothing_for_a_set_it_cannot_apply(
    tmp_path: Path, sets: List[str], refused: bool
) -> None:
    """exit-codes.md (ash config update rows, and the `--set` examples).

    ``ash config update`` runs on a one-line config file. A ``--set`` with no ``=``,
    with nothing before it, with a top-level key the configuration does not have, or
    leaving a config the schema refuses must exit 3 with ``Not updating <file>:``, and
    leave the file's bytes as they were, with ``--dry-run`` too, and a good ``--set``
    given with a bad one must not be applied either. The dash form of a top-level key,
    and the control, must exit 0 with ``fail_on_findings`` false in the file.
    """
    for sentence in _CONFIG_UPDATE_SET:
        assert_on_page(EXIT_CODES, sentence)
    config = tmp_path / "cfg" / "ash.yaml"
    config.parent.mkdir()
    original = b"project_name: demo\n"
    config.write_bytes(original)
    work = tmp_path / "work"
    work.mkdir()
    args = ["config", "update", str(config)]
    for value in sets:
        args += [value] if value == "--dry-run" else ["--set", value]

    result = _ash(args, cwd=work)

    if refused:
        assert result.returncode == 3, _output_tail(result)
        assert f"Not updating {config}:" in result.stdout, _output_tail(result)
        assert config.read_bytes() == original, _output_tail(result)
    else:
        assert result.returncode == 0, _output_tail(result)
        written = yaml.safe_load(config.read_text("utf-8"))
        assert written["fail_on_findings"] is False, _output_tail(result)


#: scale-large-repos.md (workspace mode): what --dry-run refuses before it prints a plan.
_DRY_RUN_IMPORTS_THE_MODULES = (
    "Before it prints the plan, it imports the plugin modules the run loads "
    "(`--ash-plugin-modules` and each project's `ash_plugin_modules`) and refuses what "
    "the run refuses before any project starts, with the run's exit 3 and message and "
    "no plan: a module outside the plugin namespace, a module that does not import, and "
    "two plugins of one type whose names are the same or that the config lookup reads "
    "as one, such as `csv_` beside `csv`."
)


@pytest.mark.parametrize(
    "case, refusal",
    [
        pytest.param(
            "csv_", "'csv_' (page_claims_names_ash_plugins)", id="csv_-beside-csv"
        ),
        pytest.param(
            "a-subclass-of-csv",
            "'csv' (class PageClaimsCsvReporter in page_claims_names_ash_plugins)",
            id="a-reporter-with-the-built-in-name",
        ),
        pytest.param(
            "scanner",
            "'Detect_Secrets' (page_claims_names_ash_plugins)",
            id="a-scanner-whose-name-reads-as-detect-secrets",
        ),
        pytest.param(
            "converter",
            "'Archive_' (page_claims_names_ash_plugins)",
            id="a-converter-whose-name-reads-as-archive",
        ),
        pytest.param(
            "no-import",
            "which could not be imported",
            id="a-module-that-does-not-import",
        ),
        pytest.param(
            "outside",
            "(outside ASH's plugin namespace)",
            id="a-module-outside-the-namespace",
        ),
        pytest.param(
            "project",
            "'csv_' (page_claims_names_ash_plugins)",
            id="csv_-in-a-project-config",
        ),
        pytest.param("own", None, id="control-a-reporter-with-a-name-of-its-own"),
    ],
)
@pytest.mark.integration
def test_a_workspace_dry_run_refuses_what_the_run_refuses_before_any_project(
    tmp_path: Path, case: str, refusal: Optional[str]
) -> None:
    """scale-large-repos.md (workspace mode: --dry-run), and exit-codes.md (Workspace mode).

    ``ash scan --workspace ... --dry-run`` loads a plugin module with
    ``--ash-plugin-modules``, or a project's config lists it. For a module with a
    reporter named ``csv_``, a reporter with the built-in ``csv``'s very name, a scanner
    or converter whose name reads as a built-in's, a module that does not import, and
    one outside the plugin namespace, the dry run must exit 3 with the run's refusal and
    print no plan. The control, a reporter with a name of its own, prints the plan and
    exits 0.
    """
    assert_on_page(SCALE_LARGE_REPOS, _DRY_RUN_IMPORTS_THE_MODULES)
    assert_on_page(EXIT_CODES, _NAME_CLASH_ROWS[1])
    if case == "a-subclass-of-csv":
        text = _CSV_SUBCLASS_MODULE
    elif case == "scanner":
        text = _SCANNER_NAMED_AS_ONE_MODULE
    elif case == "converter":
        text = _CONVERTER_NAMED_AS_ONE_MODULE
    else:
        own = "page-claims-own" if case == "own" else "csv_"
        text = _NAMED_REPORTER_MODULE.replace("NAME", repr(own))
    python_path = _plugin_path(tmp_path, _NAMES_MODULE, text)
    project = tmp_path / "ws" / "api"
    project.mkdir(parents=True)
    (project / "main.py").write_text("x = 1\n", encoding="utf-8")
    workspace = tmp_path / "ws" / "services.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), "utf-8")
    args = [*_CONFIG_SCAN, "--offline", "--workspace", str(workspace), "--dry-run"]
    args += ["--output-dir", str(tmp_path / "ws-output")]
    module = {"no-import": "page_claims_absent_ash_plugins", "outside": "json"}.get(
        case, _NAMES_MODULE
    )
    if case == "project":
        (project / ".ash").mkdir()
        (project / ".ash" / ".ash.yaml").write_text(
            yaml.safe_dump({"project_name": "api", "ash_plugin_modules": [module]}),
            encoding="utf-8",
        )
    else:
        args += ["--ash-plugin-modules", module]
    work = tmp_path / "work"
    work.mkdir()

    result = _ash(args, cwd=work, PYTHONPATH=python_path)
    text = _squeezed(result.stdout + result.stderr)

    if refusal is None:
        assert result.returncode == 0, _output_tail(result)
        assert "Workspace execution plan" in result.stdout, _output_tail(result)
        return
    assert result.returncode == 3, _output_tail(result)
    assert _squeezed(refusal) in text, _output_tail(result)
    assert "Workspace execution plan" not in result.stdout, _output_tail(result)


#: suppress-findings.md (path rules): a file name that is not valid UTF-8.
_A_NAME_THAT_IS_NOT_UTF8 = (
    "A file whose name is not valid UTF-8 is reported with each such byte written as "
    "`\\udcNN` (a latin-1 `secr\\xe9t.py` as `secr\\udce9t.py`). A `path` matches it "
    "written that way, since the `\\` of a `\\udcNN` escape is part of the name and not a "
    "separator, or with `?` for that `\\` (`secr?udce9t.py`), or by a glob such as "
    "`secr*t.py`. An ignore path matches such a file the same way when ASH lists the "
    "files to scan. A UTF-8 file name that spells the same `\\udcNN` text reads as the "
    "same name, so in a tree that holds both files, both are reported under that name, "
    "and a path that matches one matches both."
)
#: The name the report gives the latin-1 file secr<0xe9>t.py, as text.
_REPORTED_NAME = "secr\\udce9t.py"


def _write_non_utf8_name(tree: Path) -> None:
    """Create ``secr<0xe9>t.py`` in ``tree``, or skip where the platform cannot.

    APFS accepts only UTF-8 names and raises ``OSError``, and Windows decodes a
    bytes path as UTF-8 and raises before touching the filesystem: there the
    page's scenario cannot exist, which is the platform's claim, so the cell is
    skipped with that reason rather than failing in its own setup.
    """
    try:
        handle = open(  # noqa: SIM115 - the handle is closed on both branches
            os.path.join(os.fsencode(tree), b"secr\xe9t.py"), "wb"
        )
    except (OSError, UnicodeError) as refusal:
        assert sys.platform == "darwin" or os.name == "nt", refusal
        pytest.skip(f"this filesystem refuses a non-UTF-8 name: {refusal}")
    with handle:
        handle.write(_CONFIG_SECRET.encode("utf-8"))


@pytest.mark.parametrize(
    "setting, pattern, matches",
    [
        pytest.param(
            "suppressions", _REPORTED_NAME, True, id="suppression-as-reported"
        ),
        pytest.param("suppressions", "secr?udce9t.py", True, id="suppression-with-a-?"),
        pytest.param("suppressions", "secr*t.py", True, id="suppression-glob"),
        pytest.param(
            "suppressions", "secrét.py", False, id="control-suppression-in-utf-8"
        ),
        pytest.param(
            "ignore_paths", _REPORTED_NAME, True, id="ignore-path-as-reported"
        ),
        pytest.param("ignore_paths", "secr?udce9t.py", True, id="ignore-path-with-a-?"),
        pytest.param("ignore_paths", "secr*t.py", True, id="ignore-path-glob"),
        pytest.param(
            "ignore_paths", "secrét.py", False, id="control-ignore-path-in-utf-8"
        ),
    ],
)
@pytest.mark.integration
def test_a_path_matches_a_name_that_is_not_utf8_as_the_report_writes_it(
    tmp_path: Path, setting: str, pattern: str, matches: bool
) -> None:
    """suppress-findings.md (the path rules).

    A tree holds the same hardcoded password in ``secr<0xe9>t.py``, a latin-1 name that
    is not valid UTF-8, and in ``control.py``. The report must name the first
    ``secr\\udce9t.py``. A suppression whose ``path`` is that text, the text with ``?``
    for the backslash, or the glob ``secr*t.py`` must suppress its finding, and an
    ignore path of each form must keep the file out of the scan. The control is each
    setting spelled with a UTF-8 ``é``, which is another name: the finding is reported
    unsuppressed. ``control.py`` is reported unsuppressed in every cell.
    """
    assert_on_page(SUPPRESS_FINDINGS, _A_NAME_THAT_IS_NOT_UTF8)
    tree = _config_scan_tree(tmp_path, {"control.py": _CONFIG_SECRET})
    _write_non_utf8_name(tree)
    (tree / ".ash").mkdir()
    entry = {"path": pattern, "reason": "page claims"}
    (tree / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(
            {"project_name": "page-claims", "global_settings": {setting: [entry]}}
        ),
        encoding="utf-8",
    )
    output = tmp_path / "output"

    result = _ash(
        [
            *_CONFIG_SCAN,
            "--offline",
            "--source-dir",
            str(tree),
            "--output-dir",
            str(output),
        ],
        cwd=tmp_path,
    )

    suppressed = _suppressed_by_file(output)
    assert suppressed.get("control.py") is False, (suppressed, _output_tail(result))
    if setting == "ignore_paths" and matches:
        assert _REPORTED_NAME not in suppressed, (suppressed, _output_tail(result))
    else:
        assert suppressed.get(_REPORTED_NAME) is (
            setting == "suppressions" and matches
        ), (
            suppressed,
            _output_tail(result),
        )


@pytest.mark.parametrize("suppressed_by", [None, "secr?udce9t.py"])
@pytest.mark.integration
def test_a_utf8_name_that_spells_the_escape_reads_as_the_same_name(
    tmp_path: Path, suppressed_by: Optional[str]
) -> None:
    """suppress-findings.md (the path rules: a UTF-8 name that spells the escape).

    A tree holds the same hardcoded password in ``secr<0xe9>t.py`` and in a file whose
    UTF-8 name is the text ``secr\\udce9t.py``. Both findings must be reported under that
    one name. With a suppression that matches the name, both are suppressed; without
    one, both are reported unsuppressed.
    """
    assert_on_page(SUPPRESS_FINDINGS, _A_NAME_THAT_IS_NOT_UTF8)
    tree = _config_scan_tree(tmp_path, {_REPORTED_NAME: _CONFIG_SECRET})
    _write_non_utf8_name(tree)
    if suppressed_by is not None:
        (tree / ".ash").mkdir()
        entry = {"path": suppressed_by, "reason": "page claims"}
        (tree / ".ash" / ".ash.yaml").write_text(
            yaml.safe_dump(
                {
                    "project_name": "page-claims",
                    "global_settings": {"suppressions": [entry]},
                }
            ),
            encoding="utf-8",
        )
    output = tmp_path / "output"

    result = _ash(
        [
            *_CONFIG_SCAN,
            "--offline",
            "--source-dir",
            str(tree),
            "--output-dir",
            str(output),
        ],
        cwd=tmp_path,
    )

    sarif = json.loads((output / "reports" / "ash.sarif").read_text(encoding="utf-8"))
    flags = [
        bool(found.get("suppressions"))
        for run in sarif.get("runs", [])
        for found in run.get("results", [])
        if found["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == _REPORTED_NAME
    ]
    assert flags == [suppressed_by is not None] * 2, (flags, _output_tail(result))


#: read-results.md's ERROR row on a tool a signal ended.
_A_SIGNAL_ENDED_TOOL_IS_AN_ERROR = (
    "On Linux and macOS, a tool ended by a signal ASH did not send, such as an "
    "out-of-memory kill, is `ERROR` whatever exit codes the scanner accepts, with an "
    "error that names the signal and an exit code of 128 plus the signal's number."
)

#: read-results.md's note under the scanner status table: which sandbox backends'
#: own exit codes are read back as a likely signal death (by each backend plan's
#: declaration), the count-of-findings opt-out, and who keeps such an exit as the
#: tool's own answer. assert_on_page holds the cells below to the page's wording;
#: the behavior each sentence claims is what the cells themselves run.
_A_DECLARED_SANDBOX_EXIT_IS_READ_BACK = (
    "Under a sandbox backend that reports a signal death as its own exit (bwrap "
    "and firejail; ASH knows which backends report this way), a scanner exit of "
    "128+N is read back as a likely death by signal N: the scanner's row is "
    "ERROR with a reason that says 'likely' and names the exit code it came "
    "from, and the run's exit reflects it. This is an inference from the shell "
    "convention. A scanner that declares its tool's exit code a count of "
    "findings (cfn_nag) opts out, and such an exit grades by the findings the "
    "tool rendered; a native signal death still reads as one for every scanner. "
    "Unsandboxed runs and backends without the behavior keep such an exit as "
    "the tool's own answer."
)

#: The note's second paragraph: the mapped range (the boundary cells), the
#: fail-closed direction (the own-137 cell), and the count opt-out's traded
#: exception (the OOM-killed count cell) are stated, not implied.
_THE_READ_BACK_RANGE_AND_DIRECTION = (
    "The read-back takes only exits 129 through 192 (N of 1 to 64); 128, 255 and "
    "codes above the range stay the tool's own answer. Its fail-closed direction "
    "is deliberate: a tool that itself exits with such a code under such a "
    "backend reads as a signal death, which errs toward never reporting a killed "
    "scan as passed. The count opt-out trades that direction away for its "
    "scanner: under such a backend a count-declaring scanner's death by signal "
    "arrives only as the backend's own 128+N exit, indistinguishable by the "
    "exit code alone from a count, so it grades by the findings the tool "
    "rendered."
)

#: read-results.md's ERROR row on a scanner with more than one target.
_ANY_TARGET_MAKES_THE_ROW_AN_ERROR = (
    "One good target does not outweigh another, so the row is `ERROR` when any "
    "target failed or was never evaluated."
)

#: A plugin scanner that starts its tool through the plugin's helper and ignores the
#: tool's exit code. The tool dies by the signal ASH_PAGE_CLAIMS_SIGNAL names, or exits
#: 0 without it.
_SIGNALED_PLUGIN = """\
import os
import sys
from typing import Annotated, Any, ClassVar, Literal

from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin

# The exit code and the signal name are baked in by scan(), which runs in ASH's
# own process: the sandbox hands the tool a filtered environment, so a value read
# inside the tool could come back empty under a stricter filter and the cell
# would measure a plain exit 0 instead of the kill or the exit it set up.
_TOOL_TEMPLATE = (
    # SIG_DFL first: an ignored disposition survives fork/exec (nohup, some CI
    # agents ignore SIGHUP), and restore_signals resets only SIGPIPE/SIGXFZ/SIGXFSZ.
    # SIGKILL's disposition cannot be set, and needs no reset. EXIT_CODE makes
    # the tool exit with that code itself, no signal involved.
    "import os, signal, sys; "
    "code = EXIT_CODE or None; "
    "code and sys.exit(int(code)); "
    "name = SIGNAL_NAME or None; "
    "sig = getattr(signal, name) if name else None; "
    "name and name != 'SIGKILL' and signal.signal(sig, signal.SIG_DFL); "
    "name and os.kill(os.getpid(), sig)"
)


class SigScannerOptions(ScannerOptionsBase):
    pass


class SigScannerConfig(ScannerPluginConfigBase):
    name: Literal["page-claims-sig"] = "page-claims-sig"
    enabled: bool = True
    options: Annotated[SigScannerOptions, Field()] = SigScannerOptions()


@ash_scanner_plugin
class SigScanner(ScannerPluginBase[SigScannerConfig]):
    # Read at import, in ASH's own process like the values scan() bakes: with
    # it set the plugin declares its tool's exit code a count of findings, the
    # declaration read-results.md names for cfn_nag.
    tool_exit_code_is_a_count: ClassVar[bool] = (
        os.environ.get("ASH_PAGE_CLAIMS_COUNT_EXIT") == "1"
    )

    def model_post_init(self, context):
        if self.config is None:
            self.config = SigScannerConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError

    def scan(self, target, target_type, config: Any = None, *args, **kwargs):
        self._pre_scan(target, target_type, config)
        record = os.environ.get("ASH_PAGE_CLAIMS_TARGET_RECORD")
        if record:
            with open(record, "a", encoding="utf-8") as handle:
                handle.write(str(target_type).lower() + "\\n")
        code = os.environ.get("ASH_PAGE_CLAIMS_EXIT") or ""
        name = os.environ.get("ASH_PAGE_CLAIMS_SIGNAL") or ""
        only = os.environ.get("ASH_PAGE_CLAIMS_SIGNAL_TARGET")
        dies = not only or only in str(target_type).lower()
        tool = (
            _TOOL_TEMPLATE.replace("EXIT_CODE", repr(code)).replace(
                "SIGNAL_NAME", repr(name)
            )
            if dies
            else "pass"
        )
        self._run_subprocess(
            [sys.executable, "-c", tool],
            results_dir=str(self.results_dir),
        )
        self._post_scan(target, target_type)
        return {"findings": []}


ASH_SCANNERS = [SigScanner]
"""


_POSIX_SIGNALS = pytest.mark.skipif(
    os.name == "nt", reason="SIGKILL and SIGHUP are POSIX signals"
)

#: The read-back reason's phrases, asserted absent outside the declared
#: backends. test_the_read_back_absence_phrases_are_ashs_wording holds both to
#: ASH's own wording where this tree carries the source, so a product reword
#: fails that one test loudly on code trees instead of leaving the absence
#: checks matching nothing.
_READ_BACK_FRAGMENT = "the sandbox reported exit code"
_READ_BACK_LIKELY_PREFIX = "the tool was likely ended by"

#: The sandbox backend class each --sandbox value resolves to, shared by the
#: signal and count tests so the two cannot drift apart.
_SANDBOX_BACKEND_OF = {
    "bwrap": "BwrapBackend",
    "auto": "BwrapBackend",
    "firejail": "FirejailBackend",
    "landlock": "LandlockBackend",
}


@pytest.mark.unit
def test_the_read_back_absence_phrases_are_ashs_wording() -> None:
    """Where this tree carries the read-back's source, both phrases the scan
    cells assert absent are held to it here, once and under its own name: a
    product reword fails this one test instead of every scan cell identically,
    and the cells stay independent of the message function. A tree with no
    sandbox backends at all has no read-back to hold wording to and skips; a
    tree WITH the backends but without the wording source fails, because on
    such a tree the absence checks would hold stale text while looking green.
    Runs on every platform: describe_signal, read rather than trusted from its
    docstring, falls back to "signal 9" where the number has no Signals member,
    so the message builder cannot raise on Windows."""
    try:
        importlib.import_module("automated_security_helper.utils.sandbox.backends")
    except ImportError:
        pytest.skip(
            "this tree has no sandbox backends, so no read-back wording to hold"
        )
    try:
        from automated_security_helper.utils.subprocess_utils import (
            inferred_signal_death_message,
        )
    except ImportError:
        pytest.fail(
            "this tree has sandbox backends but no inferred_signal_death_message: "
            "the read-back's wording source moved or was renamed, so the scan "
            "cells' absence checks would hold stale text"
        )
    message = inferred_signal_death_message(9, 137)
    assert message.startswith(_READ_BACK_LIKELY_PREFIX), message
    assert f"{_READ_BACK_FRAGMENT} 137" in message, message


def _read_back_message(signum: int, returncode: int) -> str:
    """The read-back's full reason, from ASH's own source where this tree has it,
    so a product reword moves these asserts with it; otherwise the wording
    measured on the code tree these cells meet at the stacked head."""
    try:
        from automated_security_helper.utils.subprocess_utils import (
            inferred_signal_death_message,
        )
    except ImportError:
        measured = {
            1: "SIGHUP (signal 1)",
            9: "SIGKILL (signal 9)",
            64: "SIGRTMAX (signal 64)",
        }
        assert signum in measured, (
            "the fallback wording was measured for these signals only"
        )
        return (
            f"{_READ_BACK_LIKELY_PREFIX} {measured[signum]}, a signal ASH did "
            f"not send: {_READ_BACK_FRAGMENT} {returncode}, the shell "
            "convention for a death by that signal"
        )
    message = inferred_signal_death_message(signum, returncode)
    # Both ends: the derived string is what the scan prints, and the page's own
    # claim (the reason says 'likely' and names the exit code) still binds it,
    # so a product reword that drops either fails here, not silently.
    assert "likely" in message, message
    assert f"{_READ_BACK_FRAGMENT} {returncode}" in message, message
    return message


@lru_cache(maxsize=None)
def _backend_unavailable(class_name: str) -> Optional[str]:
    """Why the named sandbox backend cannot make the sandbox ASH asks for, as
    ASH's own availability probe says it, or None when it can, so the gate
    cannot drift from the backend's real requirements and the skip carries the
    probe's own reason instead of blaming the host. Only two shapes read as a
    tree property and skip: a ModuleNotFoundError naming the backends module
    (or an ancestor package) itself, and a backends module without the class.
    Every other exception propagates and errors the cell - a dependency the
    backends module failed to import, a crash in the probe, or a child
    interpreter that could not start are real breakage, never a quiet skip.
    Called inside the cells that need it (pytest.skip), never at collection, so
    deselected runs start no process and a refusal is attributed to the cell.
    ASH's bwrap probe rejects a host whose user namespaces are off, and its
    firejail probe a firejail that thinks it is already inside a sandbox and
    would run the command unconfined."""
    module_name = "automated_security_helper.utils.sandbox.backends"
    try:
        backends = importlib.import_module(module_name)
    except ModuleNotFoundError as error:
        missing = error.name or ""
        if missing == module_name or module_name.startswith(missing + "."):
            return f"this tree has no sandbox backends module to probe ({error})"
        # The backends module exists but a dependency inside it is missing:
        # that is breakage on a code tree, so it errors the cell.
        raise
    if getattr(backends, class_name, None) is None:
        return f"this tree's sandbox backends module has no {class_name}"
    # The probe runs in a contained child of this interpreter, the shape the
    # code tiers' real-program guard admits, so the backend binary it starts
    # (or the landlock ABI check's own interpreter) is the probe's child, not
    # this process's, and the probe runs off the network and the real home.
    # ASH's probe builds its child's environment itself, which is why an
    # in-process call cannot be contained from here.
    scratch = Path(tempfile.mkdtemp(prefix="ash-backend-probe-"))
    probe = (
        "from automated_security_helper.utils.sandbox import backends\n"
        f"print(repr(backends.{class_name}()._probe()))\n"
    )
    # A spawn failure or a hang (TimeoutExpired) propagates and errors the
    # cell: this interpreter failing to start its own executable is never a
    # backend property. Anything the probe itself raises arrives below as a
    # non-zero exit instead, and that fails the cell.
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=scratch,
        env={**os.environ, **_child_containment(scratch)},
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        # A probe that CRASHES must fail the cells, not skip them: a refactor
        # that breaks the probe on a working-sandbox host would otherwise turn
        # every sandbox cell green-by-skip, the regression class they exist
        # for. Only a probe that answers (exit 0, a reason or None) may skip.
        tail = (result.stderr or result.stdout).strip()[-300:]
        pytest.fail(
            f"the {class_name} probe did not answer (exit {result.returncode}): {tail}"
        )
    return ast.literal_eval(result.stdout.strip().splitlines()[-1])


def _skip_unless_backend_runs(backend_name: str, class_name: str) -> None:
    """Skip with the probe's own reason where the backend cannot sandbox - or
    FAIL where the environment declares it must (ASH_REQUIRE_SANDBOX_BACKENDS,
    the sandbox CI job's list), so a probe regression reads as a red on the
    hosts that install the backends instead of hiding as quiet skips."""
    reason = _backend_unavailable(class_name)
    if reason is None:
        return
    required = {
        name.strip()
        for name in os.environ.get("ASH_REQUIRE_SANDBOX_BACKENDS", "").split(",")
        if name.strip()
    }
    if backend_name in required:
        pytest.fail(
            f"{backend_name} is declared required here "
            f"(ASH_REQUIRE_SANDBOX_BACKENDS) but cannot sandbox: {reason}"
        )
    pytest.skip(f"{backend_name} cannot sandbox here: {reason}")


@pytest.mark.parametrize(
    "signal_name, sandbox, tool_exit, status, exit_code, read_back",
    [
        pytest.param(
            "SIGKILL",
            None,
            None,
            "ERROR",
            137,
            False,
            id="an-oom-style-kill",
            marks=_POSIX_SIGNALS,
        ),
        pytest.param(
            "SIGHUP",
            None,
            None,
            "ERROR",
            129,
            False,
            id="a-sighup",
            marks=_POSIX_SIGNALS,
        ),
        pytest.param(
            "SIGKILL",
            "off",
            None,
            "ERROR",
            137,
            False,
            id="sandbox-off-is-the-same-path",
            marks=_POSIX_SIGNALS,
        ),
        pytest.param(
            "SIGKILL",
            "bwrap",
            None,
            "ERROR",
            137,
            True,
            id="a-bwrap-exit-read-back-as-the-likely-signal",
            marks=_POSIX_SIGNALS,
        ),
        pytest.param(
            "SIGKILL",
            "firejail",
            None,
            "ERROR",
            137,
            True,
            id="a-firejail-exit-read-back-the-same-way",
            marks=_POSIX_SIGNALS,
        ),
        pytest.param(
            "SIGKILL",
            "auto",
            None,
            "ERROR",
            137,
            True,
            id="auto-resolving-to-bwrap-reads-back",
            marks=_POSIX_SIGNALS,
        ),
        pytest.param(
            None,
            "bwrap",
            137,
            "ERROR",
            137,
            True,
            id="a-tools-own-137-under-bwrap-reads-as-a-signal-death",
        ),
        pytest.param(
            None,
            "bwrap",
            129,
            "ERROR",
            129,
            True,
            id="a-bwrap-exit-129-is-the-first-read-back",
        ),
        pytest.param(
            None,
            "bwrap",
            128,
            "PASSED",
            128,
            False,
            id="a-bwrap-exit-128-is-below-the-signal-range",
        ),
        pytest.param(
            None,
            "bwrap",
            255,
            "PASSED",
            255,
            False,
            id="a-bwrap-exit-255-is-beyond-the-signal-range",
        ),
        pytest.param(
            None,
            "bwrap",
            192,
            "ERROR",
            192,
            True,
            id="a-bwrap-exit-192-is-the-last-read-back",
        ),
        pytest.param(
            None,
            "bwrap",
            193,
            "PASSED",
            193,
            False,
            id="a-bwrap-exit-193-is-past-the-last-read-back",
        ),
        pytest.param(
            None,
            "landlock",
            137,
            "PASSED",
            137,
            False,
            id="a-non-declaring-backend-keeps-the-tools-answer",
        ),
        pytest.param(
            None,
            "off",
            137,
            "PASSED",
            137,
            False,
            id="an-unsandboxed-137-stays-the-tools-answer",
        ),
        pytest.param(
            None, None, None, "PASSED", 0, False, id="control-the-tool-exits-0"
        ),
    ],
)
@pytest.mark.integration
def test_a_tool_a_signal_ended_is_an_error_naming_the_signal(
    tmp_path: Path,
    signal_name: Optional[str],
    sandbox: Optional[str],
    tool_exit: Optional[int],
    status: str,
    exit_code: int,
    read_back: bool,
) -> None:
    """read-results.md (the ERROR row, and the read-back note under the table).

    A plugin scanner starts its tool through ASH's helper, ignores the tool's exit
    code, and returns a result claiming success. When the tool dies by SIGKILL or
    SIGHUP, the scan must record the scanner ``ERROR`` with exit code 128 plus the
    signal's number, name the signal in its output or log, and exit 1, with the
    sandbox left at its default or set to ``off`` alike. Under a backend whose
    plan declares that it reports a signal death as its own exit (bwrap and
    firejail, also when ``auto`` resolves to one), an exit of 128+N is read back
    as the likely signal: the row is ``ERROR`` with a reason that says 'likely'
    and names the exit code it came from, and a tool that itself exits 137 under
    such a backend reads the same way, the fail-closed direction. The read-back
    takes only the shell signal range: 128 (N would be 0) and 255 (N would be
    127) stay the tool's own answer under bwrap, as does 137 with the sandbox
    off. Both edges are pinned exactly: 129 is the first exit read back (signal
    1) and 192 the last (signal 64), while 193 is kept as the tool's own
    answer, so an off-by-one at either end fails a cell. A backend that
    reports a signal death natively (landlock) keeps a tool's own 137 too, the
    keep direction for backends without the read-back behavior. The control,
    the same tool exiting 0, is ``PASSED`` with exit 0.
    """
    assert_on_page(READ_RESULTS, _A_SIGNAL_ENDED_TOOL_IS_AN_ERROR)
    assert_on_page(READ_RESULTS, _A_DECLARED_SANDBOX_EXIT_IS_READ_BACK)
    assert_on_page(READ_RESULTS, _THE_READ_BACK_RANGE_AND_DIRECTION)
    if sandbox in _SANDBOX_BACKEND_OF:
        _skip_unless_backend_runs(
            "bwrap" if sandbox == "auto" else sandbox, _SANDBOX_BACKEND_OF[sandbox]
        )
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    output = tmp_path / "out"
    work = tmp_path / "work"
    work.mkdir()
    module = "page_claims_sig_ash_plugins"
    args = [
        "scan",
        "--scanners",
        "page-claims-sig",
        "--no-progress",
        "--offline",
        "--mode",
        "local",
        "--source-dir",
        str(tree),
        "--output-dir",
        str(output),
        "--config-overrides",
        f"ash_plugin_modules+=[{module}]",
    ]
    if sandbox:
        args += ["--sandbox", sandbox]
    env = {}
    if signal_name:
        env["ASH_PAGE_CLAIMS_SIGNAL"] = signal_name
    if tool_exit is not None:
        env["ASH_PAGE_CLAIMS_EXIT"] = str(tool_exit)

    result = _ash(
        args,
        cwd=work,
        PYTHONPATH=_plugin_path(tmp_path, module, _SIGNALED_PLUGIN),
        **env,
    )

    results = json.loads((output / "ash_aggregated_results.json").read_text("utf-8"))
    recorded = results["scanner_results"]["page-claims-sig"]
    assert recorded["status"] == status, (recorded, _output_tail(result))
    assert recorded["exit_code"] == exit_code, (recorded, _output_tail(result))
    assert result.returncode == (1 if status == "ERROR" else 0), _output_tail(result)
    log = output / "ash.log"
    text = result.stdout + result.stderr
    text += log.read_text("utf-8", errors="replace") if log.is_file() else ""
    if signal_name and status == "ERROR":
        assert f"{signal_name} (signal" in text, _output_tail(result)
    if read_back:
        # The read-back's full reason, inference-labeled and naming the exit
        # code it came from, not a bare English word a warning could carry.
        assert _read_back_message(exit_code - 128, exit_code) in text, _output_tail(
            result
        )
    else:
        # The read-back's own phrase: no cell outside the declared backends may
        # attribute the exit to a signal this way.
        assert _READ_BACK_FRAGMENT not in text, _output_tail(result)
    if sandbox == "auto":
        # The resolution the cell's expectations assume, from the scan's own log.
        assert "using bwrap (--sandbox auto)" in text, _output_tail(result)


@pytest.mark.parametrize(
    "signal_name, sandbox, status, exit_code",
    [
        pytest.param(
            None,
            "bwrap",
            "PASSED",
            137,
            id="a-count-of-137-under-bwrap-grades-by-findings",
        ),
        pytest.param(
            "SIGKILL",
            "bwrap",
            "PASSED",
            137,
            id="an-oom-killed-count-scanner-under-bwrap-grades-by-findings",
            marks=_POSIX_SIGNALS,
        ),
        pytest.param(
            "SIGKILL",
            "off",
            "ERROR",
            137,
            id="a-native-signal-death-still-reads-as-one",
            marks=_POSIX_SIGNALS,
        ),
    ],
)
@pytest.mark.integration
def test_a_count_exit_scanner_opts_out_of_the_read_back(
    tmp_path: Path,
    signal_name: Optional[str],
    sandbox: str,
    status: str,
    exit_code: int,
) -> None:
    """read-results.md (the read-back note under the table): the count opt-out.

    The plugin declares its tool's exit code a count of findings, the declaration
    the note names for cfn_nag. Its tool exiting 137 under bwrap then grades by
    the findings it rendered (none here, so ``PASSED`` with the exit kept), with
    no read-back reason, and the same holds when the tool is SIGKILLed under
    bwrap: the sandbox reports the death only as its own exit of 137, which the
    declaration reads as the count, the traded exception the note states. A
    native signal death, subprocess's own report with the sandbox off, still
    reads as one for every scanner: the row is ``ERROR`` and the error names the
    signal without the read-back's inference label.
    """
    assert_on_page(READ_RESULTS, _A_DECLARED_SANDBOX_EXIT_IS_READ_BACK)
    assert_on_page(READ_RESULTS, _THE_READ_BACK_RANGE_AND_DIRECTION)
    if sandbox == "bwrap":
        _skip_unless_backend_runs("bwrap", _SANDBOX_BACKEND_OF["bwrap"])
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    output = tmp_path / "out"
    work = tmp_path / "work"
    work.mkdir()
    module = "page_claims_sig_ash_plugins"
    env = {"ASH_PAGE_CLAIMS_COUNT_EXIT": "1"}
    if signal_name:
        env["ASH_PAGE_CLAIMS_SIGNAL"] = signal_name
    else:
        env["ASH_PAGE_CLAIMS_EXIT"] = "137"

    result = _ash(
        [
            "scan",
            "--scanners",
            "page-claims-sig",
            "--no-progress",
            "--offline",
            "--mode",
            "local",
            "--source-dir",
            str(tree),
            "--output-dir",
            str(output),
            "--config-overrides",
            f"ash_plugin_modules+=[{module}]",
            "--sandbox",
            sandbox,
        ],
        cwd=work,
        PYTHONPATH=_plugin_path(tmp_path, module, _SIGNALED_PLUGIN),
        **env,
    )

    results = json.loads((output / "ash_aggregated_results.json").read_text("utf-8"))
    recorded = results["scanner_results"]["page-claims-sig"]
    assert recorded["status"] == status, (recorded, _output_tail(result))
    assert recorded["exit_code"] == exit_code, (recorded, _output_tail(result))
    assert result.returncode == (1 if status == "ERROR" else 0), _output_tail(result)
    log = output / "ash.log"
    text = result.stdout + result.stderr
    text += log.read_text("utf-8", errors="replace") if log.is_file() else ""
    # No cell may carry the read-back's inference: the count cells were opted
    # out, and the native death is reported as fact, not read from an exit code.
    assert _READ_BACK_LIKELY_PREFIX not in text, _output_tail(result)
    assert _READ_BACK_FRAGMENT not in text, _output_tail(result)
    if signal_name and status == "ERROR":
        assert f"{signal_name} (signal" in text, _output_tail(result)


@pytest.mark.unit
def test_cfn_nag_declares_its_tool_exit_code_a_count() -> None:
    """read-results.md (the read-back note): the note names cfn_nag as the
    shipped scanner whose exit code is a count of findings. The cells above take
    the declaration through a synthetic plugin; this holds the named shipped
    scanner class to it, so the page's one concrete example cannot drift from
    the code that carries the declaration."""
    assert_on_page(READ_RESULTS, _A_DECLARED_SANDBOX_EXIT_IS_READ_BACK)
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
        CfnNagScanner,
    )

    # The declaration is a ClassVar on the code tree this cell meets at the
    # stacked head (cfn_nag_scanner.py, measured), which plain class access
    # reads. If a refactor turns it into a pydantic field, class access raises
    # AttributeError (and getattr would read its own False default), so the
    # field's declared default is consulted before deciding. Like the wording
    # test above: a tree with no count-exit declaration anywhere (no class
    # attribute, no field) has nothing to hold cfn_nag to and skips; a tree
    # that CARRIES the declaration concept but whose cfn_nag does not declare
    # True is inconsistent with the page and fails.
    declared = getattr(CfnNagScanner, "tool_exit_code_is_a_count", None)
    if not isinstance(declared, bool):
        field = getattr(CfnNagScanner, "model_fields", {}).get(
            "tool_exit_code_is_a_count"
        )
        declared = getattr(field, "default", None)
    if declared is None:
        pytest.skip(
            "this tree's scanner classes carry no tool_exit_code_is_a_count "
            "declaration to hold cfn_nag to"
        )
    assert declared is True, (
        "the page names cfn_nag as the count-declaring scanner, but the class "
        "does not declare tool_exit_code_is_a_count"
    )


@_POSIX_SIGNALS
@pytest.mark.parametrize("dying_target", ["source", "converted"])
@pytest.mark.integration
def test_a_signal_on_one_target_makes_the_row_an_error(
    tmp_path: Path, dying_target: str
) -> None:
    """read-results.md (the ERROR row): per-target accounting.

    The plugin's tool dies by SIGKILL for one target and exits 0 for the other:
    each target in turn (the source tree, and a zip the archive converter
    extracted) is the one that dies, so a row that merely kept the last target's
    result fails one of the two cells whatever order the targets are scanned in.
    One good target does not outweigh the other: the row is ``ERROR`` with the
    signal's code, and the run exits 1. The plugin records each target type it
    saw, so a run that folded the targets together or skipped one cannot pass.
    """
    assert_on_page(READ_RESULTS, _ANY_TARGET_MAKES_THE_ROW_AN_ERROR)
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    with zipfile.ZipFile(tree / "bundle.zip", "w") as archive:
        archive.writestr("inner.py", "y = 2\n")
    output = tmp_path / "out"
    work = tmp_path / "work"
    work.mkdir()
    module = "page_claims_sig_ash_plugins"
    ran_targets = tmp_path / "ran-targets.txt"

    result = _ash(
        [
            "scan",
            "--scanners",
            "page-claims-sig",
            "--no-progress",
            "--offline",
            "--mode",
            "local",
            "--source-dir",
            str(tree),
            "--output-dir",
            str(output),
            "--config-overrides",
            f"ash_plugin_modules+=[{module}]",
        ],
        cwd=work,
        PYTHONPATH=_plugin_path(tmp_path, module, _SIGNALED_PLUGIN),
        ASH_PAGE_CLAIMS_SIGNAL="SIGKILL",
        ASH_PAGE_CLAIMS_SIGNAL_TARGET=dying_target,
        ASH_PAGE_CLAIMS_TARGET_RECORD=str(ran_targets),
    )

    results = json.loads((output / "ash_aggregated_results.json").read_text("utf-8"))
    recorded = results["scanner_results"]["page-claims-sig"]
    assert recorded["status"] == "ERROR", (recorded, _output_tail(result))
    assert recorded["exit_code"] == 137, (recorded, _output_tail(result))
    assert result.returncode == 1, _output_tail(result)
    # "One target" holds only if the other ran too: both target types scanned.
    seen = ran_targets.read_text("utf-8") if ran_targets.is_file() else ""
    for target_type in ("source", "converted"):
        assert any(target_type in line for line in seen.splitlines()), (
            target_type,
            seen,
            _output_tail(result),
        )


#: A uv that answers the runner's probes and, for a real ``tool run``, dies by the
#: signal ASH_PAGE_CLAIMS_SIGNAL names (or exits 0 without it), the way a tool
#: killed under ``uv tool run`` reaches ASH. ASH prefers the uv installed with it
#: (``bundled_uv_executable``) over any PATH entry, by design, so the cell points
#: the runner at this stand-in with ``for_probed_uv`` rather than through PATH;
#: everything after the lookup, the uv branch, the flag carry-through and the
#: recorders, runs real code on a real subprocess.
_UV_STAND_IN = """\
import os
import signal
import sys

args = sys.argv[1:]
if args[:2] == ["tool", "run"]:
    if args and args[-1] == "--version":
        print("page-claims-sig-tool 1.0")
        sys.exit(0)
    name = os.environ.get("ASH_PAGE_CLAIMS_SIGNAL")
    if name:
        sig = getattr(signal, name)
        if name != "SIGKILL":
            signal.signal(sig, signal.SIG_DFL)
        os.kill(os.getpid(), sig)
    sys.exit(0)
print("uv 0.0-page-claims-stand-in")
sys.exit(0)
"""


@pytest.mark.parametrize(
    "signal_name, status_name, exit_code",
    [
        pytest.param(
            "SIGKILL", "ERROR", 137, id="a-kill-under-uv", marks=_POSIX_SIGNALS
        ),
        pytest.param(None, "PASSED", 0, id="control-the-uv-run-exits-0"),
    ],
)
@pytest.mark.allow_real_program(
    "uv-stand-in.cmd" if os.name == "nt" else "uv-stand-in",
    where="tmp",
    reason="the test's own uv stand-in, which the pinned runner starts as this "
    "process's child; it runs the recorded Python script with this interpreter "
    "(through cmd on Windows), answers the probes, dies by the named signal for "
    "a real tool run, and starts nothing beyond that",
)
@pytest.mark.unit
def test_a_uv_tool_scanners_tool_ended_by_a_signal_is_the_same_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_name: Optional[str],
    status_name: str,
    exit_code: int,
) -> None:
    """read-results.md (the ERROR row): the uv-tool execution path.

    A scanner with ``use_uv_tool`` runs its tool through ``uv tool run``, the path
    the shipped Python scanners take, and that branch must carry a signal death
    through to the same record as a directly started tool: the row is ``ERROR``
    with 128 plus the signal's number, and the error names the signal. The uv here
    is a stand-in executable that really dies by the named signal; only the uv
    lookup is pinned (``for_probed_uv``), because ASH prefers its own bundled uv
    over PATH. The sandbox mode is explicitly ``off``. The control, the same uv
    exiting 0, is not ``ERROR``.
    """
    assert_on_page(READ_RESULTS, _A_SIGNAL_ENDED_TOOL_IS_AN_ERROR)
    from unittest.mock import MagicMock

    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.base.scanner_plugin import (
        ScannerPluginBase,
        ScannerPluginConfigBase,
    )
    from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.enums import ScannerStatus
    from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils import uv_tool_runner
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    PluginContext.model_rebuild()
    AshConfig.model_rebuild()
    AshAggregatedResults.model_rebuild()

    script = tmp_path / "uv-stand-in.py"
    script.write_text(_UV_STAND_IN, encoding="utf-8")
    stand_in = _interpreter_launcher(tmp_path, "uv-stand-in", script)
    monkeypatch.setattr(
        uv_tool_runner,
        "get_uv_tool_runner",
        lambda: UVToolRunner.for_probed_uv(str(stand_in)),
    )
    if signal_name:
        monkeypatch.setenv("ASH_PAGE_CLAIMS_SIGNAL", signal_name)
    else:
        monkeypatch.delenv("ASH_PAGE_CLAIMS_SIGNAL", raising=False)

    class UvSigConfig(ScannerPluginConfigBase):
        name: str = "page-claims-uvsig"

    class UvSigScanner(ScannerPluginBase):
        command: Optional[str] = "page-claims-sig-tool"
        use_uv_tool: bool = True

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError("scan() is overridden directly")

        def scan(self, target, target_type=None, *args, **kwargs):
            self._run_subprocess(
                [self.command], results_dir=str(self.results_dir), timeout=60
            )
            return {"severity_counts": {}}

    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    sandbox_off = SandboxConfig(mode="off")
    config = get_default_config().model_copy(update={"sandbox": sandbox_off})
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=tmp_path / "work",
        config=config,
    )
    scanner = UvSigScanner(config=UvSigConfig(), context=context)
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )

    # The private seam, deliberately: the executor's public entry points
    # (run_sequential, run_parallel) need the phase's task queue and progress
    # plumbing, while the claim here is the per-scanner record one invocation
    # produces. A rename or re-signature of this seam fails here as a TypeError,
    # which is the alarm to re-point this cell, not a page-claim verdict.
    (container,) = executor._execute_scanner(
        "page-claims-uvsig", scanner, [{"path": source, "type": "source"}]
    )

    assert container.status == getattr(ScannerStatus, status_name), (
        container.status,
        container,
    )
    assert container.exit_code == exit_code, (container.exit_code, container)
    if signal_name:
        errors = (container.raw_results or {}).get("errors") or []
        assert errors and f"{signal_name} (signal" in errors[0], (errors, container)
    else:
        assert container.status != ScannerStatus.ERROR, container


SCANNING_UNTRUSTED = "concepts/scanning-untrusted-code.md"

#: concepts/sandbox.md (What fails closed): the record of a sandbox ASH cannot provide.
_A_SANDBOX_ASH_CANNOT_PROVIDE = (
    "Its tool cannot start as asked, so each scan is recorded `ERROR` with the "
    "start-failure code 127 as the scanner's `exit_code` in "
    "`ash_aggregated_results.json`, and the default `fail_on_incomplete_scanners` "
    "makes the scan exit 1; 127 is the scanner's recorded code, not the exit status."
)

#: concepts/sandbox.md's example line, as ash.log writes it on Linux.
_THE_START_FAILURE_LINE = (
    "detect-secrets could not start its tool on source: sandbox-exec is not "
    "available: sandbox-exec is not available on Linux"
)

#: concepts/scanning-untrusted-code.md (Putting the defenses together).
_A_BACKEND_THAT_CANNOT_SANDBOX = (
    "If a backend cannot sandbox a scanner, its scans are ERROR with the "
    "start-failure code 127 and its tool never runs unsandboxed; a scanner whose "
    "tool exists only inside the repository is MISSING."
)

#: concepts/scanning-untrusted-code.md, the HOME the sandbox needs.
_A_RELATIVE_HOME_REFUSES_THE_SANDBOX = (
    "With an empty or relative `HOME`, a scanner it would run is not run and is "
    "ERROR, with `HOME is not an absolute path` in its error."
)

#: read-results.md's ERROR row on a tool that never started.
_ERROR_COVERS_A_TOOL_THAT_NEVER_STARTED = (
    "its tool failed, or never started as asked, recorded with the start-failure "
    "code 127 (a sandbox the configuration asks for that ASH cannot provide, for "
    "example)."
)

#: read-results.md on the row's exit_code field.
_EXIT_CODE_127_IN_THE_ROW = (
    "the start-failure code 127 for a tool that could not start as asked, or "
    "`null` when no tool ran."
)

#: set-the-gate.md (Incomplete scans).
_THE_GATE_LISTS_A_TOOL_THAT_COULD_NOT_START = (
    "ERROR (it failed, or its tool could not start, as when a sandbox the "
    "configuration asks for cannot be provided), MISSING (its tool is not installed)"
)


@pytest.mark.parametrize(
    "cell, status, exit_code, returncode",
    [
        pytest.param(
            "a-backend-this-host-lacks", "ERROR", 127, 1, id="a-backend-this-host-lacks"
        ),
        pytest.param(
            "the-gate-off-keeps-the-row",
            "ERROR",
            127,
            0,
            id="the-gate-off-keeps-the-row",
        ),
        pytest.param(
            "a-relative-home",
            "ERROR",
            127,
            1,
            id="a-relative-home",
            marks=pytest.mark.skipif(
                sys.platform != "linux", reason="landlock is Linux-only"
            ),
        ),
        pytest.param(
            "a-empty-home",
            "ERROR",
            127,
            1,
            id="a-empty-home",
            marks=pytest.mark.skipif(
                sys.platform != "linux", reason="landlock is Linux-only"
            ),
        ),
        pytest.param(
            "control-the-default-is-no-sandbox",
            "PASSED",
            0,
            0,
            id="control-the-default-is-no-sandbox",
        ),
    ],
)
@pytest.mark.integration
def test_a_sandbox_ash_cannot_provide_is_an_error_with_code_127(
    tmp_path: Path, cell: str, status: str, exit_code: int, returncode: int
) -> None:
    """concepts/sandbox.md (What fails closed), scanning-untrusted-code.md, read-
    results.md (the ERROR and MISSING rows, the row's exit_code), set-the-gate.md
    (Incomplete scans) and glossary.md.

    A sandbox the configuration asks for that ASH cannot provide is a tool that
    never started: each scan is ERROR with 127 as the scanner's recorded exit code,
    never MISSING from its dependency check, and the tool never runs unsandboxed.
    The run exits 1 under the default ``fail_on_incomplete_scanners`` and 0 with
    that gate off, the row unchanged. An empty or relative ``HOME`` refuses the
    sandbox the same way. ASH's default is no sandbox, so the control runs the tool.
    """
    assert_on_page(SANDBOX, _A_SANDBOX_ASH_CANNOT_PROVIDE)
    assert_on_page(SANDBOX, _THE_START_FAILURE_LINE)
    assert_on_page(SCANNING_UNTRUSTED, _A_BACKEND_THAT_CANNOT_SANDBOX)
    assert_on_page(SCANNING_UNTRUSTED, _A_RELATIVE_HOME_REFUSES_THE_SANDBOX)
    assert_on_page(READ_RESULTS, _ERROR_COVERS_A_TOOL_THAT_NEVER_STARTED)
    assert_on_page(READ_RESULTS, _EXIT_CODE_127_IN_THE_ROW)
    assert_on_page(SET_THE_GATE, _THE_GATE_LISTS_A_TOOL_THAT_COULD_NOT_START)
    for page in (READ_RESULTS, GLOSSARY):
        assert "could not be sandboxed" not in _page_text(page), page

    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    output = tmp_path / "out"
    work = tmp_path / "work"
    work.mkdir()
    unavailable = "bwrap" if sys.platform == "darwin" else "sandbox-exec"
    args = [
        "scan",
        "--scanners",
        "detect-secrets",
        "--no-progress",
        "--offline",
        "--mode",
        "local",
        "--source-dir",
        str(tree),
        "--output-dir",
        str(output),
        "--phases",
        "scan",
        "--phases",
        "report",
    ]
    env: Dict[str, str] = {}
    if cell in ("a-backend-this-host-lacks", "the-gate-off-keeps-the-row"):
        args += ["--sandbox", unavailable]
    if cell == "the-gate-off-keeps-the-row":
        args += ["--no-fail-on-incomplete-scanners"]
    if cell in ("a-relative-home", "a-empty-home"):
        args += ["--sandbox", "landlock"]
        env.update(_home_override("./rel-home" if cell == "a-relative-home" else ""))

    result = _ash(args, cwd=work, **env)

    results = json.loads((output / "ash_aggregated_results.json").read_text("utf-8"))
    row = results["scanner_results"]["detect-secrets"]
    assert row["status"] == status, (row, _output_tail(result))
    assert row["exit_code"] == exit_code, (row, _output_tail(result))
    assert result.returncode == returncode, _output_tail(result)
    log = output / "ash.log"
    text = result.stdout + result.stderr
    text += log.read_text("utf-8", errors="replace") if log.is_file() else ""
    if status == "ERROR":
        assert "detect-secrets could not start its tool on source" in text, (
            _output_tail(result)
        )
        assert "dependencies are not satisfied" not in text, _output_tail(result)
        assert row["missing_reason"] is None, row
    if cell in ("a-backend-this-host-lacks", "the-gate-off-keeps-the-row"):
        assert f"{unavailable} is not available" in text, _output_tail(result)
        if sys.platform == "linux":
            assert _THE_START_FAILURE_LINE in text, _output_tail(result)
    if cell in ("a-relative-home", "a-empty-home"):
        assert "HOME is not an absolute path" in text, _output_tail(result)


#: glossary.md's Scanner status entry on ERROR.
_GLOSSARY_ERROR_COVERS_A_START_FAILURE = (
    "ERROR: ASH tried to run it and it failed, or its tool could not start as asked."
)

#: concepts/sandbox.md (It does not wrap / What it does not do): the converter's own
#: code against the tools it starts.
_A_CONVERTERS_TOOL_IS_NOT_ASHS_PROCESS = (
    "A tool a converter starts (nbconvert for notebooks) is not ASH's own process: "
    "it is held to the sandbox like a scanner's tool;"
)
_A_CONVERTERS_TOOL_IS_CONFINED = (
    "It does not confine ASH's own process, the converters' own code, the reporters, "
    "plugin code, or the content database refresh. The tools a converter starts are "
    "confined like a scanner's."
)

#: concepts/sandbox.md (What fails closed): the converter under a refused sandbox.
_A_REFUSED_SANDBOX_STOPS_THE_CONVERTERS_TOOL = (
    "A converter's tool is held to the same rule. When the sandbox cannot be "
    "provided, nbconvert does not run: each notebook is listed in the converter's "
    "`refused_inputs` with the reason, the row's `failure` reads `jupyter could not "
    "start its tool: <reason>`, and its `dependencies_satisfied` stays true, since "
    "nothing was found missing. A tree with no notebooks loses nothing."
)


@pytest.mark.parametrize(
    "with_notebook",
    [
        pytest.param(True, id="a-notebook-is-refused-not-converted"),
        pytest.param(False, id="control-no-notebooks-lose-nothing"),
    ],
)
@pytest.mark.integration
def test_a_converter_sandbox_ash_cannot_provide_stops_its_tool(
    tmp_path: Path, with_notebook: bool
) -> None:
    """concepts/sandbox.md (It does not wrap, What fails closed, What it does not
    do) and glossary.md (Scanner status).

    The sandbox holds a converter's tool child to the same rule as a scanner's.
    When the requested sandbox cannot be provided, nbconvert never runs: each
    notebook lands in the converter's ``refused_inputs`` with the reason, the row's
    ``failure`` says the tool could not start, and ``dependencies_satisfied`` stays
    True, because the dependency check is skipped rather than reporting a tool the
    operator may well have as missing. A tree with no notebooks loses nothing: the
    same refused sandbox leaves the row without a failure.
    """
    assert_on_page(SANDBOX, _A_CONVERTERS_TOOL_IS_NOT_ASHS_PROCESS)
    assert_on_page(SANDBOX, _A_CONVERTERS_TOOL_IS_CONFINED)
    assert_on_page(SANDBOX, _A_REFUSED_SANDBOX_STOPS_THE_CONVERTERS_TOOL)
    assert_on_page(GLOSSARY, _GLOSSARY_ERROR_COVERS_A_START_FAILURE)

    files = {"app.py": "x = 1\n"}
    if with_notebook:
        files["analysis.ipynb"] = (
            '{\n "cells": [],\n "metadata": {},\n "nbformat": 4,\n'
            ' "nbformat_minor": 5\n}\n'
        )
    tree = _config_scan_tree(tmp_path, files)
    output = tmp_path / "out"
    work = tmp_path / "work"
    work.mkdir()
    unavailable = "bwrap" if sys.platform == "darwin" else "sandbox-exec"
    # The claim is that nbconvert does not run, so the cell owns the lookup and
    # the observable: recording stand-ins for both of the tool's names sit first
    # on PATH, which makes the dependency lookup answer the same on every host,
    # and anything that starts one leaves its arguments in the marker file. The
    # cell asserts that marker stays absent; a checked run's own channels see
    # such a start too, and this makes the claim first-class here.
    marker = tmp_path / "nbconvert-ran.txt"
    bin_dir = tmp_path / "bin"
    for name in ("jupyter", "jupyter-nbconvert"):
        stand_in = _place_stand_in(bin_dir, name)
        if os.name == "nt":
            stand_in.write_text(
                f'@echo %* >> "{marker}"\n@exit /b 0\n', encoding="utf-8"
            )
        else:
            stand_in.write_text(
                f'#!/bin/sh\necho "$@" >> {shlex.quote(str(marker))}\nexit 0\n',
                encoding="utf-8",
            )
            stand_in.chmod(0o755)

    result = _ash(
        [
            "scan",
            "--scanners",
            "detect-secrets",
            "--no-progress",
            "--offline",
            "--mode",
            "local",
            "--source-dir",
            str(tree),
            "--output-dir",
            str(output),
            "--sandbox",
            unavailable,
        ],
        cwd=work,
        PATH=os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]),
    )

    assert not marker.exists(), (
        f"the converter's tool ran under a refused sandbox: {marker.read_text('utf-8')}"
    )
    results = json.loads((output / "ash_aggregated_results.json").read_text("utf-8"))
    row = results["converter_results"]["jupyter"]
    assert row["dependencies_satisfied"] is True, (row, _output_tail(result))
    assert row["converted_paths"] in ([], None), row
    if with_notebook:
        failure = row["failure"] or ""
        assert "jupyter could not start its tool" in failure, (
            row,
            _output_tail(result),
        )
        assert f"{unavailable} is not available" in failure, failure
        refused = row["refused_inputs"] or []
        assert [entry["path"] for entry in refused] == ["analysis.ipynb"], refused
        assert "nbconvert was not run on it" in refused[0]["reason"], refused
    else:
        assert not row["failure"], row
        assert not row["refused_inputs"], row
    assert result.returncode == 1, _output_tail(result)


EXPORT_REPORTS = "how-to/export-reports.md"

#: export-reports.md's bullets on what --output-formats accepts and what the list does.
_OUTPUT_FORMATS_ACCEPTS = (
    "It accepts the name of every reporter ASH ships, including `github-ghas`, "
    "`gitlab-sast`, `gitlab-cyclonedx`, and `unused-suppressions`, and the names of the "
    "AWS reporters, which write a report only when an operator loads their plugin "
    "module. It also accepts `aggregated`, `dict`, `asff`, and `custom`, which no "
    "reporter writes."
)
_OUTPUT_FORMATS_NARROW = (
    "The list narrows the enabled reporters and does not turn on a disabled one. `yaml` "
    "and `spdx` are disabled by default. Naming one writes nothing until you enable its "
    "reporter; ASH logs an error in `ash.log` that names the setting."
)


@pytest.mark.parametrize(
    "formats, written, log_held, logs_error",
    [
        pytest.param(
            "github-ghas,sarif",
            ["ash.ghas.sarif", "ash.sarif"],
            None,
            False,
            id="a-shipped-reporters-name",
        ),
        pytest.param(
            "unused-suppressions",
            ["ash.unused-suppressions.json", "ash.unused-suppressions.md"],
            None,
            False,
            id="a-default-built-in",
        ),
        pytest.param("aggregated", [], None, False, id="a-name-no-reporter-writes"),
        pytest.param(
            "s3",
            [],
            "no reporter produces it in this run",
            False,
            id="an-aws-name-without-its-module",
        ),
        pytest.param(
            "yaml",
            [],
            "its reporter is disabled in the configuration",
            True,
            id="a-disabled-reporters-name",
        ),
        pytest.param(
            "gitlab-sast",
            ["ash.gl-sast-report.json"],
            None,
            False,
            id="gitlab-sast",
        ),
        pytest.param(
            "gitlab-cyclonedx",
            ["ash.gl-dependency-scanning-report.cdx.json"],
            None,
            False,
            id="gitlab-cyclonedx",
        ),
        pytest.param("dict", [], None, False, id="dict-no-reporter-writes"),
        pytest.param("asff", [], None, False, id="asff-no-reporter-writes"),
        pytest.param("custom", [], None, False, id="custom-no-reporter-writes"),
        pytest.param(
            "spdx",
            [],
            "its reporter is disabled in the configuration",
            True,
            id="spdx-disabled-by-default",
        ),
    ],
)
@pytest.mark.integration
def test_output_formats_take_every_shipped_reporters_name(
    tmp_path: Path,
    formats: str,
    written: List[str],
    log_held: Optional[str],
    logs_error: bool,
) -> None:
    """export-reports.md (The option works like this).

    ``ash scan --output-formats`` with a shipped reporter's name writes only that
    report; ``github-ghas`` and ``unused-suppressions`` are accepted like any other.
    ``aggregated`` is accepted and writes nothing. A disabled reporter's name is
    accepted, writes nothing, and leaves the page's error in ``ash.log``; an AWS
    reporter's name without its plugin module is accepted, writes nothing, and
    leaves its own message, for which the page claims no level. Every cell's scan
    exits 0.
    """
    assert_on_page(EXPORT_REPORTS, _OUTPUT_FORMATS_ACCEPTS)
    assert_on_page(EXPORT_REPORTS, _OUTPUT_FORMATS_NARROW)
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    output = tmp_path / "out"
    work = tmp_path / "work"
    work.mkdir()
    args = [
        *_CONFIG_SCAN,
        "--offline",
        "--source-dir",
        str(tree),
        "--output-dir",
        str(output),
        "--output-formats",
        formats,
    ]

    result = _ash(args, cwd=work)

    assert result.returncode == 0, _output_tail(result)
    reports = (
        sorted(p.name for p in (output / "reports").iterdir())
        if (output / "reports").is_dir()
        else []
    )
    assert reports == sorted(written), (reports, _output_tail(result))
    if log_held:
        log = (output / "ash.log").read_text("utf-8", errors="replace")
        held_lines = [line for line in log.splitlines() if log_held in line]
        assert held_lines, log[-2000:]
        if logs_error:
            # "ASH logs an error" is the page's claim for these rows; some line
            # with the phrase carries ERROR, and other levels may repeat it.
            assert any("ERROR" in line for line in held_lines), held_lines


@pytest.mark.integration
def test_merge_output_formats_take_a_shipped_reporters_name(tmp_path: Path) -> None:
    """export-reports.md: ``ash merge --output-formats`` takes the same names."""
    assert_on_page(EXPORT_REPORTS, _OUTPUT_FORMATS_ACCEPTS)
    shard = _stored_scan(tmp_path)
    merged = tmp_path / "merged"
    work = tmp_path / "work"
    work.mkdir()

    result = _ash(
        [
            "merge",
            "--results",
            str(shard / "ash_aggregated_results.json"),
            "--output-dir",
            str(merged),
            "--output-formats",
            "github-ghas",
        ],
        cwd=work,
    )

    assert result.returncode == 0, _output_tail(result)
    reports = sorted(p.name for p in (merged / "reports").iterdir())
    assert reports == ["ash.ghas.sarif"], (reports, _output_tail(result))


#: concepts/sandbox.md (What it wraps): the probes are among the wrapped processes.
_THE_PROBES_ARE_WRAPPED = (
    "When the sandbox mode is anything other than `off`, ASH wraps every process a "
    "scanner starts through ASH's process helpers while that scanner runs. That "
    "includes the probes ASH runs to check each scanner's tool,"
)

#: A plugin scanner whose dependency check starts a probe through ASH's run_command.
#: The probe creates probe-<pid> in the directory ASH_PAGE_CLAIMS_PROBES names, which a
#: sandboxed probe cannot write to, so each file left is a probe that ran unwrapped.
_PROBING_PLUGIN = """\
import os
import sys
from typing import Annotated, Any, Literal

from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.subprocess_utils import run_command

_PROBE = (
    "import os, sys; "
    "open(os.path.join(sys.argv[1], 'probe-%d' % os.getpid()), 'w').close()"
)


class ProbeScannerOptions(ScannerOptionsBase):
    pass


class ProbeScannerConfig(ScannerPluginConfigBase):
    name: Literal["page-claims-probe"] = "page-claims-probe"
    enabled: bool = True
    options: Annotated[ProbeScannerOptions, Field()] = ProbeScannerOptions()


@ash_scanner_plugin
class ProbeScanner(ScannerPluginBase[ProbeScannerConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = ProbeScannerConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        run_command(
            [sys.executable, "-c", _PROBE, os.environ["ASH_PAGE_CLAIMS_PROBES"]]
        )
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError

    def scan(self, target, target_type, config: Any = None, *args, **kwargs):
        self._pre_scan(target, target_type, config)
        self._post_scan(target, target_type)
        return {"findings": []}


ASH_SCANNERS = [ProbeScanner]
"""


@pytest.mark.parametrize(
    "mode, wrapped",
    [
        pytest.param("bwrap", True, id="bwrap"),
        pytest.param("auto", True, id="auto"),
        pytest.param("off", False, id="control-off"),
    ],
)
@pytest.mark.integration
def test_a_scanners_dependency_probe_runs_only_inside_the_sandbox(
    tmp_path: Path, mode: str, wrapped: bool
) -> None:
    """concepts/sandbox.md (What it wraps).

    A plugin scanner's dependency check starts a probe through ASH's ``run_command``,
    and the probe leaves a file in a directory a sandboxed process cannot write to.
    With ``sandbox.mode`` bwrap or auto, a scan of that scanner must leave no file:
    every check ASH makes, before queuing the scanner and in its scan, starts the
    probe wrapped (or not at all, where no backend can run). The control, mode off,
    leaves at least one, so the check does run. In each cell the scanner is recorded.
    """
    assert_on_page(SANDBOX, _THE_PROBES_ARE_WRAPPED)
    tree = _config_scan_tree(tmp_path, {"app.py": "x = 1\n"})
    probes = tmp_path / "probes"
    probes.mkdir()
    output = tmp_path / "out"
    work = tmp_path / "work"
    work.mkdir()
    module = "page_claims_probe_ash_plugins"
    args = [
        "scan",
        "--scanners",
        "page-claims-probe",
        "--no-progress",
        "--offline",
        "--mode",
        "local",
        "--source-dir",
        str(tree),
        "--output-dir",
        str(output),
        "--config-overrides",
        f"ash_plugin_modules+=[{module}]",
        "--config-overrides",
        f"sandbox.mode={mode}",
    ]

    result = _ash(
        args,
        cwd=work,
        PYTHONPATH=_plugin_path(tmp_path, module, _PROBING_PLUGIN),
        ASH_PAGE_CLAIMS_PROBES=str(probes),
    )

    results = json.loads((output / "ash_aggregated_results.json").read_text("utf-8"))
    assert "page-claims-probe" in results["scanner_results"], _output_tail(result)
    left = sorted(p.name for p in probes.iterdir())
    if wrapped:
        assert left == [], (left, _output_tail(result))
    else:
        assert left, _output_tail(result)
