# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The warning for a lockfile npm-audit cannot place under the scanned directory.

npm-audit locates each result at its lockfile, relative to the scanned directory
(``_shown_lockfile``). When there is no relative form, the lockfile's results keep
the install-location URI and a warning says so. Two things are pinned here.

* The warning fires once per conversion for a lockfile outside the directory,
  whichever package manager's it is. An npm lockfile is asked about by
  ``_lock_context``, whose answer the conversion reuses; a yarn or pnpm lockfile
  is asked about by the conversion alone. Neither path asks twice.
* The warning tells its two causes apart. ``ValueError`` means the lockfile is
  outside the directory. ``OSError`` (a directory the process cannot search) or,
  for a link loop before Python 3.13, ``RuntimeError`` means a place could not be
  resolved at all, which says nothing about
  where the lockfile is: it is worded as a place that could not be read, with the
  error's reason and not its full text (which repeats the path), and never as
  "not under the scanned directory". Both end with the same sentence about what
  the results lose.

Every path is under ``tmp_path``; ``Path.resolve`` is made to fail for the one
directory a cell names and for no other.
"""

import errno
import json
import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    _YARN_ADVISORIES_KEY,
    NpmAuditScanner,
)

pytestmark = pytest.mark.unit

GHSA = "https://github.com/advisories/GHSA-xvch-5gv4-984h"

#: The words of the ``ValueError`` warning, of the ``OSError`` warning, and the
#: sentence both end with.
NOT_UNDER = "is not under the scanned directory"
UNREADABLE = "could not be read"
CONSEQUENCE = "so its results keep the install-location URI"
#: The reason given for a link loop: a fixed text, not the system's own, which
#: reads differently from one platform to the next.
LINK_LOOP_REASON = "too many levels of symbolic links"


def _npm_report() -> dict:
    """An npm audit report with one advisory, which any lockfile may be audited from."""
    via = {
        "source": 1179,
        "name": "minimist",
        "title": "Prototype Pollution in minimist",
        "severity": "critical",
        "cwe": ["CWE-1321"],
        "range": "<0.2.4",
        "url": GHSA,
    }
    return {
        "auditReportVersion": 2,
        "vulnerabilities": {
            "minimist": {
                "name": "minimist",
                "severity": "critical",
                "via": [via],
                "range": "<0.2.4",
                "nodes": ["node_modules/minimist"],
                "fixAvailable": True,
            }
        },
        "metadata": {"vulnerabilities": {"critical": 1}},
    }


def _yarn_report(paths_key: str) -> dict:
    """The report a yarn or pnpm audit becomes: one advisory record."""
    record = {
        "package": "lodash",
        "id": 1065,
        "title": "Prototype Pollution",
        "url": GHSA,
        "severity": "high",
        "cvss": {},
        "cwe": [],
        "vulnerable_versions": "<4.17.12",
        "patched_versions": None,
        "versions": {},
        "paths_key": paths_key,
    }
    return {_YARN_ADVISORIES_KEY: [record], "metadata": {}}


#: One lockfile of each kind the conversion handles, with the report its audit gives.
LOCKFILES = [
    pytest.param("package-lock.json", _npm_report, id="npm"),
    pytest.param("npm-shrinkwrap.json", _npm_report, id="npm-shrinkwrap"),
    pytest.param("yarn.lock", lambda: _yarn_report("dependents"), id="yarn"),
    pytest.param("pnpm-lock.yaml", lambda: _yarn_report("dependency_paths"), id="pnpm"),
]


def _lockfile(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    lockfile = directory / name
    lockfile.write_text(json.dumps({"lockfileVersion": 3, "packages": {}}))
    return lockfile


def _warnings(capture, *needles: str) -> list[str]:
    """npm-audit's own warnings so far, each holding every one of ``needles``."""
    return [
        message
        for message in (record.getMessage() for record in capture.records)
        if message.startswith("npm-audit: ") and all(n in message for n in needles)
    ]


def _resolve_fails_for(monkeypatch, directory: Path, error: Exception) -> None:
    """Make ``Path.resolve`` raise ``error`` for ``directory`` and any path under
    it, and for no other path: a path under a looped directory fails to resolve
    too, so a change that resolves the lockfile itself still meets the failure."""
    real_resolve = Path.resolve

    def resolve(self, *args, **kwargs):
        if self == directory or directory in self.parents:
            raise error
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)


# --- A lockfile outside the directory: once --------------------------------------


@pytest.mark.parametrize(("lock_name", "report"), LOCKFILES)
def test_a_lockfile_outside_the_scanned_directory_warns_once(
    lock_name, report, tmp_path, capture
):
    """One warning per conversion, naming the lockfile and the directory, for an npm
    lockfile (asked about by ``_lock_context``) and a yarn or pnpm one (asked about
    by the conversion) alike. The control, the same report audited from a lockfile
    inside the directory, converts in the same test and warns nothing."""
    target = tmp_path / "repo"
    target.mkdir()
    outside = _lockfile(tmp_path / "elsewhere", lock_name)

    NpmAuditScanner.convert_results(report(), target, lock_file=outside)

    warnings = _warnings(capture, NOT_UNDER)
    assert len(warnings) == 1, [r.getMessage() for r in capture.records]
    assert str(outside) in warnings[0], warnings
    assert str(target) in warnings[0], warnings
    assert CONSEQUENCE in warnings[0], warnings
    assert _warnings(capture, UNREADABLE) == []

    capture.clear()
    inside = _lockfile(target / "app", lock_name)
    NpmAuditScanner.convert_results(report(), target, lock_file=inside)
    assert _warnings(capture) == [], [r.getMessage() for r in capture.records]


# --- A directory that cannot be resolved: its own words ---------------------------


@pytest.mark.parametrize(
    "code", [errno.ELOOP, errno.EACCES], ids=["link-loop", "cannot-search"]
)
def test_a_directory_that_cannot_be_resolved_is_not_said_to_be_outside(
    code, tmp_path, monkeypatch, capture
):
    """The lockfile may well be under the scanned directory: what failed is reading
    where the directory is. The message says so, with the error's reason alone,
    and keeps the sentence about what the results lose."""
    target = tmp_path / "repo"
    target.mkdir()
    elsewhere = tmp_path / "elsewhere"
    lockfile = _lockfile(elsewhere, "package-lock.json")
    reason = os.strerror(code)
    _resolve_fails_for(monkeypatch, elsewhere, OSError(code, reason))

    shown = npm_audit_scanner._shown_lockfile(lockfile, target)

    assert shown is None
    (warning,) = _warnings(capture)
    assert UNREADABLE in warning, warning
    assert f"({reason})" in warning, warning
    # The reason, not the error's full text, which would repeat the path.
    assert "[Errno" not in warning, warning
    assert NOT_UNDER not in warning, warning
    assert CONSEQUENCE in warning, warning
    assert str(lockfile) in warning and str(target) in warning, warning


def test_an_oserror_with_no_reason_names_its_class(tmp_path, monkeypatch, capture):
    """An ``OSError`` raised with no errno has no ``strerror``; the class names it."""
    target = tmp_path / "repo"
    target.mkdir()
    elsewhere = tmp_path / "elsewhere"
    lockfile = _lockfile(elsewhere, "package-lock.json")
    _resolve_fails_for(monkeypatch, elsewhere, OSError("unreadable"))

    npm_audit_scanner._shown_lockfile(lockfile, target)

    (warning,) = _warnings(capture)
    assert "(OSError)" in warning, warning
    assert NOT_UNDER not in warning, warning


def test_a_conversion_whose_lockfile_directory_cannot_be_resolved_warns_once(
    tmp_path, monkeypatch, capture
):
    """The same through the conversion, which is where an operator meets it: once,
    in the unreadable-place words."""
    target = tmp_path / "repo"
    target.mkdir()
    elsewhere = tmp_path / "elsewhere"
    lockfile = _lockfile(elsewhere, "package-lock.json")
    reason = os.strerror(errno.ELOOP)
    _resolve_fails_for(monkeypatch, elsewhere, OSError(errno.ELOOP, reason))

    NpmAuditScanner.convert_results(_npm_report(), target, lock_file=lockfile)

    warnings = _warnings(capture)
    assert len(warnings) == 1, [r.getMessage() for r in capture.records]
    assert UNREADABLE in warnings[0] and f"({reason})" in warnings[0], warnings
    assert NOT_UNDER not in warnings[0], warnings


def test_a_lockfile_inside_the_target_is_placed_without_resolving_it(
    tmp_path, monkeypatch, capture
):
    """The lexical compare places a lockfile that sits under the scanned directory
    before anything is resolved, so a directory that cannot be resolved changes
    nothing for it: the result keeps its relative path and no warning is given."""
    target = tmp_path / "repo"
    target.mkdir()
    app = target / "app"
    lockfile = _lockfile(app, "package-lock.json")
    _resolve_fails_for(monkeypatch, app, OSError(errno.ELOOP, os.strerror(errno.ELOOP)))

    shown = npm_audit_scanner._shown_lockfile(lockfile, target)

    assert shown == "app/package-lock.json"
    assert _warnings(capture) == [], [r.getMessage() for r in capture.records]


def test_a_scanned_target_that_is_a_link_loop_warns_once_and_raises_nothing(
    tmp_path, capture
):
    """Before Python 3.13 ``Path.resolve`` raises ``RuntimeError`` for a link loop
    where it raises no ``OSError``; from 3.13 it raises nothing. Either way the
    conversion completes and warns once. Before 3.13 the warning is the
    could-not-be-read one, with a fixed reason for a loop and never the
    ``RuntimeError``'s text, which names the looped path."""
    loop = tmp_path / "loop"
    try:
        loop.symlink_to(loop)
    except OSError as error:
        pytest.skip(f"cannot make a link here: {error}")
    lockfile = _lockfile(tmp_path / "elsewhere", "package-lock.json")

    NpmAuditScanner.convert_results(_npm_report(), loop, lock_file=lockfile)

    warnings = _warnings(capture)
    assert len(warnings) == 1, [r.getMessage() for r in capture.records]
    assert "Symlink loop" not in warnings[0], warnings
    assert CONSEQUENCE in warnings[0], warnings
    if sys.version_info < (3, 13):
        assert UNREADABLE in warnings[0], warnings
        assert f"({LINK_LOOP_REASON})" in warnings[0], warnings
        assert NOT_UNDER not in warnings[0], warnings
    else:
        assert UNREADABLE in warnings[0] or NOT_UNDER in warnings[0], warnings


# --- A RuntimeError that is no link loop is named by its class --------------------


def test_the_link_loop_runtime_error_gets_the_fixed_reason_and_not_its_text(
    tmp_path, monkeypatch, capture
):
    """CPython's own link-loop ``RuntimeError`` (its text starts ``Symlink loop``
    and names the looped path) is reported with the fixed reason for a loop,
    whichever Python runs the cell, and its text never reaches the message. The
    control for the two cells below: the same code path, the loop's error."""
    target = tmp_path / "repo"
    target.mkdir()
    elsewhere = tmp_path / "elsewhere"
    lockfile = _lockfile(elsewhere, "package-lock.json")
    _resolve_fails_for(
        monkeypatch, elsewhere, RuntimeError("Symlink loop from 'looped-place-qz4b'")
    )

    assert npm_audit_scanner._shown_lockfile(lockfile, target) is None

    (warning,) = _warnings(capture)
    assert UNREADABLE in warning, warning
    assert f"({LINK_LOOP_REASON})" in warning, warning
    assert "looped-place-qz4b" not in warning, warning
    assert "Symlink loop" not in warning, warning


@pytest.mark.parametrize(
    "error",
    [
        RecursionError("maximum recursion depth exceeded near 'recursed-place-qz4b'"),
        NotImplementedError("cannot resolve 'unsupported-place-qz4b'"),
        RuntimeError("winerror 1921 at 'winerror-place-qz4b'"),
    ],
    ids=["recursion", "not-implemented", "other-runtime-error"],
)
def test_a_runtime_error_that_is_no_link_loop_is_named_by_its_class(
    error, tmp_path, monkeypatch, capture
):
    """Only the loop's own ``RuntimeError`` reads as a link loop. A
    ``RecursionError``, a ``NotImplementedError`` and any other ``RuntimeError``
    (Windows' winerror 1921 before 3.13 among them) are named by their class, the
    reason for a loop is not given for them, and the error's own text, which can
    name a place, never reaches the message."""
    target = tmp_path / "repo"
    target.mkdir()
    elsewhere = tmp_path / "elsewhere"
    lockfile = _lockfile(elsewhere, "package-lock.json")
    _resolve_fails_for(monkeypatch, elsewhere, error)

    assert npm_audit_scanner._shown_lockfile(lockfile, target) is None

    (warning,) = _warnings(capture)
    assert UNREADABLE in warning, warning
    assert f"({type(error).__name__})" in warning, warning
    assert LINK_LOOP_REASON not in warning, warning
    assert "-place-qz4b" not in warning, warning
    assert NOT_UNDER not in warning, warning
    assert CONSEQUENCE in warning, warning
