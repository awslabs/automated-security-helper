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
  outside the directory. ``OSError`` (a link loop, a directory the process cannot
  search) means a place could not be resolved at all, which says nothing about
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


def _resolve_fails_for(monkeypatch, directory: Path, error: OSError) -> None:
    """Make ``Path.resolve`` raise ``error`` for ``directory`` and no other path."""
    real_resolve = Path.resolve

    def resolve(self, *args, **kwargs):
        if self == directory:
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
