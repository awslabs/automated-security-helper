# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One missing optional dependency must not delete unrelated plugins.

The mechanism
-------------
Plugin registration is a decorator side effect at class-definition time, so it
happens *during* import. ``ash_builtin/__init__.py`` imported its four plugin
groups in sequence inside one function, and ``load_internal_plugins`` wrapped the
whole thing in a single ``except ImportError`` that logged one WARNING and
returned an all-zero dict. Four of that function's five call sites discard the
return value.

So the loss was torn rather than clean: an unguarded optional third-party import
inside one scanner module removed that scanner *and every plugin module imported
after it*, while the groups imported before it stayed registered. Measured on
this tree with ``detect_secrets`` blocked -- the trigger every certificate in this
family used -- the registry held 2 converters and 4 scanners, and
``load_internal_plugins`` reported zeros for all three groups. The 15 reporters
and both event handlers, which import last and have nothing to do with
detect-secrets, were simply gone.

This is NOT the "zero scanners" shape that five of the six reports described. The
registry is torn, not empty, so ``no_scanner_ran``'s documented empty-set
exemption is never the operative branch and zero-scanner is not reachable from a
missing optional dependency. What is reachable, and what these tests hold, is
that an unrelated plugin group disappears and that the scanner whose dependency
is absent is recorded nowhere for any gate to see.

Why a subprocess
----------------
The block has to be in place before the first import of the module under test.
``detect_secrets`` is already imported by the time any test in this suite runs,
and reloading the scanner module re-fires its registration decorator against the
process-wide plugin manager. A clean interpreter is the only way to measure what
a deployment without the library actually gets, rather than what an already-warm
process can be talked into reporting.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

# Raising from find_spec is what makes the module genuinely unimportable. Setting
# sys.modules["detect_secrets"] = None was the alternative and is weaker: it leaves
# already-imported submodules reachable through their own sys.modules entries, so
# `from detect_secrets.settings import transient_settings` still succeeds and the
# test measures a partial block rather than an absent library.
_BLOCKER = """
import sys


class _BlockDetectSecrets:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "detect_secrets" or fullname.startswith("detect_secrets."):
            raise ImportError(f"blocked for test: {fullname}")
        return None


sys.meta_path.insert(0, _BlockDetectSecrets())
for _name in [n for n in sys.modules if n.split(".")[0] == "detect_secrets"]:
    del sys.modules[_name]
"""


def _run_probe(body: str) -> dict:
    """Run *body* in a clean interpreter with detect_secrets unimportable."""
    script = _BLOCKER + textwrap.dedent(body)
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=300,
    )
    assert proc.returncode == 0, (
        "probe interpreter failed outright, which is itself the defect when it "
        f"happens at import time.\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    marker = "ASH_PROBE_RESULT="
    for line in proc.stdout.splitlines():
        if line.startswith(marker):
            return json.loads(line[len(marker) :])
    raise AssertionError(
        f"probe printed no result.\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )


@pytest.fixture(scope="module")
def probe() -> dict:
    """What ``load_internal_plugins()`` reports with the library absent."""
    return _run_probe(
        """
        import json

        from automated_security_helper.plugins.loader import load_internal_plugins

        loaded = load_internal_plugins()
        names = {
            group: sorted(cls.__name__ for cls in classes)
            for group, classes in loaded.items()
            if isinstance(classes, list)
        }
        print(
            "ASH_PROBE_RESULT="
            + json.dumps(
                {
                    "converters": len(loaded.get("converters", [])),
                    "scanners": len(loaded.get("scanners", [])),
                    "reporters": len(loaded.get("reporters", [])),
                    "names": names,
                }
            )
        )
        """
    )


def test_the_scanner_module_still_imports(probe):
    """The first thing that has to be true: nothing raises at import time.

    ``config/ash_config.py`` imports ``DetectSecretsScannerConfig`` from this same
    module, so an unguarded top-level ``import detect_secrets`` takes out config
    resolution too -- a hard startup failure, not a degraded scan. That is why the
    probe asserts a zero exit before looking at any counts.
    """
    assert probe["scanners"] > 0


def test_reporters_are_not_collateral_damage(probe):
    """The measured loss: 15 reporters removed by a secrets-scanner dependency.

    Reporters import last, so they absorbed every failure anywhere in the scanner
    region. This is the assertion that per-group import isolation exists for.
    """
    assert probe["reporters"] >= 13, (
        "reporters import after scanners, so before per-group isolation a single "
        f"missing optional dependency removed all of them: {probe}"
    )


def test_the_affected_scanner_still_registers(probe):
    """It must be present so it can be *reported* MISSING rather than vanish.

    A scanner that never registered is absent from both sides of the completeness
    comparison and therefore produces no discrepancy. Registering it is what gives
    the gate something to fail on.
    """
    assert "DetectSecretsScanner" in probe["names"]["scanners"], (
        f"detect-secrets vanished from the plugin set entirely: {probe['names']}"
    )


def test_the_unaffected_scanners_are_all_present(probe):
    """No suffix of the scanner list may be lost either.

    ``scanners/__init__.py`` imports its ten scanners in one module in source
    order, and detect-secrets is fifth. Before the guard, the five imported after
    it -- grype, npm-audit, opengrep, semgrep, syft -- went with it.
    """
    for name in ("GrypeScanner", "NpmAuditScanner", "SemgrepScanner", "SyftScanner"):
        assert name in probe["names"]["scanners"], (
            f"{name} has no relation to detect-secrets but was lost with it: "
            f"{probe['names']['scanners']}"
        )


def test_the_affected_scanner_declines_instead_of_claiming_to_work(probe):
    """Registering is not enough: it must answer the dependency check honestly.

    A scanner that registers and then reports PASSED without the library it scans
    with would be worse than one that vanished, because the run would read clean.
    """
    result = _run_probe(
        """
        import json
        import tempfile
        from pathlib import Path

        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.default_config import get_default_config
        from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
            DetectSecretsScanner,
        )

        with tempfile.TemporaryDirectory() as root:
            for sub in ("src", "out", "work"):
                Path(root, sub).mkdir()
            context = PluginContext(
                source_dir=Path(root, "src"),
                output_dir=Path(root, "out"),
                work_dir=Path(root, "work"),
                config=get_default_config(),
            )
            scanner = DetectSecretsScanner(context=context)
            print(
                "ASH_PROBE_RESULT="
                + json.dumps(
                    {
                        "constructed": True,
                        "dependencies_satisfied": bool(
                            scanner.validate_plugin_dependencies()
                        ),
                        "reason": scanner.dependency_unavailable_reason,
                    }
                )
            )
        """
    )

    assert result["constructed"] is True
    assert result["dependencies_satisfied"] is False, (
        "a scanner whose library is absent must decline, so ScanPhase records it "
        f"MISSING through the path that already exists for exactly this: {result}"
    )
    assert "detect-secrets" in (result["reason"] or ""), result
