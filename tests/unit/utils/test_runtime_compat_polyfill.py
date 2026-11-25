# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The POLYFILL resolution kind, with checkov#7777 as its test case.

checkov's shipped default is the interpreter PIN (``>=3.10,<3.15``). The
``array_hook`` shim is the tested alternative behind the same facet family: the
shim asset, the launch-environment injector and these tests land, and no
active POLYFILL row sits in checkov's register (an active one could not
construct without ``pin_insufficient``, which is untrue while the pin serves).
The tests declare the row on a stand-in scanner, as the hypothesis "pinning
cannot serve here".

None of this runs the shim on CPython 3.15: the shim is signature-adaptive, so
its wrapping logic is exercised against a stub ``JSONArray`` with the 3.15
signature that CI's own interpreter can host.
"""

from __future__ import annotations

import importlib.util
import json.decoder
import os
import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.utils import runtime_compat_env as env_module

pytestmark = pytest.mark.unit

SHIM = "checkov_json_array_hook"

#: The checkov#7777 polyfill row, declared as the capability's test case.
ALTERNATIVE_ROW = opsf.RuntimeCompatRow(
    runtime=opsf.RuntimeName.PYTHON,
    tool_versions="",
    runtime_request=">=3.15",
    resolution=opsf.CompatResolution.POLYFILL,
    reason="CPython 3.15 requires array_hook in json.decoder.JSONArray; "
    "checkov's Decoder.json_array does not pass it",
    upstream_issue="https://github.com/bridgecrewio/checkov/issues/7777",
    open_ended=True,
    recorded_default_constraint="",
    polyfill=SHIM,
    pin_insufficient="hypothesis for the test: no interpreter below 3.15 is "
    "installable on the host",
)


def _load_shim():
    path = env_module.polyfill_directory(SHIM) / "sitecustomize.py"
    spec = importlib.util.spec_from_file_location("_ash_polyfill_under_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stub_decoder(signature_has_array_hook: bool):
    """A ``json.decoder`` stand-in whose ``JSONArray`` has the named signature."""

    class Decoder:
        calls: list = []

    if signature_has_array_hook:

        def JSONArray(s_and_end, scan_once, array_hook, _w=None, _ws=" \t\n\r"):
            Decoder.calls.append((s_and_end, scan_once, array_hook))
            return array_hook(["x"]), 1
    else:

        def JSONArray(s_and_end, scan_once, _w=None, _ws=" \t\n\r"):
            Decoder.calls.append((s_and_end, scan_once))
            return ["x"], 1

    Decoder.JSONArray = staticmethod(JSONArray)
    return Decoder


# ---- the shim -------------------------------------------------------------


def test_the_checkov_array_hook_shim_passes_array_hook_through() -> None:
    shim = _load_shim()
    stub = _stub_decoder(signature_has_array_hook=True)
    assert shim._patch(stub) is True
    # checkov's call shape: ``JSONArray(s_and_end, scan_once, **kwargs)``
    values, end = stub.JSONArray(("[1]", 1), object())
    assert values == ["x"] and end == 1
    assert stub.calls[-1][2] is list, "the stdlib default hook is supplied"


def test_an_explicit_array_hook_is_respected() -> None:
    shim = _load_shim()
    stub = _stub_decoder(signature_has_array_hook=True)
    shim._patch(stub)
    stub.JSONArray(("[1]", 1), object(), array_hook=tuple)
    assert stub.calls[-1][2] is tuple


def test_the_shim_does_not_wrap_an_older_signature() -> None:
    """Even if the version gate were wrong, nothing is wrapped without the
    required parameter."""
    shim = _load_shim()
    stub = _stub_decoder(signature_has_array_hook=False)
    original = stub.JSONArray
    assert shim._patch(stub) is False
    assert stub.JSONArray is original


@pytest.mark.skipif(
    sys.version_info >= (3, 15), reason="the shim acts on this interpreter"
)
def test_the_shim_noops_outside_its_runtime_range() -> None:
    before = json.decoder.JSONArray
    _load_shim()
    assert json.decoder.JSONArray is before


def test_the_shims_runtime_gate_matches_its_rows_runtime_request() -> None:
    shim = _load_shim()
    major, minor = shim.MINIMUM_RUNTIME
    assert ALTERNATIVE_ROW.runtime_request == f">={major}.{minor}"


def test_the_shim_ships_where_the_row_says() -> None:
    directory = env_module.polyfill_directory(ALTERNATIVE_ROW.polyfill or "")
    assert (directory / "sitecustomize.py").is_file()
    assert directory.parent.name == "polyfills"


# ---- the sitecustomize chain -----------------------------------------------
#
# Python imports ONE module named ``sitecustomize`` -- the first on
# ``sys.path`` -- and the injector prepends the shim's directory, so without a
# chain-import the shim would silently shadow a caller's own sitecustomize
# (subprocess coverage via ``COVERAGE_PROCESS_START`` rides one). These run a
# real interpreter because the chain acts only at startup, when the shim IS
# the module named ``sitecustomize``.


def _startup(env_additions: dict[str, str]) -> subprocess.CompletedProcess:
    probe = (
        "import sys\n"
        "module = sys.modules.get('sitecustomize')\n"
        "print('SITECUSTOMIZE-FILE:' + getattr(module, '__file__', 'none'))\n"
        "print('PLANTED-RAN:' + str(getattr(sys, '_ash_planted_sitecustomize', False)))\n"
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("PYTHONPATH", "PYTHONNOUSERSITE", "PYTHONSAFEPATH")
    }
    return subprocess.run(  # noqa: S603 - our own interpreter, our own files
        [sys.executable, "-c", probe],
        env={**env, **env_additions},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_the_shim_chains_to_the_callers_sitecustomize(tmp_path) -> None:
    """Both sitecustomizes run: the shim first (it is first on PYTHONPATH),
    then the caller's, which ends up owning the module name."""
    caller = tmp_path / "caller"
    caller.mkdir()
    planted = caller / "sitecustomize.py"
    planted.write_text("import sys\nsys._ash_planted_sitecustomize = True\n")
    shim_dir = str(env_module.polyfill_directory(SHIM))
    result = _startup(
        {"PYTHONPATH": shim_dir + os.pathsep + str(caller)},
    )
    assert result.returncode == 0, result.stderr
    assert "PLANTED-RAN:True" in result.stdout, (
        "the caller's sitecustomize never ran: the shim shadowed it\n"
        + result.stdout
        + result.stderr
    )
    assert f"SITECUSTOMIZE-FILE:{planted}" in result.stdout, (
        "the chained module owns the name\n" + result.stdout
    )


def test_the_shim_alone_still_owns_the_module_name(tmp_path) -> None:
    """The no-next control: with nothing to chain to, startup succeeds and the
    shim stays registered, so a later ``import sitecustomize`` is a no-op."""
    shim_dir = env_module.polyfill_directory(SHIM)
    result = _startup({"PYTHONPATH": str(shim_dir)})
    assert result.returncode == 0, result.stderr
    assert f"SITECUSTOMIZE-FILE:{shim_dir / 'sitecustomize.py'}" in result.stdout
    assert "PLANTED-RAN:False" in result.stdout


# ---- the injector ---------------------------------------------------------


def _scanner_with(rows: tuple[opsf.RuntimeCompatRow, ...], constraint=None):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
        ZizmorScanner,
    )

    facets = ZizmorScanner.operational_facets.model_copy(
        update={"runtime_compat": opsf.RuntimeCompatFacet(rows=rows)}
    )

    class Declaring:
        operational_facets = facets

        def _get_tool_version_constraint(self):
            return constraint

    return Declaring()


def test_a_polyfill_row_injects_the_shim_dir_on_pythonpath() -> None:
    result = env_module.with_runtime_compat_environment(
        {"HOME": "/h"}, _scanner_with((ALTERNATIVE_ROW,))
    )
    assert result is not None
    shim_dir = str(env_module.polyfill_directory(SHIM))
    assert result["PYTHONPATH"] == shim_dir
    assert result["HOME"] == "/h"


def test_pythonpath_prepends_and_keeps_the_callers_value() -> None:
    result = env_module.with_runtime_compat_environment(
        {"PYTHONPATH": "/caller/lib"}, _scanner_with((ALTERNATIVE_ROW,))
    )
    assert result is not None
    shim_dir = str(env_module.polyfill_directory(SHIM))
    assert result["PYTHONPATH"] == shim_dir + os.pathsep + "/caller/lib"


def test_an_inherited_environment_is_copied_with_the_addition(monkeypatch) -> None:
    monkeypatch.setenv("PYTHONPATH", "/process/lib")
    result = env_module.with_runtime_compat_environment(
        None, _scanner_with((ALTERNATIVE_ROW,))
    )
    assert result is not None
    assert result["PYTHONPATH"].endswith(os.pathsep + "/process/lib")


def test_no_row_leaves_the_environment_untouched() -> None:
    plugin = _scanner_with(())
    assert env_module.with_runtime_compat_environment(None, plugin) is None
    given = {"A": "1"}
    result = env_module.with_runtime_compat_environment(given, plugin)
    assert result == given and result is not given


def test_a_pin_row_adds_nothing_to_the_environment() -> None:
    pin = opsf.RuntimeCompatRow(
        runtime=opsf.RuntimeName.PYTHON,
        tool_versions="",
        runtime_request=">=3.10,<3.15",
        resolution=opsf.CompatResolution.PIN,
        reason="a pin, not a shim",
    )
    assert env_module.runtime_compat_environment(_scanner_with((pin,))) == {}


def test_a_class_with_no_register_row_is_left_alone() -> None:
    class ThirdParty:
        pass

    assert env_module.runtime_compat_environment(ThirdParty()) == {}


def test_a_row_outside_the_tool_constraint_is_not_injected() -> None:
    bounded = opsf.RuntimeCompatRow(
        **{
            **ALTERNATIVE_ROW.model_dump(),
            "tool_versions": "<3.5",
            "open_ended": False,
            "recorded_default_constraint": None,
        }
    )
    assert (
        env_module.runtime_compat_environment(
            _scanner_with((bounded,), constraint="==3.6.0")
        )
        == {}
    )
    assert (
        env_module.runtime_compat_environment(
            _scanner_with((bounded,), constraint="==3.4.0")
        )
        != {}
    )


def test_a_second_applicable_polyfill_row_is_refused() -> None:
    """Python imports one sitecustomize."""
    second = opsf.RuntimeCompatRow(
        **{
            **ALTERNATIVE_ROW.model_dump(),
            "tool_versions": ">=1.0",
            "polyfill": "another_shim",
        }
    )
    with pytest.raises(ValueError, match="sitecustomize"):
        env_module.runtime_compat_environment(_scanner_with((ALTERNATIVE_ROW, second)))


def test_the_injector_is_wired_into_every_scanner_subprocess() -> None:
    source = (
        Path(env_module.__file__).parent.parent / "base" / "plugin_base.py"
    ).read_text()
    assert "with_runtime_compat_environment(env, self)" in source
