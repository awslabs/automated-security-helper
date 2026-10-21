# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The unknown-mode refusal never prints a path the environment chose.

An ``extends`` entry can choose its base with a value read from the
environment, and that base's path IS the environment's value. The refusal
for an operator-owned sandbox mode outside the known set names the file
that wrote the mode, so a file reached this way is named by its hidden
form, the way the confinement warnings name it; naming it by its path
would print the value the hidden form exists to keep out of messages. The
CLI cells pin the whole surface a refusal reaches: stdout, stderr and
ash.log. The mode-value control pins the companion property the message
already kept, that a mode READ from the environment never prints either.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config import resolve_config as rc_module
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)
from tests.utils.helpers import checkout_env, mark_git_checkout

_REFUSED = (ASHConfigSourceError, ASHConfigValidationError)
# Box-drawing characters and whitespace, which console wrapping can insert
# inside a printed path: the canaries are checked with and without them.
_BOX = re.compile(r"[\s─-╿]+")
_MODE_CANARY = "canary-mode-urelombas-7391046285"
_PATH_CANARY = "canary-path-ielovasto-1029384756"


def _squeezed(text):
    return _BOX.sub("", text)


def _absent(message, *canaries):
    for canary in canaries:
        assert canary not in message, (canary, message)
        assert _squeezed(canary) not in _squeezed(message), (canary, message)


def _write(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _resolve(route, root, src, monkeypatch):
    """The resolved mode, or the refusal, for one route."""
    monkeypatch.chdir(src)
    try:
        if route == "config_file":
            monkeypatch.delenv("ASH_CONFIG", raising=False)
            config = resolve_config(
                config_path=root, source_dir=src, trusted_config_path=root
            )
        else:
            monkeypatch.setenv("ASH_CONFIG", str(root))
            config = resolve_config(source_dir=src)
    except _REFUSED as refusal:
        return None, refusal
    return config.sandbox.mode, None


def _env_chosen_chain(tmp_path, monkeypatch, base_document):
    """Root extends [an environment-chosen base, an in-tree lower file]; the
    base's path holds the path canary, and that path is the environment's
    value."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    base = _write(tmp_path / "plain" / _PATH_CANARY / "base.yaml", base_document)
    monkeypatch.setenv("ASH_BASE_UNDER_TEST", base.as_posix())
    lower = _write(src / "cfg" / "lower.yaml", {"sandbox": {"mode": "off"}})
    root = _write_text(
        tmp_path / "ash-root.yaml",
        "project_name: hidden-form\nextends:\n- ${ASH_BASE_UNDER_TEST}\n- "
        + lower.as_posix()
        + "\n",
    )
    return src, base, root


@pytest.mark.parametrize("route", ["ash_config", "config_file"])
def test_control_an_environment_chosen_base_is_read_and_recorded(
    tmp_path, monkeypatch, route
):
    """The premise: the loader reads the environment-chosen base (its
    firejail survives the in-tree off), and the operator chain records the
    base as environment-chosen, so a refusal holds what it needs to name
    the file by its hidden form."""
    src, base, root = _env_chosen_chain(
        tmp_path, monkeypatch, {"sandbox": {"mode": "firejail"}}
    )
    mode, refusal = _resolve(route, root, src, monkeypatch)
    operator = rc_module._load_operator_config(str(root), src, None)
    if operator is None:
        raise RuntimeError("premise: the operator chain must load")
    known = {Path(p).resolve() for p in operator.environment_paths}
    assert (mode, base.resolve() in known) == ("firejail", True), (mode, refusal)


@pytest.mark.parametrize("route", ["ash_config", "config_file"])
@pytest.mark.parametrize("arm", ["key", "patch"])
def test_the_refusal_never_prints_an_environment_chosen_path(
    tmp_path, monkeypatch, route, arm
):
    """The environment-chosen base writes a mode outside the known set,
    through its key or its own patch: the refusal names the file by its
    hidden form, never by the path the environment's value holds."""
    document = (
        {"sandbox": {"mode": "banana"}}
        if arm == "key"
        else {"patch": [{"op": "add", "path": "/sandbox", "value": {"mode": "melon"}}]}
    )
    src, base, root = _env_chosen_chain(tmp_path, monkeypatch, document)
    mode, refusal = _resolve(route, root, src, monkeypatch)
    if refusal is None:
        raise RuntimeError(f"premise: the chain must refuse, got {mode}")
    _absent(str(refusal), _PATH_CANARY)


# The child asserts, before the entrypoint runs, that it imported THIS
# checkout and that the routed environment is what put it there: the
# checkout under test is PYTHONPATH's first entry (checkout_env's stated
# contract) and the imported package resolves inside it. The import's
# location alone cannot carry the check, because an editable install can
# point at this tree anyway; the first-entry comparison is what an
# unrouted environment fails. The check runs in the child, and the parent
# reads back only a verdict line, because captured output masks
# environment values, the checkout path among them.
_CHECKOUT = Path(__file__).resolve().parents[3]
_CHILD_IMPORT_MARKER = "child-imported-the-checkout="
_CHILD_IMPORT_PROBE = (
    "import os as _os; from pathlib import Path as _Path; "
    "import automated_security_helper as _ash; "
    "_checkout = _Path(" + repr(str(_CHECKOUT)) + ").resolve(); "
    "_first = (_os.environ.get('PYTHONPATH') or '').split(_os.pathsep)[0]; "
    "_verdict = bool(_first) and _Path(_first).resolve() == _checkout and "
    "_Path(_ash.__file__).resolve().is_relative_to(_checkout); "
    "print('" + _CHILD_IMPORT_MARKER + "' + str(_verdict), flush=True); "
    "assert _verdict; "
)


def _cli(tmp_path, src, extra_env):
    out = tmp_path / "out"
    # One binding, no later writes: the child-process guard accepts an env
    # exactly when its every binding is checkout_env(...) and nothing
    # rewrites it afterwards.
    env = checkout_env({**os.environ, **extra_env})
    done = subprocess.run(  # nosec B603 - the venv's own interpreter, fixed arguments
        [
            sys.executable,
            "-c",
            _CHILD_IMPORT_PROBE
            + "from automated_security_helper.cli.entrypoint import main; main()",
            "scan",
            "--source-dir",
            str(src),
            "--output-dir",
            str(out),
            "--mode",
            "local",
        ],
        cwd=src,
        env=env,
        capture_output=True,
        text=True,
        timeout=240,
    )
    named = [line for line in done.stdout.splitlines() if _CHILD_IMPORT_MARKER in line]
    assert named, (done.returncode, done.stdout[-4000:], done.stderr[-4000:])
    assert named[-1].split(_CHILD_IMPORT_MARKER, 1)[1].strip() == "True", named[-1]
    logs = ""
    for log in (out / "ash.log", src / ".ash" / "ash_output" / "ash.log"):
        if log.is_file():
            logs += log.read_text(encoding="utf-8", errors="replace")
    return done, done.stdout + done.stderr + logs


def test_cli_output_never_prints_an_environment_chosen_path(tmp_path, monkeypatch):
    """The refusal's full surface: a scan refused on the environment-chosen
    base's junk mode writes neither stdout, stderr nor ash.log a path the
    environment chose."""
    src, base, root = _env_chosen_chain(
        tmp_path, monkeypatch, {"sandbox": {"mode": "banana"}}
    )
    done, text = _cli(tmp_path, src, {"ASH_CONFIG": str(root)})
    if done.returncode != 3 or "sandboxmodetheconfigurationdoesnotdefine" not in (
        _squeezed(text)
    ):
        raise RuntimeError(
            "premise: the CLI must refuse with the junk-mode sentence, "
            f"rc {done.returncode}"
        )
    _absent(text, _PATH_CANARY)


def test_control_cli_output_never_prints_an_environment_read_mode_value(
    tmp_path, monkeypatch
):
    """The companion the message already kept: a junk mode READ from the
    environment never reaches the refusal's surface either, so the two
    hidden things, the chosen path and the read value, hold together."""
    monkeypatch.setenv("ASH_MODE_UNDER_TEST", _MODE_CANARY)
    src = tmp_path / "src"
    mark_git_checkout(src)
    junk = _write_text(
        tmp_path / "plain" / "junk.yaml", "sandbox:\n  mode: ${ASH_MODE_UNDER_TEST}\n"
    )
    lower = _write(src / "cfg" / "lower.yaml", {"sandbox": {"mode": "off"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {"project_name": "hidden-form", "extends": [junk.as_posix(), lower.as_posix()]},
    )
    done, text = _cli(tmp_path, src, {"ASH_CONFIG": str(root)})
    if "sandboxmodetheconfigurationdoesnotdefine" not in _squeezed(text):
        raise RuntimeError(
            "premise: the CLI must refuse with the junk-mode sentence, "
            f"rc {done.returncode}"
        )
    assert done.returncode == 3, done.returncode
    _absent(text, _MODE_CANARY)
