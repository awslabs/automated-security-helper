"""Under a scanner sandbox, the operator's offline rule cache is readable.

An offline semgrep or opengrep scan reads its rules from ``$SEMGREP_RULES_CACHE_DIR`` or
``$OPENGREP_RULES_CACHE_DIR``. ASH checks that directory in its own process before the
scan, so a sandbox that does not mount it leaves the tool without rules: semgrep exits 7
("unable to find a config") behind a check that already passed. The documented setup
puts the cache under ``$HOME/.cache/ash`` (and the nix shell under
``$HOME/.cache/ash/semgrep-rules``), which every backend hides by default.

Required: the directory named by that variable in ASH's own environment is readable by
the scanner, and it is not writable. Only the variable grants it: a path in the
scanner's options, which the scanned repository can set, does not, and an empty
variable grants nothing.

The backend is a stand-in registered as ``bwrap`` that records each spawn's policy, so
no real sandbox is needed; ``sandbox.extra_read_paths`` is the control that shows a
granted directory reaches the recorded policy.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
)
from automated_security_helper.utils.sandbox import backends as backends_module
from automated_security_helper.utils.sandbox import policy as policy_module
from automated_security_helper.utils.sandbox import scope as scope_module
from automated_security_helper.utils.sandbox.backends import SpawnPlan

AshConfig.model_rebuild()

RULE = """\
rules:
  - id: offline-rule
    pattern: print(...)
    message: a print call
    languages: [python]
    severity: WARNING
"""

SCANNERS = {
    "semgrep": (SemgrepScanner, "SEMGREP_RULES_CACHE_DIR"),
    "opengrep": (OpengrepScanner, "OPENGREP_RULES_CACHE_DIR"),
}


class _Recorder:
    name = "recorder"
    policies: list = []

    def probe(self):
        return None

    def plan(self, argv, env, policy):
        type(self).policies.append(policy)
        return SpawnPlan(argv=list(argv), env=dict(env))


@pytest.fixture
def backend(monkeypatch):
    class Recorder(_Recorder):
        policies = []

    scope_module.clear_backend_cache()
    monkeypatch.setitem(scope_module.BACKENDS, "bwrap", Recorder)
    yield Recorder
    scope_module.clear_backend_cache()


@pytest.fixture
def layout(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('x')\n")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return tmp_path, home, source, output


def _rules_dir(path: Path) -> Path:
    path.mkdir(parents=True)
    (path / "offline-rule.yml").write_text(RULE)
    (path / ".ash-rules-fetched-at").write_text("2026-10-10T00:00:00Z\n")
    return path


def _policy(layout, backend, name, *, extra_read_paths=(), options=None):
    """The policy the scanner's tool spawn gets under ``--sandbox bwrap``."""
    _tmp, _home, source, output = layout
    scanner_class, _variable = SCANNERS[name]
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(
            project_name="offline",
            sandbox=SandboxConfig(
                mode="bwrap", extra_read_paths=list(extra_read_paths)
            ),
        ),
    )
    scanner = scanner_class(context=context)
    if options:
        for key, value in options.items():
            setattr(scanner.config.options, key, value)
    scope = scope_module.scanner_sandbox_scope(scanner, context, source)
    assert scope is not None, "sandbox mode bwrap produced no scope"
    with scope_module.sandbox_scope(scope):
        scope_module.prepare_spawn([name, "scan"], dict(os.environ), str(source))
    return backend.policies[-1]


def _real(path) -> Path:
    return Path(os.path.realpath(path))


def _readable(policy):
    return {_real(p) for p in (*policy.read_only, *policy.cache)}


def _covers(paths, target: Path) -> bool:
    target = _real(target)
    return any(target == p or p in target.parents for p in paths)


@pytest.mark.parametrize("name", sorted(SCANNERS))
@pytest.mark.parametrize("where", ["outside-home", "under-home"])
def test_the_operators_rule_cache_is_readable(
    layout, backend, monkeypatch, name, where
):
    tmp, home, _source, _output = layout
    _scanner, variable = SCANNERS[name]
    base = home / ".cache" / "ash" if where == "under-home" else tmp / "rule-cache"
    rules = _rules_dir(base / name)
    monkeypatch.setenv(variable, str(rules))

    policy = _policy(layout, backend, name)

    assert _covers(_readable(policy), rules), (
        f"{name} runs offline from ${variable}={rules}, which ASH checked in its own "
        "process, but the sandbox does not mount it; the tool finds no rules"
    )
    assert not _covers({_real(p) for p in policy.writable}, rules), (
        f"the rule cache must not be writable: {policy.writable}"
    )


def test_a_directory_in_extra_read_paths_is_readable(layout, backend, monkeypatch):
    """Control: an operator grant of the same directory reaches the recorded policy."""
    tmp, _home, _source, _output = layout
    rules = _rules_dir(tmp / "rule-cache" / "semgrep")
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(rules))

    policy = _policy(layout, backend, "semgrep", extra_read_paths=[str(rules)])

    assert _covers(_readable(policy), rules)


def test_a_rules_path_in_the_scanner_options_is_not_granted(
    layout, backend, monkeypatch
):
    """The options can come from the scanned repository; only the variable grants.

    Online, where semgrep passes ``options.config`` to the tool as its rule source.
    """
    tmp, _home, _source, _output = layout
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv(
        "SEMGREP_RULES_CACHE_DIR", str(_rules_dir(tmp / "rule-cache" / "semgrep"))
    )
    named_by_options = _rules_dir(tmp / "elsewhere" / "rules")

    policy = _policy(
        layout, backend, "semgrep", options={"config": str(named_by_options)}
    )

    assert not _covers(_readable(policy), named_by_options), (
        f"a directory named only in the scanner's options was mounted: {named_by_options}"
    )


def test_an_empty_variable_grants_nothing(layout, backend, monkeypatch):
    """An empty value must not become the working directory or the filesystem root."""
    tmp, _home, _source, _output = layout
    working = tmp / "working"
    working.mkdir()
    monkeypatch.chdir(working)
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", "")

    policy = _policy(layout, backend, "semgrep")

    readable = _readable(policy)
    assert _real(working) not in readable
    assert Path("/") not in readable


@pytest.mark.parametrize("value", ["root", "home", "holding-home"])
def test_a_variable_naming_a_root_or_the_home_directory_grants_nothing(
    layout, backend, monkeypatch, value
):
    """A value that would expose far more than a rules directory is not mounted.

    The filesystem root, $HOME, and a directory holding $HOME, which would mount
    $HOME with everything else under it. Online, so the scanner does not search that
    directory for rules files first.
    """
    _tmp, home, _source, _output = layout
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    named = {
        "root": Path(Path.cwd().anchor),
        "home": home,
        "holding-home": home.parent,
    }[value]
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(named))

    policy = _policy(layout, backend, "semgrep")

    assert _real(named) not in _readable(policy)


@pytest.mark.parametrize("value", ["passwd-home", "holding-passwd-home"])
def test_a_variable_naming_the_passwd_home_grants_nothing(
    layout, backend, monkeypatch, value
):
    """With HOME elsewhere, the passwd entry's home is a home too.

    sandbox-exec denies reading it and then allows the policy's read paths again,
    so a grant of it, or of a directory holding it, would re-open it, ~/.ssh
    included. The check measured only against HOME.
    """
    tmp, _home, _source, _output = layout
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    passwd_home = tmp / "elsewhere" / "passwd-home"
    (passwd_home / ".ssh").mkdir(parents=True)
    for module in (policy_module, backends_module):
        monkeypatch.setattr(module, "_passwd_home", lambda: passwd_home, raising=False)
    named = passwd_home if value == "passwd-home" else passwd_home.parent
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(named))

    policy = _policy(layout, backend, "semgrep")

    assert _real(named) not in _readable(policy)


def test_the_rule_cache_is_not_a_program_directory(layout, backend, monkeypatch):
    """It is data the tool reads: readable, and not among the executable paths."""
    tmp, _home, _source, _output = layout
    rules = _rules_dir(tmp / "rule-cache" / "semgrep")
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(rules))

    policy = _policy(layout, backend, "semgrep")

    assert _covers(_readable(policy), rules)
    assert _real(rules) not in {_real(p) for p in policy.executable}


def test_sandbox_exec_runs_no_program_from_the_rule_cache(layout, backend, monkeypatch):
    """Under sandbox-exec exec is denied in the cache, even inside an executable root.

    sandbox-exec is the backend that restricts exec (``_exec_rules``): programs run
    from the policy's executable paths and are denied again in the scan's data. A
    rules cache inside a directory that is itself executable (here an
    ``extra_read_paths`` entry, like ``/opt`` or ``/usr/local``) stayed executable
    through its parent. bwrap, firejail and Landlock do not restrict exec by path,
    which the docs say.
    """
    from automated_security_helper.utils.sandbox.backends import (
        _exec_rules,
        _sbpl_string,
    )

    tmp, _home, _source, _output = layout
    root = tmp / "tools-root"
    rules = _rules_dir(root / "rules" / "semgrep")
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(rules))

    policy = _policy(layout, backend, "semgrep", extra_read_paths=[str(root)])
    rules_text = "\n".join(_exec_rules(policy, tmp / "private-tmp"))

    denied = [line for line in rules_text.splitlines() if line.startswith("(deny")]
    assert denied and _sbpl_string(_real(rules)) in denied[0], rules_text


def test_a_variable_naming_a_file_grants_nothing(layout, backend, monkeypatch):
    """The variable names a rules directory; a file is not one.

    Online, so the scanner does not read that path as its rule cache first.
    """
    tmp, home, _source, _output = layout
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    named = home / "settings" / "notes.txt"
    named.parent.mkdir(parents=True)
    named.write_text("notes\n")
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(named))

    policy = _policy(layout, backend, "semgrep")

    assert not _covers(_readable(policy), named), (
        f"a file named by the variable was mounted: {named}"
    )


def test_a_relative_value_grants_nothing(layout, backend, monkeypatch):
    """A relative path would be resolved against whatever the working directory is."""
    tmp, _home, _source, _output = layout
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    rules = _rules_dir(tmp / "working" / "rules")
    monkeypatch.chdir(tmp / "working")
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", "rules")

    policy = _policy(layout, backend, "semgrep")

    assert not _covers(_readable(policy), rules)
