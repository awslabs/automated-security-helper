"""``ash dependencies install`` takes the scanners a scan of its config takes.

Reading a config's section of a scanner ASH ships whose manifest gives no typed
section (guarddog's) imports that scanner's plugin module, and the import
registers the scanner for the whole process. A scan takes only ASH's
built-in plugins and those of the modules its config's ``ash_plugin_modules``
names (``plugins.loader.scan_plugin_filter``). The installer asks that filter
for a scanner of such a module, so a config that holds ``scanners.guarddog``
and does not name guarddog's module has guarddog neither built, installed nor
option-checked, as a scan of the same file never loads it.

The command is driven for real through the install tests' runner
(``dependencies_install_support.run_install``), with the plugin registry left as
it is: the registry is what the case reads, and ``build_scene`` puts one fake
plugin in its place. Nothing is built or installed. The config gives trivy-repo,
a scanner of a module it names, an option that scanner refuses, so the run ends
at the option check, which comes before the first build, with exit code 3; a
check that refused nothing is stopped there too. Each plugin the command takes is
recorded as it reads the plugin's name, before any build, and the builds are made
from those plugins, the installs from the builds. A command it would run goes to
a recorder.
"""

from pathlib import Path
from typing import List, NamedTuple

import pytest
import typer
import yaml

from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.core.exceptions import ASHConfigValidationError
from tests.unit.cli.dependencies_install_support import Scene, run_install

pytestmark = pytest.mark.unit

#: The module that declares guarddog's scanner.
GUARDDOG_MODULE = "automated_security_helper.plugin_modules.ash_guarddog_plugins"

#: A module the config names in every run, whose trivy-repo scanner the config
#: gives an option it refuses.
TRIVY_MODULE = "automated_security_helper.plugin_modules.ash_trivy_plugins"

#: The exit code of a run the option check let through, stopped before any build.
STOPPED = 97


class _Run(NamedTuple):
    exit_code: int
    printed: str
    #: The plugin classes the command took, by name, in the order it read them.
    taken: List[str]
    #: The option check's refusals.
    refusals: List[str]
    #: The commands the command ran.
    ran: List[List[str]]


def _install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, named: bool) -> _Run:
    """``ash dependencies install --config cfg.yaml`` with no ``--tool``, for a
    config that holds guarddog's section and trivy-repo's, each giving its
    scanner an option it refuses, and that names trivy's module, and guarddog's
    too when ``named``."""
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "cfg.yaml"
    # Each section gets its own mapping: one shared object would be written as a
    # YAML anchor and alias, which the config parser refuses.
    config.write_text(
        yaml.safe_dump(
            {
                "ash_plugin_modules": (
                    [TRIVY_MODULE, GUARDDOG_MODULE] if named else [TRIVY_MODULE]
                ),
                "scanners": {
                    "trivy-repo": {"options": {"no_such_option": True}},
                    "guarddog": {"options": {"no_such_option": True}},
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    taken: List[str] = []
    declared_name = dependencies_module._declared_install_name

    def recording_name(plugin_class, plugin_type, resolved_config):
        taken.append(plugin_class.__name__)
        return declared_name(plugin_class, plugin_type, resolved_config)

    monkeypatch.setattr(dependencies_module, "_declared_install_name", recording_name)

    refusals: List[str] = []
    check = dependencies_module.refuse_unknown_options_of_registered

    def recording_check(*args, **kwargs):
        try:
            check(*args, **kwargs)
        except ASHConfigValidationError as refusal:
            refusals.append(str(refusal))
            raise
        raise typer.Exit(STOPPED)

    monkeypatch.setattr(
        dependencies_module, "refuse_unknown_options_of_registered", recording_check
    )

    scene = Scene()

    def run_command(cmd, shell=False):
        scene.calls.append((list(cmd), shell))
        return 0

    monkeypatch.setattr(dependencies_module, "run_command", run_command)
    run_install(scene, monkeypatch, tmp_path, "--config", str(config))
    return _Run(scene.result.exit_code, scene.text, taken, refusals, scene.argvs)


@pytest.mark.parametrize("named", [False, True], ids=["not-named", "named"])
def test_the_install_takes_guarddog_only_when_the_config_names_its_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: bool
) -> None:
    """guarddog is registered either way, by the read of its section. The
    command takes it only when the config names its module, as a scan does, so
    with the module unnamed it is neither built nor installed. A built-in scanner,
    and the scanner of a module the config names, are taken either way."""
    run = _install(tmp_path, monkeypatch, named=named)

    assert run.exit_code == 3, run.printed
    assert run.ran == []
    registered = {
        plugin.__name__
        for plugin in dependencies_module.ash_plugin_manager.plugin_modules("scanner")
    }
    assert "GuardDogScanner" in registered, registered
    assert {"BanditScanner", "TrivyRepoScanner"} <= set(run.taken), run.taken
    assert ("GuardDogScanner" in run.taken) is named, run.taken


@pytest.mark.parametrize("named", [False, True], ids=["not-named", "named"])
def test_the_option_check_reads_guarddogs_section_only_when_its_module_is_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: bool
) -> None:
    """The check that refuses a bad option before any build reads the sections of
    the plugins the command takes: guarddog's only when the config names its
    module, as a scan's check does, and trivy-repo's either way."""
    run = _install(tmp_path, monkeypatch, named=named)

    assert run.exit_code == 3, run.printed
    (refusal,) = run.refusals
    assert "scanners.trivy-repo.options" in refusal, refusal
    assert ("scanners.guarddog.options" in refusal) is named, refusal
