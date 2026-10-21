"""Helper functions for ASH tests."""

import os
import shutil
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    import subprocess

from tests.utils.env_assertions import NamesOnlyEnvironment

from typing_extensions import Self

#: Set in the CI job that installs every scanner (sandbox-scanner-parity in
#: ash-unified-ci.yml), so the tests that run a real scanner fail there when the
#: tool is missing instead of skipping, as ASH_REQUIRE_SYMBOLS_EXTRA does for the
#: symbol tests. Elsewhere a missing tool skips them.
REQUIRE_REAL_SCANNERS = "ASH_REQUIRE_REAL_SCANNER_TESTS"


def require_scanner_binary(name: str) -> str:
    """The path of the scanner ``name`` on PATH; skip without it, or fail when required."""
    import pytest

    found = shutil.which(name)
    if found:
        return found
    if os.environ.get(REQUIRE_REAL_SCANNERS, "").strip().upper() in (
        "1",
        "YES",
        "TRUE",
    ):
        pytest.fail(
            f"{REQUIRE_REAL_SCANNERS} is set but {name} is not on PATH. This test "
            "must run in that CI job, not skip."
        )
    pytest.skip(f"needs a {name} binary on PATH")


#: Root of the tests' own scratch area, inside the repository and gitignored.
#:
#: Named rather than inlined because anything that walks the repository has to be
#: able to exclude it, and a second hardcoded "pytest-temp" would be free to
#: drift from this one. ``TestPluginManagerSingletonState`` in
#: ``tests/unit/workspace/test_project_isolation.py`` imports this constant for
#: exactly that reason: its sweep reads every ``*.py`` under the repository root,
#: and the ``ash_temp_path`` fixture deletes a subtree of this directory on
#: teardown while other xdist workers are mid-sweep.
ASH_TEST_TEMP_ROOT = Path(__file__).parent.parent / "pytest-temp"

#: The checkout these tests belong to.
REPO_ROOT = Path(__file__).resolve().parents[2]

#: How long a test waits for a child process it starts before giving up on it.
#:
#: Every test that starts a real child (``subprocess.run``, ``Popen`` and its
#: ``communicate``/``wait``, or ASH's ``run_command``,
#: ``run_command_with_output_handling``, ``spawn_run`` and ``_run_subprocess``)
#: passes this, unless it needs a bound of its own. Without one, a child that never
#: exits stalls its xdist worker and the whole run with it, and the run ends at the
#: outer CI timeout with no word of which test it was. That happened once to
#: ``test_base_plugins.py::TestScannerPlugin::test_run_subprocess_with_stdout_stderr``
#: in a ``tests/unit -n 32`` run. With it, the child is killed and the test fails
#: naming the command. Generous because the children here (git, python, sh) take
#: seconds even on a loaded runner; the bound is for a hang, not a slow child.
CHILD_TIMEOUT_SECONDS = 120


class KillAfter:
    """Kill a child still running after ``seconds``, and fail the test saying so.

    For a ``Popen`` child the test reads from, where no call takes a timeout: a read
    on its pipes blocks until it writes or exits. Killing it ends the read with EOF.
    Whatever that EOF trips first, leaving the block then raises an
    ``AssertionError`` that names the child and the bound.

        with KillAfter(server, "the stdio server"):
            line = server.stdout.readline()
    """

    def __init__(
        self, child, what: str, seconds: float = CHILD_TIMEOUT_SECONDS
    ) -> None:
        import threading

        self._child = child
        self._what = what
        self._seconds = seconds
        self.fired = False
        self._timer = threading.Timer(seconds, self._fire)
        self._timer.daemon = True

    def _fire(self) -> None:
        if self._child.poll() is None:
            self.fired = True
            self._child.kill()

    def __enter__(self) -> Self:
        self._timer.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self._timer.cancel()
        if self.fired:
            raise AssertionError(
                f"{self._what} was still running after {self._seconds}s and was killed"
            ) from exc
        return False


def bound_run_command(monkeypatch, seconds: float = CHILD_TIMEOUT_SECONDS) -> None:
    """Give ``subprocess_utils.run_command`` a timeout when its caller passes none.

    For a test that reaches a child through ASH code with no timeout argument of its
    own, such as the installer's ``dependencies.run_command``. A child still running
    after ``seconds`` is killed and the test fails naming it. ``pytest.fail``, not an
    ``AssertionError``, because the installer catches ``Exception`` and would report
    the timeout as one more failed command.
    """
    import pytest

    from automated_security_helper.utils import subprocess_utils

    original = subprocess_utils.run_command

    def run_command(*args, **kwargs):
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = seconds
        result = original(*args, **kwargs)
        if isinstance(result, subprocess_utils.TimedOutProcess):
            pytest.fail(
                f"{result.args!r} was still running after {seconds}s and was killed"
            )
        return result

    monkeypatch.setattr(subprocess_utils, "run_command", run_command)


def importing_this_checkout(driver: str) -> str:
    """``driver``, preceded by code that has it import ASH from this checkout.

    For a child started with ``python -I``. ``-I`` leaves the current directory and
    ``PYTHONPATH`` off ``sys.path``, so such a child imports ASH from wherever the
    interpreter's installed copy points, which is not necessarily the checkout under
    test: an editable install points at the tree it was installed from. This puts the
    checkout first on ``sys.path``, and the child exits 86 before running ``driver``
    if ``automated_security_helper`` still comes from somewhere else.
    """
    root = str(REPO_ROOT)
    return (
        "import sys\n"
        f"sys.path.insert(0, {root!r})\n"
        "import automated_security_helper as _ash\n"
        "from pathlib import Path as _Path\n"
        f"if not _Path(_ash.__file__).resolve().is_relative_to({root!r}):\n"
        "    sys.stderr.write(\n"
        f"        'imported ASH from ' + _ash.__file__ + ', not from ' + {root!r}\n"
        "    )\n"
        "    raise SystemExit(86)\n"
        "del _ash, _Path\n"
    ) + driver


def mark_inner_run_completed(results_file: Path, run_id: str) -> bool:
    """Add the completion marker an inner run writes to ``results_file``, as it would.

    For tests that stand in for the inner run of a container or nix scan (see
    utils/inner_run_outcome.py). False, with the file unchanged, when it is not JSON.
    """
    import json

    from automated_security_helper.utils.inner_run_outcome import completion_marker

    try:
        document = json.loads(Path(results_file).read_text(encoding="utf-8"))
    except ValueError:
        return False
    document.setdefault("validation_checkpoints", []).append(completion_marker(run_id))
    Path(results_file).write_text(json.dumps(document), encoding="utf-8")
    return True


def builtin_reporter_classes() -> list:
    """Every built-in reporter class, from the reporters package itself.

    Not ``ash_builtin.ASH_REPORTERS``, which is empty in a process whose first ASH
    import was ``interactions.run_ash_scan``: that import reaches the built-in
    plugin package through ``config.ash_config`` while
    ``core.scanner_statistics_calculator`` is still initializing, and the reporter
    group fails to load.
    """
    from automated_security_helper.base.reporter_plugin import ReporterPluginBase
    from automated_security_helper.plugin_modules.ash_builtin import reporters

    return [
        value
        for value in vars(reporters).values()
        if isinstance(value, type)
        and issubclass(value, ReporterPluginBase)
        and value is not ReporterPluginBase
    ]


def results_of_a_scan():
    """Results that hold a scan: one scanner's entry, as a scan phase records it.

    For tests that hand ``--use-existing`` a results file. ``AshAggregatedResults()``
    on its own holds no scanner results and no findings, which ``--use-existing``
    refuses.
    """
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    return AshAggregatedResults.model_validate(
        {"scanner_results": {"bandit": {"source": {"scanner_name": "bandit"}}}}
    )


def sarif_report_written(results, name: str = "ash.sarif"):
    """Record in ``results`` that the run's SARIF reporter wrote ``reports/<name>``.

    As the report phase records it, for tests that hand ``_run_local_mode`` or
    ``_compute_exit_code`` results without running the report phase: only a file
    so recorded is counted or rewritten as the run's SARIF report. Returns
    ``results``.
    """
    from automated_security_helper.utils.inner_run_outcome import (
        record_reports_written,
    )

    record_reports_written(results, [(name, "sarif")])
    return results


def is_under_test_scratch(path: Path) -> bool:
    """Whether ``path`` is one of the tests' own throwaway files.

    Every test that walks the repository root and then reads what it enumerated
    has to call this. The walk and the read are separate steps -- ``rglob`` is
    typically materialised in full first -- so under ``-n auto`` another worker's
    ``ash_temp_path`` teardown deletes a file between the two and the read raises
    ``FileNotFoundError``.

    Measured twice, in two different walkers, which is why this is a shared
    predicate rather than a line repeated per test:

    * ``tests/unit/workspace/test_project_isolation.py`` on macos-latest py3.12,
      on ``tests/pytest-temp/<uuid>/source/test.py``.
    * ``tests/unit/test_agent_plugin_ash_version.py`` on macos-14 py3.11, on
      ``tests/pytest-temp/<uuid>/test_output_dir``.

    The first was fixed in isolation and the second failed the same way three
    hours later, so the lesson is recorded here rather than in either test: the
    exposure belongs to *any* repo-root walker, not to a particular one.

    Deliberately not solved by catching ``FileNotFoundError`` at each read site.
    That turns "a file vanished" into "no match found", and several of these
    walkers are sweeps whose whole value is that an empty result means absence
    rather than blindness.

    Resolved on both sides because a walker may yield either spelling, and
    ``is_relative_to`` is purely lexical.
    """
    try:
        return path.resolve().is_relative_to(ASH_TEST_TEMP_ROOT.resolve())
    except OSError:
        # A path that cannot be resolved (a broken link, or one the process
        # cannot stat) is not the scratch tree, and the caller's own read is the
        # right place for that failure to surface.
        return False


def iter_repo_files(
    root: Path,
    *,
    skip_dirs: frozenset[str] = frozenset(),
    prune_scratch: bool = True,
) -> Iterator[Path]:
    """Every file under ``root``, pruning the scratch tree *during* traversal.

    Why not ``root.rglob(...)``
    ---------------------------
    ``rglob`` raises from inside its own descent, before it yields anything, so no
    filter applied to its output can prevent the failure. Measured on macos-14
    py3.11:

        _candidate_files -> REPO_ROOT.rglob("*")
          pathlib.py:397 _iterate_directories   (recursive)
          pathlib.py:386   with scandir(parent_path) as scandir_it:
          -> os.scandir(self)
          FileNotFoundError: .../tests/pytest-temp/<uuid>/test_output_dir

        rglob listed the directory, another worker's ash_temp_path teardown
        removed it, and rglob then tried to descend into it.

        Observed on py3.11 and not on the other legs of the same run. Measured
        since, deterministically, by removing the directory at the moment rglob
        lists it through an audit hook on os.scandir: 3.10 and 3.11 raise
        FileNotFoundError, and 3.12, 3.13 and 3.14 skip the directory without an
        error. A newer interpreter still descends into the scratch tree and
        returns whatever is there, so it is not immune to the race, only quieter.

    ``os.walk`` can be pruned, which removes the race rather than tolerating it:
    mutating ``dirnames`` in place stops the descent from ever happening.

    Why ``onerror`` re-raises
    -------------------------
    ``os.walk`` ignores errors by default, which would make this "fixed" by going
    blind -- and several callers are sweeps whose entire value is that an empty
    result means absence rather than a broken walk. So anything that vanishes
    *outside* the pruned scratch tree is raised, and only the scratch tree is
    silently skipped. A vanishing file anywhere else is a real problem and should
    fail loudly.

    ``prune_scratch=False``
    -----------------------
    For the one caller that has to *see* the scratch tree: the control in
    ``test_the_exclusion_removes_nothing_but_the_temp_root``, which compares the
    pruned walk against the unpruned one and would prove nothing if both pruned.
    That mode tolerates a vanished directory instead of raising, because a control
    that crashes on the race it is measuring is useless. Do not use it anywhere
    else -- outside that comparison, silence is the failure mode, not the fix.
    """
    scratch = ASH_TEST_TEMP_ROOT.resolve()

    def _onerror(error: OSError) -> None:
        if not prune_scratch:
            return
        failed = Path(getattr(error, "filename", "") or "")
        try:
            inside = failed.resolve().is_relative_to(scratch)
        except OSError:
            inside = False
        if not inside:
            raise error

    for dirpath, dirnames, filenames in os.walk(root, onerror=_onerror):
        here = Path(dirpath)
        # In place, so os.walk never descends. Rebinding dirnames does nothing.
        dirnames[:] = [
            name
            for name in dirnames
            if name not in skip_dirs
            and not (prune_scratch and is_under_test_scratch(here / name))
        ]
        if prune_scratch and is_under_test_scratch(here):
            continue
        for name in filenames:
            yield here / name


def ash_tool_not_found_reason(tool: str, windows: Optional[bool] = None) -> str:
    """The skip reason for a test that needs a tool ASH installs, and found none.

    ``find_executable`` looks on PATH, then in ASH's bin directory (ASH_BIN_PATH, or
    ~/.ash/bin) and /usr/local/bin. tests/conftest.py gives every run and every test
    a home of its own, so during a run ~/.ash/bin is an empty directory there, and a
    tool ``ash dependencies install`` put in the developer's ~/.ash/bin is not found
    unless that directory is on PATH. The reason says so, because "not installed" sends
    whoever reads it to install a tool they already have. It names PATH rather than
    ASH_BIN_PATH because tests that install to the default directory install into
    ASH_BIN_PATH. ``windows`` picks the shell syntax, PowerShell and cmd or POSIX; by
    default, this platform's.
    """
    if windows is None:
        windows = os.name == "nt"
    if windows:
        advice = (
            '$env:PATH = "$HOME\\.ash\\bin;$env:PATH" (PowerShell), or '
            'set "PATH=%USERPROFILE%\\.ash\\bin;%PATH%" (cmd)'
        )
    else:
        advice = 'PATH="$HOME/.ash/bin:$PATH"'
    return (
        f"{tool} is not on PATH or in ASH's bin directory, which tests keep in a home "
        "of their own; to run this test against a copy `ash dependencies install` put "
        f"in ~/.ash/bin, run with {advice}"
    )


def get_ash_temp_path():
    """Create a temporary directory using the gitignored tests/pytest-temp directory.

    This fixture provides a consistent temporary directory that is gitignored
    and located within the tests directory structure.

    Returns:
        Path to the temporary directory
    """
    import uuid

    # Create a unique subdirectory for this test session
    temp_dir = ASH_TEST_TEMP_ROOT / str(uuid.uuid4())
    temp_dir.mkdir(parents=True, exist_ok=True)

    return temp_dir


def module_from_this_checkout(module: str) -> str:
    """Code that runs ``module`` as ``python -m`` would, importing ASH from this
    checkout (``importing_this_checkout``).

    For a child started as ``python -I -m automated_security_helper...``: ``-I``
    ignores ``PYTHONPATH``, so ``checkout_env`` cannot reach it. Start it as
    ``[sys.executable, "-I", "-c", module_from_this_checkout(module), *args]``
    instead; ``runpy`` gives the module ``sys.argv[0]`` and ``__main__`` as ``-m``
    does, and the arguments after the code are its ``sys.argv[1:]``.
    """
    return importing_this_checkout(
        "import runpy\n"
        f"runpy.run_module({module!r}, run_name='__main__', alter_sys=True)\n"
    )


def checkout_env(env: Optional[dict] = None) -> dict:
    """``env`` (os.environ when None), with this checkout first on ``PYTHONPATH``.

    For a child Python that is not started with ``-I`` or ``-E``: a
    ``-m automated_security_helper...`` module, a script that imports ASH, or the
    ``ash`` console script. Each imports ASH from wherever the interpreter's
    installed copy points unless ``PYTHONPATH`` names the checkout: an editable
    install points at the tree it was installed from, which need not be this one.

    A ``NamesOnlyEnvironment``, so a failure whose traceback passes through a frame
    given it shows its names, not their values.
    """
    given = NamesOnlyEnvironment(os.environ if env is None else env)
    parts = [str(REPO_ROOT)]
    if given.get("PYTHONPATH"):
        parts.append(given["PYTHONPATH"])
    given["PYTHONPATH"] = os.pathsep.join(parts)
    return given


def run_a_child_pytest_under_this_suite(
    source: str,
    basetemp: Path,
    *,
    prefix: str,
    options: "Sequence[str]" = (),
    environment: "Optional[dict[str, str]]" = None,
    junitxml: Optional[Path] = None,
    extra_files: "Optional[dict[str, str]]" = None,
    timeout: int = 240,
) -> "subprocess.CompletedProcess[str]":
    """Run *source* as a test module in a child pytest under this suite's own
    root conftest, and give the completed process.

    The module sits in a directory of its own (``mkdtemp``, *prefix*) under
    ASH_TEST_TEMP_ROOT, so the suite's conftest governs the child and no two
    runs share a holder; the holder is removed whatever the child did. The
    child's environment is built here, not inherited: PATH, what Windows
    needs to start Python, HOME and the temp variables at *basetemp*, no
    bytecode, this checkout first on PYTHONPATH (checkout_env), and
    *environment* over all of that. The report backstop
    (tests/utils/env_assertions.py) redacts every environment value from the
    child's failure reports, so a caller that asserts a report's exact words
    must not hand the child a value an ordinary word could be -- one host
    holds "user" as a value, and a caller that inherited this run's
    environment there missed text the backstop had rewritten.

    *extra_files* maps holder-relative paths to contents, for a probe that
    needs more than one module -- a package with its ``__init__.py`` and
    ``conftest.py``, a second module. With extra files, the child collects
    the whole holder, in name order, so a package named before ``test_zz``
    runs before *source*'s module; without them, only *source*'s module.
    """
    import subprocess
    import sys
    import tempfile

    ASH_TEST_TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    holder = Path(tempfile.mkdtemp(prefix=prefix, dir=ASH_TEST_TEMP_ROOT))
    module = holder / f"test_zz_{prefix.rstrip('-').replace('-', '_')}_probe.py"
    extras = {
        holder / relative: content for relative, content in (extra_files or {}).items()
    }
    made_directories: "list[Path]" = []
    # Everything after the mkdtemp runs inside the try: a write that fails
    # must not leave the holder behind, and the cleanup tolerates a file the
    # failure never wrote (missing_ok).
    scratch = {
        name: os.environ[name]
        for name in ("SYSTEMROOT", "COMSPEC", "PATHEXT")
        if name in os.environ
    }
    # Containment names the run sets survive the build: a sanitizing wrapper
    # carries GIT_CEILING_DIRECTORIES itself, so a child's git discovery
    # cannot walk into shared parents, and the proxies and the metadata
    # switch keep a child off the network and real credentials. Their values
    # are paths, URLs or flags, never ordinary words the report backstop
    # could rewrite out of a caller's asserted text. *environment* still
    # wins (setdefault after the update below).
    containment = (
        "GIT_CEILING_DIRECTORIES",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        # curl and git-over-http prefer the lower-case proxy names for an
        # http:// URL and fall back to all_proxy/ALL_PROXY (measured on
        # loopback: curl with only HTTP_PROXY connected straight; with
        # ALL_PROXY beside it, it stayed on the proxy). A child missing the
        # lower-case names bypasses a refusing proxy exactly when the parent
        # set no ALL_PROXY either; carrying every spelling closes that case.
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "AWS_EC2_METADATA_DISABLED",
        "ASH_BIN_PATH",
        # The run's wrapper points these off real credentials and telemetry.
        "KRB5CCNAME",
        "SEMGREP_SEND_METRICS",
    )
    scratch.update(
        {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(basetemp),
            "USERPROFILE": str(basetemp),
            "TMPDIR": str(basetemp),
            "TEMP": str(basetemp),
            "TMP": str(basetemp),
            # No __pycache__ beside the module, so its holder empties.
            "PYTHONDONTWRITEBYTECODE": "1",
            **(environment or {}),
        }
    )
    for name in containment:
        if name in os.environ:
            scratch.setdefault(name, os.environ[name])
    scratch.setdefault("UV_OFFLINE", "1")
    # The AWS file-path settings are pinned, never copied. A plain run that
    # points them at real files would re-point a child whose scratch HOME
    # was meant to hide ~/.aws, and no other AWS_*_FILE name
    # (AWS_WEB_IDENTITY_TOKEN_FILE among them) is carried at all, since this
    # environment is built, not inherited. A test that needs real AWS files
    # passes them in *environment*, which wins over these pins.
    scratch.setdefault("AWS_CONFIG_FILE", os.devnull)
    scratch.setdefault("AWS_SHARED_CREDENTIALS_FILE", os.devnull)
    try:
        module.write_text(source, encoding="utf-8")
        for path in extras:
            parent = path.parent
            missing: "list[Path]" = []
            while parent != holder and not parent.exists():
                missing.append(parent)
                parent = parent.parent
            for directory in reversed(missing):
                directory.mkdir()
                made_directories.append(directory)
        for path, content in extras.items():
            path.write_text(content, encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(holder) if extras else str(module),
                "-p",
                "no:cacheprovider",
                "-o",
                "addopts=",
                f"--basetemp={basetemp / 'bt'}",
                *([f"--junitxml={junitxml}"] if junitxml is not None else []),
                *options,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=REPO_ROOT,
            env=checkout_env(scratch),
        )
    finally:
        for path in extras:
            path.unlink(missing_ok=True)
        for directory in sorted(
            made_directories, key=lambda path: len(path.parts), reverse=True
        ):
            directory.rmdir()
        module.unlink(missing_ok=True)
        holder.rmdir()


def builtin_scanner_config_names() -> list:
    """Every built-in scanner's config name, derived from the registry.

    For a cell that disables each built-in scanner: a hardcoded list silently
    drops a newly shipped scanner out of the pin, while this list stays equal
    to what a scan registers.
    """
    import typing

    from automated_security_helper.plugin_modules import ash_builtin

    names = []
    for cls in ash_builtin.ASH_SCANNERS:
        annotation = cls.model_fields["config"].annotation
        config_cls = [a for a in typing.get_args(annotation) if a is not type(None)][0]
        names.append(config_cls.model_fields["name"].default)
    return sorted(names)


def mark_git_checkout(root: Path) -> None:
    """Mark ``root`` as a git checkout the way git's own discovery sees one.

    A ``.git`` directory holding ``HEAD``. ``sandbox_grants`` counts only a
    git-shaped ``.git`` (a gitfile, a link, or a directory with ``HEAD``) as
    a checkout boundary, so a bare empty ``.git`` directory -- a stray mkdir,
    or a transient mount point another process leaves in a shared parent --
    no longer moves it. Fixtures use this instead of ``(root / ".git").mkdir()``
    so the marker they plant is one the boundary still honors."""
    git_dir = root / ".git"
    git_dir.mkdir(parents=True, exist_ok=True)
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")


def stand_in_host_ids(monkeypatch, uid: int = 1000, gid: int = 1000) -> None:
    """Answer the host's uid and gid without running ``id -u`` and ``id -g``.

    Container mode bakes both into the image's build arguments. The real lookup
    is a program start the process guard refuses, and on Windows ``id`` does
    not exist.
    """
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: uid)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: gid)
