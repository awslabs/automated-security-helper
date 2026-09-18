"""Helper functions for ASH tests."""

import os
from collections.abc import Iterator
from pathlib import Path

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

        Observed on py3.11 and not on the other legs of the same run. Whether that
        is a pathlib version difference or just which worker lost the race is NOT
        established -- an attempt to reproduce the raise synthetically on 3.11 and
        3.13 failed to hit the window on either, so treat the leg it appeared on as
        a sample rather than as the affected set, and do not assume a newer
        interpreter is immune.

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
