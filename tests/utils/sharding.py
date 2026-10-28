# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run one shard of the suite: ignore the test modules another shard owns.

CI splits the unit-test job into shards (``ASH_TEST_SHARD=3of8``) because the whole suite
does not finish inside one job. The split is made here, in ``pytest_ignore_collect``,
rather than by handing pytest a list of files:

* A file named on the command line skips pytest's ignore machinery, so ``norecursedirs``,
  ``--ignore``, ``collect_ignore`` and the ``python_files`` match would stop applying to
  it, and a list built outside pytest would have to copy ``testpaths`` and ``python_files``
  and keep them in step.
* Here pytest collects exactly as it does for an unsharded run, with its own ``testpaths``,
  ``python_files`` and ignore rules, and this hook only removes the modules another shard
  owns. A module that is ignored is never imported.

A module belongs to shard ``crc32(path) % count + 1``, where ``path`` is its POSIX path
relative to the rootdir. That depends on the module alone, so every xdist worker and every
shard agree without sharing a list, and each module lands in exactly one shard of a given
count. Only paths that match the ``python_files`` patterns pytest was configured with are
filtered; everything else is left to pytest.

An empty shard makes pytest exit 5 (no tests collected), so a count larger than the suite
fails the job instead of passing it. A malformed ``ASH_TEST_SHARD`` is a usage error.

The setting belongs to the run it was given to. ``configure`` reads ASH_TEST_SHARD once,
at ``pytest_configure``, and removes it from ``os.environ``: a variable left there would
reach every pytest a test starts, and a child that loaded tests/conftest.py and collected
a directory would drop the modules other shards own. The hook reads the setting from the
config, never from the environment. xdist workers are started after the removal and get
the setting through ``workerinput`` (``pytest_configure_node``).
"""

from __future__ import annotations

import fnmatch
import os
import re
import zlib
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Tuple

import pytest

#: The variable the run-unit-tests action sets for a shard; unset means the whole suite.
ENV_VAR = "ASH_TEST_SHARD"

_SHARD = re.compile(r"^([1-9][0-9]*)of([1-9][0-9]*)$")


def parse_shard(text: str) -> Tuple[int, int]:
    """``'3of8'`` -> ``(3, 8)``. Refuses anything else, and an index past the count."""
    match = _SHARD.fullmatch(text)
    if match is None:
        raise ValueError(f"shard {text!r} is not <index>of<count>, for example 3of8")
    index, count = int(match.group(1)), int(match.group(2))
    if index > count:
        raise ValueError(f"shard {text!r} has an index past its count")
    return index, count


def shard_from_env(
    environ: Mapping[str, str] = os.environ,
) -> Optional[Tuple[int, int]]:
    """The shard this run is, or None for the whole suite. Raises ValueError if malformed."""
    text = environ.get(ENV_VAR)
    return None if not text else parse_shard(text)


def owner(relative_posix_path: str, count: int) -> int:
    """The 1-based shard, of ``count``, that owns a module."""
    return zlib.crc32(relative_posix_path.encode("utf-8")) % count + 1


def matches_python_files(path: Path, patterns: Sequence[str]) -> bool:
    """Whether pytest would take this file as a test module under its ``python_files``."""
    posix = path.as_posix()
    for pattern in patterns:
        if "/" in pattern:
            if fnmatch.fnmatch(posix, pattern) or fnmatch.fnmatch(
                posix, "*/" + pattern
            ):
                return True
        elif fnmatch.fnmatch(path.name, pattern):
            return True
    return False


def ignored_by_shard(
    path: Path, rootpath: Path, patterns: Sequence[str], shard: Tuple[int, int]
) -> bool:
    """Whether ``path`` is a test module that a different shard owns."""
    if not matches_python_files(path, patterns):
        return False
    try:
        relative = path.resolve().relative_to(rootpath.resolve())
    except ValueError:
        return False
    index, count = shard
    return owner(relative.as_posix(), count) != index


#: The parsed shard of this run, ``(index, count)``, or None for the whole suite.
_SHARD_KEY = pytest.StashKey[Optional[Tuple[int, int]]]()
#: The setting's text, kept so the controller can hand it to its xdist workers.
_TEXT_KEY = pytest.StashKey[str]()
#: The ``workerinput`` key the controller hands the text to a worker under.
WORKERINPUT_KEY = "ash_test_shard"


def configure(config: pytest.Config) -> None:
    """Take the shard setting for this run, once, and keep it out of the environment.

    The controller (or a plain run) reads ASH_TEST_SHARD and REMOVES it from
    ``os.environ``, so no process a test starts inherits it: a child pytest that loaded
    tests/conftest.py and collected a directory would otherwise drop the modules other
    shards own, and pass or fail by which shard it ran in. An xdist worker is started
    after this, from an environment without the variable, and is handed the setting
    through ``workerinput`` by :func:`pytest_configure_node`. Calling it twice is
    harmless, so a run that registers the module both ways reads the variable once.

    Raises ``pytest.UsageError`` for a value that is not ``<index>of<count>``.
    """
    if _SHARD_KEY in config.stash:
        return
    workerinput = getattr(config, "workerinput", None)
    if workerinput is not None:
        text = workerinput.get(WORKERINPUT_KEY) or ""
    else:
        text = os.environ.pop(ENV_VAR, "")
    try:
        shard = parse_shard(text) if text else None
    except ValueError as error:
        raise pytest.UsageError(f"{ENV_VAR}: {error}") from None
    config.stash[_SHARD_KEY] = shard
    config.stash[_TEXT_KEY] = text


def pytest_configure(config: pytest.Config) -> None:
    """The hook form of :func:`configure`, for a run that loads this module as a plugin.

    tests/conftest.py does not import this name; it calls :func:`configure` from its own
    ``pytest_configure``.
    """
    configure(config)


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node: Any) -> None:
    """Hand the controller's shard setting to an xdist worker. Not called without xdist."""
    node.workerinput[WORKERINPUT_KEY] = node.config.stash.get(_TEXT_KEY, "")


def pytest_ignore_collect(
    collection_path: Path, config: pytest.Config
) -> Optional[bool]:
    """Ignore the test modules another shard owns. None leaves pytest's own decision."""
    shard = config.stash.get(_SHARD_KEY, None)
    if shard is None:
        return None
    patterns = config.getini("python_files")
    if ignored_by_shard(collection_path, config.rootpath, patterns, shard):
        return True
    return None
