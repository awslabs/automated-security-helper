"""The volume layout, and the guard that proves it is not the broken one.

``ashx scan`` tests source/output collision by **equality only**. ``ashx merge``
tests equality **or ancestry**, and its own docstring states the asymmetry:
"Equal-to OR an ancestor-of, where ``ashx scan`` checks only equality.
``--output-dir ..`` from a subdirectory reaches the same state without the paths
ever being equal, and an ancestor is worse than equality rather than milder."

The consequence is not untidiness. ``apply_suppressions_to_sarif`` excludes
findings whose location resolves inside ``output_dir`` and outside its work
directory; when ``output_dir`` is an *ancestor* of ``source_dir`` that describes
every finding in the tree. Measured on the merge side before relocation was
added: three shards carrying five findings merged to ``Findings: 0 | Actionable:
0`` at exit 0. A green scan of a repository with findings in it.

So the operator owns the paths (see :mod:`ash_operator.constants`) and this module
asserts the invariant on every Job it builds. The assertion is not decoration: it
is the only thing standing between a future patch that makes the paths
configurable and a silently clean scan.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from ash_operator.constants import (
    CONFIG_MOUNT,
    OUTPUT_MOUNT,
    RESULTS_MOUNT,
    SOURCE_MOUNT,
)


class VolumeLayoutError(ValueError):
    """A layout was requested whose scan would report zero findings."""


def _norm(path: str) -> PurePosixPath:
    if not path.startswith("/"):
        raise VolumeLayoutError(
            f"{path!r} must be absolute. A relative mount path resolves against the "
            f"container's working directory, which no manifest here pins."
        )
    return PurePosixPath(path)


def is_ancestor_or_equal(candidate: str, other: str) -> bool:
    """True when *candidate* is ``other`` or contains it.

    Uses pure-lexical POSIX semantics rather than ``Path.resolve()``. Resolution
    would consult the controller's own filesystem, where none of these paths
    exist, and would silently answer about the wrong tree. It also follows
    symlinks, which is not what "is an ancestor of this mount path" means.
    """
    c, o = _norm(candidate), _norm(other)
    return c == o or c in o.parents


def assert_output_escapes_source(*, source_dir: str, output_dir: str) -> None:
    """Refuse a layout where the output directory swallows the scanned tree."""
    if is_ancestor_or_equal(output_dir, source_dir):
        raise VolumeLayoutError(
            f"outputDir {output_dir!r} is equal to, or an ancestor of, sourceDir "
            f"{source_dir!r}. `ashx scan` only checks equality, so this layout is "
            f"accepted by the scan and then reports zero findings, because every "
            f"finding's location resolves inside the output directory and is "
            f"suppressed. Use sibling paths."
        )
    if is_ancestor_or_equal(source_dir, output_dir):
        raise VolumeLayoutError(
            f"outputDir {output_dir!r} is inside sourceDir {source_dir!r}. The scan "
            f"would write its own results into the tree it is scanning, and the "
            f"next scan would report findings in the previous scan's reports. It "
            f"also requires a writable source volume, which a scanner should not "
            f"need."
        )


def assert_layout_is_sane() -> None:
    """Check every pair of the operator's own mount points.

    Called from the Job builders. Checking all four pairs rather than just
    source/output costs nothing and catches the case where someone moves the
    results volume under the source mount to "share a PVC".
    """
    mounts = {
        "sourceDir": SOURCE_MOUNT,
        "outputDir": OUTPUT_MOUNT,
        "configDir": CONFIG_MOUNT,
        "resultsDir": RESULTS_MOUNT,
    }
    assert_output_escapes_source(source_dir=SOURCE_MOUNT, output_dir=OUTPUT_MOUNT)
    names = sorted(mounts)
    for i, left in enumerate(names):
        for right in names[i + 1 :]:
            if is_ancestor_or_equal(mounts[left], mounts[right]) or is_ancestor_or_equal(
                mounts[right], mounts[left]
            ):
                raise VolumeLayoutError(
                    f"{left} ({mounts[left]}) and {right} ({mounts[right]}) are not "
                    f"siblings. Every mount the scan touches has to be independent; "
                    f"nesting two of them reintroduces the ancestry hazard this "
                    f"layout exists to avoid."
                )
