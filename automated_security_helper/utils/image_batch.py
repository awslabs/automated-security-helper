# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Several images from one command: N subject scans, never one merged scan.

A scan has one subject, and each image keeps its own report, its own identity
scope (``image_ref``, ``image_digest``) and its own exit code. ``ash scan
--image A --image B`` (or ``--image A,B``) is the caller's loop moved inside the
command: it runs the one-subject scan once per image, each into its own report
directory, and exits with the worst of the per-image codes. Nothing is merged,
so no finding of one image can be attributed to another.

The order of codes, worst first, is the order a CI gate would want to read them in:

- ``5`` a usage error and ``3`` a configuration or output-directory refusal: no
  verdict was reached for the image, and the cause does not depend on which
  image it was, so the batch STOPS at the first one (running the rest would
  repeat the refusal N times) and exits with that code;
- ``4`` a workspace error (never reached by an image scan, ranked for completeness);
- ``1`` an incomplete scan or any other error: the image's verdict cannot be
  trusted, which outranks a verdict of findings;
- ``2`` actionable findings;
- ``0`` clean.

Any code outside the table is ranked with ``1`` (an error). An interrupt
(Ctrl-C, SIGTERM) is not a code here: it propagates out of the loop at once, as
it does for a single scan.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from automated_security_helper.utils.image_reference import image_reference_problem

#: Codes that end the batch: the same refusal would repeat for every image.
STOPS_THE_BATCH = frozenset({3, 5})

#: Worst first; a code not named here ranks with 1.
_WORST_FIRST = (5, 3, 4, 1, 2, 0)

#: The characters of an image reference kept in its report directory's name.
_SLUG_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")

#: The longest readable part of a report directory name.
_SLUG_LENGTH = 60


class ImageListRefused(ValueError):
    """The ``--image`` values name no usable list of images."""


def split_image_arguments(values: Optional[Sequence[str]]) -> List[str]:
    """The images named by repeated ``--image`` values, each possibly a comma list.

    ``--image a --image b,c`` is ``[a, b, c]``. An empty piece (``a,,b``, a bare
    comma, an empty value) and an image named twice are refused: the first is a
    typo that would otherwise scan fewer images than the caller listed, the
    second two scans of one subject whose reports would differ in nothing. A
    piece that is not an image reference (``utils/image_reference``: a path, an
    option-shaped word) is refused too, before any image of the list runs: the
    scanner tools would read it as a directory to catalog or as an option.
    """
    images: List[str] = []
    for value in values or []:
        for piece in value.split(","):
            reference = piece.strip()
            if not reference:
                raise ImageListRefused(
                    "--image names an empty image reference (a stray comma or an "
                    "empty value). Name each image once, as --image a --image b "
                    "or --image a,b."
                )
            problem = image_reference_problem(reference)
            if problem is not None:
                raise ImageListRefused(f"--image {reference!r} {problem}.")
            if reference in images:
                raise ImageListRefused(
                    f"--image names {reference} more than once. Each image is "
                    "scanned once, into its own report directory."
                )
            images.append(reference)
    return images


def report_directory(output_dir: Path, reference: str, index: int) -> Path:
    """The report directory of the *index*-th image (1-based) of a batch.

    ``<output_dir>/<NN>-<readable reference>-<8 hex of its digest>``: ordered as
    listed, readable at a glance, and unique even when two references collapse
    to the same readable text.
    """
    readable = _SLUG_UNSAFE.sub("_", reference).strip("._-")[:_SLUG_LENGTH] or "image"
    tag = hashlib.sha256(reference.encode("utf-8")).hexdigest()[:8]
    return Path(output_dir) / f"{index:02d}-{readable}-{tag}"


def exit_code_of(error: BaseException) -> int:
    """The exit code a ``SystemExit`` or ``click``/``typer`` ``Exit`` carries."""
    code = getattr(error, "exit_code", None)
    if code is None:
        code = getattr(error, "code", None)
    if code is None:
        return 0
    if isinstance(code, int):
        return code
    # A message as the code (sys.exit("text")) is the interpreter's exit 1.
    return 1


def aggregate_exit_code(codes: Sequence[int]) -> int:
    """The worst of *codes*, in this module's order; 0 for none."""
    if not codes:
        return 0

    def rank(code: int) -> int:
        try:
            return _WORST_FIRST.index(code)
        except ValueError:
            return _WORST_FIRST.index(1)

    return min(codes, key=rank)


def run_image_batch(
    images: Sequence[str],
    output_dir: Path,
    run_one: Callable[[str, Path], None],
    *,
    say: Callable[[str], None],
) -> Tuple[int, Dict[str, int]]:
    """Scan each of *images* with *run_one* and return ``(aggregate, per image)``.

    *run_one(reference, report_dir)* is the one-subject scan, which ends the way a
    scan ends: by raising ``SystemExit`` (or an ``Exit``) with its code, or by
    returning, which is 0. An interrupt is not caught. A code in
    :data:`STOPS_THE_BATCH` ends the batch there; the images not reached are
    reported as not scanned, never as clean.
    """
    codes: Dict[str, int] = {}
    total = len(images)
    for index, reference in enumerate(images, start=1):
        report_dir = report_directory(output_dir, reference, index)
        say(f"Scanning image {index} of {total}: {reference} (reports in {report_dir})")
        try:
            run_one(reference, report_dir)
            code = 0
        except (SystemExit, Exception) as error:
            if not _is_an_exit(error):
                raise
            code = exit_code_of(error)
        codes[reference] = code
        if code in STOPS_THE_BATCH:
            skipped = list(images[index:])
            if skipped:
                say(
                    f"Exit {code} does not depend on the image, so the remaining "
                    f"{len(skipped)} image(s) were not scanned: " + ", ".join(skipped)
                )
            break
    aggregate = aggregate_exit_code(list(codes.values()))
    say("Image scan results:")
    for reference in images:
        if reference in codes:
            say(f"  {reference}: exit {codes[reference]}")
        else:
            say(f"  {reference}: not scanned")
    say(f"Exit {aggregate}: the worst of the {len(codes)} image(s) scanned.")
    return aggregate, codes


def _is_an_exit(error: BaseException) -> bool:
    """Whether *error* is a command ending (``SystemExit``, ``click.exceptions.Exit``)."""
    if isinstance(error, SystemExit):
        return True
    import click

    return isinstance(error, click.exceptions.Exit)
