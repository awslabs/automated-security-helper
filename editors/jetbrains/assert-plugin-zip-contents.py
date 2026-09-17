#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fails if the built plugin distribution carries any jar but this project's own.

WHY THIS EXISTS

packaging/README.md draws the line this check enforces: ASH's own code may ship in a
published artifact, third-party code never may. A JetBrains plugin is on the wrong side of
that line by default. `buildPlugin` copies the RUNTIME classpath into the distribution's
lib/ directory, so a single `implementation` dependency puts someone else's jar inside a zip
this project publishes as a release asset, and it does so with no warning at all.

WHY THE RULE IS A COUNT AND NOT A JUDGMENT

The same reasoning packaging/README.md gives for "exactly one bundled wheel". A rule phrased
as "no third-party jars" needs a decision per dependency, made by whoever reviewed the build
file that day, and re-made every time the dependency graph changes. A rule phrased as "every
jar in lib/ is named ash-jetbrains*" is a list comparison anyone can run and nobody can be
mistaken about.

There is a second half the deb and rpm do not need, and it is the same shape as the extra
check packaging/flatpak/build.sh carries. The .deb and .rpm can only gain third-party code by
gaining a .whl file, so counting wheels is enough. A plugin distribution could instead gain
UNPACKED third-party classes -- a fat jar, a shadow/shade step, or a `from(configurations...)`
in the jar task -- which leaves no extra jar at all. So this also refuses class files loose in
the zip, and refuses a jar whose own contents reach outside this plugin's package.

WHAT IS DELIBERATELY NOT CHECKED

Anything on the build classpath. The IntelliJ Platform Gradle plugin, Gradle itself, JaCoCo,
JUnit and the ~1 GB IDE it resolves are all build-time only and none of them ships. What
ships is this zip, which is why the check reads the zip rather than a dependency report.

USAGE

  python3 assert-plugin-zip-contents.py --dist-dir build/distributions \
      --own-jar-prefix ash-jetbrains

Exit codes: 0 pass, 1 the distribution carries something it must not, 2 there was nothing to
check, which is a failure and not a skip.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import zipfile

# The package every class in this plugin lives under. A class outside it inside the plugin's
# own jar means something was shaded or shadowed in.
OWN_PACKAGE_PREFIX = "io/github/awslabs/ash/jetbrains/"

# Files a plugin distribution legitimately carries besides its own jar. Kept explicit, so a
# new kind of member has to be looked at rather than tolerated by a loose pattern.
ALLOWED_SUFFIXES = (".jar",)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", required=True)
    parser.add_argument("--own-jar-prefix", required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv[1:])
    here = pathlib.Path(__file__).resolve().parent
    dist_dir = (here / args.dist_dir).resolve()

    zips = sorted(dist_dir.glob("*.zip")) if dist_dir.is_dir() else []
    if not zips:
        # A missing distribution is a failure. A check that passes because it found nothing to
        # open is indistinguishable from a check that opened a clean artifact, which is the
        # failure mode this repository has hit repeatedly.
        sys.stderr.write(
            f"no plugin distribution zip under {dist_dir}.\n"
            "buildPlugin either did not run or wrote somewhere else. That is a failure and not\n"
            "a skip: nothing was inspected, so nothing can be concluded.\n"
        )
        return 2
    if len(zips) > 1:
        sys.stderr.write(
            f"expected exactly one distribution zip under {dist_dir}, found "
            f"{[p.name for p in zips]}. A stale zip from a previous version would be checked "
            "alongside the current one and could pass on the strength of the wrong file.\n"
        )
        return 1

    distribution = zips[0]
    problems: list[str] = []
    jars: list[str] = []

    with zipfile.ZipFile(distribution) as archive:
        members = [name for name in archive.namelist() if not name.endswith("/")]
        if not members:
            sys.stderr.write(f"{distribution.name} is empty\n")
            return 2

        for name in members:
            if name.endswith(".jar"):
                jars.append(name)
                continue
            if name.endswith(".class"):
                # A fat jar or a shade step would land here rather than as an extra jar, so
                # counting jars alone would miss it. This is the analogue of the .dist-info
                # check packaging/flatpak/build.sh carries for the same reason.
                problems.append(f"{name} is a loose class file in the distribution")
                continue
            if not any(name.endswith(suffix) for suffix in ALLOWED_SUFFIXES):
                problems.append(
                    f"{name} is not a jar and not on the allowed list. If it belongs, add its "
                    "suffix to ALLOWED_SUFFIXES with the reason."
                )

        for name in jars:
            base = pathlib.PurePosixPath(name).name
            if not base.startswith(args.own_jar_prefix):
                problems.append(
                    f"{name} is a jar this project did not build. A plugin distribution bundles "
                    "its runtime classpath into lib/, so this is third-party code inside an "
                    "artifact published as a release asset. See packaging/README.md."
                )
                continue
            problems.extend(check_own_jar(archive, name))

    print(f"plugin distribution: {distribution.name}")
    print(f"  members: {len(members)}")
    for name in sorted(members):
        print(f"    {name}")

    if problems:
        sys.stderr.write("Plugin distribution contents check failed:\n")
        for problem in problems:
            sys.stderr.write(f"  - {problem}\n")
        return 1

    print(f"  OK: {len(jars)} jar(s), all built by this project, no loose classes")
    return 0


def check_own_jar(archive: zipfile.ZipFile, name: str) -> list[str]:
    """Refuses a jar of ours that has had someone else's classes folded into it."""
    problems: list[str] = []
    import io

    with archive.open(name) as stream:
        payload = io.BytesIO(stream.read())
    with zipfile.ZipFile(payload) as inner:
        for entry in inner.namelist():
            if not entry.endswith(".class"):
                continue
            if entry.startswith(OWN_PACKAGE_PREFIX):
                continue
            problems.append(
                f"{name} contains {entry}, which is outside {OWN_PACKAGE_PREFIX}. A shade or "
                "shadow step folds third-party classes into our own jar, which leaves the jar "
                "count at one and the boundary crossed anyway."
            )
    return problems


if __name__ == "__main__":
    sys.exit(main(sys.argv))
