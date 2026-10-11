# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The image's cfn-guard rules bundle is root's, and so is every directory above it.

Why this file exists
--------------------
cfn-guard evaluates templates against the rules bundle the image installs as root,
and only root may change what those rules are. That holds only if the bundle and
every directory above it are owned by root and not writable by other users (or, for
a shared directory, sticky), since an entry in a directory others can write can be
renamed or replaced whatever its own mode.

Why a static check
------------------
Building the image needs a working OCI runtime, so the unit suite reads the
Dockerfile as text. The image itself checks the result at build time with
``install-pinned-tool --assert-root-only`` (tested in tests/unit/assets), and these
tests make sure the Dockerfile still runs that check and keeps the bundle out of any
directory it makes writable for everyone.
"""

import re
from pathlib import Path, PurePosixPath

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"

_ENV = re.compile(
    r'^ENV\s+(?P<name>[A-Z_][A-Z0-9_]*)="?(?P<value>[^"\s]+)"?', re.MULTILINE
)
_CHMOD = re.compile(
    r"chmod\s+(?:-R\s+)?(?P<mode>[0-7]{3,4}|[ugoa]*\+\w+)\s+(?P<args>[^;&|\\\n]+)"
)


@pytest.fixture(scope="module")
def dockerfile_text() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def _env(text: str) -> dict:
    return {m.group("name"): m.group("value") for m in _ENV.finditer(text)}


def _expand(value: str, env: dict) -> str:
    return re.sub(
        r"\$\{(\w+)\}|\$(\w+)",
        lambda m: env.get(m.group(1) or m.group(2), m.group(0)),
        value,
    )


def _world_writable_dirs(text: str, env: dict) -> list:
    """Every path the Dockerfile chmods so that others may write it, unsticky."""
    found = []
    for match in _CHMOD.finditer(text):
        mode = match.group("mode")
        if mode.isdigit():
            octal = int(mode, 8)
            if not octal & 0o002 or octal & 0o1000:
                continue
        elif "o" not in mode.split("+")[0] and "a" not in mode.split("+")[0]:
            continue
        elif "w" not in mode.split("+")[1]:
            continue
        for arg in match.group("args").split():
            path = _expand(arg, env)
            if path.startswith("/"):
                found.append(PurePosixPath(path))
    return found


def test_the_rules_bundle_is_not_under_a_world_writable_directory(dockerfile_text):
    env = _env(dockerfile_text)
    rules = PurePosixPath(env["ASH_CFN_GUARD_RULES_DIR"])
    writable = _world_writable_dirs(dockerfile_text, env)
    assert writable, "found no chmod at all; this check no longer reads the file"
    under = [str(d) for d in writable if d == rules or d in rules.parents]
    assert under == [], (
        f"ASH_CFN_GUARD_RULES_DIR={rules} sits in {under}, which the Dockerfile "
        "makes writable by every user without the sticky bit; keep the bundle in a "
        "directory only root can write."
    )


def test_the_image_asserts_the_bundle_is_root_only_after_install_and_at_the_end(
    dockerfile_text,
):
    check = 'install-pinned-tool --assert-root-only "${ASH_CFN_GUARD_RULES_DIR}"'
    install = dockerfile_text.index("--rules-bundle -d ${ASH_CFN_GUARD_RULES_DIR}")
    positions = [m.start() for m in re.finditer(re.escape(check), dockerfile_text)]
    assert any(p > install for p in positions), "no check after the bundle install"
    final_stage = dockerfile_text.rindex("FROM core AS non-root")
    user = dockerfile_text.index("USER ${UID}:${GID}", final_stage)
    assert any(final_stage < p < user for p in positions), (
        "the final stage does not re-check the bundle before switching user"
    )
