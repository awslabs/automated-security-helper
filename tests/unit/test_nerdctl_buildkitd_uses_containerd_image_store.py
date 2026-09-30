# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scripts/setup-nerdctl-linux.sh`` must give buildkitd a containerd image store.

Why this file exists
--------------------
A buildkitd started with no config file uses the OCI/runc worker, which upstream constructs
with ``ImageStore: nil, // explicitly`` (``worker/runc/runc.go``). With no image store,
``nerdctl build`` cannot resolve ``FROM`` against *any* image in containerd's store -- so a base
image that ``nerdctl pull`` already fetched is invisible to the build, and BuildKit goes back to
the registry for it. That is what made ``.github/actions/prepull-base-image`` inert on the
nerdctl leg: the pre-pull exited 0 having placed the image locally, and the build then died at
``FROM ${BASE_IMAGE}`` asking the registry that had just rate-limited it.

Why no-config buildkitd picks the worker that cannot help: ``--oci-worker`` and
``--containerd-worker`` both default to the string ``"auto"`` and resolve *independently* --
there is no rule that enabling one disables the other, and ``newWorkerController`` adds every
worker that initialises. The OCI worker registers at priority 0 against the containerd worker's
1, the list is sorted by priority, buildkit's own comment on ``workercontroller.Add`` reads "The
first worker becomes the default", and ``GetDefault`` returns index 0. buildkitd then logs
``currently, only the default worker can be used.`` ``validOCIBinary()`` is just
``exec.LookPath("runc")``, and the nerdctl-full tarball unpacks a static runc into
/usr/local/bin, so the OCI worker always initialises and always wins.

The fix is a ``buildkitd.toml`` disabling the OCI worker, and it is not invented here: nerdctl's
own ``Dockerfile.d/etc_buildkit_buildkitd.toml`` does exactly this (but is only copied into
nerdctl's test image, downstream of the ``out-full`` stage, so it never reaches the tarball), and
finch ships ``/etc/finch/buildkit/buildkitd.toml`` with the identical three settings differing
only in the namespace. Rancher Desktop -- the documented nerdctl support target -- passes
``--oci-worker=false --containerd-worker=true`` as flags instead.

What these tests protect, and why they parse rather than grep
-------------------------------------------------------------
The script needs root and systemd, so it cannot be executed here; these are text and ordering
assertions, in the same idiom as this repository's PowerShell assertions.

They assert over the **extracted heredoc**, not over the file as a whole, and that distinction
is not stylistic -- it is a bug this file already had. The first version asserted
``"/etc/buildkit/buildkitd.toml" in body`` and ``body.index(...)`` for ordering. Both passed
against a deliberately broken script in which the config was written *after* the unit started,
because the path and the setting names also appear in the script's own explanatory comments, and
``str.index`` returns the first match -- which was a comment tens of lines above the code. The
test was measuring prose. Parsing the heredoc out and locating the ``cat >`` redirect is what
makes these assertions observe the script's behaviour instead of its documentation. Every
assertion below was re-checked against that same broken script and does now fail.

The two failures this catches are the two that would otherwise be silent:

1. **Ordering.** buildkitd reads its config exactly once, at startup. A config written *after*
   the unit is up changes nothing, and the leg would look fixed while being unchanged.
2. **``restart`` rather than ``start``.** ``systemctl start`` on an already-active unit is a
   no-op that exits 0, so on a re-run the old no-config daemon survives and keeps the OCI
   worker.

Both produce a green setup step and a build that still reaches the registry -- the exact shape of
the bug being fixed -- so neither would be caught by anything downstream. The script's own
``buildctl debug workers`` assertion is the runtime control for the same property; these tests
are what keep that assertion present and correctly ordered.
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SETUP = REPO_ROOT / "scripts" / "setup-nerdctl-linux.sh"

# buildkitd's default config path. Writing here is what lets the bundle's flagless
# ExecStart pick the file up with no unit edit.
DEFAULT_CONFIG_PATH = "/etc/buildkit/buildkitd.toml"

# The write itself, as opposed to any mention of the path. This is the anchor every
# positional assertion uses.
WRITE_COMMAND = f"cat > {DEFAULT_CONFIG_PATH} <<"

BUILDKIT_START = "systemctl restart buildkit"


@pytest.fixture(scope="module")
def body() -> str:
    return SETUP.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def toml(body: str) -> str:
    """The contents of the buildkitd.toml the script writes, and nothing else.

    Extracted rather than grepped for, so that a setting named only in a comment cannot satisfy
    an assertion about the file's contents.
    """
    match = re.search(
        r"cat > /etc/buildkit/buildkitd\.toml <<'EOF'\n(.*?)\nEOF\n",
        body,
        re.DOTALL,
    )
    assert match is not None, (
        "no `cat > /etc/buildkit/buildkitd.toml <<'EOF' ... EOF` block found in "
        "scripts/setup-nerdctl-linux.sh. Every assertion in this file is about the contents of "
        "that heredoc, so they would all pass vacuously if it were merely renamed -- this is "
        "the guard against that."
    )
    return match.group(1)


class TestTheConfigIsActuallyWritten:
    def test_the_write_targets_buildkitds_default_config_path(self, body: str):
        """A non-default path would need a ``--config`` flag and a matching unit edit.

        finch needs that flag precisely because its path is non-default. Writing to the default
        path is what lets the bundle's sed-derived, flagless ``ExecStart`` read the file with no
        unit change at all.
        """
        assert WRITE_COMMAND in body, (
            f"the script must write {DEFAULT_CONFIG_PATH} with a heredoc redirect. Asserted on "
            "the redirect rather than on the path alone because the path also appears in the "
            "script's comments, and an assertion a comment can satisfy is not an assertion."
        )

    def test_the_directory_is_created_before_the_write(self, body: str):
        """/etc/buildkit does not exist on a runner that has never had buildkit configured."""
        assert body.index("mkdir -p /etc/buildkit") < body.index(WRITE_COMMAND), (
            "mkdir -p /etc/buildkit must precede the redirect, or the write fails with ENOENT "
            "on any runner where the directory does not already exist"
        )


class TestTheConfigContents:
    """Asserted against the extracted heredoc only."""

    def test_the_oci_worker_is_disabled(self, toml: str):
        """The first of two conditions, and the one that is easy to leave out.

        Setting a namespace while the OCI worker is still the default changes nothing: that
        worker has no image store for any namespace to select.
        """
        assert "[worker.oci]" in toml, (
            "the config must have a [worker.oci] section; while the OCI worker is the default, "
            "buildkitd is built with ImageStore: nil and no namespace setting can make a "
            "locally-tagged base image visible at FROM"
        )
        oci_section = toml.split("[worker.oci]", 1)[1].split("[worker.", 1)[0]
        assert "enabled = false" in oci_section, (
            "the OCI worker must be disabled inside its own section. Checked per-section "
            "because an `enabled = false` anywhere in the file would otherwise satisfy this "
            "while actually disabling the containerd worker -- the opposite of the fix."
        )

    def test_the_containerd_worker_is_enabled(self, toml: str):
        assert "[worker.containerd]" in toml, (
            "the containerd worker must be explicitly enabled; with the OCI worker off and "
            "nothing else enabled, buildkitd has no worker at all"
        )
        containerd_section = toml.split("[worker.containerd]", 1)[1]
        assert "enabled = true" in containerd_section, (
            "the containerd worker must be enabled inside its own section"
        )

    def test_the_namespace_is_the_one_the_nerdctl_cli_uses(self, toml: str):
        """The second condition. A worker in another namespace reads a real but empty store.

        nerdctl's default namespace is containerd's ``namespaces.Default`` -- the string
        ``default`` (``pkg/config/config.go``) -- and nothing in the nerdctl-full bundle changes
        it. buildkit's containerd worker defaults to ``buildkit`` instead
        (``defaultContainerdNamespace``), which would read a store holding none of the images
        the pre-pull placed. That looks identical to having no store at all.
        """
        containerd_section = toml.split("[worker.containerd]", 1)[1]
        assert 'namespace = "default"' in containerd_section, (
            'the containerd worker\'s namespace must be "default" to match the nerdctl CLI. '
            'Without it buildkitd uses its own default of "buildkit" and reads a different '
            "store than the one nerdctl pulls and tags into."
        )


class TestTheOrderingThatMakesItTakeEffect:
    """buildkitd reads its config once, at startup. Ordering is the whole fix."""

    def test_the_config_is_written_before_the_unit_is_started(self, body: str):
        assert body.index(WRITE_COMMAND) < body.index(BUILDKIT_START), (
            "the buildkitd config must be written BEFORE the unit starts. buildkitd reads its "
            "config exactly once at startup, so writing it afterwards leaves the running daemon "
            "on the OCI worker -- the setup step still exits 0, and the only symptom is a build "
            "that reaches the registry anyway. Anchored on the `cat >` redirect rather than on "
            "a mention of the path, because the earlier version of this assertion was satisfied "
            "by a comment and passed against a script with exactly this defect."
        )

    def test_buildkit_is_restarted_rather_than_started(self, body: str):
        """``start`` on an active unit is a no-op that exits 0.

        On a re-run, or on any host where something already started buildkit, ``start`` would
        leave the previous no-config daemon in place and the config above would be inert.
        """
        assert BUILDKIT_START in body, (
            "buildkit must be restarted, not merely started: `systemctl start` on an "
            "already-active unit succeeds without re-reading the config file"
        )
        assert "systemctl start buildkit" not in body, (
            "a bare `systemctl start buildkit` remains in the script; on an already-running "
            "daemon it exits 0 without picking up the config written above"
        )


class TestTheRuntimeControl:
    """The script must observe the worker it got, not assume the config applied."""

    def test_the_worker_labels_are_captured_rather_than_discarded(self, body: str):
        """This probe used to send its output to /dev/null, which is why the worker this leg ran
        was never observed -- the answer was one redirect away the whole time."""
        assert "buildctl debug workers" in body, (
            "the script must probe buildkitd's workers; that is what names the default worker's "
            "executor and its containerd namespace"
        )
        assert "buildctl debug workers >/dev/null" not in body, (
            "the worker probe's output must not be discarded -- it is the only evidence of "
            "which worker the leg actually ran, and it is the control for the config above"
        )

    def test_a_worker_that_is_not_containerd_fails_the_setup(self, body: str):
        """Without this, the fix can silently not apply.

        The build would still SUCCEED with the OCI worker, because ASH_BASE_IMAGE_OVERRIDE
        redirects ``FROM`` at whichever registry answered regardless of any worker setting. So
        nothing downstream would notice that the local-store half had gone inert. That is why
        this needs its own assertion rather than being left to the build to reveal.
        """
        assert 'worker.executor":"containerd"' in body, (
            "the script must assert the default worker's executor label is containerd; reading "
            "oci there means the config did not take effect"
        )
        assert 'worker.containerd.namespace":"default"' in body, (
            "the script must also assert the worker's namespace matches nerdctl's -- the "
            "containerd worker being default only helps if it reads the store nerdctl writes to"
        )
        assert "exit 1" in body.split("buildctl debug workers", 1)[1], (
            "a non-containerd worker must FAIL the setup rather than print a warning; a warning "
            "here is indistinguishable from the bug, since the build succeeds either way"
        )
