"""Regression tests for the MCPB release phase -- what it stages for publication.

The `.mcpb` is the one backend output that leaves this repository as a binary. It
is committed, and `ash-tag-on-merge.yml` uploads it to a GitHub Release, so the
bytes a user installs into Claude Desktop are the committed bytes rather than
something built from source at install time. That makes two questions worth
asserting, and they are not the same question.

1. DOES THE RELEASE PHASE PRODUCE ANYTHING AT ALL? `phase_copy_archive` returns
   early when `ctx.dist_dir is None`, which is the correct behavior for a build
   and indistinguishable from a no-op release. A release that stages nothing
   would publish a wheel and an sdist and silently drop the bundle, which is
   precisely the state this branch found the backend in: the phase existed and
   nothing invoked it.

2. ARE THE STAGED BYTES THE ONES _base/ GENERATES? This is the arm that can
   actually answer wrongly, and the reason it is written as one end-to-end
   comparison rather than two convenient ones. `phase_copy_archive` COPIES the
   committed archive; it does not rebuild it. So "staged == committed" only
   proves `shutil.copy2` works -- it passes just as happily on a committed
   archive that went stale six releases ago, because the staged copy inherits
   whatever is committed. The assertion that has content compares the staged file
   against a freshly generated one, spanning the whole chain: _base/ generates,
   the tree commits, the release phase stages, the workflow uploads.

WHY THIS IS NOT A SECOND COPY OF THE DRIFT CHECK. `orchestrator.check_drift`
already byte-compares `ash.mcpb`, because `_files_in` rglob's the backend's whole
output directory and `emit_mcpb_bundle` writes the archive during the build stage.
Measured, not assumed: mutating one byte of the committed archive makes
`agentic-plugins check` exit 1 reporting `~ ash.mcpb`. What that check says
nothing about is `dist/` -- it compares a committed tree against a generated tree
and never runs the release phase. The composition is what is untested without
this file, and the composition is what publishes.

The member-count assertion is deliberately duplicated here and in
ash-tag-on-merge.yml, and neither copy should be deleted as redundant: they fire
at different times. The workflow asserts it on the exact bytes about to be
uploaded, which is the last possible moment; this asserts it on every pull request
through the transpiler suite, which is early enough to be cheap to fix.
"""
from __future__ import annotations

import zipfile

from transpiler import orchestrator
from transpiler.backends.mcpb import MCPBBackend
from transpiler.core import OutputAnchors, resolve_output_dir


def _staged_archives(dist_dir):
    """The `.mcpb` files the release phase wrote, sorted."""
    return sorted(dist_dir.glob("*.mcpb"))


def test_release_phase_stages_exactly_one_mcpb_into_dist(tmp_path):
    """Anti-vacuity for everything below: with no staged file, the byte
    comparisons in the other tests would have nothing to compare and would need
    to either skip or invent a subject."""
    orchestrator.release_one("mcpb", tmp_path)

    staged = _staged_archives(tmp_path)
    assert len(staged) == 1, (
        f"expected exactly one .mcpb staged in {tmp_path}, found "
        f"{[p.name for p in staged]}. `phase_copy_archive` returns early when "
        "dist_dir is None, so a release that stages nothing looks identical to a "
        "release that was never wired up -- which is the state this backend was "
        "in until ash-tag-on-merge.yml started invoking it."
    )
    assert staged[0].stat().st_size > 0, "staged an empty archive"


def test_staged_bytes_are_the_committed_bytes(tmp_path):
    """The publish contract: what gets uploaded is the artifact under version
    control, not a copy rebuilt at release time.

    On its own this proves only that the copy happened. It is asserted anyway
    because the alternative is a release phase that regenerates into dist/, and
    that would publish bytes no drift check ever saw.
    """
    orchestrator.release_one("mcpb", tmp_path)
    staged = _staged_archives(tmp_path)[0]

    committed = (
        resolve_output_dir(MCPBBackend, orchestrator.default_anchors())
        / MCPBBackend.MCPB_BUNDLE.archive_path
    )
    assert committed.exists(), f"{committed} is missing from the checkout"
    assert staged.read_bytes() == committed.read_bytes(), (
        f"{staged.name} differs from the committed {committed.name}. The release "
        "phase is meant to copy the committed archive, so a difference here means "
        "it started producing the artifact some other way and the published bytes "
        "are no longer the reviewed ones."
    )


def test_staged_bytes_are_what_base_generates_today(tmp_path):
    """The arm with content, and the one that reddens on a stale committed archive.

    Builds the backend into a throwaway sandbox through the real emitter rather
    than re-deriving the manifest here, so the expected bytes cannot drift from
    `emit_mcpb_bundle` the way a second implementation would. Both anchors are
    sandboxed, for the reason spelled out in test_output_anchors.py: a build
    rmtree's its output directory first, so a half-sandboxed build would delete
    the committed tree this comparison depends on.
    """
    sandbox = OutputAnchors.sandbox(tmp_path / "sandbox")
    orchestrator.build_one("mcpb", anchors=sandbox)
    generated = (
        resolve_output_dir(MCPBBackend, sandbox) / MCPBBackend.MCPB_BUNDLE.archive_path
    )
    assert generated.exists(), (
        f"the sandboxed build wrote no {MCPBBackend.MCPB_BUNDLE.archive_path}; "
        "the comparison below would be vacuous"
    )

    dist = tmp_path / "dist"
    orchestrator.release_one("mcpb", dist)
    staged = _staged_archives(dist)[0]

    assert staged.read_bytes() == generated.read_bytes(), (
        f"{staged.name} is not what _base/ generates today. Because the release "
        "phase copies the committed archive rather than rebuilding it, this is how "
        "a stale commit reaches a published release: the copy succeeds, the file "
        "is attached, and nothing else in the release path compares it to its "
        "source. Run `agentic-plugins build mcpb` and commit the result."
    )


def test_staged_archive_carries_only_the_ash_authored_manifest(tmp_path):
    """The publishing boundary, as arithmetic rather than as a judgment call.

    packaging/README.md: ASH's own code may ship in a published artifact,
    third-party code never may. This archive is on the permitted side because its
    only member is a manifest ASH authors -- the server itself is fetched at run
    time by the user's own uvx from the pinned ref in mcp_config. Counting members
    is the same check the .deb and .rpm get by counting bundled wheels.

    Also asserted in ash-tag-on-merge.yml on the bytes about to be uploaded. Two
    copies on purpose; see this module's docstring.
    """
    orchestrator.release_one("mcpb", tmp_path)
    staged = _staged_archives(tmp_path)[0]

    with zipfile.ZipFile(staged) as archive:
        members = [i.filename for i in archive.infolist() if not i.is_dir()]

    assert members == ["manifest.json"], (
        f"{staged.name} carries {len(members)} member(s): {members}. A published "
        "MCPB bundle must carry exactly one, manifest.json. Anything else is a "
        "file ASH did not author riding along inside an artifact ASH publishes."
    )
