"""Regression tests for the output-anchor mechanism and its escape guard.

Both hazards guarded here are destructive rather than merely wrong, which is why
they get tests rather than a comment.

1. `emitters.run_section_emitters` starts with `reset(out)` ->
   `shutil.rmtree(out)`. A backend under the `repository` anchor whose
   OUTPUT_DIR is empty, `.`, absolute, or contains `..` resolves to the
   repository root or above it, so building it deletes the checkout.

2. `orchestrator.check_drift` sandboxes a build into a tempdir and byte-compares
   the result. If it sandboxed only one of the two anchors, the tempdir build of
   a repository-anchored backend would rmtree and rewrite the very tree the
   check is comparing against -- and would then report no drift, having caused
   it. That failure is silent: a green gate that destroyed data.
"""
from __future__ import annotations

import pytest

from transpiler import orchestrator
from transpiler.core import (
    BaseBackend,
    OutputAnchors,
    resolve_output_dir,
    validated_output_dir,
)
from transpiler.registry import BackendRegistry


# ---------------------------------------------------------------------------
# Hazard 1: the escape guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "",            # resolves to the anchor root itself
        "   ",         # ditto, once stripped
        ".",           # ditto; PurePath(".").parts is empty
        "..",          # one level above the anchor
        "../evil",
        "skills/../..",
        "/etc",        # absolute on POSIX
        "C:/Windows",  # absolute on Windows; PurePosixPath would not notice
        "..\\evil",    # backslash is a separator on Windows only
        "\\\\server\\share",  # UNC root
    ],
)
def test_guard_rejects_output_dir_that_escapes_its_anchor(bad):
    """Each of these would make `out` land on or above the anchor root, and the
    build rmtree's `out` before writing."""
    with pytest.raises(ValueError):
        validated_output_dir("hypothetical-backend", bad)


@pytest.mark.parametrize("good", ["skills", "generic-skill", "claude", "a/b/c"])
def test_guard_accepts_a_plain_relative_output_dir(good):
    assert validated_output_dir("hypothetical-backend", good) == good


def test_guard_rejects_a_non_string_output_dir():
    with pytest.raises(ValueError):
        validated_output_dir("hypothetical-backend", None)  # type: ignore[arg-type]


def test_every_registered_backend_passes_the_guard():
    """The guard is only worth having if it actually runs over real backends."""
    for name, cls in BackendRegistry.all().items():
        assert validated_output_dir(name, cls.OUTPUT_DIR) == cls.OUTPUT_DIR


def test_registration_rejects_an_escaping_output_dir():
    """Fail at import, not mid-build after other backends already wrote output."""

    class Escaping(BaseBackend):
        NAME = "test-escaping-backend"
        OUTPUT_DIR = "../.."
        OUTPUT_ANCHOR = "repository"

    with pytest.raises(ValueError, match="escapes its anchor"):
        BackendRegistry.register(Escaping)

    assert "test-escaping-backend" not in BackendRegistry.all(), (
        "a backend that failed the guard must not end up in the registry"
    )


# ---------------------------------------------------------------------------
# Anchor selection
# ---------------------------------------------------------------------------


def test_resolve_output_dir_honors_the_declared_anchor(tmp_path):
    anchors = OutputAnchors(plugins=tmp_path / "plugins", repository=tmp_path / "repo")

    class PluginsAnchored(BaseBackend):
        NAME = "test-plugins-anchored"
        OUTPUT_DIR = "somewhere"

    class RepoAnchored(BaseBackend):
        NAME = "test-repo-anchored"
        OUTPUT_DIR = "somewhere"
        OUTPUT_ANCHOR = "repository"

    assert resolve_output_dir(PluginsAnchored, anchors) == tmp_path / "plugins" / "somewhere"
    assert resolve_output_dir(RepoAnchored, anchors) == tmp_path / "repo" / "somewhere"


def test_default_anchors_are_two_distinct_real_roots():
    anchors = orchestrator.default_anchors()
    assert anchors.plugins.name == "plugins"
    assert (anchors.repository / ".git").exists(), (
        "the repository anchor must be a real checkout, discovered by walking up "
        "for .git rather than by a hardcoded hop count"
    )
    assert anchors.repository != anchors.plugins


def test_repository_root_discovery_raises_rather_than_guessing(tmp_path):
    """A plausible-looking fallback here is the dangerous outcome, because the
    resolved directory gets rmtree'd."""
    with pytest.raises(RuntimeError, match="no .git found"):
        orchestrator.find_repository_root(tmp_path)


def test_sandbox_replaces_both_anchors_with_distinct_subdirs(tmp_path):
    sandboxed = OutputAnchors.sandbox(tmp_path)
    assert tmp_path in sandboxed.plugins.parents
    assert tmp_path in sandboxed.repository.parents
    assert sandboxed.plugins != sandboxed.repository, (
        "distinct so two backends on different anchors cannot collide in a sandbox"
    )


# ---------------------------------------------------------------------------
# Hazard 2: check_drift must sandbox BOTH anchors
# ---------------------------------------------------------------------------


def test_check_drift_hands_every_build_a_fully_sandboxed_anchor_pair(tmp_path, monkeypatch):
    """Both fields must point inside a throwaway directory -- not just `plugins`."""
    real_anchors = OutputAnchors(plugins=tmp_path / "plugins", repository=tmp_path / "repo")
    real_anchors.plugins.mkdir(parents=True)
    real_anchors.repository.mkdir(parents=True)

    handed: list[OutputAnchors] = []

    def spy(backend_name: str, anchors: OutputAnchors | None = None) -> None:
        handed.append(anchors)

    monkeypatch.setattr(orchestrator, "build_one", spy)
    orchestrator.check_drift(anchors=real_anchors)

    assert handed, "check_drift built nothing; the assertion below would be vacuous"
    for anchors in handed:
        assert anchors is not None
        for field_name in ("plugins", "repository"):
            got = getattr(anchors, field_name)
            assert got != getattr(real_anchors, field_name), (
                f"check_drift passed the real {field_name} anchor to a sandboxed "
                f"build; that build would rmtree and rewrite {got}"
            )
            assert tmp_path not in got.parents, (
                f"check_drift put the sandboxed {field_name} anchor at {got}, "
                f"inside {tmp_path} -- the tree holding the real anchors. The "
                "sandbox must be an independent throwaway directory: a build "
                "rmtree's its output first, so a sandbox carved out of the "
                "caller's tree destroys the very tree the check compares "
                "against. Note that tmp_path is the real-anchor tree here and "
                "not the sandbox root, so containment is the failure, not the "
                "passing condition."
            )


def test_check_drift_does_not_rewrite_the_tree_it_is_comparing(tmp_path):
    """The behavioral form of the same hazard, and the one that fails loudly.

    Plant deliberately-wrong content at the repository-anchored backend's output
    path. A correct drift check reports drift and leaves the file alone. A check
    whose tempdir build escaped into the real repository anchor would delete the
    planted file, write generated content in its place, and then compare that
    freshly-written tree against itself -- reporting success.
    """
    anchors = OutputAnchors(plugins=tmp_path / "plugins", repository=tmp_path / "repo")
    anchors.plugins.mkdir(parents=True)

    planted = anchors.repository / "skills" / "ash-mcp" / "SKILL.md"
    planted.parent.mkdir(parents=True)
    planted.write_text("SENTINEL — deliberately not what the transpiler generates\n")

    result = orchestrator.check_drift(anchors=anchors)

    assert planted.exists(), "check_drift deleted the tree it was asked to compare"
    assert planted.read_text().startswith("SENTINEL"), (
        "check_drift overwrote the tree it was asked to compare; its sandboxed "
        "build escaped into the repository anchor"
    )
    assert result == 1, (
        "planted content differs from generated output, so drift must be reported; "
        "a pass here means the check compared a tree against itself"
    )
