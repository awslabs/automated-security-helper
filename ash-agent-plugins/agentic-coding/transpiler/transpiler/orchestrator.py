"""High-level orchestration: iterate registered backends, run setup/build/release/check.

The CLI is a thin Click wrapper around these functions. Direct callers (tests,
embedders) can use the orchestrator API without going through Click.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from . import backends as _backends_pkg  # noqa: F401  triggers registration
from .core import BuildContext, Manifest, OutputAnchors, resolve_output_dir
from .jinja_renderer import render
from .registry import BackendRegistry

HERE = Path(__file__).resolve().parent              # transpiler/transpiler/
TRANSPILER_DIR = HERE.parent                         # transpiler/
BASE_DIR = TRANSPILER_DIR / "_base"
SCHEMAS_DIR = TRANSPILER_DIR / "schemas"
OUTPUT_ROOT = TRANSPILER_DIR.parent / "plugins"      # agentic-coding/plugins/


def find_repository_root(start: Path = TRANSPILER_DIR) -> Path:
    """Walk up from `start` to the first directory containing a `.git` entry.

    The repository root is not a fixed number of hops above the transpiler.
    `ash-agent-plugins/` is designed to be extractable as its own repository —
    it carries its own workflows, pre-commit config, LICENSE and .gitignore —
    so the transpiler sits three levels below the root inside the ASH monorepo
    and two levels below it standalone. A hardcoded `parents[2]` would be
    silently wrong in one of the two layouts, and because a build rmtree's its
    output directory, silently wrong here means deleting the wrong tree.

    Checks `exists()` rather than `is_dir()` because `.git` is a file, not a
    directory, in a linked worktree or a submodule.

    Raises rather than guessing: a caller that reaches here without a
    repository has no correct answer available, and a plausible-looking
    fallback would be the dangerous outcome.
    """
    start = start.resolve()
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError(
        f"no .git found in {start} or any parent; cannot locate the repository "
        f"root. Backends with OUTPUT_ANCHOR = 'repository' need a real checkout "
        f"(a source tarball or an installed wheel is not enough)."
    )


def default_anchors() -> OutputAnchors:
    """The real anchors for this checkout.

    Resolved lazily rather than as module constants so that importing the
    transpiler outside a git checkout still works; only backends that actually
    need the repository root pay for its discovery.
    """
    return OutputAnchors(plugins=OUTPUT_ROOT, repository=find_repository_root())


def _load_manifest() -> Manifest:
    return Manifest.load(BASE_DIR / "manifest.json")


def _references_concatenated() -> str:
    return "\n\n".join(
        ref.read_text()
        for ref in sorted((BASE_DIR / "references").glob("*.md"))
    )


def render_universal_agents_md(out_root: Path) -> None:
    """The repo-root AGENTS.md read natively by 9+ platforms.
    Top-level artifact, not a per-backend output — emitted by the orchestrator."""
    m = _load_manifest()
    rendered = render(
        "shared/AGENTS.md.j2",
        display_name=m.display_name,
        description=m.description,
        skill_body=(BASE_DIR / "skill.md").read_text(),
        references=_references_concatenated(),
    )
    out_root.mkdir(parents=True, exist_ok=True)
    (out_root / "AGENTS.md").write_text(rendered)


def build_one(backend_name: str, anchors: OutputAnchors | None = None) -> None:
    """Build a single backend by name."""
    anchors = anchors or default_anchors()
    m = _load_manifest()
    BackendCls = BackendRegistry.get(backend_name)
    backend = BackendCls()
    backend.build(
        manifest=m,
        out=resolve_output_dir(BackendCls, anchors),
        plugins_root=anchors.plugins,
        base_dir=BASE_DIR,
        schemas_dir=SCHEMAS_DIR,
    )


def build_all(anchors: OutputAnchors | None = None) -> None:
    """Build every registered backend + the universal AGENTS.md."""
    anchors = anchors or default_anchors()
    anchors.plugins.mkdir(parents=True, exist_ok=True)
    render_universal_agents_md(anchors.plugins)
    for name in BackendRegistry.names():
        build_one(name, anchors=anchors)


def release_one(backend_name: str, dist_dir: Path,
                anchors: OutputAnchors | None = None) -> None:
    anchors = anchors or default_anchors()
    m = _load_manifest()
    BackendCls = BackendRegistry.get(backend_name)
    backend = BackendCls()
    ctx = BuildContext(
        manifest=m,
        out=resolve_output_dir(BackendCls, anchors),
        plugins_root=anchors.plugins,
        base_dir=BASE_DIR,
        schemas_dir=SCHEMAS_DIR,
        dist_dir=dist_dir,
    )
    backend.release(ctx)


def release_all(dist_dir: Path, anchors: OutputAnchors | None = None) -> None:
    anchors = anchors or default_anchors()
    dist_dir.mkdir(parents=True, exist_ok=True)
    for name in BackendRegistry.names():
        release_one(name, dist_dir, anchors=anchors)


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------


def _files_in(path: Path) -> dict[str, bytes]:
    if not path.exists():
        return {}
    return {
        str(p.relative_to(path)): p.read_bytes()
        for p in path.rglob("*")
        if p.is_file()
    }


def check_drift(anchors: OutputAnchors | None = None) -> int:
    """Return 0 if generated outputs match what build_all() would produce; 1 otherwise.

    Builds each backend into a tempdir, then byte-compares against its on-disk
    output directory.

    The tempdir build is handed `OutputAnchors.sandbox(td)`, which replaces
    *both* anchors. Sandboxing only the plugins anchor would leave a
    repository-anchored backend resolving to the real checkout, and since a
    build begins by rmtree'ing its output directory, a drift *check* would
    delete and rewrite the very tree it is supposed to be comparing against —
    always reporting no drift, having caused it.
    """
    anchors = anchors or default_anchors()
    drift: list[tuple[str, list[str], list[str], list[str]]] = []
    out_root = anchors.plugins

    # Universal AGENTS.md
    m = _load_manifest()
    expected_agents = render(
        "shared/AGENTS.md.j2",
        display_name=m.display_name,
        description=m.description,
        skill_body=(BASE_DIR / "skill.md").read_text(),
        references=_references_concatenated(),
    ).encode("utf-8")
    on_disk_agents = (
        (out_root / "AGENTS.md").read_bytes()
        if (out_root / "AGENTS.md").exists()
        else b""
    )
    if expected_agents != on_disk_agents:
        drift.append(("AGENTS.md", [], [], ["AGENTS.md"]))

    # Per-backend
    for name in BackendRegistry.names():
        BackendCls = BackendRegistry.get(name)
        with tempfile.TemporaryDirectory() as td:
            sandboxed = OutputAnchors.sandbox(Path(td))
            build_one(name, anchors=sandboxed)
            on_disk = _files_in(resolve_output_dir(BackendCls, anchors))
            generated = _files_in(resolve_output_dir(BackendCls, sandboxed))
            if on_disk != generated:
                added = sorted(set(generated) - set(on_disk))
                removed = sorted(set(on_disk) - set(generated))
                changed = sorted(
                    k for k in generated.keys() & on_disk.keys()
                    if generated[k] != on_disk[k]
                )
                drift.append((name, added, removed, changed))

    if drift:
        print("ERROR: generated outputs differ from _base/ source.")
        print("Run `agentic-plugins build` and commit the result.\n")
        for name, added, removed, changed in drift:
            print(f"  [{name}]")
            for f in added:
                print(f"    + {f}")
            for f in removed:
                print(f"    - {f}")
            for f in changed:
                print(f"    ~ {f}")
        return 1
    print(f"OK: AGENTS.md + {len(BackendRegistry.names())} platform outputs match _base/ source.")
    return 0
