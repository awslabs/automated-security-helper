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
from .core import BuildContext, Manifest
from .jinja_renderer import render
from .registry import BackendRegistry

HERE = Path(__file__).resolve().parent              # transpiler/transpiler/
TRANSPILER_DIR = HERE.parent                         # transpiler/
BASE_DIR = TRANSPILER_DIR / "_base"
SCHEMAS_DIR = TRANSPILER_DIR / "schemas"
OUTPUT_ROOT = TRANSPILER_DIR.parent / "plugins"      # agentic-coding/plugins/


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


def build_one(backend_name: str, out_root: Path | None = None) -> None:
    """Build a single backend by name."""
    out_root = out_root or OUTPUT_ROOT
    m = _load_manifest()
    BackendCls = BackendRegistry.get(backend_name)
    backend = BackendCls()
    backend.build(
        manifest=m,
        out=out_root / BackendCls.OUTPUT_DIR,
        plugins_root=out_root,
        base_dir=BASE_DIR,
        schemas_dir=SCHEMAS_DIR,
    )


def build_all(out_root: Path | None = None) -> None:
    """Build every registered backend + the universal AGENTS.md."""
    out_root = out_root or OUTPUT_ROOT
    out_root.mkdir(parents=True, exist_ok=True)
    render_universal_agents_md(out_root)
    for name in BackendRegistry.names():
        build_one(name, out_root=out_root)


def release_one(backend_name: str, dist_dir: Path, out_root: Path | None = None) -> None:
    out_root = out_root or OUTPUT_ROOT
    m = _load_manifest()
    BackendCls = BackendRegistry.get(backend_name)
    backend = BackendCls()
    ctx = BuildContext(
        manifest=m,
        out=out_root / BackendCls.OUTPUT_DIR,
        plugins_root=out_root,
        base_dir=BASE_DIR,
        schemas_dir=SCHEMAS_DIR,
        dist_dir=dist_dir,
    )
    backend.release(ctx)


def release_all(dist_dir: Path, out_root: Path | None = None) -> None:
    out_root = out_root or OUTPUT_ROOT
    dist_dir.mkdir(parents=True, exist_ok=True)
    for name in BackendRegistry.names():
        release_one(name, dist_dir, out_root=out_root)


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


def check_drift(out_root: Path | None = None) -> int:
    """Return 0 if generated outputs match what build_all() would produce; 1 otherwise.

    Runs build_all into a tempdir, then byte-compares against the on-disk plugins
    directory."""
    out_root = out_root or OUTPUT_ROOT
    drift: list[tuple[str, list[str], list[str], list[str]]] = []

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
            tmp_root = Path(td)
            build_one(name, out_root=tmp_root)
            on_disk = _files_in(out_root / BackendCls.OUTPUT_DIR)
            generated = _files_in(tmp_root / BackendCls.OUTPUT_DIR)
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
