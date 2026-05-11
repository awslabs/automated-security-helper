"""Jinja2 environment shared by all backends.

Templates resolve in this priority order:
  1. Per-backend templates: transpiler/backends/<name>/templates/...
  2. Shared templates:       transpiler/templates/...

This lets a backend ship overrides or backend-specific Jinja files (e.g.
roo/roomodes.j2) without polluting the shared template tree, while still
inheriting the generic `skill.md.j2`, `shared/AGENTS.md.j2`, etc.

Templates are referenced from emitter code by their path under templates/,
e.g. `kiro/POWER_frontmatter.j2`. The ChoiceLoader checks each backend's
templates/ subdir first, then falls back to the shared root. Per-backend
templates therefore use the same path style — a backend's
backends/kiro/templates/kiro/POWER_frontmatter.j2 would override the shared
templates/kiro/POWER_frontmatter.j2.

StrictUndefined is enabled so a missing variable surfaces as an error
rather than silently producing empty output.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import ChoiceLoader, Environment, FileSystemLoader, StrictUndefined

# Shared templates directory (sibling to the transpiler package)
_SHARED_TEMPLATES = Path(__file__).resolve().parent.parent / "templates"

# Per-backend templates: backends/<name>/templates/. We discover all of them
# at module-load time. New backends are picked up automatically because each
# backend sub-package is imported by transpiler.backends.__init__ before any
# render() call.
_BACKENDS_DIR = Path(__file__).resolve().parent / "backends"


def _discover_backend_template_dirs() -> list[str]:
    if not _BACKENDS_DIR.exists():
        return []
    dirs: list[str] = []
    for backend_pkg in sorted(_BACKENDS_DIR.iterdir()):
        if not backend_pkg.is_dir() or backend_pkg.name.startswith("_"):
            continue
        templates = backend_pkg / "templates"
        if templates.is_dir():
            dirs.append(str(templates))
    return dirs


_loaders = [FileSystemLoader(d) for d in _discover_backend_template_dirs()]
_loaders.append(FileSystemLoader(str(_SHARED_TEMPLATES)))

ENV = Environment(
    loader=ChoiceLoader(_loaders),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    trim_blocks=False,
    lstrip_blocks=False,
)


def render(template_path: str, **context: Any) -> str:
    return ENV.get_template(template_path).render(**context)
