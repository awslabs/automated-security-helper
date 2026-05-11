"""Jinja2 environment shared by all backends.

Templates live under transpiler/templates/. The environment uses StrictUndefined
so a missing variable surfaces as an error rather than silently producing empty
output.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

# Templates directory is sibling to the transpiler package
_TEMPLATES = Path(__file__).resolve().parent.parent / "templates"

ENV = Environment(
    loader=FileSystemLoader(str(_TEMPLATES)),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    trim_blocks=False,
    lstrip_blocks=False,
)


def render(template_path: str, **context: Any) -> str:
    return ENV.get_template(template_path).render(**context)
