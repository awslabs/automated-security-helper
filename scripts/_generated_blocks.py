"""Generated-block library, stubbed: every function refuses until it is written."""

from __future__ import annotations

from dataclasses import dataclass

PLACEHOLDERS = ("{{VERSION}}", "{{RELEASE}}")
TEMPLATE_SUFFIX = ".template"
WRITTEN = "written"
UNCHANGED = "unchanged"


class MarkerError(Exception):
    """A block cannot be read or written."""


@dataclass(frozen=True)
class GeneratedBlock:
    name: str


@dataclass(frozen=True)
class Drift:
    file: str


@dataclass(frozen=True)
class WriteResult:
    file: str


def begin_marker(name, generator):
    raise NotImplementedError


def end_marker(name):
    raise NotImplementedError


def parse_blocks(text, file):
    raise NotImplementedError


def replace_blocks(text, file, bodies, generator):
    raise NotImplementedError


def diff_blocks(text, file, bodies, generator):
    raise NotImplementedError


def twin_files(root, file):
    raise NotImplementedError


def write_blocks(root, file, bodies, generator):
    raise NotImplementedError


def check_blocks(root, file, bodies, generator):
    raise NotImplementedError
