# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared presentation colors for ASH's human-facing terminal interfaces."""

from typing import TYPE_CHECKING

from rich.theme import Theme as RichTheme

from automated_security_helper.models.vocab import SEVERITY_BUCKETS

if TYPE_CHECKING:
    from textual.theme import Theme as TextualTheme

COLORS = {
    "background": "#0f141a",
    "surface": "#161d26",
    "panel": "#1b232d",
    "foreground": "#dedee3",
    "muted": "#b4b4bb",
    "border": "#424650",
    "accent": "#42b4ff",
    "critical": "#ff7a7a",
    "high": "#fe6e73",
    "medium": "#f89256",
    "low": "#f2cd54",
    "info": "#42b4ff",
    "success": "#2bb534",
    "warning": "#ffe347",
    "error": "#ff7a7a",
}

FOOTER_CREDIT = "Built with <3 at Amazon Web Services"

#: The same credit as a small markdown blockquote, for the Markdown report that is
#: posted as the pinned pull request comment.
FOOTER_CREDIT_SMALL_BLOCKQUOTE = f"> <sub>{FOOTER_CREDIT}</sub>"

#: The severities a finding carries, the only palette keys severity_color reads.
SEVERITY_LEVELS = SEVERITY_BUCKETS


def severity_color(severity: str) -> str:
    """The color of a finding's severity, or the muted color for any other text.

    Looked up among the severity keys only, not the whole palette: a severity
    spelled like a layout role ("background", "surface", "panel", "border")
    used to take that role's color, so its text was painted in the background
    color and could not be read."""
    level = str(severity).lower()
    if level in SEVERITY_LEVELS:
        # ``.get``: a level added to the ladder before it has a palette entry
        # reads muted here instead of raising, and ``rich_theme`` runs at CLI
        # import time, where a KeyError would take every command down.
        return COLORS.get(level, COLORS["muted"])
    return COLORS["muted"]


def rich_theme() -> RichTheme:
    """Semantic styles for progress, status tables, and human-readable commands."""
    return RichTheme(
        {
            "ash.brand": f"bold {COLORS['accent']}",
            "ash.muted": COLORS["muted"],
            "ash.success": COLORS["success"],
            "ash.warning": COLORS["warning"],
            "ash.error": f"bold {COLORS['error']}",
            **{f"ash.{level}": severity_color(level) for level in SEVERITY_LEVELS},
        }
    )


def textual_theme() -> "TextualTheme":
    """Create the findings explorer theme without loading Textual in other CLIs."""
    from textual.theme import Theme

    return Theme(
        name="ash",
        primary=COLORS["accent"],
        secondary=COLORS["muted"],
        accent=COLORS["accent"],
        foreground=COLORS["foreground"],
        background=COLORS["background"],
        surface=COLORS["surface"],
        panel=COLORS["panel"],
        success=COLORS["success"],
        warning=COLORS["warning"],
        error=COLORS["error"],
        dark=True,
        variables={
            "footer-background": COLORS["surface"],
            "footer-key-foreground": COLORS["accent"],
            "footer-description-foreground": COLORS["muted"],
            "input-selection-background": f"{COLORS['accent']} 25%",
            "block-cursor-text-style": "none",
            "text-muted": COLORS["muted"],
            "border-blurred": COLORS["border"],
        },
    )
