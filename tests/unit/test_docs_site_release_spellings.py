# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The docs home page names the commands of the release its install commands pin.

Why this file exists
--------------------
The home page's snippet builder writes each install command with the ref
docs/hooks/install_refs.py sets (the current release on the ``main`` version of the
site) and the commands a reader runs next beside it, and the page's own hero and
cards show a scan command too. Those commands were moved to the ASH 3.9 spellings
(``ash scan fs``, ``ash results inspect``) before any 3.9 release existed, so the
``main`` site paired ``uv tool install ...@v3.8.0`` with ``ash scan fs --mode local``,
which ASH 3.8 refuses. The pages that ``scripts/version_template_manager.py`` renders
had the same pairing; their render now writes the spellings of the release a page
pins (``spellings_for_release``), and the hook gives the theme the same rule as the
``release_spellings`` filter.

What is asserted
----------------
Each template, rendered as the site renders it for a ref of the current release before
the subjects (3.8.0), names no spelling 3.8 lacks, while it still shows its scan
commands in 3.8's spelling (the control); rendered for 3.9.0, it names the subject
spellings. With no install ref set (a pull request's build), the ref falls back to the
page's ``ash_version``, as the snippet builder's pins do.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.utils.release_spellings import NEWER_SPELLING

jinja2 = pytest.importorskip("jinja2")
pytest.importorskip("mkdocs")

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
OVERRIDES = REPO_ROOT / "docs" / "overrides"
HOOK = REPO_ROOT / "docs" / "hooks" / "install_refs.py"
REPO_URL = "https://github.com/awslabs/automated-security-" + "helper"

#: The theme's own base page, which home.html extends; only its blocks matter here.
_MAIN_STUB = (
    "{% block extrahead %}{% endblock %}"
    "{% block site_nav %}{% endblock %}"
    "{% block container %}{% endblock %}"
)

#: (template, a command it shows in 3.8's spelling, the same in 3.9's)
TEMPLATES = [
    (
        "partials/ash-snippet-builder.html",
        "ash scan --mode local",
        "ash scan fs --mode local",
    ),
    ("home.html", "ash scan --mode container", "ash scan fs --mode container"),
]


def _hook():
    spec = importlib.util.spec_from_file_location("_install_refs_for_site_test", HOOK)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _render(template: str, install_ref: str | None, ash_version: str) -> str:
    loader = jinja2.ChoiceLoader(
        [
            jinja2.DictLoader({"main.html": _MAIN_STUB}),
            jinja2.FileSystemLoader(str(OVERRIDES)),
        ]
    )
    env = jinja2.Environment(loader=loader)
    env.filters["url"] = lambda path: path
    extra = {} if install_ref is None else {"install_ref": install_ref}
    config = SimpleNamespace(
        config_file_path=str(REPO_ROOT / "mkdocs.yml"), extra=extra, repo_url=REPO_URL
    )
    env = _hook().on_env(env, config, None)
    page = SimpleNamespace(meta={"ash_version": ash_version})
    return env.get_template(template).render(config=config, page=page)


@pytest.mark.parametrize(("template", "older", "newer"), TEMPLATES)
@pytest.mark.parametrize("install_ref", ["v3.8.0", None], ids=["main", "unset"])
def test_a_page_that_pins_3_8_names_only_the_commands_3_8_reads(
    template, older, newer, install_ref
):
    html = _render(template, install_ref, "3.8.0")
    found = sorted(set(NEWER_SPELLING.findall(html)))
    assert not found, f"{template} pins 3.8.0 and still names {found}"
    assert older in html, f"control: {template} no longer shows `{older}`"


@pytest.mark.parametrize(("template", "older", "newer"), TEMPLATES)
def test_a_page_that_pins_3_9_names_the_subject_spellings(template, older, newer):
    html = _render(template, "v3.9.0", "3.9.0")
    assert newer in html, html
    assert older not in html, html


def test_the_snippets_pin_the_ref_they_are_rendered_for():
    """Control: the snippet builder's install commands are the ones that pin."""
    assert "@v3.8.0" in _render(TEMPLATES[0][0], "v3.8.0", "3.8.0")


def test_the_filter_keeps_markup_markup():
    """A snippet captured under autoescape is markup; the rewrite must not escape it a
    second time."""
    from markupsafe import Markup

    hook = _hook()
    module = hook._load(REPO_ROOT, hook.MANAGER)
    text = Markup("ash scan fs --mode local &amp;&amp; echo done")
    out = hook.release_spellings(text, "v3.8.0", module=module)
    assert isinstance(out, Markup)
    assert str(out) == "ash scan --mode local &amp;&amp; echo done"
    assert hook.release_spellings("ash scan fs", "main", module=module) == "ash scan fs"
