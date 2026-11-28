# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The page policy the docs build hook gives the configuration editor page.

The editor builds a config file in the reader's browser and sends nothing anywhere.
Its page promises that with a Content-Security-Policy meta that lets it load only
this site's own files. These tests drive the hook's page half with fixture pages:

* the policy equals the table the page promises and sits directly after the
  charset meta;
* a second computation, written separately from the hook's, finds the same hash
  for every executable inline script of the page;
* each thing the policy cannot be made true for stops the build, one fixture page
  each, and the one exempt element passes in its exact markup only;
* the hook acts on the editor page and on no other page;
* the site settings that would void the promise stay off in mkdocs.yml.

Every check is paired with the input that makes it fail, so a check that cannot
fail shows up here: a policy with a changed directive, a hasher that trims
whitespace, a near copy of the exempt anchor, a setting added to mkdocs.yml.
"""

import base64
import hashlib
import html
import importlib.util
import re
import types
from html.parser import HTMLParser
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
HOOK_PATH = REPO_ROOT / "docs" / "hooks" / "config_editor.py"
MKDOCS_YML = REPO_ROOT / "mkdocs.yml"
HOOK_ENTRY = "docs/hooks/config_editor.py"
EDITOR_PAGE = "how-to/config-editor.md"

CHARSET = '<meta charset="utf-8">'

#: Material's search-share anchor as its template writes it, with the site language's
#: word for "share" in the two translated attributes.
SHARE_ANCHOR = (
    '<a href="javascript:void(0)" class="md-search__icon md-icon" title="Share" '
    'aria-label="Share" data-clipboard data-clipboard-text="" '
    'data-md-component="search-share" tabindex="-1"></a>'
)

#: The policy the page promises, directive by directive, as the page's own table
#: gives it. The script sources are checked against the page's hashes separately.
PROMISED = [
    ("default-src", ["'none'"]),
    ("script-src", ["'self'"]),
    ("style-src", ["'self'", "'unsafe-inline'"]),
    ("img-src", ["'self'", "data:"]),
    ("font-src", ["'self'"]),
    ("connect-src", ["'self'"]),
    ("worker-src", ["'self'"]),
    ("form-action", ["'none'"]),
    ("base-uri", ["'none'"]),
    ("object-src", ["'none'"]),
    ("frame-src", ["'none'"]),
]

CLASSIC = "var palette = window.localStorage.getItem('x');\n"
INDENTED = "  document.body.dataset.ready = 'yes';  "
CRLF_TEXT = "first();\r\nsecond();\r\n"
SCRIPTS = (
    f"<script>{CLASSIC}</script>\n"
    f"<script>{INDENTED}</script>\n"
    f"<script>{CRLF_TEXT}</script>\n"
    '<script type="module">import("./module.js");</script>\n'
    '<script src="../assets/javascripts/bundle.js"></script>\n'
    '<script id="ash-config-editor-data" type="application/json">{"a":1}</script>\n'
    '<script type="text/plain">  never run  </script>\n'
)


@pytest.fixture(scope="module")
def hook():
    spec = importlib.util.spec_from_file_location("ash_config_editor_hook", HOOK_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _page(
    *,
    charset: str = CHARSET,
    head: str = "",
    body: str = "",
    body_attrs: str = "",
    scripts: str = SCRIPTS,
) -> str:
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n'
        + charset
        + '\n<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        + "<title>Editor</title>\n"
        + head
        + "</head>\n"
        + f"<body{body_attrs}>\n"
        + SHARE_ANCHOR
        + "\n"
        + body
        + scripts
        + "</body>\n</html>\n"
    )


# -- The second, independent reading of a page ---------------------------------------

_SCRIPT = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
_TYPE = re.compile(r"""\btype\s*=\s*["']?([^"'\s>]*)""", re.IGNORECASE)
_RUNS = {"", "module", "importmap", "text/javascript", "application/javascript"}
_META = re.compile(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)">')


def _independent_hashes(page: str) -> list[str]:
    """The hash of each executable inline script, in page order, written with a
    regular expression and the standard library alone."""
    found: list[str] = []
    for attributes, text in _SCRIPT.findall(page):
        if re.search(r"\bsrc\s*=", attributes, re.IGNORECASE):
            continue
        kind = _TYPE.search(attributes)
        if (kind.group(1).lower() if kind else "") not in _RUNS:
            continue
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        digest = base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest())
        value = "sha256-" + digest.decode("ascii")
        if value not in found:
            found.append(value)
    return found


def _policy(page: str) -> list[tuple[str, list[str]]]:
    found = _META.findall(page)
    assert len(found) == 1, f"the page holds {len(found)} policy metas, not one"
    parts = html.unescape(found[0]).split("; ")
    return [(part.split()[0], part.split()[1:]) for part in parts]


def _policy_problems(page: str, expected_hashes: list[str]) -> list[str]:
    """What is wrong with the policy of a built page, as sentences."""
    problems: list[str] = []
    try:
        directives = _policy(page)
    except AssertionError as error:
        return [str(error)]
    promised = [
        (
            name,
            sources
            + (
                ["'" + h + "'" for h in expected_hashes] if name == "script-src" else []
            ),
        )
        for name, sources in PROMISED
    ]
    if directives != promised:
        problems.append(f"the directives are {directives}, not {promised}")
    start = page.find(CHARSET)
    meta = page.find("<meta http-equiv")
    if start < 0 or meta != start + len(CHARSET):
        problems.append("the policy meta does not sit directly after the charset meta")
    return problems


# -- The policy equals the table, and sits first after the charset -------------------


def test_the_policy_equals_the_table_and_sits_first_after_the_charset(hook):
    page = _page()
    built = hook.apply_page_policy(page)
    expected = _independent_hashes(page)
    assert len(expected) == 4, "the fixture has four executable inline scripts"
    assert _policy_problems(built, expected) == []


def _without(text: str, old: str, new: str = "") -> str:
    assert old in text, f"{old!r} is not in the page the defect is planted in"
    return text.replace(old, new, 1)


PLANTED_POLICY_DEFECTS = {
    "img-src without data:": lambda page: _without(
        page, "img-src 'self' data:", "img-src 'self'"
    ),
    "unsafe-inline in script-src": lambda page: _without(
        page, "script-src 'self'", "script-src 'self' 'unsafe-inline'"
    ),
    "connect-src widened": lambda page: _without(
        page, "connect-src 'self'", "connect-src 'self' https:"
    ),
    "frame-src dropped": lambda page: _without(page, "; frame-src 'none'"),
    "a hash dropped": lambda page: re.sub(r" 'sha256-[^']*'", "", page, count=1),
    "policy after the title": lambda page: _without(
        _without(page, _META.search(page).group(0)),
        "<title>Editor</title>",
        "<title>Editor</title>" + _META.search(page).group(0),
    ),
}


@pytest.mark.parametrize("defect", sorted(PLANTED_POLICY_DEFECTS))
def test_a_policy_that_differs_from_the_table_is_reported(hook, defect):
    page = _page()
    built = hook.apply_page_policy(page)
    planted = PLANTED_POLICY_DEFECTS[defect](built)
    assert _policy_problems(planted, _independent_hashes(page)), (
        f"the policy check passed a built page with this defect planted: {defect}"
    )


# -- A second hash computation equals the meta's list --------------------------------


def _hash_problems(hook, page: str) -> list[str]:
    built = hook.apply_page_policy(page)
    expected = _independent_hashes(page)
    listed = [
        source.strip("'")
        for source in dict(_policy(built))["script-src"]
        if source.startswith("'sha256-")
    ]
    if listed != expected:
        return [f"the meta lists {listed}, an independent computation gives {expected}"]
    return []


def test_the_hash_list_equals_an_independent_computation(hook):
    assert _hash_problems(hook, _page()) == []


def test_a_data_block_and_a_plain_text_script_get_no_hash(hook):
    built = hook.apply_page_policy(_page())
    listed = dict(_policy(built))["script-src"]
    for text in ('{"a":1}', "  never run  "):
        digest = base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()
        assert f"'sha256-{digest}'" not in listed, f"{text!r} is not executable"


def test_a_hasher_that_trims_whitespace_fails_the_hash_check(hook, monkeypatch):
    original = hook.script_hash
    monkeypatch.setattr(hook, "script_hash", lambda text: original(text.strip()))
    assert _hash_problems(hook, _page()), (
        "a hasher that trims each script's text before hashing went unnoticed"
    )


def test_a_hasher_that_keeps_carriage_returns_fails_the_hash_check(hook, monkeypatch):
    def unnormalized(text: str) -> str:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        return "sha256-" + base64.b64encode(digest).decode("ascii")

    monkeypatch.setattr(hook, "script_hash", unnormalized)
    assert _hash_problems(hook, _page()), (
        "a hasher that keeps carriage returns, which a browser reads as line feeds, "
        "went unnoticed"
    )


def test_a_hash_is_listed_once_for_two_identical_scripts(hook):
    twice = _page(scripts="<script>same();</script>\n<script>same();</script>\n")
    built = hook.apply_page_policy(twice)
    listed = [s for s in dict(_policy(built))["script-src"] if s.startswith("'sha256-")]
    assert len(listed) == 1


# -- Each refusal has its own fixture page -------------------------------------------

REFUSED = {
    "an inline event handler on an element": (
        _page(body='<button onclick="go()">go</button>\n'),
        "inline event handler",
    ),
    "an inline event handler on the body": (
        _page(body_attrs=' onload="start()"'),
        "inline event handler",
    ),
    "an inline event handler in capitals": (
        _page(body='<img src="x.png" ONERROR="x()">\n'),
        "inline event handler",
    ),
    "a javascript: URL": (
        _page(body='<a href="javascript:alert(1)">x</a>\n'),
        "javascript: URL",
    ),
    "a javascript: URL in capitals": (
        _page(body='<a href="JAVASCRIPT:alert(1)">x</a>\n'),
        "javascript: URL",
    ),
    "a javascript: URL with a tab and spaces": (
        _page(body='<a href="  Java\tScript:alert(1)">x</a>\n'),
        "javascript: URL",
    ),
    "an external script": (
        _page(head='<script src="https://cdn.example.com/x.js"></script>\n'),
        "external script",
    ),
    "a protocol-relative script": (
        _page(head='<script src="//cdn.example.com/x.js"></script>\n'),
        "external script",
    ),
    "a script from a host written with two backslashes": (
        _page(head='<script src="\\\\cdn.example.com/x.js"></script>\n'),
        "external script",
    ),
    "a script from a host written with a slash and a backslash": (
        _page(head='<script src="/\\cdn.example.com/x.js"></script>\n'),
        "external script",
    ),
    "a script from a host split by a tab": (
        _page(head='<script src="/\t/cdn.example.com/x.js"></script>\n'),
        "external script",
    ),
    "a script from a host split by a character reference to a tab": (
        _page(head='<script src="/&#9;/cdn.example.com/x.js"></script>\n'),
        "external script",
    ),
    "a script from a host split by a line break": (
        _page(head='<script src="/\n/cdn.example.com/x.js"></script>\n'),
        "external script",
    ),
    "an SVG script that loads from href": (
        _page(
            body='<svg><script href="https://cdn.example.com/x.js"></script></svg>\n'
        ),
        "external script",
    ),
    "an SVG script that loads from xlink:href": (
        _page(
            body='<svg xmlns:xlink="http://www.w3.org/1999/xlink">'
            '<script xlink:href="//cdn.example.com/x.js"/></svg>\n'
        ),
        "external script",
    ),
    "a script that repeats src, the first value naming another host": (
        _page(
            head='<script src="https://cdn.example.com/x.js" src="/x.js"></script>\n'
        ),
        "external script",
    ),
    "a script that repeats an attribute": (
        _page(head='<script src="/a.js" src="/b.js"></script>\n'),
        "repeats the attribute 'src'",
    ),
    "a meta that repeats an attribute": (
        _page(head='<meta name="a" name="b" content="c">\n'),
        "repeats the attribute 'name'",
    ),
    "markup in an SVG style": (
        _page(body='<svg><style><img src="x" onerror="go()"></style></svg>\n'),
        "inline event handler",
    ),
    "a javascript: URL in an SVG style": (
        _page(body='<svg><style><a href="javascript:go()">x</a></style></svg>\n'),
        "javascript: URL",
    ),
    "markup in an SVG style that is never closed": (
        _page(body='<svg><style><img src="x" onerror="go()">\n'),
        "inline event handler",
    ),
    "markup in a MathML style": (
        _page(body='<math><style><img src="x" onerror="go()"></style></math>\n'),
        "inline event handler",
    ),
    "markup in an SVG script": (
        _page(body='<svg><script><img src="x" onerror="go()"></script></svg>\n'),
        "inline event handler",
    ),
    "an external script in the markup of an SVG style": (
        _page(
            body="<svg><style>"
            '<script src="https://cdn.example.com/x.js"></script>'
            "</style></svg>\n"
        ),
        "external script",
    ),
    "a second policy meta": (
        _page(
            head='<meta http-equiv="Content-Security-Policy" content="default-src *">\n'
        ),
        "already holds a Content-Security-Policy meta",
    ),
    "a second policy meta in mixed case": (
        _page(
            head='<Meta HTTP-EQUIV="content-security-policy" CONTENT="default-src *">\n'
        ),
        "already holds a Content-Security-Policy meta",
    ),
    "no charset meta": (_page(charset=""), "no <meta charset>"),
}


@pytest.mark.parametrize("defect", sorted(REFUSED))
def test_the_build_refuses_the_page(hook, defect):
    page, fragment = REFUSED[defect]
    with pytest.raises(hook.ProjectionError, match=re.escape(fragment)):
        hook.apply_page_policy(page)


def test_the_page_without_any_of_those_defects_is_built(hook):
    assert "Content-Security-Policy" in hook.apply_page_policy(_page())


#: Pages that look like the refused ones and are not. Each is the twin of a refused
#: page above, so a refusal that grows too wide fails here.
BUILT = {
    "a script from this site": '<script src="/assets/x.js"></script>\n',
    "a script from a relative path": '<script src="../assets/x.js"></script>\n',
    "a script path with a colon after a slash": '<script src="/a/b:c.js"></script>\n',
    "a script path with a backslash in it": '<script src="/assets\\x.js"></script>\n',
    "a script path that only starts like a host": (
        '<script src="/./\\cdn.example.com/x.js"></script>\n'
    ),
    "an SVG script from this site": '<svg><script href="/assets/x.js"></script></svg>\n',
    "an SVG style of plain css": (
        '<svg><style type="text/css">.a{fill:#fff}\n.b > .c{fill-rule:evenodd}'
        "</style></svg>\n"
    ),
    "an SVG style in a character data section": (
        "<svg><style><![CDATA[ .a{fill:red} ]]></style></svg>\n"
    ),
    "a style outside SVG that mentions markup": (
        '<style>/* <img src="x" onerror="go()"> */</style>\n'
    ),
    "markup text in a style after the SVG closed": (
        '<svg></svg><style>/* <img src="x" onerror="go()"> */</style>\n'
    ),
}


@pytest.mark.parametrize("name", sorted(BUILT))
def test_a_page_that_only_looks_like_a_refused_one_is_built(hook, name):
    assert "Content-Security-Policy" in hook.apply_page_policy(_page(body=BUILT[name]))


LOGO = REPO_ROOT / "docs" / "overrides" / ".icons" / "aws-logo-light.svg"


def test_the_sites_own_logo_and_its_svg_style_are_built(hook):
    logo = LOGO.read_text(encoding="utf-8")
    assert "<style" in logo
    assert "Content-Security-Policy" in hook.apply_page_policy(_page(body=logo + "\n"))


def test_the_same_logo_with_a_handler_in_its_style_is_refused(hook):
    logo = LOGO.read_text(encoding="utf-8")
    planted = logo.replace(".st0{fill:#FFFFFF;}", '<img src="x" onerror="go()">', 1)
    assert planted != logo
    with pytest.raises(hook.ProjectionError, match="inline event handler"):
        hook.apply_page_policy(_page(body=planted + "\n"))


def test_the_refusal_names_every_problem_of_the_page(hook):
    page = _page(
        charset="",
        body='<button onclick="go()">go</button><a href="javascript:x()">x</a>\n',
        head='<script src="https://cdn.example.com/x.js"></script>\n',
    )
    with pytest.raises(hook.ProjectionError) as caught:
        hook.apply_page_policy(page)
    text = str(caught.value)
    for fragment in ("event handler", "javascript: URL", "external script", "no <meta"):
        assert fragment in text, f"the refusal does not mention {fragment!r}: {text}"


def test_the_policy_is_not_applied_to_a_page_twice(hook):
    once = hook.apply_page_policy(_page())
    with pytest.raises(hook.ProjectionError, match="already holds"):
        hook.apply_page_policy(once)


# -- A page that ends inside a style or script element -------------------------------


def _page_ending_in(element: str) -> str:
    """A page whose body ends inside ``element``: no later end tag closes it, so the
    page holds no script after it."""
    return _page(body=element + "\n", scripts="")


#: Pages that end inside a style or script element, each with the element's name. A
#: browser reads the rest of the page as that element's text, so each is refused for
#: the open element itself, whatever text it holds.
UNCLOSED = {
    "a style": (_page_ending_in("<style>.a{fill:red}"), "style"),
    "a style in capitals": (_page_ending_in("<STYLE>.a{fill:red}"), "style"),
    "a script": (_page_ending_in("<script>go();"), "script"),
    "a script with a source": (
        _page_ending_in('<script src="/assets/x.js">'),
        "script",
    ),
    "an SVG style": (_page_ending_in("<svg><style>.a{fill:red}"), "style"),
    "an SVG script": (_page_ending_in("<svg><script>go();"), "script"),
    "a MathML style": (_page_ending_in("<math><style>.a{fill:red}"), "style"),
}


def _drops_open_raw_text(scanner_class):
    """The page scanner over a parser that, like CPython up to 3.12.10, hands the
    handlers none of the text of a style or script element still open when the input
    ends. Later releases hand it over from close(); this one never does, so a check
    that waits for that text sees nothing."""

    class Scanner(scanner_class):
        def goahead(self, end):
            super().goahead(end and not self.cdata_elem)

    return Scanner


@pytest.fixture(
    params=["the interpreter's parser", "a parser that hands over no open raw text"]
)
def parser_shape(request, hook, monkeypatch):
    if request.param.startswith("a parser"):
        monkeypatch.setattr(hook, "PageScanner", _drops_open_raw_text(hook.PageScanner))
    return request.param


@pytest.mark.parametrize("defect", sorted(UNCLOSED))
def test_a_page_that_ends_inside_a_style_or_script_is_refused(
    hook, parser_shape, defect
):
    page, tag = UNCLOSED[defect]
    line = page[: re.search(f"<{tag}", page, re.IGNORECASE).start()].count("\n") + 1
    with pytest.raises(
        hook.ProjectionError,
        match=re.escape(f"line {line}: the {tag} element is never closed"),
    ):
        hook.apply_page_policy(page)


def test_every_refused_page_is_refused_by_a_parser_that_hands_over_no_open_raw_text(
    hook, monkeypatch
):
    monkeypatch.setattr(hook, "PageScanner", _drops_open_raw_text(hook.PageScanner))
    missed = []
    for defect, (page, fragment) in REFUSED.items():
        try:
            hook.apply_page_policy(page)
        except hook.ProjectionError as error:
            if fragment not in str(error):
                missed.append(f"{defect}: refused for another reason")
        else:
            missed.append(f"{defect}: not refused")
    assert missed == []


def test_no_page_is_refused_too_wide_by_a_parser_that_hands_over_no_open_raw_text(
    hook, monkeypatch
):
    monkeypatch.setattr(hook, "PageScanner", _drops_open_raw_text(hook.PageScanner))
    logo = LOGO.read_text(encoding="utf-8")
    refused = []
    for name, body in {**BUILT, "the site's own logo": logo + "\n"}.items():
        try:
            hook.apply_page_policy(_page(body=body))
        except hook.ProjectionError as error:
            refused.append(f"{name}: {error}")
    assert refused == []


# -- The one exempt element, in its exact markup only --------------------------------


def _near_copies() -> dict[str, str]:
    exact = SHARE_ANCHOR
    return {
        "another javascript: URL": exact.replace("void(0)", "alert(1)"),
        "the href in capitals": exact.replace(
            "javascript:void(0)", "JAVASCRIPT:void(0)"
        ),
        "another tabindex": exact.replace('tabindex="-1"', 'tabindex="0"'),
        "another class": exact.replace("md-search__icon md-icon", "md-icon"),
        "another component": exact.replace('"search-share"', '"search-other"'),
        "a missing data-clipboard": exact.replace(
            " data-clipboard data-clipboard-text", " data-clipboard-text"
        ),
        "an extra attribute": exact.replace("<a ", '<a id="share" '),
        "an extra handler": exact.replace("<a ", '<a onclick="x()" '),
        "a repeated attribute": exact.replace("<a ", '<a class="md-icon" '),
        "a button for an anchor": exact.replace("<a ", "<button ").replace(
            "</a>", "</button>"
        ),
        "a missing translated attribute": exact.replace(' aria-label="Share"', ""),
    }


def test_the_exempt_anchor_passes_in_its_exact_markup(hook):
    page = _page()
    assert SHARE_ANCHOR in page
    assert hook.apply_page_policy(page)


@pytest.mark.parametrize("copy", sorted(_near_copies()))
def test_a_near_copy_of_the_exempt_anchor_is_refused(hook, copy):
    page = _page().replace(SHARE_ANCHOR, _near_copies()[copy])
    with pytest.raises(hook.ProjectionError):
        hook.apply_page_policy(page)


def test_a_second_exact_anchor_is_exempt_too_but_a_javascript_url_beside_it_is_not(
    hook,
):
    exact_twice = _page(body=SHARE_ANCHOR + "\n")
    assert hook.apply_page_policy(exact_twice)
    beside = _page(body='<a href="javascript:alert(1)">x</a>\n')
    with pytest.raises(hook.ProjectionError, match="javascript: URL"):
        hook.apply_page_policy(beside)


class _AnchorReader(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[list[tuple[str, str | None]]] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a" and ("data-md-component", "search-share") in attrs:
            self.anchors.append(attrs)


def _anchor_problems(template: str, fixed: dict, translated: tuple) -> list[str]:
    reader = _AnchorReader()
    reader.feed(template)
    if len(reader.anchors) != 1:
        return [f"the template holds {len(reader.anchors)} search-share anchors"]
    found = {
        name: ("" if value is None else value) for name, value in reader.anchors[0]
    }
    problems = []
    if set(found) != set(fixed) | set(translated):
        problems.append(f"the attributes are {sorted(found)}")
    for name, value in fixed.items():
        if found.get(name) != value:
            problems.append(
                f"{name} is {found.get(name)!r}, the hook exempts {value!r}"
            )
    return problems


def _material_search_partial() -> str:
    spec = importlib.util.find_spec("material")
    assert spec is not None and spec.submodule_search_locations
    root = Path(next(iter(spec.submodule_search_locations)))
    return (root / "templates" / "partials" / "search.html").read_text(encoding="utf-8")


def test_the_exempt_markup_is_the_markup_of_the_installed_material_template(hook):
    problems = _anchor_problems(
        _material_search_partial(),
        hook.SEARCH_SHARE_FIXED,
        hook.SEARCH_SHARE_TRANSLATED,
    )
    assert problems == [], (
        "the search-share anchor the hook exempts is not the one Material for MkDocs "
        "writes, so a Material upgrade changed it: " + "; ".join(problems)
    )


def test_a_template_with_a_changed_anchor_fails_the_parity_check(hook):
    template = _material_search_partial()
    marker = 'data-md-component="search-share"'
    at = template.index(marker)
    # The anchor's own tabindex follows its component attribute; the template has
    # other tabindex attributes before it, so the change is made after the marker.
    assert 'tabindex="-1"' in template[at:]
    changed = template[:at] + template[at:].replace('tabindex="-1"', 'tabindex="0"', 1)
    assert _anchor_problems(
        changed, hook.SEARCH_SHARE_FIXED, hook.SEARCH_SHARE_TRANSLATED
    ), "a template whose anchor has another tabindex passed the parity check"
    extra = template.replace(marker, marker + ' id="x"', 1)
    assert _anchor_problems(
        extra, hook.SEARCH_SHARE_FIXED, hook.SEARCH_SHARE_TRANSLATED
    ), "a template whose anchor has an extra attribute passed the parity check"


# -- The hook acts on the editor page only -------------------------------------------


def _fake_page(src_uri: str):
    return types.SimpleNamespace(file=types.SimpleNamespace(src_uri=src_uri))


@pytest.fixture
def small_block(hook, monkeypatch):
    block = {"contract": "fixture", "text": "</script><b>&</b>"}
    monkeypatch.setattr(hook, "editor_block", lambda config: block)
    return block


def test_the_editor_page_gets_the_data_block_and_the_policy(hook, small_block):
    built = hook.on_post_page(_page(), _fake_page(EDITOR_PAGE), object())
    blocks = re.findall(
        r'<script type="application/json" id="ash-config-editor-data">(.*?)</script>',
        built,
    )
    assert len(blocks) == 1
    assert not any(char in blocks[0] for char in "<>&"), (
        "the block holds a raw character"
    )
    assert built.index("ash-config-editor-data") < built.index("</body>")
    assert _policy_problems(built, _independent_hashes(_page())) == []


@pytest.mark.parametrize(
    "src_uri",
    [
        "index.md",
        "how-to/config-editor.md/",
        "How-To/config-editor.md",
        "other/config-editor.md",
    ],
)
def test_no_other_page_is_touched(hook, small_block, src_uri):
    refused_page = _page(body='<button onclick="go()">go</button>\n')
    assert (
        hook.on_post_page(refused_page, _fake_page(src_uri), object()) == refused_page
    )


def test_the_handler_runs_after_every_other_plugin(hook):
    assert hook.on_post_page.mkdocs_priority == -100


def test_the_hook_is_registered_in_mkdocs_yml():
    assert HOOK_ENTRY in _mkdocs()["hooks"]
    assert (REPO_ROOT / HOOK_ENTRY).is_file()


# -- The site settings that would void the promise stay off --------------------------


class _Loader(yaml.SafeLoader):
    """mkdocs.yml with the tags only mkdocs reads (``!!python/name:``) set aside."""


_Loader.add_multi_constructor("", lambda loader, suffix, node: None)


def _mkdocs() -> dict:
    return yaml.load(MKDOCS_YML.read_text(encoding="utf-8"), Loader=_Loader)  # nosec B506 - a SafeLoader subclass


def _forbidden_settings(config: dict) -> list[str]:
    found = []
    for feature in (config.get("theme") or {}).get("features") or []:
        if feature == "navigation.instant" or str(feature).startswith(
            "navigation.instant."
        ):
            found.append(f"theme.features: {feature}")
    for key in ("analytics", "consent"):
        if key in (config.get("extra") or {}):
            found.append(f"extra.{key}")
    return found


def test_the_site_turns_on_nothing_that_voids_the_policy():
    assert _forbidden_settings(_mkdocs()) == []


@pytest.mark.parametrize(
    "plant",
    [
        lambda config: config["theme"]["features"].append("navigation.instant"),
        lambda config: config["theme"]["features"].append(
            "navigation.instant.prefetch"
        ),
        lambda config: config["extra"].update(analytics={"provider": "google"}),
        lambda config: config["extra"].update(consent={"title": "Cookie consent"}),
    ],
    ids=["instant", "instant prefetch", "analytics", "consent"],
)
def test_each_setting_that_voids_the_policy_is_found_when_added(plant):
    config = _mkdocs()
    config.setdefault("extra", {})
    plant(config)
    assert _forbidden_settings(config), "the settings check passed a planted setting"
