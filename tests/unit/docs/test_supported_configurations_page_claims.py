"""What the supported-configurations page says, held to the register that declares it.

The page lists each configuration ASH declares with a limit or a stand-in, and each way
out of one. The register in ``automated_security_helper/base/support_register.py``
declares the same rows and ways out as data, and the page carries their sentences word
for word. This module pins those sentences the way test_page_claims.py pins the rest of
the pages: ``assert_on_page`` checks that the sentence is still on its page, so a
rewording on either side fails here with the page and the heading of the closest
paragraph named.

What it pins on how-to/supported-configurations.md:

- the sentence a declared row carries, for every row that is not plainly supported;
- the sentence each way out carries;
- the sentence each undeclared token carries;
- the name of each stand-in and each adaptation;
- the sentences that say what the page lists, what the four levels mean and how a
  configuration is described;
- the ways out that the section on a missing scanner build links, for every platform
  that can lack a build;
- the one claim that depends on the scanner list: that several tools have no build for
  Windows on arm64, which holds while at least two of the shipped scanners declare it.

The page describes what the register declares. It does not say that ASH shows a notice,
because a page may claim only what ASH does: the change that makes ASH show one rewrites
those sentences and the last test here together.

The structure of the page (its sections, anchors and place in the navigation) and the
register's own rules are held in tests/unit/base/test_support_register.py. Nothing here
starts a scanner or reads the host.
"""

from __future__ import annotations

import re

import pytest

from automated_security_helper.base import support_register as sr
from tests.unit.docs.test_page_claims import CONTENT, assert_on_page
from tests.utils.scanner_enumeration import load_scanner_universe
from tests.utils.support_gaps import all_platforms_but, gap_platform, pinned_binaries

pytestmark = pytest.mark.unit

PAGE = "how-to/supported-configurations.md"

DECLARED_ROWS = [
    row for row in sr.REGISTER.rows if row.level is not sr.SupportLevel.SUPPORTED
]

#: The sentences that say what the page lists, what a level means and how a
#: configuration is described. Each is on the page word for word, link targets aside.
FRAMING = [
    (
        "This page lists each configuration that has a limit or a stand-in: how well "
        "ASH works there, what ASH does, and what you can change to reach a supported "
        "configuration."
    ),
    (
        "A configuration this page does not list is declared supported, except the "
        "few that ASH declares nothing about."
    ),
    (
        "Each configuration below has one sentence that describes it. ASH declares the "
        "same sentence in its code, so this page and the code say the same words."
    ),
    "supported: ASH works here, and this page lists no limit for it.",
    (
        "polyfilled: ASH works here through a named stand-in for something the "
        "platform or the runtime lacks. The stand-in can change what you see, such as "
        "speed, an interpreter or a refusal of some inputs, so this page names it."
    ),
    "degraded: ASH runs here and loses a named function.",
    (
        "unsupported: ASH refuses, skips the part that cannot work, or runs with "
        "results it cannot stand behind."
    ),
    "A machine that matches several configurations has the level of the worst one.",
    (
        "Each configuration below has a level, one sentence that describes it, what "
        "ASH does there, and the ways out."
    ),
    "A way out is listed only where it can apply: WSL 2 is offered from Windows only.",
    (
        "Each way out has one sentence. The commands live in the guides this page "
        "links to, so the sentences here hold no command."
    ),
]


def test_the_pin_reads_a_register_that_declares_rows_ways_out_and_stand_ins() -> None:
    """A register that declared nothing would pin nothing and pass."""
    assert DECLARED_ROWS
    assert sr.REGISTER.paths
    assert sr.REGISTER.polyfills
    assert sr.REGISTER.not_declared


@pytest.mark.parametrize("row", DECLARED_ROWS, ids=lambda row: row.id)
def test_the_page_carries_what_a_declared_row_says(row: sr.SupportRow) -> None:
    assert_on_page(PAGE, row.message)


@pytest.mark.parametrize("path", sr.REGISTER.paths, ids=lambda path: path.id)
def test_the_page_carries_what_a_way_out_offers(path: sr.UpgradePath) -> None:
    assert_on_page(PAGE, path.summary)


@pytest.mark.parametrize(
    "token", list(sr.REGISTER.not_declared), ids=lambda token: "=".join(token)
)
def test_the_page_carries_what_an_undeclared_token_says(token: tuple[str, str]) -> None:
    assert_on_page(PAGE, sr.REGISTER.not_declared[token])


@pytest.mark.parametrize("polyfill", sr.REGISTER.polyfills, ids=lambda p: p.id)
def test_the_page_names_each_stand_in_and_adaptation(polyfill: sr.Polyfill) -> None:
    assert_on_page(PAGE, polyfill.name)


@pytest.mark.parametrize("sentence", FRAMING, ids=lambda sentence: sentence[:32])
def test_the_page_carries_its_framing_sentences(sentence: str) -> None:
    assert_on_page(PAGE, sentence)


def _section(anchor: str) -> str:
    """The raw text of the section of the page whose heading carries ``anchor``."""
    text = (CONTENT / PAGE).read_text(encoding="utf-8")
    start = text.index("{#" + anchor + "}")
    following = re.search(r"^#{1,3} ", text[start:], re.MULTILINE)
    end = start + following.start() if following else len(text)
    return text[start:end]


def test_the_no_build_section_links_every_way_out_a_missing_build_offers() -> None:
    """The register chooses the ways out of a missing build for the platform that has
    none: another machine for a Linux gap, and WSL 2, the image or another operating
    system elsewhere. The section the derived rows share links each one a gap offers."""
    binaries = (
        sr.PinnedBinary("demo-a", "tool-a", "1.0", ("linux/amd64",)),
        sr.PinnedBinary("demo-b", "tool-b", "1.0", ("linux/arm64",)),
    )
    ways = {path for row in sr.no_build_rows(binaries) for path in row.paths}
    assert ways >= {
        "wsl2",
        "container-image",
        "linux-or-macos-host",
        "x86-host-with-features",
        "ci-runner",
        "arm64-host",
    }
    section = _section(sr.NO_BUILD_ANCHOR)
    assert [path for path in sorted(ways) if f"](#{path})" not in section] == []


def test_the_no_build_section_says_a_mac_scans_in_the_container_image() -> None:
    """The sentence about a Mac and the ways out the register lists for a Mac's gap are
    one claim: the image, and only the image. WSL 2 is offered from Windows only, and
    the path to Linux or macOS is offered from Windows and from other systems, so
    neither leads out of a gap on a Mac."""
    assert_on_page(PAGE, "From a Mac, scan in the container image.")
    for gap in ("darwin/amd64", "darwin/arm64"):
        binary = sr.PinnedBinary("demo", "demo-tool", "1.0", all_platforms_but(gap))
        (row,) = sr.no_build_rows((binary,))
        assert row.paths == ("container-image",), gap


def test_the_guarddog_section_links_each_way_out_of_a_missing_kernel_sandbox() -> None:
    """GuardDog's own sandbox needs the kernel that runs the scanner: this machine's on
    a Linux host, and the container engine's virtual machine in container mode on any
    other host. The row lists both ways out, and its section links both."""
    row = sr.REGISTER.row("scanner.guarddog.sandbox-unavailable")
    assert row.paths == ("enable-landlock", "engine-landlock")
    section = _section(row.anchor)
    assert [path for path in row.paths if f"](#{path})" not in section] == []


#: The one sentence on the page that depends on which tools the scanners declare, and
#: how many tools it needs: the page says "several".
SEVERAL_TOOLS = "Several tools have no build for Windows on arm64, for example."
SEVERAL = 2


def _windows_arm64_rows() -> list[sr.SupportRow]:
    """The missing-build rows for Windows on arm64 that the shipped scanners derive.

    Only the shipped scanners are read: a tool added to the list of binaries here would
    keep the count up whatever the scanners declare."""
    classes, _errors = load_scanner_universe()
    rows = sr.no_build_rows(pinned_binaries(classes))
    return [row for row in rows if gap_platform(row) == "windows/arm64"]


def test_the_page_says_several_tools_lack_a_windows_arm64_build() -> None:
    """The page says several tools have no build for Windows on arm64, and the register
    derives a row for each tool that lacks one. The sentence is pinned, and it holds
    while at least two of the shipped scanners declare the gap: when the scanners gain
    the build, this fails until the sentence says what is left."""
    assert_on_page(PAGE, SEVERAL_TOOLS)
    rows = _windows_arm64_rows()
    assert len(rows) >= SEVERAL, (
        "the page says several tools have no build for Windows on arm64, but the "
        f"shipped scanners declare the gap for {sorted(row.scope for row in rows)}; "
        "reword the sentence to what they declare, or change this check with it"
    )


def _windows_arm64_rows_of(*scanners: str) -> list[sr.SupportRow]:
    """The Windows on arm64 rows of planted tools that lack only that build."""
    lacking = all_platforms_but("windows/arm64")
    binaries = [
        sr.PinnedBinary(name, f"{name}-tool", "1.0", lacking) for name in scanners
    ]
    rows = sr.no_build_rows(binaries)
    return [row for row in rows if gap_platform(row) == "windows/arm64"]


def test_the_several_tools_check_fails_below_two_scanners(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The must-fail control for the check above, run on the check itself: with no
    scanner or one scanner that lacks the build the page's plural is false and the
    check fails, and with two it passes. The rows here are planted, and the check above
    is the only one that reads the shipped scanners."""
    check = test_the_page_says_several_tools_lack_a_windows_arm64_build
    for scanners in ((), ("demo-a",)):
        rows = _windows_arm64_rows_of(*scanners)
        monkeypatch.setitem(globals(), "_windows_arm64_rows", lambda rows=rows: rows)
        with pytest.raises(AssertionError, match="several tools have no build"):
            check()
    rows = _windows_arm64_rows_of("demo-a", "demo-b")
    monkeypatch.setitem(globals(), "_windows_arm64_rows", lambda: rows)
    check()


def test_the_page_does_not_say_that_ash_shows_a_notice() -> None:
    """The page describes what is declared and does not claim that ASH shows a notice.

    A page may claim only what ASH does. A sentence that says a notice appears is true
    once ASH shows one, and the change that does that rewrites this check with the page.
    """
    text = " ".join((CONTENT / PAGE).read_text(encoding="utf-8").split())
    assert "notice" not in text.lower(), (
        "the page says ASH shows a notice; describe what the register declares, or "
        "change this check together with the change that makes ASH show one"
    )
