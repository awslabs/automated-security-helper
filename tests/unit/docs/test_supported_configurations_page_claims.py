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
  configuration is described.

The page describes what the register declares. It does not say that ASH shows a notice,
because a page may claim only what ASH does: the change that makes ASH show one rewrites
those sentences and the last test here together.

The structure of the page (its sections, anchors and place in the navigation) and the
register's own rules are held in tests/unit/base/test_support_register.py. Nothing here
starts a scanner or reads the host.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base import support_register as sr
from tests.unit.docs.test_page_claims import CONTENT, assert_on_page

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
