"""What the supported-configurations page says, held to the register that declares it.

The page explains each configuration ASH supports, runs through a stand-in, runs with a
named loss or does not support, and each way out of one. The register in
``automated_security_helper/base/support_register.py`` declares the same rows and ways
out as data, and the page carries their sentences word for word. This module pins those
sentences the way test_page_claims.py pins the rest of the pages: ``assert_on_page``
checks that the sentence is still on its page, so a rewording on either side fails
here with the page and the heading of the closest paragraph named.

What it pins on how-to/supported-configurations.md:

- the sentence a declared row prints, for every row that is not plainly supported;
- the sentence each way out offers;
- the name of each stand-in and each adaptation.

The structure of the page (its sections, anchors and place in the navigation) and the
register's own rules are held in tests/unit/base/test_support_register.py. Nothing here
starts a scanner or reads the host.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base import support_register as sr
from tests.unit.docs.test_page_claims import assert_on_page

pytestmark = pytest.mark.unit

PAGE = "how-to/supported-configurations.md"

DECLARED_ROWS = [
    row for row in sr.REGISTER.rows if row.level is not sr.SupportLevel.SUPPORTED
]


def test_the_pin_reads_a_register_that_declares_rows_ways_out_and_stand_ins() -> None:
    """A register that declared nothing would pin nothing and pass."""
    assert DECLARED_ROWS
    assert sr.REGISTER.paths
    assert sr.REGISTER.polyfills


@pytest.mark.parametrize("row", DECLARED_ROWS, ids=lambda row: row.id)
def test_the_page_carries_what_a_declared_row_says(row: sr.SupportRow) -> None:
    assert_on_page(PAGE, row.message)


@pytest.mark.parametrize("path", sr.REGISTER.paths, ids=lambda path: path.id)
def test_the_page_carries_what_a_way_out_offers(path: sr.UpgradePath) -> None:
    assert_on_page(PAGE, path.summary)


@pytest.mark.parametrize("polyfill", sr.REGISTER.polyfills, ids=lambda p: p.id)
def test_the_page_names_each_stand_in_and_adaptation(polyfill: sr.Polyfill) -> None:
    assert_on_page(PAGE, polyfill.name)
