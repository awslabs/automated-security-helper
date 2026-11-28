"""Where scripts/generate_support_matrices.py writes. Data only.

Why a file of data
------------------
The generator writes a matrix into two kinds of place, and the docs checks need to know
both without importing anything. This file is plain literals, so the generator reads it
with ``ast`` (``load_destinations``), and ``scripts/docs_checks.py`` reads ``BLOCKS`` the
same way it reads the list of generated reference pages: a check that ran the generator
to learn what the generator owns would run the code it is there to hold to account.

``PAGES``
    A whole page the generator writes. Each entry names its repository-relative
    ``file``, its ``title``, ``source`` (a phrase that completes "generated from"), an
    ``intro`` that says how to read a cell, and the ``sections`` it holds, each the name
    of a matrix, in the order they appear. The heading of a section is the matrix's
    title, and the id of that heading is the matrix's name, so a link to
    ``#<matrix name>`` holds.

``BLOCKS``
    A region of a page a person writes, between a pair of markers::

        <!-- BEGIN generated: support/scanners.readme (scripts/generate_support_matrices.py) -->
        <!-- END generated: support/scanners.readme -->

    Each entry names the ``file`` (a page, or its ``.template``, which are one unit),
    the ``block`` (its name in the markers), the ``matrix`` it renders and the ``view``
    ("readme" or "docs"). It may add ``rows``, a mapping from a column key to the one
    value a row must have to appear, and ``row_cap_exempt`` with ``collapsed`` for a
    README block that lists more rows than the README budget allows inside a collapsed
    element.

A block belongs here in the same change that puts its markers into a page, and a pair of
markers that names the generator and has no entry here is refused by the docs checks, as
is an entry whose markers are missing.
"""

PAGES = (
    {
        "file": "docs/content/reference/support-matrix.md",
        "title": "Support matrix",
        "source": (
            "the scanner manifests, the operational facets register and each "
            "scanner's own platform refusal"
        ),
        "intro": (
            "Each table says what ASH supports, with one row for every item the code "
            "knows about. A cell holds a name taken from the code or one phrase from a "
            "fixed set, and the notes under a table explain every phrase it uses. A "
            "cell never says more than the code states: where a fact was not declared "
            "or not measured, the cell says that."
        ),
        "sections": ("scanners",),
    },
)

BLOCKS = ()
