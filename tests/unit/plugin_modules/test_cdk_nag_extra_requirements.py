# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_cdk_extra_requirements`` must never resolve to "install nothing".

The failure mode being pinned
----------------------------
``ash dependencies install`` reports success purely by process exit code. So a
resolver that returns ``[]`` produces no pip command, exits 0, and leaves cdk-nag
MISSING -- a green install that installed nothing. That is the original defect
this resolver was written to remove, and it came back through a different door:
``packages_distributions()`` maps a top-level package name to a *list* of
distributions, and the loop returned on the first entry whose ``requires()`` was
not None whether or not any requirement carried the ``extra == "cdk"`` marker.
One stale or shadowing ``*.dist-info`` -- an editable install left next to a real
one -- was enough.

Why these tests fake importlib.metadata rather than build a real distribution
----------------------------------------------------------------------------
Installing a second distribution that shadows ASH's own top-level package inside
a test run would change what every other test imports. The two functions the
resolver calls, ``packages_distributions`` and ``requires``, are the entire
interface to that metadata, so patching them at the module boundary reproduces
each shape exactly and cannot leak.

The ``[None]`` case is not hypothetical. A ``*.dist-info`` carrying a
``top_level.txt`` but no ``METADATA`` makes the real
``importlib.metadata.packages_distributions()`` yield a list containing None, and
the real ``requires(None)`` raises ``ValueError``, which the resolver's original
``except (PackageNotFoundError, OSError)`` did not catch. That was an outright
crash in ``ash dependencies install``, not a silent no-op.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cdk_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    _CDK_EXTRA_FALLBACK_REQUIREMENTS,
    _cdk_extra_requirements,
)

#: The top-level package the resolver asks about. Derived the same way the
#: resolver derives it, so a package rename cannot make these tests stale while
#: still looking green.
ROOT = cdk_nag_scanner.__name__.split(".", 1)[0]

# The version bounds below are deliberately NOT the ones in
# _CDK_EXTRA_FALLBACK_REQUIREMENTS, and that is the whole reason they are written
# out rather than imported. Mutation caught the alternative: an earlier draft used
# the real bounds, which made the metadata-derived answer byte-identical to the
# fallback, so every assertion passed whether the resolver read the distribution
# it was supposed to read or gave up and returned pins. Changing `continue` to
# `break` in the per-name error handler -- which discards every distribution after
# the first unreadable one -- changed no test result.
#
# Markers are rendered with single quotes by importlib.metadata and double quotes
# by pyproject.toml and pip, so both spellings appear here.
REAL_CDK_REQUIREMENTS = [
    'aws-cdk-lib>=9.900.0,<10.0.0; extra == "cdk"',
    "cdk-nag>=9.9.0,<10.0.0; extra == 'cdk'",
    'constructs>=9.9.0,<10.0.0; extra == "cdk"',
]

BARE_CDK_REQUIREMENTS = [
    "aws-cdk-lib>=9.900.0,<10.0.0",
    "cdk-nag>=9.9.0,<10.0.0",
    "constructs>=9.9.0,<10.0.0",
]


def test_fixture_requirements_differ_from_the_fallback() -> None:
    """The fixtures must be distinguishable from the fallback list.

    Without this, a resolver that always returned the fallback would satisfy every
    "it read the metadata" assertion in this file. Asserted rather than left to a
    comment because the fallback tracks pyproject.toml, so a future bump could
    collide with these fixtures by accident.
    """
    assert set(BARE_CDK_REQUIREMENTS).isdisjoint(_CDK_EXTRA_FALLBACK_REQUIREMENTS)


#: A distribution that declares requirements but no cdk extra -- the shape that
#: used to short-circuit the loop and yield an empty list.
NO_CDK_EXTRA_REQUIREMENTS = [
    "pydantic>=2.0.0",
    'pytest>=8.0.0; extra == "dev"',
]


@pytest.fixture
def fake_metadata(monkeypatch):
    """Install a fake ``packages_distributions``/``requires`` pair.

    Returns a callable taking the distribution-name list the mapping should
    report and a dict from distribution name to what ``requires`` should do --
    either a list, None, or an exception instance to raise.
    """

    def _install(dist_names, requires_by_name):
        monkeypatch.setattr(
            cdk_nag_scanner, "packages_distributions", lambda: {ROOT: dist_names}
        )

        def _fake_requires(name):
            outcome = requires_by_name[name]
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        monkeypatch.setattr(cdk_nag_scanner, "requires", _fake_requires)

    return _install


class TestHealthyMetadata:
    def test_markers_are_stripped_and_only_cdk_requirements_are_kept(
        self, fake_metadata
    ) -> None:
        fake_metadata(
            ["automated-security-helper"],
            {
                "automated-security-helper": REAL_CDK_REQUIREMENTS
                + NO_CDK_EXTRA_REQUIREMENTS
            },
        )
        assert _cdk_extra_requirements() == BARE_CDK_REQUIREMENTS

    def test_declaration_order_is_preserved(self, fake_metadata) -> None:
        """pip receives the order pyproject.toml declares.

        Deduplicating through a set would reorder the command between runs, which
        is noise in any log that records it.
        """
        fake_metadata(["ash"], {"ash": list(reversed(REAL_CDK_REQUIREMENTS))})
        assert _cdk_extra_requirements() == list(reversed(BARE_CDK_REQUIREMENTS))


class TestShadowedOrStaleDistribution:
    """The finding itself: a first entry with no cdk extra must not win."""

    def test_a_stale_sibling_does_not_mask_the_real_distribution(
        self, fake_metadata
    ) -> None:
        fake_metadata(
            ["stale-editable-ash", "automated-security-helper"],
            {
                "stale-editable-ash": NO_CDK_EXTRA_REQUIREMENTS,
                "automated-security-helper": REAL_CDK_REQUIREMENTS,
            },
        )
        assert _cdk_extra_requirements() == BARE_CDK_REQUIREMENTS

    def test_a_lone_distribution_with_no_cdk_extra_falls_back(
        self, fake_metadata
    ) -> None:
        """Empty is never an answer here.

        The resolver is only called when cdk-nag is already missing, so returning
        [] means exit 0 with cdk-nag still MISSING.
        """
        fake_metadata(["ash"], {"ash": NO_CDK_EXTRA_REQUIREMENTS})
        assert _cdk_extra_requirements() == list(_CDK_EXTRA_FALLBACK_REQUIREMENTS)

    def test_requirements_are_unioned_across_distributions_without_duplicates(
        self, fake_metadata
    ) -> None:
        fake_metadata(
            ["ash-a", "ash-b"],
            {
                "ash-a": REAL_CDK_REQUIREMENTS[:2],
                "ash-b": REAL_CDK_REQUIREMENTS[1:],
            },
        )
        assert _cdk_extra_requirements() == BARE_CDK_REQUIREMENTS


class TestUnreadableMetadata:
    def test_a_none_distribution_name_does_not_crash(self, fake_metadata) -> None:
        """A dist-info with a top_level.txt but no METADATA yields [None].

        The real ``requires(None)`` raises ValueError, which the original
        two-exception clause did not catch, so this crashed the command.
        """
        fake_metadata(
            [None, "automated-security-helper"],
            {
                None: ValueError("A distribution name is required."),
                "automated-security-helper": REAL_CDK_REQUIREMENTS,
            },
        )
        assert _cdk_extra_requirements() == BARE_CDK_REQUIREMENTS

    def test_a_vanished_distribution_does_not_discard_a_good_sibling(
        self, fake_metadata
    ) -> None:
        """Per-iteration handling, not one try around the whole loop.

        A concurrent uninstall makes ``requires`` raise PackageNotFoundError for
        one name. Wrapping the loop would throw away what the other names
        declared and fall back to pins nobody reviewed.
        """
        fake_metadata(
            ["gone", "automated-security-helper"],
            {
                "gone": PackageNotFoundError("gone"),
                "automated-security-helper": REAL_CDK_REQUIREMENTS,
            },
        )
        assert _cdk_extra_requirements() == BARE_CDK_REQUIREMENTS

    def test_no_mapping_at_all_falls_back(self, monkeypatch) -> None:
        """ASH run from a checkout that was never installed.

        This reaches the fallback by the normal path -- the mapping has no entry,
        so the loop body never runs -- and not through the exception handler,
        which is what the resolver's docstring used to claim.
        """
        monkeypatch.setattr(cdk_nag_scanner, "packages_distributions", lambda: {})
        assert _cdk_extra_requirements() == list(_CDK_EXTRA_FALLBACK_REQUIREMENTS)

    def test_requires_returning_none_falls_back(self, fake_metadata) -> None:
        fake_metadata(["ash"], {"ash": None})
        assert _cdk_extra_requirements() == list(_CDK_EXTRA_FALLBACK_REQUIREMENTS)


#: Every degenerate metadata shape reachable from the two importlib calls. Each
#: entry is (dist-name list, requires outcome by name).
DEGENERATE_SHAPES = {
    "no mapping for the top-level package": ([], {}),
    "one distribution declaring nothing": (["ash"], {"ash": None}),
    "one distribution with no cdk extra": (["ash"], {"ash": NO_CDK_EXTRA_REQUIREMENTS}),
    "every distribution unreadable": (
        ["a", "b"],
        {"a": PackageNotFoundError("a"), "b": OSError("no perms")},
    ),
    "a None distribution name": ([None], {None: ValueError("name required")}),
    "an empty requirement list": (["ash"], {"ash": []}),
    "a cdk marker on a blank requirement": (
        ["ash"],
        {"ash": ['   ; extra == "cdk"']},
    ),
}


@pytest.mark.parametrize("shape", list(DEGENERATE_SHAPES), ids=list(DEGENERATE_SHAPES))
def test_never_resolves_to_install_nothing(fake_metadata, shape) -> None:
    """The contract that makes the whole area safe: the result is never empty.

    ``get_installation_commands`` appends the pip invocation unconditionally, so
    an empty result would produce ``pip install`` with no arguments. The old
    ``if requirements:`` guard turned that into no command at all, exit 0, and
    cdk-nag still MISSING. Every shape below used to be able to produce it.
    """
    dist_names, requires_by_name = DEGENERATE_SHAPES[shape]
    fake_metadata(dist_names, requires_by_name)
    assert _cdk_extra_requirements() == list(_CDK_EXTRA_FALLBACK_REQUIREMENTS)
