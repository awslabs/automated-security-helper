# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The install-package facet is declared data, consistent with the providers.

Every row names an ecosystem that is an implemented install provider (a row for a
stub would promise a route that refuses), a row's package is not blank, a tool is
declared once, no two rows of one ecosystem overlap in host match (today's rows name
no host, so a tool has one row per ecosystem), and the Nix rows name the flake output
the repository actually builds.

Host matching is held over planted rows: the register's rows name no host yet, so a
real-register run cannot tell a matcher that routes on ``ID_LIKE`` from one that does
not. Each refusal has a control that matches, so a pass is the matcher declining and
not a malformed fixture.
"""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest

from automated_security_helper.base import install_package_facets as ipf
from automated_security_helper.base.install_package_facets import (
    DEFAULT_PREFERENCE,
    INSTALL_PACKAGE_FACETS,
    NIX_FLAKE_OUTPUT,
    install_package_facet,
)
from automated_security_helper.utils.install_providers import INSTALL_PROVIDERS

pytestmark = pytest.mark.unit


def test_every_row_names_an_implemented_provider_and_a_package():
    for tool, facet in INSTALL_PACKAGE_FACETS.items():
        assert facet.tool == tool
        assert facet.rows, tool
        for row in facet.rows:
            provider = INSTALL_PROVIDERS.get(row.ecosystem)
            assert provider is not None and provider.implemented, (tool, row)
            assert row.package.strip(), (tool, row)
        for first, second in itertools.combinations(facet.rows, 2):
            assert not first.overlaps(second), (tool, first, second)


def test_every_preferred_ecosystem_is_a_known_provider():
    for facet in INSTALL_PACKAGE_FACETS.values():
        for name in facet.preference:
            assert name in INSTALL_PROVIDERS, (facet.tool, name)
    assert set(DEFAULT_PREFERENCE) <= set(INSTALL_PROVIDERS)


def test_a_row_that_installs_other_than_the_declared_range_says_so():
    for facet in INSTALL_PACKAGE_FACETS.values():
        for row in facet.rows:
            assert row.caveat, (facet.tool, row.ecosystem)


def test_the_nix_row_names_the_flake_output_the_repository_builds():
    flake = (Path(__file__).parents[3] / "flake.nix").read_text(encoding="utf-8")

    assert f"{NIX_FLAKE_OUTPUT} = pkgs.buildEnv" in flake
    for facet in INSTALL_PACKAGE_FACETS.values():
        row = facet.row_for("nix")
        if row is not None:
            assert row.package == NIX_FLAKE_OUTPUT


def test_an_undeclared_tool_has_no_facet():
    assert install_package_facet("not-a-tool") is None
    assert install_package_facet(None) is None
    assert install_package_facet("checkov") is INSTALL_PACKAGE_FACETS["checkov"]


# ---------------------------------------------------------------------------
# The register's rows are the rows it had before hosts existed
# ---------------------------------------------------------------------------

_TOOLS = (
    "actionlint",
    "bandit",
    "betterleaks",
    "cfn-guard",
    "cfn-lint",
    "cfn-nag",
    "checkov",
    "detect-secrets",
    "gitleaks",
    "grype",
    "hadolint",
    "opengrep",
    "semgrep",
    "syft",
    "trivy",
    "zizmor",
)
_WITHOUT_A_BREW_ROW = frozenset({"cfn-guard", "cfn-nag", "opengrep"})


def test_the_register_keeps_its_sixteen_tools_and_every_row_it_had():
    """Host fields were added to the row type and no row changed. A later unit that
    adds per-OS rows updates this pin with them."""
    assert tuple(sorted(INSTALL_PACKAGE_FACETS)) == _TOOLS
    for tool in _TOOLS:
        expected = [] if tool in _WITHOUT_A_BREW_ROW else [("brew", tool)]
        expected.append(("nix", NIX_FLAKE_OUTPUT))
        rows = INSTALL_PACKAGE_FACETS[tool].rows
        assert [(row.ecosystem, row.package) for row in rows] == expected, tool


def test_no_declared_row_names_a_host_or_a_new_field():
    for facet in INSTALL_PACKAGE_FACETS.values():
        for row in facet.rows:
            assert row.hosts == (), (facet.tool, row.ecosystem)
            assert row.repository is None
            assert row.upstream is None
            assert row.source is None
            assert row.read_on is None
            assert row.version_read is None
            assert row.hint_only is False


# ---------------------------------------------------------------------------
# Host-aware rows
# ---------------------------------------------------------------------------


def _row(ecosystem="apt", package="jq", hosts=()):
    return ipf.EcosystemPackage(ecosystem, package, "a caveat", hosts=hosts)


def _on(os_id, *versions):
    """The ``hosts`` of a row declared for one id and the releases it was read on."""
    return (ipf.HostMatch(ids=(os_id,), versions=versions),)


def _host(os_id, version_id="", id_like=()):
    return ipf.OsRelease(id=os_id, version_id=version_id, id_like=id_like)


def test_a_fedora_row_never_matches_a_host_that_only_names_fedora_in_id_like():
    """Rocky, AlmaLinux, RHEL and Amazon Linux 2023 carry ``fedora`` in ID_LIKE, and
    a ``grype`` row read on Fedora would route onto every one of them."""
    row = _row("dnf", "grype", hosts=_on("fedora", "43", "44"))
    facet = ipf.InstallPackageFacet(tool="grype", rows=(row,), preference=())
    rocky = _host("rocky", "9.6", ("rhel", "centos", "fedora"))
    amzn = _host("amzn", "2023", ("fedora",))

    assert facet.row_for("dnf", rocky) is None
    assert facet.row_for("dnf", amzn) is None
    # The controls: the hosts the row is declared for still match it, and a release
    # it was not read on does not.
    assert facet.row_for("dnf", _host("fedora", "43")) is row
    assert facet.row_for("dnf", _host("fedora", "44")) is row
    assert facet.row_for("dnf", _host("fedora", "45")) is None


def test_the_id_is_matched_exactly_and_id_like_is_never_read():
    ubuntu = ipf.HostMatch(ids=("ubuntu",))
    assert ubuntu.matches(_host("ubuntu", "24.04"))
    assert not ubuntu.matches(_host("pop", "24.04", ("ubuntu", "debian")))
    assert not ubuntu.matches(_host("Ubuntu", "24.04"))
    assert not ubuntu.matches(_host("ubuntu-core", "24"))


@pytest.mark.parametrize(
    ("version_id", "expected"),
    [
        ("3.24", True),
        ("3.24.4", True),
        ("3.240", False),
        ("3.2", False),
        ("3.25", False),
        ("", False),
    ],
)
def test_a_version_matches_when_it_equals_the_prefix_or_starts_with_it_and_a_dot(
    version_id, expected
):
    match = ipf.HostMatch(ids=("alpine",), versions=("3.24",))
    assert match.matches(_host("alpine", version_id)) is expected


def test_several_ids_and_versions_are_alternatives():
    match = ipf.HostMatch(ids=("rhel", "rocky", "almalinux"), versions=("9", "10"))
    for os_id in ("rhel", "rocky", "almalinux"):
        assert match.matches(_host(os_id, "9.6"))
        assert match.matches(_host(os_id, "10"))
        assert not match.matches(_host(os_id, "8.10"))


def test_a_host_match_with_no_versions_matches_every_version_of_its_ids():
    rolling = ipf.HostMatch(ids=("opensuse-tumbleweed",))
    assert rolling.matches(_host("opensuse-tumbleweed", "20261101"))
    assert rolling.matches(_host("opensuse-tumbleweed"))
    assert not rolling.matches(_host("opensuse-leap", "16.0"))


def test_a_host_match_names_at_least_one_id():
    with pytest.raises(ValueError):
        ipf.HostMatch(ids=())
    with pytest.raises(ValueError):
        ipf.HostMatch(ids=("debian", " "))


def test_row_for_prefers_a_host_row_then_the_row_without_hosts_then_nothing():
    anywhere = _row("apt", "jq-anywhere")
    debian_13 = _row("apt", "jq-debian-13", hosts=_on("debian", "13"))
    facet = ipf.InstallPackageFacet(
        tool="jq", rows=(anywhere, debian_13), preference=()
    )

    # A host row wins over a row listed before it that names no host.
    assert facet.row_for("apt", _host("debian", "13.1")) is debian_13
    assert facet.row_for("apt", _host("debian", "12")) is anywhere
    # An unread host (None, or no argument) is served only by a row with no host.
    assert facet.row_for("apt", None) is anywhere
    assert facet.row_for("apt") is anywhere
    assert facet.row_for("dnf", _host("debian", "13")) is None

    only_host = ipf.InstallPackageFacet(tool="jq", rows=(debian_13,), preference=())
    assert only_host.row_for("apt") is None
    assert only_host.row_for("apt", None) is None
    assert only_host.row_for("apt", _host("debian", "13")) is debian_13


def test_two_rows_overlap_when_one_host_can_match_both():
    debian_13 = _row("apt", hosts=_on("debian", "13"))
    debian_13_1 = _row("apt", hosts=_on("debian", "13.1"))
    debian_12 = _row("apt", hosts=_on("debian", "12"))
    debian_1 = _row("apt", hosts=_on("debian", "1"))
    ubuntu_13 = _row("apt", hosts=_on("ubuntu", "13"))
    any_debian = _row("apt", hosts=_on("debian"))
    anywhere = _row("apt")
    other_manager = _row("dnf", hosts=_on("debian", "13"))

    # 13.1.5 matches both "13" and "13.1".
    assert debian_13.overlaps(debian_13_1) and debian_13_1.overlaps(debian_13)
    # Different releases, different ids, and "1" against "13" (no dot boundary).
    assert not debian_13.overlaps(debian_12)
    assert not debian_13.overlaps(ubuntu_13)
    assert not debian_1.overlaps(debian_13)
    # No versions means every version; no hosts means every host.
    assert any_debian.overlaps(debian_13) and any_debian.overlaps(debian_12)
    assert not any_debian.overlaps(ubuntu_13)
    assert anywhere.overlaps(debian_12) and debian_12.overlaps(anywhere)
    assert anywhere.overlaps(_row("apt", "another-name"))
    # Rows of two ecosystems never compete.
    assert not debian_13.overlaps(other_manager)


def test_the_collision_and_runtime_tables_exist_and_are_empty():
    """Declared here, filled by the unit that reads the package indexes."""
    assert ipf.KNOWN_COLLISIONS == ()
    assert dict(ipf.RUNTIME_PACKAGES) == {}
    collision = ipf.PackageCollision(
        ecosystem="apt", package="a-trap", reason="a different tool of that name"
    )
    assert collision.hosts == ()


def test_an_os_release_is_a_value():
    first = _host("debian", "13", ("debian",))
    assert first == _host("debian", "13", ("debian",))
    assert len({first, _host("debian", "13", ("debian",))}) == 1
    assert _host("alpine").version_id == "" and _host("alpine").id_like == ()
