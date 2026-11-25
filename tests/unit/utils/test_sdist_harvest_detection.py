# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Detection contract of the sdist lockfile harvest (design row A1, test row 2).

A resolved dependency is flagged for harvest exactly when its ``uv.lock`` entry
names at least one platform wheel: a wheel whose filename carries a platform tag
other than ``any`` means compiled native extensions, which can statically link
another toolchain's packages that no lockfile in the scanned tree describes. A
package resolved only as pure-Python wheels (``py*-none-any``) cannot, so it is
never flagged, and never fetched.

The flag is read from the lockfile alone -- no artifact is downloaded to make
the decision -- which is why these tests feed bytes, not a network.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.sdist_harvest import (
    flagged_packages_in_uv_lock,
    is_platform_wheel_filename,
)

pytestmark = pytest.mark.unit

UV_LOCK_WITH_PLATFORM_WHEEL = b"""
version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "fixturepkg"
version = "0.1.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.test.invalid/fixturepkg-0.1.0.tar.gz", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", size = 1234 }
wheels = [
    { url = "https://files.test.invalid/fixturepkg-0.1.0-cp312-cp312-manylinux_2_17_x86_64.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", size = 2345 },
]

[[package]]
name = "purepkg"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.test.invalid/purepkg-2.0.0.tar.gz", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", size = 999 }
wheels = [
    { url = "https://files.test.invalid/purepkg-2.0.0-py3-none-any.whl", hash = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", size = 888 },
]
"""


class TestPlatformWheelFilename:
    """The wheel filename tag is the machine-readable native-payload signal."""

    @pytest.mark.parametrize(
        "filename",
        [
            "fixturepkg-0.1.0-cp312-cp312-manylinux_2_17_x86_64.whl",
            "polars_runtime_32-1.44.2-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
            "polars_runtime_32-1.44.2-cp310-abi3-win_arm64.whl",
            "polars_runtime_32-1.44.2-cp310-abi3-macosx_11_0_arm64.whl",
            "cryptography-42.0.0-cp39-abi3-musllinux_1_2_aarch64.whl",
        ],
    )
    def test_platform_tagged_wheels_are_flagged(self, filename: str) -> None:
        assert is_platform_wheel_filename(filename)

    @pytest.mark.parametrize(
        "filename",
        [
            "purepkg-2.0.0-py3-none-any.whl",
            "six-1.16.0-py2.py3-none-any.whl",
            "somepkg-1.0-cp312-none-any.whl",
        ],
    )
    def test_pure_python_wheels_are_not_flagged(self, filename: str) -> None:
        assert not is_platform_wheel_filename(filename)

    @pytest.mark.parametrize(
        "filename",
        [
            "not-a-wheel-1.0.tar.gz",
            "mangled.whl",
            "fixturepkg-0.1.0.whl",
        ],
    )
    def test_names_that_are_not_wheel_filenames_are_not_flagged(
        self, filename: str
    ) -> None:
        """A name the wheel grammar cannot parse is never a harvest trigger: the
        conservative side is to not fetch."""
        assert not is_platform_wheel_filename(filename)


class TestFlaggedPackages:
    def test_platform_wheel_entry_is_flagged_with_its_sdist_pin(self) -> None:
        flagged = flagged_packages_in_uv_lock(UV_LOCK_WITH_PLATFORM_WHEEL, "uv.lock")
        assert [p.name for p in flagged] == ["fixturepkg"]
        (pkg,) = flagged
        assert pkg.version == "0.1.0"
        assert pkg.sdist_url == "https://files.test.invalid/fixturepkg-0.1.0.tar.gz"
        assert pkg.sdist_sha256 == "a" * 64
        assert pkg.sdist_size == 1234
        assert pkg.parent_purl == "pkg:pypi/fixturepkg@0.1.0"
        assert pkg.lock_display == "uv.lock"

    def test_pure_python_entry_is_not_flagged(self) -> None:
        flagged = flagged_packages_in_uv_lock(UV_LOCK_WITH_PLATFORM_WHEEL, "uv.lock")
        assert "purepkg" not in [p.name for p in flagged]

    def test_platform_wheel_entry_without_an_sdist_is_flagged_with_no_pin(self) -> None:
        """A flagged package whose entry pins no sdist cannot be harvested; it is
        still reported so the skip is a visible fact, not a silent gap."""
        lock = b"""
version = 1

[[package]]
name = "wheelonly"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.test.invalid/wheelonly-3.0.0-cp312-cp312-win_amd64.whl", hash = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" },
]
"""
        flagged = flagged_packages_in_uv_lock(lock, "uv.lock")
        assert [p.name for p in flagged] == ["wheelonly"]
        assert flagged[0].sdist_url is None
        assert flagged[0].sdist_sha256 is None

    def test_sdist_hash_that_is_not_sha256_is_not_a_pin(self) -> None:
        """Only a sha256 pin authorizes a fetch: the verification before
        extraction is against exactly this value."""
        lock = b"""
version = 1

[[package]]
name = "oddhash"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.test.invalid/oddhash-1.0.0.tar.gz", hash = "md5:ffffffffffffffffffffffffffffffff" }
wheels = [
    { url = "https://files.test.invalid/oddhash-1.0.0-cp312-cp312-win_amd64.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111" },
]
"""
        flagged = flagged_packages_in_uv_lock(lock, "uv.lock")
        assert [p.name for p in flagged] == ["oddhash"]
        assert flagged[0].sdist_url == "https://files.test.invalid/oddhash-1.0.0.tar.gz"
        assert flagged[0].sdist_sha256 is None

    def test_a_lockfile_that_is_not_toml_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            flagged_packages_in_uv_lock(b"not toml {{{{", "uv.lock")

    def test_workspace_members_without_wheels_are_not_flagged(self) -> None:
        lock = b"""
version = 1

[[package]]
name = "local-member"
version = "0.0.1"
source = { editable = "." }
"""
        assert flagged_packages_in_uv_lock(lock, "uv.lock") == []

    @pytest.mark.parametrize(
        "name,digest",
        [("../x", "a" * 64), ("okpkg", "z" * 64), ("okpkg", "a" * 63)],
    )
    def test_entry_with_an_invalid_name_or_pin_is_marked_rejected(
        self, name: str, digest: str
    ) -> None:
        lock = f"""
version = 1

[[package]]
name = "{name}"
version = "1.0.0"
source = {{ registry = "https://pypi.org/simple" }}
sdist = {{ url = "https://files.test.invalid/x-1.0.0.tar.gz", hash = "sha256:{digest}" }}
wheels = [
    {{ url = "https://files.test.invalid/x-1.0.0-cp312-cp312-win_amd64.whl", hash = "sha256:{"1" * 64}" }},
]
""".encode()
        (package,) = flagged_packages_in_uv_lock(lock, "uv.lock")
        assert package.rejected_reason
