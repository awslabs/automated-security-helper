# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The cross-scanner correlation-id families: spelling, sharing and absence.

The compat vectors pin the full ``secret/<64 hex>`` and ``dep/<64 hex>``
strings byte-for-byte against constants computed once by hand from the
reference spelling, ``<prefix> + sha256(json.dumps([target, key],
sort_keys=True))``; any later drift in the hash, the key field names or their
order trips them. The spelling-equality tests pin the invariant behind
computing the id once: the file, project and tree values the ``secret/`` key
hashes are byte-equal to what ``identity_key`` emits for the same inputs.
"""

import pytest

from automated_security_helper.utils.finding_identity import (
    CORRELATION_PREFIXES,
    DEFAULT_CORRELATION_TARGET,
    DEP_CORRELATION_PREFIX,
    IAC_CORRELATION_PREFIX,
    SECRET_CORRELATION_PREFIX,
    correlation_id,
    correlation_target,
    dep_correlation_key,
    finding_identity,
    identity_key,
    secret_correlation_key,
)

pytestmark = pytest.mark.unit


def _secret_identity(**overrides):
    fields = {
        "scanner": "scanner-a",
        "rule_id": "SECRET-1",
        "file_path": "src/app.py",
        "line_start": 12,
        "line_end": 12,
        "workspace_project": "web",
    }
    fields.update(overrides)
    return finding_identity(**fields)


class TestCompatVectors:
    """The pinned reference spelling, byte for byte."""

    def test_secret_vector_is_byte_identical_to_the_reference_spelling(self):
        # Pinned by hand from secret/<sha256(json.dumps([target, key],
        # sort_keys=True))> with target "example-target" and key
        # {"file": "src/app.py", "startLine": 12, "project": "web"}.
        key = secret_correlation_key(_secret_identity())
        assert key == {"file": "src/app.py", "startLine": 12, "project": "web"}
        assert correlation_id(SECRET_CORRELATION_PREFIX, "example-target", key) == (
            "secret/7b332c26f2b141d12f962ddcfc9a2461ce3650edb78e05c26770a5e900bfcc26"
        )

    def test_secret_vector_for_a_converted_file_with_no_project(self):
        # Pinned by hand: key {"file": "notebooks/leak.ipynb-converted.py",
        # "startLine": 3, "project": None, "tree": "converted"}.
        identity = _secret_identity(
            file_path="notebooks/leak.ipynb-converted.py",
            line_start=3,
            line_end=3,
            workspace_project=None,
            converted=True,
        )
        key = secret_correlation_key(identity)
        assert key == {
            "file": "notebooks/leak.ipynb-converted.py",
            "startLine": 3,
            "project": None,
            "tree": "converted",
        }
        assert correlation_id(SECRET_CORRELATION_PREFIX, "example-target", key) == (
            "secret/c79e5216e2cab534b8cd7535f0d399fc3e62a713822b14fecd5437f94a6c5030"
        )

    def test_dep_vector_upper_cases_the_advisory(self):
        # Pinned by hand: key {"advisory": "CVE-2024-12345", "package":
        # "lodash", "version": "4.17.20"}; the advisory arrives lower-cased.
        key = dep_correlation_key("cve-2024-12345", "lodash", "4.17.20")
        assert key == {
            "advisory": "CVE-2024-12345",
            "package": "lodash",
            "version": "4.17.20",
        }
        assert correlation_id(DEP_CORRELATION_PREFIX, "example-target", key) == (
            "dep/d85d6313eb57fb4342490c125c4ed0e521e872e7f14d2cb06f3b344113a864a9"
        )


class TestFamilySemantics:
    """Sharing, divergence and the closed registry."""

    def test_two_scanners_at_one_location_share_a_secret_id(self):
        ours = _secret_identity(scanner="scanner-a", rule_id="SECRET-1")
        theirs = _secret_identity(scanner="scanner-b", rule_id="generic.secret.9")
        assert identity_key(ours) != identity_key(theirs)
        first = correlation_id(
            SECRET_CORRELATION_PREFIX, "t", secret_correlation_key(ours)
        )
        second = correlation_id(
            SECRET_CORRELATION_PREFIX, "t", secret_correlation_key(theirs)
        )
        assert first == second
        assert first is not None and first.startswith("secret/")

    def test_a_different_start_line_is_a_different_secret_id(self):
        base = secret_correlation_key(_secret_identity(line_start=12))
        moved = secret_correlation_key(_secret_identity(line_start=13, line_end=13))
        assert correlation_id(SECRET_CORRELATION_PREFIX, "t", base) != correlation_id(
            SECRET_CORRELATION_PREFIX, "t", moved
        )

    def test_a_different_package_version_is_a_different_dep_id(self):
        vulnerable = dep_correlation_key("CVE-2024-12345", "lodash", "4.17.20")
        upgraded = dep_correlation_key("CVE-2024-12345", "lodash", "4.17.21")
        assert correlation_id(
            DEP_CORRELATION_PREFIX, "t", vulnerable
        ) != correlation_id(DEP_CORRELATION_PREFIX, "t", upgraded)

    def test_the_families_cannot_collide(self):
        # One payload under both prefixes: the prefix alone separates them.
        key = {"file": "src/app.py", "startLine": 12, "project": None}
        secret = correlation_id(SECRET_CORRELATION_PREFIX, "t", dict(key))
        dep = correlation_id(DEP_CORRELATION_PREFIX, "t", dict(key))
        assert secret != dep
        assert secret.split("/", 1)[1] == dep.split("/", 1)[1]

    def test_a_different_target_is_a_different_id(self):
        key = secret_correlation_key(_secret_identity())
        assert correlation_id(
            SECRET_CORRELATION_PREFIX, "repo-a", key
        ) != correlation_id(SECRET_CORRELATION_PREFIX, "repo-b", key)

    def test_the_prefix_registry_is_closed(self):
        with pytest.raises(ValueError):
            correlation_id("sast/", "t", {"file": "a"})
        # Reserved, not emitted: declared so nothing else takes the prefix.
        assert IAC_CORRELATION_PREFIX == "iac/"
        assert IAC_CORRELATION_PREFIX not in CORRELATION_PREFIXES
        with pytest.raises(ValueError):
            correlation_id(IAC_CORRELATION_PREFIX, "t", {"resource": "r"})


class TestSpellingEquality:
    """The values the secret/ key hashes are the identity key's own."""

    def test_file_project_and_tree_match_the_identity_key(self):
        identity = _secret_identity(converted=True)
        emitted = identity_key(identity)
        key = secret_correlation_key(identity)
        assert key["file"] == emitted["file"]
        assert key["project"] == emitted["project"]
        assert key["tree"] == emitted["tree"]
        assert key["startLine"] == emitted["startLine"]

    def test_the_default_project_is_folded_in_as_identity_keys_folds_it(self):
        identity = _secret_identity(workspace_project=None)
        emitted = identity_key(identity, default_project="fallback")
        key = secret_correlation_key(identity, default_project="fallback")
        assert key["project"] == emitted["project"] == "fallback"

    def test_a_named_project_beats_the_default(self):
        key = secret_correlation_key(_secret_identity(), default_project="fallback")
        assert key["project"] == "web"

    def test_two_images_secrets_at_one_path_and_line_have_different_ids(self):
        # The identity contract keys the two apart (tree "image" plus the
        # image component), so the correlation key copies BOTH: with only the
        # tree copied, one in-image path and line in two different images
        # shared a secret/<sha> id, and a report over both correlated them.
        one = _secret_identity(
            file_path="/etc/app/creds.txt", image="sha256:" + "aa" * 32
        )
        other = _secret_identity(
            file_path="/etc/app/creds.txt", image="sha256:" + "bb" * 32
        )
        first = correlation_id(
            SECRET_CORRELATION_PREFIX, "t", secret_correlation_key(one)
        )
        second = correlation_id(
            SECRET_CORRELATION_PREFIX, "t", secret_correlation_key(other)
        )
        assert first != second
        # The key spells the components as the identity key does.
        key = secret_correlation_key(one)
        emitted = identity_key(one)
        assert key["tree"] == emitted["tree"]
        assert key["image"] == emitted["image"]

    def test_one_images_secret_correlates_across_scanners(self):
        # The positive control: the image component keys images apart, not
        # one image's scanners.
        image = "sha256:" + "aa" * 32
        ours = _secret_identity(
            scanner="scanner-a", file_path="/etc/app/creds.txt", image=image
        )
        theirs = _secret_identity(
            scanner="scanner-b",
            rule_id="generic.secret.9",
            file_path="/etc/app/creds.txt",
            image=image,
        )
        assert correlation_id(
            SECRET_CORRELATION_PREFIX, "t", secret_correlation_key(ours)
        ) == correlation_id(
            SECRET_CORRELATION_PREFIX, "t", secret_correlation_key(theirs)
        )


class TestAbsence:
    """A family's key is None without its fields; None hashes to None."""

    def test_a_secret_with_no_file_or_no_line_has_no_key(self):
        assert secret_correlation_key(_secret_identity(file_path=None)) is None
        assert (
            secret_correlation_key(_secret_identity(line_start=None, line_end=None))
            is None
        )

    def test_a_dep_missing_any_field_has_no_key(self):
        assert dep_correlation_key(None, "lodash", "4.17.20") is None
        assert dep_correlation_key("CVE-2024-12345", None, "4.17.20") is None
        assert dep_correlation_key("CVE-2024-12345", "lodash", None) is None
        assert dep_correlation_key("  ", "lodash", "4.17.20") is None

    def test_a_key_of_none_gives_no_id(self):
        assert correlation_id(SECRET_CORRELATION_PREFIX, "t", None) is None
        assert correlation_id(DEP_CORRELATION_PREFIX, "t", None) is None


class TestCorrelationTarget:
    def test_a_named_project_is_the_target(self):
        assert correlation_target("my-repo") == "my-repo"
        assert correlation_target("  my-repo  ") == "my-repo"

    def test_a_missing_or_blank_name_is_the_metadata_default(self):
        assert correlation_target(None) == DEFAULT_CORRELATION_TARGET
        assert correlation_target("   ") == DEFAULT_CORRELATION_TARGET
        assert DEFAULT_CORRELATION_TARGET == "ASH"
