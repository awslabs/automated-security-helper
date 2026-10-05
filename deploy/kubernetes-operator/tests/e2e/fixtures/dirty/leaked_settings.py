"""Deliberately planted credentials, for detect-secrets.

Not real. The access key id is ``AKIAIOSFODNN7EXAMPLE`` and the secret is
``wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`` -- the documentation-only pair AWS
publishes in its own examples, which is why it is safe to commit and why
detect-secrets still flags it.

This file is in the fixture so that two *different* shards each contribute a
finding. At shardCount 3, bandit sorts to position 0 and detect-secrets to position
4, so they land on shards 0 and 1 and shard 2 gets an empty assignment. A merged
report carrying both a bandit rule and a detect-secrets rule is direct evidence
that the fan-out contributed rather than merely ran.
"""

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 - documentation-only value
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # noqa: S105
