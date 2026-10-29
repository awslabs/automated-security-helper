# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A client config policy that lists none of the default ``denied_paths``.

The tests of what an MCP client's delivered config may set run each refusal twice:
under the shipped default ``denied_paths`` and under this policy, whose operator
profile sets ``replace_default_denied_paths: true`` with a list that leaves every
default entry out. What a delivered file still cannot set under this policy is
denied by ``ALWAYS_DENIED_PATHS`` (every policy holds those) or confined by the
fallback that replays the trusted base; what it can set shows which checks rest
on the default list alone. Shared by the config-trust test modules so the policy
has one spelling.
"""

from __future__ import annotations


def narrow_client_rules():
    """The rules of a policy whose own list names only ``/fail_on_findings``."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.client_config_policy import rules_from

    return rules_from(
        AshConfig.model_validate(
            {
                "global_settings": {
                    "mcp": {
                        "runtime_overrides": {
                            "denied_paths": ["/fail_on_findings"],
                            "replace_default_denied_paths": True,
                        }
                    }
                }
            }
        )
    )
