#!/usr/bin/env python3
"""CDK app entry point for the offline test infrastructure.

Usage:
    cdk synth                       # synthesize with defaults
    cdk synth -c vpc_cidr=10.1.0.0/16 -c instance_type=m5.large -c ash_version=3.4.0
    cdk deploy                      # deploy (requires AWS credentials)
    cdk destroy                     # tear down
"""

from __future__ import annotations

import aws_cdk as cdk

from offline_test_stack import OfflineTestStack

app = cdk.App()

OfflineTestStack(
    app,
    "AshOfflineTestStack",
    vpc_cidr=app.node.try_get_context("vpc_cidr") or "10.0.0.0/16",
    instance_type=app.node.try_get_context("instance_type") or "t3.medium",
    ash_version=app.node.try_get_context("ash_version") or "latest",
    description="Air-gapped VPC for testing ASH offline mode",
)

app.synth()
