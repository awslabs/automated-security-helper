#!/usr/bin/env python3
from aws_cdk import App, Aspects
from cdk_nag import AwsSolutionsChecks

import aws_cdk as cdk

from cfn_to_cdk.cfn_to_cdk_stack import CfnToCdkStack


app = cdk.App()
CfnToCdkStack(app, "cfn-to-cdk")


Aspects.of(app).add(AwsSolutionsChecks())
app.synth()
