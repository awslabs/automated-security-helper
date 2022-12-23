'''
# AWS Lambda Layer with AWS CLI

This module exports a single class called `AwsCliLayer` which is a `lambda.Layer` that bundles the AWS CLI.

Any Lambda Function that uses this layer must use a Python 3.x runtime.

Usage:

```python
# AwsCliLayer bundles the AWS CLI in a lambda layer
from aws_cdk.lambda_layer_awscli import AwsCliLayer

# fn: lambda.Function

fn.add_layers(AwsCliLayer(self, "AwsCliLayer"))
```

The CLI will be installed under `/opt/awscli/aws`.
'''
import abc
import builtins
import datetime
import enum
import typing

import jsii
import publication
import typing_extensions

from .._jsii import *

import constructs
from ..aws_lambda import LayerVersion as _LayerVersion_9ca26241


class AwsCliLayer(
    _LayerVersion_9ca26241,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.lambda_layer_awscli.AwsCliLayer",
):
    '''An AWS Lambda layer that includes the AWS CLI.

    :exampleMetadata: infused

    Example::

        # AwsCliLayer bundles the AWS CLI in a lambda layer
        from aws_cdk.lambda_layer_awscli import AwsCliLayer
        
        # fn: lambda.Function
        
        fn.add_layers(AwsCliLayer(self, "AwsCliLayer"))
    '''

    def __init__(self, scope: constructs.Construct, id: builtins.str) -> None:
        '''
        :param scope: -
        :param id: -
        '''
        jsii.create(self.__class__, self, [scope, id])


__all__ = [
    "AwsCliLayer",
]

publication.publish()
