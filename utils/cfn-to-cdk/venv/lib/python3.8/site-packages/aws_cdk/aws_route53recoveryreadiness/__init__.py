'''
# AWS::Route53RecoveryReadiness Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_route53recoveryreadiness as route53recoveryreadiness
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-route53recoveryreadiness-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::Route53RecoveryReadiness](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_Route53RecoveryReadiness.html).

(Read the [CDK Contributing Guide](https://github.com/aws/aws-cdk/blob/master/CONTRIBUTING.md) if you are interested in contributing to this construct library.)

<!--END CFNONLY DISCLAIMER-->
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
from .. import (
    CfnResource as _CfnResource_9df397a6,
    CfnTag as _CfnTag_f6864754,
    IInspectable as _IInspectable_c2943556,
    IResolvable as _IResolvable_da3f097b,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.implements(_IInspectable_c2943556)
class CfnCell(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53recoveryreadiness.CfnCell",
):
    '''A CloudFormation ``AWS::Route53RecoveryReadiness::Cell``.

    Creates a cell in an account.

    :cloudformationResource: AWS::Route53RecoveryReadiness::Cell
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-cell.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_route53recoveryreadiness as route53recoveryreadiness
        
        cfn_cell = route53recoveryreadiness.CfnCell(self, "MyCfnCell",
            cell_name="cellName",
        
            # the properties below are optional
            cells=["cells"],
            tags=[CfnTag(
                key="key",
                value="value"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cell_name: builtins.str,
        cells: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Route53RecoveryReadiness::Cell``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param cell_name: The name of the cell to create.
        :param cells: A list of cell Amazon Resource Names (ARNs) contained within this cell, for use in nested cells. For example, Availability Zones within specific AWS Regions .
        :param tags: A collection of tags associated with a resource.
        '''
        props = CfnCellProps(cell_name=cell_name, cells=cells, tags=tags)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="inspect")
    def inspect(self, inspector: _TreeInspector_488e0dd5) -> None:
        '''Examines the CloudFormation resource and discloses attributes.

        :param inspector: - tree inspector to collect and process attributes.
        '''
        return typing.cast(None, jsii.invoke(self, "inspect", [inspector]))

    @jsii.member(jsii_name="renderProperties")
    def _render_properties(
        self,
        props: typing.Mapping[builtins.str, typing.Any],
    ) -> typing.Mapping[builtins.str, typing.Any]:
        '''
        :param props: -
        '''
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.invoke(self, "renderProperties", [props]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="CFN_RESOURCE_TYPE_NAME")
    def CFN_RESOURCE_TYPE_NAME(cls) -> builtins.str:
        '''The CloudFormation resource type name for this resource class.'''
        return typing.cast(builtins.str, jsii.sget(cls, "CFN_RESOURCE_TYPE_NAME"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCellArn")
    def attr_cell_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the cell.

        :cloudformationAttribute: CellArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCellArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrParentReadinessScopes")
    def attr_parent_readiness_scopes(self) -> typing.List[builtins.str]:
        '''The readiness scope for the cell, which can be a cell Amazon Resource Name (ARN) or a recovery group ARN.

        This is a list but currently can have only one element.

        :cloudformationAttribute: ParentReadinessScopes
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrParentReadinessScopes"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A collection of tags associated with a resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-cell.html#cfn-route53recoveryreadiness-cell-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cellName")
    def cell_name(self) -> builtins.str:
        '''The name of the cell to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-cell.html#cfn-route53recoveryreadiness-cell-cellname
        '''
        return typing.cast(builtins.str, jsii.get(self, "cellName"))

    @cell_name.setter
    def cell_name(self, value: builtins.str) -> None:
        jsii.set(self, "cellName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cells")
    def cells(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of cell Amazon Resource Names (ARNs) contained within this cell, for use in nested cells.

        For example, Availability Zones within specific AWS Regions .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-cell.html#cfn-route53recoveryreadiness-cell-cells
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "cells"))

    @cells.setter
    def cells(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "cells", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53recoveryreadiness.CfnCellProps",
    jsii_struct_bases=[],
    name_mapping={"cell_name": "cellName", "cells": "cells", "tags": "tags"},
)
class CfnCellProps:
    def __init__(
        self,
        *,
        cell_name: builtins.str,
        cells: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnCell``.

        :param cell_name: The name of the cell to create.
        :param cells: A list of cell Amazon Resource Names (ARNs) contained within this cell, for use in nested cells. For example, Availability Zones within specific AWS Regions .
        :param tags: A collection of tags associated with a resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-cell.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53recoveryreadiness as route53recoveryreadiness
            
            cfn_cell_props = route53recoveryreadiness.CfnCellProps(
                cell_name="cellName",
            
                # the properties below are optional
                cells=["cells"],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cell_name": cell_name,
        }
        if cells is not None:
            self._values["cells"] = cells
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def cell_name(self) -> builtins.str:
        '''The name of the cell to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-cell.html#cfn-route53recoveryreadiness-cell-cellname
        '''
        result = self._values.get("cell_name")
        assert result is not None, "Required property 'cell_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def cells(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of cell Amazon Resource Names (ARNs) contained within this cell, for use in nested cells.

        For example, Availability Zones within specific AWS Regions .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-cell.html#cfn-route53recoveryreadiness-cell-cells
        '''
        result = self._values.get("cells")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A collection of tags associated with a resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-cell.html#cfn-route53recoveryreadiness-cell-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnCellProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnReadinessCheck(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53recoveryreadiness.CfnReadinessCheck",
):
    '''A CloudFormation ``AWS::Route53RecoveryReadiness::ReadinessCheck``.

    Creates a readiness check in an account. A readiness check monitors a resource set in your application, such as a set of Amazon Aurora instances, that Application Recovery Controller is auditing recovery readiness for. The audits run once every minute on every resource that's associated with a readiness check.

    :cloudformationResource: AWS::Route53RecoveryReadiness::ReadinessCheck
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-readinesscheck.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_route53recoveryreadiness as route53recoveryreadiness
        
        cfn_readiness_check = route53recoveryreadiness.CfnReadinessCheck(self, "MyCfnReadinessCheck",
            readiness_check_name="readinessCheckName",
        
            # the properties below are optional
            resource_set_name="resourceSetName",
            tags=[CfnTag(
                key="key",
                value="value"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        readiness_check_name: builtins.str,
        resource_set_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Route53RecoveryReadiness::ReadinessCheck``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param readiness_check_name: The name of the readiness check to create.
        :param resource_set_name: The name of the resource set to check.
        :param tags: A collection of tags associated with a resource.
        '''
        props = CfnReadinessCheckProps(
            readiness_check_name=readiness_check_name,
            resource_set_name=resource_set_name,
            tags=tags,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="inspect")
    def inspect(self, inspector: _TreeInspector_488e0dd5) -> None:
        '''Examines the CloudFormation resource and discloses attributes.

        :param inspector: - tree inspector to collect and process attributes.
        '''
        return typing.cast(None, jsii.invoke(self, "inspect", [inspector]))

    @jsii.member(jsii_name="renderProperties")
    def _render_properties(
        self,
        props: typing.Mapping[builtins.str, typing.Any],
    ) -> typing.Mapping[builtins.str, typing.Any]:
        '''
        :param props: -
        '''
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.invoke(self, "renderProperties", [props]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="CFN_RESOURCE_TYPE_NAME")
    def CFN_RESOURCE_TYPE_NAME(cls) -> builtins.str:
        '''The CloudFormation resource type name for this resource class.'''
        return typing.cast(builtins.str, jsii.sget(cls, "CFN_RESOURCE_TYPE_NAME"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrReadinessCheckArn")
    def attr_readiness_check_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the readiness check.

        :cloudformationAttribute: ReadinessCheckArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrReadinessCheckArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A collection of tags associated with a resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-readinesscheck.html#cfn-route53recoveryreadiness-readinesscheck-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="readinessCheckName")
    def readiness_check_name(self) -> builtins.str:
        '''The name of the readiness check to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-readinesscheck.html#cfn-route53recoveryreadiness-readinesscheck-readinesscheckname
        '''
        return typing.cast(builtins.str, jsii.get(self, "readinessCheckName"))

    @readiness_check_name.setter
    def readiness_check_name(self, value: builtins.str) -> None:
        jsii.set(self, "readinessCheckName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resourceSetName")
    def resource_set_name(self) -> typing.Optional[builtins.str]:
        '''The name of the resource set to check.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-readinesscheck.html#cfn-route53recoveryreadiness-readinesscheck-resourcesetname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "resourceSetName"))

    @resource_set_name.setter
    def resource_set_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "resourceSetName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53recoveryreadiness.CfnReadinessCheckProps",
    jsii_struct_bases=[],
    name_mapping={
        "readiness_check_name": "readinessCheckName",
        "resource_set_name": "resourceSetName",
        "tags": "tags",
    },
)
class CfnReadinessCheckProps:
    def __init__(
        self,
        *,
        readiness_check_name: builtins.str,
        resource_set_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnReadinessCheck``.

        :param readiness_check_name: The name of the readiness check to create.
        :param resource_set_name: The name of the resource set to check.
        :param tags: A collection of tags associated with a resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-readinesscheck.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53recoveryreadiness as route53recoveryreadiness
            
            cfn_readiness_check_props = route53recoveryreadiness.CfnReadinessCheckProps(
                readiness_check_name="readinessCheckName",
            
                # the properties below are optional
                resource_set_name="resourceSetName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "readiness_check_name": readiness_check_name,
        }
        if resource_set_name is not None:
            self._values["resource_set_name"] = resource_set_name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def readiness_check_name(self) -> builtins.str:
        '''The name of the readiness check to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-readinesscheck.html#cfn-route53recoveryreadiness-readinesscheck-readinesscheckname
        '''
        result = self._values.get("readiness_check_name")
        assert result is not None, "Required property 'readiness_check_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def resource_set_name(self) -> typing.Optional[builtins.str]:
        '''The name of the resource set to check.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-readinesscheck.html#cfn-route53recoveryreadiness-readinesscheck-resourcesetname
        '''
        result = self._values.get("resource_set_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A collection of tags associated with a resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-readinesscheck.html#cfn-route53recoveryreadiness-readinesscheck-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnReadinessCheckProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnRecoveryGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53recoveryreadiness.CfnRecoveryGroup",
):
    '''A CloudFormation ``AWS::Route53RecoveryReadiness::RecoveryGroup``.

    Creates a recovery group in an account. A recovery group corresponds to an application and includes a list of the cells that make up the application.

    :cloudformationResource: AWS::Route53RecoveryReadiness::RecoveryGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-recoverygroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_route53recoveryreadiness as route53recoveryreadiness
        
        cfn_recovery_group = route53recoveryreadiness.CfnRecoveryGroup(self, "MyCfnRecoveryGroup",
            recovery_group_name="recoveryGroupName",
        
            # the properties below are optional
            cells=["cells"],
            tags=[CfnTag(
                key="key",
                value="value"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        recovery_group_name: builtins.str,
        cells: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Route53RecoveryReadiness::RecoveryGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param recovery_group_name: The name of the recovery group to create.
        :param cells: A list of the cell Amazon Resource Names (ARNs) in the recovery group.
        :param tags: A collection of tags associated with a resource.
        '''
        props = CfnRecoveryGroupProps(
            recovery_group_name=recovery_group_name, cells=cells, tags=tags
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="inspect")
    def inspect(self, inspector: _TreeInspector_488e0dd5) -> None:
        '''Examines the CloudFormation resource and discloses attributes.

        :param inspector: - tree inspector to collect and process attributes.
        '''
        return typing.cast(None, jsii.invoke(self, "inspect", [inspector]))

    @jsii.member(jsii_name="renderProperties")
    def _render_properties(
        self,
        props: typing.Mapping[builtins.str, typing.Any],
    ) -> typing.Mapping[builtins.str, typing.Any]:
        '''
        :param props: -
        '''
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.invoke(self, "renderProperties", [props]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="CFN_RESOURCE_TYPE_NAME")
    def CFN_RESOURCE_TYPE_NAME(cls) -> builtins.str:
        '''The CloudFormation resource type name for this resource class.'''
        return typing.cast(builtins.str, jsii.sget(cls, "CFN_RESOURCE_TYPE_NAME"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrRecoveryGroupArn")
    def attr_recovery_group_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the recovery group.

        :cloudformationAttribute: RecoveryGroupArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrRecoveryGroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A collection of tags associated with a resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-recoverygroup.html#cfn-route53recoveryreadiness-recoverygroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="recoveryGroupName")
    def recovery_group_name(self) -> builtins.str:
        '''The name of the recovery group to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-recoverygroup.html#cfn-route53recoveryreadiness-recoverygroup-recoverygroupname
        '''
        return typing.cast(builtins.str, jsii.get(self, "recoveryGroupName"))

    @recovery_group_name.setter
    def recovery_group_name(self, value: builtins.str) -> None:
        jsii.set(self, "recoveryGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cells")
    def cells(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of the cell Amazon Resource Names (ARNs) in the recovery group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-recoverygroup.html#cfn-route53recoveryreadiness-recoverygroup-cells
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "cells"))

    @cells.setter
    def cells(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "cells", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53recoveryreadiness.CfnRecoveryGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "recovery_group_name": "recoveryGroupName",
        "cells": "cells",
        "tags": "tags",
    },
)
class CfnRecoveryGroupProps:
    def __init__(
        self,
        *,
        recovery_group_name: builtins.str,
        cells: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnRecoveryGroup``.

        :param recovery_group_name: The name of the recovery group to create.
        :param cells: A list of the cell Amazon Resource Names (ARNs) in the recovery group.
        :param tags: A collection of tags associated with a resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-recoverygroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53recoveryreadiness as route53recoveryreadiness
            
            cfn_recovery_group_props = route53recoveryreadiness.CfnRecoveryGroupProps(
                recovery_group_name="recoveryGroupName",
            
                # the properties below are optional
                cells=["cells"],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "recovery_group_name": recovery_group_name,
        }
        if cells is not None:
            self._values["cells"] = cells
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def recovery_group_name(self) -> builtins.str:
        '''The name of the recovery group to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-recoverygroup.html#cfn-route53recoveryreadiness-recoverygroup-recoverygroupname
        '''
        result = self._values.get("recovery_group_name")
        assert result is not None, "Required property 'recovery_group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def cells(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of the cell Amazon Resource Names (ARNs) in the recovery group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-recoverygroup.html#cfn-route53recoveryreadiness-recoverygroup-cells
        '''
        result = self._values.get("cells")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A collection of tags associated with a resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-recoverygroup.html#cfn-route53recoveryreadiness-recoverygroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRecoveryGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnResourceSet(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53recoveryreadiness.CfnResourceSet",
):
    '''A CloudFormation ``AWS::Route53RecoveryReadiness::ResourceSet``.

    Creates a resource set. A resource set is a set of resources of one type that span multiple cells. You can associate a resource set with a readiness check to monitor the resources for failover readiness.

    :cloudformationResource: AWS::Route53RecoveryReadiness::ResourceSet
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-resourceset.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_route53recoveryreadiness as route53recoveryreadiness
        
        cfn_resource_set = route53recoveryreadiness.CfnResourceSet(self, "MyCfnResourceSet",
            resources=[route53recoveryreadiness.CfnResourceSet.ResourceProperty(
                component_id="componentId",
                dns_target_resource=route53recoveryreadiness.CfnResourceSet.DNSTargetResourceProperty(
                    domain_name="domainName",
                    hosted_zone_arn="hostedZoneArn",
                    record_set_id="recordSetId",
                    record_type="recordType",
                    target_resource=route53recoveryreadiness.CfnResourceSet.TargetResourceProperty(
                        nlb_resource=route53recoveryreadiness.CfnResourceSet.NLBResourceProperty(
                            arn="arn"
                        ),
                        r53_resource=route53recoveryreadiness.CfnResourceSet.R53ResourceRecordProperty(
                            domain_name="domainName",
                            record_set_id="recordSetId"
                        )
                    )
                ),
                readiness_scopes=["readinessScopes"],
                resource_arn="resourceArn"
            )],
            resource_set_name="resourceSetName",
            resource_set_type="resourceSetType",
        
            # the properties below are optional
            tags=[CfnTag(
                key="key",
                value="value"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        resources: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnResourceSet.ResourceProperty", _IResolvable_da3f097b]]],
        resource_set_name: builtins.str,
        resource_set_type: builtins.str,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Route53RecoveryReadiness::ResourceSet``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param resources: A list of resource objects in the resource set.
        :param resource_set_name: The name of the resource set to create.
        :param resource_set_type: The resource type of the resources in the resource set. Enter one of the following values for resource type:. AWS::AutoScaling::AutoScalingGroup, AWS::CloudWatch::Alarm, AWS::EC2::CustomerGateway, AWS::DynamoDB::Table, AWS::EC2::Volume, AWS::ElasticLoadBalancing::LoadBalancer, AWS::ElasticLoadBalancingV2::LoadBalancer, AWS::MSK::Cluster, AWS::RDS::DBCluster, AWS::Route53::HealthCheck, AWS::SQS::Queue, AWS::SNS::Topic, AWS::SNS::Subscription, AWS::EC2::VPC, AWS::EC2::VPNConnection, AWS::EC2::VPNGateway, AWS::Route53RecoveryReadiness::DNSTargetResource. Note that AWS::Route53RecoveryReadiness::DNSTargetResource is only used for this setting. It isn't an actual AWS CloudFormation resource type.
        :param tags: A tag to associate with the parameters for a resource set.
        '''
        props = CfnResourceSetProps(
            resources=resources,
            resource_set_name=resource_set_name,
            resource_set_type=resource_set_type,
            tags=tags,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="inspect")
    def inspect(self, inspector: _TreeInspector_488e0dd5) -> None:
        '''Examines the CloudFormation resource and discloses attributes.

        :param inspector: - tree inspector to collect and process attributes.
        '''
        return typing.cast(None, jsii.invoke(self, "inspect", [inspector]))

    @jsii.member(jsii_name="renderProperties")
    def _render_properties(
        self,
        props: typing.Mapping[builtins.str, typing.Any],
    ) -> typing.Mapping[builtins.str, typing.Any]:
        '''
        :param props: -
        '''
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.invoke(self, "renderProperties", [props]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="CFN_RESOURCE_TYPE_NAME")
    def CFN_RESOURCE_TYPE_NAME(cls) -> builtins.str:
        '''The CloudFormation resource type name for this resource class.'''
        return typing.cast(builtins.str, jsii.sget(cls, "CFN_RESOURCE_TYPE_NAME"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrResourceSetArn")
    def attr_resource_set_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the resource set.

        :cloudformationAttribute: ResourceSetArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrResourceSetArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A tag to associate with the parameters for a resource set.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-resourceset.html#cfn-route53recoveryreadiness-resourceset-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resources")
    def resources(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnResourceSet.ResourceProperty", _IResolvable_da3f097b]]]:
        '''A list of resource objects in the resource set.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-resourceset.html#cfn-route53recoveryreadiness-resourceset-resources
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnResourceSet.ResourceProperty", _IResolvable_da3f097b]]], jsii.get(self, "resources"))

    @resources.setter
    def resources(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnResourceSet.ResourceProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "resources", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resourceSetName")
    def resource_set_name(self) -> builtins.str:
        '''The name of the resource set to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-resourceset.html#cfn-route53recoveryreadiness-resourceset-resourcesetname
        '''
        return typing.cast(builtins.str, jsii.get(self, "resourceSetName"))

    @resource_set_name.setter
    def resource_set_name(self, value: builtins.str) -> None:
        jsii.set(self, "resourceSetName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resourceSetType")
    def resource_set_type(self) -> builtins.str:
        '''The resource type of the resources in the resource set. Enter one of the following values for resource type:.

        AWS::AutoScaling::AutoScalingGroup, AWS::CloudWatch::Alarm, AWS::EC2::CustomerGateway, AWS::DynamoDB::Table, AWS::EC2::Volume, AWS::ElasticLoadBalancing::LoadBalancer, AWS::ElasticLoadBalancingV2::LoadBalancer, AWS::MSK::Cluster, AWS::RDS::DBCluster, AWS::Route53::HealthCheck, AWS::SQS::Queue, AWS::SNS::Topic, AWS::SNS::Subscription, AWS::EC2::VPC, AWS::EC2::VPNConnection, AWS::EC2::VPNGateway, AWS::Route53RecoveryReadiness::DNSTargetResource.

        Note that AWS::Route53RecoveryReadiness::DNSTargetResource is only used for this setting. It isn't an actual AWS CloudFormation resource type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-resourceset.html#cfn-route53recoveryreadiness-resourceset-resourcesettype
        '''
        return typing.cast(builtins.str, jsii.get(self, "resourceSetType"))

    @resource_set_type.setter
    def resource_set_type(self, value: builtins.str) -> None:
        jsii.set(self, "resourceSetType", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53recoveryreadiness.CfnResourceSet.DNSTargetResourceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "domain_name": "domainName",
            "hosted_zone_arn": "hostedZoneArn",
            "record_set_id": "recordSetId",
            "record_type": "recordType",
            "target_resource": "targetResource",
        },
    )
    class DNSTargetResourceProperty:
        def __init__(
            self,
            *,
            domain_name: typing.Optional[builtins.str] = None,
            hosted_zone_arn: typing.Optional[builtins.str] = None,
            record_set_id: typing.Optional[builtins.str] = None,
            record_type: typing.Optional[builtins.str] = None,
            target_resource: typing.Optional[typing.Union["CfnResourceSet.TargetResourceProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A component for DNS/routing control readiness checks and architecture checks.

            :param domain_name: The domain name that acts as an ingress point to a portion of the customer application.
            :param hosted_zone_arn: The hosted zone Amazon Resource Name (ARN) that contains the DNS record with the provided name of the target resource.
            :param record_set_id: The Route 53 record set ID that uniquely identifies a DNS record, given a name and a type.
            :param record_type: The type of DNS record of the target resource.
            :param target_resource: The target resource that the Route 53 record points to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-dnstargetresource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53recoveryreadiness as route53recoveryreadiness
                
                d_nSTarget_resource_property = route53recoveryreadiness.CfnResourceSet.DNSTargetResourceProperty(
                    domain_name="domainName",
                    hosted_zone_arn="hostedZoneArn",
                    record_set_id="recordSetId",
                    record_type="recordType",
                    target_resource=route53recoveryreadiness.CfnResourceSet.TargetResourceProperty(
                        nlb_resource=route53recoveryreadiness.CfnResourceSet.NLBResourceProperty(
                            arn="arn"
                        ),
                        r53_resource=route53recoveryreadiness.CfnResourceSet.R53ResourceRecordProperty(
                            domain_name="domainName",
                            record_set_id="recordSetId"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if domain_name is not None:
                self._values["domain_name"] = domain_name
            if hosted_zone_arn is not None:
                self._values["hosted_zone_arn"] = hosted_zone_arn
            if record_set_id is not None:
                self._values["record_set_id"] = record_set_id
            if record_type is not None:
                self._values["record_type"] = record_type
            if target_resource is not None:
                self._values["target_resource"] = target_resource

        @builtins.property
        def domain_name(self) -> typing.Optional[builtins.str]:
            '''The domain name that acts as an ingress point to a portion of the customer application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-dnstargetresource.html#cfn-route53recoveryreadiness-resourceset-dnstargetresource-domainname
            '''
            result = self._values.get("domain_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def hosted_zone_arn(self) -> typing.Optional[builtins.str]:
            '''The hosted zone Amazon Resource Name (ARN) that contains the DNS record with the provided name of the target resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-dnstargetresource.html#cfn-route53recoveryreadiness-resourceset-dnstargetresource-hostedzonearn
            '''
            result = self._values.get("hosted_zone_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def record_set_id(self) -> typing.Optional[builtins.str]:
            '''The Route 53 record set ID that uniquely identifies a DNS record, given a name and a type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-dnstargetresource.html#cfn-route53recoveryreadiness-resourceset-dnstargetresource-recordsetid
            '''
            result = self._values.get("record_set_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def record_type(self) -> typing.Optional[builtins.str]:
            '''The type of DNS record of the target resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-dnstargetresource.html#cfn-route53recoveryreadiness-resourceset-dnstargetresource-recordtype
            '''
            result = self._values.get("record_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def target_resource(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceSet.TargetResourceProperty", _IResolvable_da3f097b]]:
            '''The target resource that the Route 53 record points to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-dnstargetresource.html#cfn-route53recoveryreadiness-resourceset-dnstargetresource-targetresource
            '''
            result = self._values.get("target_resource")
            return typing.cast(typing.Optional[typing.Union["CfnResourceSet.TargetResourceProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DNSTargetResourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53recoveryreadiness.CfnResourceSet.NLBResourceProperty",
        jsii_struct_bases=[],
        name_mapping={"arn": "arn"},
    )
    class NLBResourceProperty:
        def __init__(self, *, arn: typing.Optional[builtins.str] = None) -> None:
            '''The Network Load Balancer resource that a DNS target resource points to.

            :param arn: The Network Load Balancer resource Amazon Resource Name (ARN).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-nlbresource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53recoveryreadiness as route53recoveryreadiness
                
                n_lBResource_property = route53recoveryreadiness.CfnResourceSet.NLBResourceProperty(
                    arn="arn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if arn is not None:
                self._values["arn"] = arn

        @builtins.property
        def arn(self) -> typing.Optional[builtins.str]:
            '''The Network Load Balancer resource Amazon Resource Name (ARN).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-nlbresource.html#cfn-route53recoveryreadiness-resourceset-nlbresource-arn
            '''
            result = self._values.get("arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NLBResourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53recoveryreadiness.CfnResourceSet.R53ResourceRecordProperty",
        jsii_struct_bases=[],
        name_mapping={"domain_name": "domainName", "record_set_id": "recordSetId"},
    )
    class R53ResourceRecordProperty:
        def __init__(
            self,
            *,
            domain_name: typing.Optional[builtins.str] = None,
            record_set_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The Route 53 resource that a DNS target resource record points to.

            :param domain_name: The DNS target domain name.
            :param record_set_id: The Route 53 Resource Record Set ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-r53resourcerecord.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53recoveryreadiness as route53recoveryreadiness
                
                r53_resource_record_property = route53recoveryreadiness.CfnResourceSet.R53ResourceRecordProperty(
                    domain_name="domainName",
                    record_set_id="recordSetId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if domain_name is not None:
                self._values["domain_name"] = domain_name
            if record_set_id is not None:
                self._values["record_set_id"] = record_set_id

        @builtins.property
        def domain_name(self) -> typing.Optional[builtins.str]:
            '''The DNS target domain name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-r53resourcerecord.html#cfn-route53recoveryreadiness-resourceset-r53resourcerecord-domainname
            '''
            result = self._values.get("domain_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def record_set_id(self) -> typing.Optional[builtins.str]:
            '''The Route 53 Resource Record Set ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-r53resourcerecord.html#cfn-route53recoveryreadiness-resourceset-r53resourcerecord-recordsetid
            '''
            result = self._values.get("record_set_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "R53ResourceRecordProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53recoveryreadiness.CfnResourceSet.ResourceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "component_id": "componentId",
            "dns_target_resource": "dnsTargetResource",
            "readiness_scopes": "readinessScopes",
            "resource_arn": "resourceArn",
        },
    )
    class ResourceProperty:
        def __init__(
            self,
            *,
            component_id: typing.Optional[builtins.str] = None,
            dns_target_resource: typing.Optional[typing.Union["CfnResourceSet.DNSTargetResourceProperty", _IResolvable_da3f097b]] = None,
            readiness_scopes: typing.Optional[typing.Sequence[builtins.str]] = None,
            resource_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The resource element of a resource set.

            :param component_id: The component identifier of the resource, generated when DNS target resource is used.
            :param dns_target_resource: A component for DNS/routing control readiness checks. This is a required setting when ``ResourceSet`` ``ResourceSetType`` is set to ``AWS::Route53RecoveryReadiness::DNSTargetResource`` . Do not set it for any other ``ResourceSetType`` setting.
            :param readiness_scopes: The recovery group Amazon Resource Name (ARN) or the cell ARN that the readiness checks for this resource set are scoped to.
            :param resource_arn: The Amazon Resource Name (ARN) of the AWS resource. This is a required setting for all ``ResourceSet`` ``ResourceSetType`` settings except ``AWS::Route53RecoveryReadiness::DNSTargetResource`` . Do not set this when ``ResourceSetType`` is set to ``AWS::Route53RecoveryReadiness::DNSTargetResource`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-resource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53recoveryreadiness as route53recoveryreadiness
                
                resource_property = route53recoveryreadiness.CfnResourceSet.ResourceProperty(
                    component_id="componentId",
                    dns_target_resource=route53recoveryreadiness.CfnResourceSet.DNSTargetResourceProperty(
                        domain_name="domainName",
                        hosted_zone_arn="hostedZoneArn",
                        record_set_id="recordSetId",
                        record_type="recordType",
                        target_resource=route53recoveryreadiness.CfnResourceSet.TargetResourceProperty(
                            nlb_resource=route53recoveryreadiness.CfnResourceSet.NLBResourceProperty(
                                arn="arn"
                            ),
                            r53_resource=route53recoveryreadiness.CfnResourceSet.R53ResourceRecordProperty(
                                domain_name="domainName",
                                record_set_id="recordSetId"
                            )
                        )
                    ),
                    readiness_scopes=["readinessScopes"],
                    resource_arn="resourceArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if component_id is not None:
                self._values["component_id"] = component_id
            if dns_target_resource is not None:
                self._values["dns_target_resource"] = dns_target_resource
            if readiness_scopes is not None:
                self._values["readiness_scopes"] = readiness_scopes
            if resource_arn is not None:
                self._values["resource_arn"] = resource_arn

        @builtins.property
        def component_id(self) -> typing.Optional[builtins.str]:
            '''The component identifier of the resource, generated when DNS target resource is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-resource.html#cfn-route53recoveryreadiness-resourceset-resource-componentid
            '''
            result = self._values.get("component_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def dns_target_resource(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceSet.DNSTargetResourceProperty", _IResolvable_da3f097b]]:
            '''A component for DNS/routing control readiness checks.

            This is a required setting when ``ResourceSet`` ``ResourceSetType`` is set to ``AWS::Route53RecoveryReadiness::DNSTargetResource`` . Do not set it for any other ``ResourceSetType`` setting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-resource.html#cfn-route53recoveryreadiness-resourceset-resource-dnstargetresource
            '''
            result = self._values.get("dns_target_resource")
            return typing.cast(typing.Optional[typing.Union["CfnResourceSet.DNSTargetResourceProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def readiness_scopes(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The recovery group Amazon Resource Name (ARN) or the cell ARN that the readiness checks for this resource set are scoped to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-resource.html#cfn-route53recoveryreadiness-resourceset-resource-readinessscopes
            '''
            result = self._values.get("readiness_scopes")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def resource_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the AWS resource.

            This is a required setting for all ``ResourceSet`` ``ResourceSetType`` settings except ``AWS::Route53RecoveryReadiness::DNSTargetResource`` . Do not set this when ``ResourceSetType`` is set to ``AWS::Route53RecoveryReadiness::DNSTargetResource`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-resource.html#cfn-route53recoveryreadiness-resourceset-resource-resourcearn
            '''
            result = self._values.get("resource_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53recoveryreadiness.CfnResourceSet.TargetResourceProperty",
        jsii_struct_bases=[],
        name_mapping={"nlb_resource": "nlbResource", "r53_resource": "r53Resource"},
    )
    class TargetResourceProperty:
        def __init__(
            self,
            *,
            nlb_resource: typing.Optional[typing.Union["CfnResourceSet.NLBResourceProperty", _IResolvable_da3f097b]] = None,
            r53_resource: typing.Optional[typing.Union["CfnResourceSet.R53ResourceRecordProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The target resource that the Route 53 record points to.

            :param nlb_resource: The Network Load Balancer resource that a DNS target resource points to.
            :param r53_resource: The Route 53 resource that a DNS target resource record points to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-targetresource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53recoveryreadiness as route53recoveryreadiness
                
                target_resource_property = route53recoveryreadiness.CfnResourceSet.TargetResourceProperty(
                    nlb_resource=route53recoveryreadiness.CfnResourceSet.NLBResourceProperty(
                        arn="arn"
                    ),
                    r53_resource=route53recoveryreadiness.CfnResourceSet.R53ResourceRecordProperty(
                        domain_name="domainName",
                        record_set_id="recordSetId"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if nlb_resource is not None:
                self._values["nlb_resource"] = nlb_resource
            if r53_resource is not None:
                self._values["r53_resource"] = r53_resource

        @builtins.property
        def nlb_resource(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceSet.NLBResourceProperty", _IResolvable_da3f097b]]:
            '''The Network Load Balancer resource that a DNS target resource points to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-targetresource.html#cfn-route53recoveryreadiness-resourceset-targetresource-nlbresource
            '''
            result = self._values.get("nlb_resource")
            return typing.cast(typing.Optional[typing.Union["CfnResourceSet.NLBResourceProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def r53_resource(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceSet.R53ResourceRecordProperty", _IResolvable_da3f097b]]:
            '''The Route 53 resource that a DNS target resource record points to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53recoveryreadiness-resourceset-targetresource.html#cfn-route53recoveryreadiness-resourceset-targetresource-r53resource
            '''
            result = self._values.get("r53_resource")
            return typing.cast(typing.Optional[typing.Union["CfnResourceSet.R53ResourceRecordProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TargetResourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53recoveryreadiness.CfnResourceSetProps",
    jsii_struct_bases=[],
    name_mapping={
        "resources": "resources",
        "resource_set_name": "resourceSetName",
        "resource_set_type": "resourceSetType",
        "tags": "tags",
    },
)
class CfnResourceSetProps:
    def __init__(
        self,
        *,
        resources: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnResourceSet.ResourceProperty, _IResolvable_da3f097b]]],
        resource_set_name: builtins.str,
        resource_set_type: builtins.str,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnResourceSet``.

        :param resources: A list of resource objects in the resource set.
        :param resource_set_name: The name of the resource set to create.
        :param resource_set_type: The resource type of the resources in the resource set. Enter one of the following values for resource type:. AWS::AutoScaling::AutoScalingGroup, AWS::CloudWatch::Alarm, AWS::EC2::CustomerGateway, AWS::DynamoDB::Table, AWS::EC2::Volume, AWS::ElasticLoadBalancing::LoadBalancer, AWS::ElasticLoadBalancingV2::LoadBalancer, AWS::MSK::Cluster, AWS::RDS::DBCluster, AWS::Route53::HealthCheck, AWS::SQS::Queue, AWS::SNS::Topic, AWS::SNS::Subscription, AWS::EC2::VPC, AWS::EC2::VPNConnection, AWS::EC2::VPNGateway, AWS::Route53RecoveryReadiness::DNSTargetResource. Note that AWS::Route53RecoveryReadiness::DNSTargetResource is only used for this setting. It isn't an actual AWS CloudFormation resource type.
        :param tags: A tag to associate with the parameters for a resource set.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-resourceset.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53recoveryreadiness as route53recoveryreadiness
            
            cfn_resource_set_props = route53recoveryreadiness.CfnResourceSetProps(
                resources=[route53recoveryreadiness.CfnResourceSet.ResourceProperty(
                    component_id="componentId",
                    dns_target_resource=route53recoveryreadiness.CfnResourceSet.DNSTargetResourceProperty(
                        domain_name="domainName",
                        hosted_zone_arn="hostedZoneArn",
                        record_set_id="recordSetId",
                        record_type="recordType",
                        target_resource=route53recoveryreadiness.CfnResourceSet.TargetResourceProperty(
                            nlb_resource=route53recoveryreadiness.CfnResourceSet.NLBResourceProperty(
                                arn="arn"
                            ),
                            r53_resource=route53recoveryreadiness.CfnResourceSet.R53ResourceRecordProperty(
                                domain_name="domainName",
                                record_set_id="recordSetId"
                            )
                        )
                    ),
                    readiness_scopes=["readinessScopes"],
                    resource_arn="resourceArn"
                )],
                resource_set_name="resourceSetName",
                resource_set_type="resourceSetType",
            
                # the properties below are optional
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "resources": resources,
            "resource_set_name": resource_set_name,
            "resource_set_type": resource_set_type,
        }
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def resources(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnResourceSet.ResourceProperty, _IResolvable_da3f097b]]]:
        '''A list of resource objects in the resource set.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-resourceset.html#cfn-route53recoveryreadiness-resourceset-resources
        '''
        result = self._values.get("resources")
        assert result is not None, "Required property 'resources' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnResourceSet.ResourceProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def resource_set_name(self) -> builtins.str:
        '''The name of the resource set to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-resourceset.html#cfn-route53recoveryreadiness-resourceset-resourcesetname
        '''
        result = self._values.get("resource_set_name")
        assert result is not None, "Required property 'resource_set_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def resource_set_type(self) -> builtins.str:
        '''The resource type of the resources in the resource set. Enter one of the following values for resource type:.

        AWS::AutoScaling::AutoScalingGroup, AWS::CloudWatch::Alarm, AWS::EC2::CustomerGateway, AWS::DynamoDB::Table, AWS::EC2::Volume, AWS::ElasticLoadBalancing::LoadBalancer, AWS::ElasticLoadBalancingV2::LoadBalancer, AWS::MSK::Cluster, AWS::RDS::DBCluster, AWS::Route53::HealthCheck, AWS::SQS::Queue, AWS::SNS::Topic, AWS::SNS::Subscription, AWS::EC2::VPC, AWS::EC2::VPNConnection, AWS::EC2::VPNGateway, AWS::Route53RecoveryReadiness::DNSTargetResource.

        Note that AWS::Route53RecoveryReadiness::DNSTargetResource is only used for this setting. It isn't an actual AWS CloudFormation resource type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-resourceset.html#cfn-route53recoveryreadiness-resourceset-resourcesettype
        '''
        result = self._values.get("resource_set_type")
        assert result is not None, "Required property 'resource_set_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A tag to associate with the parameters for a resource set.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53recoveryreadiness-resourceset.html#cfn-route53recoveryreadiness-resourceset-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnResourceSetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnCell",
    "CfnCellProps",
    "CfnReadinessCheck",
    "CfnReadinessCheckProps",
    "CfnRecoveryGroup",
    "CfnRecoveryGroupProps",
    "CfnResourceSet",
    "CfnResourceSetProps",
]

publication.publish()
