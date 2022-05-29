'''
# AWS::MediaPackage Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_mediapackage as mediapackage
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-mediapackage-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::MediaPackage](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_MediaPackage.html).

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
class CfnAsset(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_mediapackage.CfnAsset",
):
    '''A CloudFormation ``AWS::MediaPackage::Asset``.

    Creates an asset to ingest VOD content.

    After it's created, the asset starts ingesting content and generates playback URLs for the packaging configurations associated with it. When ingest is complete, downstream devices use the appropriate URL to request VOD content from AWS Elemental MediaPackage .

    :cloudformationResource: AWS::MediaPackage::Asset
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-asset.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_mediapackage as mediapackage
        
        cfn_asset = mediapackage.CfnAsset(self, "MyCfnAsset",
            id="id",
            packaging_group_id="packagingGroupId",
            source_arn="sourceArn",
            source_role_arn="sourceRoleArn",
        
            # the properties below are optional
            resource_id="resourceId",
            tags=[CfnTag(
                key="key",
                value="value"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id_: builtins.str,
        *,
        id: builtins.str,
        packaging_group_id: builtins.str,
        source_arn: builtins.str,
        source_role_arn: builtins.str,
        resource_id: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::MediaPackage::Asset``.

        :param scope: - scope in which this resource is defined.
        :param id_: - scoped id of the resource.
        :param id: Unique identifier that you assign to the asset.
        :param packaging_group_id: The ID of the packaging group associated with this asset.
        :param source_arn: The ARN for the source content in Amazon S3.
        :param source_role_arn: The ARN for the IAM role that provides AWS Elemental MediaPackage access to the Amazon S3 bucket where the source content is stored. Valid format: arn:aws:iam::{accountID}:role/{name}
        :param resource_id: Unique identifier for this asset, as it's configured in the key provider service.
        :param tags: The tags to assign to the asset.
        '''
        props = CfnAssetProps(
            id=id,
            packaging_group_id=packaging_group_id,
            source_arn=source_arn,
            source_role_arn=source_role_arn,
            resource_id=resource_id,
            tags=tags,
        )

        jsii.create(self.__class__, self, [scope, id_, props])

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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) for the asset.

        You can get this from the response to any request to
        the asset.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCreatedAt")
    def attr_created_at(self) -> builtins.str:
        '''The time that the asset was initially submitted for ingest.

        :cloudformationAttribute: CreatedAt
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedAt"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrEgressEndpoints")
    def attr_egress_endpoints(self) -> _IResolvable_da3f097b:
        '''
        :cloudformationAttribute: EgressEndpoints
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrEgressEndpoints"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags to assign to the asset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-asset.html#cfn-mediapackage-asset-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="id")
    def id(self) -> builtins.str:
        '''Unique identifier that you assign to the asset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-asset.html#cfn-mediapackage-asset-id
        '''
        return typing.cast(builtins.str, jsii.get(self, "id"))

    @id.setter
    def id(self, value: builtins.str) -> None:
        jsii.set(self, "id", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="packagingGroupId")
    def packaging_group_id(self) -> builtins.str:
        '''The ID of the packaging group associated with this asset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-asset.html#cfn-mediapackage-asset-packaginggroupid
        '''
        return typing.cast(builtins.str, jsii.get(self, "packagingGroupId"))

    @packaging_group_id.setter
    def packaging_group_id(self, value: builtins.str) -> None:
        jsii.set(self, "packagingGroupId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceArn")
    def source_arn(self) -> builtins.str:
        '''The ARN for the source content in Amazon S3.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-asset.html#cfn-mediapackage-asset-sourcearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "sourceArn"))

    @source_arn.setter
    def source_arn(self, value: builtins.str) -> None:
        jsii.set(self, "sourceArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceRoleArn")
    def source_role_arn(self) -> builtins.str:
        '''The ARN for the IAM role that provides AWS Elemental MediaPackage access to the Amazon S3 bucket where the source content is stored.

        Valid format: arn:aws:iam::{accountID}:role/{name}

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-asset.html#cfn-mediapackage-asset-sourcerolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "sourceRoleArn"))

    @source_role_arn.setter
    def source_role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "sourceRoleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resourceId")
    def resource_id(self) -> typing.Optional[builtins.str]:
        '''Unique identifier for this asset, as it's configured in the key provider service.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-asset.html#cfn-mediapackage-asset-resourceid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "resourceId"))

    @resource_id.setter
    def resource_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "resourceId", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnAsset.EgressEndpointProperty",
        jsii_struct_bases=[],
        name_mapping={
            "packaging_configuration_id": "packagingConfigurationId",
            "url": "url",
        },
    )
    class EgressEndpointProperty:
        def __init__(
            self,
            *,
            packaging_configuration_id: builtins.str,
            url: builtins.str,
        ) -> None:
            '''The playback endpoint for a packaging configuration on an asset.

            :param packaging_configuration_id: The ID of a packaging configuration that's applied to this asset.
            :param url: The URL that's used to request content from this endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-asset-egressendpoint.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                egress_endpoint_property = mediapackage.CfnAsset.EgressEndpointProperty(
                    packaging_configuration_id="packagingConfigurationId",
                    url="url"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "packaging_configuration_id": packaging_configuration_id,
                "url": url,
            }

        @builtins.property
        def packaging_configuration_id(self) -> builtins.str:
            '''The ID of a packaging configuration that's applied to this asset.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-asset-egressendpoint.html#cfn-mediapackage-asset-egressendpoint-packagingconfigurationid
            '''
            result = self._values.get("packaging_configuration_id")
            assert result is not None, "Required property 'packaging_configuration_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def url(self) -> builtins.str:
            '''The URL that's used to request content from this endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-asset-egressendpoint.html#cfn-mediapackage-asset-egressendpoint-url
            '''
            result = self._values.get("url")
            assert result is not None, "Required property 'url' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EgressEndpointProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_mediapackage.CfnAssetProps",
    jsii_struct_bases=[],
    name_mapping={
        "id": "id",
        "packaging_group_id": "packagingGroupId",
        "source_arn": "sourceArn",
        "source_role_arn": "sourceRoleArn",
        "resource_id": "resourceId",
        "tags": "tags",
    },
)
class CfnAssetProps:
    def __init__(
        self,
        *,
        id: builtins.str,
        packaging_group_id: builtins.str,
        source_arn: builtins.str,
        source_role_arn: builtins.str,
        resource_id: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnAsset``.

        :param id: Unique identifier that you assign to the asset.
        :param packaging_group_id: The ID of the packaging group associated with this asset.
        :param source_arn: The ARN for the source content in Amazon S3.
        :param source_role_arn: The ARN for the IAM role that provides AWS Elemental MediaPackage access to the Amazon S3 bucket where the source content is stored. Valid format: arn:aws:iam::{accountID}:role/{name}
        :param resource_id: Unique identifier for this asset, as it's configured in the key provider service.
        :param tags: The tags to assign to the asset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-asset.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_mediapackage as mediapackage
            
            cfn_asset_props = mediapackage.CfnAssetProps(
                id="id",
                packaging_group_id="packagingGroupId",
                source_arn="sourceArn",
                source_role_arn="sourceRoleArn",
            
                # the properties below are optional
                resource_id="resourceId",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "id": id,
            "packaging_group_id": packaging_group_id,
            "source_arn": source_arn,
            "source_role_arn": source_role_arn,
        }
        if resource_id is not None:
            self._values["resource_id"] = resource_id
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def id(self) -> builtins.str:
        '''Unique identifier that you assign to the asset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-asset.html#cfn-mediapackage-asset-id
        '''
        result = self._values.get("id")
        assert result is not None, "Required property 'id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def packaging_group_id(self) -> builtins.str:
        '''The ID of the packaging group associated with this asset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-asset.html#cfn-mediapackage-asset-packaginggroupid
        '''
        result = self._values.get("packaging_group_id")
        assert result is not None, "Required property 'packaging_group_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def source_arn(self) -> builtins.str:
        '''The ARN for the source content in Amazon S3.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-asset.html#cfn-mediapackage-asset-sourcearn
        '''
        result = self._values.get("source_arn")
        assert result is not None, "Required property 'source_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def source_role_arn(self) -> builtins.str:
        '''The ARN for the IAM role that provides AWS Elemental MediaPackage access to the Amazon S3 bucket where the source content is stored.

        Valid format: arn:aws:iam::{accountID}:role/{name}

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-asset.html#cfn-mediapackage-asset-sourcerolearn
        '''
        result = self._values.get("source_role_arn")
        assert result is not None, "Required property 'source_role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def resource_id(self) -> typing.Optional[builtins.str]:
        '''Unique identifier for this asset, as it's configured in the key provider service.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-asset.html#cfn-mediapackage-asset-resourceid
        '''
        result = self._values.get("resource_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags to assign to the asset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-asset.html#cfn-mediapackage-asset-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAssetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnChannel(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_mediapackage.CfnChannel",
):
    '''A CloudFormation ``AWS::MediaPackage::Channel``.

    Creates a channel to receive content.

    After it's created, a channel provides static input URLs. These URLs remain the same throughout the lifetime of the channel, regardless of any failures or upgrades that might occur. Use these URLs to configure the outputs of your upstream encoder.

    :cloudformationResource: AWS::MediaPackage::Channel
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-channel.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_mediapackage as mediapackage
        
        cfn_channel = mediapackage.CfnChannel(self, "MyCfnChannel",
            id="id",
        
            # the properties below are optional
            description="description",
            egress_access_logs=mediapackage.CfnChannel.LogConfigurationProperty(
                log_group_name="logGroupName"
            ),
            ingress_access_logs=mediapackage.CfnChannel.LogConfigurationProperty(
                log_group_name="logGroupName"
            ),
            tags=[CfnTag(
                key="key",
                value="value"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id_: builtins.str,
        *,
        id: builtins.str,
        description: typing.Optional[builtins.str] = None,
        egress_access_logs: typing.Optional[typing.Union["CfnChannel.LogConfigurationProperty", _IResolvable_da3f097b]] = None,
        ingress_access_logs: typing.Optional[typing.Union["CfnChannel.LogConfigurationProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::MediaPackage::Channel``.

        :param scope: - scope in which this resource is defined.
        :param id_: - scoped id of the resource.
        :param id: Unique identifier that you assign to the channel.
        :param description: Any descriptive information that you want to add to the channel for future identification purposes.
        :param egress_access_logs: Configures egress access logs.
        :param ingress_access_logs: Configures ingress access logs.
        :param tags: The tags to assign to the channel.
        '''
        props = CfnChannelProps(
            id=id,
            description=description,
            egress_access_logs=egress_access_logs,
            ingress_access_logs=ingress_access_logs,
            tags=tags,
        )

        jsii.create(self.__class__, self, [scope, id_, props])

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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The channel's unique system-generated resource name, based on the AWS record.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags to assign to the channel.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-channel.html#cfn-mediapackage-channel-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="id")
    def id(self) -> builtins.str:
        '''Unique identifier that you assign to the channel.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-channel.html#cfn-mediapackage-channel-id
        '''
        return typing.cast(builtins.str, jsii.get(self, "id"))

    @id.setter
    def id(self, value: builtins.str) -> None:
        jsii.set(self, "id", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''Any descriptive information that you want to add to the channel for future identification purposes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-channel.html#cfn-mediapackage-channel-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="egressAccessLogs")
    def egress_access_logs(
        self,
    ) -> typing.Optional[typing.Union["CfnChannel.LogConfigurationProperty", _IResolvable_da3f097b]]:
        '''Configures egress access logs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-channel.html#cfn-mediapackage-channel-egressaccesslogs
        '''
        return typing.cast(typing.Optional[typing.Union["CfnChannel.LogConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "egressAccessLogs"))

    @egress_access_logs.setter
    def egress_access_logs(
        self,
        value: typing.Optional[typing.Union["CfnChannel.LogConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "egressAccessLogs", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ingressAccessLogs")
    def ingress_access_logs(
        self,
    ) -> typing.Optional[typing.Union["CfnChannel.LogConfigurationProperty", _IResolvable_da3f097b]]:
        '''Configures ingress access logs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-channel.html#cfn-mediapackage-channel-ingressaccesslogs
        '''
        return typing.cast(typing.Optional[typing.Union["CfnChannel.LogConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "ingressAccessLogs"))

    @ingress_access_logs.setter
    def ingress_access_logs(
        self,
        value: typing.Optional[typing.Union["CfnChannel.LogConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "ingressAccessLogs", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnChannel.LogConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"log_group_name": "logGroupName"},
    )
    class LogConfigurationProperty:
        def __init__(
            self,
            *,
            log_group_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The access log configuration parameters for your channel.

            :param log_group_name: Sets a custom Amazon CloudWatch log group name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-channel-logconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                log_configuration_property = mediapackage.CfnChannel.LogConfigurationProperty(
                    log_group_name="logGroupName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if log_group_name is not None:
                self._values["log_group_name"] = log_group_name

        @builtins.property
        def log_group_name(self) -> typing.Optional[builtins.str]:
            '''Sets a custom Amazon CloudWatch log group name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-channel-logconfiguration.html#cfn-mediapackage-channel-logconfiguration-loggroupname
            '''
            result = self._values.get("log_group_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LogConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_mediapackage.CfnChannelProps",
    jsii_struct_bases=[],
    name_mapping={
        "id": "id",
        "description": "description",
        "egress_access_logs": "egressAccessLogs",
        "ingress_access_logs": "ingressAccessLogs",
        "tags": "tags",
    },
)
class CfnChannelProps:
    def __init__(
        self,
        *,
        id: builtins.str,
        description: typing.Optional[builtins.str] = None,
        egress_access_logs: typing.Optional[typing.Union[CfnChannel.LogConfigurationProperty, _IResolvable_da3f097b]] = None,
        ingress_access_logs: typing.Optional[typing.Union[CfnChannel.LogConfigurationProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnChannel``.

        :param id: Unique identifier that you assign to the channel.
        :param description: Any descriptive information that you want to add to the channel for future identification purposes.
        :param egress_access_logs: Configures egress access logs.
        :param ingress_access_logs: Configures ingress access logs.
        :param tags: The tags to assign to the channel.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-channel.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_mediapackage as mediapackage
            
            cfn_channel_props = mediapackage.CfnChannelProps(
                id="id",
            
                # the properties below are optional
                description="description",
                egress_access_logs=mediapackage.CfnChannel.LogConfigurationProperty(
                    log_group_name="logGroupName"
                ),
                ingress_access_logs=mediapackage.CfnChannel.LogConfigurationProperty(
                    log_group_name="logGroupName"
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "id": id,
        }
        if description is not None:
            self._values["description"] = description
        if egress_access_logs is not None:
            self._values["egress_access_logs"] = egress_access_logs
        if ingress_access_logs is not None:
            self._values["ingress_access_logs"] = ingress_access_logs
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def id(self) -> builtins.str:
        '''Unique identifier that you assign to the channel.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-channel.html#cfn-mediapackage-channel-id
        '''
        result = self._values.get("id")
        assert result is not None, "Required property 'id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''Any descriptive information that you want to add to the channel for future identification purposes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-channel.html#cfn-mediapackage-channel-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def egress_access_logs(
        self,
    ) -> typing.Optional[typing.Union[CfnChannel.LogConfigurationProperty, _IResolvable_da3f097b]]:
        '''Configures egress access logs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-channel.html#cfn-mediapackage-channel-egressaccesslogs
        '''
        result = self._values.get("egress_access_logs")
        return typing.cast(typing.Optional[typing.Union[CfnChannel.LogConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def ingress_access_logs(
        self,
    ) -> typing.Optional[typing.Union[CfnChannel.LogConfigurationProperty, _IResolvable_da3f097b]]:
        '''Configures ingress access logs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-channel.html#cfn-mediapackage-channel-ingressaccesslogs
        '''
        result = self._values.get("ingress_access_logs")
        return typing.cast(typing.Optional[typing.Union[CfnChannel.LogConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags to assign to the channel.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-channel.html#cfn-mediapackage-channel-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnChannelProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnOriginEndpoint(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_mediapackage.CfnOriginEndpoint",
):
    '''A CloudFormation ``AWS::MediaPackage::OriginEndpoint``.

    Create an endpoint on an AWS Elemental MediaPackage channel.

    An endpoint represents a single delivery point of a channel, and defines content output handling through various components, such as packaging protocols, DRM and encryption integration, and more.

    After it's created, an endpoint provides a fixed public URL. This URL remains the same throughout the lifetime of the endpoint, regardless of any failures or upgrades that might occur. Integrate the URL with a downstream CDN (such as Amazon CloudFront) or playback device.

    :cloudformationResource: AWS::MediaPackage::OriginEndpoint
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_mediapackage as mediapackage
        
        cfn_origin_endpoint = mediapackage.CfnOriginEndpoint(self, "MyCfnOriginEndpoint",
            channel_id="channelId",
            id="id",
        
            # the properties below are optional
            authorization=mediapackage.CfnOriginEndpoint.AuthorizationProperty(
                cdn_identifier_secret="cdnIdentifierSecret",
                secrets_role_arn="secretsRoleArn"
            ),
            cmaf_package=mediapackage.CfnOriginEndpoint.CmafPackageProperty(
                encryption=mediapackage.CfnOriginEndpoint.CmafEncryptionProperty(
                    speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                        resource_id="resourceId",
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url",
        
                        # the properties below are optional
                        certificate_arn="certificateArn"
                    ),
        
                    # the properties below are optional
                    constant_initialization_vector="constantInitializationVector",
                    key_rotation_interval_seconds=123
                ),
                hls_manifests=[mediapackage.CfnOriginEndpoint.HlsManifestProperty(
                    id="id",
        
                    # the properties below are optional
                    ad_markers="adMarkers",
                    ads_on_delivery_restrictions="adsOnDeliveryRestrictions",
                    ad_triggers=["adTriggers"],
                    include_iframe_only_stream=False,
                    manifest_name="manifestName",
                    playlist_type="playlistType",
                    playlist_window_seconds=123,
                    program_date_time_interval_seconds=123,
                    url="url"
                )],
                segment_duration_seconds=123,
                segment_prefix="segmentPrefix",
                stream_selection=mediapackage.CfnOriginEndpoint.StreamSelectionProperty(
                    max_video_bits_per_second=123,
                    min_video_bits_per_second=123,
                    stream_order="streamOrder"
                )
            ),
            dash_package=mediapackage.CfnOriginEndpoint.DashPackageProperty(
                ads_on_delivery_restrictions="adsOnDeliveryRestrictions",
                ad_triggers=["adTriggers"],
                encryption=mediapackage.CfnOriginEndpoint.DashEncryptionProperty(
                    speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                        resource_id="resourceId",
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url",
        
                        # the properties below are optional
                        certificate_arn="certificateArn"
                    ),
        
                    # the properties below are optional
                    key_rotation_interval_seconds=123
                ),
                manifest_layout="manifestLayout",
                manifest_window_seconds=123,
                min_buffer_time_seconds=123,
                min_update_period_seconds=123,
                period_triggers=["periodTriggers"],
                profile="profile",
                segment_duration_seconds=123,
                segment_template_format="segmentTemplateFormat",
                stream_selection=mediapackage.CfnOriginEndpoint.StreamSelectionProperty(
                    max_video_bits_per_second=123,
                    min_video_bits_per_second=123,
                    stream_order="streamOrder"
                ),
                suggested_presentation_delay_seconds=123,
                utc_timing="utcTiming",
                utc_timing_uri="utcTimingUri"
            ),
            description="description",
            hls_package=mediapackage.CfnOriginEndpoint.HlsPackageProperty(
                ad_markers="adMarkers",
                ads_on_delivery_restrictions="adsOnDeliveryRestrictions",
                ad_triggers=["adTriggers"],
                encryption=mediapackage.CfnOriginEndpoint.HlsEncryptionProperty(
                    speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                        resource_id="resourceId",
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url",
        
                        # the properties below are optional
                        certificate_arn="certificateArn"
                    ),
        
                    # the properties below are optional
                    constant_initialization_vector="constantInitializationVector",
                    encryption_method="encryptionMethod",
                    key_rotation_interval_seconds=123,
                    repeat_ext_xKey=False
                ),
                include_iframe_only_stream=False,
                playlist_type="playlistType",
                playlist_window_seconds=123,
                program_date_time_interval_seconds=123,
                segment_duration_seconds=123,
                stream_selection=mediapackage.CfnOriginEndpoint.StreamSelectionProperty(
                    max_video_bits_per_second=123,
                    min_video_bits_per_second=123,
                    stream_order="streamOrder"
                ),
                use_audio_rendition_group=False
            ),
            manifest_name="manifestName",
            mss_package=mediapackage.CfnOriginEndpoint.MssPackageProperty(
                encryption=mediapackage.CfnOriginEndpoint.MssEncryptionProperty(
                    speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                        resource_id="resourceId",
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url",
        
                        # the properties below are optional
                        certificate_arn="certificateArn"
                    )
                ),
                manifest_window_seconds=123,
                segment_duration_seconds=123,
                stream_selection=mediapackage.CfnOriginEndpoint.StreamSelectionProperty(
                    max_video_bits_per_second=123,
                    min_video_bits_per_second=123,
                    stream_order="streamOrder"
                )
            ),
            origination="origination",
            startover_window_seconds=123,
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            time_delay_seconds=123,
            whitelist=["whitelist"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id_: builtins.str,
        *,
        channel_id: builtins.str,
        id: builtins.str,
        authorization: typing.Optional[typing.Union["CfnOriginEndpoint.AuthorizationProperty", _IResolvable_da3f097b]] = None,
        cmaf_package: typing.Optional[typing.Union["CfnOriginEndpoint.CmafPackageProperty", _IResolvable_da3f097b]] = None,
        dash_package: typing.Optional[typing.Union["CfnOriginEndpoint.DashPackageProperty", _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        hls_package: typing.Optional[typing.Union["CfnOriginEndpoint.HlsPackageProperty", _IResolvable_da3f097b]] = None,
        manifest_name: typing.Optional[builtins.str] = None,
        mss_package: typing.Optional[typing.Union["CfnOriginEndpoint.MssPackageProperty", _IResolvable_da3f097b]] = None,
        origination: typing.Optional[builtins.str] = None,
        startover_window_seconds: typing.Optional[jsii.Number] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        time_delay_seconds: typing.Optional[jsii.Number] = None,
        whitelist: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::MediaPackage::OriginEndpoint``.

        :param scope: - scope in which this resource is defined.
        :param id_: - scoped id of the resource.
        :param channel_id: The ID of the channel associated with this endpoint.
        :param id: The manifest ID is required and must be unique within the OriginEndpoint. The ID can't be changed after the endpoint is created.
        :param authorization: Parameters for CDN authorization.
        :param cmaf_package: Parameters for Common Media Application Format (CMAF) packaging.
        :param dash_package: Parameters for DASH packaging.
        :param description: Any descriptive information that you want to add to the endpoint for future identification purposes.
        :param hls_package: Parameters for Apple HLS packaging.
        :param manifest_name: A short string that's appended to the end of the endpoint URL to create a unique path to this endpoint.
        :param mss_package: Parameters for Microsoft Smooth Streaming packaging.
        :param origination: Controls video origination from this endpoint. - ``ALLOW`` - enables this endpoint to serve content to requesting devices. - ``DENY`` - prevents this endpoint from serving content. Denying origination is helpful for harvesting live-to-VOD assets. For more information about harvesting and origination, see `Live-to-VOD Requirements <https://docs.aws.amazon.com/mediapackage/latest/ug/ltov-reqmts.html>`_ .
        :param startover_window_seconds: Maximum duration (seconds) of content to retain for startover playback. Omit this attribute or enter ``0`` to indicate that startover playback is disabled for this endpoint.
        :param tags: The tags to assign to the endpoint.
        :param time_delay_seconds: Minimum duration (seconds) of delay to enforce on the playback of live content. Omit this attribute or enter ``0`` to indicate that there is no time delay in effect for this endpoint
        :param whitelist: The IP addresses that can access this endpoint.
        '''
        props = CfnOriginEndpointProps(
            channel_id=channel_id,
            id=id,
            authorization=authorization,
            cmaf_package=cmaf_package,
            dash_package=dash_package,
            description=description,
            hls_package=hls_package,
            manifest_name=manifest_name,
            mss_package=mss_package,
            origination=origination,
            startover_window_seconds=startover_window_seconds,
            tags=tags,
            time_delay_seconds=time_delay_seconds,
            whitelist=whitelist,
        )

        jsii.create(self.__class__, self, [scope, id_, props])

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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The endpoint's unique system-generated resource name, based on the AWS record.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrUrl")
    def attr_url(self) -> builtins.str:
        '''URL for the key provider’s key retrieval API endpoint.

        Must start with https://.

        :cloudformationAttribute: Url
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags to assign to the endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="channelId")
    def channel_id(self) -> builtins.str:
        '''The ID of the channel associated with this endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-channelid
        '''
        return typing.cast(builtins.str, jsii.get(self, "channelId"))

    @channel_id.setter
    def channel_id(self, value: builtins.str) -> None:
        jsii.set(self, "channelId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="id")
    def id(self) -> builtins.str:
        '''The manifest ID is required and must be unique within the OriginEndpoint.

        The ID can't be changed after the endpoint is created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-id
        '''
        return typing.cast(builtins.str, jsii.get(self, "id"))

    @id.setter
    def id(self, value: builtins.str) -> None:
        jsii.set(self, "id", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="authorization")
    def authorization(
        self,
    ) -> typing.Optional[typing.Union["CfnOriginEndpoint.AuthorizationProperty", _IResolvable_da3f097b]]:
        '''Parameters for CDN authorization.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-authorization
        '''
        return typing.cast(typing.Optional[typing.Union["CfnOriginEndpoint.AuthorizationProperty", _IResolvable_da3f097b]], jsii.get(self, "authorization"))

    @authorization.setter
    def authorization(
        self,
        value: typing.Optional[typing.Union["CfnOriginEndpoint.AuthorizationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "authorization", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cmafPackage")
    def cmaf_package(
        self,
    ) -> typing.Optional[typing.Union["CfnOriginEndpoint.CmafPackageProperty", _IResolvable_da3f097b]]:
        '''Parameters for Common Media Application Format (CMAF) packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-cmafpackage
        '''
        return typing.cast(typing.Optional[typing.Union["CfnOriginEndpoint.CmafPackageProperty", _IResolvable_da3f097b]], jsii.get(self, "cmafPackage"))

    @cmaf_package.setter
    def cmaf_package(
        self,
        value: typing.Optional[typing.Union["CfnOriginEndpoint.CmafPackageProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "cmafPackage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dashPackage")
    def dash_package(
        self,
    ) -> typing.Optional[typing.Union["CfnOriginEndpoint.DashPackageProperty", _IResolvable_da3f097b]]:
        '''Parameters for DASH packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-dashpackage
        '''
        return typing.cast(typing.Optional[typing.Union["CfnOriginEndpoint.DashPackageProperty", _IResolvable_da3f097b]], jsii.get(self, "dashPackage"))

    @dash_package.setter
    def dash_package(
        self,
        value: typing.Optional[typing.Union["CfnOriginEndpoint.DashPackageProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "dashPackage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''Any descriptive information that you want to add to the endpoint for future identification purposes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hlsPackage")
    def hls_package(
        self,
    ) -> typing.Optional[typing.Union["CfnOriginEndpoint.HlsPackageProperty", _IResolvable_da3f097b]]:
        '''Parameters for Apple HLS packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-hlspackage
        '''
        return typing.cast(typing.Optional[typing.Union["CfnOriginEndpoint.HlsPackageProperty", _IResolvable_da3f097b]], jsii.get(self, "hlsPackage"))

    @hls_package.setter
    def hls_package(
        self,
        value: typing.Optional[typing.Union["CfnOriginEndpoint.HlsPackageProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "hlsPackage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="manifestName")
    def manifest_name(self) -> typing.Optional[builtins.str]:
        '''A short string that's appended to the end of the endpoint URL to create a unique path to this endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-manifestname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "manifestName"))

    @manifest_name.setter
    def manifest_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "manifestName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="mssPackage")
    def mss_package(
        self,
    ) -> typing.Optional[typing.Union["CfnOriginEndpoint.MssPackageProperty", _IResolvable_da3f097b]]:
        '''Parameters for Microsoft Smooth Streaming packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-msspackage
        '''
        return typing.cast(typing.Optional[typing.Union["CfnOriginEndpoint.MssPackageProperty", _IResolvable_da3f097b]], jsii.get(self, "mssPackage"))

    @mss_package.setter
    def mss_package(
        self,
        value: typing.Optional[typing.Union["CfnOriginEndpoint.MssPackageProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "mssPackage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="origination")
    def origination(self) -> typing.Optional[builtins.str]:
        '''Controls video origination from this endpoint.

        - ``ALLOW`` - enables this endpoint to serve content to requesting devices.
        - ``DENY`` - prevents this endpoint from serving content. Denying origination is helpful for harvesting live-to-VOD assets. For more information about harvesting and origination, see `Live-to-VOD Requirements <https://docs.aws.amazon.com/mediapackage/latest/ug/ltov-reqmts.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-origination
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "origination"))

    @origination.setter
    def origination(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "origination", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="startoverWindowSeconds")
    def startover_window_seconds(self) -> typing.Optional[jsii.Number]:
        '''Maximum duration (seconds) of content to retain for startover playback.

        Omit this attribute or enter ``0`` to indicate that startover playback is disabled for this endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-startoverwindowseconds
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "startoverWindowSeconds"))

    @startover_window_seconds.setter
    def startover_window_seconds(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "startoverWindowSeconds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="timeDelaySeconds")
    def time_delay_seconds(self) -> typing.Optional[jsii.Number]:
        '''Minimum duration (seconds) of delay to enforce on the playback of live content.

        Omit this attribute or enter ``0`` to indicate that there is no time delay in effect for this endpoint

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-timedelayseconds
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "timeDelaySeconds"))

    @time_delay_seconds.setter
    def time_delay_seconds(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "timeDelaySeconds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="whitelist")
    def whitelist(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The IP addresses that can access this endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-whitelist
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "whitelist"))

    @whitelist.setter
    def whitelist(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "whitelist", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnOriginEndpoint.AuthorizationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cdn_identifier_secret": "cdnIdentifierSecret",
            "secrets_role_arn": "secretsRoleArn",
        },
    )
    class AuthorizationProperty:
        def __init__(
            self,
            *,
            cdn_identifier_secret: builtins.str,
            secrets_role_arn: builtins.str,
        ) -> None:
            '''Parameters for enabling CDN authorization on the endpoint.

            :param cdn_identifier_secret: The Amazon Resource Name (ARN) for the secret in AWS Secrets Manager that your Content Distribution Network (CDN) uses for authorization to access your endpoint.
            :param secrets_role_arn: The Amazon Resource Name (ARN) for the IAM role that allows MediaPackage to communicate with AWS Secrets Manager .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-authorization.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                authorization_property = mediapackage.CfnOriginEndpoint.AuthorizationProperty(
                    cdn_identifier_secret="cdnIdentifierSecret",
                    secrets_role_arn="secretsRoleArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "cdn_identifier_secret": cdn_identifier_secret,
                "secrets_role_arn": secrets_role_arn,
            }

        @builtins.property
        def cdn_identifier_secret(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) for the secret in AWS Secrets Manager that your Content Distribution Network (CDN) uses for authorization to access your endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-authorization.html#cfn-mediapackage-originendpoint-authorization-cdnidentifiersecret
            '''
            result = self._values.get("cdn_identifier_secret")
            assert result is not None, "Required property 'cdn_identifier_secret' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def secrets_role_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) for the IAM role that allows MediaPackage to communicate with AWS Secrets Manager .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-authorization.html#cfn-mediapackage-originendpoint-authorization-secretsrolearn
            '''
            result = self._values.get("secrets_role_arn")
            assert result is not None, "Required property 'secrets_role_arn' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AuthorizationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnOriginEndpoint.CmafEncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "speke_key_provider": "spekeKeyProvider",
            "constant_initialization_vector": "constantInitializationVector",
            "key_rotation_interval_seconds": "keyRotationIntervalSeconds",
        },
    )
    class CmafEncryptionProperty:
        def __init__(
            self,
            *,
            speke_key_provider: typing.Union["CfnOriginEndpoint.SpekeKeyProviderProperty", _IResolvable_da3f097b],
            constant_initialization_vector: typing.Optional[builtins.str] = None,
            key_rotation_interval_seconds: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Holds encryption information so that access to the content can be controlled by a DRM solution.

            :param speke_key_provider: Parameters for the SPEKE key provider.
            :param constant_initialization_vector: An optional 128-bit, 16-byte hex value represented by a 32-character string, used in conjunction with the key for encrypting blocks. If you don't specify a value, then MediaPackage creates the constant initialization vector (IV).
            :param key_rotation_interval_seconds: Number of seconds before AWS Elemental MediaPackage rotates to a new key. By default, rotation is set to 60 seconds. Set to ``0`` to disable key rotation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-cmafencryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                cmaf_encryption_property = mediapackage.CfnOriginEndpoint.CmafEncryptionProperty(
                    speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                        resource_id="resourceId",
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url",
                
                        # the properties below are optional
                        certificate_arn="certificateArn"
                    ),
                
                    # the properties below are optional
                    constant_initialization_vector="constantInitializationVector",
                    key_rotation_interval_seconds=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "speke_key_provider": speke_key_provider,
            }
            if constant_initialization_vector is not None:
                self._values["constant_initialization_vector"] = constant_initialization_vector
            if key_rotation_interval_seconds is not None:
                self._values["key_rotation_interval_seconds"] = key_rotation_interval_seconds

        @builtins.property
        def speke_key_provider(
            self,
        ) -> typing.Union["CfnOriginEndpoint.SpekeKeyProviderProperty", _IResolvable_da3f097b]:
            '''Parameters for the SPEKE key provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-cmafencryption.html#cfn-mediapackage-originendpoint-cmafencryption-spekekeyprovider
            '''
            result = self._values.get("speke_key_provider")
            assert result is not None, "Required property 'speke_key_provider' is missing"
            return typing.cast(typing.Union["CfnOriginEndpoint.SpekeKeyProviderProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def constant_initialization_vector(self) -> typing.Optional[builtins.str]:
            '''An optional 128-bit, 16-byte hex value represented by a 32-character string, used in conjunction with the key for encrypting blocks.

            If you don't specify a value, then MediaPackage creates the constant initialization vector (IV).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-cmafencryption.html#cfn-mediapackage-originendpoint-cmafencryption-constantinitializationvector
            '''
            result = self._values.get("constant_initialization_vector")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def key_rotation_interval_seconds(self) -> typing.Optional[jsii.Number]:
            '''Number of seconds before AWS Elemental MediaPackage rotates to a new key.

            By default, rotation is set to 60 seconds. Set to ``0`` to disable key rotation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-cmafencryption.html#cfn-mediapackage-originendpoint-cmafencryption-keyrotationintervalseconds
            '''
            result = self._values.get("key_rotation_interval_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CmafEncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnOriginEndpoint.CmafPackageProperty",
        jsii_struct_bases=[],
        name_mapping={
            "encryption": "encryption",
            "hls_manifests": "hlsManifests",
            "segment_duration_seconds": "segmentDurationSeconds",
            "segment_prefix": "segmentPrefix",
            "stream_selection": "streamSelection",
        },
    )
    class CmafPackageProperty:
        def __init__(
            self,
            *,
            encryption: typing.Optional[typing.Union["CfnOriginEndpoint.CmafEncryptionProperty", _IResolvable_da3f097b]] = None,
            hls_manifests: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnOriginEndpoint.HlsManifestProperty", _IResolvable_da3f097b]]]] = None,
            segment_duration_seconds: typing.Optional[jsii.Number] = None,
            segment_prefix: typing.Optional[builtins.str] = None,
            stream_selection: typing.Optional[typing.Union["CfnOriginEndpoint.StreamSelectionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Parameters for Common Media Application Format (CMAF) packaging.

            :param encryption: Parameters for encrypting content.
            :param hls_manifests: A list of HLS manifest configurations that are available from this endpoint.
            :param segment_duration_seconds: Duration (in seconds) of each segment. Actual segments are rounded to the nearest multiple of the source segment duration.
            :param segment_prefix: An optional custom string that is prepended to the name of each segment. If not specified, the segment prefix defaults to the ChannelId.
            :param stream_selection: Limitations for outputs from the endpoint, based on the video bitrate.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-cmafpackage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                cmaf_package_property = mediapackage.CfnOriginEndpoint.CmafPackageProperty(
                    encryption=mediapackage.CfnOriginEndpoint.CmafEncryptionProperty(
                        speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                            resource_id="resourceId",
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url",
                
                            # the properties below are optional
                            certificate_arn="certificateArn"
                        ),
                
                        # the properties below are optional
                        constant_initialization_vector="constantInitializationVector",
                        key_rotation_interval_seconds=123
                    ),
                    hls_manifests=[mediapackage.CfnOriginEndpoint.HlsManifestProperty(
                        id="id",
                
                        # the properties below are optional
                        ad_markers="adMarkers",
                        ads_on_delivery_restrictions="adsOnDeliveryRestrictions",
                        ad_triggers=["adTriggers"],
                        include_iframe_only_stream=False,
                        manifest_name="manifestName",
                        playlist_type="playlistType",
                        playlist_window_seconds=123,
                        program_date_time_interval_seconds=123,
                        url="url"
                    )],
                    segment_duration_seconds=123,
                    segment_prefix="segmentPrefix",
                    stream_selection=mediapackage.CfnOriginEndpoint.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if encryption is not None:
                self._values["encryption"] = encryption
            if hls_manifests is not None:
                self._values["hls_manifests"] = hls_manifests
            if segment_duration_seconds is not None:
                self._values["segment_duration_seconds"] = segment_duration_seconds
            if segment_prefix is not None:
                self._values["segment_prefix"] = segment_prefix
            if stream_selection is not None:
                self._values["stream_selection"] = stream_selection

        @builtins.property
        def encryption(
            self,
        ) -> typing.Optional[typing.Union["CfnOriginEndpoint.CmafEncryptionProperty", _IResolvable_da3f097b]]:
            '''Parameters for encrypting content.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-cmafpackage.html#cfn-mediapackage-originendpoint-cmafpackage-encryption
            '''
            result = self._values.get("encryption")
            return typing.cast(typing.Optional[typing.Union["CfnOriginEndpoint.CmafEncryptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def hls_manifests(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnOriginEndpoint.HlsManifestProperty", _IResolvable_da3f097b]]]]:
            '''A list of HLS manifest configurations that are available from this endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-cmafpackage.html#cfn-mediapackage-originendpoint-cmafpackage-hlsmanifests
            '''
            result = self._values.get("hls_manifests")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnOriginEndpoint.HlsManifestProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def segment_duration_seconds(self) -> typing.Optional[jsii.Number]:
            '''Duration (in seconds) of each segment.

            Actual segments are rounded to the nearest multiple of the source segment duration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-cmafpackage.html#cfn-mediapackage-originendpoint-cmafpackage-segmentdurationseconds
            '''
            result = self._values.get("segment_duration_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def segment_prefix(self) -> typing.Optional[builtins.str]:
            '''An optional custom string that is prepended to the name of each segment.

            If not specified, the segment prefix defaults to the ChannelId.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-cmafpackage.html#cfn-mediapackage-originendpoint-cmafpackage-segmentprefix
            '''
            result = self._values.get("segment_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def stream_selection(
            self,
        ) -> typing.Optional[typing.Union["CfnOriginEndpoint.StreamSelectionProperty", _IResolvable_da3f097b]]:
            '''Limitations for outputs from the endpoint, based on the video bitrate.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-cmafpackage.html#cfn-mediapackage-originendpoint-cmafpackage-streamselection
            '''
            result = self._values.get("stream_selection")
            return typing.cast(typing.Optional[typing.Union["CfnOriginEndpoint.StreamSelectionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CmafPackageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnOriginEndpoint.DashEncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "speke_key_provider": "spekeKeyProvider",
            "key_rotation_interval_seconds": "keyRotationIntervalSeconds",
        },
    )
    class DashEncryptionProperty:
        def __init__(
            self,
            *,
            speke_key_provider: typing.Union["CfnOriginEndpoint.SpekeKeyProviderProperty", _IResolvable_da3f097b],
            key_rotation_interval_seconds: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Holds encryption information so that access to the content can be controlled by a DRM solution.

            :param speke_key_provider: Parameters for the SPEKE key provider.
            :param key_rotation_interval_seconds: Number of seconds before AWS Elemental MediaPackage rotates to a new key. By default, rotation is set to 60 seconds. Set to ``0`` to disable key rotation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashencryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                dash_encryption_property = mediapackage.CfnOriginEndpoint.DashEncryptionProperty(
                    speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                        resource_id="resourceId",
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url",
                
                        # the properties below are optional
                        certificate_arn="certificateArn"
                    ),
                
                    # the properties below are optional
                    key_rotation_interval_seconds=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "speke_key_provider": speke_key_provider,
            }
            if key_rotation_interval_seconds is not None:
                self._values["key_rotation_interval_seconds"] = key_rotation_interval_seconds

        @builtins.property
        def speke_key_provider(
            self,
        ) -> typing.Union["CfnOriginEndpoint.SpekeKeyProviderProperty", _IResolvable_da3f097b]:
            '''Parameters for the SPEKE key provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashencryption.html#cfn-mediapackage-originendpoint-dashencryption-spekekeyprovider
            '''
            result = self._values.get("speke_key_provider")
            assert result is not None, "Required property 'speke_key_provider' is missing"
            return typing.cast(typing.Union["CfnOriginEndpoint.SpekeKeyProviderProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def key_rotation_interval_seconds(self) -> typing.Optional[jsii.Number]:
            '''Number of seconds before AWS Elemental MediaPackage rotates to a new key.

            By default, rotation is set to 60 seconds. Set to ``0`` to disable key rotation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashencryption.html#cfn-mediapackage-originendpoint-dashencryption-keyrotationintervalseconds
            '''
            result = self._values.get("key_rotation_interval_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DashEncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnOriginEndpoint.DashPackageProperty",
        jsii_struct_bases=[],
        name_mapping={
            "ads_on_delivery_restrictions": "adsOnDeliveryRestrictions",
            "ad_triggers": "adTriggers",
            "encryption": "encryption",
            "manifest_layout": "manifestLayout",
            "manifest_window_seconds": "manifestWindowSeconds",
            "min_buffer_time_seconds": "minBufferTimeSeconds",
            "min_update_period_seconds": "minUpdatePeriodSeconds",
            "period_triggers": "periodTriggers",
            "profile": "profile",
            "segment_duration_seconds": "segmentDurationSeconds",
            "segment_template_format": "segmentTemplateFormat",
            "stream_selection": "streamSelection",
            "suggested_presentation_delay_seconds": "suggestedPresentationDelaySeconds",
            "utc_timing": "utcTiming",
            "utc_timing_uri": "utcTimingUri",
        },
    )
    class DashPackageProperty:
        def __init__(
            self,
            *,
            ads_on_delivery_restrictions: typing.Optional[builtins.str] = None,
            ad_triggers: typing.Optional[typing.Sequence[builtins.str]] = None,
            encryption: typing.Optional[typing.Union["CfnOriginEndpoint.DashEncryptionProperty", _IResolvable_da3f097b]] = None,
            manifest_layout: typing.Optional[builtins.str] = None,
            manifest_window_seconds: typing.Optional[jsii.Number] = None,
            min_buffer_time_seconds: typing.Optional[jsii.Number] = None,
            min_update_period_seconds: typing.Optional[jsii.Number] = None,
            period_triggers: typing.Optional[typing.Sequence[builtins.str]] = None,
            profile: typing.Optional[builtins.str] = None,
            segment_duration_seconds: typing.Optional[jsii.Number] = None,
            segment_template_format: typing.Optional[builtins.str] = None,
            stream_selection: typing.Optional[typing.Union["CfnOriginEndpoint.StreamSelectionProperty", _IResolvable_da3f097b]] = None,
            suggested_presentation_delay_seconds: typing.Optional[jsii.Number] = None,
            utc_timing: typing.Optional[builtins.str] = None,
            utc_timing_uri: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Parameters for DASH packaging.

            :param ads_on_delivery_restrictions: The flags on SCTE-35 segmentation descriptors that have to be present for MediaPackage to insert ad markers in the output manifest. For information about SCTE-35 in MediaPackage, see `SCTE-35 Message Options in AWS Elemental MediaPackage <https://docs.aws.amazon.com/mediapackage/latest/ug/scte.html>`_ .
            :param ad_triggers: Specifies the SCTE-35 message types that MediaPackage treats as ad markers in the output manifest. Valid values: - ``BREAK`` - ``DISTRIBUTOR_ADVERTISEMENT`` - ``DISTRIBUTOR_OVERLAY_PLACEMENT_OPPORTUNITY`` . - ``DISTRIBUTOR_PLACEMENT_OPPORTUNITY`` . - ``PROVIDER_ADVERTISEMENT`` . - ``PROVIDER_OVERLAY_PLACEMENT_OPPORTUNITY`` . - ``PROVIDER_PLACEMENT_OPPORTUNITY`` . - ``SPLICE_INSERT`` .
            :param encryption: Parameters for encrypting content.
            :param manifest_layout: Determines the position of some tags in the manifest. Options: - ``FULL`` - elements like ``SegmentTemplate`` and ``ContentProtection`` are included in each ``Representation`` . - ``COMPACT`` - duplicate elements are combined and presented at the ``AdaptationSet`` level.
            :param manifest_window_seconds: Time window (in seconds) contained in each manifest.
            :param min_buffer_time_seconds: Minimum amount of content (measured in seconds) that a player must keep available in the buffer.
            :param min_update_period_seconds: Minimum amount of time (in seconds) that the player should wait before requesting updates to the manifest.
            :param period_triggers: Controls whether MediaPackage produces single-period or multi-period DASH manifests. For more information about periods, see `Multi-period DASH in AWS Elemental MediaPackage <https://docs.aws.amazon.com/mediapackage/latest/ug/multi-period.html>`_ . Valid values: - ``ADS`` - MediaPackage will produce multi-period DASH manifests. Periods are created based on the SCTE-35 ad markers present in the input manifest. - *No value* - MediaPackage will produce single-period DASH manifests. This is the default setting.
            :param profile: DASH profile for the output, such as HbbTV. Valid values: - ``NONE`` - the output doesn't use a DASH profile. - ``HBBTV_1_5`` - the output is HbbTV-compliant.
            :param segment_duration_seconds: Duration (in seconds) of each fragment. Actual fragments are rounded to the nearest multiple of the source fragment duration.
            :param segment_template_format: Determines the type of variable used in the ``media`` URL of the ``SegmentTemplate`` tag in the manifest. Also specifies if segment timeline information is included in ``SegmentTimeline`` or ``SegmentTemplate`` . - ``NUMBER_WITH_TIMELINE`` - The ``$Number$`` variable is used in the ``media`` URL. The value of this variable is the sequential number of the segment. A full ``SegmentTimeline`` object is presented in each ``SegmentTemplate`` . - ``NUMBER_WITH_DURATION`` - The ``$Number$`` variable is used in the ``media`` URL and a ``duration`` attribute is added to the segment template. The ``SegmentTimeline`` object is removed from the representation. - ``TIME_WITH_TIMELINE`` - The ``$Time$`` variable is used in the ``media`` URL. The value of this variable is the timestamp of when the segment starts. A full ``SegmentTimeline`` object is presented in each ``SegmentTemplate`` .
            :param stream_selection: Limitations for outputs from the endpoint, based on the video bitrate.
            :param suggested_presentation_delay_seconds: Amount of time (in seconds) that the player should be from the live point at the end of the manifest.
            :param utc_timing: Determines the type of UTC timing included in the DASH Media Presentation Description (MPD).
            :param utc_timing_uri: Specifies the value attribute of the UTC timing field when utcTiming is set to HTTP-ISO or HTTP-HEAD.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                dash_package_property = mediapackage.CfnOriginEndpoint.DashPackageProperty(
                    ads_on_delivery_restrictions="adsOnDeliveryRestrictions",
                    ad_triggers=["adTriggers"],
                    encryption=mediapackage.CfnOriginEndpoint.DashEncryptionProperty(
                        speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                            resource_id="resourceId",
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url",
                
                            # the properties below are optional
                            certificate_arn="certificateArn"
                        ),
                
                        # the properties below are optional
                        key_rotation_interval_seconds=123
                    ),
                    manifest_layout="manifestLayout",
                    manifest_window_seconds=123,
                    min_buffer_time_seconds=123,
                    min_update_period_seconds=123,
                    period_triggers=["periodTriggers"],
                    profile="profile",
                    segment_duration_seconds=123,
                    segment_template_format="segmentTemplateFormat",
                    stream_selection=mediapackage.CfnOriginEndpoint.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    ),
                    suggested_presentation_delay_seconds=123,
                    utc_timing="utcTiming",
                    utc_timing_uri="utcTimingUri"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if ads_on_delivery_restrictions is not None:
                self._values["ads_on_delivery_restrictions"] = ads_on_delivery_restrictions
            if ad_triggers is not None:
                self._values["ad_triggers"] = ad_triggers
            if encryption is not None:
                self._values["encryption"] = encryption
            if manifest_layout is not None:
                self._values["manifest_layout"] = manifest_layout
            if manifest_window_seconds is not None:
                self._values["manifest_window_seconds"] = manifest_window_seconds
            if min_buffer_time_seconds is not None:
                self._values["min_buffer_time_seconds"] = min_buffer_time_seconds
            if min_update_period_seconds is not None:
                self._values["min_update_period_seconds"] = min_update_period_seconds
            if period_triggers is not None:
                self._values["period_triggers"] = period_triggers
            if profile is not None:
                self._values["profile"] = profile
            if segment_duration_seconds is not None:
                self._values["segment_duration_seconds"] = segment_duration_seconds
            if segment_template_format is not None:
                self._values["segment_template_format"] = segment_template_format
            if stream_selection is not None:
                self._values["stream_selection"] = stream_selection
            if suggested_presentation_delay_seconds is not None:
                self._values["suggested_presentation_delay_seconds"] = suggested_presentation_delay_seconds
            if utc_timing is not None:
                self._values["utc_timing"] = utc_timing
            if utc_timing_uri is not None:
                self._values["utc_timing_uri"] = utc_timing_uri

        @builtins.property
        def ads_on_delivery_restrictions(self) -> typing.Optional[builtins.str]:
            '''The flags on SCTE-35 segmentation descriptors that have to be present for MediaPackage to insert ad markers in the output manifest.

            For information about SCTE-35 in MediaPackage, see `SCTE-35 Message Options in AWS Elemental MediaPackage <https://docs.aws.amazon.com/mediapackage/latest/ug/scte.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-adsondeliveryrestrictions
            '''
            result = self._values.get("ads_on_delivery_restrictions")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ad_triggers(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Specifies the SCTE-35 message types that MediaPackage treats as ad markers in the output manifest.

            Valid values:

            - ``BREAK``
            - ``DISTRIBUTOR_ADVERTISEMENT``
            - ``DISTRIBUTOR_OVERLAY_PLACEMENT_OPPORTUNITY`` .
            - ``DISTRIBUTOR_PLACEMENT_OPPORTUNITY`` .
            - ``PROVIDER_ADVERTISEMENT`` .
            - ``PROVIDER_OVERLAY_PLACEMENT_OPPORTUNITY`` .
            - ``PROVIDER_PLACEMENT_OPPORTUNITY`` .
            - ``SPLICE_INSERT`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-adtriggers
            '''
            result = self._values.get("ad_triggers")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def encryption(
            self,
        ) -> typing.Optional[typing.Union["CfnOriginEndpoint.DashEncryptionProperty", _IResolvable_da3f097b]]:
            '''Parameters for encrypting content.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-encryption
            '''
            result = self._values.get("encryption")
            return typing.cast(typing.Optional[typing.Union["CfnOriginEndpoint.DashEncryptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def manifest_layout(self) -> typing.Optional[builtins.str]:
            '''Determines the position of some tags in the manifest.

            Options:

            - ``FULL`` - elements like ``SegmentTemplate`` and ``ContentProtection`` are included in each ``Representation`` .
            - ``COMPACT`` - duplicate elements are combined and presented at the ``AdaptationSet`` level.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-manifestlayout
            '''
            result = self._values.get("manifest_layout")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def manifest_window_seconds(self) -> typing.Optional[jsii.Number]:
            '''Time window (in seconds) contained in each manifest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-manifestwindowseconds
            '''
            result = self._values.get("manifest_window_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def min_buffer_time_seconds(self) -> typing.Optional[jsii.Number]:
            '''Minimum amount of content (measured in seconds) that a player must keep available in the buffer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-minbuffertimeseconds
            '''
            result = self._values.get("min_buffer_time_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def min_update_period_seconds(self) -> typing.Optional[jsii.Number]:
            '''Minimum amount of time (in seconds) that the player should wait before requesting updates to the manifest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-minupdateperiodseconds
            '''
            result = self._values.get("min_update_period_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def period_triggers(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Controls whether MediaPackage produces single-period or multi-period DASH manifests.

            For more information about periods, see `Multi-period DASH in AWS Elemental MediaPackage <https://docs.aws.amazon.com/mediapackage/latest/ug/multi-period.html>`_ .

            Valid values:

            - ``ADS`` - MediaPackage will produce multi-period DASH manifests. Periods are created based on the SCTE-35 ad markers present in the input manifest.
            - *No value* - MediaPackage will produce single-period DASH manifests. This is the default setting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-periodtriggers
            '''
            result = self._values.get("period_triggers")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def profile(self) -> typing.Optional[builtins.str]:
            '''DASH profile for the output, such as HbbTV.

            Valid values:

            - ``NONE`` - the output doesn't use a DASH profile.
            - ``HBBTV_1_5`` - the output is HbbTV-compliant.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-profile
            '''
            result = self._values.get("profile")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def segment_duration_seconds(self) -> typing.Optional[jsii.Number]:
            '''Duration (in seconds) of each fragment.

            Actual fragments are rounded to the nearest multiple of the source fragment duration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-segmentdurationseconds
            '''
            result = self._values.get("segment_duration_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def segment_template_format(self) -> typing.Optional[builtins.str]:
            '''Determines the type of variable used in the ``media`` URL of the ``SegmentTemplate`` tag in the manifest.

            Also specifies if segment timeline information is included in ``SegmentTimeline`` or ``SegmentTemplate`` .

            - ``NUMBER_WITH_TIMELINE`` - The ``$Number$`` variable is used in the ``media`` URL. The value of this variable is the sequential number of the segment. A full ``SegmentTimeline`` object is presented in each ``SegmentTemplate`` .
            - ``NUMBER_WITH_DURATION`` - The ``$Number$`` variable is used in the ``media`` URL and a ``duration`` attribute is added to the segment template. The ``SegmentTimeline`` object is removed from the representation.
            - ``TIME_WITH_TIMELINE`` - The ``$Time$`` variable is used in the ``media`` URL. The value of this variable is the timestamp of when the segment starts. A full ``SegmentTimeline`` object is presented in each ``SegmentTemplate`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-segmenttemplateformat
            '''
            result = self._values.get("segment_template_format")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def stream_selection(
            self,
        ) -> typing.Optional[typing.Union["CfnOriginEndpoint.StreamSelectionProperty", _IResolvable_da3f097b]]:
            '''Limitations for outputs from the endpoint, based on the video bitrate.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-streamselection
            '''
            result = self._values.get("stream_selection")
            return typing.cast(typing.Optional[typing.Union["CfnOriginEndpoint.StreamSelectionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def suggested_presentation_delay_seconds(self) -> typing.Optional[jsii.Number]:
            '''Amount of time (in seconds) that the player should be from the live point at the end of the manifest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-suggestedpresentationdelayseconds
            '''
            result = self._values.get("suggested_presentation_delay_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def utc_timing(self) -> typing.Optional[builtins.str]:
            '''Determines the type of UTC timing included in the DASH Media Presentation Description (MPD).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-utctiming
            '''
            result = self._values.get("utc_timing")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def utc_timing_uri(self) -> typing.Optional[builtins.str]:
            '''Specifies the value attribute of the UTC timing field when utcTiming is set to HTTP-ISO or HTTP-HEAD.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-dashpackage.html#cfn-mediapackage-originendpoint-dashpackage-utctiminguri
            '''
            result = self._values.get("utc_timing_uri")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DashPackageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnOriginEndpoint.HlsEncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "speke_key_provider": "spekeKeyProvider",
            "constant_initialization_vector": "constantInitializationVector",
            "encryption_method": "encryptionMethod",
            "key_rotation_interval_seconds": "keyRotationIntervalSeconds",
            "repeat_ext_x_key": "repeatExtXKey",
        },
    )
    class HlsEncryptionProperty:
        def __init__(
            self,
            *,
            speke_key_provider: typing.Union["CfnOriginEndpoint.SpekeKeyProviderProperty", _IResolvable_da3f097b],
            constant_initialization_vector: typing.Optional[builtins.str] = None,
            encryption_method: typing.Optional[builtins.str] = None,
            key_rotation_interval_seconds: typing.Optional[jsii.Number] = None,
            repeat_ext_x_key: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Holds encryption information so that access to the content can be controlled by a DRM solution.

            :param speke_key_provider: Parameters for the SPEKE key provider.
            :param constant_initialization_vector: A 128-bit, 16-byte hex value represented by a 32-character string, used with the key for encrypting blocks.
            :param encryption_method: HLS encryption type.
            :param key_rotation_interval_seconds: Number of seconds before AWS Elemental MediaPackage rotates to a new key. By default, rotation is set to 60 seconds. Set to ``0`` to disable key rotation.
            :param repeat_ext_x_key: Repeat the ``EXT-X-KEY`` directive for every media segment. This might result in an increase in client requests to the DRM server.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsencryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                hls_encryption_property = mediapackage.CfnOriginEndpoint.HlsEncryptionProperty(
                    speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                        resource_id="resourceId",
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url",
                
                        # the properties below are optional
                        certificate_arn="certificateArn"
                    ),
                
                    # the properties below are optional
                    constant_initialization_vector="constantInitializationVector",
                    encryption_method="encryptionMethod",
                    key_rotation_interval_seconds=123,
                    repeat_ext_xKey=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "speke_key_provider": speke_key_provider,
            }
            if constant_initialization_vector is not None:
                self._values["constant_initialization_vector"] = constant_initialization_vector
            if encryption_method is not None:
                self._values["encryption_method"] = encryption_method
            if key_rotation_interval_seconds is not None:
                self._values["key_rotation_interval_seconds"] = key_rotation_interval_seconds
            if repeat_ext_x_key is not None:
                self._values["repeat_ext_x_key"] = repeat_ext_x_key

        @builtins.property
        def speke_key_provider(
            self,
        ) -> typing.Union["CfnOriginEndpoint.SpekeKeyProviderProperty", _IResolvable_da3f097b]:
            '''Parameters for the SPEKE key provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsencryption.html#cfn-mediapackage-originendpoint-hlsencryption-spekekeyprovider
            '''
            result = self._values.get("speke_key_provider")
            assert result is not None, "Required property 'speke_key_provider' is missing"
            return typing.cast(typing.Union["CfnOriginEndpoint.SpekeKeyProviderProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def constant_initialization_vector(self) -> typing.Optional[builtins.str]:
            '''A 128-bit, 16-byte hex value represented by a 32-character string, used with the key for encrypting blocks.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsencryption.html#cfn-mediapackage-originendpoint-hlsencryption-constantinitializationvector
            '''
            result = self._values.get("constant_initialization_vector")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def encryption_method(self) -> typing.Optional[builtins.str]:
            '''HLS encryption type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsencryption.html#cfn-mediapackage-originendpoint-hlsencryption-encryptionmethod
            '''
            result = self._values.get("encryption_method")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def key_rotation_interval_seconds(self) -> typing.Optional[jsii.Number]:
            '''Number of seconds before AWS Elemental MediaPackage rotates to a new key.

            By default, rotation is set to 60 seconds. Set to ``0`` to disable key rotation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsencryption.html#cfn-mediapackage-originendpoint-hlsencryption-keyrotationintervalseconds
            '''
            result = self._values.get("key_rotation_interval_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def repeat_ext_x_key(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Repeat the ``EXT-X-KEY`` directive for every media segment.

            This might result in an increase in client requests to the DRM server.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsencryption.html#cfn-mediapackage-originendpoint-hlsencryption-repeatextxkey
            '''
            result = self._values.get("repeat_ext_x_key")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HlsEncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnOriginEndpoint.HlsManifestProperty",
        jsii_struct_bases=[],
        name_mapping={
            "id": "id",
            "ad_markers": "adMarkers",
            "ads_on_delivery_restrictions": "adsOnDeliveryRestrictions",
            "ad_triggers": "adTriggers",
            "include_iframe_only_stream": "includeIframeOnlyStream",
            "manifest_name": "manifestName",
            "playlist_type": "playlistType",
            "playlist_window_seconds": "playlistWindowSeconds",
            "program_date_time_interval_seconds": "programDateTimeIntervalSeconds",
            "url": "url",
        },
    )
    class HlsManifestProperty:
        def __init__(
            self,
            *,
            id: builtins.str,
            ad_markers: typing.Optional[builtins.str] = None,
            ads_on_delivery_restrictions: typing.Optional[builtins.str] = None,
            ad_triggers: typing.Optional[typing.Sequence[builtins.str]] = None,
            include_iframe_only_stream: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            manifest_name: typing.Optional[builtins.str] = None,
            playlist_type: typing.Optional[builtins.str] = None,
            playlist_window_seconds: typing.Optional[jsii.Number] = None,
            program_date_time_interval_seconds: typing.Optional[jsii.Number] = None,
            url: typing.Optional[builtins.str] = None,
        ) -> None:
            '''An HTTP Live Streaming (HLS) manifest configuration on a CMAF endpoint.

            :param id: The manifest ID is required and must be unique within the OriginEndpoint. The ID can't be changed after the endpoint is created.
            :param ad_markers: Controls how ad markers are included in the packaged endpoint. Valid values are ``none`` , ``passthrough`` , or ``scte35_enhanced`` . - ``NONE`` - omits all SCTE-35 ad markers from the output. - ``PASSTHROUGH`` - creates a copy in the output of the SCTE-35 ad markers (comments) taken directly from the input manifest. - ``SCTE35_ENHANCED`` - generates ad markers and blackout tags in the output based on the SCTE-35 messages from the input manifest.
            :param ads_on_delivery_restrictions: The flags on SCTE-35 segmentation descriptors that have to be present for MediaPackage to insert ad markers in the output manifest. For information about SCTE-35 in MediaPackage, see `SCTE-35 Message Options in AWS Elemental MediaPackage <https://docs.aws.amazon.com/mediapackage/latest/ug/scte.html>`_ .
            :param ad_triggers: Specifies the SCTE-35 message types that MediaPackage treats as ad markers in the output manifest. Valid values: - ``BREAK`` - ``DISTRIBUTOR_ADVERTISEMENT`` - ``DISTRIBUTOR_OVERLAY_PLACEMENT_OPPORTUNITY`` - ``DISTRIBUTOR_PLACEMENT_OPPORTUNITY`` - ``PROVIDER_ADVERTISEMENT`` - ``PROVIDER_OVERLAY_PLACEMENT_OPPORTUNITY`` - ``PROVIDER_PLACEMENT_OPPORTUNITY`` - ``SPLICE_INSERT``
            :param include_iframe_only_stream: Applies to stream sets with a single video track only. When true, the stream set includes an additional I-frame only stream, along with the other tracks. If false, this extra stream is not included.
            :param manifest_name: A short string that's appended to the end of the endpoint URL to create a unique path to this endpoint. The manifestName on the HLSManifest object overrides the manifestName that you provided on the originEndpoint object.
            :param playlist_type: When specified as either ``event`` or ``vod`` , a corresponding ``EXT-X-PLAYLIST-TYPE`` entry is included in the media playlist. Indicates if the playlist is live-to-VOD content.
            :param playlist_window_seconds: Time window (in seconds) contained in each parent manifest.
            :param program_date_time_interval_seconds: Inserts ``EXT-X-PROGRAM-DATE-TIME`` tags in the output manifest at the interval that you specify. Additionally, ID3Timed metadata messages are generated every 5 seconds starting when the content was ingested. Irrespective of this parameter, if any ID3Timed metadata is in the HLS input, it is passed through to the HLS output. Omit this attribute or enter ``0`` to indicate that the ``EXT-X-PROGRAM-DATE-TIME`` tags are not included in the manifest.
            :param url: The URL that's used to request this manifest from this endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsmanifest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                hls_manifest_property = mediapackage.CfnOriginEndpoint.HlsManifestProperty(
                    id="id",
                
                    # the properties below are optional
                    ad_markers="adMarkers",
                    ads_on_delivery_restrictions="adsOnDeliveryRestrictions",
                    ad_triggers=["adTriggers"],
                    include_iframe_only_stream=False,
                    manifest_name="manifestName",
                    playlist_type="playlistType",
                    playlist_window_seconds=123,
                    program_date_time_interval_seconds=123,
                    url="url"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "id": id,
            }
            if ad_markers is not None:
                self._values["ad_markers"] = ad_markers
            if ads_on_delivery_restrictions is not None:
                self._values["ads_on_delivery_restrictions"] = ads_on_delivery_restrictions
            if ad_triggers is not None:
                self._values["ad_triggers"] = ad_triggers
            if include_iframe_only_stream is not None:
                self._values["include_iframe_only_stream"] = include_iframe_only_stream
            if manifest_name is not None:
                self._values["manifest_name"] = manifest_name
            if playlist_type is not None:
                self._values["playlist_type"] = playlist_type
            if playlist_window_seconds is not None:
                self._values["playlist_window_seconds"] = playlist_window_seconds
            if program_date_time_interval_seconds is not None:
                self._values["program_date_time_interval_seconds"] = program_date_time_interval_seconds
            if url is not None:
                self._values["url"] = url

        @builtins.property
        def id(self) -> builtins.str:
            '''The manifest ID is required and must be unique within the OriginEndpoint.

            The ID can't be changed after the endpoint is created.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsmanifest.html#cfn-mediapackage-originendpoint-hlsmanifest-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def ad_markers(self) -> typing.Optional[builtins.str]:
            '''Controls how ad markers are included in the packaged endpoint.

            Valid values are ``none`` , ``passthrough`` , or ``scte35_enhanced`` .

            - ``NONE`` - omits all SCTE-35 ad markers from the output.
            - ``PASSTHROUGH`` - creates a copy in the output of the SCTE-35 ad markers (comments) taken directly from the input manifest.
            - ``SCTE35_ENHANCED`` - generates ad markers and blackout tags in the output based on the SCTE-35 messages from the input manifest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsmanifest.html#cfn-mediapackage-originendpoint-hlsmanifest-admarkers
            '''
            result = self._values.get("ad_markers")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ads_on_delivery_restrictions(self) -> typing.Optional[builtins.str]:
            '''The flags on SCTE-35 segmentation descriptors that have to be present for MediaPackage to insert ad markers in the output manifest.

            For information about SCTE-35 in MediaPackage, see `SCTE-35 Message Options in AWS Elemental MediaPackage <https://docs.aws.amazon.com/mediapackage/latest/ug/scte.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsmanifest.html#cfn-mediapackage-originendpoint-hlsmanifest-adsondeliveryrestrictions
            '''
            result = self._values.get("ads_on_delivery_restrictions")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ad_triggers(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Specifies the SCTE-35 message types that MediaPackage treats as ad markers in the output manifest.

            Valid values:

            - ``BREAK``
            - ``DISTRIBUTOR_ADVERTISEMENT``
            - ``DISTRIBUTOR_OVERLAY_PLACEMENT_OPPORTUNITY``
            - ``DISTRIBUTOR_PLACEMENT_OPPORTUNITY``
            - ``PROVIDER_ADVERTISEMENT``
            - ``PROVIDER_OVERLAY_PLACEMENT_OPPORTUNITY``
            - ``PROVIDER_PLACEMENT_OPPORTUNITY``
            - ``SPLICE_INSERT``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsmanifest.html#cfn-mediapackage-originendpoint-hlsmanifest-adtriggers
            '''
            result = self._values.get("ad_triggers")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def include_iframe_only_stream(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Applies to stream sets with a single video track only.

            When true, the stream set includes an additional I-frame only stream, along with the other tracks. If false, this extra stream is not included.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsmanifest.html#cfn-mediapackage-originendpoint-hlsmanifest-includeiframeonlystream
            '''
            result = self._values.get("include_iframe_only_stream")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def manifest_name(self) -> typing.Optional[builtins.str]:
            '''A short string that's appended to the end of the endpoint URL to create a unique path to this endpoint.

            The manifestName on the HLSManifest object overrides the manifestName that you provided on the originEndpoint object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsmanifest.html#cfn-mediapackage-originendpoint-hlsmanifest-manifestname
            '''
            result = self._values.get("manifest_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def playlist_type(self) -> typing.Optional[builtins.str]:
            '''When specified as either ``event`` or ``vod`` , a corresponding ``EXT-X-PLAYLIST-TYPE`` entry is included in the media playlist.

            Indicates if the playlist is live-to-VOD content.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsmanifest.html#cfn-mediapackage-originendpoint-hlsmanifest-playlisttype
            '''
            result = self._values.get("playlist_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def playlist_window_seconds(self) -> typing.Optional[jsii.Number]:
            '''Time window (in seconds) contained in each parent manifest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsmanifest.html#cfn-mediapackage-originendpoint-hlsmanifest-playlistwindowseconds
            '''
            result = self._values.get("playlist_window_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def program_date_time_interval_seconds(self) -> typing.Optional[jsii.Number]:
            '''Inserts ``EXT-X-PROGRAM-DATE-TIME`` tags in the output manifest at the interval that you specify.

            Additionally, ID3Timed metadata messages are generated every 5 seconds starting when the content was ingested.

            Irrespective of this parameter, if any ID3Timed metadata is in the HLS input, it is passed through to the HLS output.

            Omit this attribute or enter ``0`` to indicate that the ``EXT-X-PROGRAM-DATE-TIME`` tags are not included in the manifest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsmanifest.html#cfn-mediapackage-originendpoint-hlsmanifest-programdatetimeintervalseconds
            '''
            result = self._values.get("program_date_time_interval_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def url(self) -> typing.Optional[builtins.str]:
            '''The URL that's used to request this manifest from this endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlsmanifest.html#cfn-mediapackage-originendpoint-hlsmanifest-url
            '''
            result = self._values.get("url")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HlsManifestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnOriginEndpoint.HlsPackageProperty",
        jsii_struct_bases=[],
        name_mapping={
            "ad_markers": "adMarkers",
            "ads_on_delivery_restrictions": "adsOnDeliveryRestrictions",
            "ad_triggers": "adTriggers",
            "encryption": "encryption",
            "include_iframe_only_stream": "includeIframeOnlyStream",
            "playlist_type": "playlistType",
            "playlist_window_seconds": "playlistWindowSeconds",
            "program_date_time_interval_seconds": "programDateTimeIntervalSeconds",
            "segment_duration_seconds": "segmentDurationSeconds",
            "stream_selection": "streamSelection",
            "use_audio_rendition_group": "useAudioRenditionGroup",
        },
    )
    class HlsPackageProperty:
        def __init__(
            self,
            *,
            ad_markers: typing.Optional[builtins.str] = None,
            ads_on_delivery_restrictions: typing.Optional[builtins.str] = None,
            ad_triggers: typing.Optional[typing.Sequence[builtins.str]] = None,
            encryption: typing.Optional[typing.Union["CfnOriginEndpoint.HlsEncryptionProperty", _IResolvable_da3f097b]] = None,
            include_iframe_only_stream: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            playlist_type: typing.Optional[builtins.str] = None,
            playlist_window_seconds: typing.Optional[jsii.Number] = None,
            program_date_time_interval_seconds: typing.Optional[jsii.Number] = None,
            segment_duration_seconds: typing.Optional[jsii.Number] = None,
            stream_selection: typing.Optional[typing.Union["CfnOriginEndpoint.StreamSelectionProperty", _IResolvable_da3f097b]] = None,
            use_audio_rendition_group: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Parameters for Apple HLS packaging.

            :param ad_markers: Controls how ad markers are included in the packaged endpoint. Valid values are ``none`` , ``passthrough`` , or ``scte35_enhanced`` . - ``NONE`` - omits all SCTE-35 ad markers from the output. - ``PASSTHROUGH`` - creates a copy in the output of the SCTE-35 ad markers (comments) taken directly from the input manifest. - ``SCTE35_ENHANCED`` - generates ad markers and blackout tags in the output based on the SCTE-35 messages from the input manifest.
            :param ads_on_delivery_restrictions: The flags on SCTE-35 segmentation descriptors that have to be present for MediaPackage to insert ad markers in the output manifest. For information about SCTE-35 in MediaPackage, see `SCTE-35 Message Options in AWS Elemental MediaPackage <https://docs.aws.amazon.com/mediapackage/latest/ug/scte.html>`_ .
            :param ad_triggers: Specifies the SCTE-35 message types that MediaPackage treats as ad markers in the output manifest. Valid values: - ``BREAK`` - ``DISTRIBUTOR_ADVERTISEMENT`` - ``DISTRIBUTOR_OVERLAY_PLACEMENT_OPPORTUNITY`` - ``DISTRIBUTOR_PLACEMENT_OPPORTUNITY`` - ``PROVIDER_ADVERTISEMENT`` - ``PROVIDER_OVERLAY_PLACEMENT_OPPORTUNITY`` - ``PROVIDER_PLACEMENT_OPPORTUNITY`` - ``SPLICE_INSERT``
            :param encryption: Parameters for encrypting content.
            :param include_iframe_only_stream: Only applies to stream sets with a single video track. When true, the stream set includes an additional I-frame only stream, along with the other tracks. If false, this extra stream is not included.
            :param playlist_type: When specified as either ``event`` or ``vod`` , a corresponding ``EXT-X-PLAYLIST-TYPE`` entry is included in the media playlist. Indicates if the playlist is live-to-VOD content.
            :param playlist_window_seconds: Time window (in seconds) contained in each parent manifest.
            :param program_date_time_interval_seconds: Inserts ``EXT-X-PROGRAM-DATE-TIME`` tags in the output manifest at the interval that you specify. Additionally, ID3Timed metadata messages are generated every 5 seconds starting when the content was ingested. Irrespective of this parameter, if any ID3Timed metadata is in the HLS input, it is passed through to the HLS output. Omit this attribute or enter ``0`` to indicate that the ``EXT-X-PROGRAM-DATE-TIME`` tags are not included in the manifest.
            :param segment_duration_seconds: Duration (in seconds) of each fragment. Actual fragments are rounded to the nearest multiple of the source fragment duration.
            :param stream_selection: Limitations for outputs from the endpoint, based on the video bitrate.
            :param use_audio_rendition_group: When true, AWS Elemental MediaPackage bundles all audio tracks in a rendition group. All other tracks in the stream can be used with any audio rendition from the group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlspackage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                hls_package_property = mediapackage.CfnOriginEndpoint.HlsPackageProperty(
                    ad_markers="adMarkers",
                    ads_on_delivery_restrictions="adsOnDeliveryRestrictions",
                    ad_triggers=["adTriggers"],
                    encryption=mediapackage.CfnOriginEndpoint.HlsEncryptionProperty(
                        speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                            resource_id="resourceId",
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url",
                
                            # the properties below are optional
                            certificate_arn="certificateArn"
                        ),
                
                        # the properties below are optional
                        constant_initialization_vector="constantInitializationVector",
                        encryption_method="encryptionMethod",
                        key_rotation_interval_seconds=123,
                        repeat_ext_xKey=False
                    ),
                    include_iframe_only_stream=False,
                    playlist_type="playlistType",
                    playlist_window_seconds=123,
                    program_date_time_interval_seconds=123,
                    segment_duration_seconds=123,
                    stream_selection=mediapackage.CfnOriginEndpoint.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    ),
                    use_audio_rendition_group=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if ad_markers is not None:
                self._values["ad_markers"] = ad_markers
            if ads_on_delivery_restrictions is not None:
                self._values["ads_on_delivery_restrictions"] = ads_on_delivery_restrictions
            if ad_triggers is not None:
                self._values["ad_triggers"] = ad_triggers
            if encryption is not None:
                self._values["encryption"] = encryption
            if include_iframe_only_stream is not None:
                self._values["include_iframe_only_stream"] = include_iframe_only_stream
            if playlist_type is not None:
                self._values["playlist_type"] = playlist_type
            if playlist_window_seconds is not None:
                self._values["playlist_window_seconds"] = playlist_window_seconds
            if program_date_time_interval_seconds is not None:
                self._values["program_date_time_interval_seconds"] = program_date_time_interval_seconds
            if segment_duration_seconds is not None:
                self._values["segment_duration_seconds"] = segment_duration_seconds
            if stream_selection is not None:
                self._values["stream_selection"] = stream_selection
            if use_audio_rendition_group is not None:
                self._values["use_audio_rendition_group"] = use_audio_rendition_group

        @builtins.property
        def ad_markers(self) -> typing.Optional[builtins.str]:
            '''Controls how ad markers are included in the packaged endpoint.

            Valid values are ``none`` , ``passthrough`` , or ``scte35_enhanced`` .

            - ``NONE`` - omits all SCTE-35 ad markers from the output.
            - ``PASSTHROUGH`` - creates a copy in the output of the SCTE-35 ad markers (comments) taken directly from the input manifest.
            - ``SCTE35_ENHANCED`` - generates ad markers and blackout tags in the output based on the SCTE-35 messages from the input manifest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlspackage.html#cfn-mediapackage-originendpoint-hlspackage-admarkers
            '''
            result = self._values.get("ad_markers")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ads_on_delivery_restrictions(self) -> typing.Optional[builtins.str]:
            '''The flags on SCTE-35 segmentation descriptors that have to be present for MediaPackage to insert ad markers in the output manifest.

            For information about SCTE-35 in MediaPackage, see `SCTE-35 Message Options in AWS Elemental MediaPackage <https://docs.aws.amazon.com/mediapackage/latest/ug/scte.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlspackage.html#cfn-mediapackage-originendpoint-hlspackage-adsondeliveryrestrictions
            '''
            result = self._values.get("ads_on_delivery_restrictions")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ad_triggers(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Specifies the SCTE-35 message types that MediaPackage treats as ad markers in the output manifest.

            Valid values:

            - ``BREAK``
            - ``DISTRIBUTOR_ADVERTISEMENT``
            - ``DISTRIBUTOR_OVERLAY_PLACEMENT_OPPORTUNITY``
            - ``DISTRIBUTOR_PLACEMENT_OPPORTUNITY``
            - ``PROVIDER_ADVERTISEMENT``
            - ``PROVIDER_OVERLAY_PLACEMENT_OPPORTUNITY``
            - ``PROVIDER_PLACEMENT_OPPORTUNITY``
            - ``SPLICE_INSERT``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlspackage.html#cfn-mediapackage-originendpoint-hlspackage-adtriggers
            '''
            result = self._values.get("ad_triggers")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def encryption(
            self,
        ) -> typing.Optional[typing.Union["CfnOriginEndpoint.HlsEncryptionProperty", _IResolvable_da3f097b]]:
            '''Parameters for encrypting content.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlspackage.html#cfn-mediapackage-originendpoint-hlspackage-encryption
            '''
            result = self._values.get("encryption")
            return typing.cast(typing.Optional[typing.Union["CfnOriginEndpoint.HlsEncryptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def include_iframe_only_stream(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Only applies to stream sets with a single video track.

            When true, the stream set includes an additional I-frame only stream, along with the other tracks. If false, this extra stream is not included.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlspackage.html#cfn-mediapackage-originendpoint-hlspackage-includeiframeonlystream
            '''
            result = self._values.get("include_iframe_only_stream")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def playlist_type(self) -> typing.Optional[builtins.str]:
            '''When specified as either ``event`` or ``vod`` , a corresponding ``EXT-X-PLAYLIST-TYPE`` entry is included in the media playlist.

            Indicates if the playlist is live-to-VOD content.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlspackage.html#cfn-mediapackage-originendpoint-hlspackage-playlisttype
            '''
            result = self._values.get("playlist_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def playlist_window_seconds(self) -> typing.Optional[jsii.Number]:
            '''Time window (in seconds) contained in each parent manifest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlspackage.html#cfn-mediapackage-originendpoint-hlspackage-playlistwindowseconds
            '''
            result = self._values.get("playlist_window_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def program_date_time_interval_seconds(self) -> typing.Optional[jsii.Number]:
            '''Inserts ``EXT-X-PROGRAM-DATE-TIME`` tags in the output manifest at the interval that you specify.

            Additionally, ID3Timed metadata messages are generated every 5 seconds starting when the content was ingested.

            Irrespective of this parameter, if any ID3Timed metadata is in the HLS input, it is passed through to the HLS output.

            Omit this attribute or enter ``0`` to indicate that the ``EXT-X-PROGRAM-DATE-TIME`` tags are not included in the manifest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlspackage.html#cfn-mediapackage-originendpoint-hlspackage-programdatetimeintervalseconds
            '''
            result = self._values.get("program_date_time_interval_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def segment_duration_seconds(self) -> typing.Optional[jsii.Number]:
            '''Duration (in seconds) of each fragment.

            Actual fragments are rounded to the nearest multiple of the source fragment duration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlspackage.html#cfn-mediapackage-originendpoint-hlspackage-segmentdurationseconds
            '''
            result = self._values.get("segment_duration_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def stream_selection(
            self,
        ) -> typing.Optional[typing.Union["CfnOriginEndpoint.StreamSelectionProperty", _IResolvable_da3f097b]]:
            '''Limitations for outputs from the endpoint, based on the video bitrate.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlspackage.html#cfn-mediapackage-originendpoint-hlspackage-streamselection
            '''
            result = self._values.get("stream_selection")
            return typing.cast(typing.Optional[typing.Union["CfnOriginEndpoint.StreamSelectionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def use_audio_rendition_group(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''When true, AWS Elemental MediaPackage bundles all audio tracks in a rendition group.

            All other tracks in the stream can be used with any audio rendition from the group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-hlspackage.html#cfn-mediapackage-originendpoint-hlspackage-useaudiorenditiongroup
            '''
            result = self._values.get("use_audio_rendition_group")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HlsPackageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnOriginEndpoint.MssEncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={"speke_key_provider": "spekeKeyProvider"},
    )
    class MssEncryptionProperty:
        def __init__(
            self,
            *,
            speke_key_provider: typing.Union["CfnOriginEndpoint.SpekeKeyProviderProperty", _IResolvable_da3f097b],
        ) -> None:
            '''Holds encryption information so that access to the content can be controlled by a DRM solution.

            :param speke_key_provider: Parameters for the SPEKE key provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-mssencryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                mss_encryption_property = mediapackage.CfnOriginEndpoint.MssEncryptionProperty(
                    speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                        resource_id="resourceId",
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url",
                
                        # the properties below are optional
                        certificate_arn="certificateArn"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "speke_key_provider": speke_key_provider,
            }

        @builtins.property
        def speke_key_provider(
            self,
        ) -> typing.Union["CfnOriginEndpoint.SpekeKeyProviderProperty", _IResolvable_da3f097b]:
            '''Parameters for the SPEKE key provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-mssencryption.html#cfn-mediapackage-originendpoint-mssencryption-spekekeyprovider
            '''
            result = self._values.get("speke_key_provider")
            assert result is not None, "Required property 'speke_key_provider' is missing"
            return typing.cast(typing.Union["CfnOriginEndpoint.SpekeKeyProviderProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MssEncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnOriginEndpoint.MssPackageProperty",
        jsii_struct_bases=[],
        name_mapping={
            "encryption": "encryption",
            "manifest_window_seconds": "manifestWindowSeconds",
            "segment_duration_seconds": "segmentDurationSeconds",
            "stream_selection": "streamSelection",
        },
    )
    class MssPackageProperty:
        def __init__(
            self,
            *,
            encryption: typing.Optional[typing.Union["CfnOriginEndpoint.MssEncryptionProperty", _IResolvable_da3f097b]] = None,
            manifest_window_seconds: typing.Optional[jsii.Number] = None,
            segment_duration_seconds: typing.Optional[jsii.Number] = None,
            stream_selection: typing.Optional[typing.Union["CfnOriginEndpoint.StreamSelectionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Parameters for Microsoft Smooth Streaming packaging.

            :param encryption: Parameters for encrypting content.
            :param manifest_window_seconds: Time window (in seconds) contained in each manifest.
            :param segment_duration_seconds: Duration (in seconds) of each fragment. Actual fragments are rounded to the nearest multiple of the source fragment duration.
            :param stream_selection: Limitations for outputs from the endpoint, based on the video bitrate.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-msspackage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                mss_package_property = mediapackage.CfnOriginEndpoint.MssPackageProperty(
                    encryption=mediapackage.CfnOriginEndpoint.MssEncryptionProperty(
                        speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                            resource_id="resourceId",
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url",
                
                            # the properties below are optional
                            certificate_arn="certificateArn"
                        )
                    ),
                    manifest_window_seconds=123,
                    segment_duration_seconds=123,
                    stream_selection=mediapackage.CfnOriginEndpoint.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if encryption is not None:
                self._values["encryption"] = encryption
            if manifest_window_seconds is not None:
                self._values["manifest_window_seconds"] = manifest_window_seconds
            if segment_duration_seconds is not None:
                self._values["segment_duration_seconds"] = segment_duration_seconds
            if stream_selection is not None:
                self._values["stream_selection"] = stream_selection

        @builtins.property
        def encryption(
            self,
        ) -> typing.Optional[typing.Union["CfnOriginEndpoint.MssEncryptionProperty", _IResolvable_da3f097b]]:
            '''Parameters for encrypting content.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-msspackage.html#cfn-mediapackage-originendpoint-msspackage-encryption
            '''
            result = self._values.get("encryption")
            return typing.cast(typing.Optional[typing.Union["CfnOriginEndpoint.MssEncryptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def manifest_window_seconds(self) -> typing.Optional[jsii.Number]:
            '''Time window (in seconds) contained in each manifest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-msspackage.html#cfn-mediapackage-originendpoint-msspackage-manifestwindowseconds
            '''
            result = self._values.get("manifest_window_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def segment_duration_seconds(self) -> typing.Optional[jsii.Number]:
            '''Duration (in seconds) of each fragment.

            Actual fragments are rounded to the nearest multiple of the source fragment duration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-msspackage.html#cfn-mediapackage-originendpoint-msspackage-segmentdurationseconds
            '''
            result = self._values.get("segment_duration_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def stream_selection(
            self,
        ) -> typing.Optional[typing.Union["CfnOriginEndpoint.StreamSelectionProperty", _IResolvable_da3f097b]]:
            '''Limitations for outputs from the endpoint, based on the video bitrate.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-msspackage.html#cfn-mediapackage-originendpoint-msspackage-streamselection
            '''
            result = self._values.get("stream_selection")
            return typing.cast(typing.Optional[typing.Union["CfnOriginEndpoint.StreamSelectionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MssPackageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty",
        jsii_struct_bases=[],
        name_mapping={
            "resource_id": "resourceId",
            "role_arn": "roleArn",
            "system_ids": "systemIds",
            "url": "url",
            "certificate_arn": "certificateArn",
        },
    )
    class SpekeKeyProviderProperty:
        def __init__(
            self,
            *,
            resource_id: builtins.str,
            role_arn: builtins.str,
            system_ids: typing.Sequence[builtins.str],
            url: builtins.str,
            certificate_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Keyprovider settings for DRM.

            :param resource_id: Unique identifier for this endpoint, as it is configured in the key provider service.
            :param role_arn: The ARN for the IAM role that's granted by the key provider to provide access to the key provider API. This role must have a trust policy that allows AWS Elemental MediaPackage to assume the role, and it must have a sufficient permissions policy to allow access to the specific key retrieval URL. Valid format: arn:aws:iam::{accountID}:role/{name}
            :param system_ids: List of unique identifiers for the DRM systems to use, as defined in the CPIX specification.
            :param url: URL for the key provider’s key retrieval API endpoint. Must start with https://.
            :param certificate_arn: The Amazon Resource Name (ARN) for the certificate that you imported to AWS Certificate Manager to add content key encryption to this endpoint. For this feature to work, your DRM key provider must support content key encryption.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-spekekeyprovider.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                speke_key_provider_property = mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                    resource_id="resourceId",
                    role_arn="roleArn",
                    system_ids=["systemIds"],
                    url="url",
                
                    # the properties below are optional
                    certificate_arn="certificateArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "resource_id": resource_id,
                "role_arn": role_arn,
                "system_ids": system_ids,
                "url": url,
            }
            if certificate_arn is not None:
                self._values["certificate_arn"] = certificate_arn

        @builtins.property
        def resource_id(self) -> builtins.str:
            '''Unique identifier for this endpoint, as it is configured in the key provider service.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-spekekeyprovider.html#cfn-mediapackage-originendpoint-spekekeyprovider-resourceid
            '''
            result = self._values.get("resource_id")
            assert result is not None, "Required property 'resource_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def role_arn(self) -> builtins.str:
            '''The ARN for the IAM role that's granted by the key provider to provide access to the key provider API.

            This role must have a trust policy that allows AWS Elemental MediaPackage to assume the role, and it must have a sufficient permissions policy to allow access to the specific key retrieval URL. Valid format: arn:aws:iam::{accountID}:role/{name}

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-spekekeyprovider.html#cfn-mediapackage-originendpoint-spekekeyprovider-rolearn
            '''
            result = self._values.get("role_arn")
            assert result is not None, "Required property 'role_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def system_ids(self) -> typing.List[builtins.str]:
            '''List of unique identifiers for the DRM systems to use, as defined in the CPIX specification.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-spekekeyprovider.html#cfn-mediapackage-originendpoint-spekekeyprovider-systemids
            '''
            result = self._values.get("system_ids")
            assert result is not None, "Required property 'system_ids' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def url(self) -> builtins.str:
            '''URL for the key provider’s key retrieval API endpoint.

            Must start with https://.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-spekekeyprovider.html#cfn-mediapackage-originendpoint-spekekeyprovider-url
            '''
            result = self._values.get("url")
            assert result is not None, "Required property 'url' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def certificate_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) for the certificate that you imported to AWS Certificate Manager to add content key encryption to this endpoint.

            For this feature to work, your DRM key provider must support content key encryption.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-spekekeyprovider.html#cfn-mediapackage-originendpoint-spekekeyprovider-certificatearn
            '''
            result = self._values.get("certificate_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SpekeKeyProviderProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnOriginEndpoint.StreamSelectionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "max_video_bits_per_second": "maxVideoBitsPerSecond",
            "min_video_bits_per_second": "minVideoBitsPerSecond",
            "stream_order": "streamOrder",
        },
    )
    class StreamSelectionProperty:
        def __init__(
            self,
            *,
            max_video_bits_per_second: typing.Optional[jsii.Number] = None,
            min_video_bits_per_second: typing.Optional[jsii.Number] = None,
            stream_order: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Limitations for outputs from the endpoint, based on the video bitrate.

            :param max_video_bits_per_second: The upper limit of the bitrates that this endpoint serves. If the video track exceeds this threshold, then AWS Elemental MediaPackage excludes it from output. If you don't specify a value, it defaults to 2147483647 bits per second.
            :param min_video_bits_per_second: The lower limit of the bitrates that this endpoint serves. If the video track is below this threshold, then AWS Elemental MediaPackage excludes it from output. If you don't specify a value, it defaults to 0 bits per second.
            :param stream_order: Order in which the different video bitrates are presented to the player. Valid values: ``ORIGINAL`` , ``VIDEO_BITRATE_ASCENDING`` , ``VIDEO_BITRATE_DESCENDING`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-streamselection.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                stream_selection_property = mediapackage.CfnOriginEndpoint.StreamSelectionProperty(
                    max_video_bits_per_second=123,
                    min_video_bits_per_second=123,
                    stream_order="streamOrder"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max_video_bits_per_second is not None:
                self._values["max_video_bits_per_second"] = max_video_bits_per_second
            if min_video_bits_per_second is not None:
                self._values["min_video_bits_per_second"] = min_video_bits_per_second
            if stream_order is not None:
                self._values["stream_order"] = stream_order

        @builtins.property
        def max_video_bits_per_second(self) -> typing.Optional[jsii.Number]:
            '''The upper limit of the bitrates that this endpoint serves.

            If the video track exceeds this threshold, then AWS Elemental MediaPackage excludes it from output. If you don't specify a value, it defaults to 2147483647 bits per second.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-streamselection.html#cfn-mediapackage-originendpoint-streamselection-maxvideobitspersecond
            '''
            result = self._values.get("max_video_bits_per_second")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def min_video_bits_per_second(self) -> typing.Optional[jsii.Number]:
            '''The lower limit of the bitrates that this endpoint serves.

            If the video track is below this threshold, then AWS Elemental MediaPackage excludes it from output. If you don't specify a value, it defaults to 0 bits per second.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-streamselection.html#cfn-mediapackage-originendpoint-streamselection-minvideobitspersecond
            '''
            result = self._values.get("min_video_bits_per_second")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def stream_order(self) -> typing.Optional[builtins.str]:
            '''Order in which the different video bitrates are presented to the player.

            Valid values: ``ORIGINAL`` , ``VIDEO_BITRATE_ASCENDING`` , ``VIDEO_BITRATE_DESCENDING`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-originendpoint-streamselection.html#cfn-mediapackage-originendpoint-streamselection-streamorder
            '''
            result = self._values.get("stream_order")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StreamSelectionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_mediapackage.CfnOriginEndpointProps",
    jsii_struct_bases=[],
    name_mapping={
        "channel_id": "channelId",
        "id": "id",
        "authorization": "authorization",
        "cmaf_package": "cmafPackage",
        "dash_package": "dashPackage",
        "description": "description",
        "hls_package": "hlsPackage",
        "manifest_name": "manifestName",
        "mss_package": "mssPackage",
        "origination": "origination",
        "startover_window_seconds": "startoverWindowSeconds",
        "tags": "tags",
        "time_delay_seconds": "timeDelaySeconds",
        "whitelist": "whitelist",
    },
)
class CfnOriginEndpointProps:
    def __init__(
        self,
        *,
        channel_id: builtins.str,
        id: builtins.str,
        authorization: typing.Optional[typing.Union[CfnOriginEndpoint.AuthorizationProperty, _IResolvable_da3f097b]] = None,
        cmaf_package: typing.Optional[typing.Union[CfnOriginEndpoint.CmafPackageProperty, _IResolvable_da3f097b]] = None,
        dash_package: typing.Optional[typing.Union[CfnOriginEndpoint.DashPackageProperty, _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        hls_package: typing.Optional[typing.Union[CfnOriginEndpoint.HlsPackageProperty, _IResolvable_da3f097b]] = None,
        manifest_name: typing.Optional[builtins.str] = None,
        mss_package: typing.Optional[typing.Union[CfnOriginEndpoint.MssPackageProperty, _IResolvable_da3f097b]] = None,
        origination: typing.Optional[builtins.str] = None,
        startover_window_seconds: typing.Optional[jsii.Number] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        time_delay_seconds: typing.Optional[jsii.Number] = None,
        whitelist: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnOriginEndpoint``.

        :param channel_id: The ID of the channel associated with this endpoint.
        :param id: The manifest ID is required and must be unique within the OriginEndpoint. The ID can't be changed after the endpoint is created.
        :param authorization: Parameters for CDN authorization.
        :param cmaf_package: Parameters for Common Media Application Format (CMAF) packaging.
        :param dash_package: Parameters for DASH packaging.
        :param description: Any descriptive information that you want to add to the endpoint for future identification purposes.
        :param hls_package: Parameters for Apple HLS packaging.
        :param manifest_name: A short string that's appended to the end of the endpoint URL to create a unique path to this endpoint.
        :param mss_package: Parameters for Microsoft Smooth Streaming packaging.
        :param origination: Controls video origination from this endpoint. - ``ALLOW`` - enables this endpoint to serve content to requesting devices. - ``DENY`` - prevents this endpoint from serving content. Denying origination is helpful for harvesting live-to-VOD assets. For more information about harvesting and origination, see `Live-to-VOD Requirements <https://docs.aws.amazon.com/mediapackage/latest/ug/ltov-reqmts.html>`_ .
        :param startover_window_seconds: Maximum duration (seconds) of content to retain for startover playback. Omit this attribute or enter ``0`` to indicate that startover playback is disabled for this endpoint.
        :param tags: The tags to assign to the endpoint.
        :param time_delay_seconds: Minimum duration (seconds) of delay to enforce on the playback of live content. Omit this attribute or enter ``0`` to indicate that there is no time delay in effect for this endpoint
        :param whitelist: The IP addresses that can access this endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_mediapackage as mediapackage
            
            cfn_origin_endpoint_props = mediapackage.CfnOriginEndpointProps(
                channel_id="channelId",
                id="id",
            
                # the properties below are optional
                authorization=mediapackage.CfnOriginEndpoint.AuthorizationProperty(
                    cdn_identifier_secret="cdnIdentifierSecret",
                    secrets_role_arn="secretsRoleArn"
                ),
                cmaf_package=mediapackage.CfnOriginEndpoint.CmafPackageProperty(
                    encryption=mediapackage.CfnOriginEndpoint.CmafEncryptionProperty(
                        speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                            resource_id="resourceId",
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url",
            
                            # the properties below are optional
                            certificate_arn="certificateArn"
                        ),
            
                        # the properties below are optional
                        constant_initialization_vector="constantInitializationVector",
                        key_rotation_interval_seconds=123
                    ),
                    hls_manifests=[mediapackage.CfnOriginEndpoint.HlsManifestProperty(
                        id="id",
            
                        # the properties below are optional
                        ad_markers="adMarkers",
                        ads_on_delivery_restrictions="adsOnDeliveryRestrictions",
                        ad_triggers=["adTriggers"],
                        include_iframe_only_stream=False,
                        manifest_name="manifestName",
                        playlist_type="playlistType",
                        playlist_window_seconds=123,
                        program_date_time_interval_seconds=123,
                        url="url"
                    )],
                    segment_duration_seconds=123,
                    segment_prefix="segmentPrefix",
                    stream_selection=mediapackage.CfnOriginEndpoint.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    )
                ),
                dash_package=mediapackage.CfnOriginEndpoint.DashPackageProperty(
                    ads_on_delivery_restrictions="adsOnDeliveryRestrictions",
                    ad_triggers=["adTriggers"],
                    encryption=mediapackage.CfnOriginEndpoint.DashEncryptionProperty(
                        speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                            resource_id="resourceId",
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url",
            
                            # the properties below are optional
                            certificate_arn="certificateArn"
                        ),
            
                        # the properties below are optional
                        key_rotation_interval_seconds=123
                    ),
                    manifest_layout="manifestLayout",
                    manifest_window_seconds=123,
                    min_buffer_time_seconds=123,
                    min_update_period_seconds=123,
                    period_triggers=["periodTriggers"],
                    profile="profile",
                    segment_duration_seconds=123,
                    segment_template_format="segmentTemplateFormat",
                    stream_selection=mediapackage.CfnOriginEndpoint.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    ),
                    suggested_presentation_delay_seconds=123,
                    utc_timing="utcTiming",
                    utc_timing_uri="utcTimingUri"
                ),
                description="description",
                hls_package=mediapackage.CfnOriginEndpoint.HlsPackageProperty(
                    ad_markers="adMarkers",
                    ads_on_delivery_restrictions="adsOnDeliveryRestrictions",
                    ad_triggers=["adTriggers"],
                    encryption=mediapackage.CfnOriginEndpoint.HlsEncryptionProperty(
                        speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                            resource_id="resourceId",
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url",
            
                            # the properties below are optional
                            certificate_arn="certificateArn"
                        ),
            
                        # the properties below are optional
                        constant_initialization_vector="constantInitializationVector",
                        encryption_method="encryptionMethod",
                        key_rotation_interval_seconds=123,
                        repeat_ext_xKey=False
                    ),
                    include_iframe_only_stream=False,
                    playlist_type="playlistType",
                    playlist_window_seconds=123,
                    program_date_time_interval_seconds=123,
                    segment_duration_seconds=123,
                    stream_selection=mediapackage.CfnOriginEndpoint.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    ),
                    use_audio_rendition_group=False
                ),
                manifest_name="manifestName",
                mss_package=mediapackage.CfnOriginEndpoint.MssPackageProperty(
                    encryption=mediapackage.CfnOriginEndpoint.MssEncryptionProperty(
                        speke_key_provider=mediapackage.CfnOriginEndpoint.SpekeKeyProviderProperty(
                            resource_id="resourceId",
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url",
            
                            # the properties below are optional
                            certificate_arn="certificateArn"
                        )
                    ),
                    manifest_window_seconds=123,
                    segment_duration_seconds=123,
                    stream_selection=mediapackage.CfnOriginEndpoint.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    )
                ),
                origination="origination",
                startover_window_seconds=123,
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                time_delay_seconds=123,
                whitelist=["whitelist"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "channel_id": channel_id,
            "id": id,
        }
        if authorization is not None:
            self._values["authorization"] = authorization
        if cmaf_package is not None:
            self._values["cmaf_package"] = cmaf_package
        if dash_package is not None:
            self._values["dash_package"] = dash_package
        if description is not None:
            self._values["description"] = description
        if hls_package is not None:
            self._values["hls_package"] = hls_package
        if manifest_name is not None:
            self._values["manifest_name"] = manifest_name
        if mss_package is not None:
            self._values["mss_package"] = mss_package
        if origination is not None:
            self._values["origination"] = origination
        if startover_window_seconds is not None:
            self._values["startover_window_seconds"] = startover_window_seconds
        if tags is not None:
            self._values["tags"] = tags
        if time_delay_seconds is not None:
            self._values["time_delay_seconds"] = time_delay_seconds
        if whitelist is not None:
            self._values["whitelist"] = whitelist

    @builtins.property
    def channel_id(self) -> builtins.str:
        '''The ID of the channel associated with this endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-channelid
        '''
        result = self._values.get("channel_id")
        assert result is not None, "Required property 'channel_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def id(self) -> builtins.str:
        '''The manifest ID is required and must be unique within the OriginEndpoint.

        The ID can't be changed after the endpoint is created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-id
        '''
        result = self._values.get("id")
        assert result is not None, "Required property 'id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def authorization(
        self,
    ) -> typing.Optional[typing.Union[CfnOriginEndpoint.AuthorizationProperty, _IResolvable_da3f097b]]:
        '''Parameters for CDN authorization.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-authorization
        '''
        result = self._values.get("authorization")
        return typing.cast(typing.Optional[typing.Union[CfnOriginEndpoint.AuthorizationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def cmaf_package(
        self,
    ) -> typing.Optional[typing.Union[CfnOriginEndpoint.CmafPackageProperty, _IResolvable_da3f097b]]:
        '''Parameters for Common Media Application Format (CMAF) packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-cmafpackage
        '''
        result = self._values.get("cmaf_package")
        return typing.cast(typing.Optional[typing.Union[CfnOriginEndpoint.CmafPackageProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def dash_package(
        self,
    ) -> typing.Optional[typing.Union[CfnOriginEndpoint.DashPackageProperty, _IResolvable_da3f097b]]:
        '''Parameters for DASH packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-dashpackage
        '''
        result = self._values.get("dash_package")
        return typing.cast(typing.Optional[typing.Union[CfnOriginEndpoint.DashPackageProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''Any descriptive information that you want to add to the endpoint for future identification purposes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def hls_package(
        self,
    ) -> typing.Optional[typing.Union[CfnOriginEndpoint.HlsPackageProperty, _IResolvable_da3f097b]]:
        '''Parameters for Apple HLS packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-hlspackage
        '''
        result = self._values.get("hls_package")
        return typing.cast(typing.Optional[typing.Union[CfnOriginEndpoint.HlsPackageProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def manifest_name(self) -> typing.Optional[builtins.str]:
        '''A short string that's appended to the end of the endpoint URL to create a unique path to this endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-manifestname
        '''
        result = self._values.get("manifest_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def mss_package(
        self,
    ) -> typing.Optional[typing.Union[CfnOriginEndpoint.MssPackageProperty, _IResolvable_da3f097b]]:
        '''Parameters for Microsoft Smooth Streaming packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-msspackage
        '''
        result = self._values.get("mss_package")
        return typing.cast(typing.Optional[typing.Union[CfnOriginEndpoint.MssPackageProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def origination(self) -> typing.Optional[builtins.str]:
        '''Controls video origination from this endpoint.

        - ``ALLOW`` - enables this endpoint to serve content to requesting devices.
        - ``DENY`` - prevents this endpoint from serving content. Denying origination is helpful for harvesting live-to-VOD assets. For more information about harvesting and origination, see `Live-to-VOD Requirements <https://docs.aws.amazon.com/mediapackage/latest/ug/ltov-reqmts.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-origination
        '''
        result = self._values.get("origination")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def startover_window_seconds(self) -> typing.Optional[jsii.Number]:
        '''Maximum duration (seconds) of content to retain for startover playback.

        Omit this attribute or enter ``0`` to indicate that startover playback is disabled for this endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-startoverwindowseconds
        '''
        result = self._values.get("startover_window_seconds")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags to assign to the endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def time_delay_seconds(self) -> typing.Optional[jsii.Number]:
        '''Minimum duration (seconds) of delay to enforce on the playback of live content.

        Omit this attribute or enter ``0`` to indicate that there is no time delay in effect for this endpoint

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-timedelayseconds
        '''
        result = self._values.get("time_delay_seconds")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def whitelist(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The IP addresses that can access this endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-originendpoint.html#cfn-mediapackage-originendpoint-whitelist
        '''
        result = self._values.get("whitelist")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnOriginEndpointProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnPackagingConfiguration(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfiguration",
):
    '''A CloudFormation ``AWS::MediaPackage::PackagingConfiguration``.

    Creates a packaging configuration in a packaging group.

    The packaging configuration represents a single delivery point for an asset. It determines the format and setting for the egressing content. Specify only one package format per configuration, such as ``HlsPackage`` .

    :cloudformationResource: AWS::MediaPackage::PackagingConfiguration
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_mediapackage as mediapackage
        
        cfn_packaging_configuration = mediapackage.CfnPackagingConfiguration(self, "MyCfnPackagingConfiguration",
            id="id",
            packaging_group_id="packagingGroupId",
        
            # the properties below are optional
            cmaf_package=mediapackage.CfnPackagingConfiguration.CmafPackageProperty(
                hls_manifests=[mediapackage.CfnPackagingConfiguration.HlsManifestProperty(
                    ad_markers="adMarkers",
                    include_iframe_only_stream=False,
                    manifest_name="manifestName",
                    program_date_time_interval_seconds=123,
                    repeat_ext_xKey=False,
                    stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    )
                )],
        
                # the properties below are optional
                encryption=mediapackage.CfnPackagingConfiguration.CmafEncryptionProperty(
                    speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url"
                    )
                ),
                include_encoder_configuration_in_segments=False,
                segment_duration_seconds=123
            ),
            dash_package=mediapackage.CfnPackagingConfiguration.DashPackageProperty(
                dash_manifests=[mediapackage.CfnPackagingConfiguration.DashManifestProperty(
                    manifest_layout="manifestLayout",
                    manifest_name="manifestName",
                    min_buffer_time_seconds=123,
                    profile="profile",
                    stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    )
                )],
        
                # the properties below are optional
                encryption=mediapackage.CfnPackagingConfiguration.DashEncryptionProperty(
                    speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url"
                    )
                ),
                include_encoder_configuration_in_segments=False,
                period_triggers=["periodTriggers"],
                segment_duration_seconds=123,
                segment_template_format="segmentTemplateFormat"
            ),
            hls_package=mediapackage.CfnPackagingConfiguration.HlsPackageProperty(
                hls_manifests=[mediapackage.CfnPackagingConfiguration.HlsManifestProperty(
                    ad_markers="adMarkers",
                    include_iframe_only_stream=False,
                    manifest_name="manifestName",
                    program_date_time_interval_seconds=123,
                    repeat_ext_xKey=False,
                    stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    )
                )],
        
                # the properties below are optional
                encryption=mediapackage.CfnPackagingConfiguration.HlsEncryptionProperty(
                    speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url"
                    ),
        
                    # the properties below are optional
                    constant_initialization_vector="constantInitializationVector",
                    encryption_method="encryptionMethod"
                ),
                segment_duration_seconds=123,
                use_audio_rendition_group=False
            ),
            mss_package=mediapackage.CfnPackagingConfiguration.MssPackageProperty(
                mss_manifests=[mediapackage.CfnPackagingConfiguration.MssManifestProperty(
                    manifest_name="manifestName",
                    stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    )
                )],
        
                # the properties below are optional
                encryption=mediapackage.CfnPackagingConfiguration.MssEncryptionProperty(
                    speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url"
                    )
                ),
                segment_duration_seconds=123
            ),
            tags=[CfnTag(
                key="key",
                value="value"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id_: builtins.str,
        *,
        id: builtins.str,
        packaging_group_id: builtins.str,
        cmaf_package: typing.Optional[typing.Union["CfnPackagingConfiguration.CmafPackageProperty", _IResolvable_da3f097b]] = None,
        dash_package: typing.Optional[typing.Union["CfnPackagingConfiguration.DashPackageProperty", _IResolvable_da3f097b]] = None,
        hls_package: typing.Optional[typing.Union["CfnPackagingConfiguration.HlsPackageProperty", _IResolvable_da3f097b]] = None,
        mss_package: typing.Optional[typing.Union["CfnPackagingConfiguration.MssPackageProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::MediaPackage::PackagingConfiguration``.

        :param scope: - scope in which this resource is defined.
        :param id_: - scoped id of the resource.
        :param id: Unique identifier that you assign to the packaging configuration.
        :param packaging_group_id: The ID of the packaging group associated with this packaging configuration.
        :param cmaf_package: Parameters for CMAF packaging.
        :param dash_package: Parameters for DASH-ISO packaging.
        :param hls_package: Parameters for Apple HLS packaging.
        :param mss_package: Parameters for Microsoft Smooth Streaming packaging.
        :param tags: The tags to assign to the packaging configuration.
        '''
        props = CfnPackagingConfigurationProps(
            id=id,
            packaging_group_id=packaging_group_id,
            cmaf_package=cmaf_package,
            dash_package=dash_package,
            hls_package=hls_package,
            mss_package=mss_package,
            tags=tags,
        )

        jsii.create(self.__class__, self, [scope, id_, props])

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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) for the packaging configuration.

        You can get this from the response to any request to the packaging configuration.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags to assign to the packaging configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html#cfn-mediapackage-packagingconfiguration-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="id")
    def id(self) -> builtins.str:
        '''Unique identifier that you assign to the packaging configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html#cfn-mediapackage-packagingconfiguration-id
        '''
        return typing.cast(builtins.str, jsii.get(self, "id"))

    @id.setter
    def id(self, value: builtins.str) -> None:
        jsii.set(self, "id", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="packagingGroupId")
    def packaging_group_id(self) -> builtins.str:
        '''The ID of the packaging group associated with this packaging configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html#cfn-mediapackage-packagingconfiguration-packaginggroupid
        '''
        return typing.cast(builtins.str, jsii.get(self, "packagingGroupId"))

    @packaging_group_id.setter
    def packaging_group_id(self, value: builtins.str) -> None:
        jsii.set(self, "packagingGroupId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cmafPackage")
    def cmaf_package(
        self,
    ) -> typing.Optional[typing.Union["CfnPackagingConfiguration.CmafPackageProperty", _IResolvable_da3f097b]]:
        '''Parameters for CMAF packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html#cfn-mediapackage-packagingconfiguration-cmafpackage
        '''
        return typing.cast(typing.Optional[typing.Union["CfnPackagingConfiguration.CmafPackageProperty", _IResolvable_da3f097b]], jsii.get(self, "cmafPackage"))

    @cmaf_package.setter
    def cmaf_package(
        self,
        value: typing.Optional[typing.Union["CfnPackagingConfiguration.CmafPackageProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "cmafPackage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dashPackage")
    def dash_package(
        self,
    ) -> typing.Optional[typing.Union["CfnPackagingConfiguration.DashPackageProperty", _IResolvable_da3f097b]]:
        '''Parameters for DASH-ISO packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html#cfn-mediapackage-packagingconfiguration-dashpackage
        '''
        return typing.cast(typing.Optional[typing.Union["CfnPackagingConfiguration.DashPackageProperty", _IResolvable_da3f097b]], jsii.get(self, "dashPackage"))

    @dash_package.setter
    def dash_package(
        self,
        value: typing.Optional[typing.Union["CfnPackagingConfiguration.DashPackageProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "dashPackage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hlsPackage")
    def hls_package(
        self,
    ) -> typing.Optional[typing.Union["CfnPackagingConfiguration.HlsPackageProperty", _IResolvable_da3f097b]]:
        '''Parameters for Apple HLS packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html#cfn-mediapackage-packagingconfiguration-hlspackage
        '''
        return typing.cast(typing.Optional[typing.Union["CfnPackagingConfiguration.HlsPackageProperty", _IResolvable_da3f097b]], jsii.get(self, "hlsPackage"))

    @hls_package.setter
    def hls_package(
        self,
        value: typing.Optional[typing.Union["CfnPackagingConfiguration.HlsPackageProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "hlsPackage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="mssPackage")
    def mss_package(
        self,
    ) -> typing.Optional[typing.Union["CfnPackagingConfiguration.MssPackageProperty", _IResolvable_da3f097b]]:
        '''Parameters for Microsoft Smooth Streaming packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html#cfn-mediapackage-packagingconfiguration-msspackage
        '''
        return typing.cast(typing.Optional[typing.Union["CfnPackagingConfiguration.MssPackageProperty", _IResolvable_da3f097b]], jsii.get(self, "mssPackage"))

    @mss_package.setter
    def mss_package(
        self,
        value: typing.Optional[typing.Union["CfnPackagingConfiguration.MssPackageProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "mssPackage", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfiguration.CmafEncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={"speke_key_provider": "spekeKeyProvider"},
    )
    class CmafEncryptionProperty:
        def __init__(
            self,
            *,
            speke_key_provider: typing.Union["CfnPackagingConfiguration.SpekeKeyProviderProperty", _IResolvable_da3f097b],
        ) -> None:
            '''Holds encryption information so that access to the content can be controlled by a DRM solution.

            :param speke_key_provider: Parameters for the SPEKE key provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-cmafencryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                cmaf_encryption_property = mediapackage.CfnPackagingConfiguration.CmafEncryptionProperty(
                    speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "speke_key_provider": speke_key_provider,
            }

        @builtins.property
        def speke_key_provider(
            self,
        ) -> typing.Union["CfnPackagingConfiguration.SpekeKeyProviderProperty", _IResolvable_da3f097b]:
            '''Parameters for the SPEKE key provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-cmafencryption.html#cfn-mediapackage-packagingconfiguration-cmafencryption-spekekeyprovider
            '''
            result = self._values.get("speke_key_provider")
            assert result is not None, "Required property 'speke_key_provider' is missing"
            return typing.cast(typing.Union["CfnPackagingConfiguration.SpekeKeyProviderProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CmafEncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfiguration.CmafPackageProperty",
        jsii_struct_bases=[],
        name_mapping={
            "hls_manifests": "hlsManifests",
            "encryption": "encryption",
            "include_encoder_configuration_in_segments": "includeEncoderConfigurationInSegments",
            "segment_duration_seconds": "segmentDurationSeconds",
        },
    )
    class CmafPackageProperty:
        def __init__(
            self,
            *,
            hls_manifests: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnPackagingConfiguration.HlsManifestProperty", _IResolvable_da3f097b]]],
            encryption: typing.Optional[typing.Union["CfnPackagingConfiguration.CmafEncryptionProperty", _IResolvable_da3f097b]] = None,
            include_encoder_configuration_in_segments: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            segment_duration_seconds: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Parameters for a packaging configuration that uses Common Media Application Format (CMAF) packaging.

            :param hls_manifests: A list of HLS manifest configurations that are available from this endpoint.
            :param encryption: Parameters for encrypting content.
            :param include_encoder_configuration_in_segments: When includeEncoderConfigurationInSegments is set to true, MediaPackage places your encoder's Sequence Parameter Set (SPS), Picture Parameter Set (PPS), and Video Parameter Set (VPS) metadata in every video segment instead of in the init fragment. This lets you use different SPS/PPS/VPS settings for your assets during content playback.
            :param segment_duration_seconds: Duration (in seconds) of each segment. Actual segments are rounded to the nearest multiple of the source fragment duration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-cmafpackage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                cmaf_package_property = mediapackage.CfnPackagingConfiguration.CmafPackageProperty(
                    hls_manifests=[mediapackage.CfnPackagingConfiguration.HlsManifestProperty(
                        ad_markers="adMarkers",
                        include_iframe_only_stream=False,
                        manifest_name="manifestName",
                        program_date_time_interval_seconds=123,
                        repeat_ext_xKey=False,
                        stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                            max_video_bits_per_second=123,
                            min_video_bits_per_second=123,
                            stream_order="streamOrder"
                        )
                    )],
                
                    # the properties below are optional
                    encryption=mediapackage.CfnPackagingConfiguration.CmafEncryptionProperty(
                        speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url"
                        )
                    ),
                    include_encoder_configuration_in_segments=False,
                    segment_duration_seconds=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "hls_manifests": hls_manifests,
            }
            if encryption is not None:
                self._values["encryption"] = encryption
            if include_encoder_configuration_in_segments is not None:
                self._values["include_encoder_configuration_in_segments"] = include_encoder_configuration_in_segments
            if segment_duration_seconds is not None:
                self._values["segment_duration_seconds"] = segment_duration_seconds

        @builtins.property
        def hls_manifests(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPackagingConfiguration.HlsManifestProperty", _IResolvable_da3f097b]]]:
            '''A list of HLS manifest configurations that are available from this endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-cmafpackage.html#cfn-mediapackage-packagingconfiguration-cmafpackage-hlsmanifests
            '''
            result = self._values.get("hls_manifests")
            assert result is not None, "Required property 'hls_manifests' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPackagingConfiguration.HlsManifestProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def encryption(
            self,
        ) -> typing.Optional[typing.Union["CfnPackagingConfiguration.CmafEncryptionProperty", _IResolvable_da3f097b]]:
            '''Parameters for encrypting content.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-cmafpackage.html#cfn-mediapackage-packagingconfiguration-cmafpackage-encryption
            '''
            result = self._values.get("encryption")
            return typing.cast(typing.Optional[typing.Union["CfnPackagingConfiguration.CmafEncryptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def include_encoder_configuration_in_segments(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''When includeEncoderConfigurationInSegments is set to true, MediaPackage places your encoder's Sequence Parameter Set (SPS), Picture Parameter Set (PPS), and Video Parameter Set (VPS) metadata in every video segment instead of in the init fragment.

            This lets you use different SPS/PPS/VPS settings for your assets during content playback.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-cmafpackage.html#cfn-mediapackage-packagingconfiguration-cmafpackage-includeencoderconfigurationinsegments
            '''
            result = self._values.get("include_encoder_configuration_in_segments")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def segment_duration_seconds(self) -> typing.Optional[jsii.Number]:
            '''Duration (in seconds) of each segment.

            Actual segments are rounded to the nearest multiple of the source fragment duration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-cmafpackage.html#cfn-mediapackage-packagingconfiguration-cmafpackage-segmentdurationseconds
            '''
            result = self._values.get("segment_duration_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CmafPackageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfiguration.DashEncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={"speke_key_provider": "spekeKeyProvider"},
    )
    class DashEncryptionProperty:
        def __init__(
            self,
            *,
            speke_key_provider: typing.Union["CfnPackagingConfiguration.SpekeKeyProviderProperty", _IResolvable_da3f097b],
        ) -> None:
            '''Holds encryption information so that access to the content can be controlled by a DRM solution.

            :param speke_key_provider: Parameters for the SPEKE key provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashencryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                dash_encryption_property = mediapackage.CfnPackagingConfiguration.DashEncryptionProperty(
                    speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "speke_key_provider": speke_key_provider,
            }

        @builtins.property
        def speke_key_provider(
            self,
        ) -> typing.Union["CfnPackagingConfiguration.SpekeKeyProviderProperty", _IResolvable_da3f097b]:
            '''Parameters for the SPEKE key provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashencryption.html#cfn-mediapackage-packagingconfiguration-dashencryption-spekekeyprovider
            '''
            result = self._values.get("speke_key_provider")
            assert result is not None, "Required property 'speke_key_provider' is missing"
            return typing.cast(typing.Union["CfnPackagingConfiguration.SpekeKeyProviderProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DashEncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfiguration.DashManifestProperty",
        jsii_struct_bases=[],
        name_mapping={
            "manifest_layout": "manifestLayout",
            "manifest_name": "manifestName",
            "min_buffer_time_seconds": "minBufferTimeSeconds",
            "profile": "profile",
            "stream_selection": "streamSelection",
        },
    )
    class DashManifestProperty:
        def __init__(
            self,
            *,
            manifest_layout: typing.Optional[builtins.str] = None,
            manifest_name: typing.Optional[builtins.str] = None,
            min_buffer_time_seconds: typing.Optional[jsii.Number] = None,
            profile: typing.Optional[builtins.str] = None,
            stream_selection: typing.Optional[typing.Union["CfnPackagingConfiguration.StreamSelectionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Parameters for a DASH manifest.

            :param manifest_layout: Determines the position of some tags in the Media Presentation Description (MPD). When set to ``FULL`` , elements like ``SegmentTemplate`` and ``ContentProtection`` are included in each ``Representation`` . When set to ``COMPACT`` , duplicate elements are combined and presented at the AdaptationSet level.
            :param manifest_name: A short string that's appended to the end of the endpoint URL to create a unique path to this packaging configuration.
            :param min_buffer_time_seconds: Minimum amount of content (measured in seconds) that a player must keep available in the buffer.
            :param profile: The DASH profile type. When set to ``HBBTV_1_5`` , the content is compliant with HbbTV 1.5.
            :param stream_selection: Limitations for outputs from the endpoint, based on the video bitrate.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashmanifest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                dash_manifest_property = mediapackage.CfnPackagingConfiguration.DashManifestProperty(
                    manifest_layout="manifestLayout",
                    manifest_name="manifestName",
                    min_buffer_time_seconds=123,
                    profile="profile",
                    stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if manifest_layout is not None:
                self._values["manifest_layout"] = manifest_layout
            if manifest_name is not None:
                self._values["manifest_name"] = manifest_name
            if min_buffer_time_seconds is not None:
                self._values["min_buffer_time_seconds"] = min_buffer_time_seconds
            if profile is not None:
                self._values["profile"] = profile
            if stream_selection is not None:
                self._values["stream_selection"] = stream_selection

        @builtins.property
        def manifest_layout(self) -> typing.Optional[builtins.str]:
            '''Determines the position of some tags in the Media Presentation Description (MPD).

            When set to ``FULL`` , elements like ``SegmentTemplate`` and ``ContentProtection`` are included in each ``Representation`` . When set to ``COMPACT`` , duplicate elements are combined and presented at the AdaptationSet level.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashmanifest.html#cfn-mediapackage-packagingconfiguration-dashmanifest-manifestlayout
            '''
            result = self._values.get("manifest_layout")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def manifest_name(self) -> typing.Optional[builtins.str]:
            '''A short string that's appended to the end of the endpoint URL to create a unique path to this packaging configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashmanifest.html#cfn-mediapackage-packagingconfiguration-dashmanifest-manifestname
            '''
            result = self._values.get("manifest_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def min_buffer_time_seconds(self) -> typing.Optional[jsii.Number]:
            '''Minimum amount of content (measured in seconds) that a player must keep available in the buffer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashmanifest.html#cfn-mediapackage-packagingconfiguration-dashmanifest-minbuffertimeseconds
            '''
            result = self._values.get("min_buffer_time_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def profile(self) -> typing.Optional[builtins.str]:
            '''The DASH profile type.

            When set to ``HBBTV_1_5`` , the content is compliant with HbbTV 1.5.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashmanifest.html#cfn-mediapackage-packagingconfiguration-dashmanifest-profile
            '''
            result = self._values.get("profile")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def stream_selection(
            self,
        ) -> typing.Optional[typing.Union["CfnPackagingConfiguration.StreamSelectionProperty", _IResolvable_da3f097b]]:
            '''Limitations for outputs from the endpoint, based on the video bitrate.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashmanifest.html#cfn-mediapackage-packagingconfiguration-dashmanifest-streamselection
            '''
            result = self._values.get("stream_selection")
            return typing.cast(typing.Optional[typing.Union["CfnPackagingConfiguration.StreamSelectionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DashManifestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfiguration.DashPackageProperty",
        jsii_struct_bases=[],
        name_mapping={
            "dash_manifests": "dashManifests",
            "encryption": "encryption",
            "include_encoder_configuration_in_segments": "includeEncoderConfigurationInSegments",
            "period_triggers": "periodTriggers",
            "segment_duration_seconds": "segmentDurationSeconds",
            "segment_template_format": "segmentTemplateFormat",
        },
    )
    class DashPackageProperty:
        def __init__(
            self,
            *,
            dash_manifests: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnPackagingConfiguration.DashManifestProperty", _IResolvable_da3f097b]]],
            encryption: typing.Optional[typing.Union["CfnPackagingConfiguration.DashEncryptionProperty", _IResolvable_da3f097b]] = None,
            include_encoder_configuration_in_segments: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            period_triggers: typing.Optional[typing.Sequence[builtins.str]] = None,
            segment_duration_seconds: typing.Optional[jsii.Number] = None,
            segment_template_format: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Parameters for a packaging configuration that uses Dynamic Adaptive Streaming over HTTP (DASH) packaging.

            :param dash_manifests: A list of DASH manifest configurations that are available from this endpoint.
            :param encryption: Parameters for encrypting content.
            :param include_encoder_configuration_in_segments: When includeEncoderConfigurationInSegments is set to true, MediaPackage places your encoder's Sequence Parameter Set (SPS), Picture Parameter Set (PPS), and Video Parameter Set (VPS) metadata in every video segment instead of in the init fragment. This lets you use different SPS/PPS/VPS settings for your assets during content playback.
            :param period_triggers: Controls whether MediaPackage produces single-period or multi-period DASH manifests. For more information about periods, see `Multi-period DASH in AWS Elemental MediaPackage <https://docs.aws.amazon.com/mediapackage/latest/ug/multi-period.html>`_ . Valid values: - ``ADS`` - MediaPackage will produce multi-period DASH manifests. Periods are created based on the SCTE-35 ad markers present in the input manifest. - *No value* - MediaPackage will produce single-period DASH manifests. This is the default setting.
            :param segment_duration_seconds: Duration (in seconds) of each fragment. Actual fragments are rounded to the nearest multiple of the source segment duration.
            :param segment_template_format: Determines the type of SegmentTemplate included in the Media Presentation Description (MPD). When set to ``NUMBER_WITH_TIMELINE`` , a full timeline is presented in each SegmentTemplate, with $Number$ media URLs. When set to ``TIME_WITH_TIMELINE`` , a full timeline is presented in each SegmentTemplate, with $Time$ media URLs. When set to ``NUMBER_WITH_DURATION`` , only a duration is included in each SegmentTemplate, with $Number$ media URLs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashpackage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                dash_package_property = mediapackage.CfnPackagingConfiguration.DashPackageProperty(
                    dash_manifests=[mediapackage.CfnPackagingConfiguration.DashManifestProperty(
                        manifest_layout="manifestLayout",
                        manifest_name="manifestName",
                        min_buffer_time_seconds=123,
                        profile="profile",
                        stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                            max_video_bits_per_second=123,
                            min_video_bits_per_second=123,
                            stream_order="streamOrder"
                        )
                    )],
                
                    # the properties below are optional
                    encryption=mediapackage.CfnPackagingConfiguration.DashEncryptionProperty(
                        speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url"
                        )
                    ),
                    include_encoder_configuration_in_segments=False,
                    period_triggers=["periodTriggers"],
                    segment_duration_seconds=123,
                    segment_template_format="segmentTemplateFormat"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "dash_manifests": dash_manifests,
            }
            if encryption is not None:
                self._values["encryption"] = encryption
            if include_encoder_configuration_in_segments is not None:
                self._values["include_encoder_configuration_in_segments"] = include_encoder_configuration_in_segments
            if period_triggers is not None:
                self._values["period_triggers"] = period_triggers
            if segment_duration_seconds is not None:
                self._values["segment_duration_seconds"] = segment_duration_seconds
            if segment_template_format is not None:
                self._values["segment_template_format"] = segment_template_format

        @builtins.property
        def dash_manifests(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPackagingConfiguration.DashManifestProperty", _IResolvable_da3f097b]]]:
            '''A list of DASH manifest configurations that are available from this endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashpackage.html#cfn-mediapackage-packagingconfiguration-dashpackage-dashmanifests
            '''
            result = self._values.get("dash_manifests")
            assert result is not None, "Required property 'dash_manifests' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPackagingConfiguration.DashManifestProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def encryption(
            self,
        ) -> typing.Optional[typing.Union["CfnPackagingConfiguration.DashEncryptionProperty", _IResolvable_da3f097b]]:
            '''Parameters for encrypting content.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashpackage.html#cfn-mediapackage-packagingconfiguration-dashpackage-encryption
            '''
            result = self._values.get("encryption")
            return typing.cast(typing.Optional[typing.Union["CfnPackagingConfiguration.DashEncryptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def include_encoder_configuration_in_segments(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''When includeEncoderConfigurationInSegments is set to true, MediaPackage places your encoder's Sequence Parameter Set (SPS), Picture Parameter Set (PPS), and Video Parameter Set (VPS) metadata in every video segment instead of in the init fragment.

            This lets you use different SPS/PPS/VPS settings for your assets during content playback.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashpackage.html#cfn-mediapackage-packagingconfiguration-dashpackage-includeencoderconfigurationinsegments
            '''
            result = self._values.get("include_encoder_configuration_in_segments")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def period_triggers(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Controls whether MediaPackage produces single-period or multi-period DASH manifests.

            For more information about periods, see `Multi-period DASH in AWS Elemental MediaPackage <https://docs.aws.amazon.com/mediapackage/latest/ug/multi-period.html>`_ .

            Valid values:

            - ``ADS`` - MediaPackage will produce multi-period DASH manifests. Periods are created based on the SCTE-35 ad markers present in the input manifest.
            - *No value* - MediaPackage will produce single-period DASH manifests. This is the default setting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashpackage.html#cfn-mediapackage-packagingconfiguration-dashpackage-periodtriggers
            '''
            result = self._values.get("period_triggers")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def segment_duration_seconds(self) -> typing.Optional[jsii.Number]:
            '''Duration (in seconds) of each fragment.

            Actual fragments are rounded to the nearest multiple of the source segment duration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashpackage.html#cfn-mediapackage-packagingconfiguration-dashpackage-segmentdurationseconds
            '''
            result = self._values.get("segment_duration_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def segment_template_format(self) -> typing.Optional[builtins.str]:
            '''Determines the type of SegmentTemplate included in the Media Presentation Description (MPD).

            When set to ``NUMBER_WITH_TIMELINE`` , a full timeline is presented in each SegmentTemplate, with $Number$ media URLs. When set to ``TIME_WITH_TIMELINE`` , a full timeline is presented in each SegmentTemplate, with $Time$ media URLs. When set to ``NUMBER_WITH_DURATION`` , only a duration is included in each SegmentTemplate, with $Number$ media URLs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-dashpackage.html#cfn-mediapackage-packagingconfiguration-dashpackage-segmenttemplateformat
            '''
            result = self._values.get("segment_template_format")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DashPackageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfiguration.HlsEncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "speke_key_provider": "spekeKeyProvider",
            "constant_initialization_vector": "constantInitializationVector",
            "encryption_method": "encryptionMethod",
        },
    )
    class HlsEncryptionProperty:
        def __init__(
            self,
            *,
            speke_key_provider: typing.Union["CfnPackagingConfiguration.SpekeKeyProviderProperty", _IResolvable_da3f097b],
            constant_initialization_vector: typing.Optional[builtins.str] = None,
            encryption_method: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Holds encryption information so that access to the content can be controlled by a DRM solution.

            :param speke_key_provider: Parameters for the SPEKE key provider.
            :param constant_initialization_vector: A 128-bit, 16-byte hex value represented by a 32-character string, used with the key for encrypting blocks. If you don't specify a constant initialization vector (IV), MediaPackage periodically rotates the IV.
            :param encryption_method: HLS encryption type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlsencryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                hls_encryption_property = mediapackage.CfnPackagingConfiguration.HlsEncryptionProperty(
                    speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url"
                    ),
                
                    # the properties below are optional
                    constant_initialization_vector="constantInitializationVector",
                    encryption_method="encryptionMethod"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "speke_key_provider": speke_key_provider,
            }
            if constant_initialization_vector is not None:
                self._values["constant_initialization_vector"] = constant_initialization_vector
            if encryption_method is not None:
                self._values["encryption_method"] = encryption_method

        @builtins.property
        def speke_key_provider(
            self,
        ) -> typing.Union["CfnPackagingConfiguration.SpekeKeyProviderProperty", _IResolvable_da3f097b]:
            '''Parameters for the SPEKE key provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlsencryption.html#cfn-mediapackage-packagingconfiguration-hlsencryption-spekekeyprovider
            '''
            result = self._values.get("speke_key_provider")
            assert result is not None, "Required property 'speke_key_provider' is missing"
            return typing.cast(typing.Union["CfnPackagingConfiguration.SpekeKeyProviderProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def constant_initialization_vector(self) -> typing.Optional[builtins.str]:
            '''A 128-bit, 16-byte hex value represented by a 32-character string, used with the key for encrypting blocks.

            If you don't specify a constant initialization vector (IV), MediaPackage periodically rotates the IV.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlsencryption.html#cfn-mediapackage-packagingconfiguration-hlsencryption-constantinitializationvector
            '''
            result = self._values.get("constant_initialization_vector")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def encryption_method(self) -> typing.Optional[builtins.str]:
            '''HLS encryption type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlsencryption.html#cfn-mediapackage-packagingconfiguration-hlsencryption-encryptionmethod
            '''
            result = self._values.get("encryption_method")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HlsEncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfiguration.HlsManifestProperty",
        jsii_struct_bases=[],
        name_mapping={
            "ad_markers": "adMarkers",
            "include_iframe_only_stream": "includeIframeOnlyStream",
            "manifest_name": "manifestName",
            "program_date_time_interval_seconds": "programDateTimeIntervalSeconds",
            "repeat_ext_x_key": "repeatExtXKey",
            "stream_selection": "streamSelection",
        },
    )
    class HlsManifestProperty:
        def __init__(
            self,
            *,
            ad_markers: typing.Optional[builtins.str] = None,
            include_iframe_only_stream: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            manifest_name: typing.Optional[builtins.str] = None,
            program_date_time_interval_seconds: typing.Optional[jsii.Number] = None,
            repeat_ext_x_key: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            stream_selection: typing.Optional[typing.Union["CfnPackagingConfiguration.StreamSelectionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Parameters for an HLS manifest.

            :param ad_markers: This setting controls ad markers in the packaged content. ``NONE`` omits SCTE-35 ad markers from the output. ``PASSTHROUGH`` copies SCTE-35 ad markers from the source content to the output. ``SCTE35_ENHANCED`` generates ad markers and blackout tags in the output, based on SCTE-35 messages in the source content.
            :param include_iframe_only_stream: Applies to stream sets with a single video track only. When enabled, the output includes an additional I-frame only stream, along with the other tracks.
            :param manifest_name: A short string that's appended to the end of the endpoint URL to create a unique path to this packaging configuration.
            :param program_date_time_interval_seconds: Inserts ``EXT-X-PROGRAM-DATE-TIME`` tags in the output manifest at the interval that you specify. Additionally, ID3Timed metadata messages are generated every 5 seconds starting when the content was ingested. Irrespective of this parameter, if any ID3Timed metadata is in the HLS input, it is passed through to the HLS output. Omit this attribute or enter ``0`` to indicate that the ``EXT-X-PROGRAM-DATE-TIME`` tags are not included in the manifest.
            :param repeat_ext_x_key: Repeat the ``EXT-X-KEY`` directive for every media segment. This might result in an increase in client requests to the DRM server.
            :param stream_selection: Video bitrate limitations for outputs from this packaging configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlsmanifest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                hls_manifest_property = mediapackage.CfnPackagingConfiguration.HlsManifestProperty(
                    ad_markers="adMarkers",
                    include_iframe_only_stream=False,
                    manifest_name="manifestName",
                    program_date_time_interval_seconds=123,
                    repeat_ext_xKey=False,
                    stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if ad_markers is not None:
                self._values["ad_markers"] = ad_markers
            if include_iframe_only_stream is not None:
                self._values["include_iframe_only_stream"] = include_iframe_only_stream
            if manifest_name is not None:
                self._values["manifest_name"] = manifest_name
            if program_date_time_interval_seconds is not None:
                self._values["program_date_time_interval_seconds"] = program_date_time_interval_seconds
            if repeat_ext_x_key is not None:
                self._values["repeat_ext_x_key"] = repeat_ext_x_key
            if stream_selection is not None:
                self._values["stream_selection"] = stream_selection

        @builtins.property
        def ad_markers(self) -> typing.Optional[builtins.str]:
            '''This setting controls ad markers in the packaged content.

            ``NONE`` omits SCTE-35 ad markers from the output. ``PASSTHROUGH`` copies SCTE-35 ad markers from the source content to the output. ``SCTE35_ENHANCED`` generates ad markers and blackout tags in the output, based on SCTE-35 messages in the source content.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlsmanifest.html#cfn-mediapackage-packagingconfiguration-hlsmanifest-admarkers
            '''
            result = self._values.get("ad_markers")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def include_iframe_only_stream(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Applies to stream sets with a single video track only.

            When enabled, the output includes an additional I-frame only stream, along with the other tracks.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlsmanifest.html#cfn-mediapackage-packagingconfiguration-hlsmanifest-includeiframeonlystream
            '''
            result = self._values.get("include_iframe_only_stream")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def manifest_name(self) -> typing.Optional[builtins.str]:
            '''A short string that's appended to the end of the endpoint URL to create a unique path to this packaging configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlsmanifest.html#cfn-mediapackage-packagingconfiguration-hlsmanifest-manifestname
            '''
            result = self._values.get("manifest_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def program_date_time_interval_seconds(self) -> typing.Optional[jsii.Number]:
            '''Inserts ``EXT-X-PROGRAM-DATE-TIME`` tags in the output manifest at the interval that you specify.

            Additionally, ID3Timed metadata messages are generated every 5 seconds starting when the content was ingested.

            Irrespective of this parameter, if any ID3Timed metadata is in the HLS input, it is passed through to the HLS output.

            Omit this attribute or enter ``0`` to indicate that the ``EXT-X-PROGRAM-DATE-TIME`` tags are not included in the manifest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlsmanifest.html#cfn-mediapackage-packagingconfiguration-hlsmanifest-programdatetimeintervalseconds
            '''
            result = self._values.get("program_date_time_interval_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def repeat_ext_x_key(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Repeat the ``EXT-X-KEY`` directive for every media segment.

            This might result in an increase in client requests to the DRM server.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlsmanifest.html#cfn-mediapackage-packagingconfiguration-hlsmanifest-repeatextxkey
            '''
            result = self._values.get("repeat_ext_x_key")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def stream_selection(
            self,
        ) -> typing.Optional[typing.Union["CfnPackagingConfiguration.StreamSelectionProperty", _IResolvable_da3f097b]]:
            '''Video bitrate limitations for outputs from this packaging configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlsmanifest.html#cfn-mediapackage-packagingconfiguration-hlsmanifest-streamselection
            '''
            result = self._values.get("stream_selection")
            return typing.cast(typing.Optional[typing.Union["CfnPackagingConfiguration.StreamSelectionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HlsManifestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfiguration.HlsPackageProperty",
        jsii_struct_bases=[],
        name_mapping={
            "hls_manifests": "hlsManifests",
            "encryption": "encryption",
            "segment_duration_seconds": "segmentDurationSeconds",
            "use_audio_rendition_group": "useAudioRenditionGroup",
        },
    )
    class HlsPackageProperty:
        def __init__(
            self,
            *,
            hls_manifests: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnPackagingConfiguration.HlsManifestProperty", _IResolvable_da3f097b]]],
            encryption: typing.Optional[typing.Union["CfnPackagingConfiguration.HlsEncryptionProperty", _IResolvable_da3f097b]] = None,
            segment_duration_seconds: typing.Optional[jsii.Number] = None,
            use_audio_rendition_group: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Parameters for a packaging configuration that uses HTTP Live Streaming (HLS) packaging.

            :param hls_manifests: A list of HLS manifest configurations that are available from this endpoint.
            :param encryption: Parameters for encrypting content.
            :param segment_duration_seconds: Duration (in seconds) of each fragment. Actual fragments are rounded to the nearest multiple of the source fragment duration.
            :param use_audio_rendition_group: When true, AWS Elemental MediaPackage bundles all audio tracks in a rendition group. All other tracks in the stream can be used with any audio rendition from the group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlspackage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                hls_package_property = mediapackage.CfnPackagingConfiguration.HlsPackageProperty(
                    hls_manifests=[mediapackage.CfnPackagingConfiguration.HlsManifestProperty(
                        ad_markers="adMarkers",
                        include_iframe_only_stream=False,
                        manifest_name="manifestName",
                        program_date_time_interval_seconds=123,
                        repeat_ext_xKey=False,
                        stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                            max_video_bits_per_second=123,
                            min_video_bits_per_second=123,
                            stream_order="streamOrder"
                        )
                    )],
                
                    # the properties below are optional
                    encryption=mediapackage.CfnPackagingConfiguration.HlsEncryptionProperty(
                        speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url"
                        ),
                
                        # the properties below are optional
                        constant_initialization_vector="constantInitializationVector",
                        encryption_method="encryptionMethod"
                    ),
                    segment_duration_seconds=123,
                    use_audio_rendition_group=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "hls_manifests": hls_manifests,
            }
            if encryption is not None:
                self._values["encryption"] = encryption
            if segment_duration_seconds is not None:
                self._values["segment_duration_seconds"] = segment_duration_seconds
            if use_audio_rendition_group is not None:
                self._values["use_audio_rendition_group"] = use_audio_rendition_group

        @builtins.property
        def hls_manifests(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPackagingConfiguration.HlsManifestProperty", _IResolvable_da3f097b]]]:
            '''A list of HLS manifest configurations that are available from this endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlspackage.html#cfn-mediapackage-packagingconfiguration-hlspackage-hlsmanifests
            '''
            result = self._values.get("hls_manifests")
            assert result is not None, "Required property 'hls_manifests' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPackagingConfiguration.HlsManifestProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def encryption(
            self,
        ) -> typing.Optional[typing.Union["CfnPackagingConfiguration.HlsEncryptionProperty", _IResolvable_da3f097b]]:
            '''Parameters for encrypting content.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlspackage.html#cfn-mediapackage-packagingconfiguration-hlspackage-encryption
            '''
            result = self._values.get("encryption")
            return typing.cast(typing.Optional[typing.Union["CfnPackagingConfiguration.HlsEncryptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def segment_duration_seconds(self) -> typing.Optional[jsii.Number]:
            '''Duration (in seconds) of each fragment.

            Actual fragments are rounded to the nearest multiple of the source fragment duration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlspackage.html#cfn-mediapackage-packagingconfiguration-hlspackage-segmentdurationseconds
            '''
            result = self._values.get("segment_duration_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def use_audio_rendition_group(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''When true, AWS Elemental MediaPackage bundles all audio tracks in a rendition group.

            All other tracks in the stream can be used with any audio rendition from the group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-hlspackage.html#cfn-mediapackage-packagingconfiguration-hlspackage-useaudiorenditiongroup
            '''
            result = self._values.get("use_audio_rendition_group")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HlsPackageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfiguration.MssEncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={"speke_key_provider": "spekeKeyProvider"},
    )
    class MssEncryptionProperty:
        def __init__(
            self,
            *,
            speke_key_provider: typing.Union["CfnPackagingConfiguration.SpekeKeyProviderProperty", _IResolvable_da3f097b],
        ) -> None:
            '''Holds encryption information so that access to the content can be controlled by a DRM solution.

            :param speke_key_provider: Parameters for the SPEKE key provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-mssencryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                mss_encryption_property = mediapackage.CfnPackagingConfiguration.MssEncryptionProperty(
                    speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                        role_arn="roleArn",
                        system_ids=["systemIds"],
                        url="url"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "speke_key_provider": speke_key_provider,
            }

        @builtins.property
        def speke_key_provider(
            self,
        ) -> typing.Union["CfnPackagingConfiguration.SpekeKeyProviderProperty", _IResolvable_da3f097b]:
            '''Parameters for the SPEKE key provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-mssencryption.html#cfn-mediapackage-packagingconfiguration-mssencryption-spekekeyprovider
            '''
            result = self._values.get("speke_key_provider")
            assert result is not None, "Required property 'speke_key_provider' is missing"
            return typing.cast(typing.Union["CfnPackagingConfiguration.SpekeKeyProviderProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MssEncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfiguration.MssManifestProperty",
        jsii_struct_bases=[],
        name_mapping={
            "manifest_name": "manifestName",
            "stream_selection": "streamSelection",
        },
    )
    class MssManifestProperty:
        def __init__(
            self,
            *,
            manifest_name: typing.Optional[builtins.str] = None,
            stream_selection: typing.Optional[typing.Union["CfnPackagingConfiguration.StreamSelectionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Parameters for a Microsoft Smooth manifest.

            :param manifest_name: A short string that's appended to the end of the endpoint URL to create a unique path to this packaging configuration.
            :param stream_selection: Video bitrate limitations for outputs from this packaging configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-mssmanifest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                mss_manifest_property = mediapackage.CfnPackagingConfiguration.MssManifestProperty(
                    manifest_name="manifestName",
                    stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                        max_video_bits_per_second=123,
                        min_video_bits_per_second=123,
                        stream_order="streamOrder"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if manifest_name is not None:
                self._values["manifest_name"] = manifest_name
            if stream_selection is not None:
                self._values["stream_selection"] = stream_selection

        @builtins.property
        def manifest_name(self) -> typing.Optional[builtins.str]:
            '''A short string that's appended to the end of the endpoint URL to create a unique path to this packaging configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-mssmanifest.html#cfn-mediapackage-packagingconfiguration-mssmanifest-manifestname
            '''
            result = self._values.get("manifest_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def stream_selection(
            self,
        ) -> typing.Optional[typing.Union["CfnPackagingConfiguration.StreamSelectionProperty", _IResolvable_da3f097b]]:
            '''Video bitrate limitations for outputs from this packaging configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-mssmanifest.html#cfn-mediapackage-packagingconfiguration-mssmanifest-streamselection
            '''
            result = self._values.get("stream_selection")
            return typing.cast(typing.Optional[typing.Union["CfnPackagingConfiguration.StreamSelectionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MssManifestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfiguration.MssPackageProperty",
        jsii_struct_bases=[],
        name_mapping={
            "mss_manifests": "mssManifests",
            "encryption": "encryption",
            "segment_duration_seconds": "segmentDurationSeconds",
        },
    )
    class MssPackageProperty:
        def __init__(
            self,
            *,
            mss_manifests: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnPackagingConfiguration.MssManifestProperty", _IResolvable_da3f097b]]],
            encryption: typing.Optional[typing.Union["CfnPackagingConfiguration.MssEncryptionProperty", _IResolvable_da3f097b]] = None,
            segment_duration_seconds: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Parameters for a packaging configuration that uses Microsoft Smooth Streaming (MSS) packaging.

            :param mss_manifests: A list of Microsoft Smooth manifest configurations that are available from this endpoint.
            :param encryption: Parameters for encrypting content.
            :param segment_duration_seconds: Duration (in seconds) of each fragment. Actual fragments are rounded to the nearest multiple of the source fragment duration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-msspackage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                mss_package_property = mediapackage.CfnPackagingConfiguration.MssPackageProperty(
                    mss_manifests=[mediapackage.CfnPackagingConfiguration.MssManifestProperty(
                        manifest_name="manifestName",
                        stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                            max_video_bits_per_second=123,
                            min_video_bits_per_second=123,
                            stream_order="streamOrder"
                        )
                    )],
                
                    # the properties below are optional
                    encryption=mediapackage.CfnPackagingConfiguration.MssEncryptionProperty(
                        speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url"
                        )
                    ),
                    segment_duration_seconds=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "mss_manifests": mss_manifests,
            }
            if encryption is not None:
                self._values["encryption"] = encryption
            if segment_duration_seconds is not None:
                self._values["segment_duration_seconds"] = segment_duration_seconds

        @builtins.property
        def mss_manifests(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPackagingConfiguration.MssManifestProperty", _IResolvable_da3f097b]]]:
            '''A list of Microsoft Smooth manifest configurations that are available from this endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-msspackage.html#cfn-mediapackage-packagingconfiguration-msspackage-mssmanifests
            '''
            result = self._values.get("mss_manifests")
            assert result is not None, "Required property 'mss_manifests' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPackagingConfiguration.MssManifestProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def encryption(
            self,
        ) -> typing.Optional[typing.Union["CfnPackagingConfiguration.MssEncryptionProperty", _IResolvable_da3f097b]]:
            '''Parameters for encrypting content.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-msspackage.html#cfn-mediapackage-packagingconfiguration-msspackage-encryption
            '''
            result = self._values.get("encryption")
            return typing.cast(typing.Optional[typing.Union["CfnPackagingConfiguration.MssEncryptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def segment_duration_seconds(self) -> typing.Optional[jsii.Number]:
            '''Duration (in seconds) of each fragment.

            Actual fragments are rounded to the nearest multiple of the source fragment duration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-msspackage.html#cfn-mediapackage-packagingconfiguration-msspackage-segmentdurationseconds
            '''
            result = self._values.get("segment_duration_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MssPackageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty",
        jsii_struct_bases=[],
        name_mapping={"role_arn": "roleArn", "system_ids": "systemIds", "url": "url"},
    )
    class SpekeKeyProviderProperty:
        def __init__(
            self,
            *,
            role_arn: builtins.str,
            system_ids: typing.Sequence[builtins.str],
            url: builtins.str,
        ) -> None:
            '''A configuration for accessing an external Secure Packager and Encoder Key Exchange (SPEKE) service that provides encryption keys.

            :param role_arn: The ARN for the IAM role that's granted by the key provider to provide access to the key provider API. Valid format: arn:aws:iam::{accountID}:role/{name}
            :param system_ids: List of unique identifiers for the DRM systems to use, as defined in the CPIX specification.
            :param url: URL for the key provider's key retrieval API endpoint. Must start with https://.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-spekekeyprovider.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                speke_key_provider_property = mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                    role_arn="roleArn",
                    system_ids=["systemIds"],
                    url="url"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "role_arn": role_arn,
                "system_ids": system_ids,
                "url": url,
            }

        @builtins.property
        def role_arn(self) -> builtins.str:
            '''The ARN for the IAM role that's granted by the key provider to provide access to the key provider API.

            Valid format: arn:aws:iam::{accountID}:role/{name}

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-spekekeyprovider.html#cfn-mediapackage-packagingconfiguration-spekekeyprovider-rolearn
            '''
            result = self._values.get("role_arn")
            assert result is not None, "Required property 'role_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def system_ids(self) -> typing.List[builtins.str]:
            '''List of unique identifiers for the DRM systems to use, as defined in the CPIX specification.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-spekekeyprovider.html#cfn-mediapackage-packagingconfiguration-spekekeyprovider-systemids
            '''
            result = self._values.get("system_ids")
            assert result is not None, "Required property 'system_ids' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def url(self) -> builtins.str:
            '''URL for the key provider's key retrieval API endpoint.

            Must start with https://.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-spekekeyprovider.html#cfn-mediapackage-packagingconfiguration-spekekeyprovider-url
            '''
            result = self._values.get("url")
            assert result is not None, "Required property 'url' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SpekeKeyProviderProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfiguration.StreamSelectionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "max_video_bits_per_second": "maxVideoBitsPerSecond",
            "min_video_bits_per_second": "minVideoBitsPerSecond",
            "stream_order": "streamOrder",
        },
    )
    class StreamSelectionProperty:
        def __init__(
            self,
            *,
            max_video_bits_per_second: typing.Optional[jsii.Number] = None,
            min_video_bits_per_second: typing.Optional[jsii.Number] = None,
            stream_order: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Limitations for outputs from the endpoint, based on the video bitrate.

            :param max_video_bits_per_second: The upper limit of the bitrates that this endpoint serves. If the video track exceeds this threshold, then AWS Elemental MediaPackage excludes it from output. If you don't specify a value, it defaults to 2147483647 bits per second.
            :param min_video_bits_per_second: The lower limit of the bitrates that this endpoint serves. If the video track is below this threshold, then AWS Elemental MediaPackage excludes it from output. If you don't specify a value, it defaults to 0 bits per second.
            :param stream_order: Order in which the different video bitrates are presented to the player. Valid values: ``ORIGINAL`` , ``VIDEO_BITRATE_ASCENDING`` , ``VIDEO_BITRATE_DESCENDING`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-streamselection.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                stream_selection_property = mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                    max_video_bits_per_second=123,
                    min_video_bits_per_second=123,
                    stream_order="streamOrder"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max_video_bits_per_second is not None:
                self._values["max_video_bits_per_second"] = max_video_bits_per_second
            if min_video_bits_per_second is not None:
                self._values["min_video_bits_per_second"] = min_video_bits_per_second
            if stream_order is not None:
                self._values["stream_order"] = stream_order

        @builtins.property
        def max_video_bits_per_second(self) -> typing.Optional[jsii.Number]:
            '''The upper limit of the bitrates that this endpoint serves.

            If the video track exceeds this threshold, then AWS Elemental MediaPackage excludes it from output. If you don't specify a value, it defaults to 2147483647 bits per second.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-streamselection.html#cfn-mediapackage-packagingconfiguration-streamselection-maxvideobitspersecond
            '''
            result = self._values.get("max_video_bits_per_second")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def min_video_bits_per_second(self) -> typing.Optional[jsii.Number]:
            '''The lower limit of the bitrates that this endpoint serves.

            If the video track is below this threshold, then AWS Elemental MediaPackage excludes it from output. If you don't specify a value, it defaults to 0 bits per second.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-streamselection.html#cfn-mediapackage-packagingconfiguration-streamselection-minvideobitspersecond
            '''
            result = self._values.get("min_video_bits_per_second")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def stream_order(self) -> typing.Optional[builtins.str]:
            '''Order in which the different video bitrates are presented to the player.

            Valid values: ``ORIGINAL`` , ``VIDEO_BITRATE_ASCENDING`` , ``VIDEO_BITRATE_DESCENDING`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packagingconfiguration-streamselection.html#cfn-mediapackage-packagingconfiguration-streamselection-streamorder
            '''
            result = self._values.get("stream_order")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StreamSelectionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingConfigurationProps",
    jsii_struct_bases=[],
    name_mapping={
        "id": "id",
        "packaging_group_id": "packagingGroupId",
        "cmaf_package": "cmafPackage",
        "dash_package": "dashPackage",
        "hls_package": "hlsPackage",
        "mss_package": "mssPackage",
        "tags": "tags",
    },
)
class CfnPackagingConfigurationProps:
    def __init__(
        self,
        *,
        id: builtins.str,
        packaging_group_id: builtins.str,
        cmaf_package: typing.Optional[typing.Union[CfnPackagingConfiguration.CmafPackageProperty, _IResolvable_da3f097b]] = None,
        dash_package: typing.Optional[typing.Union[CfnPackagingConfiguration.DashPackageProperty, _IResolvable_da3f097b]] = None,
        hls_package: typing.Optional[typing.Union[CfnPackagingConfiguration.HlsPackageProperty, _IResolvable_da3f097b]] = None,
        mss_package: typing.Optional[typing.Union[CfnPackagingConfiguration.MssPackageProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnPackagingConfiguration``.

        :param id: Unique identifier that you assign to the packaging configuration.
        :param packaging_group_id: The ID of the packaging group associated with this packaging configuration.
        :param cmaf_package: Parameters for CMAF packaging.
        :param dash_package: Parameters for DASH-ISO packaging.
        :param hls_package: Parameters for Apple HLS packaging.
        :param mss_package: Parameters for Microsoft Smooth Streaming packaging.
        :param tags: The tags to assign to the packaging configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_mediapackage as mediapackage
            
            cfn_packaging_configuration_props = mediapackage.CfnPackagingConfigurationProps(
                id="id",
                packaging_group_id="packagingGroupId",
            
                # the properties below are optional
                cmaf_package=mediapackage.CfnPackagingConfiguration.CmafPackageProperty(
                    hls_manifests=[mediapackage.CfnPackagingConfiguration.HlsManifestProperty(
                        ad_markers="adMarkers",
                        include_iframe_only_stream=False,
                        manifest_name="manifestName",
                        program_date_time_interval_seconds=123,
                        repeat_ext_xKey=False,
                        stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                            max_video_bits_per_second=123,
                            min_video_bits_per_second=123,
                            stream_order="streamOrder"
                        )
                    )],
            
                    # the properties below are optional
                    encryption=mediapackage.CfnPackagingConfiguration.CmafEncryptionProperty(
                        speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url"
                        )
                    ),
                    include_encoder_configuration_in_segments=False,
                    segment_duration_seconds=123
                ),
                dash_package=mediapackage.CfnPackagingConfiguration.DashPackageProperty(
                    dash_manifests=[mediapackage.CfnPackagingConfiguration.DashManifestProperty(
                        manifest_layout="manifestLayout",
                        manifest_name="manifestName",
                        min_buffer_time_seconds=123,
                        profile="profile",
                        stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                            max_video_bits_per_second=123,
                            min_video_bits_per_second=123,
                            stream_order="streamOrder"
                        )
                    )],
            
                    # the properties below are optional
                    encryption=mediapackage.CfnPackagingConfiguration.DashEncryptionProperty(
                        speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url"
                        )
                    ),
                    include_encoder_configuration_in_segments=False,
                    period_triggers=["periodTriggers"],
                    segment_duration_seconds=123,
                    segment_template_format="segmentTemplateFormat"
                ),
                hls_package=mediapackage.CfnPackagingConfiguration.HlsPackageProperty(
                    hls_manifests=[mediapackage.CfnPackagingConfiguration.HlsManifestProperty(
                        ad_markers="adMarkers",
                        include_iframe_only_stream=False,
                        manifest_name="manifestName",
                        program_date_time_interval_seconds=123,
                        repeat_ext_xKey=False,
                        stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                            max_video_bits_per_second=123,
                            min_video_bits_per_second=123,
                            stream_order="streamOrder"
                        )
                    )],
            
                    # the properties below are optional
                    encryption=mediapackage.CfnPackagingConfiguration.HlsEncryptionProperty(
                        speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url"
                        ),
            
                        # the properties below are optional
                        constant_initialization_vector="constantInitializationVector",
                        encryption_method="encryptionMethod"
                    ),
                    segment_duration_seconds=123,
                    use_audio_rendition_group=False
                ),
                mss_package=mediapackage.CfnPackagingConfiguration.MssPackageProperty(
                    mss_manifests=[mediapackage.CfnPackagingConfiguration.MssManifestProperty(
                        manifest_name="manifestName",
                        stream_selection=mediapackage.CfnPackagingConfiguration.StreamSelectionProperty(
                            max_video_bits_per_second=123,
                            min_video_bits_per_second=123,
                            stream_order="streamOrder"
                        )
                    )],
            
                    # the properties below are optional
                    encryption=mediapackage.CfnPackagingConfiguration.MssEncryptionProperty(
                        speke_key_provider=mediapackage.CfnPackagingConfiguration.SpekeKeyProviderProperty(
                            role_arn="roleArn",
                            system_ids=["systemIds"],
                            url="url"
                        )
                    ),
                    segment_duration_seconds=123
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "id": id,
            "packaging_group_id": packaging_group_id,
        }
        if cmaf_package is not None:
            self._values["cmaf_package"] = cmaf_package
        if dash_package is not None:
            self._values["dash_package"] = dash_package
        if hls_package is not None:
            self._values["hls_package"] = hls_package
        if mss_package is not None:
            self._values["mss_package"] = mss_package
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def id(self) -> builtins.str:
        '''Unique identifier that you assign to the packaging configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html#cfn-mediapackage-packagingconfiguration-id
        '''
        result = self._values.get("id")
        assert result is not None, "Required property 'id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def packaging_group_id(self) -> builtins.str:
        '''The ID of the packaging group associated with this packaging configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html#cfn-mediapackage-packagingconfiguration-packaginggroupid
        '''
        result = self._values.get("packaging_group_id")
        assert result is not None, "Required property 'packaging_group_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def cmaf_package(
        self,
    ) -> typing.Optional[typing.Union[CfnPackagingConfiguration.CmafPackageProperty, _IResolvable_da3f097b]]:
        '''Parameters for CMAF packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html#cfn-mediapackage-packagingconfiguration-cmafpackage
        '''
        result = self._values.get("cmaf_package")
        return typing.cast(typing.Optional[typing.Union[CfnPackagingConfiguration.CmafPackageProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def dash_package(
        self,
    ) -> typing.Optional[typing.Union[CfnPackagingConfiguration.DashPackageProperty, _IResolvable_da3f097b]]:
        '''Parameters for DASH-ISO packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html#cfn-mediapackage-packagingconfiguration-dashpackage
        '''
        result = self._values.get("dash_package")
        return typing.cast(typing.Optional[typing.Union[CfnPackagingConfiguration.DashPackageProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def hls_package(
        self,
    ) -> typing.Optional[typing.Union[CfnPackagingConfiguration.HlsPackageProperty, _IResolvable_da3f097b]]:
        '''Parameters for Apple HLS packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html#cfn-mediapackage-packagingconfiguration-hlspackage
        '''
        result = self._values.get("hls_package")
        return typing.cast(typing.Optional[typing.Union[CfnPackagingConfiguration.HlsPackageProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def mss_package(
        self,
    ) -> typing.Optional[typing.Union[CfnPackagingConfiguration.MssPackageProperty, _IResolvable_da3f097b]]:
        '''Parameters for Microsoft Smooth Streaming packaging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html#cfn-mediapackage-packagingconfiguration-msspackage
        '''
        result = self._values.get("mss_package")
        return typing.cast(typing.Optional[typing.Union[CfnPackagingConfiguration.MssPackageProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags to assign to the packaging configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packagingconfiguration.html#cfn-mediapackage-packagingconfiguration-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPackagingConfigurationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnPackagingGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingGroup",
):
    '''A CloudFormation ``AWS::MediaPackage::PackagingGroup``.

    Creates a packaging group.

    The packaging group holds one or more packaging configurations. When you create an asset, you specify the packaging group associated with the asset. The asset has playback endpoints for each packaging configuration within the group.

    :cloudformationResource: AWS::MediaPackage::PackagingGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packaginggroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_mediapackage as mediapackage
        
        cfn_packaging_group = mediapackage.CfnPackagingGroup(self, "MyCfnPackagingGroup",
            id="id",
        
            # the properties below are optional
            authorization=mediapackage.CfnPackagingGroup.AuthorizationProperty(
                cdn_identifier_secret="cdnIdentifierSecret",
                secrets_role_arn="secretsRoleArn"
            ),
            egress_access_logs=mediapackage.CfnPackagingGroup.LogConfigurationProperty(
                log_group_name="logGroupName"
            ),
            tags=[CfnTag(
                key="key",
                value="value"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id_: builtins.str,
        *,
        id: builtins.str,
        authorization: typing.Optional[typing.Union["CfnPackagingGroup.AuthorizationProperty", _IResolvable_da3f097b]] = None,
        egress_access_logs: typing.Optional[typing.Union["CfnPackagingGroup.LogConfigurationProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::MediaPackage::PackagingGroup``.

        :param scope: - scope in which this resource is defined.
        :param id_: - scoped id of the resource.
        :param id: Unique identifier that you assign to the packaging group.
        :param authorization: Parameters for CDN authorization.
        :param egress_access_logs: The configuration parameters for egress access logging.
        :param tags: The tags to assign to the packaging group.
        '''
        props = CfnPackagingGroupProps(
            id=id,
            authorization=authorization,
            egress_access_logs=egress_access_logs,
            tags=tags,
        )

        jsii.create(self.__class__, self, [scope, id_, props])

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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) for the packaging group.

        You can get this from the response to any request to the packaging group.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDomainName")
    def attr_domain_name(self) -> builtins.str:
        '''The fully qualified domain name for the assets in the PackagingGroup.

        :cloudformationAttribute: DomainName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags to assign to the packaging group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packaginggroup.html#cfn-mediapackage-packaginggroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="id")
    def id(self) -> builtins.str:
        '''Unique identifier that you assign to the packaging group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packaginggroup.html#cfn-mediapackage-packaginggroup-id
        '''
        return typing.cast(builtins.str, jsii.get(self, "id"))

    @id.setter
    def id(self, value: builtins.str) -> None:
        jsii.set(self, "id", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="authorization")
    def authorization(
        self,
    ) -> typing.Optional[typing.Union["CfnPackagingGroup.AuthorizationProperty", _IResolvable_da3f097b]]:
        '''Parameters for CDN authorization.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packaginggroup.html#cfn-mediapackage-packaginggroup-authorization
        '''
        return typing.cast(typing.Optional[typing.Union["CfnPackagingGroup.AuthorizationProperty", _IResolvable_da3f097b]], jsii.get(self, "authorization"))

    @authorization.setter
    def authorization(
        self,
        value: typing.Optional[typing.Union["CfnPackagingGroup.AuthorizationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "authorization", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="egressAccessLogs")
    def egress_access_logs(
        self,
    ) -> typing.Optional[typing.Union["CfnPackagingGroup.LogConfigurationProperty", _IResolvable_da3f097b]]:
        '''The configuration parameters for egress access logging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packaginggroup.html#cfn-mediapackage-packaginggroup-egressaccesslogs
        '''
        return typing.cast(typing.Optional[typing.Union["CfnPackagingGroup.LogConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "egressAccessLogs"))

    @egress_access_logs.setter
    def egress_access_logs(
        self,
        value: typing.Optional[typing.Union["CfnPackagingGroup.LogConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "egressAccessLogs", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingGroup.AuthorizationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cdn_identifier_secret": "cdnIdentifierSecret",
            "secrets_role_arn": "secretsRoleArn",
        },
    )
    class AuthorizationProperty:
        def __init__(
            self,
            *,
            cdn_identifier_secret: builtins.str,
            secrets_role_arn: builtins.str,
        ) -> None:
            '''Parameters for enabling CDN authorization.

            :param cdn_identifier_secret: The Amazon Resource Name (ARN) for the secret in AWS Secrets Manager that is used for CDN authorization.
            :param secrets_role_arn: The Amazon Resource Name (ARN) for the IAM role that allows MediaPackage to communicate with AWS Secrets Manager .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packaginggroup-authorization.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                authorization_property = mediapackage.CfnPackagingGroup.AuthorizationProperty(
                    cdn_identifier_secret="cdnIdentifierSecret",
                    secrets_role_arn="secretsRoleArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "cdn_identifier_secret": cdn_identifier_secret,
                "secrets_role_arn": secrets_role_arn,
            }

        @builtins.property
        def cdn_identifier_secret(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) for the secret in AWS Secrets Manager that is used for CDN authorization.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packaginggroup-authorization.html#cfn-mediapackage-packaginggroup-authorization-cdnidentifiersecret
            '''
            result = self._values.get("cdn_identifier_secret")
            assert result is not None, "Required property 'cdn_identifier_secret' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def secrets_role_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) for the IAM role that allows MediaPackage to communicate with AWS Secrets Manager .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packaginggroup-authorization.html#cfn-mediapackage-packaginggroup-authorization-secretsrolearn
            '''
            result = self._values.get("secrets_role_arn")
            assert result is not None, "Required property 'secrets_role_arn' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AuthorizationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingGroup.LogConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"log_group_name": "logGroupName"},
    )
    class LogConfigurationProperty:
        def __init__(
            self,
            *,
            log_group_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Sets a custom Amazon CloudWatch log group name for egress logs.

            If a log group name isn't specified, the default name is used: /aws/MediaPackage/EgressAccessLogs.

            :param log_group_name: Sets a custom Amazon CloudWatch log group name for egress logs. If a log group name isn't specified, the default name is used: /aws/MediaPackage/EgressAccessLogs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packaginggroup-logconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediapackage as mediapackage
                
                log_configuration_property = mediapackage.CfnPackagingGroup.LogConfigurationProperty(
                    log_group_name="logGroupName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if log_group_name is not None:
                self._values["log_group_name"] = log_group_name

        @builtins.property
        def log_group_name(self) -> typing.Optional[builtins.str]:
            '''Sets a custom Amazon CloudWatch log group name for egress logs.

            If a log group name isn't specified, the default name is used: /aws/MediaPackage/EgressAccessLogs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediapackage-packaginggroup-logconfiguration.html#cfn-mediapackage-packaginggroup-logconfiguration-loggroupname
            '''
            result = self._values.get("log_group_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LogConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_mediapackage.CfnPackagingGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "id": "id",
        "authorization": "authorization",
        "egress_access_logs": "egressAccessLogs",
        "tags": "tags",
    },
)
class CfnPackagingGroupProps:
    def __init__(
        self,
        *,
        id: builtins.str,
        authorization: typing.Optional[typing.Union[CfnPackagingGroup.AuthorizationProperty, _IResolvable_da3f097b]] = None,
        egress_access_logs: typing.Optional[typing.Union[CfnPackagingGroup.LogConfigurationProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnPackagingGroup``.

        :param id: Unique identifier that you assign to the packaging group.
        :param authorization: Parameters for CDN authorization.
        :param egress_access_logs: The configuration parameters for egress access logging.
        :param tags: The tags to assign to the packaging group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packaginggroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_mediapackage as mediapackage
            
            cfn_packaging_group_props = mediapackage.CfnPackagingGroupProps(
                id="id",
            
                # the properties below are optional
                authorization=mediapackage.CfnPackagingGroup.AuthorizationProperty(
                    cdn_identifier_secret="cdnIdentifierSecret",
                    secrets_role_arn="secretsRoleArn"
                ),
                egress_access_logs=mediapackage.CfnPackagingGroup.LogConfigurationProperty(
                    log_group_name="logGroupName"
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "id": id,
        }
        if authorization is not None:
            self._values["authorization"] = authorization
        if egress_access_logs is not None:
            self._values["egress_access_logs"] = egress_access_logs
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def id(self) -> builtins.str:
        '''Unique identifier that you assign to the packaging group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packaginggroup.html#cfn-mediapackage-packaginggroup-id
        '''
        result = self._values.get("id")
        assert result is not None, "Required property 'id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def authorization(
        self,
    ) -> typing.Optional[typing.Union[CfnPackagingGroup.AuthorizationProperty, _IResolvable_da3f097b]]:
        '''Parameters for CDN authorization.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packaginggroup.html#cfn-mediapackage-packaginggroup-authorization
        '''
        result = self._values.get("authorization")
        return typing.cast(typing.Optional[typing.Union[CfnPackagingGroup.AuthorizationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def egress_access_logs(
        self,
    ) -> typing.Optional[typing.Union[CfnPackagingGroup.LogConfigurationProperty, _IResolvable_da3f097b]]:
        '''The configuration parameters for egress access logging.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packaginggroup.html#cfn-mediapackage-packaginggroup-egressaccesslogs
        '''
        result = self._values.get("egress_access_logs")
        return typing.cast(typing.Optional[typing.Union[CfnPackagingGroup.LogConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags to assign to the packaging group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediapackage-packaginggroup.html#cfn-mediapackage-packaginggroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPackagingGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnAsset",
    "CfnAssetProps",
    "CfnChannel",
    "CfnChannelProps",
    "CfnOriginEndpoint",
    "CfnOriginEndpointProps",
    "CfnPackagingConfiguration",
    "CfnPackagingConfigurationProps",
    "CfnPackagingGroup",
    "CfnPackagingGroupProps",
]

publication.publish()
