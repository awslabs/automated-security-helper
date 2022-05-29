'''
# AWS IoT Analytics Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_iotanalytics as iotanalytics
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-iotanalytics-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::IoTAnalytics](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_IoTAnalytics.html).

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
class CfnChannel(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotanalytics.CfnChannel",
):
    '''A CloudFormation ``AWS::IoTAnalytics::Channel``.

    The AWS::IoTAnalytics::Channel resource collects data from an MQTT topic and archives the raw, unprocessed messages before publishing the data to a pipeline. For more information, see `How to Use AWS IoT Analytics <https://docs.aws.amazon.com/iotanalytics/latest/userguide/welcome.html#aws-iot-analytics-how>`_ in the *AWS IoT Analytics User Guide* .

    :cloudformationResource: AWS::IoTAnalytics::Channel
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-channel.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotanalytics as iotanalytics
        
        # service_managed_s3: Any
        
        cfn_channel = iotanalytics.CfnChannel(self, "MyCfnChannel",
            channel_name="channelName",
            channel_storage=iotanalytics.CfnChannel.ChannelStorageProperty(
                customer_managed_s3=iotanalytics.CfnChannel.CustomerManagedS3Property(
                    bucket="bucket",
                    role_arn="roleArn",
        
                    # the properties below are optional
                    key_prefix="keyPrefix"
                ),
                service_managed_s3=service_managed_s3
            ),
            retention_period=iotanalytics.CfnChannel.RetentionPeriodProperty(
                number_of_days=123,
                unlimited=False
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
        id: builtins.str,
        *,
        channel_name: typing.Optional[builtins.str] = None,
        channel_storage: typing.Optional[typing.Union["CfnChannel.ChannelStorageProperty", _IResolvable_da3f097b]] = None,
        retention_period: typing.Optional[typing.Union["CfnChannel.RetentionPeriodProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::IoTAnalytics::Channel``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param channel_name: The name of the channel.
        :param channel_storage: Where channel data is stored.
        :param retention_period: How long, in days, message data is kept for the channel.
        :param tags: Metadata which can be used to manage the channel. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnChannelProps(
            channel_name=channel_name,
            channel_storage=channel_storage,
            retention_period=retention_period,
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
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''
        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Metadata which can be used to manage the channel.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-channel.html#cfn-iotanalytics-channel-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="channelName")
    def channel_name(self) -> typing.Optional[builtins.str]:
        '''The name of the channel.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-channel.html#cfn-iotanalytics-channel-channelname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "channelName"))

    @channel_name.setter
    def channel_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "channelName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="channelStorage")
    def channel_storage(
        self,
    ) -> typing.Optional[typing.Union["CfnChannel.ChannelStorageProperty", _IResolvable_da3f097b]]:
        '''Where channel data is stored.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-channel.html#cfn-iotanalytics-channel-channelstorage
        '''
        return typing.cast(typing.Optional[typing.Union["CfnChannel.ChannelStorageProperty", _IResolvable_da3f097b]], jsii.get(self, "channelStorage"))

    @channel_storage.setter
    def channel_storage(
        self,
        value: typing.Optional[typing.Union["CfnChannel.ChannelStorageProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "channelStorage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="retentionPeriod")
    def retention_period(
        self,
    ) -> typing.Optional[typing.Union["CfnChannel.RetentionPeriodProperty", _IResolvable_da3f097b]]:
        '''How long, in days, message data is kept for the channel.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-channel.html#cfn-iotanalytics-channel-retentionperiod
        '''
        return typing.cast(typing.Optional[typing.Union["CfnChannel.RetentionPeriodProperty", _IResolvable_da3f097b]], jsii.get(self, "retentionPeriod"))

    @retention_period.setter
    def retention_period(
        self,
        value: typing.Optional[typing.Union["CfnChannel.RetentionPeriodProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "retentionPeriod", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnChannel.ChannelStorageProperty",
        jsii_struct_bases=[],
        name_mapping={
            "customer_managed_s3": "customerManagedS3",
            "service_managed_s3": "serviceManagedS3",
        },
    )
    class ChannelStorageProperty:
        def __init__(
            self,
            *,
            customer_managed_s3: typing.Optional[typing.Union["CfnChannel.CustomerManagedS3Property", _IResolvable_da3f097b]] = None,
            service_managed_s3: typing.Any = None,
        ) -> None:
            '''Where channel data is stored.

            You may choose one of ``serviceManagedS3`` , ``customerManagedS3`` storage. If not specified, the default is ``serviceManagedS3`` . This can't be changed after creation of the channel.

            :param customer_managed_s3: Used to store channel data in an S3 bucket that you manage. If customer managed storage is selected, the ``retentionPeriod`` parameter is ignored. You can't change the choice of S3 storage after the data store is created.
            :param service_managed_s3: Used to store channel data in an S3 bucket managed by AWS IoT Analytics . You can't change the choice of S3 storage after the data store is created.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-channel-channelstorage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                # service_managed_s3: Any
                
                channel_storage_property = iotanalytics.CfnChannel.ChannelStorageProperty(
                    customer_managed_s3=iotanalytics.CfnChannel.CustomerManagedS3Property(
                        bucket="bucket",
                        role_arn="roleArn",
                
                        # the properties below are optional
                        key_prefix="keyPrefix"
                    ),
                    service_managed_s3=service_managed_s3
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if customer_managed_s3 is not None:
                self._values["customer_managed_s3"] = customer_managed_s3
            if service_managed_s3 is not None:
                self._values["service_managed_s3"] = service_managed_s3

        @builtins.property
        def customer_managed_s3(
            self,
        ) -> typing.Optional[typing.Union["CfnChannel.CustomerManagedS3Property", _IResolvable_da3f097b]]:
            '''Used to store channel data in an S3 bucket that you manage.

            If customer managed storage is selected, the ``retentionPeriod`` parameter is ignored. You can't change the choice of S3 storage after the data store is created.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-channel-channelstorage.html#cfn-iotanalytics-channel-channelstorage-customermanageds3
            '''
            result = self._values.get("customer_managed_s3")
            return typing.cast(typing.Optional[typing.Union["CfnChannel.CustomerManagedS3Property", _IResolvable_da3f097b]], result)

        @builtins.property
        def service_managed_s3(self) -> typing.Any:
            '''Used to store channel data in an S3 bucket managed by AWS IoT Analytics .

            You can't change the choice of S3 storage after the data store is created.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-channel-channelstorage.html#cfn-iotanalytics-channel-channelstorage-servicemanageds3
            '''
            result = self._values.get("service_managed_s3")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ChannelStorageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnChannel.CustomerManagedS3Property",
        jsii_struct_bases=[],
        name_mapping={
            "bucket": "bucket",
            "role_arn": "roleArn",
            "key_prefix": "keyPrefix",
        },
    )
    class CustomerManagedS3Property:
        def __init__(
            self,
            *,
            bucket: builtins.str,
            role_arn: builtins.str,
            key_prefix: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Used to store channel data in an S3 bucket that you manage.

            :param bucket: The name of the S3 bucket in which channel data is stored.
            :param role_arn: The ARN of the role that grants AWS IoT Analytics permission to interact with your Amazon S3 resources.
            :param key_prefix: (Optional) The prefix used to create the keys of the channel data objects. Each object in an S3 bucket has a key that is its unique identifier within the bucket (each object in a bucket has exactly one key). The prefix must end with a forward slash (/).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-channel-customermanageds3.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                customer_managed_s3_property = iotanalytics.CfnChannel.CustomerManagedS3Property(
                    bucket="bucket",
                    role_arn="roleArn",
                
                    # the properties below are optional
                    key_prefix="keyPrefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket": bucket,
                "role_arn": role_arn,
            }
            if key_prefix is not None:
                self._values["key_prefix"] = key_prefix

        @builtins.property
        def bucket(self) -> builtins.str:
            '''The name of the S3 bucket in which channel data is stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-channel-customermanageds3.html#cfn-iotanalytics-channel-customermanageds3-bucket
            '''
            result = self._values.get("bucket")
            assert result is not None, "Required property 'bucket' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def role_arn(self) -> builtins.str:
            '''The ARN of the role that grants AWS IoT Analytics permission to interact with your Amazon S3 resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-channel-customermanageds3.html#cfn-iotanalytics-channel-customermanageds3-rolearn
            '''
            result = self._values.get("role_arn")
            assert result is not None, "Required property 'role_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def key_prefix(self) -> typing.Optional[builtins.str]:
            '''(Optional) The prefix used to create the keys of the channel data objects.

            Each object in an S3 bucket has a key that is its unique identifier within the bucket (each object in a bucket has exactly one key). The prefix must end with a forward slash (/).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-channel-customermanageds3.html#cfn-iotanalytics-channel-customermanageds3-keyprefix
            '''
            result = self._values.get("key_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomerManagedS3Property(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnChannel.RetentionPeriodProperty",
        jsii_struct_bases=[],
        name_mapping={"number_of_days": "numberOfDays", "unlimited": "unlimited"},
    )
    class RetentionPeriodProperty:
        def __init__(
            self,
            *,
            number_of_days: typing.Optional[jsii.Number] = None,
            unlimited: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''How long, in days, message data is kept.

            :param number_of_days: The number of days that message data is kept. The ``unlimited`` parameter must be false.
            :param unlimited: If true, message data is kept indefinitely.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-channel-retentionperiod.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                retention_period_property = iotanalytics.CfnChannel.RetentionPeriodProperty(
                    number_of_days=123,
                    unlimited=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if number_of_days is not None:
                self._values["number_of_days"] = number_of_days
            if unlimited is not None:
                self._values["unlimited"] = unlimited

        @builtins.property
        def number_of_days(self) -> typing.Optional[jsii.Number]:
            '''The number of days that message data is kept.

            The ``unlimited`` parameter must be false.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-channel-retentionperiod.html#cfn-iotanalytics-channel-retentionperiod-numberofdays
            '''
            result = self._values.get("number_of_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def unlimited(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If true, message data is kept indefinitely.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-channel-retentionperiod.html#cfn-iotanalytics-channel-retentionperiod-unlimited
            '''
            result = self._values.get("unlimited")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RetentionPeriodProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotanalytics.CfnChannelProps",
    jsii_struct_bases=[],
    name_mapping={
        "channel_name": "channelName",
        "channel_storage": "channelStorage",
        "retention_period": "retentionPeriod",
        "tags": "tags",
    },
)
class CfnChannelProps:
    def __init__(
        self,
        *,
        channel_name: typing.Optional[builtins.str] = None,
        channel_storage: typing.Optional[typing.Union[CfnChannel.ChannelStorageProperty, _IResolvable_da3f097b]] = None,
        retention_period: typing.Optional[typing.Union[CfnChannel.RetentionPeriodProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnChannel``.

        :param channel_name: The name of the channel.
        :param channel_storage: Where channel data is stored.
        :param retention_period: How long, in days, message data is kept for the channel.
        :param tags: Metadata which can be used to manage the channel. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-channel.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotanalytics as iotanalytics
            
            # service_managed_s3: Any
            
            cfn_channel_props = iotanalytics.CfnChannelProps(
                channel_name="channelName",
                channel_storage=iotanalytics.CfnChannel.ChannelStorageProperty(
                    customer_managed_s3=iotanalytics.CfnChannel.CustomerManagedS3Property(
                        bucket="bucket",
                        role_arn="roleArn",
            
                        # the properties below are optional
                        key_prefix="keyPrefix"
                    ),
                    service_managed_s3=service_managed_s3
                ),
                retention_period=iotanalytics.CfnChannel.RetentionPeriodProperty(
                    number_of_days=123,
                    unlimited=False
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if channel_name is not None:
            self._values["channel_name"] = channel_name
        if channel_storage is not None:
            self._values["channel_storage"] = channel_storage
        if retention_period is not None:
            self._values["retention_period"] = retention_period
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def channel_name(self) -> typing.Optional[builtins.str]:
        '''The name of the channel.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-channel.html#cfn-iotanalytics-channel-channelname
        '''
        result = self._values.get("channel_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def channel_storage(
        self,
    ) -> typing.Optional[typing.Union[CfnChannel.ChannelStorageProperty, _IResolvable_da3f097b]]:
        '''Where channel data is stored.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-channel.html#cfn-iotanalytics-channel-channelstorage
        '''
        result = self._values.get("channel_storage")
        return typing.cast(typing.Optional[typing.Union[CfnChannel.ChannelStorageProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def retention_period(
        self,
    ) -> typing.Optional[typing.Union[CfnChannel.RetentionPeriodProperty, _IResolvable_da3f097b]]:
        '''How long, in days, message data is kept for the channel.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-channel.html#cfn-iotanalytics-channel-retentionperiod
        '''
        result = self._values.get("retention_period")
        return typing.cast(typing.Optional[typing.Union[CfnChannel.RetentionPeriodProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Metadata which can be used to manage the channel.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-channel.html#cfn-iotanalytics-channel-tags
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
class CfnDataset(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset",
):
    '''A CloudFormation ``AWS::IoTAnalytics::Dataset``.

    The AWS::IoTAnalytics::Dataset resource stores data retrieved from a data store by applying a ``queryAction`` (an SQL query) or a ``containerAction`` (executing a containerized application). The data set can be populated manually by calling ``CreateDatasetContent`` or automatically according to a ``trigger`` you specify. For more information, see `How to Use AWS IoT Analytics <https://docs.aws.amazon.com/iotanalytics/latest/userguide/welcome.html#aws-iot-analytics-how>`_ in the *AWS IoT Analytics User Guide* .

    :cloudformationResource: AWS::IoTAnalytics::Dataset
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotanalytics as iotanalytics
        
        cfn_dataset = iotanalytics.CfnDataset(self, "MyCfnDataset",
            actions=[iotanalytics.CfnDataset.ActionProperty(
                action_name="actionName",
        
                # the properties below are optional
                container_action=iotanalytics.CfnDataset.ContainerActionProperty(
                    execution_role_arn="executionRoleArn",
                    image="image",
                    resource_configuration=iotanalytics.CfnDataset.ResourceConfigurationProperty(
                        compute_type="computeType",
                        volume_size_in_gb=123
                    ),
        
                    # the properties below are optional
                    variables=[iotanalytics.CfnDataset.VariableProperty(
                        variable_name="variableName",
        
                        # the properties below are optional
                        dataset_content_version_value=iotanalytics.CfnDataset.DatasetContentVersionValueProperty(
                            dataset_name="datasetName"
                        ),
                        double_value=123,
                        output_file_uri_value=iotanalytics.CfnDataset.OutputFileUriValueProperty(
                            file_name="fileName"
                        ),
                        string_value="stringValue"
                    )]
                ),
                query_action=iotanalytics.CfnDataset.QueryActionProperty(
                    sql_query="sqlQuery",
        
                    # the properties below are optional
                    filters=[iotanalytics.CfnDataset.FilterProperty(
                        delta_time=iotanalytics.CfnDataset.DeltaTimeProperty(
                            offset_seconds=123,
                            time_expression="timeExpression"
                        )
                    )]
                )
            )],
        
            # the properties below are optional
            content_delivery_rules=[iotanalytics.CfnDataset.DatasetContentDeliveryRuleProperty(
                destination=iotanalytics.CfnDataset.DatasetContentDeliveryRuleDestinationProperty(
                    iot_events_destination_configuration=iotanalytics.CfnDataset.IotEventsDestinationConfigurationProperty(
                        input_name="inputName",
                        role_arn="roleArn"
                    ),
                    s3_destination_configuration=iotanalytics.CfnDataset.S3DestinationConfigurationProperty(
                        bucket="bucket",
                        key="key",
                        role_arn="roleArn",
        
                        # the properties below are optional
                        glue_configuration=iotanalytics.CfnDataset.GlueConfigurationProperty(
                            database_name="databaseName",
                            table_name="tableName"
                        )
                    )
                ),
        
                # the properties below are optional
                entry_name="entryName"
            )],
            dataset_name="datasetName",
            late_data_rules=[iotanalytics.CfnDataset.LateDataRuleProperty(
                rule_configuration=iotanalytics.CfnDataset.LateDataRuleConfigurationProperty(
                    delta_time_session_window_configuration=iotanalytics.CfnDataset.DeltaTimeSessionWindowConfigurationProperty(
                        timeout_in_minutes=123
                    )
                ),
        
                # the properties below are optional
                rule_name="ruleName"
            )],
            retention_period=iotanalytics.CfnDataset.RetentionPeriodProperty(
                number_of_days=123,
                unlimited=False
            ),
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            triggers=[iotanalytics.CfnDataset.TriggerProperty(
                schedule=iotanalytics.CfnDataset.ScheduleProperty(
                    schedule_expression="scheduleExpression"
                ),
                triggering_dataset=iotanalytics.CfnDataset.TriggeringDatasetProperty(
                    dataset_name="datasetName"
                )
            )],
            versioning_configuration=iotanalytics.CfnDataset.VersioningConfigurationProperty(
                max_versions=123,
                unlimited=False
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        actions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataset.ActionProperty", _IResolvable_da3f097b]]],
        content_delivery_rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataset.DatasetContentDeliveryRuleProperty", _IResolvable_da3f097b]]]] = None,
        dataset_name: typing.Optional[builtins.str] = None,
        late_data_rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataset.LateDataRuleProperty", _IResolvable_da3f097b]]]] = None,
        retention_period: typing.Optional[typing.Union["CfnDataset.RetentionPeriodProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        triggers: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataset.TriggerProperty", _IResolvable_da3f097b]]]] = None,
        versioning_configuration: typing.Optional[typing.Union["CfnDataset.VersioningConfigurationProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::IoTAnalytics::Dataset``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param actions: The ``DatasetAction`` objects that automatically create the dataset contents.
        :param content_delivery_rules: When dataset contents are created they are delivered to destinations specified here.
        :param dataset_name: The name of the dataset.
        :param late_data_rules: A list of data rules that send notifications to CloudWatch, when data arrives late. To specify ``lateDataRules`` , the dataset must use a `DeltaTimer <https://docs.aws.amazon.com/iotanalytics/latest/APIReference/API_DeltaTime.html>`_ filter.
        :param retention_period: Optional. How long, in days, message data is kept for the dataset.
        :param tags: Metadata which can be used to manage the data set. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        :param triggers: The ``DatasetTrigger`` objects that specify when the dataset is automatically updated.
        :param versioning_configuration: Optional. How many versions of dataset contents are kept. If not specified or set to null, only the latest version plus the latest succeeded version (if they are different) are kept for the time period specified by the ``retentionPeriod`` parameter. For more information, see `Keeping Multiple Versions of AWS IoT Analytics datasets <https://docs.aws.amazon.com/iotanalytics/latest/userguide/getting-started.html#aws-iot-analytics-dataset-versions>`_ in the *AWS IoT Analytics User Guide* .
        '''
        props = CfnDatasetProps(
            actions=actions,
            content_delivery_rules=content_delivery_rules,
            dataset_name=dataset_name,
            late_data_rules=late_data_rules,
            retention_period=retention_period,
            tags=tags,
            triggers=triggers,
            versioning_configuration=versioning_configuration,
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
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''
        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Metadata which can be used to manage the data set.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="actions")
    def actions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.ActionProperty", _IResolvable_da3f097b]]]:
        '''The ``DatasetAction`` objects that automatically create the dataset contents.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-actions
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.ActionProperty", _IResolvable_da3f097b]]], jsii.get(self, "actions"))

    @actions.setter
    def actions(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.ActionProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "actions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="contentDeliveryRules")
    def content_delivery_rules(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.DatasetContentDeliveryRuleProperty", _IResolvable_da3f097b]]]]:
        '''When dataset contents are created they are delivered to destinations specified here.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-contentdeliveryrules
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.DatasetContentDeliveryRuleProperty", _IResolvable_da3f097b]]]], jsii.get(self, "contentDeliveryRules"))

    @content_delivery_rules.setter
    def content_delivery_rules(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.DatasetContentDeliveryRuleProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "contentDeliveryRules", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="datasetName")
    def dataset_name(self) -> typing.Optional[builtins.str]:
        '''The name of the dataset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-datasetname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "datasetName"))

    @dataset_name.setter
    def dataset_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "datasetName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lateDataRules")
    def late_data_rules(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.LateDataRuleProperty", _IResolvable_da3f097b]]]]:
        '''A list of data rules that send notifications to CloudWatch, when data arrives late.

        To specify ``lateDataRules`` , the dataset must use a `DeltaTimer <https://docs.aws.amazon.com/iotanalytics/latest/APIReference/API_DeltaTime.html>`_ filter.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-latedatarules
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.LateDataRuleProperty", _IResolvable_da3f097b]]]], jsii.get(self, "lateDataRules"))

    @late_data_rules.setter
    def late_data_rules(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.LateDataRuleProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "lateDataRules", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="retentionPeriod")
    def retention_period(
        self,
    ) -> typing.Optional[typing.Union["CfnDataset.RetentionPeriodProperty", _IResolvable_da3f097b]]:
        '''Optional.

        How long, in days, message data is kept for the dataset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-retentionperiod
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDataset.RetentionPeriodProperty", _IResolvable_da3f097b]], jsii.get(self, "retentionPeriod"))

    @retention_period.setter
    def retention_period(
        self,
        value: typing.Optional[typing.Union["CfnDataset.RetentionPeriodProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "retentionPeriod", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="triggers")
    def triggers(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.TriggerProperty", _IResolvable_da3f097b]]]]:
        '''The ``DatasetTrigger`` objects that specify when the dataset is automatically updated.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-triggers
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.TriggerProperty", _IResolvable_da3f097b]]]], jsii.get(self, "triggers"))

    @triggers.setter
    def triggers(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.TriggerProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "triggers", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="versioningConfiguration")
    def versioning_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnDataset.VersioningConfigurationProperty", _IResolvable_da3f097b]]:
        '''Optional.

        How many versions of dataset contents are kept. If not specified or set to null, only the latest version plus the latest succeeded version (if they are different) are kept for the time period specified by the ``retentionPeriod`` parameter. For more information, see `Keeping Multiple Versions of AWS IoT Analytics datasets <https://docs.aws.amazon.com/iotanalytics/latest/userguide/getting-started.html#aws-iot-analytics-dataset-versions>`_ in the *AWS IoT Analytics User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-versioningconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDataset.VersioningConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "versioningConfiguration"))

    @versioning_configuration.setter
    def versioning_configuration(
        self,
        value: typing.Optional[typing.Union["CfnDataset.VersioningConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "versioningConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.ActionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "action_name": "actionName",
            "container_action": "containerAction",
            "query_action": "queryAction",
        },
    )
    class ActionProperty:
        def __init__(
            self,
            *,
            action_name: builtins.str,
            container_action: typing.Optional[typing.Union["CfnDataset.ContainerActionProperty", _IResolvable_da3f097b]] = None,
            query_action: typing.Optional[typing.Union["CfnDataset.QueryActionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Information needed to run the "containerAction" to produce data set contents.

            :param action_name: The name of the data set action by which data set contents are automatically created.
            :param container_action: Information which allows the system to run a containerized application in order to create the data set contents. The application must be in a Docker container along with any needed support libraries.
            :param query_action: An "SqlQueryDatasetAction" object that uses an SQL query to automatically create data set contents.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-action.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                action_property = iotanalytics.CfnDataset.ActionProperty(
                    action_name="actionName",
                
                    # the properties below are optional
                    container_action=iotanalytics.CfnDataset.ContainerActionProperty(
                        execution_role_arn="executionRoleArn",
                        image="image",
                        resource_configuration=iotanalytics.CfnDataset.ResourceConfigurationProperty(
                            compute_type="computeType",
                            volume_size_in_gb=123
                        ),
                
                        # the properties below are optional
                        variables=[iotanalytics.CfnDataset.VariableProperty(
                            variable_name="variableName",
                
                            # the properties below are optional
                            dataset_content_version_value=iotanalytics.CfnDataset.DatasetContentVersionValueProperty(
                                dataset_name="datasetName"
                            ),
                            double_value=123,
                            output_file_uri_value=iotanalytics.CfnDataset.OutputFileUriValueProperty(
                                file_name="fileName"
                            ),
                            string_value="stringValue"
                        )]
                    ),
                    query_action=iotanalytics.CfnDataset.QueryActionProperty(
                        sql_query="sqlQuery",
                
                        # the properties below are optional
                        filters=[iotanalytics.CfnDataset.FilterProperty(
                            delta_time=iotanalytics.CfnDataset.DeltaTimeProperty(
                                offset_seconds=123,
                                time_expression="timeExpression"
                            )
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "action_name": action_name,
            }
            if container_action is not None:
                self._values["container_action"] = container_action
            if query_action is not None:
                self._values["query_action"] = query_action

        @builtins.property
        def action_name(self) -> builtins.str:
            '''The name of the data set action by which data set contents are automatically created.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-action.html#cfn-iotanalytics-dataset-action-actionname
            '''
            result = self._values.get("action_name")
            assert result is not None, "Required property 'action_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def container_action(
            self,
        ) -> typing.Optional[typing.Union["CfnDataset.ContainerActionProperty", _IResolvable_da3f097b]]:
            '''Information which allows the system to run a containerized application in order to create the data set contents.

            The application must be in a Docker container along with any needed support libraries.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-action.html#cfn-iotanalytics-dataset-action-containeraction
            '''
            result = self._values.get("container_action")
            return typing.cast(typing.Optional[typing.Union["CfnDataset.ContainerActionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def query_action(
            self,
        ) -> typing.Optional[typing.Union["CfnDataset.QueryActionProperty", _IResolvable_da3f097b]]:
            '''An "SqlQueryDatasetAction" object that uses an SQL query to automatically create data set contents.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-action.html#cfn-iotanalytics-dataset-action-queryaction
            '''
            result = self._values.get("query_action")
            return typing.cast(typing.Optional[typing.Union["CfnDataset.QueryActionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.ContainerActionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "execution_role_arn": "executionRoleArn",
            "image": "image",
            "resource_configuration": "resourceConfiguration",
            "variables": "variables",
        },
    )
    class ContainerActionProperty:
        def __init__(
            self,
            *,
            execution_role_arn: builtins.str,
            image: builtins.str,
            resource_configuration: typing.Union["CfnDataset.ResourceConfigurationProperty", _IResolvable_da3f097b],
            variables: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataset.VariableProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Information needed to run the "containerAction" to produce data set contents.

            :param execution_role_arn: The ARN of the role which gives permission to the system to access needed resources in order to run the "containerAction". This includes, at minimum, permission to retrieve the data set contents which are the input to the containerized application.
            :param image: The ARN of the Docker container stored in your account. The Docker container contains an application and needed support libraries and is used to generate data set contents.
            :param resource_configuration: Configuration of the resource which executes the "containerAction".
            :param variables: The values of variables used within the context of the execution of the containerized application (basically, parameters passed to the application). Each variable must have a name and a value given by one of "stringValue", "datasetContentVersionValue", or "outputFileUriValue".

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-containeraction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                container_action_property = iotanalytics.CfnDataset.ContainerActionProperty(
                    execution_role_arn="executionRoleArn",
                    image="image",
                    resource_configuration=iotanalytics.CfnDataset.ResourceConfigurationProperty(
                        compute_type="computeType",
                        volume_size_in_gb=123
                    ),
                
                    # the properties below are optional
                    variables=[iotanalytics.CfnDataset.VariableProperty(
                        variable_name="variableName",
                
                        # the properties below are optional
                        dataset_content_version_value=iotanalytics.CfnDataset.DatasetContentVersionValueProperty(
                            dataset_name="datasetName"
                        ),
                        double_value=123,
                        output_file_uri_value=iotanalytics.CfnDataset.OutputFileUriValueProperty(
                            file_name="fileName"
                        ),
                        string_value="stringValue"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "execution_role_arn": execution_role_arn,
                "image": image,
                "resource_configuration": resource_configuration,
            }
            if variables is not None:
                self._values["variables"] = variables

        @builtins.property
        def execution_role_arn(self) -> builtins.str:
            '''The ARN of the role which gives permission to the system to access needed resources in order to run the "containerAction".

            This includes, at minimum, permission to retrieve the data set contents which are the input to the containerized application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-containeraction.html#cfn-iotanalytics-dataset-containeraction-executionrolearn
            '''
            result = self._values.get("execution_role_arn")
            assert result is not None, "Required property 'execution_role_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def image(self) -> builtins.str:
            '''The ARN of the Docker container stored in your account.

            The Docker container contains an application and needed support libraries and is used to generate data set contents.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-containeraction.html#cfn-iotanalytics-dataset-containeraction-image
            '''
            result = self._values.get("image")
            assert result is not None, "Required property 'image' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def resource_configuration(
            self,
        ) -> typing.Union["CfnDataset.ResourceConfigurationProperty", _IResolvable_da3f097b]:
            '''Configuration of the resource which executes the "containerAction".

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-containeraction.html#cfn-iotanalytics-dataset-containeraction-resourceconfiguration
            '''
            result = self._values.get("resource_configuration")
            assert result is not None, "Required property 'resource_configuration' is missing"
            return typing.cast(typing.Union["CfnDataset.ResourceConfigurationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def variables(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.VariableProperty", _IResolvable_da3f097b]]]]:
            '''The values of variables used within the context of the execution of the containerized application (basically, parameters passed to the application).

            Each variable must have a name and a value given by one of "stringValue", "datasetContentVersionValue", or "outputFileUriValue".

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-containeraction.html#cfn-iotanalytics-dataset-containeraction-variables
            '''
            result = self._values.get("variables")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.VariableProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ContainerActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.DatasetContentDeliveryRuleDestinationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "iot_events_destination_configuration": "iotEventsDestinationConfiguration",
            "s3_destination_configuration": "s3DestinationConfiguration",
        },
    )
    class DatasetContentDeliveryRuleDestinationProperty:
        def __init__(
            self,
            *,
            iot_events_destination_configuration: typing.Optional[typing.Union["CfnDataset.IotEventsDestinationConfigurationProperty", _IResolvable_da3f097b]] = None,
            s3_destination_configuration: typing.Optional[typing.Union["CfnDataset.S3DestinationConfigurationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The destination to which dataset contents are delivered.

            :param iot_events_destination_configuration: Configuration information for delivery of dataset contents to AWS IoT Events .
            :param s3_destination_configuration: Configuration information for delivery of dataset contents to Amazon S3.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-datasetcontentdeliveryruledestination.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                dataset_content_delivery_rule_destination_property = iotanalytics.CfnDataset.DatasetContentDeliveryRuleDestinationProperty(
                    iot_events_destination_configuration=iotanalytics.CfnDataset.IotEventsDestinationConfigurationProperty(
                        input_name="inputName",
                        role_arn="roleArn"
                    ),
                    s3_destination_configuration=iotanalytics.CfnDataset.S3DestinationConfigurationProperty(
                        bucket="bucket",
                        key="key",
                        role_arn="roleArn",
                
                        # the properties below are optional
                        glue_configuration=iotanalytics.CfnDataset.GlueConfigurationProperty(
                            database_name="databaseName",
                            table_name="tableName"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if iot_events_destination_configuration is not None:
                self._values["iot_events_destination_configuration"] = iot_events_destination_configuration
            if s3_destination_configuration is not None:
                self._values["s3_destination_configuration"] = s3_destination_configuration

        @builtins.property
        def iot_events_destination_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnDataset.IotEventsDestinationConfigurationProperty", _IResolvable_da3f097b]]:
            '''Configuration information for delivery of dataset contents to AWS IoT Events .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-datasetcontentdeliveryruledestination.html#cfn-iotanalytics-dataset-datasetcontentdeliveryruledestination-ioteventsdestinationconfiguration
            '''
            result = self._values.get("iot_events_destination_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnDataset.IotEventsDestinationConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def s3_destination_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnDataset.S3DestinationConfigurationProperty", _IResolvable_da3f097b]]:
            '''Configuration information for delivery of dataset contents to Amazon S3.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-datasetcontentdeliveryruledestination.html#cfn-iotanalytics-dataset-datasetcontentdeliveryruledestination-s3destinationconfiguration
            '''
            result = self._values.get("s3_destination_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnDataset.S3DestinationConfigurationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DatasetContentDeliveryRuleDestinationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.DatasetContentDeliveryRuleProperty",
        jsii_struct_bases=[],
        name_mapping={"destination": "destination", "entry_name": "entryName"},
    )
    class DatasetContentDeliveryRuleProperty:
        def __init__(
            self,
            *,
            destination: typing.Union["CfnDataset.DatasetContentDeliveryRuleDestinationProperty", _IResolvable_da3f097b],
            entry_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''When dataset contents are created, they are delivered to destination specified here.

            :param destination: The destination to which dataset contents are delivered.
            :param entry_name: The name of the dataset content delivery rules entry.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-datasetcontentdeliveryrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                dataset_content_delivery_rule_property = iotanalytics.CfnDataset.DatasetContentDeliveryRuleProperty(
                    destination=iotanalytics.CfnDataset.DatasetContentDeliveryRuleDestinationProperty(
                        iot_events_destination_configuration=iotanalytics.CfnDataset.IotEventsDestinationConfigurationProperty(
                            input_name="inputName",
                            role_arn="roleArn"
                        ),
                        s3_destination_configuration=iotanalytics.CfnDataset.S3DestinationConfigurationProperty(
                            bucket="bucket",
                            key="key",
                            role_arn="roleArn",
                
                            # the properties below are optional
                            glue_configuration=iotanalytics.CfnDataset.GlueConfigurationProperty(
                                database_name="databaseName",
                                table_name="tableName"
                            )
                        )
                    ),
                
                    # the properties below are optional
                    entry_name="entryName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination": destination,
            }
            if entry_name is not None:
                self._values["entry_name"] = entry_name

        @builtins.property
        def destination(
            self,
        ) -> typing.Union["CfnDataset.DatasetContentDeliveryRuleDestinationProperty", _IResolvable_da3f097b]:
            '''The destination to which dataset contents are delivered.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-datasetcontentdeliveryrule.html#cfn-iotanalytics-dataset-datasetcontentdeliveryrule-destination
            '''
            result = self._values.get("destination")
            assert result is not None, "Required property 'destination' is missing"
            return typing.cast(typing.Union["CfnDataset.DatasetContentDeliveryRuleDestinationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def entry_name(self) -> typing.Optional[builtins.str]:
            '''The name of the dataset content delivery rules entry.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-datasetcontentdeliveryrule.html#cfn-iotanalytics-dataset-datasetcontentdeliveryrule-entryname
            '''
            result = self._values.get("entry_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DatasetContentDeliveryRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.DatasetContentVersionValueProperty",
        jsii_struct_bases=[],
        name_mapping={"dataset_name": "datasetName"},
    )
    class DatasetContentVersionValueProperty:
        def __init__(self, *, dataset_name: builtins.str) -> None:
            '''The dataset whose latest contents are used as input to the notebook or application.

            :param dataset_name: The name of the dataset whose latest contents are used as input to the notebook or application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-datasetcontentversionvalue.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                dataset_content_version_value_property = iotanalytics.CfnDataset.DatasetContentVersionValueProperty(
                    dataset_name="datasetName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "dataset_name": dataset_name,
            }

        @builtins.property
        def dataset_name(self) -> builtins.str:
            '''The name of the dataset whose latest contents are used as input to the notebook or application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-datasetcontentversionvalue.html#cfn-iotanalytics-dataset-datasetcontentversionvalue-datasetname
            '''
            result = self._values.get("dataset_name")
            assert result is not None, "Required property 'dataset_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DatasetContentVersionValueProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.DeltaTimeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "offset_seconds": "offsetSeconds",
            "time_expression": "timeExpression",
        },
    )
    class DeltaTimeProperty:
        def __init__(
            self,
            *,
            offset_seconds: jsii.Number,
            time_expression: builtins.str,
        ) -> None:
            '''Used to limit data to that which has arrived since the last execution of the action.

            :param offset_seconds: The number of seconds of estimated in-flight lag time of message data. When you create dataset contents using message data from a specified timeframe, some message data might still be in flight when processing begins, and so do not arrive in time to be processed. Use this field to make allowances for the in flight time of your message data, so that data not processed from a previous timeframe is included with the next timeframe. Otherwise, missed message data would be excluded from processing during the next timeframe too, because its timestamp places it within the previous timeframe.
            :param time_expression: An expression by which the time of the message data might be determined. This can be the name of a timestamp field or a SQL expression that is used to derive the time the message data was generated.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-deltatime.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                delta_time_property = iotanalytics.CfnDataset.DeltaTimeProperty(
                    offset_seconds=123,
                    time_expression="timeExpression"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "offset_seconds": offset_seconds,
                "time_expression": time_expression,
            }

        @builtins.property
        def offset_seconds(self) -> jsii.Number:
            '''The number of seconds of estimated in-flight lag time of message data.

            When you create dataset contents using message data from a specified timeframe, some message data might still be in flight when processing begins, and so do not arrive in time to be processed. Use this field to make allowances for the in flight time of your message data, so that data not processed from a previous timeframe is included with the next timeframe. Otherwise, missed message data would be excluded from processing during the next timeframe too, because its timestamp places it within the previous timeframe.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-deltatime.html#cfn-iotanalytics-dataset-deltatime-offsetseconds
            '''
            result = self._values.get("offset_seconds")
            assert result is not None, "Required property 'offset_seconds' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def time_expression(self) -> builtins.str:
            '''An expression by which the time of the message data might be determined.

            This can be the name of a timestamp field or a SQL expression that is used to derive the time the message data was generated.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-deltatime.html#cfn-iotanalytics-dataset-deltatime-timeexpression
            '''
            result = self._values.get("time_expression")
            assert result is not None, "Required property 'time_expression' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DeltaTimeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.DeltaTimeSessionWindowConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"timeout_in_minutes": "timeoutInMinutes"},
    )
    class DeltaTimeSessionWindowConfigurationProperty:
        def __init__(self, *, timeout_in_minutes: jsii.Number) -> None:
            '''A structure that contains the configuration information of a delta time session window.

            ```DeltaTime`` <https://docs.aws.amazon.com/iotanalytics/latest/APIReference/API_DeltaTime.html>`_ specifies a time interval. You can use ``DeltaTime`` to create dataset contents with data that has arrived in the data store since the last execution. For an example of ``DeltaTime`` , see `Creating a SQL dataset with a delta window (CLI) <https://docs.aws.amazon.com/iotanalytics/latest/userguide/automate-create-dataset.html#automate-example6>`_ in the *AWS IoT Analytics User Guide* .

            :param timeout_in_minutes: A time interval. You can use ``timeoutInMinutes`` so that AWS IoT Analytics can batch up late data notifications that have been generated since the last execution. AWS IoT Analytics sends one batch of notifications to Amazon CloudWatch Events at one time. For more information about how to write a timestamp expression, see `Date and Time Functions and Operators <https://docs.aws.amazon.com/https://prestodb.io/docs/0.172/functions/datetime.html>`_ , in the *Presto 0.172 Documentation* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-deltatimesessionwindowconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                delta_time_session_window_configuration_property = iotanalytics.CfnDataset.DeltaTimeSessionWindowConfigurationProperty(
                    timeout_in_minutes=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "timeout_in_minutes": timeout_in_minutes,
            }

        @builtins.property
        def timeout_in_minutes(self) -> jsii.Number:
            '''A time interval.

            You can use ``timeoutInMinutes`` so that AWS IoT Analytics can batch up late data notifications that have been generated since the last execution. AWS IoT Analytics sends one batch of notifications to Amazon CloudWatch Events at one time.

            For more information about how to write a timestamp expression, see `Date and Time Functions and Operators <https://docs.aws.amazon.com/https://prestodb.io/docs/0.172/functions/datetime.html>`_ , in the *Presto 0.172 Documentation* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-deltatimesessionwindowconfiguration.html#cfn-iotanalytics-dataset-deltatimesessionwindowconfiguration-timeoutinminutes
            '''
            result = self._values.get("timeout_in_minutes")
            assert result is not None, "Required property 'timeout_in_minutes' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DeltaTimeSessionWindowConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.FilterProperty",
        jsii_struct_bases=[],
        name_mapping={"delta_time": "deltaTime"},
    )
    class FilterProperty:
        def __init__(
            self,
            *,
            delta_time: typing.Optional[typing.Union["CfnDataset.DeltaTimeProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Information which is used to filter message data, to segregate it according to the time frame in which it arrives.

            :param delta_time: Used to limit data to that which has arrived since the last execution of the action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-filter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                filter_property = iotanalytics.CfnDataset.FilterProperty(
                    delta_time=iotanalytics.CfnDataset.DeltaTimeProperty(
                        offset_seconds=123,
                        time_expression="timeExpression"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if delta_time is not None:
                self._values["delta_time"] = delta_time

        @builtins.property
        def delta_time(
            self,
        ) -> typing.Optional[typing.Union["CfnDataset.DeltaTimeProperty", _IResolvable_da3f097b]]:
            '''Used to limit data to that which has arrived since the last execution of the action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-filter.html#cfn-iotanalytics-dataset-filter-deltatime
            '''
            result = self._values.get("delta_time")
            return typing.cast(typing.Optional[typing.Union["CfnDataset.DeltaTimeProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.GlueConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"database_name": "databaseName", "table_name": "tableName"},
    )
    class GlueConfigurationProperty:
        def __init__(
            self,
            *,
            database_name: builtins.str,
            table_name: builtins.str,
        ) -> None:
            '''Configuration information for coordination with AWS Glue , a fully managed extract, transform and load (ETL) service.

            :param database_name: The name of the database in your AWS Glue Data Catalog in which the table is located. An AWS Glue Data Catalog database contains metadata tables.
            :param table_name: The name of the table in your AWS Glue Data Catalog that is used to perform the ETL operations. An AWS Glue Data Catalog table contains partitioned data and descriptions of data sources and targets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-glueconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                glue_configuration_property = iotanalytics.CfnDataset.GlueConfigurationProperty(
                    database_name="databaseName",
                    table_name="tableName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database_name": database_name,
                "table_name": table_name,
            }

        @builtins.property
        def database_name(self) -> builtins.str:
            '''The name of the database in your AWS Glue Data Catalog in which the table is located.

            An AWS Glue Data Catalog database contains metadata tables.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-glueconfiguration.html#cfn-iotanalytics-dataset-glueconfiguration-databasename
            '''
            result = self._values.get("database_name")
            assert result is not None, "Required property 'database_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def table_name(self) -> builtins.str:
            '''The name of the table in your AWS Glue Data Catalog that is used to perform the ETL operations.

            An AWS Glue Data Catalog table contains partitioned data and descriptions of data sources and targets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-glueconfiguration.html#cfn-iotanalytics-dataset-glueconfiguration-tablename
            '''
            result = self._values.get("table_name")
            assert result is not None, "Required property 'table_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GlueConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.IotEventsDestinationConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"input_name": "inputName", "role_arn": "roleArn"},
    )
    class IotEventsDestinationConfigurationProperty:
        def __init__(self, *, input_name: builtins.str, role_arn: builtins.str) -> None:
            '''Configuration information for delivery of dataset contents to AWS IoT Events .

            :param input_name: The name of the AWS IoT Events input to which dataset contents are delivered.
            :param role_arn: The ARN of the role that grants AWS IoT Analytics permission to deliver dataset contents to an AWS IoT Events input.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-ioteventsdestinationconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                iot_events_destination_configuration_property = iotanalytics.CfnDataset.IotEventsDestinationConfigurationProperty(
                    input_name="inputName",
                    role_arn="roleArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "input_name": input_name,
                "role_arn": role_arn,
            }

        @builtins.property
        def input_name(self) -> builtins.str:
            '''The name of the AWS IoT Events input to which dataset contents are delivered.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-ioteventsdestinationconfiguration.html#cfn-iotanalytics-dataset-ioteventsdestinationconfiguration-inputname
            '''
            result = self._values.get("input_name")
            assert result is not None, "Required property 'input_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def role_arn(self) -> builtins.str:
            '''The ARN of the role that grants AWS IoT Analytics permission to deliver dataset contents to an AWS IoT Events input.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-ioteventsdestinationconfiguration.html#cfn-iotanalytics-dataset-ioteventsdestinationconfiguration-rolearn
            '''
            result = self._values.get("role_arn")
            assert result is not None, "Required property 'role_arn' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IotEventsDestinationConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.LateDataRuleConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "delta_time_session_window_configuration": "deltaTimeSessionWindowConfiguration",
        },
    )
    class LateDataRuleConfigurationProperty:
        def __init__(
            self,
            *,
            delta_time_session_window_configuration: typing.Optional[typing.Union["CfnDataset.DeltaTimeSessionWindowConfigurationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The information needed to configure a delta time session window.

            :param delta_time_session_window_configuration: The information needed to configure a delta time session window.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-latedataruleconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                late_data_rule_configuration_property = iotanalytics.CfnDataset.LateDataRuleConfigurationProperty(
                    delta_time_session_window_configuration=iotanalytics.CfnDataset.DeltaTimeSessionWindowConfigurationProperty(
                        timeout_in_minutes=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if delta_time_session_window_configuration is not None:
                self._values["delta_time_session_window_configuration"] = delta_time_session_window_configuration

        @builtins.property
        def delta_time_session_window_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnDataset.DeltaTimeSessionWindowConfigurationProperty", _IResolvable_da3f097b]]:
            '''The information needed to configure a delta time session window.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-latedataruleconfiguration.html#cfn-iotanalytics-dataset-latedataruleconfiguration-deltatimesessionwindowconfiguration
            '''
            result = self._values.get("delta_time_session_window_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnDataset.DeltaTimeSessionWindowConfigurationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LateDataRuleConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.LateDataRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "rule_configuration": "ruleConfiguration",
            "rule_name": "ruleName",
        },
    )
    class LateDataRuleProperty:
        def __init__(
            self,
            *,
            rule_configuration: typing.Union["CfnDataset.LateDataRuleConfigurationProperty", _IResolvable_da3f097b],
            rule_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A structure that contains the name and configuration information of a late data rule.

            :param rule_configuration: The information needed to configure the late data rule.
            :param rule_name: The name of the late data rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-latedatarule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                late_data_rule_property = iotanalytics.CfnDataset.LateDataRuleProperty(
                    rule_configuration=iotanalytics.CfnDataset.LateDataRuleConfigurationProperty(
                        delta_time_session_window_configuration=iotanalytics.CfnDataset.DeltaTimeSessionWindowConfigurationProperty(
                            timeout_in_minutes=123
                        )
                    ),
                
                    # the properties below are optional
                    rule_name="ruleName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "rule_configuration": rule_configuration,
            }
            if rule_name is not None:
                self._values["rule_name"] = rule_name

        @builtins.property
        def rule_configuration(
            self,
        ) -> typing.Union["CfnDataset.LateDataRuleConfigurationProperty", _IResolvable_da3f097b]:
            '''The information needed to configure the late data rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-latedatarule.html#cfn-iotanalytics-dataset-latedatarule-ruleconfiguration
            '''
            result = self._values.get("rule_configuration")
            assert result is not None, "Required property 'rule_configuration' is missing"
            return typing.cast(typing.Union["CfnDataset.LateDataRuleConfigurationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def rule_name(self) -> typing.Optional[builtins.str]:
            '''The name of the late data rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-latedatarule.html#cfn-iotanalytics-dataset-latedatarule-rulename
            '''
            result = self._values.get("rule_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LateDataRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.OutputFileUriValueProperty",
        jsii_struct_bases=[],
        name_mapping={"file_name": "fileName"},
    )
    class OutputFileUriValueProperty:
        def __init__(self, *, file_name: builtins.str) -> None:
            '''The value of the variable as a structure that specifies an output file URI.

            :param file_name: The URI of the location where dataset contents are stored, usually the URI of a file in an S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-outputfileurivalue.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                output_file_uri_value_property = iotanalytics.CfnDataset.OutputFileUriValueProperty(
                    file_name="fileName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "file_name": file_name,
            }

        @builtins.property
        def file_name(self) -> builtins.str:
            '''The URI of the location where dataset contents are stored, usually the URI of a file in an S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-outputfileurivalue.html#cfn-iotanalytics-dataset-outputfileurivalue-filename
            '''
            result = self._values.get("file_name")
            assert result is not None, "Required property 'file_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OutputFileUriValueProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.QueryActionProperty",
        jsii_struct_bases=[],
        name_mapping={"sql_query": "sqlQuery", "filters": "filters"},
    )
    class QueryActionProperty:
        def __init__(
            self,
            *,
            sql_query: builtins.str,
            filters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataset.FilterProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''An "SqlQueryDatasetAction" object that uses an SQL query to automatically create data set contents.

            :param sql_query: An "SqlQueryDatasetAction" object that uses an SQL query to automatically create data set contents.
            :param filters: Pre-filters applied to message data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-queryaction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                query_action_property = iotanalytics.CfnDataset.QueryActionProperty(
                    sql_query="sqlQuery",
                
                    # the properties below are optional
                    filters=[iotanalytics.CfnDataset.FilterProperty(
                        delta_time=iotanalytics.CfnDataset.DeltaTimeProperty(
                            offset_seconds=123,
                            time_expression="timeExpression"
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "sql_query": sql_query,
            }
            if filters is not None:
                self._values["filters"] = filters

        @builtins.property
        def sql_query(self) -> builtins.str:
            '''An "SqlQueryDatasetAction" object that uses an SQL query to automatically create data set contents.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-queryaction.html#cfn-iotanalytics-dataset-queryaction-sqlquery
            '''
            result = self._values.get("sql_query")
            assert result is not None, "Required property 'sql_query' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def filters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.FilterProperty", _IResolvable_da3f097b]]]]:
            '''Pre-filters applied to message data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-queryaction.html#cfn-iotanalytics-dataset-queryaction-filters
            '''
            result = self._values.get("filters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataset.FilterProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "QueryActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.ResourceConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "compute_type": "computeType",
            "volume_size_in_gb": "volumeSizeInGb",
        },
    )
    class ResourceConfigurationProperty:
        def __init__(
            self,
            *,
            compute_type: builtins.str,
            volume_size_in_gb: jsii.Number,
        ) -> None:
            '''The configuration of the resource used to execute the ``containerAction`` .

            :param compute_type: The type of the compute resource used to execute the ``containerAction`` . Possible values are: ``ACU_1`` (vCPU=4, memory=16 GiB) or ``ACU_2`` (vCPU=8, memory=32 GiB).
            :param volume_size_in_gb: The size, in GB, of the persistent storage available to the resource instance used to execute the ``containerAction`` (min: 1, max: 50).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-resourceconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                resource_configuration_property = iotanalytics.CfnDataset.ResourceConfigurationProperty(
                    compute_type="computeType",
                    volume_size_in_gb=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "compute_type": compute_type,
                "volume_size_in_gb": volume_size_in_gb,
            }

        @builtins.property
        def compute_type(self) -> builtins.str:
            '''The type of the compute resource used to execute the ``containerAction`` .

            Possible values are: ``ACU_1`` (vCPU=4, memory=16 GiB) or ``ACU_2`` (vCPU=8, memory=32 GiB).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-resourceconfiguration.html#cfn-iotanalytics-dataset-resourceconfiguration-computetype
            '''
            result = self._values.get("compute_type")
            assert result is not None, "Required property 'compute_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def volume_size_in_gb(self) -> jsii.Number:
            '''The size, in GB, of the persistent storage available to the resource instance used to execute the ``containerAction`` (min: 1, max: 50).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-resourceconfiguration.html#cfn-iotanalytics-dataset-resourceconfiguration-volumesizeingb
            '''
            result = self._values.get("volume_size_in_gb")
            assert result is not None, "Required property 'volume_size_in_gb' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourceConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.RetentionPeriodProperty",
        jsii_struct_bases=[],
        name_mapping={"number_of_days": "numberOfDays", "unlimited": "unlimited"},
    )
    class RetentionPeriodProperty:
        def __init__(
            self,
            *,
            number_of_days: typing.Optional[jsii.Number] = None,
            unlimited: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''How long, in days, message data is kept.

            :param number_of_days: The number of days that message data is kept. The ``unlimited`` parameter must be false.
            :param unlimited: If true, message data is kept indefinitely.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-retentionperiod.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                retention_period_property = iotanalytics.CfnDataset.RetentionPeriodProperty(
                    number_of_days=123,
                    unlimited=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if number_of_days is not None:
                self._values["number_of_days"] = number_of_days
            if unlimited is not None:
                self._values["unlimited"] = unlimited

        @builtins.property
        def number_of_days(self) -> typing.Optional[jsii.Number]:
            '''The number of days that message data is kept.

            The ``unlimited`` parameter must be false.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-retentionperiod.html#cfn-iotanalytics-dataset-retentionperiod-numberofdays
            '''
            result = self._values.get("number_of_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def unlimited(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If true, message data is kept indefinitely.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-retentionperiod.html#cfn-iotanalytics-dataset-retentionperiod-unlimited
            '''
            result = self._values.get("unlimited")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RetentionPeriodProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.S3DestinationConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket": "bucket",
            "key": "key",
            "role_arn": "roleArn",
            "glue_configuration": "glueConfiguration",
        },
    )
    class S3DestinationConfigurationProperty:
        def __init__(
            self,
            *,
            bucket: builtins.str,
            key: builtins.str,
            role_arn: builtins.str,
            glue_configuration: typing.Optional[typing.Union["CfnDataset.GlueConfigurationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Configuration information for delivery of dataset contents to Amazon Simple Storage Service (Amazon S3).

            :param bucket: The name of the S3 bucket to which dataset contents are delivered.
            :param key: The key of the dataset contents object in an S3 bucket. Each object has a key that is a unique identifier. Each object has exactly one key. You can create a unique key with the following options: - Use ``!{iotanalytics:scheduleTime}`` to insert the time of a scheduled SQL query run. - Use ``!{iotanalytics:versionId}`` to insert a unique hash that identifies a dataset content. - Use ``!{iotanalytics:creationTime}`` to insert the creation time of a dataset content. The following example creates a unique key for a CSV file: ``dataset/mydataset/!{iotanalytics:scheduleTime}/!{iotanalytics:versionId}.csv`` .. epigraph:: If you don't use ``!{iotanalytics:versionId}`` to specify the key, you might get duplicate keys. For example, you might have two dataset contents with the same ``scheduleTime`` but different ``versionId`` s. This means that one dataset content overwrites the other.
            :param role_arn: The ARN of the role that grants AWS IoT Analytics permission to interact with your Amazon S3 and AWS Glue resources.
            :param glue_configuration: Configuration information for coordination with AWS Glue , a fully managed extract, transform and load (ETL) service.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-s3destinationconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                s3_destination_configuration_property = iotanalytics.CfnDataset.S3DestinationConfigurationProperty(
                    bucket="bucket",
                    key="key",
                    role_arn="roleArn",
                
                    # the properties below are optional
                    glue_configuration=iotanalytics.CfnDataset.GlueConfigurationProperty(
                        database_name="databaseName",
                        table_name="tableName"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket": bucket,
                "key": key,
                "role_arn": role_arn,
            }
            if glue_configuration is not None:
                self._values["glue_configuration"] = glue_configuration

        @builtins.property
        def bucket(self) -> builtins.str:
            '''The name of the S3 bucket to which dataset contents are delivered.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-s3destinationconfiguration.html#cfn-iotanalytics-dataset-s3destinationconfiguration-bucket
            '''
            result = self._values.get("bucket")
            assert result is not None, "Required property 'bucket' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def key(self) -> builtins.str:
            '''The key of the dataset contents object in an S3 bucket.

            Each object has a key that is a unique identifier. Each object has exactly one key.

            You can create a unique key with the following options:

            - Use ``!{iotanalytics:scheduleTime}`` to insert the time of a scheduled SQL query run.
            - Use ``!{iotanalytics:versionId}`` to insert a unique hash that identifies a dataset content.
            - Use ``!{iotanalytics:creationTime}`` to insert the creation time of a dataset content.

            The following example creates a unique key for a CSV file: ``dataset/mydataset/!{iotanalytics:scheduleTime}/!{iotanalytics:versionId}.csv``
            .. epigraph::

               If you don't use ``!{iotanalytics:versionId}`` to specify the key, you might get duplicate keys. For example, you might have two dataset contents with the same ``scheduleTime`` but different ``versionId`` s. This means that one dataset content overwrites the other.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-s3destinationconfiguration.html#cfn-iotanalytics-dataset-s3destinationconfiguration-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def role_arn(self) -> builtins.str:
            '''The ARN of the role that grants AWS IoT Analytics permission to interact with your Amazon S3 and AWS Glue resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-s3destinationconfiguration.html#cfn-iotanalytics-dataset-s3destinationconfiguration-rolearn
            '''
            result = self._values.get("role_arn")
            assert result is not None, "Required property 'role_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def glue_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnDataset.GlueConfigurationProperty", _IResolvable_da3f097b]]:
            '''Configuration information for coordination with AWS Glue , a fully managed extract, transform and load (ETL) service.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-s3destinationconfiguration.html#cfn-iotanalytics-dataset-s3destinationconfiguration-glueconfiguration
            '''
            result = self._values.get("glue_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnDataset.GlueConfigurationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3DestinationConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.ScheduleProperty",
        jsii_struct_bases=[],
        name_mapping={"schedule_expression": "scheduleExpression"},
    )
    class ScheduleProperty:
        def __init__(self, *, schedule_expression: builtins.str) -> None:
            '''The schedule for when to trigger an update.

            :param schedule_expression: The expression that defines when to trigger an update. For more information, see `Schedule Expressions for Rules <https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html>`_ in the Amazon CloudWatch documentation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-schedule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                schedule_property = iotanalytics.CfnDataset.ScheduleProperty(
                    schedule_expression="scheduleExpression"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "schedule_expression": schedule_expression,
            }

        @builtins.property
        def schedule_expression(self) -> builtins.str:
            '''The expression that defines when to trigger an update.

            For more information, see `Schedule Expressions for Rules <https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html>`_ in the Amazon CloudWatch documentation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-schedule.html#cfn-iotanalytics-dataset-schedule-scheduleexpression
            '''
            result = self._values.get("schedule_expression")
            assert result is not None, "Required property 'schedule_expression' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScheduleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.TriggerProperty",
        jsii_struct_bases=[],
        name_mapping={
            "schedule": "schedule",
            "triggering_dataset": "triggeringDataset",
        },
    )
    class TriggerProperty:
        def __init__(
            self,
            *,
            schedule: typing.Optional[typing.Union["CfnDataset.ScheduleProperty", _IResolvable_da3f097b]] = None,
            triggering_dataset: typing.Optional[typing.Union["CfnDataset.TriggeringDatasetProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The "DatasetTrigger" that specifies when the data set is automatically updated.

            :param schedule: The "Schedule" when the trigger is initiated.
            :param triggering_dataset: Information about the data set whose content generation triggers the new data set content generation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-trigger.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                trigger_property = iotanalytics.CfnDataset.TriggerProperty(
                    schedule=iotanalytics.CfnDataset.ScheduleProperty(
                        schedule_expression="scheduleExpression"
                    ),
                    triggering_dataset=iotanalytics.CfnDataset.TriggeringDatasetProperty(
                        dataset_name="datasetName"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if schedule is not None:
                self._values["schedule"] = schedule
            if triggering_dataset is not None:
                self._values["triggering_dataset"] = triggering_dataset

        @builtins.property
        def schedule(
            self,
        ) -> typing.Optional[typing.Union["CfnDataset.ScheduleProperty", _IResolvable_da3f097b]]:
            '''The "Schedule" when the trigger is initiated.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-trigger.html#cfn-iotanalytics-dataset-trigger-schedule
            '''
            result = self._values.get("schedule")
            return typing.cast(typing.Optional[typing.Union["CfnDataset.ScheduleProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def triggering_dataset(
            self,
        ) -> typing.Optional[typing.Union["CfnDataset.TriggeringDatasetProperty", _IResolvable_da3f097b]]:
            '''Information about the data set whose content generation triggers the new data set content generation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-trigger.html#cfn-iotanalytics-dataset-trigger-triggeringdataset
            '''
            result = self._values.get("triggering_dataset")
            return typing.cast(typing.Optional[typing.Union["CfnDataset.TriggeringDatasetProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TriggerProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.TriggeringDatasetProperty",
        jsii_struct_bases=[],
        name_mapping={"dataset_name": "datasetName"},
    )
    class TriggeringDatasetProperty:
        def __init__(self, *, dataset_name: builtins.str) -> None:
            '''Information about the dataset whose content generation triggers the new dataset content generation.

            :param dataset_name: The name of the data set whose content generation triggers the new data set content generation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-triggeringdataset.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                triggering_dataset_property = iotanalytics.CfnDataset.TriggeringDatasetProperty(
                    dataset_name="datasetName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "dataset_name": dataset_name,
            }

        @builtins.property
        def dataset_name(self) -> builtins.str:
            '''The name of the data set whose content generation triggers the new data set content generation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-triggeringdataset.html#cfn-iotanalytics-dataset-triggeringdataset-datasetname
            '''
            result = self._values.get("dataset_name")
            assert result is not None, "Required property 'dataset_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TriggeringDatasetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.VariableProperty",
        jsii_struct_bases=[],
        name_mapping={
            "variable_name": "variableName",
            "dataset_content_version_value": "datasetContentVersionValue",
            "double_value": "doubleValue",
            "output_file_uri_value": "outputFileUriValue",
            "string_value": "stringValue",
        },
    )
    class VariableProperty:
        def __init__(
            self,
            *,
            variable_name: builtins.str,
            dataset_content_version_value: typing.Optional[typing.Union["CfnDataset.DatasetContentVersionValueProperty", _IResolvable_da3f097b]] = None,
            double_value: typing.Optional[jsii.Number] = None,
            output_file_uri_value: typing.Optional[typing.Union["CfnDataset.OutputFileUriValueProperty", _IResolvable_da3f097b]] = None,
            string_value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''An instance of a variable to be passed to the ``containerAction`` execution.

            Each variable must have a name and a value given by one of ``stringValue`` , ``datasetContentVersionValue`` , or ``outputFileUriValue`` .

            :param variable_name: The name of the variable.
            :param dataset_content_version_value: The value of the variable as a structure that specifies a dataset content version.
            :param double_value: The value of the variable as a double (numeric).
            :param output_file_uri_value: The value of the variable as a structure that specifies an output file URI.
            :param string_value: The value of the variable as a string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-variable.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                variable_property = iotanalytics.CfnDataset.VariableProperty(
                    variable_name="variableName",
                
                    # the properties below are optional
                    dataset_content_version_value=iotanalytics.CfnDataset.DatasetContentVersionValueProperty(
                        dataset_name="datasetName"
                    ),
                    double_value=123,
                    output_file_uri_value=iotanalytics.CfnDataset.OutputFileUriValueProperty(
                        file_name="fileName"
                    ),
                    string_value="stringValue"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "variable_name": variable_name,
            }
            if dataset_content_version_value is not None:
                self._values["dataset_content_version_value"] = dataset_content_version_value
            if double_value is not None:
                self._values["double_value"] = double_value
            if output_file_uri_value is not None:
                self._values["output_file_uri_value"] = output_file_uri_value
            if string_value is not None:
                self._values["string_value"] = string_value

        @builtins.property
        def variable_name(self) -> builtins.str:
            '''The name of the variable.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-variable.html#cfn-iotanalytics-dataset-variable-variablename
            '''
            result = self._values.get("variable_name")
            assert result is not None, "Required property 'variable_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def dataset_content_version_value(
            self,
        ) -> typing.Optional[typing.Union["CfnDataset.DatasetContentVersionValueProperty", _IResolvable_da3f097b]]:
            '''The value of the variable as a structure that specifies a dataset content version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-variable.html#cfn-iotanalytics-dataset-variable-datasetcontentversionvalue
            '''
            result = self._values.get("dataset_content_version_value")
            return typing.cast(typing.Optional[typing.Union["CfnDataset.DatasetContentVersionValueProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def double_value(self) -> typing.Optional[jsii.Number]:
            '''The value of the variable as a double (numeric).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-variable.html#cfn-iotanalytics-dataset-variable-doublevalue
            '''
            result = self._values.get("double_value")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def output_file_uri_value(
            self,
        ) -> typing.Optional[typing.Union["CfnDataset.OutputFileUriValueProperty", _IResolvable_da3f097b]]:
            '''The value of the variable as a structure that specifies an output file URI.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-variable.html#cfn-iotanalytics-dataset-variable-outputfileurivalue
            '''
            result = self._values.get("output_file_uri_value")
            return typing.cast(typing.Optional[typing.Union["CfnDataset.OutputFileUriValueProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def string_value(self) -> typing.Optional[builtins.str]:
            '''The value of the variable as a string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-variable.html#cfn-iotanalytics-dataset-variable-stringvalue
            '''
            result = self._values.get("string_value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VariableProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDataset.VersioningConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"max_versions": "maxVersions", "unlimited": "unlimited"},
    )
    class VersioningConfigurationProperty:
        def __init__(
            self,
            *,
            max_versions: typing.Optional[jsii.Number] = None,
            unlimited: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Information about the versioning of dataset contents.

            :param max_versions: How many versions of dataset contents are kept. The ``unlimited`` parameter must be ``false`` .
            :param unlimited: If true, unlimited versions of dataset contents are kept.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-versioningconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                versioning_configuration_property = iotanalytics.CfnDataset.VersioningConfigurationProperty(
                    max_versions=123,
                    unlimited=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max_versions is not None:
                self._values["max_versions"] = max_versions
            if unlimited is not None:
                self._values["unlimited"] = unlimited

        @builtins.property
        def max_versions(self) -> typing.Optional[jsii.Number]:
            '''How many versions of dataset contents are kept.

            The ``unlimited`` parameter must be ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-versioningconfiguration.html#cfn-iotanalytics-dataset-versioningconfiguration-maxversions
            '''
            result = self._values.get("max_versions")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def unlimited(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If true, unlimited versions of dataset contents are kept.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-dataset-versioningconfiguration.html#cfn-iotanalytics-dataset-versioningconfiguration-unlimited
            '''
            result = self._values.get("unlimited")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VersioningConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatasetProps",
    jsii_struct_bases=[],
    name_mapping={
        "actions": "actions",
        "content_delivery_rules": "contentDeliveryRules",
        "dataset_name": "datasetName",
        "late_data_rules": "lateDataRules",
        "retention_period": "retentionPeriod",
        "tags": "tags",
        "triggers": "triggers",
        "versioning_configuration": "versioningConfiguration",
    },
)
class CfnDatasetProps:
    def __init__(
        self,
        *,
        actions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnDataset.ActionProperty, _IResolvable_da3f097b]]],
        content_delivery_rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnDataset.DatasetContentDeliveryRuleProperty, _IResolvable_da3f097b]]]] = None,
        dataset_name: typing.Optional[builtins.str] = None,
        late_data_rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnDataset.LateDataRuleProperty, _IResolvable_da3f097b]]]] = None,
        retention_period: typing.Optional[typing.Union[CfnDataset.RetentionPeriodProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        triggers: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnDataset.TriggerProperty, _IResolvable_da3f097b]]]] = None,
        versioning_configuration: typing.Optional[typing.Union[CfnDataset.VersioningConfigurationProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDataset``.

        :param actions: The ``DatasetAction`` objects that automatically create the dataset contents.
        :param content_delivery_rules: When dataset contents are created they are delivered to destinations specified here.
        :param dataset_name: The name of the dataset.
        :param late_data_rules: A list of data rules that send notifications to CloudWatch, when data arrives late. To specify ``lateDataRules`` , the dataset must use a `DeltaTimer <https://docs.aws.amazon.com/iotanalytics/latest/APIReference/API_DeltaTime.html>`_ filter.
        :param retention_period: Optional. How long, in days, message data is kept for the dataset.
        :param tags: Metadata which can be used to manage the data set. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        :param triggers: The ``DatasetTrigger`` objects that specify when the dataset is automatically updated.
        :param versioning_configuration: Optional. How many versions of dataset contents are kept. If not specified or set to null, only the latest version plus the latest succeeded version (if they are different) are kept for the time period specified by the ``retentionPeriod`` parameter. For more information, see `Keeping Multiple Versions of AWS IoT Analytics datasets <https://docs.aws.amazon.com/iotanalytics/latest/userguide/getting-started.html#aws-iot-analytics-dataset-versions>`_ in the *AWS IoT Analytics User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotanalytics as iotanalytics
            
            cfn_dataset_props = iotanalytics.CfnDatasetProps(
                actions=[iotanalytics.CfnDataset.ActionProperty(
                    action_name="actionName",
            
                    # the properties below are optional
                    container_action=iotanalytics.CfnDataset.ContainerActionProperty(
                        execution_role_arn="executionRoleArn",
                        image="image",
                        resource_configuration=iotanalytics.CfnDataset.ResourceConfigurationProperty(
                            compute_type="computeType",
                            volume_size_in_gb=123
                        ),
            
                        # the properties below are optional
                        variables=[iotanalytics.CfnDataset.VariableProperty(
                            variable_name="variableName",
            
                            # the properties below are optional
                            dataset_content_version_value=iotanalytics.CfnDataset.DatasetContentVersionValueProperty(
                                dataset_name="datasetName"
                            ),
                            double_value=123,
                            output_file_uri_value=iotanalytics.CfnDataset.OutputFileUriValueProperty(
                                file_name="fileName"
                            ),
                            string_value="stringValue"
                        )]
                    ),
                    query_action=iotanalytics.CfnDataset.QueryActionProperty(
                        sql_query="sqlQuery",
            
                        # the properties below are optional
                        filters=[iotanalytics.CfnDataset.FilterProperty(
                            delta_time=iotanalytics.CfnDataset.DeltaTimeProperty(
                                offset_seconds=123,
                                time_expression="timeExpression"
                            )
                        )]
                    )
                )],
            
                # the properties below are optional
                content_delivery_rules=[iotanalytics.CfnDataset.DatasetContentDeliveryRuleProperty(
                    destination=iotanalytics.CfnDataset.DatasetContentDeliveryRuleDestinationProperty(
                        iot_events_destination_configuration=iotanalytics.CfnDataset.IotEventsDestinationConfigurationProperty(
                            input_name="inputName",
                            role_arn="roleArn"
                        ),
                        s3_destination_configuration=iotanalytics.CfnDataset.S3DestinationConfigurationProperty(
                            bucket="bucket",
                            key="key",
                            role_arn="roleArn",
            
                            # the properties below are optional
                            glue_configuration=iotanalytics.CfnDataset.GlueConfigurationProperty(
                                database_name="databaseName",
                                table_name="tableName"
                            )
                        )
                    ),
            
                    # the properties below are optional
                    entry_name="entryName"
                )],
                dataset_name="datasetName",
                late_data_rules=[iotanalytics.CfnDataset.LateDataRuleProperty(
                    rule_configuration=iotanalytics.CfnDataset.LateDataRuleConfigurationProperty(
                        delta_time_session_window_configuration=iotanalytics.CfnDataset.DeltaTimeSessionWindowConfigurationProperty(
                            timeout_in_minutes=123
                        )
                    ),
            
                    # the properties below are optional
                    rule_name="ruleName"
                )],
                retention_period=iotanalytics.CfnDataset.RetentionPeriodProperty(
                    number_of_days=123,
                    unlimited=False
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                triggers=[iotanalytics.CfnDataset.TriggerProperty(
                    schedule=iotanalytics.CfnDataset.ScheduleProperty(
                        schedule_expression="scheduleExpression"
                    ),
                    triggering_dataset=iotanalytics.CfnDataset.TriggeringDatasetProperty(
                        dataset_name="datasetName"
                    )
                )],
                versioning_configuration=iotanalytics.CfnDataset.VersioningConfigurationProperty(
                    max_versions=123,
                    unlimited=False
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "actions": actions,
        }
        if content_delivery_rules is not None:
            self._values["content_delivery_rules"] = content_delivery_rules
        if dataset_name is not None:
            self._values["dataset_name"] = dataset_name
        if late_data_rules is not None:
            self._values["late_data_rules"] = late_data_rules
        if retention_period is not None:
            self._values["retention_period"] = retention_period
        if tags is not None:
            self._values["tags"] = tags
        if triggers is not None:
            self._values["triggers"] = triggers
        if versioning_configuration is not None:
            self._values["versioning_configuration"] = versioning_configuration

    @builtins.property
    def actions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataset.ActionProperty, _IResolvable_da3f097b]]]:
        '''The ``DatasetAction`` objects that automatically create the dataset contents.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-actions
        '''
        result = self._values.get("actions")
        assert result is not None, "Required property 'actions' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataset.ActionProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def content_delivery_rules(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataset.DatasetContentDeliveryRuleProperty, _IResolvable_da3f097b]]]]:
        '''When dataset contents are created they are delivered to destinations specified here.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-contentdeliveryrules
        '''
        result = self._values.get("content_delivery_rules")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataset.DatasetContentDeliveryRuleProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def dataset_name(self) -> typing.Optional[builtins.str]:
        '''The name of the dataset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-datasetname
        '''
        result = self._values.get("dataset_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def late_data_rules(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataset.LateDataRuleProperty, _IResolvable_da3f097b]]]]:
        '''A list of data rules that send notifications to CloudWatch, when data arrives late.

        To specify ``lateDataRules`` , the dataset must use a `DeltaTimer <https://docs.aws.amazon.com/iotanalytics/latest/APIReference/API_DeltaTime.html>`_ filter.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-latedatarules
        '''
        result = self._values.get("late_data_rules")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataset.LateDataRuleProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def retention_period(
        self,
    ) -> typing.Optional[typing.Union[CfnDataset.RetentionPeriodProperty, _IResolvable_da3f097b]]:
        '''Optional.

        How long, in days, message data is kept for the dataset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-retentionperiod
        '''
        result = self._values.get("retention_period")
        return typing.cast(typing.Optional[typing.Union[CfnDataset.RetentionPeriodProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Metadata which can be used to manage the data set.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def triggers(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataset.TriggerProperty, _IResolvable_da3f097b]]]]:
        '''The ``DatasetTrigger`` objects that specify when the dataset is automatically updated.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-triggers
        '''
        result = self._values.get("triggers")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataset.TriggerProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def versioning_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnDataset.VersioningConfigurationProperty, _IResolvable_da3f097b]]:
        '''Optional.

        How many versions of dataset contents are kept. If not specified or set to null, only the latest version plus the latest succeeded version (if they are different) are kept for the time period specified by the ``retentionPeriod`` parameter. For more information, see `Keeping Multiple Versions of AWS IoT Analytics datasets <https://docs.aws.amazon.com/iotanalytics/latest/userguide/getting-started.html#aws-iot-analytics-dataset-versions>`_ in the *AWS IoT Analytics User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-dataset.html#cfn-iotanalytics-dataset-versioningconfiguration
        '''
        result = self._values.get("versioning_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnDataset.VersioningConfigurationProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDatasetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDatastore(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastore",
):
    '''A CloudFormation ``AWS::IoTAnalytics::Datastore``.

    AWS::IoTAnalytics::Datastore resource is a repository for messages. For more information, see `How to Use AWS IoT Analytics <https://docs.aws.amazon.com/iotanalytics/latest/userguide/welcome.html#aws-iot-analytics-how>`_ in the *AWS IoT Analytics User Guide* .

    :cloudformationResource: AWS::IoTAnalytics::Datastore
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-datastore.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotanalytics as iotanalytics
        
        # json_configuration: Any
        # service_managed_s3: Any
        
        cfn_datastore = iotanalytics.CfnDatastore(self, "MyCfnDatastore",
            datastore_name="datastoreName",
            datastore_partitions=iotanalytics.CfnDatastore.DatastorePartitionsProperty(
                partitions=[iotanalytics.CfnDatastore.DatastorePartitionProperty(
                    partition=iotanalytics.CfnDatastore.PartitionProperty(
                        attribute_name="attributeName"
                    ),
                    timestamp_partition=iotanalytics.CfnDatastore.TimestampPartitionProperty(
                        attribute_name="attributeName",
        
                        # the properties below are optional
                        timestamp_format="timestampFormat"
                    )
                )]
            ),
            datastore_storage=iotanalytics.CfnDatastore.DatastoreStorageProperty(
                customer_managed_s3=iotanalytics.CfnDatastore.CustomerManagedS3Property(
                    bucket="bucket",
                    role_arn="roleArn",
        
                    # the properties below are optional
                    key_prefix="keyPrefix"
                ),
                iot_site_wise_multi_layer_storage=iotanalytics.CfnDatastore.IotSiteWiseMultiLayerStorageProperty(
                    customer_managed_s3_storage=iotanalytics.CfnDatastore.CustomerManagedS3StorageProperty(
                        bucket="bucket",
        
                        # the properties below are optional
                        key_prefix="keyPrefix"
                    )
                ),
                service_managed_s3=service_managed_s3
            ),
            file_format_configuration=iotanalytics.CfnDatastore.FileFormatConfigurationProperty(
                json_configuration=json_configuration,
                parquet_configuration=iotanalytics.CfnDatastore.ParquetConfigurationProperty(
                    schema_definition=iotanalytics.CfnDatastore.SchemaDefinitionProperty(
                        columns=[iotanalytics.CfnDatastore.ColumnProperty(
                            name="name",
                            type="type"
                        )]
                    )
                )
            ),
            retention_period=iotanalytics.CfnDatastore.RetentionPeriodProperty(
                number_of_days=123,
                unlimited=False
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
        id: builtins.str,
        *,
        datastore_name: typing.Optional[builtins.str] = None,
        datastore_partitions: typing.Optional[typing.Union["CfnDatastore.DatastorePartitionsProperty", _IResolvable_da3f097b]] = None,
        datastore_storage: typing.Optional[typing.Union["CfnDatastore.DatastoreStorageProperty", _IResolvable_da3f097b]] = None,
        file_format_configuration: typing.Optional[typing.Union["CfnDatastore.FileFormatConfigurationProperty", _IResolvable_da3f097b]] = None,
        retention_period: typing.Optional[typing.Union["CfnDatastore.RetentionPeriodProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::IoTAnalytics::Datastore``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param datastore_name: The name of the data store.
        :param datastore_partitions: Information about the partition dimensions in a data store.
        :param datastore_storage: Where data store data is stored.
        :param file_format_configuration: Contains the configuration information of file formats. AWS IoT Analytics data stores support JSON and `Parquet <https://docs.aws.amazon.com/https://parquet.apache.org/>`_ . The default file format is JSON. You can specify only one format. You can't change the file format after you create the data store.
        :param retention_period: How long, in days, message data is kept for the data store. When ``customerManagedS3`` storage is selected, this parameter is ignored.
        :param tags: Metadata which can be used to manage the data store. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnDatastoreProps(
            datastore_name=datastore_name,
            datastore_partitions=datastore_partitions,
            datastore_storage=datastore_storage,
            file_format_configuration=file_format_configuration,
            retention_period=retention_period,
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
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''
        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Metadata which can be used to manage the data store.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-datastore.html#cfn-iotanalytics-datastore-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="datastoreName")
    def datastore_name(self) -> typing.Optional[builtins.str]:
        '''The name of the data store.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-datastore.html#cfn-iotanalytics-datastore-datastorename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "datastoreName"))

    @datastore_name.setter
    def datastore_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "datastoreName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="datastorePartitions")
    def datastore_partitions(
        self,
    ) -> typing.Optional[typing.Union["CfnDatastore.DatastorePartitionsProperty", _IResolvable_da3f097b]]:
        '''Information about the partition dimensions in a data store.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-datastore.html#cfn-iotanalytics-datastore-datastorepartitions
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDatastore.DatastorePartitionsProperty", _IResolvable_da3f097b]], jsii.get(self, "datastorePartitions"))

    @datastore_partitions.setter
    def datastore_partitions(
        self,
        value: typing.Optional[typing.Union["CfnDatastore.DatastorePartitionsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "datastorePartitions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="datastoreStorage")
    def datastore_storage(
        self,
    ) -> typing.Optional[typing.Union["CfnDatastore.DatastoreStorageProperty", _IResolvable_da3f097b]]:
        '''Where data store data is stored.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-datastore.html#cfn-iotanalytics-datastore-datastorestorage
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDatastore.DatastoreStorageProperty", _IResolvable_da3f097b]], jsii.get(self, "datastoreStorage"))

    @datastore_storage.setter
    def datastore_storage(
        self,
        value: typing.Optional[typing.Union["CfnDatastore.DatastoreStorageProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "datastoreStorage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fileFormatConfiguration")
    def file_format_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnDatastore.FileFormatConfigurationProperty", _IResolvable_da3f097b]]:
        '''Contains the configuration information of file formats. AWS IoT Analytics data stores support JSON and `Parquet <https://docs.aws.amazon.com/https://parquet.apache.org/>`_ .

        The default file format is JSON. You can specify only one format.

        You can't change the file format after you create the data store.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-datastore.html#cfn-iotanalytics-datastore-fileformatconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDatastore.FileFormatConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "fileFormatConfiguration"))

    @file_format_configuration.setter
    def file_format_configuration(
        self,
        value: typing.Optional[typing.Union["CfnDatastore.FileFormatConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "fileFormatConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="retentionPeriod")
    def retention_period(
        self,
    ) -> typing.Optional[typing.Union["CfnDatastore.RetentionPeriodProperty", _IResolvable_da3f097b]]:
        '''How long, in days, message data is kept for the data store.

        When ``customerManagedS3`` storage is selected, this parameter is ignored.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-datastore.html#cfn-iotanalytics-datastore-retentionperiod
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDatastore.RetentionPeriodProperty", _IResolvable_da3f097b]], jsii.get(self, "retentionPeriod"))

    @retention_period.setter
    def retention_period(
        self,
        value: typing.Optional[typing.Union["CfnDatastore.RetentionPeriodProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "retentionPeriod", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastore.ColumnProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "type": "type"},
    )
    class ColumnProperty:
        def __init__(self, *, name: builtins.str, type: builtins.str) -> None:
            '''Contains information about a column that stores your data.

            :param name: The name of the column.
            :param type: The type of data. For more information about the supported data types, see `Common data types <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-common.html>`_ in the *AWS Glue Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-column.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                column_property = iotanalytics.CfnDatastore.ColumnProperty(
                    name="name",
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "type": type,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-column.html#cfn-iotanalytics-datastore-column-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def type(self) -> builtins.str:
            '''The type of data.

            For more information about the supported data types, see `Common data types <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-common.html>`_ in the *AWS Glue Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-column.html#cfn-iotanalytics-datastore-column-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ColumnProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastore.CustomerManagedS3Property",
        jsii_struct_bases=[],
        name_mapping={
            "bucket": "bucket",
            "role_arn": "roleArn",
            "key_prefix": "keyPrefix",
        },
    )
    class CustomerManagedS3Property:
        def __init__(
            self,
            *,
            bucket: builtins.str,
            role_arn: builtins.str,
            key_prefix: typing.Optional[builtins.str] = None,
        ) -> None:
            '''S3-customer-managed;

            When you choose customer-managed storage, the ``retentionPeriod`` parameter is ignored. You can't change the choice of Amazon S3 storage after your data store is created.

            :param bucket: The name of the Amazon S3 bucket where your data is stored.
            :param role_arn: The ARN of the role that grants AWS IoT Analytics permission to interact with your Amazon S3 resources.
            :param key_prefix: (Optional) The prefix used to create the keys of the data store data objects. Each object in an Amazon S3 bucket has a key that is its unique identifier in the bucket. Each object in a bucket has exactly one key. The prefix must end with a forward slash (/).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-customermanageds3.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                customer_managed_s3_property = iotanalytics.CfnDatastore.CustomerManagedS3Property(
                    bucket="bucket",
                    role_arn="roleArn",
                
                    # the properties below are optional
                    key_prefix="keyPrefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket": bucket,
                "role_arn": role_arn,
            }
            if key_prefix is not None:
                self._values["key_prefix"] = key_prefix

        @builtins.property
        def bucket(self) -> builtins.str:
            '''The name of the Amazon S3 bucket where your data is stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-customermanageds3.html#cfn-iotanalytics-datastore-customermanageds3-bucket
            '''
            result = self._values.get("bucket")
            assert result is not None, "Required property 'bucket' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def role_arn(self) -> builtins.str:
            '''The ARN of the role that grants AWS IoT Analytics permission to interact with your Amazon S3 resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-customermanageds3.html#cfn-iotanalytics-datastore-customermanageds3-rolearn
            '''
            result = self._values.get("role_arn")
            assert result is not None, "Required property 'role_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def key_prefix(self) -> typing.Optional[builtins.str]:
            '''(Optional) The prefix used to create the keys of the data store data objects.

            Each object in an Amazon S3 bucket has a key that is its unique identifier in the bucket. Each object in a bucket has exactly one key. The prefix must end with a forward slash (/).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-customermanageds3.html#cfn-iotanalytics-datastore-customermanageds3-keyprefix
            '''
            result = self._values.get("key_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomerManagedS3Property(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastore.CustomerManagedS3StorageProperty",
        jsii_struct_bases=[],
        name_mapping={"bucket": "bucket", "key_prefix": "keyPrefix"},
    )
    class CustomerManagedS3StorageProperty:
        def __init__(
            self,
            *,
            bucket: builtins.str,
            key_prefix: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Amazon S3 -customer-managed;

            When you choose customer-managed storage, the ``retentionPeriod`` parameter is ignored. You can't change the choice of Amazon S3 storage after your data store is created.

            :param bucket: The name of the Amazon S3 bucket where your data is stored.
            :param key_prefix: (Optional) The prefix used to create the keys of the data store data objects. Each object in an Amazon S3 bucket has a key that is its unique identifier in the bucket. Each object in a bucket has exactly one key. The prefix must end with a forward slash (/).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-customermanageds3storage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                customer_managed_s3_storage_property = iotanalytics.CfnDatastore.CustomerManagedS3StorageProperty(
                    bucket="bucket",
                
                    # the properties below are optional
                    key_prefix="keyPrefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket": bucket,
            }
            if key_prefix is not None:
                self._values["key_prefix"] = key_prefix

        @builtins.property
        def bucket(self) -> builtins.str:
            '''The name of the Amazon S3 bucket where your data is stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-customermanageds3storage.html#cfn-iotanalytics-datastore-customermanageds3storage-bucket
            '''
            result = self._values.get("bucket")
            assert result is not None, "Required property 'bucket' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def key_prefix(self) -> typing.Optional[builtins.str]:
            '''(Optional) The prefix used to create the keys of the data store data objects.

            Each object in an Amazon S3 bucket has a key that is its unique identifier in the bucket. Each object in a bucket has exactly one key. The prefix must end with a forward slash (/).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-customermanageds3storage.html#cfn-iotanalytics-datastore-customermanageds3storage-keyprefix
            '''
            result = self._values.get("key_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomerManagedS3StorageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastore.DatastorePartitionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "partition": "partition",
            "timestamp_partition": "timestampPartition",
        },
    )
    class DatastorePartitionProperty:
        def __init__(
            self,
            *,
            partition: typing.Optional[typing.Union["CfnDatastore.PartitionProperty", _IResolvable_da3f097b]] = None,
            timestamp_partition: typing.Optional[typing.Union["CfnDatastore.TimestampPartitionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A single dimension to partition a data store.

            The dimension must be an ``AttributePartition`` or a ``TimestampPartition`` .

            :param partition: A partition dimension defined by an attribute.
            :param timestamp_partition: A partition dimension defined by a timestamp attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-datastorepartition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                datastore_partition_property = iotanalytics.CfnDatastore.DatastorePartitionProperty(
                    partition=iotanalytics.CfnDatastore.PartitionProperty(
                        attribute_name="attributeName"
                    ),
                    timestamp_partition=iotanalytics.CfnDatastore.TimestampPartitionProperty(
                        attribute_name="attributeName",
                
                        # the properties below are optional
                        timestamp_format="timestampFormat"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if partition is not None:
                self._values["partition"] = partition
            if timestamp_partition is not None:
                self._values["timestamp_partition"] = timestamp_partition

        @builtins.property
        def partition(
            self,
        ) -> typing.Optional[typing.Union["CfnDatastore.PartitionProperty", _IResolvable_da3f097b]]:
            '''A partition dimension defined by an attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-datastorepartition.html#cfn-iotanalytics-datastore-datastorepartition-partition
            '''
            result = self._values.get("partition")
            return typing.cast(typing.Optional[typing.Union["CfnDatastore.PartitionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def timestamp_partition(
            self,
        ) -> typing.Optional[typing.Union["CfnDatastore.TimestampPartitionProperty", _IResolvable_da3f097b]]:
            '''A partition dimension defined by a timestamp attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-datastorepartition.html#cfn-iotanalytics-datastore-datastorepartition-timestamppartition
            '''
            result = self._values.get("timestamp_partition")
            return typing.cast(typing.Optional[typing.Union["CfnDatastore.TimestampPartitionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DatastorePartitionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastore.DatastorePartitionsProperty",
        jsii_struct_bases=[],
        name_mapping={"partitions": "partitions"},
    )
    class DatastorePartitionsProperty:
        def __init__(
            self,
            *,
            partitions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDatastore.DatastorePartitionProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Information about the partition dimensions in a data store.

            :param partitions: A list of partition dimensions in a data store.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-datastorepartitions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                datastore_partitions_property = iotanalytics.CfnDatastore.DatastorePartitionsProperty(
                    partitions=[iotanalytics.CfnDatastore.DatastorePartitionProperty(
                        partition=iotanalytics.CfnDatastore.PartitionProperty(
                            attribute_name="attributeName"
                        ),
                        timestamp_partition=iotanalytics.CfnDatastore.TimestampPartitionProperty(
                            attribute_name="attributeName",
                
                            # the properties below are optional
                            timestamp_format="timestampFormat"
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if partitions is not None:
                self._values["partitions"] = partitions

        @builtins.property
        def partitions(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDatastore.DatastorePartitionProperty", _IResolvable_da3f097b]]]]:
            '''A list of partition dimensions in a data store.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-datastorepartitions.html#cfn-iotanalytics-datastore-datastorepartitions-partitions
            '''
            result = self._values.get("partitions")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDatastore.DatastorePartitionProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DatastorePartitionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastore.DatastoreStorageProperty",
        jsii_struct_bases=[],
        name_mapping={
            "customer_managed_s3": "customerManagedS3",
            "iot_site_wise_multi_layer_storage": "iotSiteWiseMultiLayerStorage",
            "service_managed_s3": "serviceManagedS3",
        },
    )
    class DatastoreStorageProperty:
        def __init__(
            self,
            *,
            customer_managed_s3: typing.Optional[typing.Union["CfnDatastore.CustomerManagedS3Property", _IResolvable_da3f097b]] = None,
            iot_site_wise_multi_layer_storage: typing.Optional[typing.Union["CfnDatastore.IotSiteWiseMultiLayerStorageProperty", _IResolvable_da3f097b]] = None,
            service_managed_s3: typing.Any = None,
        ) -> None:
            '''Where data store data is stored.

            :param customer_managed_s3: Use this to store data store data in an S3 bucket that you manage. The choice of service-managed or customer-managed S3 storage cannot be changed after creation of the data store.
            :param iot_site_wise_multi_layer_storage: Use this to store data used by AWS IoT SiteWise in an Amazon S3 bucket that you manage. You can't change the choice of Amazon S3 storage after your data store is created.
            :param service_managed_s3: Use this to store data store data in an S3 bucket managed by the AWS IoT Analytics service. The choice of service-managed or customer-managed S3 storage cannot be changed after creation of the data store.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-datastorestorage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                # service_managed_s3: Any
                
                datastore_storage_property = iotanalytics.CfnDatastore.DatastoreStorageProperty(
                    customer_managed_s3=iotanalytics.CfnDatastore.CustomerManagedS3Property(
                        bucket="bucket",
                        role_arn="roleArn",
                
                        # the properties below are optional
                        key_prefix="keyPrefix"
                    ),
                    iot_site_wise_multi_layer_storage=iotanalytics.CfnDatastore.IotSiteWiseMultiLayerStorageProperty(
                        customer_managed_s3_storage=iotanalytics.CfnDatastore.CustomerManagedS3StorageProperty(
                            bucket="bucket",
                
                            # the properties below are optional
                            key_prefix="keyPrefix"
                        )
                    ),
                    service_managed_s3=service_managed_s3
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if customer_managed_s3 is not None:
                self._values["customer_managed_s3"] = customer_managed_s3
            if iot_site_wise_multi_layer_storage is not None:
                self._values["iot_site_wise_multi_layer_storage"] = iot_site_wise_multi_layer_storage
            if service_managed_s3 is not None:
                self._values["service_managed_s3"] = service_managed_s3

        @builtins.property
        def customer_managed_s3(
            self,
        ) -> typing.Optional[typing.Union["CfnDatastore.CustomerManagedS3Property", _IResolvable_da3f097b]]:
            '''Use this to store data store data in an S3 bucket that you manage.

            The choice of service-managed or customer-managed S3 storage cannot be changed after creation of the data store.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-datastorestorage.html#cfn-iotanalytics-datastore-datastorestorage-customermanageds3
            '''
            result = self._values.get("customer_managed_s3")
            return typing.cast(typing.Optional[typing.Union["CfnDatastore.CustomerManagedS3Property", _IResolvable_da3f097b]], result)

        @builtins.property
        def iot_site_wise_multi_layer_storage(
            self,
        ) -> typing.Optional[typing.Union["CfnDatastore.IotSiteWiseMultiLayerStorageProperty", _IResolvable_da3f097b]]:
            '''Use this to store data used by AWS IoT SiteWise in an Amazon S3 bucket that you manage.

            You can't change the choice of Amazon S3 storage after your data store is created.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-datastorestorage.html#cfn-iotanalytics-datastore-datastorestorage-iotsitewisemultilayerstorage
            '''
            result = self._values.get("iot_site_wise_multi_layer_storage")
            return typing.cast(typing.Optional[typing.Union["CfnDatastore.IotSiteWiseMultiLayerStorageProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def service_managed_s3(self) -> typing.Any:
            '''Use this to store data store data in an S3 bucket managed by the AWS IoT Analytics service.

            The choice of service-managed or customer-managed S3 storage cannot be changed after creation of the data store.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-datastorestorage.html#cfn-iotanalytics-datastore-datastorestorage-servicemanageds3
            '''
            result = self._values.get("service_managed_s3")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DatastoreStorageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastore.FileFormatConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "json_configuration": "jsonConfiguration",
            "parquet_configuration": "parquetConfiguration",
        },
    )
    class FileFormatConfigurationProperty:
        def __init__(
            self,
            *,
            json_configuration: typing.Any = None,
            parquet_configuration: typing.Optional[typing.Union["CfnDatastore.ParquetConfigurationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Contains the configuration information of file formats. AWS IoT Analytics data stores support JSON and `Parquet <https://docs.aws.amazon.com/https://parquet.apache.org/>`_ .

            The default file format is JSON. You can specify only one format.

            You can't change the file format after you create the data store.

            :param json_configuration: Contains the configuration information of the JSON format.
            :param parquet_configuration: Contains the configuration information of the Parquet format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-fileformatconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                # json_configuration: Any
                
                file_format_configuration_property = iotanalytics.CfnDatastore.FileFormatConfigurationProperty(
                    json_configuration=json_configuration,
                    parquet_configuration=iotanalytics.CfnDatastore.ParquetConfigurationProperty(
                        schema_definition=iotanalytics.CfnDatastore.SchemaDefinitionProperty(
                            columns=[iotanalytics.CfnDatastore.ColumnProperty(
                                name="name",
                                type="type"
                            )]
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if json_configuration is not None:
                self._values["json_configuration"] = json_configuration
            if parquet_configuration is not None:
                self._values["parquet_configuration"] = parquet_configuration

        @builtins.property
        def json_configuration(self) -> typing.Any:
            '''Contains the configuration information of the JSON format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-fileformatconfiguration.html#cfn-iotanalytics-datastore-fileformatconfiguration-jsonconfiguration
            '''
            result = self._values.get("json_configuration")
            return typing.cast(typing.Any, result)

        @builtins.property
        def parquet_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnDatastore.ParquetConfigurationProperty", _IResolvable_da3f097b]]:
            '''Contains the configuration information of the Parquet format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-fileformatconfiguration.html#cfn-iotanalytics-datastore-fileformatconfiguration-parquetconfiguration
            '''
            result = self._values.get("parquet_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnDatastore.ParquetConfigurationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FileFormatConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastore.IotSiteWiseMultiLayerStorageProperty",
        jsii_struct_bases=[],
        name_mapping={"customer_managed_s3_storage": "customerManagedS3Storage"},
    )
    class IotSiteWiseMultiLayerStorageProperty:
        def __init__(
            self,
            *,
            customer_managed_s3_storage: typing.Optional[typing.Union["CfnDatastore.CustomerManagedS3StorageProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Stores data used by AWS IoT SiteWise in an Amazon S3 bucket that you manage.

            You can't change the choice of Amazon S3 storage after your data store is created.

            :param customer_managed_s3_storage: Stores data used by AWS IoT SiteWise in an Amazon S3 bucket that you manage.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-iotsitewisemultilayerstorage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                iot_site_wise_multi_layer_storage_property = iotanalytics.CfnDatastore.IotSiteWiseMultiLayerStorageProperty(
                    customer_managed_s3_storage=iotanalytics.CfnDatastore.CustomerManagedS3StorageProperty(
                        bucket="bucket",
                
                        # the properties below are optional
                        key_prefix="keyPrefix"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if customer_managed_s3_storage is not None:
                self._values["customer_managed_s3_storage"] = customer_managed_s3_storage

        @builtins.property
        def customer_managed_s3_storage(
            self,
        ) -> typing.Optional[typing.Union["CfnDatastore.CustomerManagedS3StorageProperty", _IResolvable_da3f097b]]:
            '''Stores data used by AWS IoT SiteWise in an Amazon S3 bucket that you manage.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-iotsitewisemultilayerstorage.html#cfn-iotanalytics-datastore-iotsitewisemultilayerstorage-customermanageds3storage
            '''
            result = self._values.get("customer_managed_s3_storage")
            return typing.cast(typing.Optional[typing.Union["CfnDatastore.CustomerManagedS3StorageProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IotSiteWiseMultiLayerStorageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastore.ParquetConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"schema_definition": "schemaDefinition"},
    )
    class ParquetConfigurationProperty:
        def __init__(
            self,
            *,
            schema_definition: typing.Optional[typing.Union["CfnDatastore.SchemaDefinitionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Contains the configuration information of the Parquet format.

            :param schema_definition: Information needed to define a schema.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-parquetconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                parquet_configuration_property = iotanalytics.CfnDatastore.ParquetConfigurationProperty(
                    schema_definition=iotanalytics.CfnDatastore.SchemaDefinitionProperty(
                        columns=[iotanalytics.CfnDatastore.ColumnProperty(
                            name="name",
                            type="type"
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if schema_definition is not None:
                self._values["schema_definition"] = schema_definition

        @builtins.property
        def schema_definition(
            self,
        ) -> typing.Optional[typing.Union["CfnDatastore.SchemaDefinitionProperty", _IResolvable_da3f097b]]:
            '''Information needed to define a schema.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-parquetconfiguration.html#cfn-iotanalytics-datastore-parquetconfiguration-schemadefinition
            '''
            result = self._values.get("schema_definition")
            return typing.cast(typing.Optional[typing.Union["CfnDatastore.SchemaDefinitionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ParquetConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastore.PartitionProperty",
        jsii_struct_bases=[],
        name_mapping={"attribute_name": "attributeName"},
    )
    class PartitionProperty:
        def __init__(self, *, attribute_name: builtins.str) -> None:
            '''A single dimension to partition a data store.

            The dimension must be an ``AttributePartition`` or a ``TimestampPartition`` .

            :param attribute_name: The name of the attribute that defines a partition dimension.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-partition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                partition_property = iotanalytics.CfnDatastore.PartitionProperty(
                    attribute_name="attributeName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "attribute_name": attribute_name,
            }

        @builtins.property
        def attribute_name(self) -> builtins.str:
            '''The name of the attribute that defines a partition dimension.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-partition.html#cfn-iotanalytics-datastore-partition-attributename
            '''
            result = self._values.get("attribute_name")
            assert result is not None, "Required property 'attribute_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PartitionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastore.RetentionPeriodProperty",
        jsii_struct_bases=[],
        name_mapping={"number_of_days": "numberOfDays", "unlimited": "unlimited"},
    )
    class RetentionPeriodProperty:
        def __init__(
            self,
            *,
            number_of_days: typing.Optional[jsii.Number] = None,
            unlimited: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''How long, in days, message data is kept.

            :param number_of_days: The number of days that message data is kept. The ``unlimited`` parameter must be false.
            :param unlimited: If true, message data is kept indefinitely.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-retentionperiod.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                retention_period_property = iotanalytics.CfnDatastore.RetentionPeriodProperty(
                    number_of_days=123,
                    unlimited=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if number_of_days is not None:
                self._values["number_of_days"] = number_of_days
            if unlimited is not None:
                self._values["unlimited"] = unlimited

        @builtins.property
        def number_of_days(self) -> typing.Optional[jsii.Number]:
            '''The number of days that message data is kept.

            The ``unlimited`` parameter must be false.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-retentionperiod.html#cfn-iotanalytics-datastore-retentionperiod-numberofdays
            '''
            result = self._values.get("number_of_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def unlimited(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If true, message data is kept indefinitely.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-retentionperiod.html#cfn-iotanalytics-datastore-retentionperiod-unlimited
            '''
            result = self._values.get("unlimited")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RetentionPeriodProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastore.SchemaDefinitionProperty",
        jsii_struct_bases=[],
        name_mapping={"columns": "columns"},
    )
    class SchemaDefinitionProperty:
        def __init__(
            self,
            *,
            columns: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDatastore.ColumnProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Information needed to define a schema.

            :param columns: Specifies one or more columns that store your data. Each schema can have up to 100 columns. Each column can have up to 100 nested types.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-schemadefinition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                schema_definition_property = iotanalytics.CfnDatastore.SchemaDefinitionProperty(
                    columns=[iotanalytics.CfnDatastore.ColumnProperty(
                        name="name",
                        type="type"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if columns is not None:
                self._values["columns"] = columns

        @builtins.property
        def columns(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDatastore.ColumnProperty", _IResolvable_da3f097b]]]]:
            '''Specifies one or more columns that store your data.

            Each schema can have up to 100 columns. Each column can have up to 100 nested types.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-schemadefinition.html#cfn-iotanalytics-datastore-schemadefinition-columns
            '''
            result = self._values.get("columns")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDatastore.ColumnProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SchemaDefinitionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastore.TimestampPartitionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "attribute_name": "attributeName",
            "timestamp_format": "timestampFormat",
        },
    )
    class TimestampPartitionProperty:
        def __init__(
            self,
            *,
            attribute_name: builtins.str,
            timestamp_format: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A partition dimension defined by a timestamp attribute.

            :param attribute_name: The attribute name of the partition defined by a timestamp.
            :param timestamp_format: The timestamp format of a partition defined by a timestamp. The default format is seconds since epoch (January 1, 1970 at midnight UTC time).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-timestamppartition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                timestamp_partition_property = iotanalytics.CfnDatastore.TimestampPartitionProperty(
                    attribute_name="attributeName",
                
                    # the properties below are optional
                    timestamp_format="timestampFormat"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "attribute_name": attribute_name,
            }
            if timestamp_format is not None:
                self._values["timestamp_format"] = timestamp_format

        @builtins.property
        def attribute_name(self) -> builtins.str:
            '''The attribute name of the partition defined by a timestamp.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-timestamppartition.html#cfn-iotanalytics-datastore-timestamppartition-attributename
            '''
            result = self._values.get("attribute_name")
            assert result is not None, "Required property 'attribute_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def timestamp_format(self) -> typing.Optional[builtins.str]:
            '''The timestamp format of a partition defined by a timestamp.

            The default format is seconds since epoch (January 1, 1970 at midnight UTC time).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-datastore-timestamppartition.html#cfn-iotanalytics-datastore-timestamppartition-timestampformat
            '''
            result = self._values.get("timestamp_format")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TimestampPartitionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotanalytics.CfnDatastoreProps",
    jsii_struct_bases=[],
    name_mapping={
        "datastore_name": "datastoreName",
        "datastore_partitions": "datastorePartitions",
        "datastore_storage": "datastoreStorage",
        "file_format_configuration": "fileFormatConfiguration",
        "retention_period": "retentionPeriod",
        "tags": "tags",
    },
)
class CfnDatastoreProps:
    def __init__(
        self,
        *,
        datastore_name: typing.Optional[builtins.str] = None,
        datastore_partitions: typing.Optional[typing.Union[CfnDatastore.DatastorePartitionsProperty, _IResolvable_da3f097b]] = None,
        datastore_storage: typing.Optional[typing.Union[CfnDatastore.DatastoreStorageProperty, _IResolvable_da3f097b]] = None,
        file_format_configuration: typing.Optional[typing.Union[CfnDatastore.FileFormatConfigurationProperty, _IResolvable_da3f097b]] = None,
        retention_period: typing.Optional[typing.Union[CfnDatastore.RetentionPeriodProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDatastore``.

        :param datastore_name: The name of the data store.
        :param datastore_partitions: Information about the partition dimensions in a data store.
        :param datastore_storage: Where data store data is stored.
        :param file_format_configuration: Contains the configuration information of file formats. AWS IoT Analytics data stores support JSON and `Parquet <https://docs.aws.amazon.com/https://parquet.apache.org/>`_ . The default file format is JSON. You can specify only one format. You can't change the file format after you create the data store.
        :param retention_period: How long, in days, message data is kept for the data store. When ``customerManagedS3`` storage is selected, this parameter is ignored.
        :param tags: Metadata which can be used to manage the data store. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-datastore.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotanalytics as iotanalytics
            
            # json_configuration: Any
            # service_managed_s3: Any
            
            cfn_datastore_props = iotanalytics.CfnDatastoreProps(
                datastore_name="datastoreName",
                datastore_partitions=iotanalytics.CfnDatastore.DatastorePartitionsProperty(
                    partitions=[iotanalytics.CfnDatastore.DatastorePartitionProperty(
                        partition=iotanalytics.CfnDatastore.PartitionProperty(
                            attribute_name="attributeName"
                        ),
                        timestamp_partition=iotanalytics.CfnDatastore.TimestampPartitionProperty(
                            attribute_name="attributeName",
            
                            # the properties below are optional
                            timestamp_format="timestampFormat"
                        )
                    )]
                ),
                datastore_storage=iotanalytics.CfnDatastore.DatastoreStorageProperty(
                    customer_managed_s3=iotanalytics.CfnDatastore.CustomerManagedS3Property(
                        bucket="bucket",
                        role_arn="roleArn",
            
                        # the properties below are optional
                        key_prefix="keyPrefix"
                    ),
                    iot_site_wise_multi_layer_storage=iotanalytics.CfnDatastore.IotSiteWiseMultiLayerStorageProperty(
                        customer_managed_s3_storage=iotanalytics.CfnDatastore.CustomerManagedS3StorageProperty(
                            bucket="bucket",
            
                            # the properties below are optional
                            key_prefix="keyPrefix"
                        )
                    ),
                    service_managed_s3=service_managed_s3
                ),
                file_format_configuration=iotanalytics.CfnDatastore.FileFormatConfigurationProperty(
                    json_configuration=json_configuration,
                    parquet_configuration=iotanalytics.CfnDatastore.ParquetConfigurationProperty(
                        schema_definition=iotanalytics.CfnDatastore.SchemaDefinitionProperty(
                            columns=[iotanalytics.CfnDatastore.ColumnProperty(
                                name="name",
                                type="type"
                            )]
                        )
                    )
                ),
                retention_period=iotanalytics.CfnDatastore.RetentionPeriodProperty(
                    number_of_days=123,
                    unlimited=False
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if datastore_name is not None:
            self._values["datastore_name"] = datastore_name
        if datastore_partitions is not None:
            self._values["datastore_partitions"] = datastore_partitions
        if datastore_storage is not None:
            self._values["datastore_storage"] = datastore_storage
        if file_format_configuration is not None:
            self._values["file_format_configuration"] = file_format_configuration
        if retention_period is not None:
            self._values["retention_period"] = retention_period
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def datastore_name(self) -> typing.Optional[builtins.str]:
        '''The name of the data store.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-datastore.html#cfn-iotanalytics-datastore-datastorename
        '''
        result = self._values.get("datastore_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def datastore_partitions(
        self,
    ) -> typing.Optional[typing.Union[CfnDatastore.DatastorePartitionsProperty, _IResolvable_da3f097b]]:
        '''Information about the partition dimensions in a data store.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-datastore.html#cfn-iotanalytics-datastore-datastorepartitions
        '''
        result = self._values.get("datastore_partitions")
        return typing.cast(typing.Optional[typing.Union[CfnDatastore.DatastorePartitionsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def datastore_storage(
        self,
    ) -> typing.Optional[typing.Union[CfnDatastore.DatastoreStorageProperty, _IResolvable_da3f097b]]:
        '''Where data store data is stored.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-datastore.html#cfn-iotanalytics-datastore-datastorestorage
        '''
        result = self._values.get("datastore_storage")
        return typing.cast(typing.Optional[typing.Union[CfnDatastore.DatastoreStorageProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def file_format_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnDatastore.FileFormatConfigurationProperty, _IResolvable_da3f097b]]:
        '''Contains the configuration information of file formats. AWS IoT Analytics data stores support JSON and `Parquet <https://docs.aws.amazon.com/https://parquet.apache.org/>`_ .

        The default file format is JSON. You can specify only one format.

        You can't change the file format after you create the data store.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-datastore.html#cfn-iotanalytics-datastore-fileformatconfiguration
        '''
        result = self._values.get("file_format_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnDatastore.FileFormatConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def retention_period(
        self,
    ) -> typing.Optional[typing.Union[CfnDatastore.RetentionPeriodProperty, _IResolvable_da3f097b]]:
        '''How long, in days, message data is kept for the data store.

        When ``customerManagedS3`` storage is selected, this parameter is ignored.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-datastore.html#cfn-iotanalytics-datastore-retentionperiod
        '''
        result = self._values.get("retention_period")
        return typing.cast(typing.Optional[typing.Union[CfnDatastore.RetentionPeriodProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Metadata which can be used to manage the data store.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-datastore.html#cfn-iotanalytics-datastore-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDatastoreProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnPipeline(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotanalytics.CfnPipeline",
):
    '''A CloudFormation ``AWS::IoTAnalytics::Pipeline``.

    The AWS::IoTAnalytics::Pipeline resource consumes messages from one or more channels and allows you to process the messages before storing them in a data store. You must specify both a ``channel`` and a ``datastore`` activity and, optionally, as many as 23 additional activities in the ``pipelineActivities`` array. For more information, see `How to Use AWS IoT Analytics <https://docs.aws.amazon.com/iotanalytics/latest/userguide/welcome.html#aws-iot-analytics-how>`_ in the *AWS IoT Analytics User Guide* .

    :cloudformationResource: AWS::IoTAnalytics::Pipeline
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-pipeline.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotanalytics as iotanalytics
        
        cfn_pipeline = iotanalytics.CfnPipeline(self, "MyCfnPipeline",
            pipeline_activities=[iotanalytics.CfnPipeline.ActivityProperty(
                add_attributes=iotanalytics.CfnPipeline.AddAttributesProperty(
                    attributes={
                        "attributes_key": "attributes"
                    },
                    name="name",
        
                    # the properties below are optional
                    next="next"
                ),
                channel=iotanalytics.CfnPipeline.ChannelProperty(
                    channel_name="channelName",
                    name="name",
        
                    # the properties below are optional
                    next="next"
                ),
                datastore=iotanalytics.CfnPipeline.DatastoreProperty(
                    datastore_name="datastoreName",
                    name="name"
                ),
                device_registry_enrich=iotanalytics.CfnPipeline.DeviceRegistryEnrichProperty(
                    attribute="attribute",
                    name="name",
                    role_arn="roleArn",
                    thing_name="thingName",
        
                    # the properties below are optional
                    next="next"
                ),
                device_shadow_enrich=iotanalytics.CfnPipeline.DeviceShadowEnrichProperty(
                    attribute="attribute",
                    name="name",
                    role_arn="roleArn",
                    thing_name="thingName",
        
                    # the properties below are optional
                    next="next"
                ),
                filter=iotanalytics.CfnPipeline.FilterProperty(
                    filter="filter",
                    name="name",
        
                    # the properties below are optional
                    next="next"
                ),
                lambda_=iotanalytics.CfnPipeline.LambdaProperty(
                    batch_size=123,
                    lambda_name="lambdaName",
                    name="name",
        
                    # the properties below are optional
                    next="next"
                ),
                math=iotanalytics.CfnPipeline.MathProperty(
                    attribute="attribute",
                    math="math",
                    name="name",
        
                    # the properties below are optional
                    next="next"
                ),
                remove_attributes=iotanalytics.CfnPipeline.RemoveAttributesProperty(
                    attributes=["attributes"],
                    name="name",
        
                    # the properties below are optional
                    next="next"
                ),
                select_attributes=iotanalytics.CfnPipeline.SelectAttributesProperty(
                    attributes=["attributes"],
                    name="name",
        
                    # the properties below are optional
                    next="next"
                )
            )],
        
            # the properties below are optional
            pipeline_name="pipelineName",
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
        pipeline_activities: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnPipeline.ActivityProperty", _IResolvable_da3f097b]]],
        pipeline_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::IoTAnalytics::Pipeline``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param pipeline_activities: A list of "PipelineActivity" objects. Activities perform transformations on your messages, such as removing, renaming or adding message attributes; filtering messages based on attribute values; invoking your Lambda functions on messages for advanced processing; or performing mathematical transformations to normalize device data. The list can be 2-25 *PipelineActivity* objects and must contain both a ``channel`` and a ``datastore`` activity. Each entry in the list must contain only one activity, for example: ``pipelineActivities = [ { "channel": { ... } }, { "lambda": { ... } }, ... ]``
        :param pipeline_name: The name of the pipeline.
        :param tags: Metadata which can be used to manage the pipeline. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnPipelineProps(
            pipeline_activities=pipeline_activities,
            pipeline_name=pipeline_name,
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
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''
        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Metadata which can be used to manage the pipeline.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-pipeline.html#cfn-iotanalytics-pipeline-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="pipelineActivities")
    def pipeline_activities(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPipeline.ActivityProperty", _IResolvable_da3f097b]]]:
        '''A list of "PipelineActivity" objects.

        Activities perform transformations on your messages, such as removing, renaming or adding message attributes; filtering messages based on attribute values; invoking your Lambda functions on messages for advanced processing; or performing mathematical transformations to normalize device data.

        The list can be 2-25 *PipelineActivity* objects and must contain both a ``channel`` and a ``datastore`` activity. Each entry in the list must contain only one activity, for example:

        ``pipelineActivities = [ { "channel": { ... } }, { "lambda": { ... } }, ... ]``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-pipeline.html#cfn-iotanalytics-pipeline-pipelineactivities
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPipeline.ActivityProperty", _IResolvable_da3f097b]]], jsii.get(self, "pipelineActivities"))

    @pipeline_activities.setter
    def pipeline_activities(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPipeline.ActivityProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "pipelineActivities", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="pipelineName")
    def pipeline_name(self) -> typing.Optional[builtins.str]:
        '''The name of the pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-pipeline.html#cfn-iotanalytics-pipeline-pipelinename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "pipelineName"))

    @pipeline_name.setter
    def pipeline_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "pipelineName", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnPipeline.ActivityProperty",
        jsii_struct_bases=[],
        name_mapping={
            "add_attributes": "addAttributes",
            "channel": "channel",
            "datastore": "datastore",
            "device_registry_enrich": "deviceRegistryEnrich",
            "device_shadow_enrich": "deviceShadowEnrich",
            "filter": "filter",
            "lambda_": "lambda",
            "math": "math",
            "remove_attributes": "removeAttributes",
            "select_attributes": "selectAttributes",
        },
    )
    class ActivityProperty:
        def __init__(
            self,
            *,
            add_attributes: typing.Optional[typing.Union["CfnPipeline.AddAttributesProperty", _IResolvable_da3f097b]] = None,
            channel: typing.Optional[typing.Union["CfnPipeline.ChannelProperty", _IResolvable_da3f097b]] = None,
            datastore: typing.Optional[typing.Union["CfnPipeline.DatastoreProperty", _IResolvable_da3f097b]] = None,
            device_registry_enrich: typing.Optional[typing.Union["CfnPipeline.DeviceRegistryEnrichProperty", _IResolvable_da3f097b]] = None,
            device_shadow_enrich: typing.Optional[typing.Union["CfnPipeline.DeviceShadowEnrichProperty", _IResolvable_da3f097b]] = None,
            filter: typing.Optional[typing.Union["CfnPipeline.FilterProperty", _IResolvable_da3f097b]] = None,
            lambda_: typing.Optional[typing.Union["CfnPipeline.LambdaProperty", _IResolvable_da3f097b]] = None,
            math: typing.Optional[typing.Union["CfnPipeline.MathProperty", _IResolvable_da3f097b]] = None,
            remove_attributes: typing.Optional[typing.Union["CfnPipeline.RemoveAttributesProperty", _IResolvable_da3f097b]] = None,
            select_attributes: typing.Optional[typing.Union["CfnPipeline.SelectAttributesProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''An activity that performs a transformation on a message.

            :param add_attributes: Adds other attributes based on existing attributes in the message.
            :param channel: Determines the source of the messages to be processed.
            :param datastore: Specifies where to store the processed message data.
            :param device_registry_enrich: Adds data from the AWS IoT device registry to your message.
            :param device_shadow_enrich: Adds information from the AWS IoT Device Shadows service to a message.
            :param filter: Filters a message based on its attributes.
            :param lambda_: Runs a Lambda function to modify the message.
            :param math: Computes an arithmetic expression using the message's attributes and adds it to the message.
            :param remove_attributes: Removes attributes from a message.
            :param select_attributes: Creates a new message using only the specified attributes from the original message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-activity.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                activity_property = iotanalytics.CfnPipeline.ActivityProperty(
                    add_attributes=iotanalytics.CfnPipeline.AddAttributesProperty(
                        attributes={
                            "attributes_key": "attributes"
                        },
                        name="name",
                
                        # the properties below are optional
                        next="next"
                    ),
                    channel=iotanalytics.CfnPipeline.ChannelProperty(
                        channel_name="channelName",
                        name="name",
                
                        # the properties below are optional
                        next="next"
                    ),
                    datastore=iotanalytics.CfnPipeline.DatastoreProperty(
                        datastore_name="datastoreName",
                        name="name"
                    ),
                    device_registry_enrich=iotanalytics.CfnPipeline.DeviceRegistryEnrichProperty(
                        attribute="attribute",
                        name="name",
                        role_arn="roleArn",
                        thing_name="thingName",
                
                        # the properties below are optional
                        next="next"
                    ),
                    device_shadow_enrich=iotanalytics.CfnPipeline.DeviceShadowEnrichProperty(
                        attribute="attribute",
                        name="name",
                        role_arn="roleArn",
                        thing_name="thingName",
                
                        # the properties below are optional
                        next="next"
                    ),
                    filter=iotanalytics.CfnPipeline.FilterProperty(
                        filter="filter",
                        name="name",
                
                        # the properties below are optional
                        next="next"
                    ),
                    lambda_=iotanalytics.CfnPipeline.LambdaProperty(
                        batch_size=123,
                        lambda_name="lambdaName",
                        name="name",
                
                        # the properties below are optional
                        next="next"
                    ),
                    math=iotanalytics.CfnPipeline.MathProperty(
                        attribute="attribute",
                        math="math",
                        name="name",
                
                        # the properties below are optional
                        next="next"
                    ),
                    remove_attributes=iotanalytics.CfnPipeline.RemoveAttributesProperty(
                        attributes=["attributes"],
                        name="name",
                
                        # the properties below are optional
                        next="next"
                    ),
                    select_attributes=iotanalytics.CfnPipeline.SelectAttributesProperty(
                        attributes=["attributes"],
                        name="name",
                
                        # the properties below are optional
                        next="next"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if add_attributes is not None:
                self._values["add_attributes"] = add_attributes
            if channel is not None:
                self._values["channel"] = channel
            if datastore is not None:
                self._values["datastore"] = datastore
            if device_registry_enrich is not None:
                self._values["device_registry_enrich"] = device_registry_enrich
            if device_shadow_enrich is not None:
                self._values["device_shadow_enrich"] = device_shadow_enrich
            if filter is not None:
                self._values["filter"] = filter
            if lambda_ is not None:
                self._values["lambda_"] = lambda_
            if math is not None:
                self._values["math"] = math
            if remove_attributes is not None:
                self._values["remove_attributes"] = remove_attributes
            if select_attributes is not None:
                self._values["select_attributes"] = select_attributes

        @builtins.property
        def add_attributes(
            self,
        ) -> typing.Optional[typing.Union["CfnPipeline.AddAttributesProperty", _IResolvable_da3f097b]]:
            '''Adds other attributes based on existing attributes in the message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-activity.html#cfn-iotanalytics-pipeline-activity-addattributes
            '''
            result = self._values.get("add_attributes")
            return typing.cast(typing.Optional[typing.Union["CfnPipeline.AddAttributesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def channel(
            self,
        ) -> typing.Optional[typing.Union["CfnPipeline.ChannelProperty", _IResolvable_da3f097b]]:
            '''Determines the source of the messages to be processed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-activity.html#cfn-iotanalytics-pipeline-activity-channel
            '''
            result = self._values.get("channel")
            return typing.cast(typing.Optional[typing.Union["CfnPipeline.ChannelProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def datastore(
            self,
        ) -> typing.Optional[typing.Union["CfnPipeline.DatastoreProperty", _IResolvable_da3f097b]]:
            '''Specifies where to store the processed message data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-activity.html#cfn-iotanalytics-pipeline-activity-datastore
            '''
            result = self._values.get("datastore")
            return typing.cast(typing.Optional[typing.Union["CfnPipeline.DatastoreProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def device_registry_enrich(
            self,
        ) -> typing.Optional[typing.Union["CfnPipeline.DeviceRegistryEnrichProperty", _IResolvable_da3f097b]]:
            '''Adds data from the AWS IoT device registry to your message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-activity.html#cfn-iotanalytics-pipeline-activity-deviceregistryenrich
            '''
            result = self._values.get("device_registry_enrich")
            return typing.cast(typing.Optional[typing.Union["CfnPipeline.DeviceRegistryEnrichProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def device_shadow_enrich(
            self,
        ) -> typing.Optional[typing.Union["CfnPipeline.DeviceShadowEnrichProperty", _IResolvable_da3f097b]]:
            '''Adds information from the AWS IoT Device Shadows service to a message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-activity.html#cfn-iotanalytics-pipeline-activity-deviceshadowenrich
            '''
            result = self._values.get("device_shadow_enrich")
            return typing.cast(typing.Optional[typing.Union["CfnPipeline.DeviceShadowEnrichProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def filter(
            self,
        ) -> typing.Optional[typing.Union["CfnPipeline.FilterProperty", _IResolvable_da3f097b]]:
            '''Filters a message based on its attributes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-activity.html#cfn-iotanalytics-pipeline-activity-filter
            '''
            result = self._values.get("filter")
            return typing.cast(typing.Optional[typing.Union["CfnPipeline.FilterProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def lambda_(
            self,
        ) -> typing.Optional[typing.Union["CfnPipeline.LambdaProperty", _IResolvable_da3f097b]]:
            '''Runs a Lambda function to modify the message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-activity.html#cfn-iotanalytics-pipeline-activity-lambda
            '''
            result = self._values.get("lambda_")
            return typing.cast(typing.Optional[typing.Union["CfnPipeline.LambdaProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def math(
            self,
        ) -> typing.Optional[typing.Union["CfnPipeline.MathProperty", _IResolvable_da3f097b]]:
            '''Computes an arithmetic expression using the message's attributes and adds it to the message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-activity.html#cfn-iotanalytics-pipeline-activity-math
            '''
            result = self._values.get("math")
            return typing.cast(typing.Optional[typing.Union["CfnPipeline.MathProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def remove_attributes(
            self,
        ) -> typing.Optional[typing.Union["CfnPipeline.RemoveAttributesProperty", _IResolvable_da3f097b]]:
            '''Removes attributes from a message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-activity.html#cfn-iotanalytics-pipeline-activity-removeattributes
            '''
            result = self._values.get("remove_attributes")
            return typing.cast(typing.Optional[typing.Union["CfnPipeline.RemoveAttributesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def select_attributes(
            self,
        ) -> typing.Optional[typing.Union["CfnPipeline.SelectAttributesProperty", _IResolvable_da3f097b]]:
            '''Creates a new message using only the specified attributes from the original message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-activity.html#cfn-iotanalytics-pipeline-activity-selectattributes
            '''
            result = self._values.get("select_attributes")
            return typing.cast(typing.Optional[typing.Union["CfnPipeline.SelectAttributesProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ActivityProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnPipeline.AddAttributesProperty",
        jsii_struct_bases=[],
        name_mapping={"attributes": "attributes", "name": "name", "next": "next"},
    )
    class AddAttributesProperty:
        def __init__(
            self,
            *,
            attributes: typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]],
            name: builtins.str,
            next: typing.Optional[builtins.str] = None,
        ) -> None:
            '''An activity that adds other attributes based on existing attributes in the message.

            :param attributes: A list of 1-50 "AttributeNameMapping" objects that map an existing attribute to a new attribute. .. epigraph:: The existing attributes remain in the message, so if you want to remove the originals, use "RemoveAttributeActivity".
            :param name: The name of the 'addAttributes' activity.
            :param next: The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-addattributes.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                add_attributes_property = iotanalytics.CfnPipeline.AddAttributesProperty(
                    attributes={
                        "attributes_key": "attributes"
                    },
                    name="name",
                
                    # the properties below are optional
                    next="next"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "attributes": attributes,
                "name": name,
            }
            if next is not None:
                self._values["next"] = next

        @builtins.property
        def attributes(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]:
            '''A list of 1-50 "AttributeNameMapping" objects that map an existing attribute to a new attribute.

            .. epigraph::

               The existing attributes remain in the message, so if you want to remove the originals, use "RemoveAttributeActivity".

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-addattributes.html#cfn-iotanalytics-pipeline-addattributes-attributes
            '''
            result = self._values.get("attributes")
            assert result is not None, "Required property 'attributes' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]], result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the 'addAttributes' activity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-addattributes.html#cfn-iotanalytics-pipeline-addattributes-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def next(self) -> typing.Optional[builtins.str]:
            '''The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-addattributes.html#cfn-iotanalytics-pipeline-addattributes-next
            '''
            result = self._values.get("next")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AddAttributesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnPipeline.ChannelProperty",
        jsii_struct_bases=[],
        name_mapping={"channel_name": "channelName", "name": "name", "next": "next"},
    )
    class ChannelProperty:
        def __init__(
            self,
            *,
            channel_name: builtins.str,
            name: builtins.str,
            next: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Determines the source of the messages to be processed.

            :param channel_name: The name of the channel from which the messages are processed.
            :param name: The name of the 'channel' activity.
            :param next: The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-channel.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                channel_property = iotanalytics.CfnPipeline.ChannelProperty(
                    channel_name="channelName",
                    name="name",
                
                    # the properties below are optional
                    next="next"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "channel_name": channel_name,
                "name": name,
            }
            if next is not None:
                self._values["next"] = next

        @builtins.property
        def channel_name(self) -> builtins.str:
            '''The name of the channel from which the messages are processed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-channel.html#cfn-iotanalytics-pipeline-channel-channelname
            '''
            result = self._values.get("channel_name")
            assert result is not None, "Required property 'channel_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the 'channel' activity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-channel.html#cfn-iotanalytics-pipeline-channel-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def next(self) -> typing.Optional[builtins.str]:
            '''The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-channel.html#cfn-iotanalytics-pipeline-channel-next
            '''
            result = self._values.get("next")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ChannelProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnPipeline.DatastoreProperty",
        jsii_struct_bases=[],
        name_mapping={"datastore_name": "datastoreName", "name": "name"},
    )
    class DatastoreProperty:
        def __init__(self, *, datastore_name: builtins.str, name: builtins.str) -> None:
            '''The datastore activity that specifies where to store the processed data.

            :param datastore_name: The name of the data store where processed messages are stored.
            :param name: The name of the datastore activity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-datastore.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                datastore_property = iotanalytics.CfnPipeline.DatastoreProperty(
                    datastore_name="datastoreName",
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "datastore_name": datastore_name,
                "name": name,
            }

        @builtins.property
        def datastore_name(self) -> builtins.str:
            '''The name of the data store where processed messages are stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-datastore.html#cfn-iotanalytics-pipeline-datastore-datastorename
            '''
            result = self._values.get("datastore_name")
            assert result is not None, "Required property 'datastore_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the datastore activity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-datastore.html#cfn-iotanalytics-pipeline-datastore-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DatastoreProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnPipeline.DeviceRegistryEnrichProperty",
        jsii_struct_bases=[],
        name_mapping={
            "attribute": "attribute",
            "name": "name",
            "role_arn": "roleArn",
            "thing_name": "thingName",
            "next": "next",
        },
    )
    class DeviceRegistryEnrichProperty:
        def __init__(
            self,
            *,
            attribute: builtins.str,
            name: builtins.str,
            role_arn: builtins.str,
            thing_name: builtins.str,
            next: typing.Optional[builtins.str] = None,
        ) -> None:
            '''An activity that adds data from the AWS IoT device registry to your message.

            :param attribute: The name of the attribute that is added to the message.
            :param name: The name of the 'deviceRegistryEnrich' activity.
            :param role_arn: The ARN of the role that allows access to the device's registry information.
            :param thing_name: The name of the IoT device whose registry information is added to the message.
            :param next: The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-deviceregistryenrich.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                device_registry_enrich_property = iotanalytics.CfnPipeline.DeviceRegistryEnrichProperty(
                    attribute="attribute",
                    name="name",
                    role_arn="roleArn",
                    thing_name="thingName",
                
                    # the properties below are optional
                    next="next"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "attribute": attribute,
                "name": name,
                "role_arn": role_arn,
                "thing_name": thing_name,
            }
            if next is not None:
                self._values["next"] = next

        @builtins.property
        def attribute(self) -> builtins.str:
            '''The name of the attribute that is added to the message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-deviceregistryenrich.html#cfn-iotanalytics-pipeline-deviceregistryenrich-attribute
            '''
            result = self._values.get("attribute")
            assert result is not None, "Required property 'attribute' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the 'deviceRegistryEnrich' activity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-deviceregistryenrich.html#cfn-iotanalytics-pipeline-deviceregistryenrich-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def role_arn(self) -> builtins.str:
            '''The ARN of the role that allows access to the device's registry information.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-deviceregistryenrich.html#cfn-iotanalytics-pipeline-deviceregistryenrich-rolearn
            '''
            result = self._values.get("role_arn")
            assert result is not None, "Required property 'role_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def thing_name(self) -> builtins.str:
            '''The name of the IoT device whose registry information is added to the message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-deviceregistryenrich.html#cfn-iotanalytics-pipeline-deviceregistryenrich-thingname
            '''
            result = self._values.get("thing_name")
            assert result is not None, "Required property 'thing_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def next(self) -> typing.Optional[builtins.str]:
            '''The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-deviceregistryenrich.html#cfn-iotanalytics-pipeline-deviceregistryenrich-next
            '''
            result = self._values.get("next")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DeviceRegistryEnrichProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnPipeline.DeviceShadowEnrichProperty",
        jsii_struct_bases=[],
        name_mapping={
            "attribute": "attribute",
            "name": "name",
            "role_arn": "roleArn",
            "thing_name": "thingName",
            "next": "next",
        },
    )
    class DeviceShadowEnrichProperty:
        def __init__(
            self,
            *,
            attribute: builtins.str,
            name: builtins.str,
            role_arn: builtins.str,
            thing_name: builtins.str,
            next: typing.Optional[builtins.str] = None,
        ) -> None:
            '''An activity that adds information from the AWS IoT Device Shadows service to a message.

            :param attribute: The name of the attribute that is added to the message.
            :param name: The name of the 'deviceShadowEnrich' activity.
            :param role_arn: The ARN of the role that allows access to the device's shadow.
            :param thing_name: The name of the IoT device whose shadow information is added to the message.
            :param next: The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-deviceshadowenrich.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                device_shadow_enrich_property = iotanalytics.CfnPipeline.DeviceShadowEnrichProperty(
                    attribute="attribute",
                    name="name",
                    role_arn="roleArn",
                    thing_name="thingName",
                
                    # the properties below are optional
                    next="next"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "attribute": attribute,
                "name": name,
                "role_arn": role_arn,
                "thing_name": thing_name,
            }
            if next is not None:
                self._values["next"] = next

        @builtins.property
        def attribute(self) -> builtins.str:
            '''The name of the attribute that is added to the message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-deviceshadowenrich.html#cfn-iotanalytics-pipeline-deviceshadowenrich-attribute
            '''
            result = self._values.get("attribute")
            assert result is not None, "Required property 'attribute' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the 'deviceShadowEnrich' activity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-deviceshadowenrich.html#cfn-iotanalytics-pipeline-deviceshadowenrich-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def role_arn(self) -> builtins.str:
            '''The ARN of the role that allows access to the device's shadow.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-deviceshadowenrich.html#cfn-iotanalytics-pipeline-deviceshadowenrich-rolearn
            '''
            result = self._values.get("role_arn")
            assert result is not None, "Required property 'role_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def thing_name(self) -> builtins.str:
            '''The name of the IoT device whose shadow information is added to the message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-deviceshadowenrich.html#cfn-iotanalytics-pipeline-deviceshadowenrich-thingname
            '''
            result = self._values.get("thing_name")
            assert result is not None, "Required property 'thing_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def next(self) -> typing.Optional[builtins.str]:
            '''The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-deviceshadowenrich.html#cfn-iotanalytics-pipeline-deviceshadowenrich-next
            '''
            result = self._values.get("next")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DeviceShadowEnrichProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnPipeline.FilterProperty",
        jsii_struct_bases=[],
        name_mapping={"filter": "filter", "name": "name", "next": "next"},
    )
    class FilterProperty:
        def __init__(
            self,
            *,
            filter: builtins.str,
            name: builtins.str,
            next: typing.Optional[builtins.str] = None,
        ) -> None:
            '''An activity that filters a message based on its attributes.

            :param filter: An expression that looks like an SQL WHERE clause that must return a Boolean value.
            :param name: The name of the 'filter' activity.
            :param next: The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-filter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                filter_property = iotanalytics.CfnPipeline.FilterProperty(
                    filter="filter",
                    name="name",
                
                    # the properties below are optional
                    next="next"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "filter": filter,
                "name": name,
            }
            if next is not None:
                self._values["next"] = next

        @builtins.property
        def filter(self) -> builtins.str:
            '''An expression that looks like an SQL WHERE clause that must return a Boolean value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-filter.html#cfn-iotanalytics-pipeline-filter-filter
            '''
            result = self._values.get("filter")
            assert result is not None, "Required property 'filter' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the 'filter' activity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-filter.html#cfn-iotanalytics-pipeline-filter-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def next(self) -> typing.Optional[builtins.str]:
            '''The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-filter.html#cfn-iotanalytics-pipeline-filter-next
            '''
            result = self._values.get("next")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnPipeline.LambdaProperty",
        jsii_struct_bases=[],
        name_mapping={
            "batch_size": "batchSize",
            "lambda_name": "lambdaName",
            "name": "name",
            "next": "next",
        },
    )
    class LambdaProperty:
        def __init__(
            self,
            *,
            batch_size: jsii.Number,
            lambda_name: builtins.str,
            name: builtins.str,
            next: typing.Optional[builtins.str] = None,
        ) -> None:
            '''An activity that runs a Lambda function to modify the message.

            :param batch_size: The number of messages passed to the Lambda function for processing. The AWS Lambda function must be able to process all of these messages within five minutes, which is the maximum timeout duration for Lambda functions.
            :param lambda_name: The name of the Lambda function that is run on the message.
            :param name: The name of the 'lambda' activity.
            :param next: The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-lambda.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                lambda_property = iotanalytics.CfnPipeline.LambdaProperty(
                    batch_size=123,
                    lambda_name="lambdaName",
                    name="name",
                
                    # the properties below are optional
                    next="next"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "batch_size": batch_size,
                "lambda_name": lambda_name,
                "name": name,
            }
            if next is not None:
                self._values["next"] = next

        @builtins.property
        def batch_size(self) -> jsii.Number:
            '''The number of messages passed to the Lambda function for processing.

            The AWS Lambda function must be able to process all of these messages within five minutes, which is the maximum timeout duration for Lambda functions.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-lambda.html#cfn-iotanalytics-pipeline-lambda-batchsize
            '''
            result = self._values.get("batch_size")
            assert result is not None, "Required property 'batch_size' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def lambda_name(self) -> builtins.str:
            '''The name of the Lambda function that is run on the message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-lambda.html#cfn-iotanalytics-pipeline-lambda-lambdaname
            '''
            result = self._values.get("lambda_name")
            assert result is not None, "Required property 'lambda_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the 'lambda' activity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-lambda.html#cfn-iotanalytics-pipeline-lambda-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def next(self) -> typing.Optional[builtins.str]:
            '''The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-lambda.html#cfn-iotanalytics-pipeline-lambda-next
            '''
            result = self._values.get("next")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LambdaProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnPipeline.MathProperty",
        jsii_struct_bases=[],
        name_mapping={
            "attribute": "attribute",
            "math": "math",
            "name": "name",
            "next": "next",
        },
    )
    class MathProperty:
        def __init__(
            self,
            *,
            attribute: builtins.str,
            math: builtins.str,
            name: builtins.str,
            next: typing.Optional[builtins.str] = None,
        ) -> None:
            '''An activity that computes an arithmetic expression using the message's attributes.

            :param attribute: The name of the attribute that contains the result of the math operation.
            :param math: An expression that uses one or more existing attributes and must return an integer value.
            :param name: The name of the 'math' activity.
            :param next: The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-math.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                math_property = iotanalytics.CfnPipeline.MathProperty(
                    attribute="attribute",
                    math="math",
                    name="name",
                
                    # the properties below are optional
                    next="next"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "attribute": attribute,
                "math": math,
                "name": name,
            }
            if next is not None:
                self._values["next"] = next

        @builtins.property
        def attribute(self) -> builtins.str:
            '''The name of the attribute that contains the result of the math operation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-math.html#cfn-iotanalytics-pipeline-math-attribute
            '''
            result = self._values.get("attribute")
            assert result is not None, "Required property 'attribute' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def math(self) -> builtins.str:
            '''An expression that uses one or more existing attributes and must return an integer value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-math.html#cfn-iotanalytics-pipeline-math-math
            '''
            result = self._values.get("math")
            assert result is not None, "Required property 'math' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the 'math' activity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-math.html#cfn-iotanalytics-pipeline-math-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def next(self) -> typing.Optional[builtins.str]:
            '''The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-math.html#cfn-iotanalytics-pipeline-math-next
            '''
            result = self._values.get("next")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MathProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnPipeline.RemoveAttributesProperty",
        jsii_struct_bases=[],
        name_mapping={"attributes": "attributes", "name": "name", "next": "next"},
    )
    class RemoveAttributesProperty:
        def __init__(
            self,
            *,
            attributes: typing.Sequence[builtins.str],
            name: builtins.str,
            next: typing.Optional[builtins.str] = None,
        ) -> None:
            '''An activity that removes attributes from a message.

            :param attributes: A list of 1-50 attributes to remove from the message.
            :param name: The name of the 'removeAttributes' activity.
            :param next: The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-removeattributes.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                remove_attributes_property = iotanalytics.CfnPipeline.RemoveAttributesProperty(
                    attributes=["attributes"],
                    name="name",
                
                    # the properties below are optional
                    next="next"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "attributes": attributes,
                "name": name,
            }
            if next is not None:
                self._values["next"] = next

        @builtins.property
        def attributes(self) -> typing.List[builtins.str]:
            '''A list of 1-50 attributes to remove from the message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-removeattributes.html#cfn-iotanalytics-pipeline-removeattributes-attributes
            '''
            result = self._values.get("attributes")
            assert result is not None, "Required property 'attributes' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the 'removeAttributes' activity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-removeattributes.html#cfn-iotanalytics-pipeline-removeattributes-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def next(self) -> typing.Optional[builtins.str]:
            '''The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-removeattributes.html#cfn-iotanalytics-pipeline-removeattributes-next
            '''
            result = self._values.get("next")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RemoveAttributesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotanalytics.CfnPipeline.SelectAttributesProperty",
        jsii_struct_bases=[],
        name_mapping={"attributes": "attributes", "name": "name", "next": "next"},
    )
    class SelectAttributesProperty:
        def __init__(
            self,
            *,
            attributes: typing.Sequence[builtins.str],
            name: builtins.str,
            next: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Creates a new message using only the specified attributes from the original message.

            :param attributes: A list of the attributes to select from the message.
            :param name: The name of the 'selectAttributes' activity.
            :param next: The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-selectattributes.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotanalytics as iotanalytics
                
                select_attributes_property = iotanalytics.CfnPipeline.SelectAttributesProperty(
                    attributes=["attributes"],
                    name="name",
                
                    # the properties below are optional
                    next="next"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "attributes": attributes,
                "name": name,
            }
            if next is not None:
                self._values["next"] = next

        @builtins.property
        def attributes(self) -> typing.List[builtins.str]:
            '''A list of the attributes to select from the message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-selectattributes.html#cfn-iotanalytics-pipeline-selectattributes-attributes
            '''
            result = self._values.get("attributes")
            assert result is not None, "Required property 'attributes' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the 'selectAttributes' activity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-selectattributes.html#cfn-iotanalytics-pipeline-selectattributes-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def next(self) -> typing.Optional[builtins.str]:
            '''The next activity in the pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotanalytics-pipeline-selectattributes.html#cfn-iotanalytics-pipeline-selectattributes-next
            '''
            result = self._values.get("next")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SelectAttributesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotanalytics.CfnPipelineProps",
    jsii_struct_bases=[],
    name_mapping={
        "pipeline_activities": "pipelineActivities",
        "pipeline_name": "pipelineName",
        "tags": "tags",
    },
)
class CfnPipelineProps:
    def __init__(
        self,
        *,
        pipeline_activities: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnPipeline.ActivityProperty, _IResolvable_da3f097b]]],
        pipeline_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnPipeline``.

        :param pipeline_activities: A list of "PipelineActivity" objects. Activities perform transformations on your messages, such as removing, renaming or adding message attributes; filtering messages based on attribute values; invoking your Lambda functions on messages for advanced processing; or performing mathematical transformations to normalize device data. The list can be 2-25 *PipelineActivity* objects and must contain both a ``channel`` and a ``datastore`` activity. Each entry in the list must contain only one activity, for example: ``pipelineActivities = [ { "channel": { ... } }, { "lambda": { ... } }, ... ]``
        :param pipeline_name: The name of the pipeline.
        :param tags: Metadata which can be used to manage the pipeline. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-pipeline.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotanalytics as iotanalytics
            
            cfn_pipeline_props = iotanalytics.CfnPipelineProps(
                pipeline_activities=[iotanalytics.CfnPipeline.ActivityProperty(
                    add_attributes=iotanalytics.CfnPipeline.AddAttributesProperty(
                        attributes={
                            "attributes_key": "attributes"
                        },
                        name="name",
            
                        # the properties below are optional
                        next="next"
                    ),
                    channel=iotanalytics.CfnPipeline.ChannelProperty(
                        channel_name="channelName",
                        name="name",
            
                        # the properties below are optional
                        next="next"
                    ),
                    datastore=iotanalytics.CfnPipeline.DatastoreProperty(
                        datastore_name="datastoreName",
                        name="name"
                    ),
                    device_registry_enrich=iotanalytics.CfnPipeline.DeviceRegistryEnrichProperty(
                        attribute="attribute",
                        name="name",
                        role_arn="roleArn",
                        thing_name="thingName",
            
                        # the properties below are optional
                        next="next"
                    ),
                    device_shadow_enrich=iotanalytics.CfnPipeline.DeviceShadowEnrichProperty(
                        attribute="attribute",
                        name="name",
                        role_arn="roleArn",
                        thing_name="thingName",
            
                        # the properties below are optional
                        next="next"
                    ),
                    filter=iotanalytics.CfnPipeline.FilterProperty(
                        filter="filter",
                        name="name",
            
                        # the properties below are optional
                        next="next"
                    ),
                    lambda_=iotanalytics.CfnPipeline.LambdaProperty(
                        batch_size=123,
                        lambda_name="lambdaName",
                        name="name",
            
                        # the properties below are optional
                        next="next"
                    ),
                    math=iotanalytics.CfnPipeline.MathProperty(
                        attribute="attribute",
                        math="math",
                        name="name",
            
                        # the properties below are optional
                        next="next"
                    ),
                    remove_attributes=iotanalytics.CfnPipeline.RemoveAttributesProperty(
                        attributes=["attributes"],
                        name="name",
            
                        # the properties below are optional
                        next="next"
                    ),
                    select_attributes=iotanalytics.CfnPipeline.SelectAttributesProperty(
                        attributes=["attributes"],
                        name="name",
            
                        # the properties below are optional
                        next="next"
                    )
                )],
            
                # the properties below are optional
                pipeline_name="pipelineName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "pipeline_activities": pipeline_activities,
        }
        if pipeline_name is not None:
            self._values["pipeline_name"] = pipeline_name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def pipeline_activities(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnPipeline.ActivityProperty, _IResolvable_da3f097b]]]:
        '''A list of "PipelineActivity" objects.

        Activities perform transformations on your messages, such as removing, renaming or adding message attributes; filtering messages based on attribute values; invoking your Lambda functions on messages for advanced processing; or performing mathematical transformations to normalize device data.

        The list can be 2-25 *PipelineActivity* objects and must contain both a ``channel`` and a ``datastore`` activity. Each entry in the list must contain only one activity, for example:

        ``pipelineActivities = [ { "channel": { ... } }, { "lambda": { ... } }, ... ]``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-pipeline.html#cfn-iotanalytics-pipeline-pipelineactivities
        '''
        result = self._values.get("pipeline_activities")
        assert result is not None, "Required property 'pipeline_activities' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnPipeline.ActivityProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def pipeline_name(self) -> typing.Optional[builtins.str]:
        '''The name of the pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-pipeline.html#cfn-iotanalytics-pipeline-pipelinename
        '''
        result = self._values.get("pipeline_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Metadata which can be used to manage the pipeline.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotanalytics-pipeline.html#cfn-iotanalytics-pipeline-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPipelineProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnChannel",
    "CfnChannelProps",
    "CfnDataset",
    "CfnDatasetProps",
    "CfnDatastore",
    "CfnDatastoreProps",
    "CfnPipeline",
    "CfnPipelineProps",
]

publication.publish()
