'''
# AWS::AppIntegrations Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_appintegrations as appintegrations
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-appintegrations-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::AppIntegrations](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_AppIntegrations.html).

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
class CfnDataIntegration(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appintegrations.CfnDataIntegration",
):
    '''A CloudFormation ``AWS::AppIntegrations::DataIntegration``.

    Creates and persists a DataIntegration resource.

    :cloudformationResource: AWS::AppIntegrations::DataIntegration
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-dataintegration.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appintegrations as appintegrations
        
        cfn_data_integration = appintegrations.CfnDataIntegration(self, "MyCfnDataIntegration",
            kms_key="kmsKey",
            name="name",
            schedule_config=appintegrations.CfnDataIntegration.ScheduleConfigProperty(
                first_execution_from="firstExecutionFrom",
                object="object",
                schedule_expression="scheduleExpression"
            ),
            source_uri="sourceUri",
        
            # the properties below are optional
            description="description",
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
        kms_key: builtins.str,
        name: builtins.str,
        schedule_config: typing.Union["CfnDataIntegration.ScheduleConfigProperty", _IResolvable_da3f097b],
        source_uri: builtins.str,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::AppIntegrations::DataIntegration``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param kms_key: The KMS key for the DataIntegration.
        :param name: The name of the DataIntegration.
        :param schedule_config: The name of the data and how often it should be pulled from the source.
        :param source_uri: The URI of the data source.
        :param description: A description of the DataIntegration.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnDataIntegrationProps(
            kms_key=kms_key,
            name=name,
            schedule_config=schedule_config,
            source_uri=source_uri,
            description=description,
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
    @jsii.member(jsii_name="attrDataIntegrationArn")
    def attr_data_integration_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) for the DataIntegration.

        :cloudformationAttribute: DataIntegrationArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrDataIntegrationArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''A unique identifier.

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
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-dataintegration.html#cfn-appintegrations-dataintegration-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKey")
    def kms_key(self) -> builtins.str:
        '''The KMS key for the DataIntegration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-dataintegration.html#cfn-appintegrations-dataintegration-kmskey
        '''
        return typing.cast(builtins.str, jsii.get(self, "kmsKey"))

    @kms_key.setter
    def kms_key(self, value: builtins.str) -> None:
        jsii.set(self, "kmsKey", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the DataIntegration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-dataintegration.html#cfn-appintegrations-dataintegration-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scheduleConfig")
    def schedule_config(
        self,
    ) -> typing.Union["CfnDataIntegration.ScheduleConfigProperty", _IResolvable_da3f097b]:
        '''The name of the data and how often it should be pulled from the source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-dataintegration.html#cfn-appintegrations-dataintegration-scheduleconfig
        '''
        return typing.cast(typing.Union["CfnDataIntegration.ScheduleConfigProperty", _IResolvable_da3f097b], jsii.get(self, "scheduleConfig"))

    @schedule_config.setter
    def schedule_config(
        self,
        value: typing.Union["CfnDataIntegration.ScheduleConfigProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "scheduleConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceUri")
    def source_uri(self) -> builtins.str:
        '''The URI of the data source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-dataintegration.html#cfn-appintegrations-dataintegration-sourceuri
        '''
        return typing.cast(builtins.str, jsii.get(self, "sourceUri"))

    @source_uri.setter
    def source_uri(self, value: builtins.str) -> None:
        jsii.set(self, "sourceUri", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the DataIntegration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-dataintegration.html#cfn-appintegrations-dataintegration-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appintegrations.CfnDataIntegration.ScheduleConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "first_execution_from": "firstExecutionFrom",
            "object": "object",
            "schedule_expression": "scheduleExpression",
        },
    )
    class ScheduleConfigProperty:
        def __init__(
            self,
            *,
            first_execution_from: builtins.str,
            object: builtins.str,
            schedule_expression: builtins.str,
        ) -> None:
            '''The name of the data and how often it should be pulled from the source.

            :param first_execution_from: The start date for objects to import in the first flow run as an Unix/epoch timestamp in milliseconds or in ISO-8601 format.
            :param object: The name of the object to pull from the data source.
            :param schedule_expression: How often the data should be pulled from data source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-dataintegration-scheduleconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appintegrations as appintegrations
                
                schedule_config_property = appintegrations.CfnDataIntegration.ScheduleConfigProperty(
                    first_execution_from="firstExecutionFrom",
                    object="object",
                    schedule_expression="scheduleExpression"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "first_execution_from": first_execution_from,
                "object": object,
                "schedule_expression": schedule_expression,
            }

        @builtins.property
        def first_execution_from(self) -> builtins.str:
            '''The start date for objects to import in the first flow run as an Unix/epoch timestamp in milliseconds or in ISO-8601 format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-dataintegration-scheduleconfig.html#cfn-appintegrations-dataintegration-scheduleconfig-firstexecutionfrom
            '''
            result = self._values.get("first_execution_from")
            assert result is not None, "Required property 'first_execution_from' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def object(self) -> builtins.str:
            '''The name of the object to pull from the data source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-dataintegration-scheduleconfig.html#cfn-appintegrations-dataintegration-scheduleconfig-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def schedule_expression(self) -> builtins.str:
            '''How often the data should be pulled from data source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-dataintegration-scheduleconfig.html#cfn-appintegrations-dataintegration-scheduleconfig-scheduleexpression
            '''
            result = self._values.get("schedule_expression")
            assert result is not None, "Required property 'schedule_expression' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScheduleConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appintegrations.CfnDataIntegrationProps",
    jsii_struct_bases=[],
    name_mapping={
        "kms_key": "kmsKey",
        "name": "name",
        "schedule_config": "scheduleConfig",
        "source_uri": "sourceUri",
        "description": "description",
        "tags": "tags",
    },
)
class CfnDataIntegrationProps:
    def __init__(
        self,
        *,
        kms_key: builtins.str,
        name: builtins.str,
        schedule_config: typing.Union[CfnDataIntegration.ScheduleConfigProperty, _IResolvable_da3f097b],
        source_uri: builtins.str,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDataIntegration``.

        :param kms_key: The KMS key for the DataIntegration.
        :param name: The name of the DataIntegration.
        :param schedule_config: The name of the data and how often it should be pulled from the source.
        :param source_uri: The URI of the data source.
        :param description: A description of the DataIntegration.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-dataintegration.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appintegrations as appintegrations
            
            cfn_data_integration_props = appintegrations.CfnDataIntegrationProps(
                kms_key="kmsKey",
                name="name",
                schedule_config=appintegrations.CfnDataIntegration.ScheduleConfigProperty(
                    first_execution_from="firstExecutionFrom",
                    object="object",
                    schedule_expression="scheduleExpression"
                ),
                source_uri="sourceUri",
            
                # the properties below are optional
                description="description",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "kms_key": kms_key,
            "name": name,
            "schedule_config": schedule_config,
            "source_uri": source_uri,
        }
        if description is not None:
            self._values["description"] = description
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def kms_key(self) -> builtins.str:
        '''The KMS key for the DataIntegration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-dataintegration.html#cfn-appintegrations-dataintegration-kmskey
        '''
        result = self._values.get("kms_key")
        assert result is not None, "Required property 'kms_key' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the DataIntegration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-dataintegration.html#cfn-appintegrations-dataintegration-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def schedule_config(
        self,
    ) -> typing.Union[CfnDataIntegration.ScheduleConfigProperty, _IResolvable_da3f097b]:
        '''The name of the data and how often it should be pulled from the source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-dataintegration.html#cfn-appintegrations-dataintegration-scheduleconfig
        '''
        result = self._values.get("schedule_config")
        assert result is not None, "Required property 'schedule_config' is missing"
        return typing.cast(typing.Union[CfnDataIntegration.ScheduleConfigProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def source_uri(self) -> builtins.str:
        '''The URI of the data source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-dataintegration.html#cfn-appintegrations-dataintegration-sourceuri
        '''
        result = self._values.get("source_uri")
        assert result is not None, "Required property 'source_uri' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the DataIntegration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-dataintegration.html#cfn-appintegrations-dataintegration-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-dataintegration.html#cfn-appintegrations-dataintegration-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDataIntegrationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnEventIntegration(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appintegrations.CfnEventIntegration",
):
    '''A CloudFormation ``AWS::AppIntegrations::EventIntegration``.

    Creates an event integration. You provide a name, description, and a reference to an Amazon EventBridge bus in your account and a partner event source that will push events to that bus. No objects are created in your account, only metadata that is persisted on the EventIntegration control plane.

    :cloudformationResource: AWS::AppIntegrations::EventIntegration
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-eventintegration.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appintegrations as appintegrations
        
        cfn_event_integration = appintegrations.CfnEventIntegration(self, "MyCfnEventIntegration",
            event_bridge_bus="eventBridgeBus",
            event_filter=appintegrations.CfnEventIntegration.EventFilterProperty(
                source="source"
            ),
            name="name",
        
            # the properties below are optional
            description="description",
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
        event_bridge_bus: builtins.str,
        event_filter: typing.Union["CfnEventIntegration.EventFilterProperty", _IResolvable_da3f097b],
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::AppIntegrations::EventIntegration``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param event_bridge_bus: The Amazon EventBridge bus for the event integration.
        :param event_filter: The event integration filter.
        :param name: The name of the event integration.
        :param description: The event integration description.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnEventIntegrationProps(
            event_bridge_bus=event_bridge_bus,
            event_filter=event_filter,
            name=name,
            description=description,
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
    @jsii.member(jsii_name="attrAssociations")
    def attr_associations(self) -> _IResolvable_da3f097b:
        '''The association status of the event integration, returned as an array of EventIntegrationAssociation objects.

        :cloudformationAttribute: Associations
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrAssociations"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrEventIntegrationArn")
    def attr_event_integration_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the event integration.

        :cloudformationAttribute: EventIntegrationArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrEventIntegrationArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-eventintegration.html#cfn-appintegrations-eventintegration-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventBridgeBus")
    def event_bridge_bus(self) -> builtins.str:
        '''The Amazon EventBridge bus for the event integration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-eventintegration.html#cfn-appintegrations-eventintegration-eventbridgebus
        '''
        return typing.cast(builtins.str, jsii.get(self, "eventBridgeBus"))

    @event_bridge_bus.setter
    def event_bridge_bus(self, value: builtins.str) -> None:
        jsii.set(self, "eventBridgeBus", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventFilter")
    def event_filter(
        self,
    ) -> typing.Union["CfnEventIntegration.EventFilterProperty", _IResolvable_da3f097b]:
        '''The event integration filter.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-eventintegration.html#cfn-appintegrations-eventintegration-eventfilter
        '''
        return typing.cast(typing.Union["CfnEventIntegration.EventFilterProperty", _IResolvable_da3f097b], jsii.get(self, "eventFilter"))

    @event_filter.setter
    def event_filter(
        self,
        value: typing.Union["CfnEventIntegration.EventFilterProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "eventFilter", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the event integration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-eventintegration.html#cfn-appintegrations-eventintegration-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The event integration description.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-eventintegration.html#cfn-appintegrations-eventintegration-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appintegrations.CfnEventIntegration.EventFilterProperty",
        jsii_struct_bases=[],
        name_mapping={"source": "source"},
    )
    class EventFilterProperty:
        def __init__(self, *, source: builtins.str) -> None:
            '''The event integration filter.

            :param source: The source of the events.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-eventintegration-eventfilter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appintegrations as appintegrations
                
                event_filter_property = appintegrations.CfnEventIntegration.EventFilterProperty(
                    source="source"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "source": source,
            }

        @builtins.property
        def source(self) -> builtins.str:
            '''The source of the events.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-eventintegration-eventfilter.html#cfn-appintegrations-eventintegration-eventfilter-source
            '''
            result = self._values.get("source")
            assert result is not None, "Required property 'source' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EventFilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appintegrations.CfnEventIntegration.EventIntegrationAssociationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "client_association_metadata": "clientAssociationMetadata",
            "client_id": "clientId",
            "event_bridge_rule_name": "eventBridgeRuleName",
            "event_integration_association_arn": "eventIntegrationAssociationArn",
            "event_integration_association_id": "eventIntegrationAssociationId",
        },
    )
    class EventIntegrationAssociationProperty:
        def __init__(
            self,
            *,
            client_association_metadata: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnEventIntegration.MetadataProperty", _IResolvable_da3f097b]]]] = None,
            client_id: typing.Optional[builtins.str] = None,
            event_bridge_rule_name: typing.Optional[builtins.str] = None,
            event_integration_association_arn: typing.Optional[builtins.str] = None,
            event_integration_association_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The event integration association.

            :param client_association_metadata: The metadata associated with the client.
            :param client_id: The identifier for the client that is associated with the event integration.
            :param event_bridge_rule_name: The name of the EventBridge rule.
            :param event_integration_association_arn: The Amazon Resource Name (ARN) for the event integration association.
            :param event_integration_association_id: The identifier for the event integration association.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-eventintegration-eventintegrationassociation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appintegrations as appintegrations
                
                event_integration_association_property = appintegrations.CfnEventIntegration.EventIntegrationAssociationProperty(
                    client_association_metadata=[appintegrations.CfnEventIntegration.MetadataProperty(
                        key="key",
                        value="value"
                    )],
                    client_id="clientId",
                    event_bridge_rule_name="eventBridgeRuleName",
                    event_integration_association_arn="eventIntegrationAssociationArn",
                    event_integration_association_id="eventIntegrationAssociationId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if client_association_metadata is not None:
                self._values["client_association_metadata"] = client_association_metadata
            if client_id is not None:
                self._values["client_id"] = client_id
            if event_bridge_rule_name is not None:
                self._values["event_bridge_rule_name"] = event_bridge_rule_name
            if event_integration_association_arn is not None:
                self._values["event_integration_association_arn"] = event_integration_association_arn
            if event_integration_association_id is not None:
                self._values["event_integration_association_id"] = event_integration_association_id

        @builtins.property
        def client_association_metadata(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnEventIntegration.MetadataProperty", _IResolvable_da3f097b]]]]:
            '''The metadata associated with the client.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-eventintegration-eventintegrationassociation.html#cfn-appintegrations-eventintegration-eventintegrationassociation-clientassociationmetadata
            '''
            result = self._values.get("client_association_metadata")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnEventIntegration.MetadataProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def client_id(self) -> typing.Optional[builtins.str]:
            '''The identifier for the client that is associated with the event integration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-eventintegration-eventintegrationassociation.html#cfn-appintegrations-eventintegration-eventintegrationassociation-clientid
            '''
            result = self._values.get("client_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def event_bridge_rule_name(self) -> typing.Optional[builtins.str]:
            '''The name of the EventBridge rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-eventintegration-eventintegrationassociation.html#cfn-appintegrations-eventintegration-eventintegrationassociation-eventbridgerulename
            '''
            result = self._values.get("event_bridge_rule_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def event_integration_association_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) for the event integration association.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-eventintegration-eventintegrationassociation.html#cfn-appintegrations-eventintegration-eventintegrationassociation-eventintegrationassociationarn
            '''
            result = self._values.get("event_integration_association_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def event_integration_association_id(self) -> typing.Optional[builtins.str]:
            '''The identifier for the event integration association.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-eventintegration-eventintegrationassociation.html#cfn-appintegrations-eventintegration-eventintegrationassociation-eventintegrationassociationid
            '''
            result = self._values.get("event_integration_association_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EventIntegrationAssociationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appintegrations.CfnEventIntegration.MetadataProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class MetadataProperty:
        def __init__(self, *, key: builtins.str, value: builtins.str) -> None:
            '''The metadata associated with the client.

            :param key: The key name.
            :param value: The value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-eventintegration-metadata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appintegrations as appintegrations
                
                metadata_property = appintegrations.CfnEventIntegration.MetadataProperty(
                    key="key",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "key": key,
                "value": value,
            }

        @builtins.property
        def key(self) -> builtins.str:
            '''The key name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-eventintegration-metadata.html#cfn-appintegrations-eventintegration-metadata-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appintegrations-eventintegration-metadata.html#cfn-appintegrations-eventintegration-metadata-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MetadataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appintegrations.CfnEventIntegrationProps",
    jsii_struct_bases=[],
    name_mapping={
        "event_bridge_bus": "eventBridgeBus",
        "event_filter": "eventFilter",
        "name": "name",
        "description": "description",
        "tags": "tags",
    },
)
class CfnEventIntegrationProps:
    def __init__(
        self,
        *,
        event_bridge_bus: builtins.str,
        event_filter: typing.Union[CfnEventIntegration.EventFilterProperty, _IResolvable_da3f097b],
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnEventIntegration``.

        :param event_bridge_bus: The Amazon EventBridge bus for the event integration.
        :param event_filter: The event integration filter.
        :param name: The name of the event integration.
        :param description: The event integration description.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-eventintegration.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appintegrations as appintegrations
            
            cfn_event_integration_props = appintegrations.CfnEventIntegrationProps(
                event_bridge_bus="eventBridgeBus",
                event_filter=appintegrations.CfnEventIntegration.EventFilterProperty(
                    source="source"
                ),
                name="name",
            
                # the properties below are optional
                description="description",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "event_bridge_bus": event_bridge_bus,
            "event_filter": event_filter,
            "name": name,
        }
        if description is not None:
            self._values["description"] = description
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def event_bridge_bus(self) -> builtins.str:
        '''The Amazon EventBridge bus for the event integration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-eventintegration.html#cfn-appintegrations-eventintegration-eventbridgebus
        '''
        result = self._values.get("event_bridge_bus")
        assert result is not None, "Required property 'event_bridge_bus' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def event_filter(
        self,
    ) -> typing.Union[CfnEventIntegration.EventFilterProperty, _IResolvable_da3f097b]:
        '''The event integration filter.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-eventintegration.html#cfn-appintegrations-eventintegration-eventfilter
        '''
        result = self._values.get("event_filter")
        assert result is not None, "Required property 'event_filter' is missing"
        return typing.cast(typing.Union[CfnEventIntegration.EventFilterProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the event integration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-eventintegration.html#cfn-appintegrations-eventintegration-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The event integration description.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-eventintegration.html#cfn-appintegrations-eventintegration-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appintegrations-eventintegration.html#cfn-appintegrations-eventintegration-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnEventIntegrationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnDataIntegration",
    "CfnDataIntegrationProps",
    "CfnEventIntegration",
    "CfnEventIntegrationProps",
]

publication.publish()
