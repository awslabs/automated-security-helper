'''
# AWS::Panorama Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_panorama as panorama
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-panorama-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::Panorama](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_Panorama.html).

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
class CfnApplicationInstance(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_panorama.CfnApplicationInstance",
):
    '''A CloudFormation ``AWS::Panorama::ApplicationInstance``.

    Creates an application instance and deploys it to a device.

    :cloudformationResource: AWS::Panorama::ApplicationInstance
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_panorama as panorama
        
        cfn_application_instance = panorama.CfnApplicationInstance(self, "MyCfnApplicationInstance",
            default_runtime_context_device="defaultRuntimeContextDevice",
            manifest_payload=panorama.CfnApplicationInstance.ManifestPayloadProperty(
                payload_data="payloadData"
            ),
        
            # the properties below are optional
            application_instance_id_to_replace="applicationInstanceIdToReplace",
            description="description",
            device_id="deviceId",
            manifest_overrides_payload=panorama.CfnApplicationInstance.ManifestOverridesPayloadProperty(
                payload_data="payloadData"
            ),
            name="name",
            runtime_role_arn="runtimeRoleArn",
            status_filter="statusFilter",
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
        default_runtime_context_device: builtins.str,
        manifest_payload: typing.Union["CfnApplicationInstance.ManifestPayloadProperty", _IResolvable_da3f097b],
        application_instance_id_to_replace: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        device_id: typing.Optional[builtins.str] = None,
        manifest_overrides_payload: typing.Optional[typing.Union["CfnApplicationInstance.ManifestOverridesPayloadProperty", _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        runtime_role_arn: typing.Optional[builtins.str] = None,
        status_filter: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Panorama::ApplicationInstance``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param default_runtime_context_device: The device's ID.
        :param manifest_payload: The application's manifest document.
        :param application_instance_id_to_replace: The ID of an application instance to replace with the new instance.
        :param description: A description for the application instance.
        :param device_id: A device's ID.
        :param manifest_overrides_payload: Setting overrides for the application manifest.
        :param name: A name for the application instance.
        :param runtime_role_arn: The ARN of a runtime role for the application instance.
        :param status_filter: Only include instances with a specific status.
        :param tags: Tags for the application instance.
        '''
        props = CfnApplicationInstanceProps(
            default_runtime_context_device=default_runtime_context_device,
            manifest_payload=manifest_payload,
            application_instance_id_to_replace=application_instance_id_to_replace,
            description=description,
            device_id=device_id,
            manifest_overrides_payload=manifest_overrides_payload,
            name=name,
            runtime_role_arn=runtime_role_arn,
            status_filter=status_filter,
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
    @jsii.member(jsii_name="attrApplicationInstanceId")
    def attr_application_instance_id(self) -> builtins.str:
        '''The application instance's ID.

        :cloudformationAttribute: ApplicationInstanceId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrApplicationInstanceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The application instance's ARN.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCreatedTime")
    def attr_created_time(self) -> jsii.Number:
        '''The application instance's created time.

        :cloudformationAttribute: CreatedTime
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrCreatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDefaultRuntimeContextDeviceName")
    def attr_default_runtime_context_device_name(self) -> builtins.str:
        '''The application instance's default runtime context device name.

        :cloudformationAttribute: DefaultRuntimeContextDeviceName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrDefaultRuntimeContextDeviceName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrHealthStatus")
    def attr_health_status(self) -> builtins.str:
        '''The application instance's health status.

        :cloudformationAttribute: HealthStatus
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrHealthStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLastUpdatedTime")
    def attr_last_updated_time(self) -> jsii.Number:
        '''The application instance's last updated time.

        :cloudformationAttribute: LastUpdatedTime
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrLastUpdatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStatus")
    def attr_status(self) -> builtins.str:
        '''The application instance's status.

        :cloudformationAttribute: Status
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStatusDescription")
    def attr_status_description(self) -> builtins.str:
        '''The application instance's status description.

        :cloudformationAttribute: StatusDescription
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStatusDescription"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Tags for the application instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultRuntimeContextDevice")
    def default_runtime_context_device(self) -> builtins.str:
        '''The device's ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-defaultruntimecontextdevice
        '''
        return typing.cast(builtins.str, jsii.get(self, "defaultRuntimeContextDevice"))

    @default_runtime_context_device.setter
    def default_runtime_context_device(self, value: builtins.str) -> None:
        jsii.set(self, "defaultRuntimeContextDevice", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="manifestPayload")
    def manifest_payload(
        self,
    ) -> typing.Union["CfnApplicationInstance.ManifestPayloadProperty", _IResolvable_da3f097b]:
        '''The application's manifest document.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-manifestpayload
        '''
        return typing.cast(typing.Union["CfnApplicationInstance.ManifestPayloadProperty", _IResolvable_da3f097b], jsii.get(self, "manifestPayload"))

    @manifest_payload.setter
    def manifest_payload(
        self,
        value: typing.Union["CfnApplicationInstance.ManifestPayloadProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "manifestPayload", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="applicationInstanceIdToReplace")
    def application_instance_id_to_replace(self) -> typing.Optional[builtins.str]:
        '''The ID of an application instance to replace with the new instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-applicationinstanceidtoreplace
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "applicationInstanceIdToReplace"))

    @application_instance_id_to_replace.setter
    def application_instance_id_to_replace(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "applicationInstanceIdToReplace", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the application instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="deviceId")
    def device_id(self) -> typing.Optional[builtins.str]:
        '''A device's ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-deviceid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "deviceId"))

    @device_id.setter
    def device_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "deviceId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="manifestOverridesPayload")
    def manifest_overrides_payload(
        self,
    ) -> typing.Optional[typing.Union["CfnApplicationInstance.ManifestOverridesPayloadProperty", _IResolvable_da3f097b]]:
        '''Setting overrides for the application manifest.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-manifestoverridespayload
        '''
        return typing.cast(typing.Optional[typing.Union["CfnApplicationInstance.ManifestOverridesPayloadProperty", _IResolvable_da3f097b]], jsii.get(self, "manifestOverridesPayload"))

    @manifest_overrides_payload.setter
    def manifest_overrides_payload(
        self,
        value: typing.Optional[typing.Union["CfnApplicationInstance.ManifestOverridesPayloadProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "manifestOverridesPayload", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''A name for the application instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="runtimeRoleArn")
    def runtime_role_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of a runtime role for the application instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-runtimerolearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "runtimeRoleArn"))

    @runtime_role_arn.setter
    def runtime_role_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "runtimeRoleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="statusFilter")
    def status_filter(self) -> typing.Optional[builtins.str]:
        '''Only include instances with a specific status.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-statusfilter
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "statusFilter"))

    @status_filter.setter
    def status_filter(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "statusFilter", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_panorama.CfnApplicationInstance.ManifestOverridesPayloadProperty",
        jsii_struct_bases=[],
        name_mapping={"payload_data": "payloadData"},
    )
    class ManifestOverridesPayloadProperty:
        def __init__(
            self,
            *,
            payload_data: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Parameter overrides for an application instance.

            This is a JSON document that has a single key ( ``PayloadData`` ) where the value is an escaped string representation of the overrides document.

            :param payload_data: The overrides document.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-panorama-applicationinstance-manifestoverridespayload.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_panorama as panorama
                
                manifest_overrides_payload_property = panorama.CfnApplicationInstance.ManifestOverridesPayloadProperty(
                    payload_data="payloadData"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if payload_data is not None:
                self._values["payload_data"] = payload_data

        @builtins.property
        def payload_data(self) -> typing.Optional[builtins.str]:
            '''The overrides document.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-panorama-applicationinstance-manifestoverridespayload.html#cfn-panorama-applicationinstance-manifestoverridespayload-payloaddata
            '''
            result = self._values.get("payload_data")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ManifestOverridesPayloadProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_panorama.CfnApplicationInstance.ManifestPayloadProperty",
        jsii_struct_bases=[],
        name_mapping={"payload_data": "payloadData"},
    )
    class ManifestPayloadProperty:
        def __init__(
            self,
            *,
            payload_data: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A application verion's manifest file.

            This is a JSON document that has a single key ( ``PayloadData`` ) where the value is an escaped string representation of the application manifest ( ``graph.json`` ). This file is located in the ``graphs`` folder in your application source.

            :param payload_data: The application manifest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-panorama-applicationinstance-manifestpayload.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_panorama as panorama
                
                manifest_payload_property = panorama.CfnApplicationInstance.ManifestPayloadProperty(
                    payload_data="payloadData"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if payload_data is not None:
                self._values["payload_data"] = payload_data

        @builtins.property
        def payload_data(self) -> typing.Optional[builtins.str]:
            '''The application manifest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-panorama-applicationinstance-manifestpayload.html#cfn-panorama-applicationinstance-manifestpayload-payloaddata
            '''
            result = self._values.get("payload_data")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ManifestPayloadProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_panorama.CfnApplicationInstanceProps",
    jsii_struct_bases=[],
    name_mapping={
        "default_runtime_context_device": "defaultRuntimeContextDevice",
        "manifest_payload": "manifestPayload",
        "application_instance_id_to_replace": "applicationInstanceIdToReplace",
        "description": "description",
        "device_id": "deviceId",
        "manifest_overrides_payload": "manifestOverridesPayload",
        "name": "name",
        "runtime_role_arn": "runtimeRoleArn",
        "status_filter": "statusFilter",
        "tags": "tags",
    },
)
class CfnApplicationInstanceProps:
    def __init__(
        self,
        *,
        default_runtime_context_device: builtins.str,
        manifest_payload: typing.Union[CfnApplicationInstance.ManifestPayloadProperty, _IResolvable_da3f097b],
        application_instance_id_to_replace: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        device_id: typing.Optional[builtins.str] = None,
        manifest_overrides_payload: typing.Optional[typing.Union[CfnApplicationInstance.ManifestOverridesPayloadProperty, _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        runtime_role_arn: typing.Optional[builtins.str] = None,
        status_filter: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnApplicationInstance``.

        :param default_runtime_context_device: The device's ID.
        :param manifest_payload: The application's manifest document.
        :param application_instance_id_to_replace: The ID of an application instance to replace with the new instance.
        :param description: A description for the application instance.
        :param device_id: A device's ID.
        :param manifest_overrides_payload: Setting overrides for the application manifest.
        :param name: A name for the application instance.
        :param runtime_role_arn: The ARN of a runtime role for the application instance.
        :param status_filter: Only include instances with a specific status.
        :param tags: Tags for the application instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_panorama as panorama
            
            cfn_application_instance_props = panorama.CfnApplicationInstanceProps(
                default_runtime_context_device="defaultRuntimeContextDevice",
                manifest_payload=panorama.CfnApplicationInstance.ManifestPayloadProperty(
                    payload_data="payloadData"
                ),
            
                # the properties below are optional
                application_instance_id_to_replace="applicationInstanceIdToReplace",
                description="description",
                device_id="deviceId",
                manifest_overrides_payload=panorama.CfnApplicationInstance.ManifestOverridesPayloadProperty(
                    payload_data="payloadData"
                ),
                name="name",
                runtime_role_arn="runtimeRoleArn",
                status_filter="statusFilter",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "default_runtime_context_device": default_runtime_context_device,
            "manifest_payload": manifest_payload,
        }
        if application_instance_id_to_replace is not None:
            self._values["application_instance_id_to_replace"] = application_instance_id_to_replace
        if description is not None:
            self._values["description"] = description
        if device_id is not None:
            self._values["device_id"] = device_id
        if manifest_overrides_payload is not None:
            self._values["manifest_overrides_payload"] = manifest_overrides_payload
        if name is not None:
            self._values["name"] = name
        if runtime_role_arn is not None:
            self._values["runtime_role_arn"] = runtime_role_arn
        if status_filter is not None:
            self._values["status_filter"] = status_filter
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def default_runtime_context_device(self) -> builtins.str:
        '''The device's ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-defaultruntimecontextdevice
        '''
        result = self._values.get("default_runtime_context_device")
        assert result is not None, "Required property 'default_runtime_context_device' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def manifest_payload(
        self,
    ) -> typing.Union[CfnApplicationInstance.ManifestPayloadProperty, _IResolvable_da3f097b]:
        '''The application's manifest document.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-manifestpayload
        '''
        result = self._values.get("manifest_payload")
        assert result is not None, "Required property 'manifest_payload' is missing"
        return typing.cast(typing.Union[CfnApplicationInstance.ManifestPayloadProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def application_instance_id_to_replace(self) -> typing.Optional[builtins.str]:
        '''The ID of an application instance to replace with the new instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-applicationinstanceidtoreplace
        '''
        result = self._values.get("application_instance_id_to_replace")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the application instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def device_id(self) -> typing.Optional[builtins.str]:
        '''A device's ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-deviceid
        '''
        result = self._values.get("device_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def manifest_overrides_payload(
        self,
    ) -> typing.Optional[typing.Union[CfnApplicationInstance.ManifestOverridesPayloadProperty, _IResolvable_da3f097b]]:
        '''Setting overrides for the application manifest.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-manifestoverridespayload
        '''
        result = self._values.get("manifest_overrides_payload")
        return typing.cast(typing.Optional[typing.Union[CfnApplicationInstance.ManifestOverridesPayloadProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''A name for the application instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def runtime_role_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of a runtime role for the application instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-runtimerolearn
        '''
        result = self._values.get("runtime_role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def status_filter(self) -> typing.Optional[builtins.str]:
        '''Only include instances with a specific status.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-statusfilter
        '''
        result = self._values.get("status_filter")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Tags for the application instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-applicationinstance.html#cfn-panorama-applicationinstance-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnApplicationInstanceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnPackage(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_panorama.CfnPackage",
):
    '''A CloudFormation ``AWS::Panorama::Package``.

    Creates a package and storage location in an Amazon S3 access point.

    :cloudformationResource: AWS::Panorama::Package
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-package.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_panorama as panorama
        
        cfn_package = panorama.CfnPackage(self, "MyCfnPackage",
            package_name="packageName",
        
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
        package_name: builtins.str,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Panorama::Package``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param package_name: A name for the package.
        :param tags: Tags for the package.
        '''
        props = CfnPackageProps(package_name=package_name, tags=tags)

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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The package's ARN.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCreatedTime")
    def attr_created_time(self) -> jsii.Number:
        '''The item's created time.

        :cloudformationAttribute: CreatedTime
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrCreatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrPackageId")
    def attr_package_id(self) -> builtins.str:
        '''The package's ID.

        :cloudformationAttribute: PackageId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrPackageId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Tags for the package.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-package.html#cfn-panorama-package-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="packageName")
    def package_name(self) -> builtins.str:
        '''A name for the package.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-package.html#cfn-panorama-package-packagename
        '''
        return typing.cast(builtins.str, jsii.get(self, "packageName"))

    @package_name.setter
    def package_name(self, value: builtins.str) -> None:
        jsii.set(self, "packageName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_panorama.CfnPackageProps",
    jsii_struct_bases=[],
    name_mapping={"package_name": "packageName", "tags": "tags"},
)
class CfnPackageProps:
    def __init__(
        self,
        *,
        package_name: builtins.str,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnPackage``.

        :param package_name: A name for the package.
        :param tags: Tags for the package.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-package.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_panorama as panorama
            
            cfn_package_props = panorama.CfnPackageProps(
                package_name="packageName",
            
                # the properties below are optional
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "package_name": package_name,
        }
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def package_name(self) -> builtins.str:
        '''A name for the package.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-package.html#cfn-panorama-package-packagename
        '''
        result = self._values.get("package_name")
        assert result is not None, "Required property 'package_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Tags for the package.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-package.html#cfn-panorama-package-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPackageProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnPackageVersion(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_panorama.CfnPackageVersion",
):
    '''A CloudFormation ``AWS::Panorama::PackageVersion``.

    Registers a package version.

    :cloudformationResource: AWS::Panorama::PackageVersion
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-packageversion.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_panorama as panorama
        
        cfn_package_version = panorama.CfnPackageVersion(self, "MyCfnPackageVersion",
            package_id="packageId",
            package_version="packageVersion",
            patch_version="patchVersion",
        
            # the properties below are optional
            mark_latest=False,
            owner_account="ownerAccount",
            updated_latest_patch_version="updatedLatestPatchVersion"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        package_id: builtins.str,
        package_version: builtins.str,
        patch_version: builtins.str,
        mark_latest: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        owner_account: typing.Optional[builtins.str] = None,
        updated_latest_patch_version: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Panorama::PackageVersion``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param package_id: A package ID.
        :param package_version: A package version.
        :param patch_version: A patch version.
        :param mark_latest: Whether to mark the new version as the latest version.
        :param owner_account: An owner account.
        :param updated_latest_patch_version: If the version was marked latest, the new version to maker as latest.
        '''
        props = CfnPackageVersionProps(
            package_id=package_id,
            package_version=package_version,
            patch_version=patch_version,
            mark_latest=mark_latest,
            owner_account=owner_account,
            updated_latest_patch_version=updated_latest_patch_version,
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
    @jsii.member(jsii_name="attrIsLatestPatch")
    def attr_is_latest_patch(self) -> _IResolvable_da3f097b:
        '''Whether the package version is the latest version.

        :cloudformationAttribute: IsLatestPatch
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrIsLatestPatch"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrPackageArn")
    def attr_package_arn(self) -> builtins.str:
        '''The package version's ARN.

        :cloudformationAttribute: PackageArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrPackageArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrPackageName")
    def attr_package_name(self) -> builtins.str:
        '''The package version's name.

        :cloudformationAttribute: PackageName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrPackageName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrRegisteredTime")
    def attr_registered_time(self) -> jsii.Number:
        '''The package version's registered time.

        :cloudformationAttribute: RegisteredTime
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrRegisteredTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStatus")
    def attr_status(self) -> builtins.str:
        '''The package version's status.

        :cloudformationAttribute: Status
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStatusDescription")
    def attr_status_description(self) -> builtins.str:
        '''The package version's status description.

        :cloudformationAttribute: StatusDescription
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStatusDescription"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="packageId")
    def package_id(self) -> builtins.str:
        '''A package ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-packageversion.html#cfn-panorama-packageversion-packageid
        '''
        return typing.cast(builtins.str, jsii.get(self, "packageId"))

    @package_id.setter
    def package_id(self, value: builtins.str) -> None:
        jsii.set(self, "packageId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="packageVersion")
    def package_version(self) -> builtins.str:
        '''A package version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-packageversion.html#cfn-panorama-packageversion-packageversion
        '''
        return typing.cast(builtins.str, jsii.get(self, "packageVersion"))

    @package_version.setter
    def package_version(self, value: builtins.str) -> None:
        jsii.set(self, "packageVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="patchVersion")
    def patch_version(self) -> builtins.str:
        '''A patch version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-packageversion.html#cfn-panorama-packageversion-patchversion
        '''
        return typing.cast(builtins.str, jsii.get(self, "patchVersion"))

    @patch_version.setter
    def patch_version(self, value: builtins.str) -> None:
        jsii.set(self, "patchVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="markLatest")
    def mark_latest(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Whether to mark the new version as the latest version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-packageversion.html#cfn-panorama-packageversion-marklatest
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "markLatest"))

    @mark_latest.setter
    def mark_latest(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "markLatest", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ownerAccount")
    def owner_account(self) -> typing.Optional[builtins.str]:
        '''An owner account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-packageversion.html#cfn-panorama-packageversion-owneraccount
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "ownerAccount"))

    @owner_account.setter
    def owner_account(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "ownerAccount", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="updatedLatestPatchVersion")
    def updated_latest_patch_version(self) -> typing.Optional[builtins.str]:
        '''If the version was marked latest, the new version to maker as latest.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-packageversion.html#cfn-panorama-packageversion-updatedlatestpatchversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "updatedLatestPatchVersion"))

    @updated_latest_patch_version.setter
    def updated_latest_patch_version(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "updatedLatestPatchVersion", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_panorama.CfnPackageVersionProps",
    jsii_struct_bases=[],
    name_mapping={
        "package_id": "packageId",
        "package_version": "packageVersion",
        "patch_version": "patchVersion",
        "mark_latest": "markLatest",
        "owner_account": "ownerAccount",
        "updated_latest_patch_version": "updatedLatestPatchVersion",
    },
)
class CfnPackageVersionProps:
    def __init__(
        self,
        *,
        package_id: builtins.str,
        package_version: builtins.str,
        patch_version: builtins.str,
        mark_latest: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        owner_account: typing.Optional[builtins.str] = None,
        updated_latest_patch_version: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnPackageVersion``.

        :param package_id: A package ID.
        :param package_version: A package version.
        :param patch_version: A patch version.
        :param mark_latest: Whether to mark the new version as the latest version.
        :param owner_account: An owner account.
        :param updated_latest_patch_version: If the version was marked latest, the new version to maker as latest.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-packageversion.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_panorama as panorama
            
            cfn_package_version_props = panorama.CfnPackageVersionProps(
                package_id="packageId",
                package_version="packageVersion",
                patch_version="patchVersion",
            
                # the properties below are optional
                mark_latest=False,
                owner_account="ownerAccount",
                updated_latest_patch_version="updatedLatestPatchVersion"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "package_id": package_id,
            "package_version": package_version,
            "patch_version": patch_version,
        }
        if mark_latest is not None:
            self._values["mark_latest"] = mark_latest
        if owner_account is not None:
            self._values["owner_account"] = owner_account
        if updated_latest_patch_version is not None:
            self._values["updated_latest_patch_version"] = updated_latest_patch_version

    @builtins.property
    def package_id(self) -> builtins.str:
        '''A package ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-packageversion.html#cfn-panorama-packageversion-packageid
        '''
        result = self._values.get("package_id")
        assert result is not None, "Required property 'package_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def package_version(self) -> builtins.str:
        '''A package version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-packageversion.html#cfn-panorama-packageversion-packageversion
        '''
        result = self._values.get("package_version")
        assert result is not None, "Required property 'package_version' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def patch_version(self) -> builtins.str:
        '''A patch version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-packageversion.html#cfn-panorama-packageversion-patchversion
        '''
        result = self._values.get("patch_version")
        assert result is not None, "Required property 'patch_version' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def mark_latest(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Whether to mark the new version as the latest version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-packageversion.html#cfn-panorama-packageversion-marklatest
        '''
        result = self._values.get("mark_latest")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def owner_account(self) -> typing.Optional[builtins.str]:
        '''An owner account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-packageversion.html#cfn-panorama-packageversion-owneraccount
        '''
        result = self._values.get("owner_account")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def updated_latest_patch_version(self) -> typing.Optional[builtins.str]:
        '''If the version was marked latest, the new version to maker as latest.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-panorama-packageversion.html#cfn-panorama-packageversion-updatedlatestpatchversion
        '''
        result = self._values.get("updated_latest_patch_version")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPackageVersionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnApplicationInstance",
    "CfnApplicationInstanceProps",
    "CfnPackage",
    "CfnPackageProps",
    "CfnPackageVersion",
    "CfnPackageVersionProps",
]

publication.publish()
