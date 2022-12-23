'''
# AWS::IoTWireless Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_iotwireless as iotwireless
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-iotwireless-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::IoTWireless](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_IoTWireless.html).

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
class CfnDestination(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnDestination",
):
    '''A CloudFormation ``AWS::IoTWireless::Destination``.

    Creates a new destination that maps a device message to an AWS IoT rule.

    :cloudformationResource: AWS::IoTWireless::Destination
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-destination.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotwireless as iotwireless
        
        cfn_destination = iotwireless.CfnDestination(self, "MyCfnDestination",
            expression="expression",
            expression_type="expressionType",
            name="name",
            role_arn="roleArn",
        
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
        expression: builtins.str,
        expression_type: builtins.str,
        name: builtins.str,
        role_arn: builtins.str,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::IoTWireless::Destination``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param expression: The rule name to send messages to.
        :param expression_type: The type of value in ``Expression`` .
        :param name: The name of the new resource.
        :param role_arn: The ARN of the IAM Role that authorizes the destination.
        :param description: The description of the new resource. Maximum length is 2048 characters.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.
        '''
        props = CfnDestinationProps(
            expression=expression,
            expression_type=expression_type,
            name=name,
            role_arn=role_arn,
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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The ARN of the destination created.

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
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-destination.html#cfn-iotwireless-destination-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="expression")
    def expression(self) -> builtins.str:
        '''The rule name to send messages to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-destination.html#cfn-iotwireless-destination-expression
        '''
        return typing.cast(builtins.str, jsii.get(self, "expression"))

    @expression.setter
    def expression(self, value: builtins.str) -> None:
        jsii.set(self, "expression", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="expressionType")
    def expression_type(self) -> builtins.str:
        '''The type of value in ``Expression`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-destination.html#cfn-iotwireless-destination-expressiontype
        '''
        return typing.cast(builtins.str, jsii.get(self, "expressionType"))

    @expression_type.setter
    def expression_type(self, value: builtins.str) -> None:
        jsii.set(self, "expressionType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-destination.html#cfn-iotwireless-destination-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''The ARN of the IAM Role that authorizes the destination.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-destination.html#cfn-iotwireless-destination-rolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "roleArn"))

    @role_arn.setter
    def role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "roleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the new resource.

        Maximum length is 2048 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-destination.html#cfn-iotwireless-destination-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnDestinationProps",
    jsii_struct_bases=[],
    name_mapping={
        "expression": "expression",
        "expression_type": "expressionType",
        "name": "name",
        "role_arn": "roleArn",
        "description": "description",
        "tags": "tags",
    },
)
class CfnDestinationProps:
    def __init__(
        self,
        *,
        expression: builtins.str,
        expression_type: builtins.str,
        name: builtins.str,
        role_arn: builtins.str,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDestination``.

        :param expression: The rule name to send messages to.
        :param expression_type: The type of value in ``Expression`` .
        :param name: The name of the new resource.
        :param role_arn: The ARN of the IAM Role that authorizes the destination.
        :param description: The description of the new resource. Maximum length is 2048 characters.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-destination.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotwireless as iotwireless
            
            cfn_destination_props = iotwireless.CfnDestinationProps(
                expression="expression",
                expression_type="expressionType",
                name="name",
                role_arn="roleArn",
            
                # the properties below are optional
                description="description",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "expression": expression,
            "expression_type": expression_type,
            "name": name,
            "role_arn": role_arn,
        }
        if description is not None:
            self._values["description"] = description
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def expression(self) -> builtins.str:
        '''The rule name to send messages to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-destination.html#cfn-iotwireless-destination-expression
        '''
        result = self._values.get("expression")
        assert result is not None, "Required property 'expression' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def expression_type(self) -> builtins.str:
        '''The type of value in ``Expression`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-destination.html#cfn-iotwireless-destination-expressiontype
        '''
        result = self._values.get("expression_type")
        assert result is not None, "Required property 'expression_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-destination.html#cfn-iotwireless-destination-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def role_arn(self) -> builtins.str:
        '''The ARN of the IAM Role that authorizes the destination.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-destination.html#cfn-iotwireless-destination-rolearn
        '''
        result = self._values.get("role_arn")
        assert result is not None, "Required property 'role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the new resource.

        Maximum length is 2048 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-destination.html#cfn-iotwireless-destination-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-destination.html#cfn-iotwireless-destination-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDestinationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDeviceProfile(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnDeviceProfile",
):
    '''A CloudFormation ``AWS::IoTWireless::DeviceProfile``.

    Creates a new device profile.

    :cloudformationResource: AWS::IoTWireless::DeviceProfile
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-deviceprofile.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotwireless as iotwireless
        
        cfn_device_profile = iotwireless.CfnDeviceProfile(self, "MyCfnDeviceProfile",
            lo_ra_wan=iotwireless.CfnDeviceProfile.LoRaWANDeviceProfileProperty(
                class_bTimeout=123,
                class_cTimeout=123,
                mac_version="macVersion",
                max_duty_cycle=123,
                max_eirp=123,
                ping_slot_dr=123,
                ping_slot_freq=123,
                ping_slot_period=123,
                reg_params_revision="regParamsRevision",
                rf_region="rfRegion",
                supports32_bit_fCnt=False,
                supports_class_b=False,
                supports_class_c=False,
                supports_join=False
            ),
            name="name",
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
        lo_ra_wan: typing.Optional[typing.Union["CfnDeviceProfile.LoRaWANDeviceProfileProperty", _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::IoTWireless::DeviceProfile``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param lo_ra_wan: LoRaWAN device profile object.
        :param name: The name of the new resource.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.
        '''
        props = CfnDeviceProfileProps(lo_ra_wan=lo_ra_wan, name=name, tags=tags)

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
        '''The ARN of the device profile created.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the device profile created.

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
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-deviceprofile.html#cfn-iotwireless-deviceprofile-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loRaWan")
    def lo_ra_wan(
        self,
    ) -> typing.Optional[typing.Union["CfnDeviceProfile.LoRaWANDeviceProfileProperty", _IResolvable_da3f097b]]:
        '''LoRaWAN device profile object.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-deviceprofile.html#cfn-iotwireless-deviceprofile-lorawan
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDeviceProfile.LoRaWANDeviceProfileProperty", _IResolvable_da3f097b]], jsii.get(self, "loRaWan"))

    @lo_ra_wan.setter
    def lo_ra_wan(
        self,
        value: typing.Optional[typing.Union["CfnDeviceProfile.LoRaWANDeviceProfileProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "loRaWan", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-deviceprofile.html#cfn-iotwireless-deviceprofile-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnDeviceProfile.LoRaWANDeviceProfileProperty",
        jsii_struct_bases=[],
        name_mapping={
            "class_b_timeout": "classBTimeout",
            "class_c_timeout": "classCTimeout",
            "mac_version": "macVersion",
            "max_duty_cycle": "maxDutyCycle",
            "max_eirp": "maxEirp",
            "ping_slot_dr": "pingSlotDr",
            "ping_slot_freq": "pingSlotFreq",
            "ping_slot_period": "pingSlotPeriod",
            "reg_params_revision": "regParamsRevision",
            "rf_region": "rfRegion",
            "supports32_bit_f_cnt": "supports32BitFCnt",
            "supports_class_b": "supportsClassB",
            "supports_class_c": "supportsClassC",
            "supports_join": "supportsJoin",
        },
    )
    class LoRaWANDeviceProfileProperty:
        def __init__(
            self,
            *,
            class_b_timeout: typing.Optional[jsii.Number] = None,
            class_c_timeout: typing.Optional[jsii.Number] = None,
            mac_version: typing.Optional[builtins.str] = None,
            max_duty_cycle: typing.Optional[jsii.Number] = None,
            max_eirp: typing.Optional[jsii.Number] = None,
            ping_slot_dr: typing.Optional[jsii.Number] = None,
            ping_slot_freq: typing.Optional[jsii.Number] = None,
            ping_slot_period: typing.Optional[jsii.Number] = None,
            reg_params_revision: typing.Optional[builtins.str] = None,
            rf_region: typing.Optional[builtins.str] = None,
            supports32_bit_f_cnt: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            supports_class_b: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            supports_class_c: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            supports_join: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''LoRaWAN device profile object.

            :param class_b_timeout: The ClassBTimeout value.
            :param class_c_timeout: The ClassCTimeout value.
            :param mac_version: The MAC version (such as OTAA 1.1 or OTAA 1.0.3) to use with this device profile.
            :param max_duty_cycle: The MaxDutyCycle value.
            :param max_eirp: The MaxEIRP value.
            :param ping_slot_dr: The PingSlotDR value.
            :param ping_slot_freq: The PingSlotFreq value.
            :param ping_slot_period: The PingSlotPeriod value.
            :param reg_params_revision: The version of regional parameters.
            :param rf_region: The frequency band (RFRegion) value.
            :param supports32_bit_f_cnt: The Supports32BitFCnt value.
            :param supports_class_b: The SupportsClassB value.
            :param supports_class_c: The SupportsClassC value.
            :param supports_join: The SupportsJoin value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                lo_ra_wANDevice_profile_property = iotwireless.CfnDeviceProfile.LoRaWANDeviceProfileProperty(
                    class_bTimeout=123,
                    class_cTimeout=123,
                    mac_version="macVersion",
                    max_duty_cycle=123,
                    max_eirp=123,
                    ping_slot_dr=123,
                    ping_slot_freq=123,
                    ping_slot_period=123,
                    reg_params_revision="regParamsRevision",
                    rf_region="rfRegion",
                    supports32_bit_fCnt=False,
                    supports_class_b=False,
                    supports_class_c=False,
                    supports_join=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if class_b_timeout is not None:
                self._values["class_b_timeout"] = class_b_timeout
            if class_c_timeout is not None:
                self._values["class_c_timeout"] = class_c_timeout
            if mac_version is not None:
                self._values["mac_version"] = mac_version
            if max_duty_cycle is not None:
                self._values["max_duty_cycle"] = max_duty_cycle
            if max_eirp is not None:
                self._values["max_eirp"] = max_eirp
            if ping_slot_dr is not None:
                self._values["ping_slot_dr"] = ping_slot_dr
            if ping_slot_freq is not None:
                self._values["ping_slot_freq"] = ping_slot_freq
            if ping_slot_period is not None:
                self._values["ping_slot_period"] = ping_slot_period
            if reg_params_revision is not None:
                self._values["reg_params_revision"] = reg_params_revision
            if rf_region is not None:
                self._values["rf_region"] = rf_region
            if supports32_bit_f_cnt is not None:
                self._values["supports32_bit_f_cnt"] = supports32_bit_f_cnt
            if supports_class_b is not None:
                self._values["supports_class_b"] = supports_class_b
            if supports_class_c is not None:
                self._values["supports_class_c"] = supports_class_c
            if supports_join is not None:
                self._values["supports_join"] = supports_join

        @builtins.property
        def class_b_timeout(self) -> typing.Optional[jsii.Number]:
            '''The ClassBTimeout value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html#cfn-iotwireless-deviceprofile-lorawandeviceprofile-classbtimeout
            '''
            result = self._values.get("class_b_timeout")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def class_c_timeout(self) -> typing.Optional[jsii.Number]:
            '''The ClassCTimeout value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html#cfn-iotwireless-deviceprofile-lorawandeviceprofile-classctimeout
            '''
            result = self._values.get("class_c_timeout")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def mac_version(self) -> typing.Optional[builtins.str]:
            '''The MAC version (such as OTAA 1.1 or OTAA 1.0.3) to use with this device profile.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html#cfn-iotwireless-deviceprofile-lorawandeviceprofile-macversion
            '''
            result = self._values.get("mac_version")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def max_duty_cycle(self) -> typing.Optional[jsii.Number]:
            '''The MaxDutyCycle value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html#cfn-iotwireless-deviceprofile-lorawandeviceprofile-maxdutycycle
            '''
            result = self._values.get("max_duty_cycle")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def max_eirp(self) -> typing.Optional[jsii.Number]:
            '''The MaxEIRP value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html#cfn-iotwireless-deviceprofile-lorawandeviceprofile-maxeirp
            '''
            result = self._values.get("max_eirp")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def ping_slot_dr(self) -> typing.Optional[jsii.Number]:
            '''The PingSlotDR value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html#cfn-iotwireless-deviceprofile-lorawandeviceprofile-pingslotdr
            '''
            result = self._values.get("ping_slot_dr")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def ping_slot_freq(self) -> typing.Optional[jsii.Number]:
            '''The PingSlotFreq value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html#cfn-iotwireless-deviceprofile-lorawandeviceprofile-pingslotfreq
            '''
            result = self._values.get("ping_slot_freq")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def ping_slot_period(self) -> typing.Optional[jsii.Number]:
            '''The PingSlotPeriod value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html#cfn-iotwireless-deviceprofile-lorawandeviceprofile-pingslotperiod
            '''
            result = self._values.get("ping_slot_period")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def reg_params_revision(self) -> typing.Optional[builtins.str]:
            '''The version of regional parameters.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html#cfn-iotwireless-deviceprofile-lorawandeviceprofile-regparamsrevision
            '''
            result = self._values.get("reg_params_revision")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def rf_region(self) -> typing.Optional[builtins.str]:
            '''The frequency band (RFRegion) value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html#cfn-iotwireless-deviceprofile-lorawandeviceprofile-rfregion
            '''
            result = self._values.get("rf_region")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def supports32_bit_f_cnt(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The Supports32BitFCnt value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html#cfn-iotwireless-deviceprofile-lorawandeviceprofile-supports32bitfcnt
            '''
            result = self._values.get("supports32_bit_f_cnt")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def supports_class_b(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The SupportsClassB value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html#cfn-iotwireless-deviceprofile-lorawandeviceprofile-supportsclassb
            '''
            result = self._values.get("supports_class_b")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def supports_class_c(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The SupportsClassC value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html#cfn-iotwireless-deviceprofile-lorawandeviceprofile-supportsclassc
            '''
            result = self._values.get("supports_class_c")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def supports_join(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The SupportsJoin value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-deviceprofile-lorawandeviceprofile.html#cfn-iotwireless-deviceprofile-lorawandeviceprofile-supportsjoin
            '''
            result = self._values.get("supports_join")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoRaWANDeviceProfileProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnDeviceProfileProps",
    jsii_struct_bases=[],
    name_mapping={"lo_ra_wan": "loRaWan", "name": "name", "tags": "tags"},
)
class CfnDeviceProfileProps:
    def __init__(
        self,
        *,
        lo_ra_wan: typing.Optional[typing.Union[CfnDeviceProfile.LoRaWANDeviceProfileProperty, _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDeviceProfile``.

        :param lo_ra_wan: LoRaWAN device profile object.
        :param name: The name of the new resource.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-deviceprofile.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotwireless as iotwireless
            
            cfn_device_profile_props = iotwireless.CfnDeviceProfileProps(
                lo_ra_wan=iotwireless.CfnDeviceProfile.LoRaWANDeviceProfileProperty(
                    class_bTimeout=123,
                    class_cTimeout=123,
                    mac_version="macVersion",
                    max_duty_cycle=123,
                    max_eirp=123,
                    ping_slot_dr=123,
                    ping_slot_freq=123,
                    ping_slot_period=123,
                    reg_params_revision="regParamsRevision",
                    rf_region="rfRegion",
                    supports32_bit_fCnt=False,
                    supports_class_b=False,
                    supports_class_c=False,
                    supports_join=False
                ),
                name="name",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if lo_ra_wan is not None:
            self._values["lo_ra_wan"] = lo_ra_wan
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def lo_ra_wan(
        self,
    ) -> typing.Optional[typing.Union[CfnDeviceProfile.LoRaWANDeviceProfileProperty, _IResolvable_da3f097b]]:
        '''LoRaWAN device profile object.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-deviceprofile.html#cfn-iotwireless-deviceprofile-lorawan
        '''
        result = self._values.get("lo_ra_wan")
        return typing.cast(typing.Optional[typing.Union[CfnDeviceProfile.LoRaWANDeviceProfileProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-deviceprofile.html#cfn-iotwireless-deviceprofile-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-deviceprofile.html#cfn-iotwireless-deviceprofile-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDeviceProfileProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnFuotaTask(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnFuotaTask",
):
    '''A CloudFormation ``AWS::IoTWireless::FuotaTask``.

    A FUOTA task.

    :cloudformationResource: AWS::IoTWireless::FuotaTask
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotwireless as iotwireless
        
        cfn_fuota_task = iotwireless.CfnFuotaTask(self, "MyCfnFuotaTask",
            firmware_update_image="firmwareUpdateImage",
            firmware_update_role="firmwareUpdateRole",
            lo_ra_wan=iotwireless.CfnFuotaTask.LoRaWANProperty(
                rf_region="rfRegion",
        
                # the properties below are optional
                start_time="startTime"
            ),
        
            # the properties below are optional
            associate_multicast_group="associateMulticastGroup",
            associate_wireless_device="associateWirelessDevice",
            description="description",
            disassociate_multicast_group="disassociateMulticastGroup",
            disassociate_wireless_device="disassociateWirelessDevice",
            name="name",
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
        firmware_update_image: builtins.str,
        firmware_update_role: builtins.str,
        lo_ra_wan: typing.Union["CfnFuotaTask.LoRaWANProperty", _IResolvable_da3f097b],
        associate_multicast_group: typing.Optional[builtins.str] = None,
        associate_wireless_device: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        disassociate_multicast_group: typing.Optional[builtins.str] = None,
        disassociate_wireless_device: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::IoTWireless::FuotaTask``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param firmware_update_image: The S3 URI points to a firmware update image that is to be used with a FUOTA task.
        :param firmware_update_role: The firmware update role that is to be used with a FUOTA task.
        :param lo_ra_wan: The LoRaWAN information used with a FUOTA task.
        :param associate_multicast_group: The ID of the multicast group to associate with a FUOTA task.
        :param associate_wireless_device: The ID of the wireless device to associate with a multicast group.
        :param description: The description of the new resource.
        :param disassociate_multicast_group: The ID of the multicast group to disassociate from a FUOTA task.
        :param disassociate_wireless_device: The ID of the wireless device to disassociate from a FUOTA task.
        :param name: The name of a FUOTA task.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.
        '''
        props = CfnFuotaTaskProps(
            firmware_update_image=firmware_update_image,
            firmware_update_role=firmware_update_role,
            lo_ra_wan=lo_ra_wan,
            associate_multicast_group=associate_multicast_group,
            associate_wireless_device=associate_wireless_device,
            description=description,
            disassociate_multicast_group=disassociate_multicast_group,
            disassociate_wireless_device=disassociate_wireless_device,
            name=name,
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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The ARN of a FUOTA task.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrFuotaTaskStatus")
    def attr_fuota_task_status(self) -> builtins.str:
        '''The status of a FUOTA task.

        :cloudformationAttribute: FuotaTaskStatus
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrFuotaTaskStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of a FUOTA task.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanStartTime")
    def attr_lo_ra_wan_start_time(self) -> builtins.str:
        '''Start time of a FUOTA task.

        :cloudformationAttribute: LoRaWAN.StartTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLoRaWanStartTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="firmwareUpdateImage")
    def firmware_update_image(self) -> builtins.str:
        '''The S3 URI points to a firmware update image that is to be used with a FUOTA task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-firmwareupdateimage
        '''
        return typing.cast(builtins.str, jsii.get(self, "firmwareUpdateImage"))

    @firmware_update_image.setter
    def firmware_update_image(self, value: builtins.str) -> None:
        jsii.set(self, "firmwareUpdateImage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="firmwareUpdateRole")
    def firmware_update_role(self) -> builtins.str:
        '''The firmware update role that is to be used with a FUOTA task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-firmwareupdaterole
        '''
        return typing.cast(builtins.str, jsii.get(self, "firmwareUpdateRole"))

    @firmware_update_role.setter
    def firmware_update_role(self, value: builtins.str) -> None:
        jsii.set(self, "firmwareUpdateRole", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loRaWan")
    def lo_ra_wan(
        self,
    ) -> typing.Union["CfnFuotaTask.LoRaWANProperty", _IResolvable_da3f097b]:
        '''The LoRaWAN information used with a FUOTA task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-lorawan
        '''
        return typing.cast(typing.Union["CfnFuotaTask.LoRaWANProperty", _IResolvable_da3f097b], jsii.get(self, "loRaWan"))

    @lo_ra_wan.setter
    def lo_ra_wan(
        self,
        value: typing.Union["CfnFuotaTask.LoRaWANProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "loRaWan", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="associateMulticastGroup")
    def associate_multicast_group(self) -> typing.Optional[builtins.str]:
        '''The ID of the multicast group to associate with a FUOTA task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-associatemulticastgroup
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "associateMulticastGroup"))

    @associate_multicast_group.setter
    def associate_multicast_group(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "associateMulticastGroup", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="associateWirelessDevice")
    def associate_wireless_device(self) -> typing.Optional[builtins.str]:
        '''The ID of the wireless device to associate with a multicast group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-associatewirelessdevice
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "associateWirelessDevice"))

    @associate_wireless_device.setter
    def associate_wireless_device(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "associateWirelessDevice", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="disassociateMulticastGroup")
    def disassociate_multicast_group(self) -> typing.Optional[builtins.str]:
        '''The ID of the multicast group to disassociate from a FUOTA task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-disassociatemulticastgroup
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "disassociateMulticastGroup"))

    @disassociate_multicast_group.setter
    def disassociate_multicast_group(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "disassociateMulticastGroup", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="disassociateWirelessDevice")
    def disassociate_wireless_device(self) -> typing.Optional[builtins.str]:
        '''The ID of the wireless device to disassociate from a FUOTA task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-disassociatewirelessdevice
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "disassociateWirelessDevice"))

    @disassociate_wireless_device.setter
    def disassociate_wireless_device(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "disassociateWirelessDevice", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of a FUOTA task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnFuotaTask.LoRaWANProperty",
        jsii_struct_bases=[],
        name_mapping={"rf_region": "rfRegion", "start_time": "startTime"},
    )
    class LoRaWANProperty:
        def __init__(
            self,
            *,
            rf_region: builtins.str,
            start_time: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The LoRaWAN information used with a FUOTA task.

            :param rf_region: The frequency band (RFRegion) value.
            :param start_time: Start time of a FUOTA task.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-fuotatask-lorawan.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                lo_ra_wANProperty = iotwireless.CfnFuotaTask.LoRaWANProperty(
                    rf_region="rfRegion",
                
                    # the properties below are optional
                    start_time="startTime"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "rf_region": rf_region,
            }
            if start_time is not None:
                self._values["start_time"] = start_time

        @builtins.property
        def rf_region(self) -> builtins.str:
            '''The frequency band (RFRegion) value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-fuotatask-lorawan.html#cfn-iotwireless-fuotatask-lorawan-rfregion
            '''
            result = self._values.get("rf_region")
            assert result is not None, "Required property 'rf_region' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def start_time(self) -> typing.Optional[builtins.str]:
            '''Start time of a FUOTA task.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-fuotatask-lorawan.html#cfn-iotwireless-fuotatask-lorawan-starttime
            '''
            result = self._values.get("start_time")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoRaWANProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnFuotaTaskProps",
    jsii_struct_bases=[],
    name_mapping={
        "firmware_update_image": "firmwareUpdateImage",
        "firmware_update_role": "firmwareUpdateRole",
        "lo_ra_wan": "loRaWan",
        "associate_multicast_group": "associateMulticastGroup",
        "associate_wireless_device": "associateWirelessDevice",
        "description": "description",
        "disassociate_multicast_group": "disassociateMulticastGroup",
        "disassociate_wireless_device": "disassociateWirelessDevice",
        "name": "name",
        "tags": "tags",
    },
)
class CfnFuotaTaskProps:
    def __init__(
        self,
        *,
        firmware_update_image: builtins.str,
        firmware_update_role: builtins.str,
        lo_ra_wan: typing.Union[CfnFuotaTask.LoRaWANProperty, _IResolvable_da3f097b],
        associate_multicast_group: typing.Optional[builtins.str] = None,
        associate_wireless_device: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        disassociate_multicast_group: typing.Optional[builtins.str] = None,
        disassociate_wireless_device: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnFuotaTask``.

        :param firmware_update_image: The S3 URI points to a firmware update image that is to be used with a FUOTA task.
        :param firmware_update_role: The firmware update role that is to be used with a FUOTA task.
        :param lo_ra_wan: The LoRaWAN information used with a FUOTA task.
        :param associate_multicast_group: The ID of the multicast group to associate with a FUOTA task.
        :param associate_wireless_device: The ID of the wireless device to associate with a multicast group.
        :param description: The description of the new resource.
        :param disassociate_multicast_group: The ID of the multicast group to disassociate from a FUOTA task.
        :param disassociate_wireless_device: The ID of the wireless device to disassociate from a FUOTA task.
        :param name: The name of a FUOTA task.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotwireless as iotwireless
            
            cfn_fuota_task_props = iotwireless.CfnFuotaTaskProps(
                firmware_update_image="firmwareUpdateImage",
                firmware_update_role="firmwareUpdateRole",
                lo_ra_wan=iotwireless.CfnFuotaTask.LoRaWANProperty(
                    rf_region="rfRegion",
            
                    # the properties below are optional
                    start_time="startTime"
                ),
            
                # the properties below are optional
                associate_multicast_group="associateMulticastGroup",
                associate_wireless_device="associateWirelessDevice",
                description="description",
                disassociate_multicast_group="disassociateMulticastGroup",
                disassociate_wireless_device="disassociateWirelessDevice",
                name="name",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "firmware_update_image": firmware_update_image,
            "firmware_update_role": firmware_update_role,
            "lo_ra_wan": lo_ra_wan,
        }
        if associate_multicast_group is not None:
            self._values["associate_multicast_group"] = associate_multicast_group
        if associate_wireless_device is not None:
            self._values["associate_wireless_device"] = associate_wireless_device
        if description is not None:
            self._values["description"] = description
        if disassociate_multicast_group is not None:
            self._values["disassociate_multicast_group"] = disassociate_multicast_group
        if disassociate_wireless_device is not None:
            self._values["disassociate_wireless_device"] = disassociate_wireless_device
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def firmware_update_image(self) -> builtins.str:
        '''The S3 URI points to a firmware update image that is to be used with a FUOTA task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-firmwareupdateimage
        '''
        result = self._values.get("firmware_update_image")
        assert result is not None, "Required property 'firmware_update_image' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def firmware_update_role(self) -> builtins.str:
        '''The firmware update role that is to be used with a FUOTA task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-firmwareupdaterole
        '''
        result = self._values.get("firmware_update_role")
        assert result is not None, "Required property 'firmware_update_role' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def lo_ra_wan(
        self,
    ) -> typing.Union[CfnFuotaTask.LoRaWANProperty, _IResolvable_da3f097b]:
        '''The LoRaWAN information used with a FUOTA task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-lorawan
        '''
        result = self._values.get("lo_ra_wan")
        assert result is not None, "Required property 'lo_ra_wan' is missing"
        return typing.cast(typing.Union[CfnFuotaTask.LoRaWANProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def associate_multicast_group(self) -> typing.Optional[builtins.str]:
        '''The ID of the multicast group to associate with a FUOTA task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-associatemulticastgroup
        '''
        result = self._values.get("associate_multicast_group")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def associate_wireless_device(self) -> typing.Optional[builtins.str]:
        '''The ID of the wireless device to associate with a multicast group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-associatewirelessdevice
        '''
        result = self._values.get("associate_wireless_device")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def disassociate_multicast_group(self) -> typing.Optional[builtins.str]:
        '''The ID of the multicast group to disassociate from a FUOTA task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-disassociatemulticastgroup
        '''
        result = self._values.get("disassociate_multicast_group")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def disassociate_wireless_device(self) -> typing.Optional[builtins.str]:
        '''The ID of the wireless device to disassociate from a FUOTA task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-disassociatewirelessdevice
        '''
        result = self._values.get("disassociate_wireless_device")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of a FUOTA task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-fuotatask.html#cfn-iotwireless-fuotatask-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnFuotaTaskProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnMulticastGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnMulticastGroup",
):
    '''A CloudFormation ``AWS::IoTWireless::MulticastGroup``.

    A multicast group.

    :cloudformationResource: AWS::IoTWireless::MulticastGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-multicastgroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotwireless as iotwireless
        
        cfn_multicast_group = iotwireless.CfnMulticastGroup(self, "MyCfnMulticastGroup",
            lo_ra_wan=iotwireless.CfnMulticastGroup.LoRaWANProperty(
                dl_class="dlClass",
                rf_region="rfRegion",
        
                # the properties below are optional
                number_of_devices_in_group=123,
                number_of_devices_requested=123
            ),
        
            # the properties below are optional
            associate_wireless_device="associateWirelessDevice",
            description="description",
            disassociate_wireless_device="disassociateWirelessDevice",
            name="name",
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
        lo_ra_wan: typing.Union["CfnMulticastGroup.LoRaWANProperty", _IResolvable_da3f097b],
        associate_wireless_device: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        disassociate_wireless_device: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::IoTWireless::MulticastGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param lo_ra_wan: The LoRaWAN information that is to be used with the multicast group.
        :param associate_wireless_device: The ID of the wireless device to associate with a multicast group.
        :param description: The description of the multicast group.
        :param disassociate_wireless_device: The ID of the wireless device to disassociate from a multicast group.
        :param name: The name of the multicast group.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.
        '''
        props = CfnMulticastGroupProps(
            lo_ra_wan=lo_ra_wan,
            associate_wireless_device=associate_wireless_device,
            description=description,
            disassociate_wireless_device=disassociate_wireless_device,
            name=name,
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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The ARN of the multicast group.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the multicast group.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanNumberOfDevicesInGroup")
    def attr_lo_ra_wan_number_of_devices_in_group(self) -> jsii.Number:
        '''The number of devices that are associated to the multicast group.

        :cloudformationAttribute: LoRaWAN.NumberOfDevicesInGroup
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrLoRaWanNumberOfDevicesInGroup"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanNumberOfDevicesRequested")
    def attr_lo_ra_wan_number_of_devices_requested(self) -> jsii.Number:
        '''The number of devices that are requested to be associated with the multicast group.

        :cloudformationAttribute: LoRaWAN.NumberOfDevicesRequested
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrLoRaWanNumberOfDevicesRequested"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStatus")
    def attr_status(self) -> builtins.str:
        '''The status of a multicast group.

        :cloudformationAttribute: Status
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-multicastgroup.html#cfn-iotwireless-multicastgroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loRaWan")
    def lo_ra_wan(
        self,
    ) -> typing.Union["CfnMulticastGroup.LoRaWANProperty", _IResolvable_da3f097b]:
        '''The LoRaWAN information that is to be used with the multicast group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-multicastgroup.html#cfn-iotwireless-multicastgroup-lorawan
        '''
        return typing.cast(typing.Union["CfnMulticastGroup.LoRaWANProperty", _IResolvable_da3f097b], jsii.get(self, "loRaWan"))

    @lo_ra_wan.setter
    def lo_ra_wan(
        self,
        value: typing.Union["CfnMulticastGroup.LoRaWANProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "loRaWan", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="associateWirelessDevice")
    def associate_wireless_device(self) -> typing.Optional[builtins.str]:
        '''The ID of the wireless device to associate with a multicast group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-multicastgroup.html#cfn-iotwireless-multicastgroup-associatewirelessdevice
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "associateWirelessDevice"))

    @associate_wireless_device.setter
    def associate_wireless_device(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "associateWirelessDevice", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the multicast group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-multicastgroup.html#cfn-iotwireless-multicastgroup-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="disassociateWirelessDevice")
    def disassociate_wireless_device(self) -> typing.Optional[builtins.str]:
        '''The ID of the wireless device to disassociate from a multicast group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-multicastgroup.html#cfn-iotwireless-multicastgroup-disassociatewirelessdevice
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "disassociateWirelessDevice"))

    @disassociate_wireless_device.setter
    def disassociate_wireless_device(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "disassociateWirelessDevice", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the multicast group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-multicastgroup.html#cfn-iotwireless-multicastgroup-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnMulticastGroup.LoRaWANProperty",
        jsii_struct_bases=[],
        name_mapping={
            "dl_class": "dlClass",
            "rf_region": "rfRegion",
            "number_of_devices_in_group": "numberOfDevicesInGroup",
            "number_of_devices_requested": "numberOfDevicesRequested",
        },
    )
    class LoRaWANProperty:
        def __init__(
            self,
            *,
            dl_class: builtins.str,
            rf_region: builtins.str,
            number_of_devices_in_group: typing.Optional[jsii.Number] = None,
            number_of_devices_requested: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The LoRaWAN information that is to be used with the multicast group.

            :param dl_class: DlClass for LoRaWAN. Valid values are ClassB and ClassC.
            :param rf_region: The frequency band (RFRegion) value.
            :param number_of_devices_in_group: Number of devices that are associated to the multicast group.
            :param number_of_devices_requested: Number of devices that are requested to be associated with the multicast group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-multicastgroup-lorawan.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                lo_ra_wANProperty = iotwireless.CfnMulticastGroup.LoRaWANProperty(
                    dl_class="dlClass",
                    rf_region="rfRegion",
                
                    # the properties below are optional
                    number_of_devices_in_group=123,
                    number_of_devices_requested=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "dl_class": dl_class,
                "rf_region": rf_region,
            }
            if number_of_devices_in_group is not None:
                self._values["number_of_devices_in_group"] = number_of_devices_in_group
            if number_of_devices_requested is not None:
                self._values["number_of_devices_requested"] = number_of_devices_requested

        @builtins.property
        def dl_class(self) -> builtins.str:
            '''DlClass for LoRaWAN.

            Valid values are ClassB and ClassC.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-multicastgroup-lorawan.html#cfn-iotwireless-multicastgroup-lorawan-dlclass
            '''
            result = self._values.get("dl_class")
            assert result is not None, "Required property 'dl_class' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def rf_region(self) -> builtins.str:
            '''The frequency band (RFRegion) value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-multicastgroup-lorawan.html#cfn-iotwireless-multicastgroup-lorawan-rfregion
            '''
            result = self._values.get("rf_region")
            assert result is not None, "Required property 'rf_region' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def number_of_devices_in_group(self) -> typing.Optional[jsii.Number]:
            '''Number of devices that are associated to the multicast group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-multicastgroup-lorawan.html#cfn-iotwireless-multicastgroup-lorawan-numberofdevicesingroup
            '''
            result = self._values.get("number_of_devices_in_group")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def number_of_devices_requested(self) -> typing.Optional[jsii.Number]:
            '''Number of devices that are requested to be associated with the multicast group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-multicastgroup-lorawan.html#cfn-iotwireless-multicastgroup-lorawan-numberofdevicesrequested
            '''
            result = self._values.get("number_of_devices_requested")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoRaWANProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnMulticastGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "lo_ra_wan": "loRaWan",
        "associate_wireless_device": "associateWirelessDevice",
        "description": "description",
        "disassociate_wireless_device": "disassociateWirelessDevice",
        "name": "name",
        "tags": "tags",
    },
)
class CfnMulticastGroupProps:
    def __init__(
        self,
        *,
        lo_ra_wan: typing.Union[CfnMulticastGroup.LoRaWANProperty, _IResolvable_da3f097b],
        associate_wireless_device: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        disassociate_wireless_device: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnMulticastGroup``.

        :param lo_ra_wan: The LoRaWAN information that is to be used with the multicast group.
        :param associate_wireless_device: The ID of the wireless device to associate with a multicast group.
        :param description: The description of the multicast group.
        :param disassociate_wireless_device: The ID of the wireless device to disassociate from a multicast group.
        :param name: The name of the multicast group.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-multicastgroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotwireless as iotwireless
            
            cfn_multicast_group_props = iotwireless.CfnMulticastGroupProps(
                lo_ra_wan=iotwireless.CfnMulticastGroup.LoRaWANProperty(
                    dl_class="dlClass",
                    rf_region="rfRegion",
            
                    # the properties below are optional
                    number_of_devices_in_group=123,
                    number_of_devices_requested=123
                ),
            
                # the properties below are optional
                associate_wireless_device="associateWirelessDevice",
                description="description",
                disassociate_wireless_device="disassociateWirelessDevice",
                name="name",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "lo_ra_wan": lo_ra_wan,
        }
        if associate_wireless_device is not None:
            self._values["associate_wireless_device"] = associate_wireless_device
        if description is not None:
            self._values["description"] = description
        if disassociate_wireless_device is not None:
            self._values["disassociate_wireless_device"] = disassociate_wireless_device
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def lo_ra_wan(
        self,
    ) -> typing.Union[CfnMulticastGroup.LoRaWANProperty, _IResolvable_da3f097b]:
        '''The LoRaWAN information that is to be used with the multicast group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-multicastgroup.html#cfn-iotwireless-multicastgroup-lorawan
        '''
        result = self._values.get("lo_ra_wan")
        assert result is not None, "Required property 'lo_ra_wan' is missing"
        return typing.cast(typing.Union[CfnMulticastGroup.LoRaWANProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def associate_wireless_device(self) -> typing.Optional[builtins.str]:
        '''The ID of the wireless device to associate with a multicast group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-multicastgroup.html#cfn-iotwireless-multicastgroup-associatewirelessdevice
        '''
        result = self._values.get("associate_wireless_device")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the multicast group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-multicastgroup.html#cfn-iotwireless-multicastgroup-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def disassociate_wireless_device(self) -> typing.Optional[builtins.str]:
        '''The ID of the wireless device to disassociate from a multicast group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-multicastgroup.html#cfn-iotwireless-multicastgroup-disassociatewirelessdevice
        '''
        result = self._values.get("disassociate_wireless_device")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the multicast group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-multicastgroup.html#cfn-iotwireless-multicastgroup-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-multicastgroup.html#cfn-iotwireless-multicastgroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnMulticastGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnPartnerAccount(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnPartnerAccount",
):
    '''A CloudFormation ``AWS::IoTWireless::PartnerAccount``.

    A partner account. If ``PartnerAccountId`` and ``PartnerType`` are ``null`` , returns all partner accounts.

    :cloudformationResource: AWS::IoTWireless::PartnerAccount
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotwireless as iotwireless
        
        cfn_partner_account = iotwireless.CfnPartnerAccount(self, "MyCfnPartnerAccount",
            account_linked=False,
            fingerprint="fingerprint",
            partner_account_id="partnerAccountId",
            partner_type="partnerType",
            sidewalk=iotwireless.CfnPartnerAccount.SidewalkAccountInfoProperty(
                app_server_private_key="appServerPrivateKey"
            ),
            sidewalk_update=iotwireless.CfnPartnerAccount.SidewalkUpdateAccountProperty(
                app_server_private_key="appServerPrivateKey"
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
        account_linked: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        fingerprint: typing.Optional[builtins.str] = None,
        partner_account_id: typing.Optional[builtins.str] = None,
        partner_type: typing.Optional[builtins.str] = None,
        sidewalk: typing.Optional[typing.Union["CfnPartnerAccount.SidewalkAccountInfoProperty", _IResolvable_da3f097b]] = None,
        sidewalk_update: typing.Optional[typing.Union["CfnPartnerAccount.SidewalkUpdateAccountProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::IoTWireless::PartnerAccount``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param account_linked: ``AWS::IoTWireless::PartnerAccount.AccountLinked``.
        :param fingerprint: ``AWS::IoTWireless::PartnerAccount.Fingerprint``.
        :param partner_account_id: The ID of the partner account to update.
        :param partner_type: ``AWS::IoTWireless::PartnerAccount.PartnerType``.
        :param sidewalk: The Sidewalk account credentials.
        :param sidewalk_update: ``AWS::IoTWireless::PartnerAccount.SidewalkUpdate``.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.
        '''
        props = CfnPartnerAccountProps(
            account_linked=account_linked,
            fingerprint=fingerprint,
            partner_account_id=partner_account_id,
            partner_type=partner_type,
            sidewalk=sidewalk,
            sidewalk_update=sidewalk_update,
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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the resource.

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
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html#cfn-iotwireless-partneraccount-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accountLinked")
    def account_linked(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''``AWS::IoTWireless::PartnerAccount.AccountLinked``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html#cfn-iotwireless-partneraccount-accountlinked
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "accountLinked"))

    @account_linked.setter
    def account_linked(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "accountLinked", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fingerprint")
    def fingerprint(self) -> typing.Optional[builtins.str]:
        '''``AWS::IoTWireless::PartnerAccount.Fingerprint``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html#cfn-iotwireless-partneraccount-fingerprint
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "fingerprint"))

    @fingerprint.setter
    def fingerprint(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "fingerprint", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="partnerAccountId")
    def partner_account_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the partner account to update.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html#cfn-iotwireless-partneraccount-partneraccountid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "partnerAccountId"))

    @partner_account_id.setter
    def partner_account_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "partnerAccountId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="partnerType")
    def partner_type(self) -> typing.Optional[builtins.str]:
        '''``AWS::IoTWireless::PartnerAccount.PartnerType``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html#cfn-iotwireless-partneraccount-partnertype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "partnerType"))

    @partner_type.setter
    def partner_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "partnerType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sidewalk")
    def sidewalk(
        self,
    ) -> typing.Optional[typing.Union["CfnPartnerAccount.SidewalkAccountInfoProperty", _IResolvable_da3f097b]]:
        '''The Sidewalk account credentials.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html#cfn-iotwireless-partneraccount-sidewalk
        '''
        return typing.cast(typing.Optional[typing.Union["CfnPartnerAccount.SidewalkAccountInfoProperty", _IResolvable_da3f097b]], jsii.get(self, "sidewalk"))

    @sidewalk.setter
    def sidewalk(
        self,
        value: typing.Optional[typing.Union["CfnPartnerAccount.SidewalkAccountInfoProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "sidewalk", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sidewalkUpdate")
    def sidewalk_update(
        self,
    ) -> typing.Optional[typing.Union["CfnPartnerAccount.SidewalkUpdateAccountProperty", _IResolvable_da3f097b]]:
        '''``AWS::IoTWireless::PartnerAccount.SidewalkUpdate``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html#cfn-iotwireless-partneraccount-sidewalkupdate
        '''
        return typing.cast(typing.Optional[typing.Union["CfnPartnerAccount.SidewalkUpdateAccountProperty", _IResolvable_da3f097b]], jsii.get(self, "sidewalkUpdate"))

    @sidewalk_update.setter
    def sidewalk_update(
        self,
        value: typing.Optional[typing.Union["CfnPartnerAccount.SidewalkUpdateAccountProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "sidewalkUpdate", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnPartnerAccount.SidewalkAccountInfoProperty",
        jsii_struct_bases=[],
        name_mapping={"app_server_private_key": "appServerPrivateKey"},
    )
    class SidewalkAccountInfoProperty:
        def __init__(self, *, app_server_private_key: builtins.str) -> None:
            '''Information about a Sidewalk account.

            :param app_server_private_key: The Sidewalk application server private key. The application server private key is a secret key, which you should handle in a similar way as you would an application password. You can protect the application server private key by storing the value in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-partneraccount-sidewalkaccountinfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                sidewalk_account_info_property = iotwireless.CfnPartnerAccount.SidewalkAccountInfoProperty(
                    app_server_private_key="appServerPrivateKey"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "app_server_private_key": app_server_private_key,
            }

        @builtins.property
        def app_server_private_key(self) -> builtins.str:
            '''The Sidewalk application server private key.

            The application server private key is a secret key, which you should handle in a similar way as you would an application password. You can protect the application server private key by storing the value in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-partneraccount-sidewalkaccountinfo.html#cfn-iotwireless-partneraccount-sidewalkaccountinfo-appserverprivatekey
            '''
            result = self._values.get("app_server_private_key")
            assert result is not None, "Required property 'app_server_private_key' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SidewalkAccountInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnPartnerAccount.SidewalkUpdateAccountProperty",
        jsii_struct_bases=[],
        name_mapping={"app_server_private_key": "appServerPrivateKey"},
    )
    class SidewalkUpdateAccountProperty:
        def __init__(
            self,
            *,
            app_server_private_key: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Sidewalk update.

            :param app_server_private_key: The new Sidewalk application server private key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-partneraccount-sidewalkupdateaccount.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                sidewalk_update_account_property = iotwireless.CfnPartnerAccount.SidewalkUpdateAccountProperty(
                    app_server_private_key="appServerPrivateKey"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if app_server_private_key is not None:
                self._values["app_server_private_key"] = app_server_private_key

        @builtins.property
        def app_server_private_key(self) -> typing.Optional[builtins.str]:
            '''The new Sidewalk application server private key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-partneraccount-sidewalkupdateaccount.html#cfn-iotwireless-partneraccount-sidewalkupdateaccount-appserverprivatekey
            '''
            result = self._values.get("app_server_private_key")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SidewalkUpdateAccountProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnPartnerAccountProps",
    jsii_struct_bases=[],
    name_mapping={
        "account_linked": "accountLinked",
        "fingerprint": "fingerprint",
        "partner_account_id": "partnerAccountId",
        "partner_type": "partnerType",
        "sidewalk": "sidewalk",
        "sidewalk_update": "sidewalkUpdate",
        "tags": "tags",
    },
)
class CfnPartnerAccountProps:
    def __init__(
        self,
        *,
        account_linked: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        fingerprint: typing.Optional[builtins.str] = None,
        partner_account_id: typing.Optional[builtins.str] = None,
        partner_type: typing.Optional[builtins.str] = None,
        sidewalk: typing.Optional[typing.Union[CfnPartnerAccount.SidewalkAccountInfoProperty, _IResolvable_da3f097b]] = None,
        sidewalk_update: typing.Optional[typing.Union[CfnPartnerAccount.SidewalkUpdateAccountProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnPartnerAccount``.

        :param account_linked: ``AWS::IoTWireless::PartnerAccount.AccountLinked``.
        :param fingerprint: ``AWS::IoTWireless::PartnerAccount.Fingerprint``.
        :param partner_account_id: The ID of the partner account to update.
        :param partner_type: ``AWS::IoTWireless::PartnerAccount.PartnerType``.
        :param sidewalk: The Sidewalk account credentials.
        :param sidewalk_update: ``AWS::IoTWireless::PartnerAccount.SidewalkUpdate``.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotwireless as iotwireless
            
            cfn_partner_account_props = iotwireless.CfnPartnerAccountProps(
                account_linked=False,
                fingerprint="fingerprint",
                partner_account_id="partnerAccountId",
                partner_type="partnerType",
                sidewalk=iotwireless.CfnPartnerAccount.SidewalkAccountInfoProperty(
                    app_server_private_key="appServerPrivateKey"
                ),
                sidewalk_update=iotwireless.CfnPartnerAccount.SidewalkUpdateAccountProperty(
                    app_server_private_key="appServerPrivateKey"
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if account_linked is not None:
            self._values["account_linked"] = account_linked
        if fingerprint is not None:
            self._values["fingerprint"] = fingerprint
        if partner_account_id is not None:
            self._values["partner_account_id"] = partner_account_id
        if partner_type is not None:
            self._values["partner_type"] = partner_type
        if sidewalk is not None:
            self._values["sidewalk"] = sidewalk
        if sidewalk_update is not None:
            self._values["sidewalk_update"] = sidewalk_update
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def account_linked(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''``AWS::IoTWireless::PartnerAccount.AccountLinked``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html#cfn-iotwireless-partneraccount-accountlinked
        '''
        result = self._values.get("account_linked")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def fingerprint(self) -> typing.Optional[builtins.str]:
        '''``AWS::IoTWireless::PartnerAccount.Fingerprint``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html#cfn-iotwireless-partneraccount-fingerprint
        '''
        result = self._values.get("fingerprint")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def partner_account_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the partner account to update.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html#cfn-iotwireless-partneraccount-partneraccountid
        '''
        result = self._values.get("partner_account_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def partner_type(self) -> typing.Optional[builtins.str]:
        '''``AWS::IoTWireless::PartnerAccount.PartnerType``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html#cfn-iotwireless-partneraccount-partnertype
        '''
        result = self._values.get("partner_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def sidewalk(
        self,
    ) -> typing.Optional[typing.Union[CfnPartnerAccount.SidewalkAccountInfoProperty, _IResolvable_da3f097b]]:
        '''The Sidewalk account credentials.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html#cfn-iotwireless-partneraccount-sidewalk
        '''
        result = self._values.get("sidewalk")
        return typing.cast(typing.Optional[typing.Union[CfnPartnerAccount.SidewalkAccountInfoProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def sidewalk_update(
        self,
    ) -> typing.Optional[typing.Union[CfnPartnerAccount.SidewalkUpdateAccountProperty, _IResolvable_da3f097b]]:
        '''``AWS::IoTWireless::PartnerAccount.SidewalkUpdate``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html#cfn-iotwireless-partneraccount-sidewalkupdate
        '''
        result = self._values.get("sidewalk_update")
        return typing.cast(typing.Optional[typing.Union[CfnPartnerAccount.SidewalkUpdateAccountProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-partneraccount.html#cfn-iotwireless-partneraccount-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPartnerAccountProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnServiceProfile(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnServiceProfile",
):
    '''A CloudFormation ``AWS::IoTWireless::ServiceProfile``.

    Creates a new service profile.

    :cloudformationResource: AWS::IoTWireless::ServiceProfile
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-serviceprofile.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotwireless as iotwireless
        
        cfn_service_profile = iotwireless.CfnServiceProfile(self, "MyCfnServiceProfile",
            lo_ra_wan=iotwireless.CfnServiceProfile.LoRaWANServiceProfileProperty(
                add_gw_metadata=False,
                channel_mask="channelMask",
                dev_status_req_freq=123,
                dl_bucket_size=123,
                dl_rate=123,
                dl_rate_policy="dlRatePolicy",
                dr_max=123,
                dr_min=123,
                hr_allowed=False,
                min_gw_diversity=123,
                nwk_geo_loc=False,
                pr_allowed=False,
                ra_allowed=False,
                report_dev_status_battery=False,
                report_dev_status_margin=False,
                target_per=123,
                ul_bucket_size=123,
                ul_rate=123,
                ul_rate_policy="ulRatePolicy"
            ),
            name="name",
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
        lo_ra_wan: typing.Optional[typing.Union["CfnServiceProfile.LoRaWANServiceProfileProperty", _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::IoTWireless::ServiceProfile``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param lo_ra_wan: LoRaWAN service profile object.
        :param name: The name of the new resource.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.
        '''
        props = CfnServiceProfileProps(lo_ra_wan=lo_ra_wan, name=name, tags=tags)

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
        '''The ARN of the service profile created.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the service profile created.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanChannelMask")
    def attr_lo_ra_wan_channel_mask(self) -> builtins.str:
        '''The ChannelMask value.

        :cloudformationAttribute: LoRaWAN.ChannelMask
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLoRaWanChannelMask"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanDevStatusReqFreq")
    def attr_lo_ra_wan_dev_status_req_freq(self) -> jsii.Number:
        '''The DevStatusReqFreq value.

        :cloudformationAttribute: LoRaWAN.DevStatusReqFreq
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrLoRaWanDevStatusReqFreq"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanDlBucketSize")
    def attr_lo_ra_wan_dl_bucket_size(self) -> jsii.Number:
        '''The DLBucketSize value.

        :cloudformationAttribute: LoRaWAN.DlBucketSize
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrLoRaWanDlBucketSize"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanDlRate")
    def attr_lo_ra_wan_dl_rate(self) -> jsii.Number:
        '''The DLRate value.

        :cloudformationAttribute: LoRaWAN.DlRate
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrLoRaWanDlRate"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanDlRatePolicy")
    def attr_lo_ra_wan_dl_rate_policy(self) -> builtins.str:
        '''The DLRatePolicy value.

        :cloudformationAttribute: LoRaWAN.DlRatePolicy
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLoRaWanDlRatePolicy"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanDrMax")
    def attr_lo_ra_wan_dr_max(self) -> jsii.Number:
        '''The DRMax value.

        :cloudformationAttribute: LoRaWAN.DrMax
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrLoRaWanDrMax"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanDrMin")
    def attr_lo_ra_wan_dr_min(self) -> jsii.Number:
        '''The DRMin value.

        :cloudformationAttribute: LoRaWAN.DrMin
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrLoRaWanDrMin"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanHrAllowed")
    def attr_lo_ra_wan_hr_allowed(self) -> _IResolvable_da3f097b:
        '''The HRAllowed value that describes whether handover roaming is allowed.

        :cloudformationAttribute: LoRaWAN.HrAllowed
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrLoRaWanHrAllowed"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanMinGwDiversity")
    def attr_lo_ra_wan_min_gw_diversity(self) -> jsii.Number:
        '''The MinGwDiversity value.

        :cloudformationAttribute: LoRaWAN.MinGwDiversity
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrLoRaWanMinGwDiversity"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanNwkGeoLoc")
    def attr_lo_ra_wan_nwk_geo_loc(self) -> _IResolvable_da3f097b:
        '''The NwkGeoLoc value.

        :cloudformationAttribute: LoRaWAN.NwkGeoLoc
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrLoRaWanNwkGeoLoc"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanPrAllowed")
    def attr_lo_ra_wan_pr_allowed(self) -> _IResolvable_da3f097b:
        '''The PRAllowed value that describes whether passive roaming is allowed.

        :cloudformationAttribute: LoRaWAN.PrAllowed
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrLoRaWanPrAllowed"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanRaAllowed")
    def attr_lo_ra_wan_ra_allowed(self) -> _IResolvable_da3f097b:
        '''The RAAllowed value that describes whether roaming activation is allowed.

        :cloudformationAttribute: LoRaWAN.RaAllowed
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrLoRaWanRaAllowed"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanReportDevStatusBattery")
    def attr_lo_ra_wan_report_dev_status_battery(self) -> _IResolvable_da3f097b:
        '''The ReportDevStatusBattery value.

        :cloudformationAttribute: LoRaWAN.ReportDevStatusBattery
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrLoRaWanReportDevStatusBattery"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanReportDevStatusMargin")
    def attr_lo_ra_wan_report_dev_status_margin(self) -> _IResolvable_da3f097b:
        '''The ReportDevStatusMargin value.

        :cloudformationAttribute: LoRaWAN.ReportDevStatusMargin
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrLoRaWanReportDevStatusMargin"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanResponse")
    def attr_lo_ra_wan_response(self) -> _IResolvable_da3f097b:
        '''
        :cloudformationAttribute: LoRaWANResponse
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrLoRaWanResponse"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanTargetPer")
    def attr_lo_ra_wan_target_per(self) -> jsii.Number:
        '''The TargetPer value.

        :cloudformationAttribute: LoRaWAN.TargetPer
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrLoRaWanTargetPer"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanUlBucketSize")
    def attr_lo_ra_wan_ul_bucket_size(self) -> jsii.Number:
        '''The UlBucketSize value.

        :cloudformationAttribute: LoRaWAN.UlBucketSize
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrLoRaWanUlBucketSize"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanUlRate")
    def attr_lo_ra_wan_ul_rate(self) -> jsii.Number:
        '''The ULRate value.

        :cloudformationAttribute: LoRaWAN.UlRate
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrLoRaWanUlRate"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoRaWanUlRatePolicy")
    def attr_lo_ra_wan_ul_rate_policy(self) -> builtins.str:
        '''The ULRatePolicy value.

        :cloudformationAttribute: LoRaWAN.UlRatePolicy
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLoRaWanUlRatePolicy"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-serviceprofile.html#cfn-iotwireless-serviceprofile-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loRaWan")
    def lo_ra_wan(
        self,
    ) -> typing.Optional[typing.Union["CfnServiceProfile.LoRaWANServiceProfileProperty", _IResolvable_da3f097b]]:
        '''LoRaWAN service profile object.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-serviceprofile.html#cfn-iotwireless-serviceprofile-lorawan
        '''
        return typing.cast(typing.Optional[typing.Union["CfnServiceProfile.LoRaWANServiceProfileProperty", _IResolvable_da3f097b]], jsii.get(self, "loRaWan"))

    @lo_ra_wan.setter
    def lo_ra_wan(
        self,
        value: typing.Optional[typing.Union["CfnServiceProfile.LoRaWANServiceProfileProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "loRaWan", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-serviceprofile.html#cfn-iotwireless-serviceprofile-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnServiceProfile.LoRaWANServiceProfileProperty",
        jsii_struct_bases=[],
        name_mapping={
            "add_gw_metadata": "addGwMetadata",
            "channel_mask": "channelMask",
            "dev_status_req_freq": "devStatusReqFreq",
            "dl_bucket_size": "dlBucketSize",
            "dl_rate": "dlRate",
            "dl_rate_policy": "dlRatePolicy",
            "dr_max": "drMax",
            "dr_min": "drMin",
            "hr_allowed": "hrAllowed",
            "min_gw_diversity": "minGwDiversity",
            "nwk_geo_loc": "nwkGeoLoc",
            "pr_allowed": "prAllowed",
            "ra_allowed": "raAllowed",
            "report_dev_status_battery": "reportDevStatusBattery",
            "report_dev_status_margin": "reportDevStatusMargin",
            "target_per": "targetPer",
            "ul_bucket_size": "ulBucketSize",
            "ul_rate": "ulRate",
            "ul_rate_policy": "ulRatePolicy",
        },
    )
    class LoRaWANServiceProfileProperty:
        def __init__(
            self,
            *,
            add_gw_metadata: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            channel_mask: typing.Optional[builtins.str] = None,
            dev_status_req_freq: typing.Optional[jsii.Number] = None,
            dl_bucket_size: typing.Optional[jsii.Number] = None,
            dl_rate: typing.Optional[jsii.Number] = None,
            dl_rate_policy: typing.Optional[builtins.str] = None,
            dr_max: typing.Optional[jsii.Number] = None,
            dr_min: typing.Optional[jsii.Number] = None,
            hr_allowed: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            min_gw_diversity: typing.Optional[jsii.Number] = None,
            nwk_geo_loc: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            pr_allowed: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            ra_allowed: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            report_dev_status_battery: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            report_dev_status_margin: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            target_per: typing.Optional[jsii.Number] = None,
            ul_bucket_size: typing.Optional[jsii.Number] = None,
            ul_rate: typing.Optional[jsii.Number] = None,
            ul_rate_policy: typing.Optional[builtins.str] = None,
        ) -> None:
            '''LoRaWANServiceProfile object.

            :param add_gw_metadata: The AddGWMetaData value.
            :param channel_mask: The ChannelMask value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param dev_status_req_freq: The DevStatusReqFreq value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param dl_bucket_size: The DLBucketSize value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param dl_rate: The DLRate value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param dl_rate_policy: The DLRatePolicy value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param dr_max: The DRMax value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param dr_min: The DRMin value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param hr_allowed: The HRAllowed value that describes whether handover roaming is allowed. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param min_gw_diversity: The MinGwDiversity value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param nwk_geo_loc: The NwkGeoLoc value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param pr_allowed: The PRAllowed value that describes whether passive roaming is allowed. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param ra_allowed: The RAAllowed value that describes whether roaming activation is allowed.
            :param report_dev_status_battery: The ReportDevStatusBattery value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param report_dev_status_margin: The ReportDevStatusMargin value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param target_per: The TargetPer value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param ul_bucket_size: The UlBucketSize value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param ul_rate: The ULRate value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``
            :param ul_rate_policy: The ULRatePolicy value. This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                lo_ra_wANService_profile_property = iotwireless.CfnServiceProfile.LoRaWANServiceProfileProperty(
                    add_gw_metadata=False,
                    channel_mask="channelMask",
                    dev_status_req_freq=123,
                    dl_bucket_size=123,
                    dl_rate=123,
                    dl_rate_policy="dlRatePolicy",
                    dr_max=123,
                    dr_min=123,
                    hr_allowed=False,
                    min_gw_diversity=123,
                    nwk_geo_loc=False,
                    pr_allowed=False,
                    ra_allowed=False,
                    report_dev_status_battery=False,
                    report_dev_status_margin=False,
                    target_per=123,
                    ul_bucket_size=123,
                    ul_rate=123,
                    ul_rate_policy="ulRatePolicy"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if add_gw_metadata is not None:
                self._values["add_gw_metadata"] = add_gw_metadata
            if channel_mask is not None:
                self._values["channel_mask"] = channel_mask
            if dev_status_req_freq is not None:
                self._values["dev_status_req_freq"] = dev_status_req_freq
            if dl_bucket_size is not None:
                self._values["dl_bucket_size"] = dl_bucket_size
            if dl_rate is not None:
                self._values["dl_rate"] = dl_rate
            if dl_rate_policy is not None:
                self._values["dl_rate_policy"] = dl_rate_policy
            if dr_max is not None:
                self._values["dr_max"] = dr_max
            if dr_min is not None:
                self._values["dr_min"] = dr_min
            if hr_allowed is not None:
                self._values["hr_allowed"] = hr_allowed
            if min_gw_diversity is not None:
                self._values["min_gw_diversity"] = min_gw_diversity
            if nwk_geo_loc is not None:
                self._values["nwk_geo_loc"] = nwk_geo_loc
            if pr_allowed is not None:
                self._values["pr_allowed"] = pr_allowed
            if ra_allowed is not None:
                self._values["ra_allowed"] = ra_allowed
            if report_dev_status_battery is not None:
                self._values["report_dev_status_battery"] = report_dev_status_battery
            if report_dev_status_margin is not None:
                self._values["report_dev_status_margin"] = report_dev_status_margin
            if target_per is not None:
                self._values["target_per"] = target_per
            if ul_bucket_size is not None:
                self._values["ul_bucket_size"] = ul_bucket_size
            if ul_rate is not None:
                self._values["ul_rate"] = ul_rate
            if ul_rate_policy is not None:
                self._values["ul_rate_policy"] = ul_rate_policy

        @builtins.property
        def add_gw_metadata(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The AddGWMetaData value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-addgwmetadata
            '''
            result = self._values.get("add_gw_metadata")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def channel_mask(self) -> typing.Optional[builtins.str]:
            '''The ChannelMask value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-channelmask
            '''
            result = self._values.get("channel_mask")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def dev_status_req_freq(self) -> typing.Optional[jsii.Number]:
            '''The DevStatusReqFreq value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-devstatusreqfreq
            '''
            result = self._values.get("dev_status_req_freq")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def dl_bucket_size(self) -> typing.Optional[jsii.Number]:
            '''The DLBucketSize value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-dlbucketsize
            '''
            result = self._values.get("dl_bucket_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def dl_rate(self) -> typing.Optional[jsii.Number]:
            '''The DLRate value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-dlrate
            '''
            result = self._values.get("dl_rate")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def dl_rate_policy(self) -> typing.Optional[builtins.str]:
            '''The DLRatePolicy value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-dlratepolicy
            '''
            result = self._values.get("dl_rate_policy")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def dr_max(self) -> typing.Optional[jsii.Number]:
            '''The DRMax value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-drmax
            '''
            result = self._values.get("dr_max")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def dr_min(self) -> typing.Optional[jsii.Number]:
            '''The DRMin value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-drmin
            '''
            result = self._values.get("dr_min")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def hr_allowed(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The HRAllowed value that describes whether handover roaming is allowed.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-hrallowed
            '''
            result = self._values.get("hr_allowed")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def min_gw_diversity(self) -> typing.Optional[jsii.Number]:
            '''The MinGwDiversity value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-mingwdiversity
            '''
            result = self._values.get("min_gw_diversity")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def nwk_geo_loc(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The NwkGeoLoc value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-nwkgeoloc
            '''
            result = self._values.get("nwk_geo_loc")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def pr_allowed(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The PRAllowed value that describes whether passive roaming is allowed.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-prallowed
            '''
            result = self._values.get("pr_allowed")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def ra_allowed(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The RAAllowed value that describes whether roaming activation is allowed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-raallowed
            '''
            result = self._values.get("ra_allowed")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def report_dev_status_battery(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The ReportDevStatusBattery value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-reportdevstatusbattery
            '''
            result = self._values.get("report_dev_status_battery")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def report_dev_status_margin(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The ReportDevStatusMargin value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-reportdevstatusmargin
            '''
            result = self._values.get("report_dev_status_margin")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def target_per(self) -> typing.Optional[jsii.Number]:
            '''The TargetPer value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-targetper
            '''
            result = self._values.get("target_per")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def ul_bucket_size(self) -> typing.Optional[jsii.Number]:
            '''The UlBucketSize value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-ulbucketsize
            '''
            result = self._values.get("ul_bucket_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def ul_rate(self) -> typing.Optional[jsii.Number]:
            '''The ULRate value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-ulrate
            '''
            result = self._values.get("ul_rate")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def ul_rate_policy(self) -> typing.Optional[builtins.str]:
            '''The ULRatePolicy value.

            This property is ``ReadOnly`` and can't be inputted for create. It's returned with ``Fn::GetAtt``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-serviceprofile-lorawanserviceprofile.html#cfn-iotwireless-serviceprofile-lorawanserviceprofile-ulratepolicy
            '''
            result = self._values.get("ul_rate_policy")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoRaWANServiceProfileProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnServiceProfileProps",
    jsii_struct_bases=[],
    name_mapping={"lo_ra_wan": "loRaWan", "name": "name", "tags": "tags"},
)
class CfnServiceProfileProps:
    def __init__(
        self,
        *,
        lo_ra_wan: typing.Optional[typing.Union[CfnServiceProfile.LoRaWANServiceProfileProperty, _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnServiceProfile``.

        :param lo_ra_wan: LoRaWAN service profile object.
        :param name: The name of the new resource.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-serviceprofile.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotwireless as iotwireless
            
            cfn_service_profile_props = iotwireless.CfnServiceProfileProps(
                lo_ra_wan=iotwireless.CfnServiceProfile.LoRaWANServiceProfileProperty(
                    add_gw_metadata=False,
                    channel_mask="channelMask",
                    dev_status_req_freq=123,
                    dl_bucket_size=123,
                    dl_rate=123,
                    dl_rate_policy="dlRatePolicy",
                    dr_max=123,
                    dr_min=123,
                    hr_allowed=False,
                    min_gw_diversity=123,
                    nwk_geo_loc=False,
                    pr_allowed=False,
                    ra_allowed=False,
                    report_dev_status_battery=False,
                    report_dev_status_margin=False,
                    target_per=123,
                    ul_bucket_size=123,
                    ul_rate=123,
                    ul_rate_policy="ulRatePolicy"
                ),
                name="name",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if lo_ra_wan is not None:
            self._values["lo_ra_wan"] = lo_ra_wan
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def lo_ra_wan(
        self,
    ) -> typing.Optional[typing.Union[CfnServiceProfile.LoRaWANServiceProfileProperty, _IResolvable_da3f097b]]:
        '''LoRaWAN service profile object.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-serviceprofile.html#cfn-iotwireless-serviceprofile-lorawan
        '''
        result = self._values.get("lo_ra_wan")
        return typing.cast(typing.Optional[typing.Union[CfnServiceProfile.LoRaWANServiceProfileProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-serviceprofile.html#cfn-iotwireless-serviceprofile-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-serviceprofile.html#cfn-iotwireless-serviceprofile-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnServiceProfileProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnTaskDefinition(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnTaskDefinition",
):
    '''A CloudFormation ``AWS::IoTWireless::TaskDefinition``.

    Creates a gateway task definition.

    :cloudformationResource: AWS::IoTWireless::TaskDefinition
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-taskdefinition.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotwireless as iotwireless
        
        cfn_task_definition = iotwireless.CfnTaskDefinition(self, "MyCfnTaskDefinition",
            auto_create_tasks=False,
        
            # the properties below are optional
            lo_ra_wan_update_gateway_task_entry=iotwireless.CfnTaskDefinition.LoRaWANUpdateGatewayTaskEntryProperty(
                current_version=iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                    model="model",
                    package_version="packageVersion",
                    station="station"
                ),
                update_version=iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                    model="model",
                    package_version="packageVersion",
                    station="station"
                )
            ),
            name="name",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            task_definition_type="taskDefinitionType",
            update=iotwireless.CfnTaskDefinition.UpdateWirelessGatewayTaskCreateProperty(
                lo_ra_wan=iotwireless.CfnTaskDefinition.LoRaWANUpdateGatewayTaskCreateProperty(
                    current_version=iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                        model="model",
                        package_version="packageVersion",
                        station="station"
                    ),
                    sig_key_crc=123,
                    update_signature="updateSignature",
                    update_version=iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                        model="model",
                        package_version="packageVersion",
                        station="station"
                    )
                ),
                update_data_role="updateDataRole",
                update_data_source="updateDataSource"
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        auto_create_tasks: typing.Union[builtins.bool, _IResolvable_da3f097b],
        lo_ra_wan_update_gateway_task_entry: typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANUpdateGatewayTaskEntryProperty", _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        task_definition_type: typing.Optional[builtins.str] = None,
        update: typing.Optional[typing.Union["CfnTaskDefinition.UpdateWirelessGatewayTaskCreateProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::IoTWireless::TaskDefinition``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param auto_create_tasks: Whether to automatically create tasks using this task definition for all gateways with the specified current version. If ``false`` , the task must me created by calling ``CreateWirelessGatewayTask`` .
        :param lo_ra_wan_update_gateway_task_entry: ``AWS::IoTWireless::TaskDefinition.LoRaWANUpdateGatewayTaskEntry``.
        :param name: The name of the new resource.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.
        :param task_definition_type: ``AWS::IoTWireless::TaskDefinition.TaskDefinitionType``.
        :param update: Information about the gateways to update.
        '''
        props = CfnTaskDefinitionProps(
            auto_create_tasks=auto_create_tasks,
            lo_ra_wan_update_gateway_task_entry=lo_ra_wan_update_gateway_task_entry,
            name=name,
            tags=tags,
            task_definition_type=task_definition_type,
            update=update,
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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The Amazon Resource Name of the resource.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the new wireless gateway task definition.

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
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-taskdefinition.html#cfn-iotwireless-taskdefinition-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoCreateTasks")
    def auto_create_tasks(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Whether to automatically create tasks using this task definition for all gateways with the specified current version.

        If ``false`` , the task must me created by calling ``CreateWirelessGatewayTask`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-taskdefinition.html#cfn-iotwireless-taskdefinition-autocreatetasks
        '''
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], jsii.get(self, "autoCreateTasks"))

    @auto_create_tasks.setter
    def auto_create_tasks(
        self,
        value: typing.Union[builtins.bool, _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "autoCreateTasks", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loRaWanUpdateGatewayTaskEntry")
    def lo_ra_wan_update_gateway_task_entry(
        self,
    ) -> typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANUpdateGatewayTaskEntryProperty", _IResolvable_da3f097b]]:
        '''``AWS::IoTWireless::TaskDefinition.LoRaWANUpdateGatewayTaskEntry``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-taskdefinition.html#cfn-iotwireless-taskdefinition-lorawanupdategatewaytaskentry
        '''
        return typing.cast(typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANUpdateGatewayTaskEntryProperty", _IResolvable_da3f097b]], jsii.get(self, "loRaWanUpdateGatewayTaskEntry"))

    @lo_ra_wan_update_gateway_task_entry.setter
    def lo_ra_wan_update_gateway_task_entry(
        self,
        value: typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANUpdateGatewayTaskEntryProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "loRaWanUpdateGatewayTaskEntry", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-taskdefinition.html#cfn-iotwireless-taskdefinition-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="taskDefinitionType")
    def task_definition_type(self) -> typing.Optional[builtins.str]:
        '''``AWS::IoTWireless::TaskDefinition.TaskDefinitionType``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-taskdefinition.html#cfn-iotwireless-taskdefinition-taskdefinitiontype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "taskDefinitionType"))

    @task_definition_type.setter
    def task_definition_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "taskDefinitionType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="update")
    def update(
        self,
    ) -> typing.Optional[typing.Union["CfnTaskDefinition.UpdateWirelessGatewayTaskCreateProperty", _IResolvable_da3f097b]]:
        '''Information about the gateways to update.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-taskdefinition.html#cfn-iotwireless-taskdefinition-update
        '''
        return typing.cast(typing.Optional[typing.Union["CfnTaskDefinition.UpdateWirelessGatewayTaskCreateProperty", _IResolvable_da3f097b]], jsii.get(self, "update"))

    @update.setter
    def update(
        self,
        value: typing.Optional[typing.Union["CfnTaskDefinition.UpdateWirelessGatewayTaskCreateProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "update", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "model": "model",
            "package_version": "packageVersion",
            "station": "station",
        },
    )
    class LoRaWANGatewayVersionProperty:
        def __init__(
            self,
            *,
            model: typing.Optional[builtins.str] = None,
            package_version: typing.Optional[builtins.str] = None,
            station: typing.Optional[builtins.str] = None,
        ) -> None:
            '''LoRaWANGatewayVersion object.

            :param model: The model number of the wireless gateway.
            :param package_version: The version of the wireless gateway firmware.
            :param station: The basic station version of the wireless gateway.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-lorawangatewayversion.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                lo_ra_wANGateway_version_property = iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                    model="model",
                    package_version="packageVersion",
                    station="station"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if model is not None:
                self._values["model"] = model
            if package_version is not None:
                self._values["package_version"] = package_version
            if station is not None:
                self._values["station"] = station

        @builtins.property
        def model(self) -> typing.Optional[builtins.str]:
            '''The model number of the wireless gateway.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-lorawangatewayversion.html#cfn-iotwireless-taskdefinition-lorawangatewayversion-model
            '''
            result = self._values.get("model")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def package_version(self) -> typing.Optional[builtins.str]:
            '''The version of the wireless gateway firmware.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-lorawangatewayversion.html#cfn-iotwireless-taskdefinition-lorawangatewayversion-packageversion
            '''
            result = self._values.get("package_version")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def station(self) -> typing.Optional[builtins.str]:
            '''The basic station version of the wireless gateway.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-lorawangatewayversion.html#cfn-iotwireless-taskdefinition-lorawangatewayversion-station
            '''
            result = self._values.get("station")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoRaWANGatewayVersionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnTaskDefinition.LoRaWANUpdateGatewayTaskCreateProperty",
        jsii_struct_bases=[],
        name_mapping={
            "current_version": "currentVersion",
            "sig_key_crc": "sigKeyCrc",
            "update_signature": "updateSignature",
            "update_version": "updateVersion",
        },
    )
    class LoRaWANUpdateGatewayTaskCreateProperty:
        def __init__(
            self,
            *,
            current_version: typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANGatewayVersionProperty", _IResolvable_da3f097b]] = None,
            sig_key_crc: typing.Optional[jsii.Number] = None,
            update_signature: typing.Optional[builtins.str] = None,
            update_version: typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANGatewayVersionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The signature used to verify the update firmware.

            :param current_version: The version of the gateways that should receive the update.
            :param sig_key_crc: The CRC of the signature private key to check.
            :param update_signature: The signature used to verify the update firmware.
            :param update_version: The firmware version to update the gateway to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-lorawanupdategatewaytaskcreate.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                lo_ra_wANUpdate_gateway_task_create_property = iotwireless.CfnTaskDefinition.LoRaWANUpdateGatewayTaskCreateProperty(
                    current_version=iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                        model="model",
                        package_version="packageVersion",
                        station="station"
                    ),
                    sig_key_crc=123,
                    update_signature="updateSignature",
                    update_version=iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                        model="model",
                        package_version="packageVersion",
                        station="station"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if current_version is not None:
                self._values["current_version"] = current_version
            if sig_key_crc is not None:
                self._values["sig_key_crc"] = sig_key_crc
            if update_signature is not None:
                self._values["update_signature"] = update_signature
            if update_version is not None:
                self._values["update_version"] = update_version

        @builtins.property
        def current_version(
            self,
        ) -> typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANGatewayVersionProperty", _IResolvable_da3f097b]]:
            '''The version of the gateways that should receive the update.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-lorawanupdategatewaytaskcreate.html#cfn-iotwireless-taskdefinition-lorawanupdategatewaytaskcreate-currentversion
            '''
            result = self._values.get("current_version")
            return typing.cast(typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANGatewayVersionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sig_key_crc(self) -> typing.Optional[jsii.Number]:
            '''The CRC of the signature private key to check.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-lorawanupdategatewaytaskcreate.html#cfn-iotwireless-taskdefinition-lorawanupdategatewaytaskcreate-sigkeycrc
            '''
            result = self._values.get("sig_key_crc")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def update_signature(self) -> typing.Optional[builtins.str]:
            '''The signature used to verify the update firmware.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-lorawanupdategatewaytaskcreate.html#cfn-iotwireless-taskdefinition-lorawanupdategatewaytaskcreate-updatesignature
            '''
            result = self._values.get("update_signature")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def update_version(
            self,
        ) -> typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANGatewayVersionProperty", _IResolvable_da3f097b]]:
            '''The firmware version to update the gateway to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-lorawanupdategatewaytaskcreate.html#cfn-iotwireless-taskdefinition-lorawanupdategatewaytaskcreate-updateversion
            '''
            result = self._values.get("update_version")
            return typing.cast(typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANGatewayVersionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoRaWANUpdateGatewayTaskCreateProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnTaskDefinition.LoRaWANUpdateGatewayTaskEntryProperty",
        jsii_struct_bases=[],
        name_mapping={
            "current_version": "currentVersion",
            "update_version": "updateVersion",
        },
    )
    class LoRaWANUpdateGatewayTaskEntryProperty:
        def __init__(
            self,
            *,
            current_version: typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANGatewayVersionProperty", _IResolvable_da3f097b]] = None,
            update_version: typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANGatewayVersionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''LoRaWANUpdateGatewayTaskEntry object.

            :param current_version: The version of the gateways that should receive the update.
            :param update_version: The firmware version to update the gateway to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-lorawanupdategatewaytaskentry.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                lo_ra_wANUpdate_gateway_task_entry_property = iotwireless.CfnTaskDefinition.LoRaWANUpdateGatewayTaskEntryProperty(
                    current_version=iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                        model="model",
                        package_version="packageVersion",
                        station="station"
                    ),
                    update_version=iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                        model="model",
                        package_version="packageVersion",
                        station="station"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if current_version is not None:
                self._values["current_version"] = current_version
            if update_version is not None:
                self._values["update_version"] = update_version

        @builtins.property
        def current_version(
            self,
        ) -> typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANGatewayVersionProperty", _IResolvable_da3f097b]]:
            '''The version of the gateways that should receive the update.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-lorawanupdategatewaytaskentry.html#cfn-iotwireless-taskdefinition-lorawanupdategatewaytaskentry-currentversion
            '''
            result = self._values.get("current_version")
            return typing.cast(typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANGatewayVersionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def update_version(
            self,
        ) -> typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANGatewayVersionProperty", _IResolvable_da3f097b]]:
            '''The firmware version to update the gateway to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-lorawanupdategatewaytaskentry.html#cfn-iotwireless-taskdefinition-lorawanupdategatewaytaskentry-updateversion
            '''
            result = self._values.get("update_version")
            return typing.cast(typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANGatewayVersionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoRaWANUpdateGatewayTaskEntryProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnTaskDefinition.UpdateWirelessGatewayTaskCreateProperty",
        jsii_struct_bases=[],
        name_mapping={
            "lo_ra_wan": "loRaWan",
            "update_data_role": "updateDataRole",
            "update_data_source": "updateDataSource",
        },
    )
    class UpdateWirelessGatewayTaskCreateProperty:
        def __init__(
            self,
            *,
            lo_ra_wan: typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANUpdateGatewayTaskCreateProperty", _IResolvable_da3f097b]] = None,
            update_data_role: typing.Optional[builtins.str] = None,
            update_data_source: typing.Optional[builtins.str] = None,
        ) -> None:
            '''UpdateWirelessGatewayTaskCreate object.

            :param lo_ra_wan: The properties that relate to the LoRaWAN wireless gateway.
            :param update_data_role: The IAM role used to read data from the S3 bucket.
            :param update_data_source: The link to the S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-updatewirelessgatewaytaskcreate.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                update_wireless_gateway_task_create_property = iotwireless.CfnTaskDefinition.UpdateWirelessGatewayTaskCreateProperty(
                    lo_ra_wan=iotwireless.CfnTaskDefinition.LoRaWANUpdateGatewayTaskCreateProperty(
                        current_version=iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                            model="model",
                            package_version="packageVersion",
                            station="station"
                        ),
                        sig_key_crc=123,
                        update_signature="updateSignature",
                        update_version=iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                            model="model",
                            package_version="packageVersion",
                            station="station"
                        )
                    ),
                    update_data_role="updateDataRole",
                    update_data_source="updateDataSource"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if lo_ra_wan is not None:
                self._values["lo_ra_wan"] = lo_ra_wan
            if update_data_role is not None:
                self._values["update_data_role"] = update_data_role
            if update_data_source is not None:
                self._values["update_data_source"] = update_data_source

        @builtins.property
        def lo_ra_wan(
            self,
        ) -> typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANUpdateGatewayTaskCreateProperty", _IResolvable_da3f097b]]:
            '''The properties that relate to the LoRaWAN wireless gateway.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-updatewirelessgatewaytaskcreate.html#cfn-iotwireless-taskdefinition-updatewirelessgatewaytaskcreate-lorawan
            '''
            result = self._values.get("lo_ra_wan")
            return typing.cast(typing.Optional[typing.Union["CfnTaskDefinition.LoRaWANUpdateGatewayTaskCreateProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def update_data_role(self) -> typing.Optional[builtins.str]:
            '''The IAM role used to read data from the S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-updatewirelessgatewaytaskcreate.html#cfn-iotwireless-taskdefinition-updatewirelessgatewaytaskcreate-updatedatarole
            '''
            result = self._values.get("update_data_role")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def update_data_source(self) -> typing.Optional[builtins.str]:
            '''The link to the S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-taskdefinition-updatewirelessgatewaytaskcreate.html#cfn-iotwireless-taskdefinition-updatewirelessgatewaytaskcreate-updatedatasource
            '''
            result = self._values.get("update_data_source")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "UpdateWirelessGatewayTaskCreateProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnTaskDefinitionProps",
    jsii_struct_bases=[],
    name_mapping={
        "auto_create_tasks": "autoCreateTasks",
        "lo_ra_wan_update_gateway_task_entry": "loRaWanUpdateGatewayTaskEntry",
        "name": "name",
        "tags": "tags",
        "task_definition_type": "taskDefinitionType",
        "update": "update",
    },
)
class CfnTaskDefinitionProps:
    def __init__(
        self,
        *,
        auto_create_tasks: typing.Union[builtins.bool, _IResolvable_da3f097b],
        lo_ra_wan_update_gateway_task_entry: typing.Optional[typing.Union[CfnTaskDefinition.LoRaWANUpdateGatewayTaskEntryProperty, _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        task_definition_type: typing.Optional[builtins.str] = None,
        update: typing.Optional[typing.Union[CfnTaskDefinition.UpdateWirelessGatewayTaskCreateProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnTaskDefinition``.

        :param auto_create_tasks: Whether to automatically create tasks using this task definition for all gateways with the specified current version. If ``false`` , the task must me created by calling ``CreateWirelessGatewayTask`` .
        :param lo_ra_wan_update_gateway_task_entry: ``AWS::IoTWireless::TaskDefinition.LoRaWANUpdateGatewayTaskEntry``.
        :param name: The name of the new resource.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.
        :param task_definition_type: ``AWS::IoTWireless::TaskDefinition.TaskDefinitionType``.
        :param update: Information about the gateways to update.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-taskdefinition.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotwireless as iotwireless
            
            cfn_task_definition_props = iotwireless.CfnTaskDefinitionProps(
                auto_create_tasks=False,
            
                # the properties below are optional
                lo_ra_wan_update_gateway_task_entry=iotwireless.CfnTaskDefinition.LoRaWANUpdateGatewayTaskEntryProperty(
                    current_version=iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                        model="model",
                        package_version="packageVersion",
                        station="station"
                    ),
                    update_version=iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                        model="model",
                        package_version="packageVersion",
                        station="station"
                    )
                ),
                name="name",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                task_definition_type="taskDefinitionType",
                update=iotwireless.CfnTaskDefinition.UpdateWirelessGatewayTaskCreateProperty(
                    lo_ra_wan=iotwireless.CfnTaskDefinition.LoRaWANUpdateGatewayTaskCreateProperty(
                        current_version=iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                            model="model",
                            package_version="packageVersion",
                            station="station"
                        ),
                        sig_key_crc=123,
                        update_signature="updateSignature",
                        update_version=iotwireless.CfnTaskDefinition.LoRaWANGatewayVersionProperty(
                            model="model",
                            package_version="packageVersion",
                            station="station"
                        )
                    ),
                    update_data_role="updateDataRole",
                    update_data_source="updateDataSource"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "auto_create_tasks": auto_create_tasks,
        }
        if lo_ra_wan_update_gateway_task_entry is not None:
            self._values["lo_ra_wan_update_gateway_task_entry"] = lo_ra_wan_update_gateway_task_entry
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags
        if task_definition_type is not None:
            self._values["task_definition_type"] = task_definition_type
        if update is not None:
            self._values["update"] = update

    @builtins.property
    def auto_create_tasks(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Whether to automatically create tasks using this task definition for all gateways with the specified current version.

        If ``false`` , the task must me created by calling ``CreateWirelessGatewayTask`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-taskdefinition.html#cfn-iotwireless-taskdefinition-autocreatetasks
        '''
        result = self._values.get("auto_create_tasks")
        assert result is not None, "Required property 'auto_create_tasks' is missing"
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

    @builtins.property
    def lo_ra_wan_update_gateway_task_entry(
        self,
    ) -> typing.Optional[typing.Union[CfnTaskDefinition.LoRaWANUpdateGatewayTaskEntryProperty, _IResolvable_da3f097b]]:
        '''``AWS::IoTWireless::TaskDefinition.LoRaWANUpdateGatewayTaskEntry``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-taskdefinition.html#cfn-iotwireless-taskdefinition-lorawanupdategatewaytaskentry
        '''
        result = self._values.get("lo_ra_wan_update_gateway_task_entry")
        return typing.cast(typing.Optional[typing.Union[CfnTaskDefinition.LoRaWANUpdateGatewayTaskEntryProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-taskdefinition.html#cfn-iotwireless-taskdefinition-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-taskdefinition.html#cfn-iotwireless-taskdefinition-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def task_definition_type(self) -> typing.Optional[builtins.str]:
        '''``AWS::IoTWireless::TaskDefinition.TaskDefinitionType``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-taskdefinition.html#cfn-iotwireless-taskdefinition-taskdefinitiontype
        '''
        result = self._values.get("task_definition_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def update(
        self,
    ) -> typing.Optional[typing.Union[CfnTaskDefinition.UpdateWirelessGatewayTaskCreateProperty, _IResolvable_da3f097b]]:
        '''Information about the gateways to update.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-taskdefinition.html#cfn-iotwireless-taskdefinition-update
        '''
        result = self._values.get("update")
        return typing.cast(typing.Optional[typing.Union[CfnTaskDefinition.UpdateWirelessGatewayTaskCreateProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnTaskDefinitionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnWirelessDevice(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnWirelessDevice",
):
    '''A CloudFormation ``AWS::IoTWireless::WirelessDevice``.

    Provisions a wireless device.

    :cloudformationResource: AWS::IoTWireless::WirelessDevice
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotwireless as iotwireless
        
        cfn_wireless_device = iotwireless.CfnWirelessDevice(self, "MyCfnWirelessDevice",
            destination_name="destinationName",
            type="type",
        
            # the properties below are optional
            description="description",
            last_uplink_received_at="lastUplinkReceivedAt",
            lo_ra_wan=iotwireless.CfnWirelessDevice.LoRaWANDeviceProperty(
                abp_v10_x=iotwireless.CfnWirelessDevice.AbpV10xProperty(
                    dev_addr="devAddr",
                    session_keys=iotwireless.CfnWirelessDevice.SessionKeysAbpV10xProperty(
                        app_sKey="appSKey",
                        nwk_sKey="nwkSKey"
                    )
                ),
                abp_v11=iotwireless.CfnWirelessDevice.AbpV11Property(
                    dev_addr="devAddr",
                    session_keys=iotwireless.CfnWirelessDevice.SessionKeysAbpV11Property(
                        app_sKey="appSKey",
                        f_nwk_sInt_key="fNwkSIntKey",
                        nwk_sEnc_key="nwkSEncKey",
                        s_nwk_sInt_key="sNwkSIntKey"
                    )
                ),
                dev_eui="devEui",
                device_profile_id="deviceProfileId",
                otaa_v10_x=iotwireless.CfnWirelessDevice.OtaaV10xProperty(
                    app_eui="appEui",
                    app_key="appKey"
                ),
                otaa_v11=iotwireless.CfnWirelessDevice.OtaaV11Property(
                    app_key="appKey",
                    join_eui="joinEui",
                    nwk_key="nwkKey"
                ),
                service_profile_id="serviceProfileId"
            ),
            name="name",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            thing_arn="thingArn"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        destination_name: builtins.str,
        type: builtins.str,
        description: typing.Optional[builtins.str] = None,
        last_uplink_received_at: typing.Optional[builtins.str] = None,
        lo_ra_wan: typing.Optional[typing.Union["CfnWirelessDevice.LoRaWANDeviceProperty", _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        thing_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::IoTWireless::WirelessDevice``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param destination_name: The name of the destination to assign to the new wireless device. Can have only have alphanumeric, - (hyphen) and _ (underscore) characters and it can't have any spaces.
        :param type: The wireless device type.
        :param description: The description of the new resource. Maximum length is 2048.
        :param last_uplink_received_at: The date and time when the most recent uplink was received.
        :param lo_ra_wan: The device configuration information to use to create the wireless device. Must be at least one of OtaaV10x, OtaaV11, AbpV11, or AbpV10x.
        :param name: The name of the new resource.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.
        :param thing_arn: The ARN of the thing to associate with the wireless device.
        '''
        props = CfnWirelessDeviceProps(
            destination_name=destination_name,
            type=type,
            description=description,
            last_uplink_received_at=last_uplink_received_at,
            lo_ra_wan=lo_ra_wan,
            name=name,
            tags=tags,
            thing_arn=thing_arn,
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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The ARN of the wireless device created.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the wireless device created.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrThingName")
    def attr_thing_name(self) -> builtins.str:
        '''The name of the thing associated with the wireless device.

        The value is empty if a thing isn't associated with the device.

        :cloudformationAttribute: ThingName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrThingName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="destinationName")
    def destination_name(self) -> builtins.str:
        '''The name of the destination to assign to the new wireless device.

        Can have only have alphanumeric, - (hyphen) and _ (underscore) characters and it can't have any spaces.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-destinationname
        '''
        return typing.cast(builtins.str, jsii.get(self, "destinationName"))

    @destination_name.setter
    def destination_name(self, value: builtins.str) -> None:
        jsii.set(self, "destinationName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> builtins.str:
        '''The wireless device type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-type
        '''
        return typing.cast(builtins.str, jsii.get(self, "type"))

    @type.setter
    def type(self, value: builtins.str) -> None:
        jsii.set(self, "type", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the new resource.

        Maximum length is 2048.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lastUplinkReceivedAt")
    def last_uplink_received_at(self) -> typing.Optional[builtins.str]:
        '''The date and time when the most recent uplink was received.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-lastuplinkreceivedat
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "lastUplinkReceivedAt"))

    @last_uplink_received_at.setter
    def last_uplink_received_at(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "lastUplinkReceivedAt", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loRaWan")
    def lo_ra_wan(
        self,
    ) -> typing.Optional[typing.Union["CfnWirelessDevice.LoRaWANDeviceProperty", _IResolvable_da3f097b]]:
        '''The device configuration information to use to create the wireless device.

        Must be at least one of OtaaV10x, OtaaV11, AbpV11, or AbpV10x.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-lorawan
        '''
        return typing.cast(typing.Optional[typing.Union["CfnWirelessDevice.LoRaWANDeviceProperty", _IResolvable_da3f097b]], jsii.get(self, "loRaWan"))

    @lo_ra_wan.setter
    def lo_ra_wan(
        self,
        value: typing.Optional[typing.Union["CfnWirelessDevice.LoRaWANDeviceProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "loRaWan", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="thingArn")
    def thing_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the thing to associate with the wireless device.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-thingarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "thingArn"))

    @thing_arn.setter
    def thing_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "thingArn", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnWirelessDevice.AbpV10xProperty",
        jsii_struct_bases=[],
        name_mapping={"dev_addr": "devAddr", "session_keys": "sessionKeys"},
    )
    class AbpV10xProperty:
        def __init__(
            self,
            *,
            dev_addr: builtins.str,
            session_keys: typing.Union["CfnWirelessDevice.SessionKeysAbpV10xProperty", _IResolvable_da3f097b],
        ) -> None:
            '''ABP device object for LoRaWAN specification v1.0.x.

            :param dev_addr: The DevAddr value.
            :param session_keys: Session keys for ABP v1.0.x.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-abpv10x.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                abp_v10x_property = iotwireless.CfnWirelessDevice.AbpV10xProperty(
                    dev_addr="devAddr",
                    session_keys=iotwireless.CfnWirelessDevice.SessionKeysAbpV10xProperty(
                        app_sKey="appSKey",
                        nwk_sKey="nwkSKey"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "dev_addr": dev_addr,
                "session_keys": session_keys,
            }

        @builtins.property
        def dev_addr(self) -> builtins.str:
            '''The DevAddr value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-abpv10x.html#cfn-iotwireless-wirelessdevice-abpv10x-devaddr
            '''
            result = self._values.get("dev_addr")
            assert result is not None, "Required property 'dev_addr' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def session_keys(
            self,
        ) -> typing.Union["CfnWirelessDevice.SessionKeysAbpV10xProperty", _IResolvable_da3f097b]:
            '''Session keys for ABP v1.0.x.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-abpv10x.html#cfn-iotwireless-wirelessdevice-abpv10x-sessionkeys
            '''
            result = self._values.get("session_keys")
            assert result is not None, "Required property 'session_keys' is missing"
            return typing.cast(typing.Union["CfnWirelessDevice.SessionKeysAbpV10xProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AbpV10xProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnWirelessDevice.AbpV11Property",
        jsii_struct_bases=[],
        name_mapping={"dev_addr": "devAddr", "session_keys": "sessionKeys"},
    )
    class AbpV11Property:
        def __init__(
            self,
            *,
            dev_addr: builtins.str,
            session_keys: typing.Union["CfnWirelessDevice.SessionKeysAbpV11Property", _IResolvable_da3f097b],
        ) -> None:
            '''ABP device object for create APIs for v1.1.

            :param dev_addr: The DevAddr value.
            :param session_keys: Session keys for ABP v1.1.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-abpv11.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                abp_v11_property = iotwireless.CfnWirelessDevice.AbpV11Property(
                    dev_addr="devAddr",
                    session_keys=iotwireless.CfnWirelessDevice.SessionKeysAbpV11Property(
                        app_sKey="appSKey",
                        f_nwk_sInt_key="fNwkSIntKey",
                        nwk_sEnc_key="nwkSEncKey",
                        s_nwk_sInt_key="sNwkSIntKey"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "dev_addr": dev_addr,
                "session_keys": session_keys,
            }

        @builtins.property
        def dev_addr(self) -> builtins.str:
            '''The DevAddr value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-abpv11.html#cfn-iotwireless-wirelessdevice-abpv11-devaddr
            '''
            result = self._values.get("dev_addr")
            assert result is not None, "Required property 'dev_addr' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def session_keys(
            self,
        ) -> typing.Union["CfnWirelessDevice.SessionKeysAbpV11Property", _IResolvable_da3f097b]:
            '''Session keys for ABP v1.1.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-abpv11.html#cfn-iotwireless-wirelessdevice-abpv11-sessionkeys
            '''
            result = self._values.get("session_keys")
            assert result is not None, "Required property 'session_keys' is missing"
            return typing.cast(typing.Union["CfnWirelessDevice.SessionKeysAbpV11Property", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AbpV11Property(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnWirelessDevice.LoRaWANDeviceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "abp_v10_x": "abpV10X",
            "abp_v11": "abpV11",
            "dev_eui": "devEui",
            "device_profile_id": "deviceProfileId",
            "otaa_v10_x": "otaaV10X",
            "otaa_v11": "otaaV11",
            "service_profile_id": "serviceProfileId",
        },
    )
    class LoRaWANDeviceProperty:
        def __init__(
            self,
            *,
            abp_v10_x: typing.Optional[typing.Union["CfnWirelessDevice.AbpV10xProperty", _IResolvable_da3f097b]] = None,
            abp_v11: typing.Optional[typing.Union["CfnWirelessDevice.AbpV11Property", _IResolvable_da3f097b]] = None,
            dev_eui: typing.Optional[builtins.str] = None,
            device_profile_id: typing.Optional[builtins.str] = None,
            otaa_v10_x: typing.Optional[typing.Union["CfnWirelessDevice.OtaaV10xProperty", _IResolvable_da3f097b]] = None,
            otaa_v11: typing.Optional[typing.Union["CfnWirelessDevice.OtaaV11Property", _IResolvable_da3f097b]] = None,
            service_profile_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''LoRaWAN object for create functions.

            :param abp_v10_x: LoRaWAN object for create APIs.
            :param abp_v11: ABP device object for create APIs for v1.1.
            :param dev_eui: The DevEUI value.
            :param device_profile_id: The ID of the device profile for the new wireless device.
            :param otaa_v10_x: OTAA device object for create APIs for v1.0.x.
            :param otaa_v11: OTAA device object for v1.1 for create APIs.
            :param service_profile_id: The ID of the service profile.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-lorawandevice.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                lo_ra_wANDevice_property = iotwireless.CfnWirelessDevice.LoRaWANDeviceProperty(
                    abp_v10_x=iotwireless.CfnWirelessDevice.AbpV10xProperty(
                        dev_addr="devAddr",
                        session_keys=iotwireless.CfnWirelessDevice.SessionKeysAbpV10xProperty(
                            app_sKey="appSKey",
                            nwk_sKey="nwkSKey"
                        )
                    ),
                    abp_v11=iotwireless.CfnWirelessDevice.AbpV11Property(
                        dev_addr="devAddr",
                        session_keys=iotwireless.CfnWirelessDevice.SessionKeysAbpV11Property(
                            app_sKey="appSKey",
                            f_nwk_sInt_key="fNwkSIntKey",
                            nwk_sEnc_key="nwkSEncKey",
                            s_nwk_sInt_key="sNwkSIntKey"
                        )
                    ),
                    dev_eui="devEui",
                    device_profile_id="deviceProfileId",
                    otaa_v10_x=iotwireless.CfnWirelessDevice.OtaaV10xProperty(
                        app_eui="appEui",
                        app_key="appKey"
                    ),
                    otaa_v11=iotwireless.CfnWirelessDevice.OtaaV11Property(
                        app_key="appKey",
                        join_eui="joinEui",
                        nwk_key="nwkKey"
                    ),
                    service_profile_id="serviceProfileId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if abp_v10_x is not None:
                self._values["abp_v10_x"] = abp_v10_x
            if abp_v11 is not None:
                self._values["abp_v11"] = abp_v11
            if dev_eui is not None:
                self._values["dev_eui"] = dev_eui
            if device_profile_id is not None:
                self._values["device_profile_id"] = device_profile_id
            if otaa_v10_x is not None:
                self._values["otaa_v10_x"] = otaa_v10_x
            if otaa_v11 is not None:
                self._values["otaa_v11"] = otaa_v11
            if service_profile_id is not None:
                self._values["service_profile_id"] = service_profile_id

        @builtins.property
        def abp_v10_x(
            self,
        ) -> typing.Optional[typing.Union["CfnWirelessDevice.AbpV10xProperty", _IResolvable_da3f097b]]:
            '''LoRaWAN object for create APIs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-lorawandevice.html#cfn-iotwireless-wirelessdevice-lorawandevice-abpv10x
            '''
            result = self._values.get("abp_v10_x")
            return typing.cast(typing.Optional[typing.Union["CfnWirelessDevice.AbpV10xProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def abp_v11(
            self,
        ) -> typing.Optional[typing.Union["CfnWirelessDevice.AbpV11Property", _IResolvable_da3f097b]]:
            '''ABP device object for create APIs for v1.1.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-lorawandevice.html#cfn-iotwireless-wirelessdevice-lorawandevice-abpv11
            '''
            result = self._values.get("abp_v11")
            return typing.cast(typing.Optional[typing.Union["CfnWirelessDevice.AbpV11Property", _IResolvable_da3f097b]], result)

        @builtins.property
        def dev_eui(self) -> typing.Optional[builtins.str]:
            '''The DevEUI value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-lorawandevice.html#cfn-iotwireless-wirelessdevice-lorawandevice-deveui
            '''
            result = self._values.get("dev_eui")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def device_profile_id(self) -> typing.Optional[builtins.str]:
            '''The ID of the device profile for the new wireless device.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-lorawandevice.html#cfn-iotwireless-wirelessdevice-lorawandevice-deviceprofileid
            '''
            result = self._values.get("device_profile_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def otaa_v10_x(
            self,
        ) -> typing.Optional[typing.Union["CfnWirelessDevice.OtaaV10xProperty", _IResolvable_da3f097b]]:
            '''OTAA device object for create APIs for v1.0.x.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-lorawandevice.html#cfn-iotwireless-wirelessdevice-lorawandevice-otaav10x
            '''
            result = self._values.get("otaa_v10_x")
            return typing.cast(typing.Optional[typing.Union["CfnWirelessDevice.OtaaV10xProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def otaa_v11(
            self,
        ) -> typing.Optional[typing.Union["CfnWirelessDevice.OtaaV11Property", _IResolvable_da3f097b]]:
            '''OTAA device object for v1.1 for create APIs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-lorawandevice.html#cfn-iotwireless-wirelessdevice-lorawandevice-otaav11
            '''
            result = self._values.get("otaa_v11")
            return typing.cast(typing.Optional[typing.Union["CfnWirelessDevice.OtaaV11Property", _IResolvable_da3f097b]], result)

        @builtins.property
        def service_profile_id(self) -> typing.Optional[builtins.str]:
            '''The ID of the service profile.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-lorawandevice.html#cfn-iotwireless-wirelessdevice-lorawandevice-serviceprofileid
            '''
            result = self._values.get("service_profile_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoRaWANDeviceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnWirelessDevice.OtaaV10xProperty",
        jsii_struct_bases=[],
        name_mapping={"app_eui": "appEui", "app_key": "appKey"},
    )
    class OtaaV10xProperty:
        def __init__(self, *, app_eui: builtins.str, app_key: builtins.str) -> None:
            '''OTAA device object for create APIs for v1.0.x.

            :param app_eui: The AppEUI value, with pattern of ``[a-fA-F0-9]{16}`` .
            :param app_key: The AppKey is a secret key, which you should handle in a similar way as you would an application password. You can protect the AppKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-otaav10x.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                otaa_v10x_property = iotwireless.CfnWirelessDevice.OtaaV10xProperty(
                    app_eui="appEui",
                    app_key="appKey"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "app_eui": app_eui,
                "app_key": app_key,
            }

        @builtins.property
        def app_eui(self) -> builtins.str:
            '''The AppEUI value, with pattern of ``[a-fA-F0-9]{16}`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-otaav10x.html#cfn-iotwireless-wirelessdevice-otaav10x-appeui
            '''
            result = self._values.get("app_eui")
            assert result is not None, "Required property 'app_eui' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def app_key(self) -> builtins.str:
            '''The AppKey is a secret key, which you should handle in a similar way as you would an application password.

            You can protect the AppKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-otaav10x.html#cfn-iotwireless-wirelessdevice-otaav10x-appkey
            '''
            result = self._values.get("app_key")
            assert result is not None, "Required property 'app_key' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OtaaV10xProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnWirelessDevice.OtaaV11Property",
        jsii_struct_bases=[],
        name_mapping={"app_key": "appKey", "join_eui": "joinEui", "nwk_key": "nwkKey"},
    )
    class OtaaV11Property:
        def __init__(
            self,
            *,
            app_key: builtins.str,
            join_eui: builtins.str,
            nwk_key: builtins.str,
        ) -> None:
            '''OTAA device object for v1.1 for create APIs.

            :param app_key: The AppKey is a secret key, which you should handle in a similar way as you would an application password. You can protect the AppKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.
            :param join_eui: The JoinEUI value.
            :param nwk_key: The NwkKey is a secret key, which you should handle in a similar way as you would an application password. You can protect the NwkKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-otaav11.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                otaa_v11_property = iotwireless.CfnWirelessDevice.OtaaV11Property(
                    app_key="appKey",
                    join_eui="joinEui",
                    nwk_key="nwkKey"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "app_key": app_key,
                "join_eui": join_eui,
                "nwk_key": nwk_key,
            }

        @builtins.property
        def app_key(self) -> builtins.str:
            '''The AppKey is a secret key, which you should handle in a similar way as you would an application password.

            You can protect the AppKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-otaav11.html#cfn-iotwireless-wirelessdevice-otaav11-appkey
            '''
            result = self._values.get("app_key")
            assert result is not None, "Required property 'app_key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def join_eui(self) -> builtins.str:
            '''The JoinEUI value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-otaav11.html#cfn-iotwireless-wirelessdevice-otaav11-joineui
            '''
            result = self._values.get("join_eui")
            assert result is not None, "Required property 'join_eui' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def nwk_key(self) -> builtins.str:
            '''The NwkKey is a secret key, which you should handle in a similar way as you would an application password.

            You can protect the NwkKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-otaav11.html#cfn-iotwireless-wirelessdevice-otaav11-nwkkey
            '''
            result = self._values.get("nwk_key")
            assert result is not None, "Required property 'nwk_key' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OtaaV11Property(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnWirelessDevice.SessionKeysAbpV10xProperty",
        jsii_struct_bases=[],
        name_mapping={"app_s_key": "appSKey", "nwk_s_key": "nwkSKey"},
    )
    class SessionKeysAbpV10xProperty:
        def __init__(self, *, app_s_key: builtins.str, nwk_s_key: builtins.str) -> None:
            '''LoRaWAN object for create APIs.

            :param app_s_key: The AppSKey is a secret key, which you should handle in a similar way as you would an application password. You can protect the AppSKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.
            :param nwk_s_key: The NwkSKey is a secret key, which you should handle in a similar way as you would an application password. You can protect the NwkSKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-sessionkeysabpv10x.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                session_keys_abp_v10x_property = iotwireless.CfnWirelessDevice.SessionKeysAbpV10xProperty(
                    app_sKey="appSKey",
                    nwk_sKey="nwkSKey"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "app_s_key": app_s_key,
                "nwk_s_key": nwk_s_key,
            }

        @builtins.property
        def app_s_key(self) -> builtins.str:
            '''The AppSKey is a secret key, which you should handle in a similar way as you would an application password.

            You can protect the AppSKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-sessionkeysabpv10x.html#cfn-iotwireless-wirelessdevice-sessionkeysabpv10x-appskey
            '''
            result = self._values.get("app_s_key")
            assert result is not None, "Required property 'app_s_key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def nwk_s_key(self) -> builtins.str:
            '''The NwkSKey is a secret key, which you should handle in a similar way as you would an application password.

            You can protect the NwkSKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-sessionkeysabpv10x.html#cfn-iotwireless-wirelessdevice-sessionkeysabpv10x-nwkskey
            '''
            result = self._values.get("nwk_s_key")
            assert result is not None, "Required property 'nwk_s_key' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SessionKeysAbpV10xProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnWirelessDevice.SessionKeysAbpV11Property",
        jsii_struct_bases=[],
        name_mapping={
            "app_s_key": "appSKey",
            "f_nwk_s_int_key": "fNwkSIntKey",
            "nwk_s_enc_key": "nwkSEncKey",
            "s_nwk_s_int_key": "sNwkSIntKey",
        },
    )
    class SessionKeysAbpV11Property:
        def __init__(
            self,
            *,
            app_s_key: builtins.str,
            f_nwk_s_int_key: builtins.str,
            nwk_s_enc_key: builtins.str,
            s_nwk_s_int_key: builtins.str,
        ) -> None:
            '''Session keys for ABP v1.1.

            :param app_s_key: The AppSKey is a secret key, which you should handle in a similar way as you would an application password. You can protect the AppSKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.
            :param f_nwk_s_int_key: The FNwkSIntKey is a secret key, which you should handle in a similar way as you would an application password. You can protect the FNwkSIntKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.
            :param nwk_s_enc_key: The NwkSEncKey is a secret key, which you should handle in a similar way as you would an application password. You can protect the NwkSEncKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.
            :param s_nwk_s_int_key: The SNwkSIntKey is a secret key, which you should handle in a similar way as you would an application password. You can protect the SNwkSIntKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-sessionkeysabpv11.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                session_keys_abp_v11_property = iotwireless.CfnWirelessDevice.SessionKeysAbpV11Property(
                    app_sKey="appSKey",
                    f_nwk_sInt_key="fNwkSIntKey",
                    nwk_sEnc_key="nwkSEncKey",
                    s_nwk_sInt_key="sNwkSIntKey"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "app_s_key": app_s_key,
                "f_nwk_s_int_key": f_nwk_s_int_key,
                "nwk_s_enc_key": nwk_s_enc_key,
                "s_nwk_s_int_key": s_nwk_s_int_key,
            }

        @builtins.property
        def app_s_key(self) -> builtins.str:
            '''The AppSKey is a secret key, which you should handle in a similar way as you would an application password.

            You can protect the AppSKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-sessionkeysabpv11.html#cfn-iotwireless-wirelessdevice-sessionkeysabpv11-appskey
            '''
            result = self._values.get("app_s_key")
            assert result is not None, "Required property 'app_s_key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def f_nwk_s_int_key(self) -> builtins.str:
            '''The FNwkSIntKey is a secret key, which you should handle in a similar way as you would an application password.

            You can protect the FNwkSIntKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-sessionkeysabpv11.html#cfn-iotwireless-wirelessdevice-sessionkeysabpv11-fnwksintkey
            '''
            result = self._values.get("f_nwk_s_int_key")
            assert result is not None, "Required property 'f_nwk_s_int_key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def nwk_s_enc_key(self) -> builtins.str:
            '''The NwkSEncKey is a secret key, which you should handle in a similar way as you would an application password.

            You can protect the NwkSEncKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-sessionkeysabpv11.html#cfn-iotwireless-wirelessdevice-sessionkeysabpv11-nwksenckey
            '''
            result = self._values.get("nwk_s_enc_key")
            assert result is not None, "Required property 'nwk_s_enc_key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s_nwk_s_int_key(self) -> builtins.str:
            '''The SNwkSIntKey is a secret key, which you should handle in a similar way as you would an application password.

            You can protect the SNwkSIntKey value by storing it in the AWS Secrets Manager and use the `secretsmanager <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ to reference this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessdevice-sessionkeysabpv11.html#cfn-iotwireless-wirelessdevice-sessionkeysabpv11-snwksintkey
            '''
            result = self._values.get("s_nwk_s_int_key")
            assert result is not None, "Required property 's_nwk_s_int_key' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SessionKeysAbpV11Property(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnWirelessDeviceProps",
    jsii_struct_bases=[],
    name_mapping={
        "destination_name": "destinationName",
        "type": "type",
        "description": "description",
        "last_uplink_received_at": "lastUplinkReceivedAt",
        "lo_ra_wan": "loRaWan",
        "name": "name",
        "tags": "tags",
        "thing_arn": "thingArn",
    },
)
class CfnWirelessDeviceProps:
    def __init__(
        self,
        *,
        destination_name: builtins.str,
        type: builtins.str,
        description: typing.Optional[builtins.str] = None,
        last_uplink_received_at: typing.Optional[builtins.str] = None,
        lo_ra_wan: typing.Optional[typing.Union[CfnWirelessDevice.LoRaWANDeviceProperty, _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        thing_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnWirelessDevice``.

        :param destination_name: The name of the destination to assign to the new wireless device. Can have only have alphanumeric, - (hyphen) and _ (underscore) characters and it can't have any spaces.
        :param type: The wireless device type.
        :param description: The description of the new resource. Maximum length is 2048.
        :param last_uplink_received_at: The date and time when the most recent uplink was received.
        :param lo_ra_wan: The device configuration information to use to create the wireless device. Must be at least one of OtaaV10x, OtaaV11, AbpV11, or AbpV10x.
        :param name: The name of the new resource.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.
        :param thing_arn: The ARN of the thing to associate with the wireless device.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotwireless as iotwireless
            
            cfn_wireless_device_props = iotwireless.CfnWirelessDeviceProps(
                destination_name="destinationName",
                type="type",
            
                # the properties below are optional
                description="description",
                last_uplink_received_at="lastUplinkReceivedAt",
                lo_ra_wan=iotwireless.CfnWirelessDevice.LoRaWANDeviceProperty(
                    abp_v10_x=iotwireless.CfnWirelessDevice.AbpV10xProperty(
                        dev_addr="devAddr",
                        session_keys=iotwireless.CfnWirelessDevice.SessionKeysAbpV10xProperty(
                            app_sKey="appSKey",
                            nwk_sKey="nwkSKey"
                        )
                    ),
                    abp_v11=iotwireless.CfnWirelessDevice.AbpV11Property(
                        dev_addr="devAddr",
                        session_keys=iotwireless.CfnWirelessDevice.SessionKeysAbpV11Property(
                            app_sKey="appSKey",
                            f_nwk_sInt_key="fNwkSIntKey",
                            nwk_sEnc_key="nwkSEncKey",
                            s_nwk_sInt_key="sNwkSIntKey"
                        )
                    ),
                    dev_eui="devEui",
                    device_profile_id="deviceProfileId",
                    otaa_v10_x=iotwireless.CfnWirelessDevice.OtaaV10xProperty(
                        app_eui="appEui",
                        app_key="appKey"
                    ),
                    otaa_v11=iotwireless.CfnWirelessDevice.OtaaV11Property(
                        app_key="appKey",
                        join_eui="joinEui",
                        nwk_key="nwkKey"
                    ),
                    service_profile_id="serviceProfileId"
                ),
                name="name",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                thing_arn="thingArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "destination_name": destination_name,
            "type": type,
        }
        if description is not None:
            self._values["description"] = description
        if last_uplink_received_at is not None:
            self._values["last_uplink_received_at"] = last_uplink_received_at
        if lo_ra_wan is not None:
            self._values["lo_ra_wan"] = lo_ra_wan
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags
        if thing_arn is not None:
            self._values["thing_arn"] = thing_arn

    @builtins.property
    def destination_name(self) -> builtins.str:
        '''The name of the destination to assign to the new wireless device.

        Can have only have alphanumeric, - (hyphen) and _ (underscore) characters and it can't have any spaces.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-destinationname
        '''
        result = self._values.get("destination_name")
        assert result is not None, "Required property 'destination_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def type(self) -> builtins.str:
        '''The wireless device type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-type
        '''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the new resource.

        Maximum length is 2048.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def last_uplink_received_at(self) -> typing.Optional[builtins.str]:
        '''The date and time when the most recent uplink was received.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-lastuplinkreceivedat
        '''
        result = self._values.get("last_uplink_received_at")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def lo_ra_wan(
        self,
    ) -> typing.Optional[typing.Union[CfnWirelessDevice.LoRaWANDeviceProperty, _IResolvable_da3f097b]]:
        '''The device configuration information to use to create the wireless device.

        Must be at least one of OtaaV10x, OtaaV11, AbpV11, or AbpV10x.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-lorawan
        '''
        result = self._values.get("lo_ra_wan")
        return typing.cast(typing.Optional[typing.Union[CfnWirelessDevice.LoRaWANDeviceProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def thing_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the thing to associate with the wireless device.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessdevice.html#cfn-iotwireless-wirelessdevice-thingarn
        '''
        result = self._values.get("thing_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnWirelessDeviceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnWirelessGateway(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnWirelessGateway",
):
    '''A CloudFormation ``AWS::IoTWireless::WirelessGateway``.

    Provisions a wireless gateway.

    :cloudformationResource: AWS::IoTWireless::WirelessGateway
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessgateway.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotwireless as iotwireless
        
        cfn_wireless_gateway = iotwireless.CfnWirelessGateway(self, "MyCfnWirelessGateway",
            lo_ra_wan=iotwireless.CfnWirelessGateway.LoRaWANGatewayProperty(
                gateway_eui="gatewayEui",
                rf_region="rfRegion"
            ),
        
            # the properties below are optional
            description="description",
            last_uplink_received_at="lastUplinkReceivedAt",
            name="name",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            thing_arn="thingArn"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        lo_ra_wan: typing.Union["CfnWirelessGateway.LoRaWANGatewayProperty", _IResolvable_da3f097b],
        description: typing.Optional[builtins.str] = None,
        last_uplink_received_at: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        thing_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::IoTWireless::WirelessGateway``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param lo_ra_wan: The gateway configuration information to use to create the wireless gateway.
        :param description: The description of the new resource. The maximum length is 2048 characters.
        :param last_uplink_received_at: The date and time when the most recent uplink was received.
        :param name: The name of the new resource.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.
        :param thing_arn: The ARN of the thing to associate with the wireless gateway.
        '''
        props = CfnWirelessGatewayProps(
            lo_ra_wan=lo_ra_wan,
            description=description,
            last_uplink_received_at=last_uplink_received_at,
            name=name,
            tags=tags,
            thing_arn=thing_arn,
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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The ARN of the wireless gateway created.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the wireless gateway created.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrThingName")
    def attr_thing_name(self) -> builtins.str:
        '''The name of the thing associated with the wireless gateway.

        The value is empty if a thing isn't associated with the gateway.

        :cloudformationAttribute: ThingName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrThingName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessgateway.html#cfn-iotwireless-wirelessgateway-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loRaWan")
    def lo_ra_wan(
        self,
    ) -> typing.Union["CfnWirelessGateway.LoRaWANGatewayProperty", _IResolvable_da3f097b]:
        '''The gateway configuration information to use to create the wireless gateway.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessgateway.html#cfn-iotwireless-wirelessgateway-lorawan
        '''
        return typing.cast(typing.Union["CfnWirelessGateway.LoRaWANGatewayProperty", _IResolvable_da3f097b], jsii.get(self, "loRaWan"))

    @lo_ra_wan.setter
    def lo_ra_wan(
        self,
        value: typing.Union["CfnWirelessGateway.LoRaWANGatewayProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "loRaWan", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the new resource.

        The maximum length is 2048 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessgateway.html#cfn-iotwireless-wirelessgateway-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lastUplinkReceivedAt")
    def last_uplink_received_at(self) -> typing.Optional[builtins.str]:
        '''The date and time when the most recent uplink was received.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessgateway.html#cfn-iotwireless-wirelessgateway-lastuplinkreceivedat
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "lastUplinkReceivedAt"))

    @last_uplink_received_at.setter
    def last_uplink_received_at(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "lastUplinkReceivedAt", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessgateway.html#cfn-iotwireless-wirelessgateway-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="thingArn")
    def thing_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the thing to associate with the wireless gateway.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessgateway.html#cfn-iotwireless-wirelessgateway-thingarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "thingArn"))

    @thing_arn.setter
    def thing_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "thingArn", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotwireless.CfnWirelessGateway.LoRaWANGatewayProperty",
        jsii_struct_bases=[],
        name_mapping={"gateway_eui": "gatewayEui", "rf_region": "rfRegion"},
    )
    class LoRaWANGatewayProperty:
        def __init__(
            self,
            *,
            gateway_eui: builtins.str,
            rf_region: builtins.str,
        ) -> None:
            '''LoRaWAN wireless gateway object.

            :param gateway_eui: The gateway's EUI value.
            :param rf_region: The frequency band (RFRegion) value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessgateway-lorawangateway.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotwireless as iotwireless
                
                lo_ra_wANGateway_property = iotwireless.CfnWirelessGateway.LoRaWANGatewayProperty(
                    gateway_eui="gatewayEui",
                    rf_region="rfRegion"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "gateway_eui": gateway_eui,
                "rf_region": rf_region,
            }

        @builtins.property
        def gateway_eui(self) -> builtins.str:
            '''The gateway's EUI value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessgateway-lorawangateway.html#cfn-iotwireless-wirelessgateway-lorawangateway-gatewayeui
            '''
            result = self._values.get("gateway_eui")
            assert result is not None, "Required property 'gateway_eui' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def rf_region(self) -> builtins.str:
            '''The frequency band (RFRegion) value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotwireless-wirelessgateway-lorawangateway.html#cfn-iotwireless-wirelessgateway-lorawangateway-rfregion
            '''
            result = self._values.get("rf_region")
            assert result is not None, "Required property 'rf_region' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoRaWANGatewayProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotwireless.CfnWirelessGatewayProps",
    jsii_struct_bases=[],
    name_mapping={
        "lo_ra_wan": "loRaWan",
        "description": "description",
        "last_uplink_received_at": "lastUplinkReceivedAt",
        "name": "name",
        "tags": "tags",
        "thing_arn": "thingArn",
    },
)
class CfnWirelessGatewayProps:
    def __init__(
        self,
        *,
        lo_ra_wan: typing.Union[CfnWirelessGateway.LoRaWANGatewayProperty, _IResolvable_da3f097b],
        description: typing.Optional[builtins.str] = None,
        last_uplink_received_at: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        thing_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnWirelessGateway``.

        :param lo_ra_wan: The gateway configuration information to use to create the wireless gateway.
        :param description: The description of the new resource. The maximum length is 2048 characters.
        :param last_uplink_received_at: The date and time when the most recent uplink was received.
        :param name: The name of the new resource.
        :param tags: The tags are an array of key-value pairs to attach to the specified resource. Tags can have a minimum of 0 and a maximum of 50 items.
        :param thing_arn: The ARN of the thing to associate with the wireless gateway.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessgateway.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotwireless as iotwireless
            
            cfn_wireless_gateway_props = iotwireless.CfnWirelessGatewayProps(
                lo_ra_wan=iotwireless.CfnWirelessGateway.LoRaWANGatewayProperty(
                    gateway_eui="gatewayEui",
                    rf_region="rfRegion"
                ),
            
                # the properties below are optional
                description="description",
                last_uplink_received_at="lastUplinkReceivedAt",
                name="name",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                thing_arn="thingArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "lo_ra_wan": lo_ra_wan,
        }
        if description is not None:
            self._values["description"] = description
        if last_uplink_received_at is not None:
            self._values["last_uplink_received_at"] = last_uplink_received_at
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags
        if thing_arn is not None:
            self._values["thing_arn"] = thing_arn

    @builtins.property
    def lo_ra_wan(
        self,
    ) -> typing.Union[CfnWirelessGateway.LoRaWANGatewayProperty, _IResolvable_da3f097b]:
        '''The gateway configuration information to use to create the wireless gateway.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessgateway.html#cfn-iotwireless-wirelessgateway-lorawan
        '''
        result = self._values.get("lo_ra_wan")
        assert result is not None, "Required property 'lo_ra_wan' is missing"
        return typing.cast(typing.Union[CfnWirelessGateway.LoRaWANGatewayProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the new resource.

        The maximum length is 2048 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessgateway.html#cfn-iotwireless-wirelessgateway-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def last_uplink_received_at(self) -> typing.Optional[builtins.str]:
        '''The date and time when the most recent uplink was received.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessgateway.html#cfn-iotwireless-wirelessgateway-lastuplinkreceivedat
        '''
        result = self._values.get("last_uplink_received_at")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessgateway.html#cfn-iotwireless-wirelessgateway-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags are an array of key-value pairs to attach to the specified resource.

        Tags can have a minimum of 0 and a maximum of 50 items.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessgateway.html#cfn-iotwireless-wirelessgateway-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def thing_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the thing to associate with the wireless gateway.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotwireless-wirelessgateway.html#cfn-iotwireless-wirelessgateway-thingarn
        '''
        result = self._values.get("thing_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnWirelessGatewayProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnDestination",
    "CfnDestinationProps",
    "CfnDeviceProfile",
    "CfnDeviceProfileProps",
    "CfnFuotaTask",
    "CfnFuotaTaskProps",
    "CfnMulticastGroup",
    "CfnMulticastGroupProps",
    "CfnPartnerAccount",
    "CfnPartnerAccountProps",
    "CfnServiceProfile",
    "CfnServiceProfileProps",
    "CfnTaskDefinition",
    "CfnTaskDefinitionProps",
    "CfnWirelessDevice",
    "CfnWirelessDeviceProps",
    "CfnWirelessGateway",
    "CfnWirelessGatewayProps",
]

publication.publish()
