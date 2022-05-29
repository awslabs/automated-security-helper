'''
# AWS::SSMContacts Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_ssmcontacts as ssmcontacts
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-ssmcontacts-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::SSMContacts](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_SSMContacts.html).

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
    IInspectable as _IInspectable_c2943556,
    IResolvable as _IResolvable_da3f097b,
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.implements(_IInspectable_c2943556)
class CfnContact(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ssmcontacts.CfnContact",
):
    '''A CloudFormation ``AWS::SSMContacts::Contact``.

    The ``AWS::SSMContacts::Contact`` resource specifies a contact or escalation plan. Incident Manager contacts are a subset of actions and data types that you can use for managing responder engagement and interaction.

    :cloudformationResource: AWS::SSMContacts::Contact
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contact.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_ssmcontacts as ssmcontacts
        
        cfn_contact = ssmcontacts.CfnContact(self, "MyCfnContact",
            alias="alias",
            display_name="displayName",
            plan=[ssmcontacts.CfnContact.StageProperty(
                duration_in_minutes=123,
        
                # the properties below are optional
                targets=[ssmcontacts.CfnContact.TargetsProperty(
                    channel_target_info=ssmcontacts.CfnContact.ChannelTargetInfoProperty(
                        channel_id="channelId",
                        retry_interval_in_minutes=123
                    ),
                    contact_target_info=ssmcontacts.CfnContact.ContactTargetInfoProperty(
                        contact_id="contactId",
                        is_essential=False
                    )
                )]
            )],
            type="type"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        alias: builtins.str,
        display_name: builtins.str,
        plan: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnContact.StageProperty", _IResolvable_da3f097b]]],
        type: builtins.str,
    ) -> None:
        '''Create a new ``AWS::SSMContacts::Contact``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param alias: The unique and identifiable alias of the contact or escalation plan.
        :param display_name: The full name of the contact or escalation plan.
        :param plan: A list of stages. A contact has an engagement plan with stages that contact specified contact channels. An escalation plan uses stages that contact specified contacts.
        :param type: Refers to the type of contact. A single contact is type ``PERSONAL`` and an escalation plan is type ``ESCALATION`` .
        '''
        props = CfnContactProps(
            alias=alias, display_name=display_name, plan=plan, type=type
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
        '''The Amazon Resource Name (ARN) of the ``Contact`` resource, such as ``arn:aws:ssm-contacts:us-west-2:123456789012:contact/contactalias`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="alias")
    def alias(self) -> builtins.str:
        '''The unique and identifiable alias of the contact or escalation plan.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contact.html#cfn-ssmcontacts-contact-alias
        '''
        return typing.cast(builtins.str, jsii.get(self, "alias"))

    @alias.setter
    def alias(self, value: builtins.str) -> None:
        jsii.set(self, "alias", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="displayName")
    def display_name(self) -> builtins.str:
        '''The full name of the contact or escalation plan.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contact.html#cfn-ssmcontacts-contact-displayname
        '''
        return typing.cast(builtins.str, jsii.get(self, "displayName"))

    @display_name.setter
    def display_name(self, value: builtins.str) -> None:
        jsii.set(self, "displayName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="plan")
    def plan(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnContact.StageProperty", _IResolvable_da3f097b]]]:
        '''A list of stages.

        A contact has an engagement plan with stages that contact specified contact channels. An escalation plan uses stages that contact specified contacts.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contact.html#cfn-ssmcontacts-contact-plan
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnContact.StageProperty", _IResolvable_da3f097b]]], jsii.get(self, "plan"))

    @plan.setter
    def plan(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnContact.StageProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "plan", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> builtins.str:
        '''Refers to the type of contact.

        A single contact is type ``PERSONAL`` and an escalation plan is type ``ESCALATION`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contact.html#cfn-ssmcontacts-contact-type
        '''
        return typing.cast(builtins.str, jsii.get(self, "type"))

    @type.setter
    def type(self, value: builtins.str) -> None:
        jsii.set(self, "type", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_ssmcontacts.CfnContact.ChannelTargetInfoProperty",
        jsii_struct_bases=[],
        name_mapping={
            "channel_id": "channelId",
            "retry_interval_in_minutes": "retryIntervalInMinutes",
        },
    )
    class ChannelTargetInfoProperty:
        def __init__(
            self,
            *,
            channel_id: builtins.str,
            retry_interval_in_minutes: jsii.Number,
        ) -> None:
            '''Information about the contact channel that Incident Manager uses to engage the contact.

            :param channel_id: The Amazon Resource Name (ARN) of the contact channel.
            :param retry_interval_in_minutes: The number of minutes to wait to retry sending engagement in the case the engagement initially fails.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ssmcontacts-contact-channeltargetinfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_ssmcontacts as ssmcontacts
                
                channel_target_info_property = ssmcontacts.CfnContact.ChannelTargetInfoProperty(
                    channel_id="channelId",
                    retry_interval_in_minutes=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "channel_id": channel_id,
                "retry_interval_in_minutes": retry_interval_in_minutes,
            }

        @builtins.property
        def channel_id(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the contact channel.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ssmcontacts-contact-channeltargetinfo.html#cfn-ssmcontacts-contact-channeltargetinfo-channelid
            '''
            result = self._values.get("channel_id")
            assert result is not None, "Required property 'channel_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def retry_interval_in_minutes(self) -> jsii.Number:
            '''The number of minutes to wait to retry sending engagement in the case the engagement initially fails.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ssmcontacts-contact-channeltargetinfo.html#cfn-ssmcontacts-contact-channeltargetinfo-retryintervalinminutes
            '''
            result = self._values.get("retry_interval_in_minutes")
            assert result is not None, "Required property 'retry_interval_in_minutes' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ChannelTargetInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_ssmcontacts.CfnContact.ContactTargetInfoProperty",
        jsii_struct_bases=[],
        name_mapping={"contact_id": "contactId", "is_essential": "isEssential"},
    )
    class ContactTargetInfoProperty:
        def __init__(
            self,
            *,
            contact_id: builtins.str,
            is_essential: typing.Union[builtins.bool, _IResolvable_da3f097b],
        ) -> None:
            '''The contact that Incident Manager is engaging during an incident.

            :param contact_id: The Amazon Resource Name (ARN) of the contact.
            :param is_essential: A Boolean value determining if the contact's acknowledgement stops the progress of stages in the plan.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ssmcontacts-contact-contacttargetinfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_ssmcontacts as ssmcontacts
                
                contact_target_info_property = ssmcontacts.CfnContact.ContactTargetInfoProperty(
                    contact_id="contactId",
                    is_essential=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "contact_id": contact_id,
                "is_essential": is_essential,
            }

        @builtins.property
        def contact_id(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the contact.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ssmcontacts-contact-contacttargetinfo.html#cfn-ssmcontacts-contact-contacttargetinfo-contactid
            '''
            result = self._values.get("contact_id")
            assert result is not None, "Required property 'contact_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def is_essential(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''A Boolean value determining if the contact's acknowledgement stops the progress of stages in the plan.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ssmcontacts-contact-contacttargetinfo.html#cfn-ssmcontacts-contact-contacttargetinfo-isessential
            '''
            result = self._values.get("is_essential")
            assert result is not None, "Required property 'is_essential' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ContactTargetInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_ssmcontacts.CfnContact.StageProperty",
        jsii_struct_bases=[],
        name_mapping={
            "duration_in_minutes": "durationInMinutes",
            "targets": "targets",
        },
    )
    class StageProperty:
        def __init__(
            self,
            *,
            duration_in_minutes: jsii.Number,
            targets: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnContact.TargetsProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''The ``Stage`` property type specifies a set amount of time that an escalation plan or engagement plan engages the specified contacts or contact methods.

            :param duration_in_minutes: The time to wait until beginning the next stage. The duration can only be set to 0 if a target is specified.
            :param targets: The contacts or contact methods that the escalation plan or engagement plan is engaging.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ssmcontacts-contact-stage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_ssmcontacts as ssmcontacts
                
                stage_property = ssmcontacts.CfnContact.StageProperty(
                    duration_in_minutes=123,
                
                    # the properties below are optional
                    targets=[ssmcontacts.CfnContact.TargetsProperty(
                        channel_target_info=ssmcontacts.CfnContact.ChannelTargetInfoProperty(
                            channel_id="channelId",
                            retry_interval_in_minutes=123
                        ),
                        contact_target_info=ssmcontacts.CfnContact.ContactTargetInfoProperty(
                            contact_id="contactId",
                            is_essential=False
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "duration_in_minutes": duration_in_minutes,
            }
            if targets is not None:
                self._values["targets"] = targets

        @builtins.property
        def duration_in_minutes(self) -> jsii.Number:
            '''The time to wait until beginning the next stage.

            The duration can only be set to 0 if a target is specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ssmcontacts-contact-stage.html#cfn-ssmcontacts-contact-stage-durationinminutes
            '''
            result = self._values.get("duration_in_minutes")
            assert result is not None, "Required property 'duration_in_minutes' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def targets(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnContact.TargetsProperty", _IResolvable_da3f097b]]]]:
            '''The contacts or contact methods that the escalation plan or engagement plan is engaging.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ssmcontacts-contact-stage.html#cfn-ssmcontacts-contact-stage-targets
            '''
            result = self._values.get("targets")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnContact.TargetsProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_ssmcontacts.CfnContact.TargetsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "channel_target_info": "channelTargetInfo",
            "contact_target_info": "contactTargetInfo",
        },
    )
    class TargetsProperty:
        def __init__(
            self,
            *,
            channel_target_info: typing.Optional[typing.Union["CfnContact.ChannelTargetInfoProperty", _IResolvable_da3f097b]] = None,
            contact_target_info: typing.Optional[typing.Union["CfnContact.ContactTargetInfoProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The contact or contact channel that's being engaged.

            :param channel_target_info: Information about the contact channel Incident Manager is engaging.
            :param contact_target_info: The contact that Incident Manager is engaging during an incident.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ssmcontacts-contact-targets.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_ssmcontacts as ssmcontacts
                
                targets_property = ssmcontacts.CfnContact.TargetsProperty(
                    channel_target_info=ssmcontacts.CfnContact.ChannelTargetInfoProperty(
                        channel_id="channelId",
                        retry_interval_in_minutes=123
                    ),
                    contact_target_info=ssmcontacts.CfnContact.ContactTargetInfoProperty(
                        contact_id="contactId",
                        is_essential=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if channel_target_info is not None:
                self._values["channel_target_info"] = channel_target_info
            if contact_target_info is not None:
                self._values["contact_target_info"] = contact_target_info

        @builtins.property
        def channel_target_info(
            self,
        ) -> typing.Optional[typing.Union["CfnContact.ChannelTargetInfoProperty", _IResolvable_da3f097b]]:
            '''Information about the contact channel Incident Manager is engaging.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ssmcontacts-contact-targets.html#cfn-ssmcontacts-contact-targets-channeltargetinfo
            '''
            result = self._values.get("channel_target_info")
            return typing.cast(typing.Optional[typing.Union["CfnContact.ChannelTargetInfoProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def contact_target_info(
            self,
        ) -> typing.Optional[typing.Union["CfnContact.ContactTargetInfoProperty", _IResolvable_da3f097b]]:
            '''The contact that Incident Manager is engaging during an incident.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ssmcontacts-contact-targets.html#cfn-ssmcontacts-contact-targets-contacttargetinfo
            '''
            result = self._values.get("contact_target_info")
            return typing.cast(typing.Optional[typing.Union["CfnContact.ContactTargetInfoProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TargetsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnContactChannel(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ssmcontacts.CfnContactChannel",
):
    '''A CloudFormation ``AWS::SSMContacts::ContactChannel``.

    The ``AWS::SSMContacts::ContactChannel`` resource specifies a contact channel as the method that Incident Manager uses to engage your contact.

    :cloudformationResource: AWS::SSMContacts::ContactChannel
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contactchannel.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_ssmcontacts as ssmcontacts
        
        cfn_contact_channel = ssmcontacts.CfnContactChannel(self, "MyCfnContactChannel",
            channel_address="channelAddress",
            channel_name="channelName",
            channel_type="channelType",
            contact_id="contactId",
        
            # the properties below are optional
            defer_activation=False
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        channel_address: builtins.str,
        channel_name: builtins.str,
        channel_type: builtins.str,
        contact_id: builtins.str,
        defer_activation: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::SSMContacts::ContactChannel``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param channel_address: The details that Incident Manager uses when trying to engage the contact channel.
        :param channel_name: The name of the contact channel.
        :param channel_type: The type of the contact channel. Incident Manager supports three contact methods:. - SMS - VOICE - EMAIL
        :param contact_id: The Amazon Resource Name (ARN) of the contact you are adding the contact channel to.
        :param defer_activation: If you want to activate the channel at a later time, you can choose to defer activation. Incident Manager can't engage your contact channel until it has been activated.
        '''
        props = CfnContactChannelProps(
            channel_address=channel_address,
            channel_name=channel_name,
            channel_type=channel_type,
            contact_id=contact_id,
            defer_activation=defer_activation,
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
        '''The Amazon Resource Name (ARN) of the ``ContactChannel`` resource.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="channelAddress")
    def channel_address(self) -> builtins.str:
        '''The details that Incident Manager uses when trying to engage the contact channel.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contactchannel.html#cfn-ssmcontacts-contactchannel-channeladdress
        '''
        return typing.cast(builtins.str, jsii.get(self, "channelAddress"))

    @channel_address.setter
    def channel_address(self, value: builtins.str) -> None:
        jsii.set(self, "channelAddress", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="channelName")
    def channel_name(self) -> builtins.str:
        '''The name of the contact channel.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contactchannel.html#cfn-ssmcontacts-contactchannel-channelname
        '''
        return typing.cast(builtins.str, jsii.get(self, "channelName"))

    @channel_name.setter
    def channel_name(self, value: builtins.str) -> None:
        jsii.set(self, "channelName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="channelType")
    def channel_type(self) -> builtins.str:
        '''The type of the contact channel. Incident Manager supports three contact methods:.

        - SMS
        - VOICE
        - EMAIL

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contactchannel.html#cfn-ssmcontacts-contactchannel-channeltype
        '''
        return typing.cast(builtins.str, jsii.get(self, "channelType"))

    @channel_type.setter
    def channel_type(self, value: builtins.str) -> None:
        jsii.set(self, "channelType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="contactId")
    def contact_id(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the contact you are adding the contact channel to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contactchannel.html#cfn-ssmcontacts-contactchannel-contactid
        '''
        return typing.cast(builtins.str, jsii.get(self, "contactId"))

    @contact_id.setter
    def contact_id(self, value: builtins.str) -> None:
        jsii.set(self, "contactId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="deferActivation")
    def defer_activation(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''If you want to activate the channel at a later time, you can choose to defer activation.

        Incident Manager can't engage your contact channel until it has been activated.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contactchannel.html#cfn-ssmcontacts-contactchannel-deferactivation
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "deferActivation"))

    @defer_activation.setter
    def defer_activation(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "deferActivation", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ssmcontacts.CfnContactChannelProps",
    jsii_struct_bases=[],
    name_mapping={
        "channel_address": "channelAddress",
        "channel_name": "channelName",
        "channel_type": "channelType",
        "contact_id": "contactId",
        "defer_activation": "deferActivation",
    },
)
class CfnContactChannelProps:
    def __init__(
        self,
        *,
        channel_address: builtins.str,
        channel_name: builtins.str,
        channel_type: builtins.str,
        contact_id: builtins.str,
        defer_activation: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnContactChannel``.

        :param channel_address: The details that Incident Manager uses when trying to engage the contact channel.
        :param channel_name: The name of the contact channel.
        :param channel_type: The type of the contact channel. Incident Manager supports three contact methods:. - SMS - VOICE - EMAIL
        :param contact_id: The Amazon Resource Name (ARN) of the contact you are adding the contact channel to.
        :param defer_activation: If you want to activate the channel at a later time, you can choose to defer activation. Incident Manager can't engage your contact channel until it has been activated.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contactchannel.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ssmcontacts as ssmcontacts
            
            cfn_contact_channel_props = ssmcontacts.CfnContactChannelProps(
                channel_address="channelAddress",
                channel_name="channelName",
                channel_type="channelType",
                contact_id="contactId",
            
                # the properties below are optional
                defer_activation=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "channel_address": channel_address,
            "channel_name": channel_name,
            "channel_type": channel_type,
            "contact_id": contact_id,
        }
        if defer_activation is not None:
            self._values["defer_activation"] = defer_activation

    @builtins.property
    def channel_address(self) -> builtins.str:
        '''The details that Incident Manager uses when trying to engage the contact channel.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contactchannel.html#cfn-ssmcontacts-contactchannel-channeladdress
        '''
        result = self._values.get("channel_address")
        assert result is not None, "Required property 'channel_address' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def channel_name(self) -> builtins.str:
        '''The name of the contact channel.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contactchannel.html#cfn-ssmcontacts-contactchannel-channelname
        '''
        result = self._values.get("channel_name")
        assert result is not None, "Required property 'channel_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def channel_type(self) -> builtins.str:
        '''The type of the contact channel. Incident Manager supports three contact methods:.

        - SMS
        - VOICE
        - EMAIL

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contactchannel.html#cfn-ssmcontacts-contactchannel-channeltype
        '''
        result = self._values.get("channel_type")
        assert result is not None, "Required property 'channel_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def contact_id(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the contact you are adding the contact channel to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contactchannel.html#cfn-ssmcontacts-contactchannel-contactid
        '''
        result = self._values.get("contact_id")
        assert result is not None, "Required property 'contact_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def defer_activation(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''If you want to activate the channel at a later time, you can choose to defer activation.

        Incident Manager can't engage your contact channel until it has been activated.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contactchannel.html#cfn-ssmcontacts-contactchannel-deferactivation
        '''
        result = self._values.get("defer_activation")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnContactChannelProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ssmcontacts.CfnContactProps",
    jsii_struct_bases=[],
    name_mapping={
        "alias": "alias",
        "display_name": "displayName",
        "plan": "plan",
        "type": "type",
    },
)
class CfnContactProps:
    def __init__(
        self,
        *,
        alias: builtins.str,
        display_name: builtins.str,
        plan: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnContact.StageProperty, _IResolvable_da3f097b]]],
        type: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnContact``.

        :param alias: The unique and identifiable alias of the contact or escalation plan.
        :param display_name: The full name of the contact or escalation plan.
        :param plan: A list of stages. A contact has an engagement plan with stages that contact specified contact channels. An escalation plan uses stages that contact specified contacts.
        :param type: Refers to the type of contact. A single contact is type ``PERSONAL`` and an escalation plan is type ``ESCALATION`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contact.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ssmcontacts as ssmcontacts
            
            cfn_contact_props = ssmcontacts.CfnContactProps(
                alias="alias",
                display_name="displayName",
                plan=[ssmcontacts.CfnContact.StageProperty(
                    duration_in_minutes=123,
            
                    # the properties below are optional
                    targets=[ssmcontacts.CfnContact.TargetsProperty(
                        channel_target_info=ssmcontacts.CfnContact.ChannelTargetInfoProperty(
                            channel_id="channelId",
                            retry_interval_in_minutes=123
                        ),
                        contact_target_info=ssmcontacts.CfnContact.ContactTargetInfoProperty(
                            contact_id="contactId",
                            is_essential=False
                        )
                    )]
                )],
                type="type"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "alias": alias,
            "display_name": display_name,
            "plan": plan,
            "type": type,
        }

    @builtins.property
    def alias(self) -> builtins.str:
        '''The unique and identifiable alias of the contact or escalation plan.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contact.html#cfn-ssmcontacts-contact-alias
        '''
        result = self._values.get("alias")
        assert result is not None, "Required property 'alias' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def display_name(self) -> builtins.str:
        '''The full name of the contact or escalation plan.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contact.html#cfn-ssmcontacts-contact-displayname
        '''
        result = self._values.get("display_name")
        assert result is not None, "Required property 'display_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def plan(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnContact.StageProperty, _IResolvable_da3f097b]]]:
        '''A list of stages.

        A contact has an engagement plan with stages that contact specified contact channels. An escalation plan uses stages that contact specified contacts.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contact.html#cfn-ssmcontacts-contact-plan
        '''
        result = self._values.get("plan")
        assert result is not None, "Required property 'plan' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnContact.StageProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def type(self) -> builtins.str:
        '''Refers to the type of contact.

        A single contact is type ``PERSONAL`` and an escalation plan is type ``ESCALATION`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssmcontacts-contact.html#cfn-ssmcontacts-contact-type
        '''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnContactProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnContact",
    "CfnContactChannel",
    "CfnContactChannelProps",
    "CfnContactProps",
]

publication.publish()
