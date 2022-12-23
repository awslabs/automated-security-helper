'''
# Amazon Data Lifecycle Manager Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_dlm as dlm
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-dlm-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::DLM](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_DLM.html).

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
class CfnLifecyclePolicy(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy",
):
    '''A CloudFormation ``AWS::DLM::LifecyclePolicy``.

    Specifies a lifecycle policy, which is used to automate operations on Amazon EBS resources.

    The properties are required when you add a lifecycle policy and optional when you update a lifecycle policy.

    :cloudformationResource: AWS::DLM::LifecyclePolicy
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dlm-lifecyclepolicy.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_dlm as dlm
        
        cfn_lifecycle_policy = dlm.CfnLifecyclePolicy(self, "MyCfnLifecyclePolicy",
            description="description",
            execution_role_arn="executionRoleArn",
            policy_details=dlm.CfnLifecyclePolicy.PolicyDetailsProperty(
                actions=[dlm.CfnLifecyclePolicy.ActionProperty(
                    cross_region_copy=[dlm.CfnLifecyclePolicy.CrossRegionCopyActionProperty(
                        encryption_configuration=dlm.CfnLifecyclePolicy.EncryptionConfigurationProperty(
                            encrypted=False,
        
                            # the properties below are optional
                            cmk_arn="cmkArn"
                        ),
                        target="target",
        
                        # the properties below are optional
                        retain_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty(
                            interval=123,
                            interval_unit="intervalUnit"
                        )
                    )],
                    name="name"
                )],
                event_source=dlm.CfnLifecyclePolicy.EventSourceProperty(
                    type="type",
        
                    # the properties below are optional
                    parameters=dlm.CfnLifecyclePolicy.EventParametersProperty(
                        event_type="eventType",
                        snapshot_owner=["snapshotOwner"],
        
                        # the properties below are optional
                        description_regex="descriptionRegex"
                    )
                ),
                parameters=dlm.CfnLifecyclePolicy.ParametersProperty(
                    exclude_boot_volume=False,
                    no_reboot=False
                ),
                policy_type="policyType",
                resource_locations=["resourceLocations"],
                resource_types=["resourceTypes"],
                schedules=[dlm.CfnLifecyclePolicy.ScheduleProperty(
                    copy_tags=False,
                    create_rule=dlm.CfnLifecyclePolicy.CreateRuleProperty(
                        cron_expression="cronExpression",
                        interval=123,
                        interval_unit="intervalUnit",
                        location="location",
                        times=["times"]
                    ),
                    cross_region_copy_rules=[dlm.CfnLifecyclePolicy.CrossRegionCopyRuleProperty(
                        encrypted=False,
        
                        # the properties below are optional
                        cmk_arn="cmkArn",
                        copy_tags=False,
                        deprecate_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyDeprecateRuleProperty(
                            interval=123,
                            interval_unit="intervalUnit"
                        ),
                        retain_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty(
                            interval=123,
                            interval_unit="intervalUnit"
                        ),
                        target="target",
                        target_region="targetRegion"
                    )],
                    deprecate_rule=dlm.CfnLifecyclePolicy.DeprecateRuleProperty(
                        count=123,
                        interval=123,
                        interval_unit="intervalUnit"
                    ),
                    fast_restore_rule=dlm.CfnLifecyclePolicy.FastRestoreRuleProperty(
                        availability_zones=["availabilityZones"],
                        count=123,
                        interval=123,
                        interval_unit="intervalUnit"
                    ),
                    name="name",
                    retain_rule=dlm.CfnLifecyclePolicy.RetainRuleProperty(
                        count=123,
                        interval=123,
                        interval_unit="intervalUnit"
                    ),
                    share_rules=[dlm.CfnLifecyclePolicy.ShareRuleProperty(
                        target_accounts=["targetAccounts"],
                        unshare_interval=123,
                        unshare_interval_unit="unshareIntervalUnit"
                    )],
                    tags_to_add=[CfnTag(
                        key="key",
                        value="value"
                    )],
                    variable_tags=[CfnTag(
                        key="key",
                        value="value"
                    )]
                )],
                target_tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            ),
            state="state",
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
        description: typing.Optional[builtins.str] = None,
        execution_role_arn: typing.Optional[builtins.str] = None,
        policy_details: typing.Optional[typing.Union["CfnLifecyclePolicy.PolicyDetailsProperty", _IResolvable_da3f097b]] = None,
        state: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::DLM::LifecyclePolicy``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param description: A description of the lifecycle policy. The characters ^[0-9A-Za-z _-]+$ are supported.
        :param execution_role_arn: The Amazon Resource Name (ARN) of the IAM role used to run the operations specified by the lifecycle policy.
        :param policy_details: The configuration details of the lifecycle policy.
        :param state: The activation state of the lifecycle policy.
        :param tags: The tags to apply to the lifecycle policy during creation.
        '''
        props = CfnLifecyclePolicyProps(
            description=description,
            execution_role_arn=execution_role_arn,
            policy_details=policy_details,
            state=state,
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
        '''The Amazon Resource Name (ARN) of the lifecycle policy.

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
        '''The tags to apply to the lifecycle policy during creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dlm-lifecyclepolicy.html#cfn-dlm-lifecyclepolicy-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the lifecycle policy.

        The characters ^[0-9A-Za-z _-]+$ are supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dlm-lifecyclepolicy.html#cfn-dlm-lifecyclepolicy-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="executionRoleArn")
    def execution_role_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the IAM role used to run the operations specified by the lifecycle policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dlm-lifecyclepolicy.html#cfn-dlm-lifecyclepolicy-executionrolearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "executionRoleArn"))

    @execution_role_arn.setter
    def execution_role_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "executionRoleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyDetails")
    def policy_details(
        self,
    ) -> typing.Optional[typing.Union["CfnLifecyclePolicy.PolicyDetailsProperty", _IResolvable_da3f097b]]:
        '''The configuration details of the lifecycle policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dlm-lifecyclepolicy.html#cfn-dlm-lifecyclepolicy-policydetails
        '''
        return typing.cast(typing.Optional[typing.Union["CfnLifecyclePolicy.PolicyDetailsProperty", _IResolvable_da3f097b]], jsii.get(self, "policyDetails"))

    @policy_details.setter
    def policy_details(
        self,
        value: typing.Optional[typing.Union["CfnLifecyclePolicy.PolicyDetailsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "policyDetails", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="state")
    def state(self) -> typing.Optional[builtins.str]:
        '''The activation state of the lifecycle policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dlm-lifecyclepolicy.html#cfn-dlm-lifecyclepolicy-state
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "state"))

    @state.setter
    def state(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "state", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.ActionProperty",
        jsii_struct_bases=[],
        name_mapping={"cross_region_copy": "crossRegionCopy", "name": "name"},
    )
    class ActionProperty:
        def __init__(
            self,
            *,
            cross_region_copy: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnLifecyclePolicy.CrossRegionCopyActionProperty", _IResolvable_da3f097b]]],
            name: builtins.str,
        ) -> None:
            '''Specifies an action for an event-based policy.

            :param cross_region_copy: The rule for copying shared snapshots across Regions.
            :param name: A descriptive name for the action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-action.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                action_property = dlm.CfnLifecyclePolicy.ActionProperty(
                    cross_region_copy=[dlm.CfnLifecyclePolicy.CrossRegionCopyActionProperty(
                        encryption_configuration=dlm.CfnLifecyclePolicy.EncryptionConfigurationProperty(
                            encrypted=False,
                
                            # the properties below are optional
                            cmk_arn="cmkArn"
                        ),
                        target="target",
                
                        # the properties below are optional
                        retain_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty(
                            interval=123,
                            interval_unit="intervalUnit"
                        )
                    )],
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "cross_region_copy": cross_region_copy,
                "name": name,
            }

        @builtins.property
        def cross_region_copy(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLifecyclePolicy.CrossRegionCopyActionProperty", _IResolvable_da3f097b]]]:
            '''The rule for copying shared snapshots across Regions.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-action.html#cfn-dlm-lifecyclepolicy-action-crossregioncopy
            '''
            result = self._values.get("cross_region_copy")
            assert result is not None, "Required property 'cross_region_copy' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLifecyclePolicy.CrossRegionCopyActionProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def name(self) -> builtins.str:
            '''A descriptive name for the action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-action.html#cfn-dlm-lifecyclepolicy-action-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.CreateRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cron_expression": "cronExpression",
            "interval": "interval",
            "interval_unit": "intervalUnit",
            "location": "location",
            "times": "times",
        },
    )
    class CreateRuleProperty:
        def __init__(
            self,
            *,
            cron_expression: typing.Optional[builtins.str] = None,
            interval: typing.Optional[jsii.Number] = None,
            interval_unit: typing.Optional[builtins.str] = None,
            location: typing.Optional[builtins.str] = None,
            times: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Specifies when to create snapshots of EBS volumes.

            You must specify either a Cron expression or an interval, interval unit, and start time. You cannot specify both.

            :param cron_expression: The schedule, as a Cron expression. The schedule interval must be between 1 hour and 1 year. For more information, see `Cron expressions <https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html#CronExpressions>`_ in the *Amazon CloudWatch User Guide* .
            :param interval: The interval between snapshots. The supported values are 1, 2, 3, 4, 6, 8, 12, and 24.
            :param interval_unit: The interval unit.
            :param location: Specifies the destination for snapshots created by the policy. To create snapshots in the same Region as the source resource, specify ``CLOUD`` . To create snapshots on the same Outpost as the source resource, specify ``OUTPOST_LOCAL`` . If you omit this parameter, ``CLOUD`` is used by default. If the policy targets resources in an AWS Region , then you must create snapshots in the same Region as the source resource. If the policy targets resources on an Outpost, then you can create snapshots on the same Outpost as the source resource, or in the Region of that Outpost.
            :param times: The time, in UTC, to start the operation. The supported format is hh:mm. The operation occurs within a one-hour window following the specified time. If you do not specify a time, Amazon DLM selects a time within the next 24 hours.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-createrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                create_rule_property = dlm.CfnLifecyclePolicy.CreateRuleProperty(
                    cron_expression="cronExpression",
                    interval=123,
                    interval_unit="intervalUnit",
                    location="location",
                    times=["times"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if cron_expression is not None:
                self._values["cron_expression"] = cron_expression
            if interval is not None:
                self._values["interval"] = interval
            if interval_unit is not None:
                self._values["interval_unit"] = interval_unit
            if location is not None:
                self._values["location"] = location
            if times is not None:
                self._values["times"] = times

        @builtins.property
        def cron_expression(self) -> typing.Optional[builtins.str]:
            '''The schedule, as a Cron expression.

            The schedule interval must be between 1 hour and 1 year. For more information, see `Cron expressions <https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html#CronExpressions>`_ in the *Amazon CloudWatch User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-createrule.html#cfn-dlm-lifecyclepolicy-createrule-cronexpression
            '''
            result = self._values.get("cron_expression")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def interval(self) -> typing.Optional[jsii.Number]:
            '''The interval between snapshots.

            The supported values are 1, 2, 3, 4, 6, 8, 12, and 24.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-createrule.html#cfn-dlm-lifecyclepolicy-createrule-interval
            '''
            result = self._values.get("interval")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def interval_unit(self) -> typing.Optional[builtins.str]:
            '''The interval unit.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-createrule.html#cfn-dlm-lifecyclepolicy-createrule-intervalunit
            '''
            result = self._values.get("interval_unit")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def location(self) -> typing.Optional[builtins.str]:
            '''Specifies the destination for snapshots created by the policy.

            To create snapshots in the same Region as the source resource, specify ``CLOUD`` . To create snapshots on the same Outpost as the source resource, specify ``OUTPOST_LOCAL`` . If you omit this parameter, ``CLOUD`` is used by default.

            If the policy targets resources in an AWS Region , then you must create snapshots in the same Region as the source resource.

            If the policy targets resources on an Outpost, then you can create snapshots on the same Outpost as the source resource, or in the Region of that Outpost.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-createrule.html#cfn-dlm-lifecyclepolicy-createrule-location
            '''
            result = self._values.get("location")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def times(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The time, in UTC, to start the operation. The supported format is hh:mm.

            The operation occurs within a one-hour window following the specified time. If you do not specify a time, Amazon DLM selects a time within the next 24 hours.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-createrule.html#cfn-dlm-lifecyclepolicy-createrule-times
            '''
            result = self._values.get("times")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CreateRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.CrossRegionCopyActionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "encryption_configuration": "encryptionConfiguration",
            "target": "target",
            "retain_rule": "retainRule",
        },
    )
    class CrossRegionCopyActionProperty:
        def __init__(
            self,
            *,
            encryption_configuration: typing.Union["CfnLifecyclePolicy.EncryptionConfigurationProperty", _IResolvable_da3f097b],
            target: builtins.str,
            retain_rule: typing.Optional[typing.Union["CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies a rule for copying shared snapshots across Regions.

            :param encryption_configuration: The encryption settings for the copied snapshot.
            :param target: The target Region.
            :param retain_rule: Specifies the retention rule for cross-Region snapshot copies.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyaction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                cross_region_copy_action_property = dlm.CfnLifecyclePolicy.CrossRegionCopyActionProperty(
                    encryption_configuration=dlm.CfnLifecyclePolicy.EncryptionConfigurationProperty(
                        encrypted=False,
                
                        # the properties below are optional
                        cmk_arn="cmkArn"
                    ),
                    target="target",
                
                    # the properties below are optional
                    retain_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty(
                        interval=123,
                        interval_unit="intervalUnit"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "encryption_configuration": encryption_configuration,
                "target": target,
            }
            if retain_rule is not None:
                self._values["retain_rule"] = retain_rule

        @builtins.property
        def encryption_configuration(
            self,
        ) -> typing.Union["CfnLifecyclePolicy.EncryptionConfigurationProperty", _IResolvable_da3f097b]:
            '''The encryption settings for the copied snapshot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyaction.html#cfn-dlm-lifecyclepolicy-crossregioncopyaction-encryptionconfiguration
            '''
            result = self._values.get("encryption_configuration")
            assert result is not None, "Required property 'encryption_configuration' is missing"
            return typing.cast(typing.Union["CfnLifecyclePolicy.EncryptionConfigurationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def target(self) -> builtins.str:
            '''The target Region.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyaction.html#cfn-dlm-lifecyclepolicy-crossregioncopyaction-target
            '''
            result = self._values.get("target")
            assert result is not None, "Required property 'target' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def retain_rule(
            self,
        ) -> typing.Optional[typing.Union["CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty", _IResolvable_da3f097b]]:
            '''Specifies the retention rule for cross-Region snapshot copies.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyaction.html#cfn-dlm-lifecyclepolicy-crossregioncopyaction-retainrule
            '''
            result = self._values.get("retain_rule")
            return typing.cast(typing.Optional[typing.Union["CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CrossRegionCopyActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.CrossRegionCopyDeprecateRuleProperty",
        jsii_struct_bases=[],
        name_mapping={"interval": "interval", "interval_unit": "intervalUnit"},
    )
    class CrossRegionCopyDeprecateRuleProperty:
        def __init__(
            self,
            *,
            interval: jsii.Number,
            interval_unit: builtins.str,
        ) -> None:
            '''Specifies an AMI deprecation rule for cross-Region AMI copies created by a cross-Region copy rule.

            :param interval: The period after which to deprecate the cross-Region AMI copies. The period must be less than or equal to the cross-Region AMI copy retention period, and it can't be greater than 10 years. This is equivalent to 120 months, 520 weeks, or 3650 days.
            :param interval_unit: The unit of time in which to measure the *Interval* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopydeprecaterule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                cross_region_copy_deprecate_rule_property = dlm.CfnLifecyclePolicy.CrossRegionCopyDeprecateRuleProperty(
                    interval=123,
                    interval_unit="intervalUnit"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "interval": interval,
                "interval_unit": interval_unit,
            }

        @builtins.property
        def interval(self) -> jsii.Number:
            '''The period after which to deprecate the cross-Region AMI copies.

            The period must be less than or equal to the cross-Region AMI copy retention period, and it can't be greater than 10 years. This is equivalent to 120 months, 520 weeks, or 3650 days.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopydeprecaterule.html#cfn-dlm-lifecyclepolicy-crossregioncopydeprecaterule-interval
            '''
            result = self._values.get("interval")
            assert result is not None, "Required property 'interval' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def interval_unit(self) -> builtins.str:
            '''The unit of time in which to measure the *Interval* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopydeprecaterule.html#cfn-dlm-lifecyclepolicy-crossregioncopydeprecaterule-intervalunit
            '''
            result = self._values.get("interval_unit")
            assert result is not None, "Required property 'interval_unit' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CrossRegionCopyDeprecateRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty",
        jsii_struct_bases=[],
        name_mapping={"interval": "interval", "interval_unit": "intervalUnit"},
    )
    class CrossRegionCopyRetainRuleProperty:
        def __init__(
            self,
            *,
            interval: jsii.Number,
            interval_unit: builtins.str,
        ) -> None:
            '''Specifies the retention rule for cross-Region snapshot copies.

            :param interval: The amount of time to retain each snapshot. The maximum is 100 years. This is equivalent to 1200 months, 5200 weeks, or 36500 days.
            :param interval_unit: The unit of time for time-based retention.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyretainrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                cross_region_copy_retain_rule_property = dlm.CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty(
                    interval=123,
                    interval_unit="intervalUnit"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "interval": interval,
                "interval_unit": interval_unit,
            }

        @builtins.property
        def interval(self) -> jsii.Number:
            '''The amount of time to retain each snapshot.

            The maximum is 100 years. This is equivalent to 1200 months, 5200 weeks, or 36500 days.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyretainrule.html#cfn-dlm-lifecyclepolicy-crossregioncopyretainrule-interval
            '''
            result = self._values.get("interval")
            assert result is not None, "Required property 'interval' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def interval_unit(self) -> builtins.str:
            '''The unit of time for time-based retention.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyretainrule.html#cfn-dlm-lifecyclepolicy-crossregioncopyretainrule-intervalunit
            '''
            result = self._values.get("interval_unit")
            assert result is not None, "Required property 'interval_unit' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CrossRegionCopyRetainRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.CrossRegionCopyRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "encrypted": "encrypted",
            "cmk_arn": "cmkArn",
            "copy_tags": "copyTags",
            "deprecate_rule": "deprecateRule",
            "retain_rule": "retainRule",
            "target": "target",
            "target_region": "targetRegion",
        },
    )
    class CrossRegionCopyRuleProperty:
        def __init__(
            self,
            *,
            encrypted: typing.Union[builtins.bool, _IResolvable_da3f097b],
            cmk_arn: typing.Optional[builtins.str] = None,
            copy_tags: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            deprecate_rule: typing.Optional[typing.Union["CfnLifecyclePolicy.CrossRegionCopyDeprecateRuleProperty", _IResolvable_da3f097b]] = None,
            retain_rule: typing.Optional[typing.Union["CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty", _IResolvable_da3f097b]] = None,
            target: typing.Optional[builtins.str] = None,
            target_region: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies a rule for cross-Region snapshot copies.

            :param encrypted: To encrypt a copy of an unencrypted snapshot if encryption by default is not enabled, enable encryption using this parameter. Copies of encrypted snapshots are encrypted, even if this parameter is false or if encryption by default is not enabled.
            :param cmk_arn: The Amazon Resource Name (ARN) of the AWS KMS key to use for EBS encryption. If this parameter is not specified, the default KMS key for the account is used.
            :param copy_tags: Indicates whether to copy all user-defined tags from the source snapshot to the cross-Region snapshot copy.
            :param deprecate_rule: The AMI deprecation rule for cross-Region AMI copies created by the rule.
            :param retain_rule: The retention rule that indicates how long snapshot copies are to be retained in the destination Region.
            :param target: The target Region or the Amazon Resource Name (ARN) of the target Outpost for the snapshot copies. Use this parameter instead of *TargetRegion* . Do not specify both.
            :param target_region: Avoid using this parameter when creating new policies. Instead, use *Target* to specify a target Region or a target Outpost for snapshot copies. For policies created before the *Target* parameter was introduced, this parameter indicates the target Region for snapshot copies.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                cross_region_copy_rule_property = dlm.CfnLifecyclePolicy.CrossRegionCopyRuleProperty(
                    encrypted=False,
                
                    # the properties below are optional
                    cmk_arn="cmkArn",
                    copy_tags=False,
                    deprecate_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyDeprecateRuleProperty(
                        interval=123,
                        interval_unit="intervalUnit"
                    ),
                    retain_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty(
                        interval=123,
                        interval_unit="intervalUnit"
                    ),
                    target="target",
                    target_region="targetRegion"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "encrypted": encrypted,
            }
            if cmk_arn is not None:
                self._values["cmk_arn"] = cmk_arn
            if copy_tags is not None:
                self._values["copy_tags"] = copy_tags
            if deprecate_rule is not None:
                self._values["deprecate_rule"] = deprecate_rule
            if retain_rule is not None:
                self._values["retain_rule"] = retain_rule
            if target is not None:
                self._values["target"] = target
            if target_region is not None:
                self._values["target_region"] = target_region

        @builtins.property
        def encrypted(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''To encrypt a copy of an unencrypted snapshot if encryption by default is not enabled, enable encryption using this parameter.

            Copies of encrypted snapshots are encrypted, even if this parameter is false or if encryption by default is not enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyrule.html#cfn-dlm-lifecyclepolicy-crossregioncopyrule-encrypted
            '''
            result = self._values.get("encrypted")
            assert result is not None, "Required property 'encrypted' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def cmk_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the AWS KMS key to use for EBS encryption.

            If this parameter is not specified, the default KMS key for the account is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyrule.html#cfn-dlm-lifecyclepolicy-crossregioncopyrule-cmkarn
            '''
            result = self._values.get("cmk_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def copy_tags(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether to copy all user-defined tags from the source snapshot to the cross-Region snapshot copy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyrule.html#cfn-dlm-lifecyclepolicy-crossregioncopyrule-copytags
            '''
            result = self._values.get("copy_tags")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def deprecate_rule(
            self,
        ) -> typing.Optional[typing.Union["CfnLifecyclePolicy.CrossRegionCopyDeprecateRuleProperty", _IResolvable_da3f097b]]:
            '''The AMI deprecation rule for cross-Region AMI copies created by the rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyrule.html#cfn-dlm-lifecyclepolicy-crossregioncopyrule-deprecaterule
            '''
            result = self._values.get("deprecate_rule")
            return typing.cast(typing.Optional[typing.Union["CfnLifecyclePolicy.CrossRegionCopyDeprecateRuleProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def retain_rule(
            self,
        ) -> typing.Optional[typing.Union["CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty", _IResolvable_da3f097b]]:
            '''The retention rule that indicates how long snapshot copies are to be retained in the destination Region.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyrule.html#cfn-dlm-lifecyclepolicy-crossregioncopyrule-retainrule
            '''
            result = self._values.get("retain_rule")
            return typing.cast(typing.Optional[typing.Union["CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def target(self) -> typing.Optional[builtins.str]:
            '''The target Region or the Amazon Resource Name (ARN) of the target Outpost for the snapshot copies.

            Use this parameter instead of *TargetRegion* . Do not specify both.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyrule.html#cfn-dlm-lifecyclepolicy-crossregioncopyrule-target
            '''
            result = self._values.get("target")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def target_region(self) -> typing.Optional[builtins.str]:
            '''Avoid using this parameter when creating new policies.

            Instead, use *Target* to specify a target Region or a target Outpost for snapshot copies.

            For policies created before the *Target* parameter was introduced, this parameter indicates the target Region for snapshot copies.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-crossregioncopyrule.html#cfn-dlm-lifecyclepolicy-crossregioncopyrule-targetregion
            '''
            result = self._values.get("target_region")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CrossRegionCopyRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.DeprecateRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "count": "count",
            "interval": "interval",
            "interval_unit": "intervalUnit",
        },
    )
    class DeprecateRuleProperty:
        def __init__(
            self,
            *,
            count: typing.Optional[jsii.Number] = None,
            interval: typing.Optional[jsii.Number] = None,
            interval_unit: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies an AMI deprecation rule for a schedule.

            :param count: If the schedule has a count-based retention rule, this parameter specifies the number of oldest AMIs to deprecate. The count must be less than or equal to the schedule's retention count, and it can't be greater than 1000.
            :param interval: If the schedule has an age-based retention rule, this parameter specifies the period after which to deprecate AMIs created by the schedule. The period must be less than or equal to the schedule's retention period, and it can't be greater than 10 years. This is equivalent to 120 months, 520 weeks, or 3650 days.
            :param interval_unit: The unit of time in which to measure the *Interval* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-deprecaterule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                deprecate_rule_property = dlm.CfnLifecyclePolicy.DeprecateRuleProperty(
                    count=123,
                    interval=123,
                    interval_unit="intervalUnit"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if count is not None:
                self._values["count"] = count
            if interval is not None:
                self._values["interval"] = interval
            if interval_unit is not None:
                self._values["interval_unit"] = interval_unit

        @builtins.property
        def count(self) -> typing.Optional[jsii.Number]:
            '''If the schedule has a count-based retention rule, this parameter specifies the number of oldest AMIs to deprecate.

            The count must be less than or equal to the schedule's retention count, and it can't be greater than 1000.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-deprecaterule.html#cfn-dlm-lifecyclepolicy-deprecaterule-count
            '''
            result = self._values.get("count")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def interval(self) -> typing.Optional[jsii.Number]:
            '''If the schedule has an age-based retention rule, this parameter specifies the period after which to deprecate AMIs created by the schedule.

            The period must be less than or equal to the schedule's retention period, and it can't be greater than 10 years. This is equivalent to 120 months, 520 weeks, or 3650 days.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-deprecaterule.html#cfn-dlm-lifecyclepolicy-deprecaterule-interval
            '''
            result = self._values.get("interval")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def interval_unit(self) -> typing.Optional[builtins.str]:
            '''The unit of time in which to measure the *Interval* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-deprecaterule.html#cfn-dlm-lifecyclepolicy-deprecaterule-intervalunit
            '''
            result = self._values.get("interval_unit")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DeprecateRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.EncryptionConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"encrypted": "encrypted", "cmk_arn": "cmkArn"},
    )
    class EncryptionConfigurationProperty:
        def __init__(
            self,
            *,
            encrypted: typing.Union[builtins.bool, _IResolvable_da3f097b],
            cmk_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies the encryption settings for shared snapshots that are copied across Regions.

            :param encrypted: To encrypt a copy of an unencrypted snapshot when encryption by default is not enabled, enable encryption using this parameter. Copies of encrypted snapshots are encrypted, even if this parameter is false or when encryption by default is not enabled.
            :param cmk_arn: The Amazon Resource Name (ARN) of the AWS KMS key to use for EBS encryption. If this parameter is not specified, the default KMS key for the account is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-encryptionconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                encryption_configuration_property = dlm.CfnLifecyclePolicy.EncryptionConfigurationProperty(
                    encrypted=False,
                
                    # the properties below are optional
                    cmk_arn="cmkArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "encrypted": encrypted,
            }
            if cmk_arn is not None:
                self._values["cmk_arn"] = cmk_arn

        @builtins.property
        def encrypted(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''To encrypt a copy of an unencrypted snapshot when encryption by default is not enabled, enable encryption using this parameter.

            Copies of encrypted snapshots are encrypted, even if this parameter is false or when encryption by default is not enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-encryptionconfiguration.html#cfn-dlm-lifecyclepolicy-encryptionconfiguration-encrypted
            '''
            result = self._values.get("encrypted")
            assert result is not None, "Required property 'encrypted' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def cmk_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the AWS KMS key to use for EBS encryption.

            If this parameter is not specified, the default KMS key for the account is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-encryptionconfiguration.html#cfn-dlm-lifecyclepolicy-encryptionconfiguration-cmkarn
            '''
            result = self._values.get("cmk_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EncryptionConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.EventParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "event_type": "eventType",
            "snapshot_owner": "snapshotOwner",
            "description_regex": "descriptionRegex",
        },
    )
    class EventParametersProperty:
        def __init__(
            self,
            *,
            event_type: builtins.str,
            snapshot_owner: typing.Sequence[builtins.str],
            description_regex: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies an event that triggers an event-based policy.

            :param event_type: The type of event. Currently, only snapshot sharing events are supported.
            :param snapshot_owner: The IDs of the AWS accounts that can trigger policy by sharing snapshots with your account. The policy only runs if one of the specified AWS accounts shares a snapshot with your account.
            :param description_regex: The snapshot description that can trigger the policy. The description pattern is specified using a regular expression. The policy runs only if a snapshot with a description that matches the specified pattern is shared with your account. For example, specifying ``^.*Created for policy: policy-1234567890abcdef0.*$`` configures the policy to run only if snapshots created by policy ``policy-1234567890abcdef0`` are shared with your account.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-eventparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                event_parameters_property = dlm.CfnLifecyclePolicy.EventParametersProperty(
                    event_type="eventType",
                    snapshot_owner=["snapshotOwner"],
                
                    # the properties below are optional
                    description_regex="descriptionRegex"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "event_type": event_type,
                "snapshot_owner": snapshot_owner,
            }
            if description_regex is not None:
                self._values["description_regex"] = description_regex

        @builtins.property
        def event_type(self) -> builtins.str:
            '''The type of event.

            Currently, only snapshot sharing events are supported.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-eventparameters.html#cfn-dlm-lifecyclepolicy-eventparameters-eventtype
            '''
            result = self._values.get("event_type")
            assert result is not None, "Required property 'event_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def snapshot_owner(self) -> typing.List[builtins.str]:
            '''The IDs of the AWS accounts that can trigger policy by sharing snapshots with your account.

            The policy only runs if one of the specified AWS accounts shares a snapshot with your account.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-eventparameters.html#cfn-dlm-lifecyclepolicy-eventparameters-snapshotowner
            '''
            result = self._values.get("snapshot_owner")
            assert result is not None, "Required property 'snapshot_owner' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def description_regex(self) -> typing.Optional[builtins.str]:
            '''The snapshot description that can trigger the policy.

            The description pattern is specified using a regular expression. The policy runs only if a snapshot with a description that matches the specified pattern is shared with your account.

            For example, specifying ``^.*Created for policy: policy-1234567890abcdef0.*$`` configures the policy to run only if snapshots created by policy ``policy-1234567890abcdef0`` are shared with your account.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-eventparameters.html#cfn-dlm-lifecyclepolicy-eventparameters-descriptionregex
            '''
            result = self._values.get("description_regex")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EventParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.EventSourceProperty",
        jsii_struct_bases=[],
        name_mapping={"type": "type", "parameters": "parameters"},
    )
    class EventSourceProperty:
        def __init__(
            self,
            *,
            type: builtins.str,
            parameters: typing.Optional[typing.Union["CfnLifecyclePolicy.EventParametersProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies an event that triggers an event-based policy.

            :param type: The source of the event. Currently only managed CloudWatch Events rules are supported.
            :param parameters: Information about the event.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-eventsource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                event_source_property = dlm.CfnLifecyclePolicy.EventSourceProperty(
                    type="type",
                
                    # the properties below are optional
                    parameters=dlm.CfnLifecyclePolicy.EventParametersProperty(
                        event_type="eventType",
                        snapshot_owner=["snapshotOwner"],
                
                        # the properties below are optional
                        description_regex="descriptionRegex"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "type": type,
            }
            if parameters is not None:
                self._values["parameters"] = parameters

        @builtins.property
        def type(self) -> builtins.str:
            '''The source of the event.

            Currently only managed CloudWatch Events rules are supported.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-eventsource.html#cfn-dlm-lifecyclepolicy-eventsource-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnLifecyclePolicy.EventParametersProperty", _IResolvable_da3f097b]]:
            '''Information about the event.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-eventsource.html#cfn-dlm-lifecyclepolicy-eventsource-parameters
            '''
            result = self._values.get("parameters")
            return typing.cast(typing.Optional[typing.Union["CfnLifecyclePolicy.EventParametersProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EventSourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.FastRestoreRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "availability_zones": "availabilityZones",
            "count": "count",
            "interval": "interval",
            "interval_unit": "intervalUnit",
        },
    )
    class FastRestoreRuleProperty:
        def __init__(
            self,
            *,
            availability_zones: typing.Optional[typing.Sequence[builtins.str]] = None,
            count: typing.Optional[jsii.Number] = None,
            interval: typing.Optional[jsii.Number] = None,
            interval_unit: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies a rule for enabling fast snapshot restore.

            You can enable fast snapshot restore based on either a count or a time interval.

            :param availability_zones: The Availability Zones in which to enable fast snapshot restore.
            :param count: The number of snapshots to be enabled with fast snapshot restore.
            :param interval: The amount of time to enable fast snapshot restore. The maximum is 100 years. This is equivalent to 1200 months, 5200 weeks, or 36500 days.
            :param interval_unit: The unit of time for enabling fast snapshot restore.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-fastrestorerule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                fast_restore_rule_property = dlm.CfnLifecyclePolicy.FastRestoreRuleProperty(
                    availability_zones=["availabilityZones"],
                    count=123,
                    interval=123,
                    interval_unit="intervalUnit"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if availability_zones is not None:
                self._values["availability_zones"] = availability_zones
            if count is not None:
                self._values["count"] = count
            if interval is not None:
                self._values["interval"] = interval
            if interval_unit is not None:
                self._values["interval_unit"] = interval_unit

        @builtins.property
        def availability_zones(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The Availability Zones in which to enable fast snapshot restore.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-fastrestorerule.html#cfn-dlm-lifecyclepolicy-fastrestorerule-availabilityzones
            '''
            result = self._values.get("availability_zones")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def count(self) -> typing.Optional[jsii.Number]:
            '''The number of snapshots to be enabled with fast snapshot restore.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-fastrestorerule.html#cfn-dlm-lifecyclepolicy-fastrestorerule-count
            '''
            result = self._values.get("count")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def interval(self) -> typing.Optional[jsii.Number]:
            '''The amount of time to enable fast snapshot restore.

            The maximum is 100 years. This is equivalent to 1200 months, 5200 weeks, or 36500 days.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-fastrestorerule.html#cfn-dlm-lifecyclepolicy-fastrestorerule-interval
            '''
            result = self._values.get("interval")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def interval_unit(self) -> typing.Optional[builtins.str]:
            '''The unit of time for enabling fast snapshot restore.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-fastrestorerule.html#cfn-dlm-lifecyclepolicy-fastrestorerule-intervalunit
            '''
            result = self._values.get("interval_unit")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FastRestoreRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.ParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "exclude_boot_volume": "excludeBootVolume",
            "no_reboot": "noReboot",
        },
    )
    class ParametersProperty:
        def __init__(
            self,
            *,
            exclude_boot_volume: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            no_reboot: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies optional parameters to add to a policy.

            The set of valid parameters depends on the combination of policy type and resource type.

            :param exclude_boot_volume: [EBS Snapshot Management – Instance policies only] Indicates whether to exclude the root volume from snapshots created using `CreateSnapshots <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateSnapshots.html>`_ . The default is false.
            :param no_reboot: Applies to AMI lifecycle policies only. Indicates whether targeted instances are rebooted when the lifecycle policy runs. ``true`` indicates that targeted instances are not rebooted when the policy runs. ``false`` indicates that target instances are rebooted when the policy runs. The default is ``true`` (instances are not rebooted).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-parameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                parameters_property = dlm.CfnLifecyclePolicy.ParametersProperty(
                    exclude_boot_volume=False,
                    no_reboot=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if exclude_boot_volume is not None:
                self._values["exclude_boot_volume"] = exclude_boot_volume
            if no_reboot is not None:
                self._values["no_reboot"] = no_reboot

        @builtins.property
        def exclude_boot_volume(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''[EBS Snapshot Management – Instance policies only] Indicates whether to exclude the root volume from snapshots created using `CreateSnapshots <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateSnapshots.html>`_ . The default is false.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-parameters.html#cfn-dlm-lifecyclepolicy-parameters-excludebootvolume
            '''
            result = self._values.get("exclude_boot_volume")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def no_reboot(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Applies to AMI lifecycle policies only.

            Indicates whether targeted instances are rebooted when the lifecycle policy runs. ``true`` indicates that targeted instances are not rebooted when the policy runs. ``false`` indicates that target instances are rebooted when the policy runs. The default is ``true`` (instances are not rebooted).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-parameters.html#cfn-dlm-lifecyclepolicy-parameters-noreboot
            '''
            result = self._values.get("no_reboot")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.PolicyDetailsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "actions": "actions",
            "event_source": "eventSource",
            "parameters": "parameters",
            "policy_type": "policyType",
            "resource_locations": "resourceLocations",
            "resource_types": "resourceTypes",
            "schedules": "schedules",
            "target_tags": "targetTags",
        },
    )
    class PolicyDetailsProperty:
        def __init__(
            self,
            *,
            actions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnLifecyclePolicy.ActionProperty", _IResolvable_da3f097b]]]] = None,
            event_source: typing.Optional[typing.Union["CfnLifecyclePolicy.EventSourceProperty", _IResolvable_da3f097b]] = None,
            parameters: typing.Optional[typing.Union["CfnLifecyclePolicy.ParametersProperty", _IResolvable_da3f097b]] = None,
            policy_type: typing.Optional[builtins.str] = None,
            resource_locations: typing.Optional[typing.Sequence[builtins.str]] = None,
            resource_types: typing.Optional[typing.Sequence[builtins.str]] = None,
            schedules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnLifecyclePolicy.ScheduleProperty", _IResolvable_da3f097b]]]] = None,
            target_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]] = None,
        ) -> None:
            '''Specifies the configuration of a lifecycle policy.

            :param actions: The actions to be performed when the event-based policy is triggered. You can specify only one action per policy. This parameter is required for event-based policies only. If you are creating a snapshot or AMI policy, omit this parameter.
            :param event_source: The event that triggers the event-based policy. This parameter is required for event-based policies only. If you are creating a snapshot or AMI policy, omit this parameter.
            :param parameters: A set of optional parameters for snapshot and AMI lifecycle policies. This parameter is required for snapshot and AMI policies only. If you are creating an event-based policy, omit this parameter. .. epigraph:: If you are modifying a policy that was created or previously modified using the Amazon Data Lifecycle Manager console, then you must include this parameter and specify either the default values or the new values that you require. You can't omit this parameter or set its values to null.
            :param policy_type: The valid target resource types and actions a policy can manage. Specify ``EBS_SNAPSHOT_MANAGEMENT`` to create a lifecycle policy that manages the lifecycle of Amazon EBS snapshots. Specify ``IMAGE_MANAGEMENT`` to create a lifecycle policy that manages the lifecycle of EBS-backed AMIs. Specify ``EVENT_BASED_POLICY`` to create an event-based policy that performs specific actions when a defined event occurs in your AWS account . The default is ``EBS_SNAPSHOT_MANAGEMENT`` .
            :param resource_locations: The location of the resources to backup. If the source resources are located in an AWS Region , specify ``CLOUD`` . If the source resources are located on an Outpost in your account, specify ``OUTPOST`` . If you specify ``OUTPOST`` , Amazon Data Lifecycle Manager backs up all resources of the specified type with matching target tags across all of the Outposts in your account.
            :param resource_types: The target resource type for snapshot and AMI lifecycle policies. Use ``VOLUME`` to create snapshots of individual volumes or use ``INSTANCE`` to create multi-volume snapshots from the volumes for an instance. This parameter is required for snapshot and AMI policies only. If you are creating an event-based policy, omit this parameter.
            :param schedules: The schedules of policy-defined actions for snapshot and AMI lifecycle policies. A policy can have up to four schedules—one mandatory schedule and up to three optional schedules. This parameter is required for snapshot and AMI policies only. If you are creating an event-based policy, omit this parameter.
            :param target_tags: The single tag that identifies targeted resources for this policy. This parameter is required for snapshot and AMI policies only. If you are creating an event-based policy, omit this parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-policydetails.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                policy_details_property = dlm.CfnLifecyclePolicy.PolicyDetailsProperty(
                    actions=[dlm.CfnLifecyclePolicy.ActionProperty(
                        cross_region_copy=[dlm.CfnLifecyclePolicy.CrossRegionCopyActionProperty(
                            encryption_configuration=dlm.CfnLifecyclePolicy.EncryptionConfigurationProperty(
                                encrypted=False,
                
                                # the properties below are optional
                                cmk_arn="cmkArn"
                            ),
                            target="target",
                
                            # the properties below are optional
                            retain_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty(
                                interval=123,
                                interval_unit="intervalUnit"
                            )
                        )],
                        name="name"
                    )],
                    event_source=dlm.CfnLifecyclePolicy.EventSourceProperty(
                        type="type",
                
                        # the properties below are optional
                        parameters=dlm.CfnLifecyclePolicy.EventParametersProperty(
                            event_type="eventType",
                            snapshot_owner=["snapshotOwner"],
                
                            # the properties below are optional
                            description_regex="descriptionRegex"
                        )
                    ),
                    parameters=dlm.CfnLifecyclePolicy.ParametersProperty(
                        exclude_boot_volume=False,
                        no_reboot=False
                    ),
                    policy_type="policyType",
                    resource_locations=["resourceLocations"],
                    resource_types=["resourceTypes"],
                    schedules=[dlm.CfnLifecyclePolicy.ScheduleProperty(
                        copy_tags=False,
                        create_rule=dlm.CfnLifecyclePolicy.CreateRuleProperty(
                            cron_expression="cronExpression",
                            interval=123,
                            interval_unit="intervalUnit",
                            location="location",
                            times=["times"]
                        ),
                        cross_region_copy_rules=[dlm.CfnLifecyclePolicy.CrossRegionCopyRuleProperty(
                            encrypted=False,
                
                            # the properties below are optional
                            cmk_arn="cmkArn",
                            copy_tags=False,
                            deprecate_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyDeprecateRuleProperty(
                                interval=123,
                                interval_unit="intervalUnit"
                            ),
                            retain_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty(
                                interval=123,
                                interval_unit="intervalUnit"
                            ),
                            target="target",
                            target_region="targetRegion"
                        )],
                        deprecate_rule=dlm.CfnLifecyclePolicy.DeprecateRuleProperty(
                            count=123,
                            interval=123,
                            interval_unit="intervalUnit"
                        ),
                        fast_restore_rule=dlm.CfnLifecyclePolicy.FastRestoreRuleProperty(
                            availability_zones=["availabilityZones"],
                            count=123,
                            interval=123,
                            interval_unit="intervalUnit"
                        ),
                        name="name",
                        retain_rule=dlm.CfnLifecyclePolicy.RetainRuleProperty(
                            count=123,
                            interval=123,
                            interval_unit="intervalUnit"
                        ),
                        share_rules=[dlm.CfnLifecyclePolicy.ShareRuleProperty(
                            target_accounts=["targetAccounts"],
                            unshare_interval=123,
                            unshare_interval_unit="unshareIntervalUnit"
                        )],
                        tags_to_add=[CfnTag(
                            key="key",
                            value="value"
                        )],
                        variable_tags=[CfnTag(
                            key="key",
                            value="value"
                        )]
                    )],
                    target_tags=[CfnTag(
                        key="key",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if actions is not None:
                self._values["actions"] = actions
            if event_source is not None:
                self._values["event_source"] = event_source
            if parameters is not None:
                self._values["parameters"] = parameters
            if policy_type is not None:
                self._values["policy_type"] = policy_type
            if resource_locations is not None:
                self._values["resource_locations"] = resource_locations
            if resource_types is not None:
                self._values["resource_types"] = resource_types
            if schedules is not None:
                self._values["schedules"] = schedules
            if target_tags is not None:
                self._values["target_tags"] = target_tags

        @builtins.property
        def actions(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLifecyclePolicy.ActionProperty", _IResolvable_da3f097b]]]]:
            '''The actions to be performed when the event-based policy is triggered. You can specify only one action per policy.

            This parameter is required for event-based policies only. If you are creating a snapshot or AMI policy, omit this parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-policydetails.html#cfn-dlm-lifecyclepolicy-policydetails-actions
            '''
            result = self._values.get("actions")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLifecyclePolicy.ActionProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def event_source(
            self,
        ) -> typing.Optional[typing.Union["CfnLifecyclePolicy.EventSourceProperty", _IResolvable_da3f097b]]:
            '''The event that triggers the event-based policy.

            This parameter is required for event-based policies only. If you are creating a snapshot or AMI policy, omit this parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-policydetails.html#cfn-dlm-lifecyclepolicy-policydetails-eventsource
            '''
            result = self._values.get("event_source")
            return typing.cast(typing.Optional[typing.Union["CfnLifecyclePolicy.EventSourceProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnLifecyclePolicy.ParametersProperty", _IResolvable_da3f097b]]:
            '''A set of optional parameters for snapshot and AMI lifecycle policies.

            This parameter is required for snapshot and AMI policies only. If you are creating an event-based policy, omit this parameter.
            .. epigraph::

               If you are modifying a policy that was created or previously modified using the Amazon Data Lifecycle Manager console, then you must include this parameter and specify either the default values or the new values that you require. You can't omit this parameter or set its values to null.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-policydetails.html#cfn-dlm-lifecyclepolicy-policydetails-parameters
            '''
            result = self._values.get("parameters")
            return typing.cast(typing.Optional[typing.Union["CfnLifecyclePolicy.ParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def policy_type(self) -> typing.Optional[builtins.str]:
            '''The valid target resource types and actions a policy can manage.

            Specify ``EBS_SNAPSHOT_MANAGEMENT`` to create a lifecycle policy that manages the lifecycle of Amazon EBS snapshots. Specify ``IMAGE_MANAGEMENT`` to create a lifecycle policy that manages the lifecycle of EBS-backed AMIs. Specify ``EVENT_BASED_POLICY`` to create an event-based policy that performs specific actions when a defined event occurs in your AWS account .

            The default is ``EBS_SNAPSHOT_MANAGEMENT`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-policydetails.html#cfn-dlm-lifecyclepolicy-policydetails-policytype
            '''
            result = self._values.get("policy_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def resource_locations(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The location of the resources to backup.

            If the source resources are located in an AWS Region , specify ``CLOUD`` . If the source resources are located on an Outpost in your account, specify ``OUTPOST`` .

            If you specify ``OUTPOST`` , Amazon Data Lifecycle Manager backs up all resources of the specified type with matching target tags across all of the Outposts in your account.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-policydetails.html#cfn-dlm-lifecyclepolicy-policydetails-resourcelocations
            '''
            result = self._values.get("resource_locations")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def resource_types(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The target resource type for snapshot and AMI lifecycle policies.

            Use ``VOLUME`` to create snapshots of individual volumes or use ``INSTANCE`` to create multi-volume snapshots from the volumes for an instance.

            This parameter is required for snapshot and AMI policies only. If you are creating an event-based policy, omit this parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-policydetails.html#cfn-dlm-lifecyclepolicy-policydetails-resourcetypes
            '''
            result = self._values.get("resource_types")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def schedules(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLifecyclePolicy.ScheduleProperty", _IResolvable_da3f097b]]]]:
            '''The schedules of policy-defined actions for snapshot and AMI lifecycle policies.

            A policy can have up to four schedules—one mandatory schedule and up to three optional schedules.

            This parameter is required for snapshot and AMI policies only. If you are creating an event-based policy, omit this parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-policydetails.html#cfn-dlm-lifecyclepolicy-policydetails-schedules
            '''
            result = self._values.get("schedules")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLifecyclePolicy.ScheduleProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def target_tags(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]]:
            '''The single tag that identifies targeted resources for this policy.

            This parameter is required for snapshot and AMI policies only. If you are creating an event-based policy, omit this parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-policydetails.html#cfn-dlm-lifecyclepolicy-policydetails-targettags
            '''
            result = self._values.get("target_tags")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PolicyDetailsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.RetainRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "count": "count",
            "interval": "interval",
            "interval_unit": "intervalUnit",
        },
    )
    class RetainRuleProperty:
        def __init__(
            self,
            *,
            count: typing.Optional[jsii.Number] = None,
            interval: typing.Optional[jsii.Number] = None,
            interval_unit: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies the retention rule for a lifecycle policy.

            You can retain snapshots based on either a count or a time interval.

            :param count: The number of snapshots to retain for each volume, up to a maximum of 1000.
            :param interval: The amount of time to retain each snapshot. The maximum is 100 years. This is equivalent to 1200 months, 5200 weeks, or 36500 days.
            :param interval_unit: The unit of time for time-based retention.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-retainrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                retain_rule_property = dlm.CfnLifecyclePolicy.RetainRuleProperty(
                    count=123,
                    interval=123,
                    interval_unit="intervalUnit"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if count is not None:
                self._values["count"] = count
            if interval is not None:
                self._values["interval"] = interval
            if interval_unit is not None:
                self._values["interval_unit"] = interval_unit

        @builtins.property
        def count(self) -> typing.Optional[jsii.Number]:
            '''The number of snapshots to retain for each volume, up to a maximum of 1000.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-retainrule.html#cfn-dlm-lifecyclepolicy-retainrule-count
            '''
            result = self._values.get("count")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def interval(self) -> typing.Optional[jsii.Number]:
            '''The amount of time to retain each snapshot.

            The maximum is 100 years. This is equivalent to 1200 months, 5200 weeks, or 36500 days.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-retainrule.html#cfn-dlm-lifecyclepolicy-retainrule-interval
            '''
            result = self._values.get("interval")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def interval_unit(self) -> typing.Optional[builtins.str]:
            '''The unit of time for time-based retention.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-retainrule.html#cfn-dlm-lifecyclepolicy-retainrule-intervalunit
            '''
            result = self._values.get("interval_unit")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RetainRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.ScheduleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "copy_tags": "copyTags",
            "create_rule": "createRule",
            "cross_region_copy_rules": "crossRegionCopyRules",
            "deprecate_rule": "deprecateRule",
            "fast_restore_rule": "fastRestoreRule",
            "name": "name",
            "retain_rule": "retainRule",
            "share_rules": "shareRules",
            "tags_to_add": "tagsToAdd",
            "variable_tags": "variableTags",
        },
    )
    class ScheduleProperty:
        def __init__(
            self,
            *,
            copy_tags: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            create_rule: typing.Optional[typing.Union["CfnLifecyclePolicy.CreateRuleProperty", _IResolvable_da3f097b]] = None,
            cross_region_copy_rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnLifecyclePolicy.CrossRegionCopyRuleProperty", _IResolvable_da3f097b]]]] = None,
            deprecate_rule: typing.Optional[typing.Union["CfnLifecyclePolicy.DeprecateRuleProperty", _IResolvable_da3f097b]] = None,
            fast_restore_rule: typing.Optional[typing.Union["CfnLifecyclePolicy.FastRestoreRuleProperty", _IResolvable_da3f097b]] = None,
            name: typing.Optional[builtins.str] = None,
            retain_rule: typing.Optional[typing.Union["CfnLifecyclePolicy.RetainRuleProperty", _IResolvable_da3f097b]] = None,
            share_rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnLifecyclePolicy.ShareRuleProperty", _IResolvable_da3f097b]]]] = None,
            tags_to_add: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]] = None,
            variable_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]] = None,
        ) -> None:
            '''Specifies a backup schedule for a snapshot or AMI lifecycle policy.

            :param copy_tags: Copy all user-defined tags on a source volume to snapshots of the volume created by this policy.
            :param create_rule: The creation rule.
            :param cross_region_copy_rules: The rule for cross-Region snapshot copies. You can only specify cross-Region copy rules for policies that create snapshots in a Region. If the policy creates snapshots on an Outpost, then you cannot copy the snapshots to a Region or to an Outpost. If the policy creates snapshots in a Region, then snapshots can be copied to up to three Regions or Outposts.
            :param deprecate_rule: The AMI deprecation rule for the schedule.
            :param fast_restore_rule: The rule for enabling fast snapshot restore.
            :param name: The name of the schedule.
            :param retain_rule: The retention rule.
            :param share_rules: The rule for sharing snapshots with other AWS accounts .
            :param tags_to_add: The tags to apply to policy-created resources. These user-defined tags are in addition to the AWS -added lifecycle tags.
            :param variable_tags: A collection of key/value pairs with values determined dynamically when the policy is executed. Keys may be any valid Amazon EC2 tag key. Values must be in one of the two following formats: ``$(instance-id)`` or ``$(timestamp)`` . Variable tags are only valid for EBS Snapshot Management – Instance policies.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-schedule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                schedule_property = dlm.CfnLifecyclePolicy.ScheduleProperty(
                    copy_tags=False,
                    create_rule=dlm.CfnLifecyclePolicy.CreateRuleProperty(
                        cron_expression="cronExpression",
                        interval=123,
                        interval_unit="intervalUnit",
                        location="location",
                        times=["times"]
                    ),
                    cross_region_copy_rules=[dlm.CfnLifecyclePolicy.CrossRegionCopyRuleProperty(
                        encrypted=False,
                
                        # the properties below are optional
                        cmk_arn="cmkArn",
                        copy_tags=False,
                        deprecate_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyDeprecateRuleProperty(
                            interval=123,
                            interval_unit="intervalUnit"
                        ),
                        retain_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty(
                            interval=123,
                            interval_unit="intervalUnit"
                        ),
                        target="target",
                        target_region="targetRegion"
                    )],
                    deprecate_rule=dlm.CfnLifecyclePolicy.DeprecateRuleProperty(
                        count=123,
                        interval=123,
                        interval_unit="intervalUnit"
                    ),
                    fast_restore_rule=dlm.CfnLifecyclePolicy.FastRestoreRuleProperty(
                        availability_zones=["availabilityZones"],
                        count=123,
                        interval=123,
                        interval_unit="intervalUnit"
                    ),
                    name="name",
                    retain_rule=dlm.CfnLifecyclePolicy.RetainRuleProperty(
                        count=123,
                        interval=123,
                        interval_unit="intervalUnit"
                    ),
                    share_rules=[dlm.CfnLifecyclePolicy.ShareRuleProperty(
                        target_accounts=["targetAccounts"],
                        unshare_interval=123,
                        unshare_interval_unit="unshareIntervalUnit"
                    )],
                    tags_to_add=[CfnTag(
                        key="key",
                        value="value"
                    )],
                    variable_tags=[CfnTag(
                        key="key",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if copy_tags is not None:
                self._values["copy_tags"] = copy_tags
            if create_rule is not None:
                self._values["create_rule"] = create_rule
            if cross_region_copy_rules is not None:
                self._values["cross_region_copy_rules"] = cross_region_copy_rules
            if deprecate_rule is not None:
                self._values["deprecate_rule"] = deprecate_rule
            if fast_restore_rule is not None:
                self._values["fast_restore_rule"] = fast_restore_rule
            if name is not None:
                self._values["name"] = name
            if retain_rule is not None:
                self._values["retain_rule"] = retain_rule
            if share_rules is not None:
                self._values["share_rules"] = share_rules
            if tags_to_add is not None:
                self._values["tags_to_add"] = tags_to_add
            if variable_tags is not None:
                self._values["variable_tags"] = variable_tags

        @builtins.property
        def copy_tags(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Copy all user-defined tags on a source volume to snapshots of the volume created by this policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-schedule.html#cfn-dlm-lifecyclepolicy-schedule-copytags
            '''
            result = self._values.get("copy_tags")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def create_rule(
            self,
        ) -> typing.Optional[typing.Union["CfnLifecyclePolicy.CreateRuleProperty", _IResolvable_da3f097b]]:
            '''The creation rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-schedule.html#cfn-dlm-lifecyclepolicy-schedule-createrule
            '''
            result = self._values.get("create_rule")
            return typing.cast(typing.Optional[typing.Union["CfnLifecyclePolicy.CreateRuleProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def cross_region_copy_rules(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLifecyclePolicy.CrossRegionCopyRuleProperty", _IResolvable_da3f097b]]]]:
            '''The rule for cross-Region snapshot copies.

            You can only specify cross-Region copy rules for policies that create snapshots in a Region. If the policy creates snapshots on an Outpost, then you cannot copy the snapshots to a Region or to an Outpost. If the policy creates snapshots in a Region, then snapshots can be copied to up to three Regions or Outposts.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-schedule.html#cfn-dlm-lifecyclepolicy-schedule-crossregioncopyrules
            '''
            result = self._values.get("cross_region_copy_rules")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLifecyclePolicy.CrossRegionCopyRuleProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def deprecate_rule(
            self,
        ) -> typing.Optional[typing.Union["CfnLifecyclePolicy.DeprecateRuleProperty", _IResolvable_da3f097b]]:
            '''The AMI deprecation rule for the schedule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-schedule.html#cfn-dlm-lifecyclepolicy-schedule-deprecaterule
            '''
            result = self._values.get("deprecate_rule")
            return typing.cast(typing.Optional[typing.Union["CfnLifecyclePolicy.DeprecateRuleProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def fast_restore_rule(
            self,
        ) -> typing.Optional[typing.Union["CfnLifecyclePolicy.FastRestoreRuleProperty", _IResolvable_da3f097b]]:
            '''The rule for enabling fast snapshot restore.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-schedule.html#cfn-dlm-lifecyclepolicy-schedule-fastrestorerule
            '''
            result = self._values.get("fast_restore_rule")
            return typing.cast(typing.Optional[typing.Union["CfnLifecyclePolicy.FastRestoreRuleProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the schedule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-schedule.html#cfn-dlm-lifecyclepolicy-schedule-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def retain_rule(
            self,
        ) -> typing.Optional[typing.Union["CfnLifecyclePolicy.RetainRuleProperty", _IResolvable_da3f097b]]:
            '''The retention rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-schedule.html#cfn-dlm-lifecyclepolicy-schedule-retainrule
            '''
            result = self._values.get("retain_rule")
            return typing.cast(typing.Optional[typing.Union["CfnLifecyclePolicy.RetainRuleProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def share_rules(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLifecyclePolicy.ShareRuleProperty", _IResolvable_da3f097b]]]]:
            '''The rule for sharing snapshots with other AWS accounts .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-schedule.html#cfn-dlm-lifecyclepolicy-schedule-sharerules
            '''
            result = self._values.get("share_rules")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLifecyclePolicy.ShareRuleProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def tags_to_add(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]]:
            '''The tags to apply to policy-created resources.

            These user-defined tags are in addition to the AWS -added lifecycle tags.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-schedule.html#cfn-dlm-lifecyclepolicy-schedule-tagstoadd
            '''
            result = self._values.get("tags_to_add")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]], result)

        @builtins.property
        def variable_tags(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]]:
            '''A collection of key/value pairs with values determined dynamically when the policy is executed.

            Keys may be any valid Amazon EC2 tag key. Values must be in one of the two following formats: ``$(instance-id)`` or ``$(timestamp)`` . Variable tags are only valid for EBS Snapshot Management – Instance policies.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-schedule.html#cfn-dlm-lifecyclepolicy-schedule-variabletags
            '''
            result = self._values.get("variable_tags")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScheduleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicy.ShareRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "target_accounts": "targetAccounts",
            "unshare_interval": "unshareInterval",
            "unshare_interval_unit": "unshareIntervalUnit",
        },
    )
    class ShareRuleProperty:
        def __init__(
            self,
            *,
            target_accounts: typing.Optional[typing.Sequence[builtins.str]] = None,
            unshare_interval: typing.Optional[jsii.Number] = None,
            unshare_interval_unit: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies a rule for sharing snapshots across AWS accounts .

            :param target_accounts: The IDs of the AWS accounts with which to share the snapshots.
            :param unshare_interval: The period after which snapshots that are shared with other AWS accounts are automatically unshared.
            :param unshare_interval_unit: The unit of time for the automatic unsharing interval.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-sharerule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dlm as dlm
                
                share_rule_property = dlm.CfnLifecyclePolicy.ShareRuleProperty(
                    target_accounts=["targetAccounts"],
                    unshare_interval=123,
                    unshare_interval_unit="unshareIntervalUnit"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if target_accounts is not None:
                self._values["target_accounts"] = target_accounts
            if unshare_interval is not None:
                self._values["unshare_interval"] = unshare_interval
            if unshare_interval_unit is not None:
                self._values["unshare_interval_unit"] = unshare_interval_unit

        @builtins.property
        def target_accounts(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The IDs of the AWS accounts with which to share the snapshots.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-sharerule.html#cfn-dlm-lifecyclepolicy-sharerule-targetaccounts
            '''
            result = self._values.get("target_accounts")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def unshare_interval(self) -> typing.Optional[jsii.Number]:
            '''The period after which snapshots that are shared with other AWS accounts are automatically unshared.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-sharerule.html#cfn-dlm-lifecyclepolicy-sharerule-unshareinterval
            '''
            result = self._values.get("unshare_interval")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def unshare_interval_unit(self) -> typing.Optional[builtins.str]:
            '''The unit of time for the automatic unsharing interval.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dlm-lifecyclepolicy-sharerule.html#cfn-dlm-lifecyclepolicy-sharerule-unshareintervalunit
            '''
            result = self._values.get("unshare_interval_unit")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ShareRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_dlm.CfnLifecyclePolicyProps",
    jsii_struct_bases=[],
    name_mapping={
        "description": "description",
        "execution_role_arn": "executionRoleArn",
        "policy_details": "policyDetails",
        "state": "state",
        "tags": "tags",
    },
)
class CfnLifecyclePolicyProps:
    def __init__(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        execution_role_arn: typing.Optional[builtins.str] = None,
        policy_details: typing.Optional[typing.Union[CfnLifecyclePolicy.PolicyDetailsProperty, _IResolvable_da3f097b]] = None,
        state: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnLifecyclePolicy``.

        :param description: A description of the lifecycle policy. The characters ^[0-9A-Za-z _-]+$ are supported.
        :param execution_role_arn: The Amazon Resource Name (ARN) of the IAM role used to run the operations specified by the lifecycle policy.
        :param policy_details: The configuration details of the lifecycle policy.
        :param state: The activation state of the lifecycle policy.
        :param tags: The tags to apply to the lifecycle policy during creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dlm-lifecyclepolicy.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_dlm as dlm
            
            cfn_lifecycle_policy_props = dlm.CfnLifecyclePolicyProps(
                description="description",
                execution_role_arn="executionRoleArn",
                policy_details=dlm.CfnLifecyclePolicy.PolicyDetailsProperty(
                    actions=[dlm.CfnLifecyclePolicy.ActionProperty(
                        cross_region_copy=[dlm.CfnLifecyclePolicy.CrossRegionCopyActionProperty(
                            encryption_configuration=dlm.CfnLifecyclePolicy.EncryptionConfigurationProperty(
                                encrypted=False,
            
                                # the properties below are optional
                                cmk_arn="cmkArn"
                            ),
                            target="target",
            
                            # the properties below are optional
                            retain_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty(
                                interval=123,
                                interval_unit="intervalUnit"
                            )
                        )],
                        name="name"
                    )],
                    event_source=dlm.CfnLifecyclePolicy.EventSourceProperty(
                        type="type",
            
                        # the properties below are optional
                        parameters=dlm.CfnLifecyclePolicy.EventParametersProperty(
                            event_type="eventType",
                            snapshot_owner=["snapshotOwner"],
            
                            # the properties below are optional
                            description_regex="descriptionRegex"
                        )
                    ),
                    parameters=dlm.CfnLifecyclePolicy.ParametersProperty(
                        exclude_boot_volume=False,
                        no_reboot=False
                    ),
                    policy_type="policyType",
                    resource_locations=["resourceLocations"],
                    resource_types=["resourceTypes"],
                    schedules=[dlm.CfnLifecyclePolicy.ScheduleProperty(
                        copy_tags=False,
                        create_rule=dlm.CfnLifecyclePolicy.CreateRuleProperty(
                            cron_expression="cronExpression",
                            interval=123,
                            interval_unit="intervalUnit",
                            location="location",
                            times=["times"]
                        ),
                        cross_region_copy_rules=[dlm.CfnLifecyclePolicy.CrossRegionCopyRuleProperty(
                            encrypted=False,
            
                            # the properties below are optional
                            cmk_arn="cmkArn",
                            copy_tags=False,
                            deprecate_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyDeprecateRuleProperty(
                                interval=123,
                                interval_unit="intervalUnit"
                            ),
                            retain_rule=dlm.CfnLifecyclePolicy.CrossRegionCopyRetainRuleProperty(
                                interval=123,
                                interval_unit="intervalUnit"
                            ),
                            target="target",
                            target_region="targetRegion"
                        )],
                        deprecate_rule=dlm.CfnLifecyclePolicy.DeprecateRuleProperty(
                            count=123,
                            interval=123,
                            interval_unit="intervalUnit"
                        ),
                        fast_restore_rule=dlm.CfnLifecyclePolicy.FastRestoreRuleProperty(
                            availability_zones=["availabilityZones"],
                            count=123,
                            interval=123,
                            interval_unit="intervalUnit"
                        ),
                        name="name",
                        retain_rule=dlm.CfnLifecyclePolicy.RetainRuleProperty(
                            count=123,
                            interval=123,
                            interval_unit="intervalUnit"
                        ),
                        share_rules=[dlm.CfnLifecyclePolicy.ShareRuleProperty(
                            target_accounts=["targetAccounts"],
                            unshare_interval=123,
                            unshare_interval_unit="unshareIntervalUnit"
                        )],
                        tags_to_add=[CfnTag(
                            key="key",
                            value="value"
                        )],
                        variable_tags=[CfnTag(
                            key="key",
                            value="value"
                        )]
                    )],
                    target_tags=[CfnTag(
                        key="key",
                        value="value"
                    )]
                ),
                state="state",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if description is not None:
            self._values["description"] = description
        if execution_role_arn is not None:
            self._values["execution_role_arn"] = execution_role_arn
        if policy_details is not None:
            self._values["policy_details"] = policy_details
        if state is not None:
            self._values["state"] = state
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the lifecycle policy.

        The characters ^[0-9A-Za-z _-]+$ are supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dlm-lifecyclepolicy.html#cfn-dlm-lifecyclepolicy-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def execution_role_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the IAM role used to run the operations specified by the lifecycle policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dlm-lifecyclepolicy.html#cfn-dlm-lifecyclepolicy-executionrolearn
        '''
        result = self._values.get("execution_role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def policy_details(
        self,
    ) -> typing.Optional[typing.Union[CfnLifecyclePolicy.PolicyDetailsProperty, _IResolvable_da3f097b]]:
        '''The configuration details of the lifecycle policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dlm-lifecyclepolicy.html#cfn-dlm-lifecyclepolicy-policydetails
        '''
        result = self._values.get("policy_details")
        return typing.cast(typing.Optional[typing.Union[CfnLifecyclePolicy.PolicyDetailsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def state(self) -> typing.Optional[builtins.str]:
        '''The activation state of the lifecycle policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dlm-lifecyclepolicy.html#cfn-dlm-lifecyclepolicy-state
        '''
        result = self._values.get("state")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags to apply to the lifecycle policy during creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dlm-lifecyclepolicy.html#cfn-dlm-lifecyclepolicy-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnLifecyclePolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnLifecyclePolicy",
    "CfnLifecyclePolicyProps",
]

publication.publish()
