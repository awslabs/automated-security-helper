'''
# AWS::FIS Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_fis as fis
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-fis-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::FIS](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_FIS.html).

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
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.implements(_IInspectable_c2943556)
class CfnExperimentTemplate(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_fis.CfnExperimentTemplate",
):
    '''A CloudFormation ``AWS::FIS::ExperimentTemplate``.

    Specifies an experiment template.

    An experiment template includes the following components:

    - *Targets* : A target can be a specific resource in your AWS environment, or one or more resources that match criteria that you specify, for example, resources that have specific tags.
    - *Actions* : The actions to carry out on the target. You can specify multiple actions, the duration of each action, and when to start each action during an experiment.
    - *Stop conditions* : If a stop condition is triggered while an experiment is running, the experiment is automatically stopped. You can define a stop condition as a CloudWatch alarm.

    For more information, see `Experiment templates <https://docs.aws.amazon.com/fis/latest/userguide/experiment-templates.html>`_ in the *AWS Fault Injection Simulator User Guide* .

    :cloudformationResource: AWS::FIS::ExperimentTemplate
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fis-experimenttemplate.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_fis as fis
        
        cfn_experiment_template = fis.CfnExperimentTemplate(self, "MyCfnExperimentTemplate",
            description="description",
            role_arn="roleArn",
            stop_conditions=[fis.CfnExperimentTemplate.ExperimentTemplateStopConditionProperty(
                source="source",
        
                # the properties below are optional
                value="value"
            )],
            tags={
                "tags_key": "tags"
            },
            targets={
                "targets_key": fis.CfnExperimentTemplate.ExperimentTemplateTargetProperty(
                    resource_type="resourceType",
                    selection_mode="selectionMode",
        
                    # the properties below are optional
                    filters=[fis.CfnExperimentTemplate.ExperimentTemplateTargetFilterProperty(
                        path="path",
                        values=["values"]
                    )],
                    resource_arns=["resourceArns"],
                    resource_tags={
                        "resource_tags_key": "resourceTags"
                    }
                )
            },
        
            # the properties below are optional
            actions={
                "actions_key": fis.CfnExperimentTemplate.ExperimentTemplateActionProperty(
                    action_id="actionId",
        
                    # the properties below are optional
                    description="description",
                    parameters={
                        "parameters_key": "parameters"
                    },
                    start_after=["startAfter"],
                    targets={
                        "targets_key": "targets"
                    }
                )
            }
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        description: builtins.str,
        role_arn: builtins.str,
        stop_conditions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnExperimentTemplate.ExperimentTemplateStopConditionProperty", _IResolvable_da3f097b]]],
        tags: typing.Mapping[builtins.str, builtins.str],
        targets: typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnExperimentTemplate.ExperimentTemplateTargetProperty", _IResolvable_da3f097b]]],
        actions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnExperimentTemplate.ExperimentTemplateActionProperty", _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Create a new ``AWS::FIS::ExperimentTemplate``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param description: A description for the experiment template.
        :param role_arn: The Amazon Resource Name (ARN) of an IAM role that grants the AWS FIS service permission to perform service actions on your behalf.
        :param stop_conditions: The stop conditions.
        :param tags: The tags to apply to the experiment template.
        :param targets: The targets for the experiment.
        :param actions: The actions for the experiment.
        '''
        props = CfnExperimentTemplateProps(
            description=description,
            role_arn=role_arn,
            stop_conditions=stop_conditions,
            tags=tags,
            targets=targets,
            actions=actions,
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
        '''The ID of the experiment template.

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
        '''The tags to apply to the experiment template.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fis-experimenttemplate.html#cfn-fis-experimenttemplate-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> builtins.str:
        '''A description for the experiment template.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fis-experimenttemplate.html#cfn-fis-experimenttemplate-description
        '''
        return typing.cast(builtins.str, jsii.get(self, "description"))

    @description.setter
    def description(self, value: builtins.str) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of an IAM role that grants the AWS FIS service permission to perform service actions on your behalf.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fis-experimenttemplate.html#cfn-fis-experimenttemplate-rolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "roleArn"))

    @role_arn.setter
    def role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "roleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="stopConditions")
    def stop_conditions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnExperimentTemplate.ExperimentTemplateStopConditionProperty", _IResolvable_da3f097b]]]:
        '''The stop conditions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fis-experimenttemplate.html#cfn-fis-experimenttemplate-stopconditions
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnExperimentTemplate.ExperimentTemplateStopConditionProperty", _IResolvable_da3f097b]]], jsii.get(self, "stopConditions"))

    @stop_conditions.setter
    def stop_conditions(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnExperimentTemplate.ExperimentTemplateStopConditionProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "stopConditions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targets")
    def targets(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnExperimentTemplate.ExperimentTemplateTargetProperty", _IResolvable_da3f097b]]]:
        '''The targets for the experiment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fis-experimenttemplate.html#cfn-fis-experimenttemplate-targets
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnExperimentTemplate.ExperimentTemplateTargetProperty", _IResolvable_da3f097b]]], jsii.get(self, "targets"))

    @targets.setter
    def targets(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnExperimentTemplate.ExperimentTemplateTargetProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "targets", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="actions")
    def actions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnExperimentTemplate.ExperimentTemplateActionProperty", _IResolvable_da3f097b]]]]:
        '''The actions for the experiment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fis-experimenttemplate.html#cfn-fis-experimenttemplate-actions
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnExperimentTemplate.ExperimentTemplateActionProperty", _IResolvable_da3f097b]]]], jsii.get(self, "actions"))

    @actions.setter
    def actions(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnExperimentTemplate.ExperimentTemplateActionProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "actions", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fis.CfnExperimentTemplate.ExperimentTemplateActionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "action_id": "actionId",
            "description": "description",
            "parameters": "parameters",
            "start_after": "startAfter",
            "targets": "targets",
        },
    )
    class ExperimentTemplateActionProperty:
        def __init__(
            self,
            *,
            action_id: builtins.str,
            description: typing.Optional[builtins.str] = None,
            parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
            start_after: typing.Optional[typing.Sequence[builtins.str]] = None,
            targets: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
        ) -> None:
            '''Specifies an action for an experiment template.

            For more information, see `Actions <https://docs.aws.amazon.com/fis/latest/userguide/actions.html>`_ in the *AWS Fault Injection Simulator User Guide* .

            :param action_id: The ID of the action. The format of the action ID is: aws: *service-name* : *action-type* .
            :param description: A description for the action.
            :param parameters: The parameters for the action, if applicable.
            :param start_after: The name of the action that must be completed before the current action starts. Omit this parameter to run the action at the start of the experiment.
            :param targets: The targets for the action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplateaction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fis as fis
                
                experiment_template_action_property = fis.CfnExperimentTemplate.ExperimentTemplateActionProperty(
                    action_id="actionId",
                
                    # the properties below are optional
                    description="description",
                    parameters={
                        "parameters_key": "parameters"
                    },
                    start_after=["startAfter"],
                    targets={
                        "targets_key": "targets"
                    }
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "action_id": action_id,
            }
            if description is not None:
                self._values["description"] = description
            if parameters is not None:
                self._values["parameters"] = parameters
            if start_after is not None:
                self._values["start_after"] = start_after
            if targets is not None:
                self._values["targets"] = targets

        @builtins.property
        def action_id(self) -> builtins.str:
            '''The ID of the action.

            The format of the action ID is: aws: *service-name* : *action-type* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplateaction.html#cfn-fis-experimenttemplate-experimenttemplateaction-actionid
            '''
            result = self._values.get("action_id")
            assert result is not None, "Required property 'action_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def description(self) -> typing.Optional[builtins.str]:
            '''A description for the action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplateaction.html#cfn-fis-experimenttemplate-experimenttemplateaction-description
            '''
            result = self._values.get("description")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''The parameters for the action, if applicable.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplateaction.html#cfn-fis-experimenttemplate-experimenttemplateaction-parameters
            '''
            result = self._values.get("parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        @builtins.property
        def start_after(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The name of the action that must be completed before the current action starts.

            Omit this parameter to run the action at the start of the experiment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplateaction.html#cfn-fis-experimenttemplate-experimenttemplateaction-startafter
            '''
            result = self._values.get("start_after")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def targets(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''The targets for the action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplateaction.html#cfn-fis-experimenttemplate-experimenttemplateaction-targets
            '''
            result = self._values.get("targets")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ExperimentTemplateActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fis.CfnExperimentTemplate.ExperimentTemplateStopConditionProperty",
        jsii_struct_bases=[],
        name_mapping={"source": "source", "value": "value"},
    )
    class ExperimentTemplateStopConditionProperty:
        def __init__(
            self,
            *,
            source: builtins.str,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies a stop condition for an experiment template.

            :param source: The source for the stop condition. Specify ``aws:cloudwatch:alarm`` if the stop condition is defined by a CloudWatch alarm. Specify ``none`` if there is no stop condition.
            :param value: The Amazon Resource Name (ARN) of the CloudWatch alarm. This is required if the source is a CloudWatch alarm.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplatestopcondition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fis as fis
                
                experiment_template_stop_condition_property = fis.CfnExperimentTemplate.ExperimentTemplateStopConditionProperty(
                    source="source",
                
                    # the properties below are optional
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "source": source,
            }
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def source(self) -> builtins.str:
            '''The source for the stop condition.

            Specify ``aws:cloudwatch:alarm`` if the stop condition is defined by a CloudWatch alarm. Specify ``none`` if there is no stop condition.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplatestopcondition.html#cfn-fis-experimenttemplate-experimenttemplatestopcondition-source
            '''
            result = self._values.get("source")
            assert result is not None, "Required property 'source' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the CloudWatch alarm.

            This is required if the source is a CloudWatch alarm.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplatestopcondition.html#cfn-fis-experimenttemplate-experimenttemplatestopcondition-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ExperimentTemplateStopConditionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fis.CfnExperimentTemplate.ExperimentTemplateTargetFilterProperty",
        jsii_struct_bases=[],
        name_mapping={"path": "path", "values": "values"},
    )
    class ExperimentTemplateTargetFilterProperty:
        def __init__(
            self,
            *,
            path: builtins.str,
            values: typing.Sequence[builtins.str],
        ) -> None:
            '''Specifies a filter used for the target resource input in an experiment template.

            For more information, see `Resource filters <https://docs.aws.amazon.com/fis/latest/userguide/targets.html#target-filters>`_ in the *AWS Fault Injection Simulator User Guide* .

            :param path: The attribute path for the filter.
            :param values: The attribute values for the filter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplatetargetfilter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fis as fis
                
                experiment_template_target_filter_property = fis.CfnExperimentTemplate.ExperimentTemplateTargetFilterProperty(
                    path="path",
                    values=["values"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "path": path,
                "values": values,
            }

        @builtins.property
        def path(self) -> builtins.str:
            '''The attribute path for the filter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplatetargetfilter.html#cfn-fis-experimenttemplate-experimenttemplatetargetfilter-path
            '''
            result = self._values.get("path")
            assert result is not None, "Required property 'path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def values(self) -> typing.List[builtins.str]:
            '''The attribute values for the filter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplatetargetfilter.html#cfn-fis-experimenttemplate-experimenttemplatetargetfilter-values
            '''
            result = self._values.get("values")
            assert result is not None, "Required property 'values' is missing"
            return typing.cast(typing.List[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ExperimentTemplateTargetFilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fis.CfnExperimentTemplate.ExperimentTemplateTargetProperty",
        jsii_struct_bases=[],
        name_mapping={
            "resource_type": "resourceType",
            "selection_mode": "selectionMode",
            "filters": "filters",
            "resource_arns": "resourceArns",
            "resource_tags": "resourceTags",
        },
    )
    class ExperimentTemplateTargetProperty:
        def __init__(
            self,
            *,
            resource_type: builtins.str,
            selection_mode: builtins.str,
            filters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnExperimentTemplate.ExperimentTemplateTargetFilterProperty", _IResolvable_da3f097b]]]] = None,
            resource_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
            resource_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
        ) -> None:
            '''Specifies a target for an experiment.

            You must specify at least one Amazon Resource Name (ARN) or at least one resource tag. You cannot specify both ARNs and tags.

            For more information, see `Targets <https://docs.aws.amazon.com/fis/latest/userguide/targets.html>`_ in the *AWS Fault Injection Simulator User Guide* .

            :param resource_type: The resource type. The resource type must be supported for the specified action.
            :param selection_mode: Scopes the identified resources to a specific count of the resources at random, or a percentage of the resources. All identified resources are included in the target. - ALL - Run the action on all identified targets. This is the default. - COUNT(n) - Run the action on the specified number of targets, chosen from the identified targets at random. For example, COUNT(1) selects one of the targets. - PERCENT(n) - Run the action on the specified percentage of targets, chosen from the identified targets at random. For example, PERCENT(25) selects 25% of the targets.
            :param filters: The filters to apply to identify target resources using specific attributes.
            :param resource_arns: The Amazon Resource Names (ARNs) of the resources.
            :param resource_tags: The tags for the target resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplatetarget.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fis as fis
                
                experiment_template_target_property = fis.CfnExperimentTemplate.ExperimentTemplateTargetProperty(
                    resource_type="resourceType",
                    selection_mode="selectionMode",
                
                    # the properties below are optional
                    filters=[fis.CfnExperimentTemplate.ExperimentTemplateTargetFilterProperty(
                        path="path",
                        values=["values"]
                    )],
                    resource_arns=["resourceArns"],
                    resource_tags={
                        "resource_tags_key": "resourceTags"
                    }
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "resource_type": resource_type,
                "selection_mode": selection_mode,
            }
            if filters is not None:
                self._values["filters"] = filters
            if resource_arns is not None:
                self._values["resource_arns"] = resource_arns
            if resource_tags is not None:
                self._values["resource_tags"] = resource_tags

        @builtins.property
        def resource_type(self) -> builtins.str:
            '''The resource type.

            The resource type must be supported for the specified action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplatetarget.html#cfn-fis-experimenttemplate-experimenttemplatetarget-resourcetype
            '''
            result = self._values.get("resource_type")
            assert result is not None, "Required property 'resource_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def selection_mode(self) -> builtins.str:
            '''Scopes the identified resources to a specific count of the resources at random, or a percentage of the resources.

            All identified resources are included in the target.

            - ALL - Run the action on all identified targets. This is the default.
            - COUNT(n) - Run the action on the specified number of targets, chosen from the identified targets at random. For example, COUNT(1) selects one of the targets.
            - PERCENT(n) - Run the action on the specified percentage of targets, chosen from the identified targets at random. For example, PERCENT(25) selects 25% of the targets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplatetarget.html#cfn-fis-experimenttemplate-experimenttemplatetarget-selectionmode
            '''
            result = self._values.get("selection_mode")
            assert result is not None, "Required property 'selection_mode' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def filters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnExperimentTemplate.ExperimentTemplateTargetFilterProperty", _IResolvable_da3f097b]]]]:
            '''The filters to apply to identify target resources using specific attributes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplatetarget.html#cfn-fis-experimenttemplate-experimenttemplatetarget-filters
            '''
            result = self._values.get("filters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnExperimentTemplate.ExperimentTemplateTargetFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def resource_arns(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The Amazon Resource Names (ARNs) of the resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplatetarget.html#cfn-fis-experimenttemplate-experimenttemplatetarget-resourcearns
            '''
            result = self._values.get("resource_arns")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def resource_tags(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''The tags for the target resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fis-experimenttemplate-experimenttemplatetarget.html#cfn-fis-experimenttemplate-experimenttemplatetarget-resourcetags
            '''
            result = self._values.get("resource_tags")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ExperimentTemplateTargetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_fis.CfnExperimentTemplateProps",
    jsii_struct_bases=[],
    name_mapping={
        "description": "description",
        "role_arn": "roleArn",
        "stop_conditions": "stopConditions",
        "tags": "tags",
        "targets": "targets",
        "actions": "actions",
    },
)
class CfnExperimentTemplateProps:
    def __init__(
        self,
        *,
        description: builtins.str,
        role_arn: builtins.str,
        stop_conditions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnExperimentTemplate.ExperimentTemplateStopConditionProperty, _IResolvable_da3f097b]]],
        tags: typing.Mapping[builtins.str, builtins.str],
        targets: typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnExperimentTemplate.ExperimentTemplateTargetProperty, _IResolvable_da3f097b]]],
        actions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnExperimentTemplate.ExperimentTemplateActionProperty, _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnExperimentTemplate``.

        :param description: A description for the experiment template.
        :param role_arn: The Amazon Resource Name (ARN) of an IAM role that grants the AWS FIS service permission to perform service actions on your behalf.
        :param stop_conditions: The stop conditions.
        :param tags: The tags to apply to the experiment template.
        :param targets: The targets for the experiment.
        :param actions: The actions for the experiment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fis-experimenttemplate.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_fis as fis
            
            cfn_experiment_template_props = fis.CfnExperimentTemplateProps(
                description="description",
                role_arn="roleArn",
                stop_conditions=[fis.CfnExperimentTemplate.ExperimentTemplateStopConditionProperty(
                    source="source",
            
                    # the properties below are optional
                    value="value"
                )],
                tags={
                    "tags_key": "tags"
                },
                targets={
                    "targets_key": fis.CfnExperimentTemplate.ExperimentTemplateTargetProperty(
                        resource_type="resourceType",
                        selection_mode="selectionMode",
            
                        # the properties below are optional
                        filters=[fis.CfnExperimentTemplate.ExperimentTemplateTargetFilterProperty(
                            path="path",
                            values=["values"]
                        )],
                        resource_arns=["resourceArns"],
                        resource_tags={
                            "resource_tags_key": "resourceTags"
                        }
                    )
                },
            
                # the properties below are optional
                actions={
                    "actions_key": fis.CfnExperimentTemplate.ExperimentTemplateActionProperty(
                        action_id="actionId",
            
                        # the properties below are optional
                        description="description",
                        parameters={
                            "parameters_key": "parameters"
                        },
                        start_after=["startAfter"],
                        targets={
                            "targets_key": "targets"
                        }
                    )
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "description": description,
            "role_arn": role_arn,
            "stop_conditions": stop_conditions,
            "tags": tags,
            "targets": targets,
        }
        if actions is not None:
            self._values["actions"] = actions

    @builtins.property
    def description(self) -> builtins.str:
        '''A description for the experiment template.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fis-experimenttemplate.html#cfn-fis-experimenttemplate-description
        '''
        result = self._values.get("description")
        assert result is not None, "Required property 'description' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def role_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of an IAM role that grants the AWS FIS service permission to perform service actions on your behalf.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fis-experimenttemplate.html#cfn-fis-experimenttemplate-rolearn
        '''
        result = self._values.get("role_arn")
        assert result is not None, "Required property 'role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def stop_conditions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnExperimentTemplate.ExperimentTemplateStopConditionProperty, _IResolvable_da3f097b]]]:
        '''The stop conditions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fis-experimenttemplate.html#cfn-fis-experimenttemplate-stopconditions
        '''
        result = self._values.get("stop_conditions")
        assert result is not None, "Required property 'stop_conditions' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnExperimentTemplate.ExperimentTemplateStopConditionProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def tags(self) -> typing.Mapping[builtins.str, builtins.str]:
        '''The tags to apply to the experiment template.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fis-experimenttemplate.html#cfn-fis-experimenttemplate-tags
        '''
        result = self._values.get("tags")
        assert result is not None, "Required property 'tags' is missing"
        return typing.cast(typing.Mapping[builtins.str, builtins.str], result)

    @builtins.property
    def targets(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnExperimentTemplate.ExperimentTemplateTargetProperty, _IResolvable_da3f097b]]]:
        '''The targets for the experiment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fis-experimenttemplate.html#cfn-fis-experimenttemplate-targets
        '''
        result = self._values.get("targets")
        assert result is not None, "Required property 'targets' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnExperimentTemplate.ExperimentTemplateTargetProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def actions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnExperimentTemplate.ExperimentTemplateActionProperty, _IResolvable_da3f097b]]]]:
        '''The actions for the experiment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fis-experimenttemplate.html#cfn-fis-experimenttemplate-actions
        '''
        result = self._values.get("actions")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnExperimentTemplate.ExperimentTemplateActionProperty, _IResolvable_da3f097b]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnExperimentTemplateProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnExperimentTemplate",
    "CfnExperimentTemplateProps",
]

publication.publish()
