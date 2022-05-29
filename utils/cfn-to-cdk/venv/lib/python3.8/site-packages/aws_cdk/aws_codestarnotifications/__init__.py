'''
# AWS CodeStarNotifications Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

## NotificationRule

The `NotificationRule` construct defines an AWS CodeStarNotifications rule.
The rule specifies the events you want notifications about and the targets
(such as Amazon SNS topics or AWS Chatbot clients configured for Slack)
where you want to receive them.
Notification targets are objects that implement the `INotificationRuleTarget`
interface and notification source is object that implement the `INotificationRuleSource` interface.

## Notification Targets

This module includes classes that implement the `INotificationRuleTarget` interface for SNS and slack in AWS Chatbot.

The following targets are supported:

* `SNS`: specify event and notify to SNS topic.
* `AWS Chatbot`: specify event and notify to slack channel and only support `SlackChannelConfiguration`.

## Examples

```python
import aws_cdk.aws_codestarnotifications as notifications
import aws_cdk.aws_codebuild as codebuild
import aws_cdk.aws_sns as sns
import aws_cdk.aws_chatbot as chatbot


project = codebuild.PipelineProject(self, "MyProject")

topic = sns.Topic(self, "MyTopic1")

slack = chatbot.SlackChannelConfiguration(self, "MySlackChannel",
    slack_channel_configuration_name="YOUR_CHANNEL_NAME",
    slack_workspace_id="YOUR_SLACK_WORKSPACE_ID",
    slack_channel_id="YOUR_SLACK_CHANNEL_ID"
)

rule = notifications.NotificationRule(self, "NotificationRule",
    source=project,
    events=["codebuild-project-build-state-succeeded", "codebuild-project-build-state-failed"
    ],
    targets=[topic]
)
rule.add_target(slack)
```

## Notification Source

This module includes classes that implement the `INotificationRuleSource` interface for AWS CodeBuild,
AWS CodePipeline and will support AWS CodeCommit, AWS CodeDeploy in future.

The following sources are supported:

* `AWS CodeBuild`: support codebuild project to trigger notification when event specified.
* `AWS CodePipeline`: support codepipeline to trigger notification when event specified.

## Events

For the complete list of supported event types for CodeBuild and CodePipeline, see:

* [Events for notification rules on build projects](https://docs.aws.amazon.com/dtconsole/latest/userguide/concepts.html#events-ref-buildproject).
* [Events for notification rules on pipelines](https://docs.aws.amazon.com/dtconsole/latest/userguide/concepts.html#events-ref-pipeline).
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
    IResource as _IResource_c80c4260,
    Resource as _Resource_45bc6135,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.implements(_IInspectable_c2943556)
class CfnNotificationRule(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_codestarnotifications.CfnNotificationRule",
):
    '''A CloudFormation ``AWS::CodeStarNotifications::NotificationRule``.

    Creates a notification rule for a resource. The rule specifies the events you want notifications about and the targets (such as AWS Chatbot topics or AWS Chatbot clients configured for Slack) where you want to receive them.

    :cloudformationResource: AWS::CodeStarNotifications::NotificationRule
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_codestarnotifications as codestarnotifications
        
        # tags: Any
        
        cfn_notification_rule = codestarnotifications.CfnNotificationRule(self, "MyCfnNotificationRule",
            detail_type="detailType",
            event_type_ids=["eventTypeIds"],
            name="name",
            resource="resource",
            targets=[codestarnotifications.CfnNotificationRule.TargetProperty(
                target_address="targetAddress",
                target_type="targetType"
            )],
        
            # the properties below are optional
            created_by="createdBy",
            event_type_id="eventTypeId",
            status="status",
            tags=tags,
            target_address="targetAddress"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        detail_type: builtins.str,
        event_type_ids: typing.Sequence[builtins.str],
        name: builtins.str,
        resource: builtins.str,
        targets: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnNotificationRule.TargetProperty", _IResolvable_da3f097b]]],
        created_by: typing.Optional[builtins.str] = None,
        event_type_id: typing.Optional[builtins.str] = None,
        status: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
        target_address: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::CodeStarNotifications::NotificationRule``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param detail_type: The level of detail to include in the notifications for this resource. ``BASIC`` will include only the contents of the event as it would appear in Amazon CloudWatch. ``FULL`` will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created.
        :param event_type_ids: A list of event types associated with this notification rule. For a complete list of event types and IDs, see `Notification concepts <https://docs.aws.amazon.com/codestar-notifications/latest/userguide/concepts.html#concepts-api>`_ in the *Developer Tools Console User Guide* .
        :param name: The name for the notification rule. Notification rule names must be unique in your AWS account .
        :param resource: The Amazon Resource Name (ARN) of the resource to associate with the notification rule. Supported resources include pipelines in AWS CodePipeline , repositories in AWS CodeCommit , and build projects in AWS CodeBuild .
        :param targets: A list of Amazon Resource Names (ARNs) of AWS Chatbot topics and AWS Chatbot clients to associate with the notification rule.
        :param created_by: ``AWS::CodeStarNotifications::NotificationRule.CreatedBy``.
        :param event_type_id: ``AWS::CodeStarNotifications::NotificationRule.EventTypeId``.
        :param status: The status of the notification rule. The default value is ``ENABLED`` . If the status is set to ``DISABLED`` , notifications aren't sent for the notification rule.
        :param tags: A list of tags to apply to this notification rule. Key names cannot start with " ``aws`` ".
        :param target_address: ``AWS::CodeStarNotifications::NotificationRule.TargetAddress``.
        '''
        props = CfnNotificationRuleProps(
            detail_type=detail_type,
            event_type_ids=event_type_ids,
            name=name,
            resource=resource,
            targets=targets,
            created_by=created_by,
            event_type_id=event_type_id,
            status=status,
            tags=tags,
            target_address=target_address,
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
        '''
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
        '''A list of tags to apply to this notification rule.

        Key names cannot start with " ``aws`` ".

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="detailType")
    def detail_type(self) -> builtins.str:
        '''The level of detail to include in the notifications for this resource.

        ``BASIC`` will include only the contents of the event as it would appear in Amazon CloudWatch. ``FULL`` will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-detailtype
        '''
        return typing.cast(builtins.str, jsii.get(self, "detailType"))

    @detail_type.setter
    def detail_type(self, value: builtins.str) -> None:
        jsii.set(self, "detailType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventTypeIds")
    def event_type_ids(self) -> typing.List[builtins.str]:
        '''A list of event types associated with this notification rule.

        For a complete list of event types and IDs, see `Notification concepts <https://docs.aws.amazon.com/codestar-notifications/latest/userguide/concepts.html#concepts-api>`_ in the *Developer Tools Console User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-eventtypeids
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "eventTypeIds"))

    @event_type_ids.setter
    def event_type_ids(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "eventTypeIds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name for the notification rule.

        Notification rule names must be unique in your AWS account .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resource")
    def resource(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the resource to associate with the notification rule.

        Supported resources include pipelines in AWS CodePipeline , repositories in AWS CodeCommit , and build projects in AWS CodeBuild .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-resource
        '''
        return typing.cast(builtins.str, jsii.get(self, "resource"))

    @resource.setter
    def resource(self, value: builtins.str) -> None:
        jsii.set(self, "resource", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targets")
    def targets(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnNotificationRule.TargetProperty", _IResolvable_da3f097b]]]:
        '''A list of Amazon Resource Names (ARNs) of AWS Chatbot topics and AWS Chatbot clients to associate with the notification rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-targets
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnNotificationRule.TargetProperty", _IResolvable_da3f097b]]], jsii.get(self, "targets"))

    @targets.setter
    def targets(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnNotificationRule.TargetProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "targets", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="createdBy")
    def created_by(self) -> typing.Optional[builtins.str]:
        '''``AWS::CodeStarNotifications::NotificationRule.CreatedBy``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-createdby
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "createdBy"))

    @created_by.setter
    def created_by(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "createdBy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventTypeId")
    def event_type_id(self) -> typing.Optional[builtins.str]:
        '''``AWS::CodeStarNotifications::NotificationRule.EventTypeId``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-eventtypeid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "eventTypeId"))

    @event_type_id.setter
    def event_type_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "eventTypeId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="status")
    def status(self) -> typing.Optional[builtins.str]:
        '''The status of the notification rule.

        The default value is ``ENABLED`` . If the status is set to ``DISABLED`` , notifications aren't sent for the notification rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-status
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "status"))

    @status.setter
    def status(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "status", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetAddress")
    def target_address(self) -> typing.Optional[builtins.str]:
        '''``AWS::CodeStarNotifications::NotificationRule.TargetAddress``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-targetaddress
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "targetAddress"))

    @target_address.setter
    def target_address(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "targetAddress", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_codestarnotifications.CfnNotificationRule.TargetProperty",
        jsii_struct_bases=[],
        name_mapping={"target_address": "targetAddress", "target_type": "targetType"},
    )
    class TargetProperty:
        def __init__(
            self,
            *,
            target_address: builtins.str,
            target_type: builtins.str,
        ) -> None:
            '''Information about the AWS Chatbot topics or AWS Chatbot clients associated with a notification rule.

            :param target_address: The Amazon Resource Name (ARN) of the AWS Chatbot topic or AWS Chatbot client.
            :param target_type: The target type. Can be an Amazon Simple Notification Service topic or AWS Chatbot client. - Amazon Simple Notification Service topics are specified as ``SNS`` . - AWS Chatbot clients are specified as ``AWSChatbotSlack`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codestarnotifications-notificationrule-target.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_codestarnotifications as codestarnotifications
                
                target_property = codestarnotifications.CfnNotificationRule.TargetProperty(
                    target_address="targetAddress",
                    target_type="targetType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "target_address": target_address,
                "target_type": target_type,
            }

        @builtins.property
        def target_address(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the AWS Chatbot topic or AWS Chatbot client.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codestarnotifications-notificationrule-target.html#cfn-codestarnotifications-notificationrule-target-targetaddress
            '''
            result = self._values.get("target_address")
            assert result is not None, "Required property 'target_address' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def target_type(self) -> builtins.str:
            '''The target type. Can be an Amazon Simple Notification Service topic or AWS Chatbot client.

            - Amazon Simple Notification Service topics are specified as ``SNS`` .
            - AWS Chatbot clients are specified as ``AWSChatbotSlack`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codestarnotifications-notificationrule-target.html#cfn-codestarnotifications-notificationrule-target-targettype
            '''
            result = self._values.get("target_type")
            assert result is not None, "Required property 'target_type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TargetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_codestarnotifications.CfnNotificationRuleProps",
    jsii_struct_bases=[],
    name_mapping={
        "detail_type": "detailType",
        "event_type_ids": "eventTypeIds",
        "name": "name",
        "resource": "resource",
        "targets": "targets",
        "created_by": "createdBy",
        "event_type_id": "eventTypeId",
        "status": "status",
        "tags": "tags",
        "target_address": "targetAddress",
    },
)
class CfnNotificationRuleProps:
    def __init__(
        self,
        *,
        detail_type: builtins.str,
        event_type_ids: typing.Sequence[builtins.str],
        name: builtins.str,
        resource: builtins.str,
        targets: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnNotificationRule.TargetProperty, _IResolvable_da3f097b]]],
        created_by: typing.Optional[builtins.str] = None,
        event_type_id: typing.Optional[builtins.str] = None,
        status: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
        target_address: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnNotificationRule``.

        :param detail_type: The level of detail to include in the notifications for this resource. ``BASIC`` will include only the contents of the event as it would appear in Amazon CloudWatch. ``FULL`` will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created.
        :param event_type_ids: A list of event types associated with this notification rule. For a complete list of event types and IDs, see `Notification concepts <https://docs.aws.amazon.com/codestar-notifications/latest/userguide/concepts.html#concepts-api>`_ in the *Developer Tools Console User Guide* .
        :param name: The name for the notification rule. Notification rule names must be unique in your AWS account .
        :param resource: The Amazon Resource Name (ARN) of the resource to associate with the notification rule. Supported resources include pipelines in AWS CodePipeline , repositories in AWS CodeCommit , and build projects in AWS CodeBuild .
        :param targets: A list of Amazon Resource Names (ARNs) of AWS Chatbot topics and AWS Chatbot clients to associate with the notification rule.
        :param created_by: ``AWS::CodeStarNotifications::NotificationRule.CreatedBy``.
        :param event_type_id: ``AWS::CodeStarNotifications::NotificationRule.EventTypeId``.
        :param status: The status of the notification rule. The default value is ``ENABLED`` . If the status is set to ``DISABLED`` , notifications aren't sent for the notification rule.
        :param tags: A list of tags to apply to this notification rule. Key names cannot start with " ``aws`` ".
        :param target_address: ``AWS::CodeStarNotifications::NotificationRule.TargetAddress``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_codestarnotifications as codestarnotifications
            
            # tags: Any
            
            cfn_notification_rule_props = codestarnotifications.CfnNotificationRuleProps(
                detail_type="detailType",
                event_type_ids=["eventTypeIds"],
                name="name",
                resource="resource",
                targets=[codestarnotifications.CfnNotificationRule.TargetProperty(
                    target_address="targetAddress",
                    target_type="targetType"
                )],
            
                # the properties below are optional
                created_by="createdBy",
                event_type_id="eventTypeId",
                status="status",
                tags=tags,
                target_address="targetAddress"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "detail_type": detail_type,
            "event_type_ids": event_type_ids,
            "name": name,
            "resource": resource,
            "targets": targets,
        }
        if created_by is not None:
            self._values["created_by"] = created_by
        if event_type_id is not None:
            self._values["event_type_id"] = event_type_id
        if status is not None:
            self._values["status"] = status
        if tags is not None:
            self._values["tags"] = tags
        if target_address is not None:
            self._values["target_address"] = target_address

    @builtins.property
    def detail_type(self) -> builtins.str:
        '''The level of detail to include in the notifications for this resource.

        ``BASIC`` will include only the contents of the event as it would appear in Amazon CloudWatch. ``FULL`` will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-detailtype
        '''
        result = self._values.get("detail_type")
        assert result is not None, "Required property 'detail_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def event_type_ids(self) -> typing.List[builtins.str]:
        '''A list of event types associated with this notification rule.

        For a complete list of event types and IDs, see `Notification concepts <https://docs.aws.amazon.com/codestar-notifications/latest/userguide/concepts.html#concepts-api>`_ in the *Developer Tools Console User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-eventtypeids
        '''
        result = self._values.get("event_type_ids")
        assert result is not None, "Required property 'event_type_ids' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name for the notification rule.

        Notification rule names must be unique in your AWS account .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def resource(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the resource to associate with the notification rule.

        Supported resources include pipelines in AWS CodePipeline , repositories in AWS CodeCommit , and build projects in AWS CodeBuild .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-resource
        '''
        result = self._values.get("resource")
        assert result is not None, "Required property 'resource' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def targets(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnNotificationRule.TargetProperty, _IResolvable_da3f097b]]]:
        '''A list of Amazon Resource Names (ARNs) of AWS Chatbot topics and AWS Chatbot clients to associate with the notification rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-targets
        '''
        result = self._values.get("targets")
        assert result is not None, "Required property 'targets' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnNotificationRule.TargetProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def created_by(self) -> typing.Optional[builtins.str]:
        '''``AWS::CodeStarNotifications::NotificationRule.CreatedBy``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-createdby
        '''
        result = self._values.get("created_by")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def event_type_id(self) -> typing.Optional[builtins.str]:
        '''``AWS::CodeStarNotifications::NotificationRule.EventTypeId``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-eventtypeid
        '''
        result = self._values.get("event_type_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def status(self) -> typing.Optional[builtins.str]:
        '''The status of the notification rule.

        The default value is ``ENABLED`` . If the status is set to ``DISABLED`` , notifications aren't sent for the notification rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-status
        '''
        result = self._values.get("status")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''A list of tags to apply to this notification rule.

        Key names cannot start with " ``aws`` ".

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    @builtins.property
    def target_address(self) -> typing.Optional[builtins.str]:
        '''``AWS::CodeStarNotifications::NotificationRule.TargetAddress``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-targetaddress
        '''
        result = self._values.get("target_address")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnNotificationRuleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_codestarnotifications.DetailType")
class DetailType(enum.Enum):
    '''The level of detail to include in the notifications for this resource.'''

    BASIC = "BASIC"
    '''BASIC will include only the contents of the event as it would appear in AWS CloudWatch.'''
    FULL = "FULL"
    '''FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created.'''


@jsii.interface(jsii_type="aws-cdk-lib.aws_codestarnotifications.INotificationRule")
class INotificationRule(_IResource_c80c4260, typing_extensions.Protocol):
    '''Represents a notification rule.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="notificationRuleArn")
    def notification_rule_arn(self) -> builtins.str:
        '''The ARN of the notification rule (i.e. arn:aws:codestar-notifications:::notificationrule/01234abcde).

        :attribute: true
        '''
        ...

    @jsii.member(jsii_name="addTarget")
    def add_target(self, target: "INotificationRuleTarget") -> builtins.bool:
        '''Adds target to notification rule.

        :param target: The SNS topic or AWS Chatbot Slack target.

        :return: boolean - return true if it had any effect
        '''
        ...


class _INotificationRuleProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Represents a notification rule.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_codestarnotifications.INotificationRule"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="notificationRuleArn")
    def notification_rule_arn(self) -> builtins.str:
        '''The ARN of the notification rule (i.e. arn:aws:codestar-notifications:::notificationrule/01234abcde).

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "notificationRuleArn"))

    @jsii.member(jsii_name="addTarget")
    def add_target(self, target: "INotificationRuleTarget") -> builtins.bool:
        '''Adds target to notification rule.

        :param target: The SNS topic or AWS Chatbot Slack target.

        :return: boolean - return true if it had any effect
        '''
        return typing.cast(builtins.bool, jsii.invoke(self, "addTarget", [target]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, INotificationRule).__jsii_proxy_class__ = lambda : _INotificationRuleProxy


@jsii.interface(
    jsii_type="aws-cdk-lib.aws_codestarnotifications.INotificationRuleSource"
)
class INotificationRuleSource(typing_extensions.Protocol):
    '''Represents a notification source The source that allows CodeBuild and CodePipeline to associate with this rule.'''

    @jsii.member(jsii_name="bindAsNotificationRuleSource")
    def bind_as_notification_rule_source(
        self,
        scope: constructs.Construct,
    ) -> "NotificationRuleSourceConfig":
        '''Returns a source configuration for notification rule.

        :param scope: -
        '''
        ...


class _INotificationRuleSourceProxy:
    '''Represents a notification source The source that allows CodeBuild and CodePipeline to associate with this rule.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_codestarnotifications.INotificationRuleSource"

    @jsii.member(jsii_name="bindAsNotificationRuleSource")
    def bind_as_notification_rule_source(
        self,
        scope: constructs.Construct,
    ) -> "NotificationRuleSourceConfig":
        '''Returns a source configuration for notification rule.

        :param scope: -
        '''
        return typing.cast("NotificationRuleSourceConfig", jsii.invoke(self, "bindAsNotificationRuleSource", [scope]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, INotificationRuleSource).__jsii_proxy_class__ = lambda : _INotificationRuleSourceProxy


@jsii.interface(
    jsii_type="aws-cdk-lib.aws_codestarnotifications.INotificationRuleTarget"
)
class INotificationRuleTarget(typing_extensions.Protocol):
    '''Represents a notification target That allows AWS Chatbot and SNS topic to associate with this rule target.'''

    @jsii.member(jsii_name="bindAsNotificationRuleTarget")
    def bind_as_notification_rule_target(
        self,
        scope: constructs.Construct,
    ) -> "NotificationRuleTargetConfig":
        '''Returns a target configuration for notification rule.

        :param scope: -
        '''
        ...


class _INotificationRuleTargetProxy:
    '''Represents a notification target That allows AWS Chatbot and SNS topic to associate with this rule target.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_codestarnotifications.INotificationRuleTarget"

    @jsii.member(jsii_name="bindAsNotificationRuleTarget")
    def bind_as_notification_rule_target(
        self,
        scope: constructs.Construct,
    ) -> "NotificationRuleTargetConfig":
        '''Returns a target configuration for notification rule.

        :param scope: -
        '''
        return typing.cast("NotificationRuleTargetConfig", jsii.invoke(self, "bindAsNotificationRuleTarget", [scope]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, INotificationRuleTarget).__jsii_proxy_class__ = lambda : _INotificationRuleTargetProxy


@jsii.implements(INotificationRule)
class NotificationRule(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_codestarnotifications.NotificationRule",
):
    '''A new notification rule.

    :exampleMetadata: infused
    :resource: AWS::CodeStarNotifications::NotificationRule

    Example::

        import aws_cdk.aws_codestarnotifications as notifications
        import aws_cdk.aws_codebuild as codebuild
        import aws_cdk.aws_sns as sns
        import aws_cdk.aws_chatbot as chatbot
        
        
        project = codebuild.PipelineProject(self, "MyProject")
        
        topic = sns.Topic(self, "MyTopic1")
        
        slack = chatbot.SlackChannelConfiguration(self, "MySlackChannel",
            slack_channel_configuration_name="YOUR_CHANNEL_NAME",
            slack_workspace_id="YOUR_SLACK_WORKSPACE_ID",
            slack_channel_id="YOUR_SLACK_CHANNEL_ID"
        )
        
        rule = notifications.NotificationRule(self, "NotificationRule",
            source=project,
            events=["codebuild-project-build-state-succeeded", "codebuild-project-build-state-failed"
            ],
            targets=[topic]
        )
        rule.add_target(slack)
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        events: typing.Sequence[builtins.str],
        source: INotificationRuleSource,
        targets: typing.Optional[typing.Sequence[INotificationRuleTarget]] = None,
        detail_type: typing.Optional[DetailType] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param events: A list of event types associated with this notification rule. For a complete list of event types and IDs, see Notification concepts in the Developer Tools Console User Guide.
        :param source: The Amazon Resource Name (ARN) of the resource to associate with the notification rule. Currently, Supported sources include pipelines in AWS CodePipeline, build projects in AWS CodeBuild, and repositories in AWS CodeCommit in this L2 constructor.
        :param targets: The targets to register for the notification destination. Default: - No targets are added to the rule. Use ``addTarget()`` to add a target.
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        props = NotificationRuleProps(
            events=events,
            source=source,
            targets=targets,
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromNotificationRuleArn") # type: ignore[misc]
    @builtins.classmethod
    def from_notification_rule_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        notification_rule_arn: builtins.str,
    ) -> INotificationRule:
        '''Import an existing notification rule provided an ARN.

        :param scope: The parent creating construct.
        :param id: The construct's name.
        :param notification_rule_arn: Notification rule ARN (i.e. arn:aws:codestar-notifications:::notificationrule/01234abcde).
        '''
        return typing.cast(INotificationRule, jsii.sinvoke(cls, "fromNotificationRuleArn", [scope, id, notification_rule_arn]))

    @jsii.member(jsii_name="addTarget")
    def add_target(self, target: INotificationRuleTarget) -> builtins.bool:
        '''Adds target to notification rule.

        :param target: The SNS topic or AWS Chatbot Slack target.
        '''
        return typing.cast(builtins.bool, jsii.invoke(self, "addTarget", [target]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="notificationRuleArn")
    def notification_rule_arn(self) -> builtins.str:
        '''The ARN of the notification rule (i.e. arn:aws:codestar-notifications:::notificationrule/01234abcde).

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "notificationRuleArn"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_codestarnotifications.NotificationRuleOptions",
    jsii_struct_bases=[],
    name_mapping={
        "detail_type": "detailType",
        "enabled": "enabled",
        "notification_rule_name": "notificationRuleName",
    },
)
class NotificationRuleOptions:
    def __init__(
        self,
        *,
        detail_type: typing.Optional[DetailType] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Standard set of options for ``notifyOnXxx`` codestar notification handler on construct.

        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_codestarnotifications as codestarnotifications
            
            notification_rule_options = codestarnotifications.NotificationRuleOptions(
                detail_type=codestarnotifications.DetailType.BASIC,
                enabled=False,
                notification_rule_name="notificationRuleName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if detail_type is not None:
            self._values["detail_type"] = detail_type
        if enabled is not None:
            self._values["enabled"] = enabled
        if notification_rule_name is not None:
            self._values["notification_rule_name"] = notification_rule_name

    @builtins.property
    def detail_type(self) -> typing.Optional[DetailType]:
        '''The level of detail to include in the notifications for this resource.

        BASIC will include only the contents of the event as it would appear in AWS CloudWatch.
        FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created.

        :default: DetailType.FULL
        '''
        result = self._values.get("detail_type")
        return typing.cast(typing.Optional[DetailType], result)

    @builtins.property
    def enabled(self) -> typing.Optional[builtins.bool]:
        '''The status of the notification rule.

        If the enabled is set to DISABLED, notifications aren't sent for the notification rule.

        :default: true
        '''
        result = self._values.get("enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def notification_rule_name(self) -> typing.Optional[builtins.str]:
        '''The name for the notification rule.

        Notification rule names must be unique in your AWS account.

        :default: - generated from the ``id``
        '''
        result = self._values.get("notification_rule_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NotificationRuleOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_codestarnotifications.NotificationRuleProps",
    jsii_struct_bases=[NotificationRuleOptions],
    name_mapping={
        "detail_type": "detailType",
        "enabled": "enabled",
        "notification_rule_name": "notificationRuleName",
        "events": "events",
        "source": "source",
        "targets": "targets",
    },
)
class NotificationRuleProps(NotificationRuleOptions):
    def __init__(
        self,
        *,
        detail_type: typing.Optional[DetailType] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
        events: typing.Sequence[builtins.str],
        source: INotificationRuleSource,
        targets: typing.Optional[typing.Sequence[INotificationRuleTarget]] = None,
    ) -> None:
        '''Properties for a new notification rule.

        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        :param events: A list of event types associated with this notification rule. For a complete list of event types and IDs, see Notification concepts in the Developer Tools Console User Guide.
        :param source: The Amazon Resource Name (ARN) of the resource to associate with the notification rule. Currently, Supported sources include pipelines in AWS CodePipeline, build projects in AWS CodeBuild, and repositories in AWS CodeCommit in this L2 constructor.
        :param targets: The targets to register for the notification destination. Default: - No targets are added to the rule. Use ``addTarget()`` to add a target.

        :exampleMetadata: infused

        Example::

            import aws_cdk.aws_codestarnotifications as notifications
            import aws_cdk.aws_codebuild as codebuild
            import aws_cdk.aws_sns as sns
            import aws_cdk.aws_chatbot as chatbot
            
            
            project = codebuild.PipelineProject(self, "MyProject")
            
            topic = sns.Topic(self, "MyTopic1")
            
            slack = chatbot.SlackChannelConfiguration(self, "MySlackChannel",
                slack_channel_configuration_name="YOUR_CHANNEL_NAME",
                slack_workspace_id="YOUR_SLACK_WORKSPACE_ID",
                slack_channel_id="YOUR_SLACK_CHANNEL_ID"
            )
            
            rule = notifications.NotificationRule(self, "NotificationRule",
                source=project,
                events=["codebuild-project-build-state-succeeded", "codebuild-project-build-state-failed"
                ],
                targets=[topic]
            )
            rule.add_target(slack)
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "events": events,
            "source": source,
        }
        if detail_type is not None:
            self._values["detail_type"] = detail_type
        if enabled is not None:
            self._values["enabled"] = enabled
        if notification_rule_name is not None:
            self._values["notification_rule_name"] = notification_rule_name
        if targets is not None:
            self._values["targets"] = targets

    @builtins.property
    def detail_type(self) -> typing.Optional[DetailType]:
        '''The level of detail to include in the notifications for this resource.

        BASIC will include only the contents of the event as it would appear in AWS CloudWatch.
        FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created.

        :default: DetailType.FULL
        '''
        result = self._values.get("detail_type")
        return typing.cast(typing.Optional[DetailType], result)

    @builtins.property
    def enabled(self) -> typing.Optional[builtins.bool]:
        '''The status of the notification rule.

        If the enabled is set to DISABLED, notifications aren't sent for the notification rule.

        :default: true
        '''
        result = self._values.get("enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def notification_rule_name(self) -> typing.Optional[builtins.str]:
        '''The name for the notification rule.

        Notification rule names must be unique in your AWS account.

        :default: - generated from the ``id``
        '''
        result = self._values.get("notification_rule_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def events(self) -> typing.List[builtins.str]:
        '''A list of event types associated with this notification rule.

        For a complete list of event types and IDs, see Notification concepts in the Developer Tools Console User Guide.

        :see: https://docs.aws.amazon.com/dtconsole/latest/userguide/concepts.html#concepts-api
        '''
        result = self._values.get("events")
        assert result is not None, "Required property 'events' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def source(self) -> INotificationRuleSource:
        '''The Amazon Resource Name (ARN) of the resource to associate with the notification rule.

        Currently, Supported sources include pipelines in AWS CodePipeline, build projects in AWS CodeBuild, and repositories in AWS CodeCommit in this L2 constructor.

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestarnotifications-notificationrule.html#cfn-codestarnotifications-notificationrule-resource
        '''
        result = self._values.get("source")
        assert result is not None, "Required property 'source' is missing"
        return typing.cast(INotificationRuleSource, result)

    @builtins.property
    def targets(self) -> typing.Optional[typing.List[INotificationRuleTarget]]:
        '''The targets to register for the notification destination.

        :default: - No targets are added to the rule. Use ``addTarget()`` to add a target.
        '''
        result = self._values.get("targets")
        return typing.cast(typing.Optional[typing.List[INotificationRuleTarget]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NotificationRuleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_codestarnotifications.NotificationRuleSourceConfig",
    jsii_struct_bases=[],
    name_mapping={"source_arn": "sourceArn"},
)
class NotificationRuleSourceConfig:
    def __init__(self, *, source_arn: builtins.str) -> None:
        '''Information about the Codebuild or CodePipeline associated with a notification source.

        :param source_arn: The Amazon Resource Name (ARN) of the notification source.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_codestarnotifications as codestarnotifications
            
            notification_rule_source_config = codestarnotifications.NotificationRuleSourceConfig(
                source_arn="sourceArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "source_arn": source_arn,
        }

    @builtins.property
    def source_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the notification source.'''
        result = self._values.get("source_arn")
        assert result is not None, "Required property 'source_arn' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NotificationRuleSourceConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_codestarnotifications.NotificationRuleTargetConfig",
    jsii_struct_bases=[],
    name_mapping={"target_address": "targetAddress", "target_type": "targetType"},
)
class NotificationRuleTargetConfig:
    def __init__(
        self,
        *,
        target_address: builtins.str,
        target_type: builtins.str,
    ) -> None:
        '''Information about the SNS topic or AWS Chatbot client associated with a notification target.

        :param target_address: The Amazon Resource Name (ARN) of the Amazon SNS topic or AWS Chatbot client.
        :param target_type: The target type. Can be an Amazon SNS topic or AWS Chatbot client.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_codestarnotifications as codestarnotifications
            
            notification_rule_target_config = codestarnotifications.NotificationRuleTargetConfig(
                target_address="targetAddress",
                target_type="targetType"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "target_address": target_address,
            "target_type": target_type,
        }

    @builtins.property
    def target_address(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the Amazon SNS topic or AWS Chatbot client.'''
        result = self._values.get("target_address")
        assert result is not None, "Required property 'target_address' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def target_type(self) -> builtins.str:
        '''The target type.

        Can be an Amazon SNS topic or AWS Chatbot client.
        '''
        result = self._values.get("target_type")
        assert result is not None, "Required property 'target_type' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NotificationRuleTargetConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnNotificationRule",
    "CfnNotificationRuleProps",
    "DetailType",
    "INotificationRule",
    "INotificationRuleSource",
    "INotificationRuleTarget",
    "NotificationRule",
    "NotificationRuleOptions",
    "NotificationRuleProps",
    "NotificationRuleSourceConfig",
    "NotificationRuleTargetConfig",
]

publication.publish()
