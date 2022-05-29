'''
# AWS::Chatbot Construct Library

AWS Chatbot is an AWS service that enables DevOps and software development teams to use Slack chat rooms to monitor and respond to operational events in their AWS Cloud. AWS Chatbot processes AWS service notifications from Amazon Simple Notification Service (Amazon SNS), and forwards them to Slack chat rooms so teams can analyze and act on them immediately, regardless of location.

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_chatbot as chatbot
import aws_cdk.aws_sns as sns
import aws_cdk.aws_iam as iam


slack_channel = chatbot.SlackChannelConfiguration(self, "MySlackChannel",
    slack_channel_configuration_name="YOUR_CHANNEL_NAME",
    slack_workspace_id="YOUR_SLACK_WORKSPACE_ID",
    slack_channel_id="YOUR_SLACK_CHANNEL_ID"
)

slack_channel.add_to_role_policy(iam.PolicyStatement(
    effect=iam.Effect.ALLOW,
    actions=["s3:GetObject"
    ],
    resources=["arn:aws:s3:::abc/xyz/123.txt"]
))

slack_channel.add_notification_topic(sns.Topic(self, "MyTopic"))
```

## Log Group

Slack channel configuration automatically create a log group with the name `/aws/chatbot/<configuration-name>` in `us-east-1` upon first execution with
log data set to never expire.

The `logRetention` property can be used to set a different expiration period. A log group will be created if not already exists.
If the log group already exists, it's expiration will be configured to the value specified in this construct (never expire, by default).

By default, CDK uses the AWS SDK retry options when interacting with the log group. The `logRetentionRetryOptions` property
allows you to customize the maximum number of retries and base backoff duration.

*Note* that, if `logRetention` is set, a [CloudFormation custom
resource](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cfn-customresource.html) is added
to the stack that pre-creates the log group as part of the stack deployment, if it already doesn't exist, and sets the
correct log retention period (never expire, by default).
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
    Duration as _Duration_4839e8c3,
    IInspectable as _IInspectable_c2943556,
    IResolvable as _IResolvable_da3f097b,
    IResource as _IResource_c80c4260,
    Resource as _Resource_45bc6135,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_cloudwatch import (
    Metric as _Metric_e396a4dc,
    MetricOptions as _MetricOptions_1788b62f,
    Unit as _Unit_61bc6f70,
)
from ..aws_codestarnotifications import (
    INotificationRuleTarget as _INotificationRuleTarget_faa3b79b,
    NotificationRuleTargetConfig as _NotificationRuleTargetConfig_ea27e095,
)
from ..aws_iam import (
    IGrantable as _IGrantable_71c4f5de,
    IPrincipal as _IPrincipal_539bb2fd,
    IRole as _IRole_235f5d8e,
    PolicyStatement as _PolicyStatement_0fe33853,
)
from ..aws_logs import (
    LogRetentionRetryOptions as _LogRetentionRetryOptions_62d80a14,
    RetentionDays as _RetentionDays_070f99f0,
)
from ..aws_sns import ITopic as _ITopic_9eca4852


@jsii.implements(_IInspectable_c2943556)
class CfnSlackChannelConfiguration(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_chatbot.CfnSlackChannelConfiguration",
):
    '''A CloudFormation ``AWS::Chatbot::SlackChannelConfiguration``.

    The ``AWS::Chatbot::SlackChannelConfiguration`` resource configures a Slack channel to allow users to use AWS Chatbot with AWS CloudFormation templates.

    This resource requires some setup to be done in the AWS Chatbot console. To provide the required Slack workspace ID, you must perform the initial authorization flow with Slack in the AWS Chatbot console, then copy and paste the workspace ID from the console. For more details, see steps 1-4 in `Setting Up AWS Chatbot with Slack <https://docs.aws.amazon.com/chatbot/latest/adminguide/setting-up.html#Setup_intro>`_ in the *AWS Chatbot User Guide* .

    :cloudformationResource: AWS::Chatbot::SlackChannelConfiguration
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_chatbot as chatbot
        
        cfn_slack_channel_configuration = chatbot.CfnSlackChannelConfiguration(self, "MyCfnSlackChannelConfiguration",
            configuration_name="configurationName",
            iam_role_arn="iamRoleArn",
            slack_channel_id="slackChannelId",
            slack_workspace_id="slackWorkspaceId",
        
            # the properties below are optional
            guardrail_policies=["guardrailPolicies"],
            logging_level="loggingLevel",
            sns_topic_arns=["snsTopicArns"],
            user_role_required=False
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        configuration_name: builtins.str,
        iam_role_arn: builtins.str,
        slack_channel_id: builtins.str,
        slack_workspace_id: builtins.str,
        guardrail_policies: typing.Optional[typing.Sequence[builtins.str]] = None,
        logging_level: typing.Optional[builtins.str] = None,
        sns_topic_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        user_role_required: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::Chatbot::SlackChannelConfiguration``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param configuration_name: The name of the configuration.
        :param iam_role_arn: The ARN of the IAM role that defines the permissions for AWS Chatbot . This is a user-definworked role that AWS Chatbot will assume. This is not the service-linked role. For more information, see `IAM Policies for AWS Chatbot <https://docs.aws.amazon.com/chatbot/latest/adminguide/chatbot-iam-policies.html>`_ .
        :param slack_channel_id: The ID of the Slack channel. To get the ID, open Slack, right click on the channel name in the left pane, then choose Copy Link. The channel ID is the 9-character string at the end of the URL. For example, ``ABCBBLZZZ`` .
        :param slack_workspace_id: The ID of the Slack workspace authorized with AWS Chatbot . To get the workspace ID, you must perform the initial authorization flow with Slack in the AWS Chatbot console. Then you can copy and paste the workspace ID from the console. For more details, see steps 1-4 in `Setting Up AWS Chatbot with Slack <https://docs.aws.amazon.com/chatbot/latest/adminguide/setting-up.html#Setup_intro>`_ in the *AWS Chatbot User Guide* .
        :param guardrail_policies: The list of IAM policy ARNs that are applied as channel guardrails. The AWS managed 'AdministratorAccess' policy is applied as a default if this is not set. Currently, only 1 IAM policy is supported.
        :param logging_level: Specifies the logging level for this configuration. This property affects the log entries pushed to Amazon CloudWatch Logs. Logging levels include ``ERROR`` , ``INFO`` , or ``NONE`` .
        :param sns_topic_arns: The ARNs of the SNS topics that deliver notifications to AWS Chatbot .
        :param user_role_required: Enables use of a user role requirement in your chat configuration.
        '''
        props = CfnSlackChannelConfigurationProps(
            configuration_name=configuration_name,
            iam_role_arn=iam_role_arn,
            slack_channel_id=slack_channel_id,
            slack_workspace_id=slack_workspace_id,
            guardrail_policies=guardrail_policies,
            logging_level=logging_level,
            sns_topic_arns=sns_topic_arns,
            user_role_required=user_role_required,
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
    @jsii.member(jsii_name="configurationName")
    def configuration_name(self) -> builtins.str:
        '''The name of the configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-configurationname
        '''
        return typing.cast(builtins.str, jsii.get(self, "configurationName"))

    @configuration_name.setter
    def configuration_name(self, value: builtins.str) -> None:
        jsii.set(self, "configurationName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="iamRoleArn")
    def iam_role_arn(self) -> builtins.str:
        '''The ARN of the IAM role that defines the permissions for AWS Chatbot .

        This is a user-definworked role that AWS Chatbot will assume. This is not the service-linked role. For more information, see `IAM Policies for AWS Chatbot <https://docs.aws.amazon.com/chatbot/latest/adminguide/chatbot-iam-policies.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-iamrolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "iamRoleArn"))

    @iam_role_arn.setter
    def iam_role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "iamRoleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="slackChannelId")
    def slack_channel_id(self) -> builtins.str:
        '''The ID of the Slack channel.

        To get the ID, open Slack, right click on the channel name in the left pane, then choose Copy Link. The channel ID is the 9-character string at the end of the URL. For example, ``ABCBBLZZZ`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-slackchannelid
        '''
        return typing.cast(builtins.str, jsii.get(self, "slackChannelId"))

    @slack_channel_id.setter
    def slack_channel_id(self, value: builtins.str) -> None:
        jsii.set(self, "slackChannelId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="slackWorkspaceId")
    def slack_workspace_id(self) -> builtins.str:
        '''The ID of the Slack workspace authorized with AWS Chatbot .

        To get the workspace ID, you must perform the initial authorization flow with Slack in the AWS Chatbot console. Then you can copy and paste the workspace ID from the console. For more details, see steps 1-4 in `Setting Up AWS Chatbot with Slack <https://docs.aws.amazon.com/chatbot/latest/adminguide/setting-up.html#Setup_intro>`_ in the *AWS Chatbot User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-slackworkspaceid
        '''
        return typing.cast(builtins.str, jsii.get(self, "slackWorkspaceId"))

    @slack_workspace_id.setter
    def slack_workspace_id(self, value: builtins.str) -> None:
        jsii.set(self, "slackWorkspaceId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="guardrailPolicies")
    def guardrail_policies(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of IAM policy ARNs that are applied as channel guardrails.

        The AWS managed 'AdministratorAccess' policy is applied as a default if this is not set. Currently, only 1 IAM policy is supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-guardrailpolicies
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "guardrailPolicies"))

    @guardrail_policies.setter
    def guardrail_policies(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "guardrailPolicies", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loggingLevel")
    def logging_level(self) -> typing.Optional[builtins.str]:
        '''Specifies the logging level for this configuration. This property affects the log entries pushed to Amazon CloudWatch Logs.

        Logging levels include ``ERROR`` , ``INFO`` , or ``NONE`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-logginglevel
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "loggingLevel"))

    @logging_level.setter
    def logging_level(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "loggingLevel", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snsTopicArns")
    def sns_topic_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The ARNs of the SNS topics that deliver notifications to AWS Chatbot .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-snstopicarns
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "snsTopicArns"))

    @sns_topic_arns.setter
    def sns_topic_arns(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "snsTopicArns", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userRoleRequired")
    def user_role_required(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables use of a user role requirement in your chat configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-userrolerequired
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "userRoleRequired"))

    @user_role_required.setter
    def user_role_required(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "userRoleRequired", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_chatbot.CfnSlackChannelConfigurationProps",
    jsii_struct_bases=[],
    name_mapping={
        "configuration_name": "configurationName",
        "iam_role_arn": "iamRoleArn",
        "slack_channel_id": "slackChannelId",
        "slack_workspace_id": "slackWorkspaceId",
        "guardrail_policies": "guardrailPolicies",
        "logging_level": "loggingLevel",
        "sns_topic_arns": "snsTopicArns",
        "user_role_required": "userRoleRequired",
    },
)
class CfnSlackChannelConfigurationProps:
    def __init__(
        self,
        *,
        configuration_name: builtins.str,
        iam_role_arn: builtins.str,
        slack_channel_id: builtins.str,
        slack_workspace_id: builtins.str,
        guardrail_policies: typing.Optional[typing.Sequence[builtins.str]] = None,
        logging_level: typing.Optional[builtins.str] = None,
        sns_topic_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        user_role_required: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnSlackChannelConfiguration``.

        :param configuration_name: The name of the configuration.
        :param iam_role_arn: The ARN of the IAM role that defines the permissions for AWS Chatbot . This is a user-definworked role that AWS Chatbot will assume. This is not the service-linked role. For more information, see `IAM Policies for AWS Chatbot <https://docs.aws.amazon.com/chatbot/latest/adminguide/chatbot-iam-policies.html>`_ .
        :param slack_channel_id: The ID of the Slack channel. To get the ID, open Slack, right click on the channel name in the left pane, then choose Copy Link. The channel ID is the 9-character string at the end of the URL. For example, ``ABCBBLZZZ`` .
        :param slack_workspace_id: The ID of the Slack workspace authorized with AWS Chatbot . To get the workspace ID, you must perform the initial authorization flow with Slack in the AWS Chatbot console. Then you can copy and paste the workspace ID from the console. For more details, see steps 1-4 in `Setting Up AWS Chatbot with Slack <https://docs.aws.amazon.com/chatbot/latest/adminguide/setting-up.html#Setup_intro>`_ in the *AWS Chatbot User Guide* .
        :param guardrail_policies: The list of IAM policy ARNs that are applied as channel guardrails. The AWS managed 'AdministratorAccess' policy is applied as a default if this is not set. Currently, only 1 IAM policy is supported.
        :param logging_level: Specifies the logging level for this configuration. This property affects the log entries pushed to Amazon CloudWatch Logs. Logging levels include ``ERROR`` , ``INFO`` , or ``NONE`` .
        :param sns_topic_arns: The ARNs of the SNS topics that deliver notifications to AWS Chatbot .
        :param user_role_required: Enables use of a user role requirement in your chat configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_chatbot as chatbot
            
            cfn_slack_channel_configuration_props = chatbot.CfnSlackChannelConfigurationProps(
                configuration_name="configurationName",
                iam_role_arn="iamRoleArn",
                slack_channel_id="slackChannelId",
                slack_workspace_id="slackWorkspaceId",
            
                # the properties below are optional
                guardrail_policies=["guardrailPolicies"],
                logging_level="loggingLevel",
                sns_topic_arns=["snsTopicArns"],
                user_role_required=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "configuration_name": configuration_name,
            "iam_role_arn": iam_role_arn,
            "slack_channel_id": slack_channel_id,
            "slack_workspace_id": slack_workspace_id,
        }
        if guardrail_policies is not None:
            self._values["guardrail_policies"] = guardrail_policies
        if logging_level is not None:
            self._values["logging_level"] = logging_level
        if sns_topic_arns is not None:
            self._values["sns_topic_arns"] = sns_topic_arns
        if user_role_required is not None:
            self._values["user_role_required"] = user_role_required

    @builtins.property
    def configuration_name(self) -> builtins.str:
        '''The name of the configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-configurationname
        '''
        result = self._values.get("configuration_name")
        assert result is not None, "Required property 'configuration_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def iam_role_arn(self) -> builtins.str:
        '''The ARN of the IAM role that defines the permissions for AWS Chatbot .

        This is a user-definworked role that AWS Chatbot will assume. This is not the service-linked role. For more information, see `IAM Policies for AWS Chatbot <https://docs.aws.amazon.com/chatbot/latest/adminguide/chatbot-iam-policies.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-iamrolearn
        '''
        result = self._values.get("iam_role_arn")
        assert result is not None, "Required property 'iam_role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def slack_channel_id(self) -> builtins.str:
        '''The ID of the Slack channel.

        To get the ID, open Slack, right click on the channel name in the left pane, then choose Copy Link. The channel ID is the 9-character string at the end of the URL. For example, ``ABCBBLZZZ`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-slackchannelid
        '''
        result = self._values.get("slack_channel_id")
        assert result is not None, "Required property 'slack_channel_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def slack_workspace_id(self) -> builtins.str:
        '''The ID of the Slack workspace authorized with AWS Chatbot .

        To get the workspace ID, you must perform the initial authorization flow with Slack in the AWS Chatbot console. Then you can copy and paste the workspace ID from the console. For more details, see steps 1-4 in `Setting Up AWS Chatbot with Slack <https://docs.aws.amazon.com/chatbot/latest/adminguide/setting-up.html#Setup_intro>`_ in the *AWS Chatbot User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-slackworkspaceid
        '''
        result = self._values.get("slack_workspace_id")
        assert result is not None, "Required property 'slack_workspace_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def guardrail_policies(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of IAM policy ARNs that are applied as channel guardrails.

        The AWS managed 'AdministratorAccess' policy is applied as a default if this is not set. Currently, only 1 IAM policy is supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-guardrailpolicies
        '''
        result = self._values.get("guardrail_policies")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def logging_level(self) -> typing.Optional[builtins.str]:
        '''Specifies the logging level for this configuration. This property affects the log entries pushed to Amazon CloudWatch Logs.

        Logging levels include ``ERROR`` , ``INFO`` , or ``NONE`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-logginglevel
        '''
        result = self._values.get("logging_level")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def sns_topic_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The ARNs of the SNS topics that deliver notifications to AWS Chatbot .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-snstopicarns
        '''
        result = self._values.get("sns_topic_arns")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def user_role_required(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables use of a user role requirement in your chat configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-chatbot-slackchannelconfiguration.html#cfn-chatbot-slackchannelconfiguration-userrolerequired
        '''
        result = self._values.get("user_role_required")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSlackChannelConfigurationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.interface(jsii_type="aws-cdk-lib.aws_chatbot.ISlackChannelConfiguration")
class ISlackChannelConfiguration(
    _IResource_c80c4260,
    _IGrantable_71c4f5de,
    _INotificationRuleTarget_faa3b79b,
    typing_extensions.Protocol,
):
    '''Represents a Slack channel configuration.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="slackChannelConfigurationArn")
    def slack_channel_configuration_arn(self) -> builtins.str:
        '''The ARN of the Slack channel configuration In the form of arn:aws:chatbot:{region}:{account}:chat-configuration/slack-channel/{slackChannelName}.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="slackChannelConfigurationName")
    def slack_channel_configuration_name(self) -> builtins.str:
        '''The name of Slack channel configuration.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="role")
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The permission role of Slack channel configuration.

        :default: - A role will be created.

        :attribute: true
        '''
        ...

    @jsii.member(jsii_name="addToRolePolicy")
    def add_to_role_policy(self, statement: _PolicyStatement_0fe33853) -> None:
        '''Adds a statement to the IAM role.

        :param statement: -
        '''
        ...

    @jsii.member(jsii_name="metric")
    def metric(
        self,
        metric_name: builtins.str,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the given named metric for this SlackChannelConfiguration.

        :param metric_name: -
        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream
        '''
        ...


class _ISlackChannelConfigurationProxy(
    jsii.proxy_for(_IResource_c80c4260), # type: ignore[misc]
    jsii.proxy_for(_IGrantable_71c4f5de), # type: ignore[misc]
    jsii.proxy_for(_INotificationRuleTarget_faa3b79b), # type: ignore[misc]
):
    '''Represents a Slack channel configuration.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_chatbot.ISlackChannelConfiguration"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="slackChannelConfigurationArn")
    def slack_channel_configuration_arn(self) -> builtins.str:
        '''The ARN of the Slack channel configuration In the form of arn:aws:chatbot:{region}:{account}:chat-configuration/slack-channel/{slackChannelName}.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "slackChannelConfigurationArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="slackChannelConfigurationName")
    def slack_channel_configuration_name(self) -> builtins.str:
        '''The name of Slack channel configuration.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "slackChannelConfigurationName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="role")
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The permission role of Slack channel configuration.

        :default: - A role will be created.

        :attribute: true
        '''
        return typing.cast(typing.Optional[_IRole_235f5d8e], jsii.get(self, "role"))

    @jsii.member(jsii_name="addToRolePolicy")
    def add_to_role_policy(self, statement: _PolicyStatement_0fe33853) -> None:
        '''Adds a statement to the IAM role.

        :param statement: -
        '''
        return typing.cast(None, jsii.invoke(self, "addToRolePolicy", [statement]))

    @jsii.member(jsii_name="metric")
    def metric(
        self,
        metric_name: builtins.str,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the given named metric for this SlackChannelConfiguration.

        :param metric_name: -
        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metric", [metric_name, props]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ISlackChannelConfiguration).__jsii_proxy_class__ = lambda : _ISlackChannelConfigurationProxy


@jsii.enum(jsii_type="aws-cdk-lib.aws_chatbot.LoggingLevel")
class LoggingLevel(enum.Enum):
    '''Logging levels include ERROR, INFO, or NONE.'''

    ERROR = "ERROR"
    '''ERROR.'''
    INFO = "INFO"
    '''INFO.'''
    NONE = "NONE"
    '''NONE.'''


@jsii.implements(ISlackChannelConfiguration)
class SlackChannelConfiguration(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_chatbot.SlackChannelConfiguration",
):
    '''A new Slack channel configuration.

    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_chatbot as chatbot
        
        # project: codebuild.Project
        
        
        target = chatbot.SlackChannelConfiguration(self, "MySlackChannel",
            slack_channel_configuration_name="YOUR_CHANNEL_NAME",
            slack_workspace_id="YOUR_SLACK_WORKSPACE_ID",
            slack_channel_id="YOUR_SLACK_CHANNEL_ID"
        )
        
        rule = project.notify_on_build_succeeded("NotifyOnBuildSucceeded", target)
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        slack_channel_configuration_name: builtins.str,
        slack_channel_id: builtins.str,
        slack_workspace_id: builtins.str,
        logging_level: typing.Optional[LoggingLevel] = None,
        log_retention: typing.Optional[_RetentionDays_070f99f0] = None,
        log_retention_retry_options: typing.Optional[_LogRetentionRetryOptions_62d80a14] = None,
        log_retention_role: typing.Optional[_IRole_235f5d8e] = None,
        notification_topics: typing.Optional[typing.Sequence[_ITopic_9eca4852]] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param slack_channel_configuration_name: The name of Slack channel configuration.
        :param slack_channel_id: The ID of the Slack channel. To get the ID, open Slack, right click on the channel name in the left pane, then choose Copy Link. The channel ID is the 9-character string at the end of the URL. For example, ABCBBLZZZ.
        :param slack_workspace_id: The ID of the Slack workspace authorized with AWS Chatbot. To get the workspace ID, you must perform the initial authorization flow with Slack in the AWS Chatbot console. Then you can copy and paste the workspace ID from the console. For more details, see steps 1-4 in Setting Up AWS Chatbot with Slack in the AWS Chatbot User Guide.
        :param logging_level: Specifies the logging level for this configuration. This property affects the log entries pushed to Amazon CloudWatch Logs. Default: LoggingLevel.NONE
        :param log_retention: The number of days log events are kept in CloudWatch Logs. When updating this property, unsetting it doesn't remove the log retention policy. To remove the retention policy, set the value to ``INFINITE``. Default: logs.RetentionDays.INFINITE
        :param log_retention_retry_options: When log retention is specified, a custom resource attempts to create the CloudWatch log group. These options control the retry policy when interacting with CloudWatch APIs. Default: - Default AWS SDK retry options.
        :param log_retention_role: The IAM role for the Lambda function associated with the custom resource that sets the retention policy. Default: - A new role is created.
        :param notification_topics: The SNS topics that deliver notifications to AWS Chatbot. Default: None
        :param role: The permission role of Slack channel configuration. Default: - A role will be created.
        '''
        props = SlackChannelConfigurationProps(
            slack_channel_configuration_name=slack_channel_configuration_name,
            slack_channel_id=slack_channel_id,
            slack_workspace_id=slack_workspace_id,
            logging_level=logging_level,
            log_retention=log_retention,
            log_retention_retry_options=log_retention_retry_options,
            log_retention_role=log_retention_role,
            notification_topics=notification_topics,
            role=role,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromSlackChannelConfigurationArn") # type: ignore[misc]
    @builtins.classmethod
    def from_slack_channel_configuration_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        slack_channel_configuration_arn: builtins.str,
    ) -> ISlackChannelConfiguration:
        '''Import an existing Slack channel configuration provided an ARN.

        :param scope: The parent creating construct.
        :param id: The construct's name.
        :param slack_channel_configuration_arn: configuration ARN (i.e. arn:aws:chatbot::1234567890:chat-configuration/slack-channel/my-slack).

        :return: a reference to the existing Slack channel configuration
        '''
        return typing.cast(ISlackChannelConfiguration, jsii.sinvoke(cls, "fromSlackChannelConfigurationArn", [scope, id, slack_channel_configuration_arn]))

    @jsii.member(jsii_name="metricAll") # type: ignore[misc]
    @builtins.classmethod
    def metric_all(
        cls,
        metric_name: builtins.str,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the given named metric for All SlackChannelConfigurations.

        :param metric_name: -
        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.sinvoke(cls, "metricAll", [metric_name, props]))

    @jsii.member(jsii_name="addNotificationTopic")
    def add_notification_topic(self, notification_topic: _ITopic_9eca4852) -> None:
        '''Adds a SNS topic that deliver notifications to AWS Chatbot.

        :param notification_topic: -
        '''
        return typing.cast(None, jsii.invoke(self, "addNotificationTopic", [notification_topic]))

    @jsii.member(jsii_name="addToRolePolicy")
    def add_to_role_policy(self, statement: _PolicyStatement_0fe33853) -> None:
        '''Adds extra permission to iam-role of Slack channel configuration.

        :param statement: -
        '''
        return typing.cast(None, jsii.invoke(self, "addToRolePolicy", [statement]))

    @jsii.member(jsii_name="bindAsNotificationRuleTarget")
    def bind_as_notification_rule_target(
        self,
        _scope: constructs.Construct,
    ) -> _NotificationRuleTargetConfig_ea27e095:
        '''Returns a target configuration for notification rule.

        :param _scope: -
        '''
        return typing.cast(_NotificationRuleTargetConfig_ea27e095, jsii.invoke(self, "bindAsNotificationRuleTarget", [_scope]))

    @jsii.member(jsii_name="metric")
    def metric(
        self,
        metric_name: builtins.str,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the given named metric for this SlackChannelConfiguration.

        :param metric_name: -
        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metric", [metric_name, props]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="grantPrincipal")
    def grant_principal(self) -> _IPrincipal_539bb2fd:
        '''The principal to grant permissions to.'''
        return typing.cast(_IPrincipal_539bb2fd, jsii.get(self, "grantPrincipal"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="slackChannelConfigurationArn")
    def slack_channel_configuration_arn(self) -> builtins.str:
        '''The ARN of the Slack channel configuration In the form of arn:aws:chatbot:{region}:{account}:chat-configuration/slack-channel/{slackChannelName}.'''
        return typing.cast(builtins.str, jsii.get(self, "slackChannelConfigurationArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="slackChannelConfigurationName")
    def slack_channel_configuration_name(self) -> builtins.str:
        '''The name of Slack channel configuration.'''
        return typing.cast(builtins.str, jsii.get(self, "slackChannelConfigurationName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="role")
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The permission role of Slack channel configuration.'''
        return typing.cast(typing.Optional[_IRole_235f5d8e], jsii.get(self, "role"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_chatbot.SlackChannelConfigurationProps",
    jsii_struct_bases=[],
    name_mapping={
        "slack_channel_configuration_name": "slackChannelConfigurationName",
        "slack_channel_id": "slackChannelId",
        "slack_workspace_id": "slackWorkspaceId",
        "logging_level": "loggingLevel",
        "log_retention": "logRetention",
        "log_retention_retry_options": "logRetentionRetryOptions",
        "log_retention_role": "logRetentionRole",
        "notification_topics": "notificationTopics",
        "role": "role",
    },
)
class SlackChannelConfigurationProps:
    def __init__(
        self,
        *,
        slack_channel_configuration_name: builtins.str,
        slack_channel_id: builtins.str,
        slack_workspace_id: builtins.str,
        logging_level: typing.Optional[LoggingLevel] = None,
        log_retention: typing.Optional[_RetentionDays_070f99f0] = None,
        log_retention_retry_options: typing.Optional[_LogRetentionRetryOptions_62d80a14] = None,
        log_retention_role: typing.Optional[_IRole_235f5d8e] = None,
        notification_topics: typing.Optional[typing.Sequence[_ITopic_9eca4852]] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> None:
        '''Properties for a new Slack channel configuration.

        :param slack_channel_configuration_name: The name of Slack channel configuration.
        :param slack_channel_id: The ID of the Slack channel. To get the ID, open Slack, right click on the channel name in the left pane, then choose Copy Link. The channel ID is the 9-character string at the end of the URL. For example, ABCBBLZZZ.
        :param slack_workspace_id: The ID of the Slack workspace authorized with AWS Chatbot. To get the workspace ID, you must perform the initial authorization flow with Slack in the AWS Chatbot console. Then you can copy and paste the workspace ID from the console. For more details, see steps 1-4 in Setting Up AWS Chatbot with Slack in the AWS Chatbot User Guide.
        :param logging_level: Specifies the logging level for this configuration. This property affects the log entries pushed to Amazon CloudWatch Logs. Default: LoggingLevel.NONE
        :param log_retention: The number of days log events are kept in CloudWatch Logs. When updating this property, unsetting it doesn't remove the log retention policy. To remove the retention policy, set the value to ``INFINITE``. Default: logs.RetentionDays.INFINITE
        :param log_retention_retry_options: When log retention is specified, a custom resource attempts to create the CloudWatch log group. These options control the retry policy when interacting with CloudWatch APIs. Default: - Default AWS SDK retry options.
        :param log_retention_role: The IAM role for the Lambda function associated with the custom resource that sets the retention policy. Default: - A new role is created.
        :param notification_topics: The SNS topics that deliver notifications to AWS Chatbot. Default: None
        :param role: The permission role of Slack channel configuration. Default: - A role will be created.

        :exampleMetadata: infused

        Example::

            import aws_cdk.aws_chatbot as chatbot
            
            # project: codebuild.Project
            
            
            target = chatbot.SlackChannelConfiguration(self, "MySlackChannel",
                slack_channel_configuration_name="YOUR_CHANNEL_NAME",
                slack_workspace_id="YOUR_SLACK_WORKSPACE_ID",
                slack_channel_id="YOUR_SLACK_CHANNEL_ID"
            )
            
            rule = project.notify_on_build_succeeded("NotifyOnBuildSucceeded", target)
        '''
        if isinstance(log_retention_retry_options, dict):
            log_retention_retry_options = _LogRetentionRetryOptions_62d80a14(**log_retention_retry_options)
        self._values: typing.Dict[str, typing.Any] = {
            "slack_channel_configuration_name": slack_channel_configuration_name,
            "slack_channel_id": slack_channel_id,
            "slack_workspace_id": slack_workspace_id,
        }
        if logging_level is not None:
            self._values["logging_level"] = logging_level
        if log_retention is not None:
            self._values["log_retention"] = log_retention
        if log_retention_retry_options is not None:
            self._values["log_retention_retry_options"] = log_retention_retry_options
        if log_retention_role is not None:
            self._values["log_retention_role"] = log_retention_role
        if notification_topics is not None:
            self._values["notification_topics"] = notification_topics
        if role is not None:
            self._values["role"] = role

    @builtins.property
    def slack_channel_configuration_name(self) -> builtins.str:
        '''The name of Slack channel configuration.'''
        result = self._values.get("slack_channel_configuration_name")
        assert result is not None, "Required property 'slack_channel_configuration_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def slack_channel_id(self) -> builtins.str:
        '''The ID of the Slack channel.

        To get the ID, open Slack, right click on the channel name in the left pane, then choose Copy Link.
        The channel ID is the 9-character string at the end of the URL. For example, ABCBBLZZZ.
        '''
        result = self._values.get("slack_channel_id")
        assert result is not None, "Required property 'slack_channel_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def slack_workspace_id(self) -> builtins.str:
        '''The ID of the Slack workspace authorized with AWS Chatbot.

        To get the workspace ID, you must perform the initial authorization flow with Slack in the AWS Chatbot console.
        Then you can copy and paste the workspace ID from the console.
        For more details, see steps 1-4 in Setting Up AWS Chatbot with Slack in the AWS Chatbot User Guide.

        :see: https://docs.aws.amazon.com/chatbot/latest/adminguide/setting-up.html#Setup_intro
        '''
        result = self._values.get("slack_workspace_id")
        assert result is not None, "Required property 'slack_workspace_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def logging_level(self) -> typing.Optional[LoggingLevel]:
        '''Specifies the logging level for this configuration.

        This property affects the log entries pushed to Amazon CloudWatch Logs.

        :default: LoggingLevel.NONE
        '''
        result = self._values.get("logging_level")
        return typing.cast(typing.Optional[LoggingLevel], result)

    @builtins.property
    def log_retention(self) -> typing.Optional[_RetentionDays_070f99f0]:
        '''The number of days log events are kept in CloudWatch Logs.

        When updating
        this property, unsetting it doesn't remove the log retention policy. To
        remove the retention policy, set the value to ``INFINITE``.

        :default: logs.RetentionDays.INFINITE
        '''
        result = self._values.get("log_retention")
        return typing.cast(typing.Optional[_RetentionDays_070f99f0], result)

    @builtins.property
    def log_retention_retry_options(
        self,
    ) -> typing.Optional[_LogRetentionRetryOptions_62d80a14]:
        '''When log retention is specified, a custom resource attempts to create the CloudWatch log group.

        These options control the retry policy when interacting with CloudWatch APIs.

        :default: - Default AWS SDK retry options.
        '''
        result = self._values.get("log_retention_retry_options")
        return typing.cast(typing.Optional[_LogRetentionRetryOptions_62d80a14], result)

    @builtins.property
    def log_retention_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The IAM role for the Lambda function associated with the custom resource that sets the retention policy.

        :default: - A new role is created.
        '''
        result = self._values.get("log_retention_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def notification_topics(self) -> typing.Optional[typing.List[_ITopic_9eca4852]]:
        '''The SNS topics that deliver notifications to AWS Chatbot.

        :default: None
        '''
        result = self._values.get("notification_topics")
        return typing.cast(typing.Optional[typing.List[_ITopic_9eca4852]], result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The permission role of Slack channel configuration.

        :default: - A role will be created.
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SlackChannelConfigurationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnSlackChannelConfiguration",
    "CfnSlackChannelConfigurationProps",
    "ISlackChannelConfiguration",
    "LoggingLevel",
    "SlackChannelConfiguration",
    "SlackChannelConfigurationProps",
]

publication.publish()
