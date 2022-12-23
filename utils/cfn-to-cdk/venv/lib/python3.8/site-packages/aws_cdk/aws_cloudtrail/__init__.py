'''
# AWS CloudTrail Construct Library

## Trail

AWS CloudTrail enables governance, compliance, and operational and risk auditing of your AWS account. Actions taken by
a user, role, or an AWS service are recorded as events in CloudTrail. Learn more at the [CloudTrail
documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html).

The `Trail` construct enables ongoing delivery of events as log files to an Amazon S3 bucket. Learn more about [Creating
a Trail for Your AWS Account](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html).
The following code creates a simple CloudTrail for your account -

```python
trail = cloudtrail.Trail(self, "CloudTrail")
```

By default, this will create a new S3 Bucket that CloudTrail will write to, and choose a few other reasonable defaults
such as turning on multi-region and global service events.
The defaults for each property and how to override them are all documented on the `TrailProps` interface.

## Log File Validation

In order to validate that the CloudTrail log file was not modified after CloudTrail delivered it, CloudTrail provides a
digital signature for each file. Learn more at [Validating CloudTrail Log File
Integrity](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html).

This is enabled on the `Trail` construct by default, but can be turned off by setting `enableFileValidation` to `false`.

```python
trail = cloudtrail.Trail(self, "CloudTrail",
    enable_file_validation=False
)
```

## Notifications

Amazon SNS notifications can be configured upon new log files containing Trail events are delivered to S3.
Learn more at [Configuring Amazon SNS Notifications for
CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-sns-notifications-for-cloudtrail.html).
The following code configures an SNS topic to be notified -

```python
topic = sns.Topic(self, "TrailTopic")
trail = cloudtrail.Trail(self, "CloudTrail",
    sns_topic=topic
)
```

## Service Integrations

Besides sending trail events to S3, they can also be configured to notify other AWS services -

### Amazon CloudWatch Logs

CloudTrail events can be delivered to a CloudWatch Logs LogGroup. By default, a new LogGroup is created with a
default retention setting. The following code enables sending CloudWatch logs but specifies a particular retention
period for the created Log Group.

```python
import aws_cdk.aws_logs as logs


trail = cloudtrail.Trail(self, "CloudTrail",
    send_to_cloud_watch_logs=True,
    cloud_watch_logs_retention=logs.RetentionDays.FOUR_MONTHS
)
```

If you would like to use a specific log group instead, this can be configured via `cloudwatchLogGroup`.

### Amazon EventBridge

Amazon EventBridge rules can be configured to be triggered when CloudTrail events occur using the `Trail.onEvent()` API.
Using APIs available in `aws-events`, these events can be filtered to match to those that are of interest, either from
a specific service, account or time range. See [Events delivered via
CloudTrail](https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/EventTypes.html#events-for-services-not-listed)
to learn more about the event structure for events from CloudTrail.

The following code filters events for S3 from a specific AWS account and triggers a lambda function.

```python
my_function_handler = lambda_.Function(self, "MyFunction",
    code=lambda_.Code.from_asset("resource/myfunction"),
    runtime=lambda_.Runtime.NODEJS_12_X,
    handler="index.handler"
)

event_rule = cloudtrail.Trail.on_event(self, "MyCloudWatchEvent",
    target=targets.LambdaFunction(my_function_handler)
)

event_rule.add_event_pattern(
    account=["123456789012"],
    source=["aws.s3"]
)
```

## Multi-Region & Global Service Events

By default, a `Trail` is configured to deliver log files from multiple regions to a single S3 bucket for a given
account. This creates shadow trails (replication of the trails) in all of the other regions. Learn more about [How
CloudTrail Behaves Regionally](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-regional-and-global-services)
and about the [`IsMultiRegion`
property](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-ismultiregiontrail).

For most services, events are recorded in the region where the action occurred. For global services such as AWS IAM,
AWS STS, Amazon CloudFront, Route 53, etc., events are delivered to any trail that includes global services. Learn more
[About Global Service Events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-global-service-events).

Events for global services are turned on by default for `Trail` constructs in the CDK.

The following code disables multi-region trail delivery and trail delivery for global services for a specific `Trail` -

```python
trail = cloudtrail.Trail(self, "CloudTrail",
    # ...
    is_multi_region_trail=False,
    include_global_service_events=False
)
```

## Events Types

**Management events** provide information about management operations that are performed on resources in your AWS
account. These are also known as control plane operations. Learn more about [Management
Events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-events).

By default, a `Trail` logs all management events. However, they can be configured to either be turned off, or to only
log 'Read' or 'Write' events.

The following code configures the `Trail` to only track management events that are of type 'Read'.

```python
trail = cloudtrail.Trail(self, "CloudTrail",
    # ...
    management_events=cloudtrail.ReadWriteType.READ_ONLY
)
```

**Data events** provide information about the resource operations performed on or in a resource. These are also known
as data plane operations. Learn more about [Data
Events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-events).
By default, no data events are logged for a `Trail`.

AWS CloudTrail supports data event logging for Amazon S3 objects and AWS Lambda functions.

The `logAllS3DataEvents()` API configures the trail to log all S3 data events while the `addS3EventSelector()` API can
be used to configure logging of S3 data events for specific buckets and specific object prefix. The following code
configures logging of S3 data events for `fooBucket` and with object prefix `bar/`.

```python
import aws_cdk.aws_s3 as s3
# bucket: s3.Bucket


trail = cloudtrail.Trail(self, "MyAmazingCloudTrail")

# Adds an event selector to the bucket foo
trail.add_s3_event_selector([
    bucket=bucket,
    object_prefix="bar/"
])
```

Similarly, the `logAllLambdaDataEvents()` configures the trail to log all Lambda data events while the
`addLambdaEventSelector()` API can be used to configure logging for specific Lambda functions. The following code
configures logging of Lambda data events for a specific Function.

```python
trail = cloudtrail.Trail(self, "MyAmazingCloudTrail")
amazing_function = lambda_.Function(self, "AnAmazingFunction",
    runtime=lambda_.Runtime.NODEJS_12_X,
    handler="hello.handler",
    code=lambda_.Code.from_asset("lambda")
)

# Add an event selector to log data events for the provided Lambda functions.
trail.add_lambda_event_selector([amazing_function])
```
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
    Resource as _Resource_45bc6135,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_events import (
    EventPattern as _EventPattern_fe557901,
    IRuleTarget as _IRuleTarget_7a91f454,
    OnEventOptions as _OnEventOptions_8711b8b3,
    Rule as _Rule_334ed2b5,
)
from ..aws_kms import IKey as _IKey_5f11635f
from ..aws_lambda import IFunction as _IFunction_6adb0ab8
from ..aws_logs import (
    ILogGroup as _ILogGroup_3c4fa718, RetentionDays as _RetentionDays_070f99f0
)
from ..aws_s3 import IBucket as _IBucket_42e086fd
from ..aws_sns import ITopic as _ITopic_9eca4852


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cloudtrail.AddEventSelectorOptions",
    jsii_struct_bases=[],
    name_mapping={
        "exclude_management_event_sources": "excludeManagementEventSources",
        "include_management_events": "includeManagementEvents",
        "read_write_type": "readWriteType",
    },
)
class AddEventSelectorOptions:
    def __init__(
        self,
        *,
        exclude_management_event_sources: typing.Optional[typing.Sequence["ManagementEventSources"]] = None,
        include_management_events: typing.Optional[builtins.bool] = None,
        read_write_type: typing.Optional["ReadWriteType"] = None,
    ) -> None:
        '''Options for adding an event selector.

        :param exclude_management_event_sources: An optional list of service event sources from which you do not want management events to be logged on your trail. Default: []
        :param include_management_events: Specifies whether the event selector includes management events for the trail. Default: true
        :param read_write_type: Specifies whether to log read-only events, write-only events, or all events. Default: ReadWriteType.All

        :exampleMetadata: infused

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            import aws_cdk.aws_cloudtrail as cloudtrail
            
            # source_bucket: s3.Bucket
            
            source_output = codepipeline.Artifact()
            key = "some/key.zip"
            trail = cloudtrail.Trail(self, "CloudTrail")
            trail.add_s3_event_selector([cloudtrail.S3EventSelector(
                bucket=source_bucket,
                object_prefix=key
            )],
                read_write_type=cloudtrail.ReadWriteType.WRITE_ONLY
            )
            source_action = codepipeline_actions.S3SourceAction(
                action_name="S3Source",
                bucket_key=key,
                bucket=source_bucket,
                output=source_output,
                trigger=codepipeline_actions.S3Trigger.EVENTS
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if exclude_management_event_sources is not None:
            self._values["exclude_management_event_sources"] = exclude_management_event_sources
        if include_management_events is not None:
            self._values["include_management_events"] = include_management_events
        if read_write_type is not None:
            self._values["read_write_type"] = read_write_type

    @builtins.property
    def exclude_management_event_sources(
        self,
    ) -> typing.Optional[typing.List["ManagementEventSources"]]:
        '''An optional list of service event sources from which you do not want management events to be logged on your trail.

        :default: []
        '''
        result = self._values.get("exclude_management_event_sources")
        return typing.cast(typing.Optional[typing.List["ManagementEventSources"]], result)

    @builtins.property
    def include_management_events(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether the event selector includes management events for the trail.

        :default: true
        '''
        result = self._values.get("include_management_events")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def read_write_type(self) -> typing.Optional["ReadWriteType"]:
        '''Specifies whether to log read-only events, write-only events, or all events.

        :default: ReadWriteType.All
        '''
        result = self._values.get("read_write_type")
        return typing.cast(typing.Optional["ReadWriteType"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AddEventSelectorOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnTrail(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cloudtrail.CfnTrail",
):
    '''A CloudFormation ``AWS::CloudTrail::Trail``.

    Creates a trail that specifies the settings for delivery of log data to an Amazon S3 bucket.

    :cloudformationResource: AWS::CloudTrail::Trail
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cloudtrail as cloudtrail
        
        cfn_trail = cloudtrail.CfnTrail(self, "MyCfnTrail",
            is_logging=False,
            s3_bucket_name="s3BucketName",
        
            # the properties below are optional
            cloud_watch_logs_log_group_arn="cloudWatchLogsLogGroupArn",
            cloud_watch_logs_role_arn="cloudWatchLogsRoleArn",
            enable_log_file_validation=False,
            event_selectors=[cloudtrail.CfnTrail.EventSelectorProperty(
                data_resources=[cloudtrail.CfnTrail.DataResourceProperty(
                    type="type",
        
                    # the properties below are optional
                    values=["values"]
                )],
                exclude_management_event_sources=["excludeManagementEventSources"],
                include_management_events=False,
                read_write_type="readWriteType"
            )],
            include_global_service_events=False,
            insight_selectors=[cloudtrail.CfnTrail.InsightSelectorProperty(
                insight_type="insightType"
            )],
            is_multi_region_trail=False,
            is_organization_trail=False,
            kms_key_id="kmsKeyId",
            s3_key_prefix="s3KeyPrefix",
            sns_topic_name="snsTopicName",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            trail_name="trailName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        is_logging: typing.Union[builtins.bool, _IResolvable_da3f097b],
        s3_bucket_name: builtins.str,
        cloud_watch_logs_log_group_arn: typing.Optional[builtins.str] = None,
        cloud_watch_logs_role_arn: typing.Optional[builtins.str] = None,
        enable_log_file_validation: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        event_selectors: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTrail.EventSelectorProperty", _IResolvable_da3f097b]]]] = None,
        include_global_service_events: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        insight_selectors: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTrail.InsightSelectorProperty", _IResolvable_da3f097b]]]] = None,
        is_multi_region_trail: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        is_organization_trail: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        s3_key_prefix: typing.Optional[builtins.str] = None,
        sns_topic_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        trail_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::CloudTrail::Trail``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param is_logging: Whether the CloudTrail trail is currently logging AWS API calls.
        :param s3_bucket_name: Specifies the name of the Amazon S3 bucket designated for publishing log files. See `Amazon S3 Bucket Naming Requirements <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create_trail_naming_policy.html>`_ .
        :param cloud_watch_logs_log_group_arn: Specifies a log group name using an Amazon Resource Name (ARN), a unique identifier that represents the log group to which CloudTrail logs are delivered. Not required unless you specify ``CloudWatchLogsRoleArn`` .
        :param cloud_watch_logs_role_arn: Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group.
        :param enable_log_file_validation: Specifies whether log file validation is enabled. The default is false. .. epigraph:: When you disable log file integrity validation, the chain of digest files is broken after one hour. CloudTrail does not create digest files for log files that were delivered during a period in which log file integrity validation was disabled. For example, if you enable log file integrity validation at noon on January 1, disable it at noon on January 2, and re-enable it at noon on January 10, digest files will not be created for the log files delivered from noon on January 2 to noon on January 10. The same applies whenever you stop CloudTrail logging or delete a trail.
        :param event_selectors: Use event selectors to further specify the management and data event settings for your trail. By default, trails created without specific event selectors will be configured to log all read and write management events, and no data events. When an event occurs in your account, CloudTrail evaluates the event selector for all trails. For each trail, if the event matches any event selector, the trail processes and logs the event. If the event doesn't match any event selector, the trail doesn't log the event. You can configure up to five event selectors for a trail. You cannot apply both event selectors and advanced event selectors to a trail.
        :param include_global_service_events: Specifies whether the trail is publishing events from global services such as IAM to the log files.
        :param insight_selectors: Specifies whether a trail has insight types specified in an ``InsightSelector`` list.
        :param is_multi_region_trail: Specifies whether the trail applies only to the current region or to all regions. The default is false. If the trail exists only in the current region and this value is set to true, shadow trails (replications of the trail) will be created in the other regions. If the trail exists in all regions and this value is set to false, the trail will remain in the region where it was created, and its shadow trails in other regions will be deleted. As a best practice, consider using trails that log events in all regions.
        :param is_organization_trail: Specifies whether the trail is created for all accounts in an organization in AWS Organizations , or only for the current AWS account . The default is false, and cannot be true unless the call is made on behalf of an AWS account that is the management account for an organization in AWS Organizations .
        :param kms_key_id: Specifies the AWS KMS key ID to use to encrypt the logs delivered by CloudTrail. The value can be an alias name prefixed by "alias/", a fully specified ARN to an alias, a fully specified ARN to a key, or a globally unique identifier. CloudTrail also supports AWS KMS multi-Region keys. For more information about multi-Region keys, see `Using multi-Region keys <https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html>`_ in the *AWS Key Management Service Developer Guide* . Examples: - alias/MyAliasName - arn:aws:kms:us-east-2:123456789012:alias/MyAliasName - arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012 - 12345678-1234-1234-1234-123456789012
        :param s3_key_prefix: Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery. For more information, see `Finding Your CloudTrail Log Files <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-find-log-files.html>`_ . The maximum length is 200 characters.
        :param sns_topic_name: Specifies the name of the Amazon SNS topic defined for notification of log file delivery. The maximum length is 256 characters.
        :param tags: A custom set of tags (key-value pairs) for this trail.
        :param trail_name: Specifies the name of the trail. The name must meet the following requirements:. - Contain only ASCII letters (a-z, A-Z), numbers (0-9), periods (.), underscores (_), or dashes (-) - Start with a letter or number, and end with a letter or number - Be between 3 and 128 characters - Have no adjacent periods, underscores or dashes. Names like ``my-_namespace`` and ``my--namespace`` are not valid. - Not be in IP address format (for example, 192.168.5.4)
        '''
        props = CfnTrailProps(
            is_logging=is_logging,
            s3_bucket_name=s3_bucket_name,
            cloud_watch_logs_log_group_arn=cloud_watch_logs_log_group_arn,
            cloud_watch_logs_role_arn=cloud_watch_logs_role_arn,
            enable_log_file_validation=enable_log_file_validation,
            event_selectors=event_selectors,
            include_global_service_events=include_global_service_events,
            insight_selectors=insight_selectors,
            is_multi_region_trail=is_multi_region_trail,
            is_organization_trail=is_organization_trail,
            kms_key_id=kms_key_id,
            s3_key_prefix=s3_key_prefix,
            sns_topic_name=sns_topic_name,
            tags=tags,
            trail_name=trail_name,
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
        '''``Ref`` returns the ARN of the CloudTrail trail, such as ``arn:aws:cloudtrail:us-east-2:123456789012:trail/myCloudTrail`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSnsTopicArn")
    def attr_sns_topic_arn(self) -> builtins.str:
        '''``Ref`` returns the ARN of the Amazon SNS topic that's associated with the CloudTrail trail, such as ``arn:aws:sns:us-east-2:123456789012:mySNSTopic`` .

        :cloudformationAttribute: SnsTopicArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSnsTopicArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A custom set of tags (key-value pairs) for this trail.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="isLogging")
    def is_logging(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Whether the CloudTrail trail is currently logging AWS API calls.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-islogging
        '''
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], jsii.get(self, "isLogging"))

    @is_logging.setter
    def is_logging(
        self,
        value: typing.Union[builtins.bool, _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "isLogging", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="s3BucketName")
    def s3_bucket_name(self) -> builtins.str:
        '''Specifies the name of the Amazon S3 bucket designated for publishing log files.

        See `Amazon S3 Bucket Naming Requirements <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create_trail_naming_policy.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-s3bucketname
        '''
        return typing.cast(builtins.str, jsii.get(self, "s3BucketName"))

    @s3_bucket_name.setter
    def s3_bucket_name(self, value: builtins.str) -> None:
        jsii.set(self, "s3BucketName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cloudWatchLogsLogGroupArn")
    def cloud_watch_logs_log_group_arn(self) -> typing.Optional[builtins.str]:
        '''Specifies a log group name using an Amazon Resource Name (ARN), a unique identifier that represents the log group to which CloudTrail logs are delivered.

        Not required unless you specify ``CloudWatchLogsRoleArn`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-cloudwatchlogsloggrouparn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "cloudWatchLogsLogGroupArn"))

    @cloud_watch_logs_log_group_arn.setter
    def cloud_watch_logs_log_group_arn(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "cloudWatchLogsLogGroupArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cloudWatchLogsRoleArn")
    def cloud_watch_logs_role_arn(self) -> typing.Optional[builtins.str]:
        '''Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-cloudwatchlogsrolearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "cloudWatchLogsRoleArn"))

    @cloud_watch_logs_role_arn.setter
    def cloud_watch_logs_role_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "cloudWatchLogsRoleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enableLogFileValidation")
    def enable_log_file_validation(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether log file validation is enabled. The default is false.

        .. epigraph::

           When you disable log file integrity validation, the chain of digest files is broken after one hour. CloudTrail does not create digest files for log files that were delivered during a period in which log file integrity validation was disabled. For example, if you enable log file integrity validation at noon on January 1, disable it at noon on January 2, and re-enable it at noon on January 10, digest files will not be created for the log files delivered from noon on January 2 to noon on January 10. The same applies whenever you stop CloudTrail logging or delete a trail.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-enablelogfilevalidation
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enableLogFileValidation"))

    @enable_log_file_validation.setter
    def enable_log_file_validation(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enableLogFileValidation", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventSelectors")
    def event_selectors(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTrail.EventSelectorProperty", _IResolvable_da3f097b]]]]:
        '''Use event selectors to further specify the management and data event settings for your trail.

        By default, trails created without specific event selectors will be configured to log all read and write management events, and no data events. When an event occurs in your account, CloudTrail evaluates the event selector for all trails. For each trail, if the event matches any event selector, the trail processes and logs the event. If the event doesn't match any event selector, the trail doesn't log the event.

        You can configure up to five event selectors for a trail.

        You cannot apply both event selectors and advanced event selectors to a trail.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-eventselectors
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTrail.EventSelectorProperty", _IResolvable_da3f097b]]]], jsii.get(self, "eventSelectors"))

    @event_selectors.setter
    def event_selectors(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTrail.EventSelectorProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "eventSelectors", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="includeGlobalServiceEvents")
    def include_global_service_events(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether the trail is publishing events from global services such as IAM to the log files.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-includeglobalserviceevents
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "includeGlobalServiceEvents"))

    @include_global_service_events.setter
    def include_global_service_events(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "includeGlobalServiceEvents", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="insightSelectors")
    def insight_selectors(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTrail.InsightSelectorProperty", _IResolvable_da3f097b]]]]:
        '''Specifies whether a trail has insight types specified in an ``InsightSelector`` list.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-insightselectors
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTrail.InsightSelectorProperty", _IResolvable_da3f097b]]]], jsii.get(self, "insightSelectors"))

    @insight_selectors.setter
    def insight_selectors(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTrail.InsightSelectorProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "insightSelectors", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="isMultiRegionTrail")
    def is_multi_region_trail(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether the trail applies only to the current region or to all regions.

        The default is false. If the trail exists only in the current region and this value is set to true, shadow trails (replications of the trail) will be created in the other regions. If the trail exists in all regions and this value is set to false, the trail will remain in the region where it was created, and its shadow trails in other regions will be deleted. As a best practice, consider using trails that log events in all regions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-ismultiregiontrail
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "isMultiRegionTrail"))

    @is_multi_region_trail.setter
    def is_multi_region_trail(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "isMultiRegionTrail", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="isOrganizationTrail")
    def is_organization_trail(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether the trail is created for all accounts in an organization in AWS Organizations , or only for the current AWS account .

        The default is false, and cannot be true unless the call is made on behalf of an AWS account that is the management account for an organization in AWS Organizations .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-isorganizationtrail
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "isOrganizationTrail"))

    @is_organization_trail.setter
    def is_organization_trail(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "isOrganizationTrail", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKeyId")
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''Specifies the AWS KMS key ID to use to encrypt the logs delivered by CloudTrail.

        The value can be an alias name prefixed by "alias/", a fully specified ARN to an alias, a fully specified ARN to a key, or a globally unique identifier.

        CloudTrail also supports AWS KMS multi-Region keys. For more information about multi-Region keys, see `Using multi-Region keys <https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html>`_ in the *AWS Key Management Service Developer Guide* .

        Examples:

        - alias/MyAliasName
        - arn:aws:kms:us-east-2:123456789012:alias/MyAliasName
        - arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012
        - 12345678-1234-1234-1234-123456789012

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-kmskeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKeyId"))

    @kms_key_id.setter
    def kms_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKeyId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="s3KeyPrefix")
    def s3_key_prefix(self) -> typing.Optional[builtins.str]:
        '''Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery.

        For more information, see `Finding Your CloudTrail Log Files <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-find-log-files.html>`_ . The maximum length is 200 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-s3keyprefix
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "s3KeyPrefix"))

    @s3_key_prefix.setter
    def s3_key_prefix(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "s3KeyPrefix", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snsTopicName")
    def sns_topic_name(self) -> typing.Optional[builtins.str]:
        '''Specifies the name of the Amazon SNS topic defined for notification of log file delivery.

        The maximum length is 256 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-snstopicname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "snsTopicName"))

    @sns_topic_name.setter
    def sns_topic_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "snsTopicName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="trailName")
    def trail_name(self) -> typing.Optional[builtins.str]:
        '''Specifies the name of the trail. The name must meet the following requirements:.

        - Contain only ASCII letters (a-z, A-Z), numbers (0-9), periods (.), underscores (_), or dashes (-)
        - Start with a letter or number, and end with a letter or number
        - Be between 3 and 128 characters
        - Have no adjacent periods, underscores or dashes. Names like ``my-_namespace`` and ``my--namespace`` are not valid.
        - Not be in IP address format (for example, 192.168.5.4)

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-trailname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "trailName"))

    @trail_name.setter
    def trail_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "trailName", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cloudtrail.CfnTrail.DataResourceProperty",
        jsii_struct_bases=[],
        name_mapping={"type": "type", "values": "values"},
    )
    class DataResourceProperty:
        def __init__(
            self,
            *,
            type: builtins.str,
            values: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''The Amazon S3 buckets, AWS Lambda functions, or Amazon DynamoDB tables that you specify in your event selectors for your trail to log data events.

            Data events provide information about the resource operations performed on or within a resource itself. These are also known as data plane operations. You can specify up to 250 data resources for a trail.
            .. epigraph::

               The total number of allowed data resources is 250. This number can be distributed between 1 and 5 event selectors, but the total cannot exceed 250 across all selectors.

               If you are using advanced event selectors, the maximum total number of values for all conditions, across all advanced event selectors for the trail, is 500.

            The following example demonstrates how logging works when you configure logging of all data events for an S3 bucket named ``bucket-1`` . In this example, the CloudTrail user specified an empty prefix, and the option to log both ``Read`` and ``Write`` data events.

            - A user uploads an image file to ``bucket-1`` .
            - The ``PutObject`` API operation is an Amazon S3 object-level API. It is recorded as a data event in CloudTrail. Because the CloudTrail user specified an S3 bucket with an empty prefix, events that occur on any object in that bucket are logged. The trail processes and logs the event.
            - A user uploads an object to an Amazon S3 bucket named ``arn:aws:s3:::bucket-2`` .
            - The ``PutObject`` API operation occurred for an object in an S3 bucket that the CloudTrail user didn't specify for the trail. The trail doesn’t log the event.

            The following example demonstrates how logging works when you configure logging of AWS Lambda data events for a Lambda function named *MyLambdaFunction* , but not for all Lambda functions.

            - A user runs a script that includes a call to the *MyLambdaFunction* function and the *MyOtherLambdaFunction* function.
            - The ``Invoke`` API operation on *MyLambdaFunction* is an Lambda API. It is recorded as a data event in CloudTrail. Because the CloudTrail user specified logging data events for *MyLambdaFunction* , any invocations of that function are logged. The trail processes and logs the event.
            - The ``Invoke`` API operation on *MyOtherLambdaFunction* is an Lambda API. Because the CloudTrail user did not specify logging data events for all Lambda functions, the ``Invoke`` operation for *MyOtherLambdaFunction* does not match the function specified for the trail. The trail doesn’t log the event.

            :param type: The resource type in which you want to log data events. You can specify the following *basic* event selector resource types: - ``AWS::S3::Object`` - ``AWS::Lambda::Function`` - ``AWS::DynamoDB::Table`` The following resource types are also availble through *advanced* event selectors. Basic event selector resource types are valid in advanced event selectors, but advanced event selector resource types are not valid in basic event selectors. For more information, see `AdvancedFieldSelector:Field <https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AdvancedFieldSelector.html#awscloudtrail-Type-AdvancedFieldSelector-Field>`_ . - ``AWS::S3Outposts::Object`` - ``AWS::ManagedBlockchain::Node`` - ``AWS::S3ObjectLambda::AccessPoint`` - ``AWS::EC2::Snapshot`` - ``AWS::S3::AccessPoint`` - ``AWS::DynamoDB::Stream``
            :param values: An array of Amazon Resource Name (ARN) strings or partial ARN strings for the specified objects. - To log data events for all objects in all S3 buckets in your AWS account , specify the prefix as ``arn:aws:s3:::`` . .. epigraph:: This also enables logging of data event activity performed by any user or role in your AWS account , even if that activity is performed on a bucket that belongs to another AWS account . - To log data events for all objects in an S3 bucket, specify the bucket and an empty object prefix such as ``arn:aws:s3:::bucket-1/`` . The trail logs data events for all objects in this S3 bucket. - To log data events for specific objects, specify the S3 bucket and object prefix such as ``arn:aws:s3:::bucket-1/example-images`` . The trail logs data events for objects in this S3 bucket that match the prefix. - To log data events for all Lambda functions in your AWS account , specify the prefix as ``arn:aws:lambda`` . .. epigraph:: This also enables logging of ``Invoke`` activity performed by any user or role in your AWS account , even if that activity is performed on a function that belongs to another AWS account . - To log data events for a specific Lambda function, specify the function ARN. .. epigraph:: Lambda function ARNs are exact. For example, if you specify a function ARN *arn:aws:lambda:us-west-2:111111111111:function:helloworld* , data events will only be logged for *arn:aws:lambda:us-west-2:111111111111:function:helloworld* . They will not be logged for *arn:aws:lambda:us-west-2:111111111111:function:helloworld2* . - To log data events for all DynamoDB tables in your AWS account , specify the prefix as ``arn:aws:dynamodb`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudtrail-trail-dataresource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cloudtrail as cloudtrail
                
                data_resource_property = cloudtrail.CfnTrail.DataResourceProperty(
                    type="type",
                
                    # the properties below are optional
                    values=["values"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "type": type,
            }
            if values is not None:
                self._values["values"] = values

        @builtins.property
        def type(self) -> builtins.str:
            '''The resource type in which you want to log data events.

            You can specify the following *basic* event selector resource types:

            - ``AWS::S3::Object``
            - ``AWS::Lambda::Function``
            - ``AWS::DynamoDB::Table``

            The following resource types are also availble through *advanced* event selectors. Basic event selector resource types are valid in advanced event selectors, but advanced event selector resource types are not valid in basic event selectors. For more information, see `AdvancedFieldSelector:Field <https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AdvancedFieldSelector.html#awscloudtrail-Type-AdvancedFieldSelector-Field>`_ .

            - ``AWS::S3Outposts::Object``
            - ``AWS::ManagedBlockchain::Node``
            - ``AWS::S3ObjectLambda::AccessPoint``
            - ``AWS::EC2::Snapshot``
            - ``AWS::S3::AccessPoint``
            - ``AWS::DynamoDB::Stream``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudtrail-trail-dataresource.html#cfn-cloudtrail-trail-dataresource-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def values(self) -> typing.Optional[typing.List[builtins.str]]:
            '''An array of Amazon Resource Name (ARN) strings or partial ARN strings for the specified objects.

            - To log data events for all objects in all S3 buckets in your AWS account , specify the prefix as ``arn:aws:s3:::`` .

            .. epigraph::

               This also enables logging of data event activity performed by any user or role in your AWS account , even if that activity is performed on a bucket that belongs to another AWS account .

            - To log data events for all objects in an S3 bucket, specify the bucket and an empty object prefix such as ``arn:aws:s3:::bucket-1/`` . The trail logs data events for all objects in this S3 bucket.
            - To log data events for specific objects, specify the S3 bucket and object prefix such as ``arn:aws:s3:::bucket-1/example-images`` . The trail logs data events for objects in this S3 bucket that match the prefix.
            - To log data events for all Lambda functions in your AWS account , specify the prefix as ``arn:aws:lambda`` .

            .. epigraph::

               This also enables logging of ``Invoke`` activity performed by any user or role in your AWS account , even if that activity is performed on a function that belongs to another AWS account .

            - To log data events for a specific Lambda function, specify the function ARN.

            .. epigraph::

               Lambda function ARNs are exact. For example, if you specify a function ARN *arn:aws:lambda:us-west-2:111111111111:function:helloworld* , data events will only be logged for *arn:aws:lambda:us-west-2:111111111111:function:helloworld* . They will not be logged for *arn:aws:lambda:us-west-2:111111111111:function:helloworld2* .

            - To log data events for all DynamoDB tables in your AWS account , specify the prefix as ``arn:aws:dynamodb`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudtrail-trail-dataresource.html#cfn-cloudtrail-trail-dataresource-values
            '''
            result = self._values.get("values")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataResourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cloudtrail.CfnTrail.EventSelectorProperty",
        jsii_struct_bases=[],
        name_mapping={
            "data_resources": "dataResources",
            "exclude_management_event_sources": "excludeManagementEventSources",
            "include_management_events": "includeManagementEvents",
            "read_write_type": "readWriteType",
        },
    )
    class EventSelectorProperty:
        def __init__(
            self,
            *,
            data_resources: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTrail.DataResourceProperty", _IResolvable_da3f097b]]]] = None,
            exclude_management_event_sources: typing.Optional[typing.Sequence[builtins.str]] = None,
            include_management_events: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            read_write_type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Use event selectors to further specify the management and data event settings for your trail.

            By default, trails created without specific event selectors will be configured to log all read and write management events, and no data events. When an event occurs in your account, CloudTrail evaluates the event selector for all trails. For each trail, if the event matches any event selector, the trail processes and logs the event. If the event doesn't match any event selector, the trail doesn't log the event.

            You can configure up to five event selectors for a trail.

            You cannot apply both event selectors and advanced event selectors to a trail.

            :param data_resources: CloudTrail supports data event logging for Amazon S3 objects and AWS Lambda functions. You can specify up to 250 resources for an individual event selector, but the total number of data resources cannot exceed 250 across all event selectors in a trail. This limit does not apply if you configure resource logging for all data events. For more information, see `Data Events <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-and-data-events-with-cloudtrail.html#logging-data-events>`_ and `Limits in AWS CloudTrail <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/WhatIsCloudTrail-Limits.html>`_ in the *AWS CloudTrail User Guide* .
            :param exclude_management_event_sources: An optional list of service event sources from which you do not want management events to be logged on your trail. In this release, the list can be empty (disables the filter), or it can filter out AWS Key Management Service or Amazon RDS Data API events by containing ``kms.amazonaws.com`` or ``rdsdata.amazonaws.com`` . By default, ``ExcludeManagementEventSources`` is empty, and AWS KMS and Amazon RDS Data API events are logged to your trail. You can exclude management event sources only in regions that support the event source.
            :param include_management_events: Specify if you want your event selector to include management events for your trail. For more information, see `Management Events <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-and-data-events-with-cloudtrail.html#logging-management-events>`_ in the *AWS CloudTrail User Guide* . By default, the value is ``true`` . The first copy of management events is free. You are charged for additional copies of management events that you are logging on any subsequent trail in the same region. For more information about CloudTrail pricing, see `AWS CloudTrail Pricing <https://docs.aws.amazon.com/cloudtrail/pricing/>`_ .
            :param read_write_type: Specify if you want your trail to log read-only events, write-only events, or all. For example, the EC2 ``GetConsoleOutput`` is a read-only API operation and ``RunInstances`` is a write-only API operation. By default, the value is ``All`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudtrail-trail-eventselector.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cloudtrail as cloudtrail
                
                event_selector_property = cloudtrail.CfnTrail.EventSelectorProperty(
                    data_resources=[cloudtrail.CfnTrail.DataResourceProperty(
                        type="type",
                
                        # the properties below are optional
                        values=["values"]
                    )],
                    exclude_management_event_sources=["excludeManagementEventSources"],
                    include_management_events=False,
                    read_write_type="readWriteType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if data_resources is not None:
                self._values["data_resources"] = data_resources
            if exclude_management_event_sources is not None:
                self._values["exclude_management_event_sources"] = exclude_management_event_sources
            if include_management_events is not None:
                self._values["include_management_events"] = include_management_events
            if read_write_type is not None:
                self._values["read_write_type"] = read_write_type

        @builtins.property
        def data_resources(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTrail.DataResourceProperty", _IResolvable_da3f097b]]]]:
            '''CloudTrail supports data event logging for Amazon S3 objects and AWS Lambda functions.

            You can specify up to 250 resources for an individual event selector, but the total number of data resources cannot exceed 250 across all event selectors in a trail. This limit does not apply if you configure resource logging for all data events.

            For more information, see `Data Events <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-and-data-events-with-cloudtrail.html#logging-data-events>`_ and `Limits in AWS CloudTrail <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/WhatIsCloudTrail-Limits.html>`_ in the *AWS CloudTrail User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudtrail-trail-eventselector.html#cfn-cloudtrail-trail-eventselector-dataresources
            '''
            result = self._values.get("data_resources")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTrail.DataResourceProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def exclude_management_event_sources(
            self,
        ) -> typing.Optional[typing.List[builtins.str]]:
            '''An optional list of service event sources from which you do not want management events to be logged on your trail.

            In this release, the list can be empty (disables the filter), or it can filter out AWS Key Management Service or Amazon RDS Data API events by containing ``kms.amazonaws.com`` or ``rdsdata.amazonaws.com`` . By default, ``ExcludeManagementEventSources`` is empty, and AWS KMS and Amazon RDS Data API events are logged to your trail. You can exclude management event sources only in regions that support the event source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudtrail-trail-eventselector.html#cfn-cloudtrail-trail-eventselector-excludemanagementeventsources
            '''
            result = self._values.get("exclude_management_event_sources")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def include_management_events(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specify if you want your event selector to include management events for your trail.

            For more information, see `Management Events <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-and-data-events-with-cloudtrail.html#logging-management-events>`_ in the *AWS CloudTrail User Guide* .

            By default, the value is ``true`` .

            The first copy of management events is free. You are charged for additional copies of management events that you are logging on any subsequent trail in the same region. For more information about CloudTrail pricing, see `AWS CloudTrail Pricing <https://docs.aws.amazon.com/cloudtrail/pricing/>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudtrail-trail-eventselector.html#cfn-cloudtrail-trail-eventselector-includemanagementevents
            '''
            result = self._values.get("include_management_events")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def read_write_type(self) -> typing.Optional[builtins.str]:
            '''Specify if you want your trail to log read-only events, write-only events, or all.

            For example, the EC2 ``GetConsoleOutput`` is a read-only API operation and ``RunInstances`` is a write-only API operation.

            By default, the value is ``All`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudtrail-trail-eventselector.html#cfn-cloudtrail-trail-eventselector-readwritetype
            '''
            result = self._values.get("read_write_type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EventSelectorProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cloudtrail.CfnTrail.InsightSelectorProperty",
        jsii_struct_bases=[],
        name_mapping={"insight_type": "insightType"},
    )
    class InsightSelectorProperty:
        def __init__(
            self,
            *,
            insight_type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A JSON string that contains a list of insight types that are logged on a trail.

            :param insight_type: The type of insights to log on a trail. ``ApiCallRateInsight`` and ``ApiErrorRateInsight`` are valid insight types.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudtrail-trail-insightselector.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cloudtrail as cloudtrail
                
                insight_selector_property = cloudtrail.CfnTrail.InsightSelectorProperty(
                    insight_type="insightType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if insight_type is not None:
                self._values["insight_type"] = insight_type

        @builtins.property
        def insight_type(self) -> typing.Optional[builtins.str]:
            '''The type of insights to log on a trail.

            ``ApiCallRateInsight`` and ``ApiErrorRateInsight`` are valid insight types.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudtrail-trail-insightselector.html#cfn-cloudtrail-trail-insightselector-insighttype
            '''
            result = self._values.get("insight_type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InsightSelectorProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cloudtrail.CfnTrailProps",
    jsii_struct_bases=[],
    name_mapping={
        "is_logging": "isLogging",
        "s3_bucket_name": "s3BucketName",
        "cloud_watch_logs_log_group_arn": "cloudWatchLogsLogGroupArn",
        "cloud_watch_logs_role_arn": "cloudWatchLogsRoleArn",
        "enable_log_file_validation": "enableLogFileValidation",
        "event_selectors": "eventSelectors",
        "include_global_service_events": "includeGlobalServiceEvents",
        "insight_selectors": "insightSelectors",
        "is_multi_region_trail": "isMultiRegionTrail",
        "is_organization_trail": "isOrganizationTrail",
        "kms_key_id": "kmsKeyId",
        "s3_key_prefix": "s3KeyPrefix",
        "sns_topic_name": "snsTopicName",
        "tags": "tags",
        "trail_name": "trailName",
    },
)
class CfnTrailProps:
    def __init__(
        self,
        *,
        is_logging: typing.Union[builtins.bool, _IResolvable_da3f097b],
        s3_bucket_name: builtins.str,
        cloud_watch_logs_log_group_arn: typing.Optional[builtins.str] = None,
        cloud_watch_logs_role_arn: typing.Optional[builtins.str] = None,
        enable_log_file_validation: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        event_selectors: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnTrail.EventSelectorProperty, _IResolvable_da3f097b]]]] = None,
        include_global_service_events: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        insight_selectors: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnTrail.InsightSelectorProperty, _IResolvable_da3f097b]]]] = None,
        is_multi_region_trail: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        is_organization_trail: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        s3_key_prefix: typing.Optional[builtins.str] = None,
        sns_topic_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        trail_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnTrail``.

        :param is_logging: Whether the CloudTrail trail is currently logging AWS API calls.
        :param s3_bucket_name: Specifies the name of the Amazon S3 bucket designated for publishing log files. See `Amazon S3 Bucket Naming Requirements <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create_trail_naming_policy.html>`_ .
        :param cloud_watch_logs_log_group_arn: Specifies a log group name using an Amazon Resource Name (ARN), a unique identifier that represents the log group to which CloudTrail logs are delivered. Not required unless you specify ``CloudWatchLogsRoleArn`` .
        :param cloud_watch_logs_role_arn: Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group.
        :param enable_log_file_validation: Specifies whether log file validation is enabled. The default is false. .. epigraph:: When you disable log file integrity validation, the chain of digest files is broken after one hour. CloudTrail does not create digest files for log files that were delivered during a period in which log file integrity validation was disabled. For example, if you enable log file integrity validation at noon on January 1, disable it at noon on January 2, and re-enable it at noon on January 10, digest files will not be created for the log files delivered from noon on January 2 to noon on January 10. The same applies whenever you stop CloudTrail logging or delete a trail.
        :param event_selectors: Use event selectors to further specify the management and data event settings for your trail. By default, trails created without specific event selectors will be configured to log all read and write management events, and no data events. When an event occurs in your account, CloudTrail evaluates the event selector for all trails. For each trail, if the event matches any event selector, the trail processes and logs the event. If the event doesn't match any event selector, the trail doesn't log the event. You can configure up to five event selectors for a trail. You cannot apply both event selectors and advanced event selectors to a trail.
        :param include_global_service_events: Specifies whether the trail is publishing events from global services such as IAM to the log files.
        :param insight_selectors: Specifies whether a trail has insight types specified in an ``InsightSelector`` list.
        :param is_multi_region_trail: Specifies whether the trail applies only to the current region or to all regions. The default is false. If the trail exists only in the current region and this value is set to true, shadow trails (replications of the trail) will be created in the other regions. If the trail exists in all regions and this value is set to false, the trail will remain in the region where it was created, and its shadow trails in other regions will be deleted. As a best practice, consider using trails that log events in all regions.
        :param is_organization_trail: Specifies whether the trail is created for all accounts in an organization in AWS Organizations , or only for the current AWS account . The default is false, and cannot be true unless the call is made on behalf of an AWS account that is the management account for an organization in AWS Organizations .
        :param kms_key_id: Specifies the AWS KMS key ID to use to encrypt the logs delivered by CloudTrail. The value can be an alias name prefixed by "alias/", a fully specified ARN to an alias, a fully specified ARN to a key, or a globally unique identifier. CloudTrail also supports AWS KMS multi-Region keys. For more information about multi-Region keys, see `Using multi-Region keys <https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html>`_ in the *AWS Key Management Service Developer Guide* . Examples: - alias/MyAliasName - arn:aws:kms:us-east-2:123456789012:alias/MyAliasName - arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012 - 12345678-1234-1234-1234-123456789012
        :param s3_key_prefix: Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery. For more information, see `Finding Your CloudTrail Log Files <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-find-log-files.html>`_ . The maximum length is 200 characters.
        :param sns_topic_name: Specifies the name of the Amazon SNS topic defined for notification of log file delivery. The maximum length is 256 characters.
        :param tags: A custom set of tags (key-value pairs) for this trail.
        :param trail_name: Specifies the name of the trail. The name must meet the following requirements:. - Contain only ASCII letters (a-z, A-Z), numbers (0-9), periods (.), underscores (_), or dashes (-) - Start with a letter or number, and end with a letter or number - Be between 3 and 128 characters - Have no adjacent periods, underscores or dashes. Names like ``my-_namespace`` and ``my--namespace`` are not valid. - Not be in IP address format (for example, 192.168.5.4)

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cloudtrail as cloudtrail
            
            cfn_trail_props = cloudtrail.CfnTrailProps(
                is_logging=False,
                s3_bucket_name="s3BucketName",
            
                # the properties below are optional
                cloud_watch_logs_log_group_arn="cloudWatchLogsLogGroupArn",
                cloud_watch_logs_role_arn="cloudWatchLogsRoleArn",
                enable_log_file_validation=False,
                event_selectors=[cloudtrail.CfnTrail.EventSelectorProperty(
                    data_resources=[cloudtrail.CfnTrail.DataResourceProperty(
                        type="type",
            
                        # the properties below are optional
                        values=["values"]
                    )],
                    exclude_management_event_sources=["excludeManagementEventSources"],
                    include_management_events=False,
                    read_write_type="readWriteType"
                )],
                include_global_service_events=False,
                insight_selectors=[cloudtrail.CfnTrail.InsightSelectorProperty(
                    insight_type="insightType"
                )],
                is_multi_region_trail=False,
                is_organization_trail=False,
                kms_key_id="kmsKeyId",
                s3_key_prefix="s3KeyPrefix",
                sns_topic_name="snsTopicName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                trail_name="trailName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "is_logging": is_logging,
            "s3_bucket_name": s3_bucket_name,
        }
        if cloud_watch_logs_log_group_arn is not None:
            self._values["cloud_watch_logs_log_group_arn"] = cloud_watch_logs_log_group_arn
        if cloud_watch_logs_role_arn is not None:
            self._values["cloud_watch_logs_role_arn"] = cloud_watch_logs_role_arn
        if enable_log_file_validation is not None:
            self._values["enable_log_file_validation"] = enable_log_file_validation
        if event_selectors is not None:
            self._values["event_selectors"] = event_selectors
        if include_global_service_events is not None:
            self._values["include_global_service_events"] = include_global_service_events
        if insight_selectors is not None:
            self._values["insight_selectors"] = insight_selectors
        if is_multi_region_trail is not None:
            self._values["is_multi_region_trail"] = is_multi_region_trail
        if is_organization_trail is not None:
            self._values["is_organization_trail"] = is_organization_trail
        if kms_key_id is not None:
            self._values["kms_key_id"] = kms_key_id
        if s3_key_prefix is not None:
            self._values["s3_key_prefix"] = s3_key_prefix
        if sns_topic_name is not None:
            self._values["sns_topic_name"] = sns_topic_name
        if tags is not None:
            self._values["tags"] = tags
        if trail_name is not None:
            self._values["trail_name"] = trail_name

    @builtins.property
    def is_logging(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Whether the CloudTrail trail is currently logging AWS API calls.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-islogging
        '''
        result = self._values.get("is_logging")
        assert result is not None, "Required property 'is_logging' is missing"
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

    @builtins.property
    def s3_bucket_name(self) -> builtins.str:
        '''Specifies the name of the Amazon S3 bucket designated for publishing log files.

        See `Amazon S3 Bucket Naming Requirements <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create_trail_naming_policy.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-s3bucketname
        '''
        result = self._values.get("s3_bucket_name")
        assert result is not None, "Required property 's3_bucket_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def cloud_watch_logs_log_group_arn(self) -> typing.Optional[builtins.str]:
        '''Specifies a log group name using an Amazon Resource Name (ARN), a unique identifier that represents the log group to which CloudTrail logs are delivered.

        Not required unless you specify ``CloudWatchLogsRoleArn`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-cloudwatchlogsloggrouparn
        '''
        result = self._values.get("cloud_watch_logs_log_group_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cloud_watch_logs_role_arn(self) -> typing.Optional[builtins.str]:
        '''Specifies the role for the CloudWatch Logs endpoint to assume to write to a user's log group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-cloudwatchlogsrolearn
        '''
        result = self._values.get("cloud_watch_logs_role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def enable_log_file_validation(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether log file validation is enabled. The default is false.

        .. epigraph::

           When you disable log file integrity validation, the chain of digest files is broken after one hour. CloudTrail does not create digest files for log files that were delivered during a period in which log file integrity validation was disabled. For example, if you enable log file integrity validation at noon on January 1, disable it at noon on January 2, and re-enable it at noon on January 10, digest files will not be created for the log files delivered from noon on January 2 to noon on January 10. The same applies whenever you stop CloudTrail logging or delete a trail.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-enablelogfilevalidation
        '''
        result = self._values.get("enable_log_file_validation")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def event_selectors(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTrail.EventSelectorProperty, _IResolvable_da3f097b]]]]:
        '''Use event selectors to further specify the management and data event settings for your trail.

        By default, trails created without specific event selectors will be configured to log all read and write management events, and no data events. When an event occurs in your account, CloudTrail evaluates the event selector for all trails. For each trail, if the event matches any event selector, the trail processes and logs the event. If the event doesn't match any event selector, the trail doesn't log the event.

        You can configure up to five event selectors for a trail.

        You cannot apply both event selectors and advanced event selectors to a trail.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-eventselectors
        '''
        result = self._values.get("event_selectors")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTrail.EventSelectorProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def include_global_service_events(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether the trail is publishing events from global services such as IAM to the log files.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-includeglobalserviceevents
        '''
        result = self._values.get("include_global_service_events")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def insight_selectors(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTrail.InsightSelectorProperty, _IResolvable_da3f097b]]]]:
        '''Specifies whether a trail has insight types specified in an ``InsightSelector`` list.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-insightselectors
        '''
        result = self._values.get("insight_selectors")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTrail.InsightSelectorProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def is_multi_region_trail(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether the trail applies only to the current region or to all regions.

        The default is false. If the trail exists only in the current region and this value is set to true, shadow trails (replications of the trail) will be created in the other regions. If the trail exists in all regions and this value is set to false, the trail will remain in the region where it was created, and its shadow trails in other regions will be deleted. As a best practice, consider using trails that log events in all regions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-ismultiregiontrail
        '''
        result = self._values.get("is_multi_region_trail")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def is_organization_trail(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether the trail is created for all accounts in an organization in AWS Organizations , or only for the current AWS account .

        The default is false, and cannot be true unless the call is made on behalf of an AWS account that is the management account for an organization in AWS Organizations .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-isorganizationtrail
        '''
        result = self._values.get("is_organization_trail")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''Specifies the AWS KMS key ID to use to encrypt the logs delivered by CloudTrail.

        The value can be an alias name prefixed by "alias/", a fully specified ARN to an alias, a fully specified ARN to a key, or a globally unique identifier.

        CloudTrail also supports AWS KMS multi-Region keys. For more information about multi-Region keys, see `Using multi-Region keys <https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html>`_ in the *AWS Key Management Service Developer Guide* .

        Examples:

        - alias/MyAliasName
        - arn:aws:kms:us-east-2:123456789012:alias/MyAliasName
        - arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012
        - 12345678-1234-1234-1234-123456789012

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-kmskeyid
        '''
        result = self._values.get("kms_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def s3_key_prefix(self) -> typing.Optional[builtins.str]:
        '''Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery.

        For more information, see `Finding Your CloudTrail Log Files <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-find-log-files.html>`_ . The maximum length is 200 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-s3keyprefix
        '''
        result = self._values.get("s3_key_prefix")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def sns_topic_name(self) -> typing.Optional[builtins.str]:
        '''Specifies the name of the Amazon SNS topic defined for notification of log file delivery.

        The maximum length is 256 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-snstopicname
        '''
        result = self._values.get("sns_topic_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A custom set of tags (key-value pairs) for this trail.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def trail_name(self) -> typing.Optional[builtins.str]:
        '''Specifies the name of the trail. The name must meet the following requirements:.

        - Contain only ASCII letters (a-z, A-Z), numbers (0-9), periods (.), underscores (_), or dashes (-)
        - Start with a letter or number, and end with a letter or number
        - Be between 3 and 128 characters
        - Have no adjacent periods, underscores or dashes. Names like ``my-_namespace`` and ``my--namespace`` are not valid.
        - Not be in IP address format (for example, 192.168.5.4)

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-trailname
        '''
        result = self._values.get("trail_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnTrailProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_cloudtrail.DataResourceType")
class DataResourceType(enum.Enum):
    '''Resource type for a data event.'''

    LAMBDA_FUNCTION = "LAMBDA_FUNCTION"
    '''Data resource type for Lambda function.'''
    S3_OBJECT = "S3_OBJECT"
    '''Data resource type for S3 objects.'''


@jsii.enum(jsii_type="aws-cdk-lib.aws_cloudtrail.ManagementEventSources")
class ManagementEventSources(enum.Enum):
    '''Types of management event sources that can be excluded.'''

    KMS = "KMS"
    '''AWS Key Management Service (AWS KMS) events.'''
    RDS_DATA_API = "RDS_DATA_API"
    '''Data API events.'''


@jsii.enum(jsii_type="aws-cdk-lib.aws_cloudtrail.ReadWriteType")
class ReadWriteType(enum.Enum):
    '''Types of events that CloudTrail can log.

    :exampleMetadata: infused

    Example::

        trail = cloudtrail.Trail(self, "CloudTrail",
            # ...
            management_events=cloudtrail.ReadWriteType.READ_ONLY
        )
    '''

    READ_ONLY = "READ_ONLY"
    '''Read-only events include API operations that read your resources, but don't make changes.

    For example, read-only events include the Amazon EC2 DescribeSecurityGroups
    and DescribeSubnets API operations.
    '''
    WRITE_ONLY = "WRITE_ONLY"
    '''Write-only events include API operations that modify (or might modify) your resources.

    For example, the Amazon EC2 RunInstances and TerminateInstances API
    operations modify your instances.
    '''
    ALL = "ALL"
    '''All events.'''
    NONE = "NONE"
    '''No events.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cloudtrail.S3EventSelector",
    jsii_struct_bases=[],
    name_mapping={"bucket": "bucket", "object_prefix": "objectPrefix"},
)
class S3EventSelector:
    def __init__(
        self,
        *,
        bucket: _IBucket_42e086fd,
        object_prefix: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Selecting an S3 bucket and an optional prefix to be logged for data events.

        :param bucket: S3 bucket.
        :param object_prefix: Data events for objects whose key matches this prefix will be logged. Default: - all objects

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cloudtrail as cloudtrail
            from aws_cdk import aws_s3 as s3
            
            # bucket: s3.Bucket
            
            s3_event_selector = cloudtrail.S3EventSelector(
                bucket=bucket,
            
                # the properties below are optional
                object_prefix="objectPrefix"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "bucket": bucket,
        }
        if object_prefix is not None:
            self._values["object_prefix"] = object_prefix

    @builtins.property
    def bucket(self) -> _IBucket_42e086fd:
        '''S3 bucket.'''
        result = self._values.get("bucket")
        assert result is not None, "Required property 'bucket' is missing"
        return typing.cast(_IBucket_42e086fd, result)

    @builtins.property
    def object_prefix(self) -> typing.Optional[builtins.str]:
        '''Data events for objects whose key matches this prefix will be logged.

        :default: - all objects
        '''
        result = self._values.get("object_prefix")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "S3EventSelector(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class Trail(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cloudtrail.Trail",
):
    '''Cloud trail allows you to log events that happen in your AWS account For example:.

    import { CloudTrail } from '@aws-cdk/aws-cloudtrail'

    const cloudTrail = new CloudTrail(this, 'MyTrail');

    NOTE the above example creates an UNENCRYPTED bucket by default,
    If you are required to use an Encrypted bucket you can supply a preconfigured bucket
    via TrailProps

    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_cloudtrail as cloudtrail
        
        
        my_key_alias = kms.Alias.from_alias_name(self, "myKey", "alias/aws/s3")
        trail = cloudtrail.Trail(self, "myCloudTrail",
            send_to_cloud_watch_logs=True,
            kms_key=my_key_alias
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        bucket: typing.Optional[_IBucket_42e086fd] = None,
        cloud_watch_log_group: typing.Optional[_ILogGroup_3c4fa718] = None,
        cloud_watch_logs_retention: typing.Optional[_RetentionDays_070f99f0] = None,
        enable_file_validation: typing.Optional[builtins.bool] = None,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        include_global_service_events: typing.Optional[builtins.bool] = None,
        is_multi_region_trail: typing.Optional[builtins.bool] = None,
        management_events: typing.Optional[ReadWriteType] = None,
        s3_key_prefix: typing.Optional[builtins.str] = None,
        send_to_cloud_watch_logs: typing.Optional[builtins.bool] = None,
        sns_topic: typing.Optional[_ITopic_9eca4852] = None,
        trail_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param bucket: The Amazon S3 bucket. Default: - if not supplied a bucket will be created with all the correct permisions
        :param cloud_watch_log_group: Log Group to which CloudTrail to push logs to. Ignored if sendToCloudWatchLogs is set to false. Default: - a new log group is created and used.
        :param cloud_watch_logs_retention: How long to retain logs in CloudWatchLogs. Ignored if sendToCloudWatchLogs is false or if cloudWatchLogGroup is set. Default: logs.RetentionDays.ONE_YEAR
        :param enable_file_validation: To determine whether a log file was modified, deleted, or unchanged after CloudTrail delivered it, you can use CloudTrail log file integrity validation. This feature is built using industry standard algorithms: SHA-256 for hashing and SHA-256 with RSA for digital signing. This makes it computationally infeasible to modify, delete or forge CloudTrail log files without detection. You can use the AWS CLI to validate the files in the location where CloudTrail delivered them. Default: true
        :param encryption_key: The AWS Key Management Service (AWS KMS) key ID that you want to use to encrypt CloudTrail logs. Default: - No encryption.
        :param include_global_service_events: For most services, events are recorded in the region where the action occurred. For global services such as AWS Identity and Access Management (IAM), AWS STS, Amazon CloudFront, and Route 53, events are delivered to any trail that includes global services, and are logged as occurring in US East (N. Virginia) Region. Default: true
        :param is_multi_region_trail: Whether or not this trail delivers log files from multiple regions to a single S3 bucket for a single account. Default: true
        :param management_events: When an event occurs in your account, CloudTrail evaluates whether the event matches the settings for your trails. Only events that match your trail settings are delivered to your Amazon S3 bucket and Amazon CloudWatch Logs log group. This method sets the management configuration for this trail. Management events provide insight into management operations that are performed on resources in your AWS account. These are also known as control plane operations. Management events can also include non-API events that occur in your account. For example, when a user logs in to your account, CloudTrail logs the ConsoleLogin event. Default: ReadWriteType.ALL
        :param s3_key_prefix: An Amazon S3 object key prefix that precedes the name of all log files. Default: - No prefix.
        :param send_to_cloud_watch_logs: If CloudTrail pushes logs to CloudWatch Logs in addition to S3. Disabled for cost out of the box. Default: false
        :param sns_topic: SNS topic that is notified when new log files are published. Default: - No notifications.
        :param trail_name: The name of the trail. We recommend customers do not set an explicit name. Default: - AWS CloudFormation generated name.
        '''
        props = TrailProps(
            bucket=bucket,
            cloud_watch_log_group=cloud_watch_log_group,
            cloud_watch_logs_retention=cloud_watch_logs_retention,
            enable_file_validation=enable_file_validation,
            encryption_key=encryption_key,
            include_global_service_events=include_global_service_events,
            is_multi_region_trail=is_multi_region_trail,
            management_events=management_events,
            s3_key_prefix=s3_key_prefix,
            send_to_cloud_watch_logs=send_to_cloud_watch_logs,
            sns_topic=sns_topic,
            trail_name=trail_name,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="onEvent") # type: ignore[misc]
    @builtins.classmethod
    def on_event(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Create an event rule for when an event is recorded by any Trail in the account.

        Note that the event doesn't necessarily have to come from this Trail, it can
        be captured from any one.

        Be sure to filter the event further down using an event pattern.

        :param scope: -
        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.sinvoke(cls, "onEvent", [scope, id, options]))

    @jsii.member(jsii_name="addEventSelector")
    def add_event_selector(
        self,
        data_resource_type: DataResourceType,
        data_resource_values: typing.Sequence[builtins.str],
        *,
        exclude_management_event_sources: typing.Optional[typing.Sequence[ManagementEventSources]] = None,
        include_management_events: typing.Optional[builtins.bool] = None,
        read_write_type: typing.Optional[ReadWriteType] = None,
    ) -> None:
        '''When an event occurs in your account, CloudTrail evaluates whether the event matches the settings for your trails.

        Only events that match your trail settings are delivered to your Amazon S3 bucket and Amazon CloudWatch Logs log group.

        This method adds an Event Selector for filtering events that match either S3 or Lambda function operations.

        Data events: These events provide insight into the resource operations performed on or within a resource.
        These are also known as data plane operations.

        :param data_resource_type: -
        :param data_resource_values: the list of data resource ARNs to include in logging (maximum 250 entries).
        :param exclude_management_event_sources: An optional list of service event sources from which you do not want management events to be logged on your trail. Default: []
        :param include_management_events: Specifies whether the event selector includes management events for the trail. Default: true
        :param read_write_type: Specifies whether to log read-only events, write-only events, or all events. Default: ReadWriteType.All
        '''
        options = AddEventSelectorOptions(
            exclude_management_event_sources=exclude_management_event_sources,
            include_management_events=include_management_events,
            read_write_type=read_write_type,
        )

        return typing.cast(None, jsii.invoke(self, "addEventSelector", [data_resource_type, data_resource_values, options]))

    @jsii.member(jsii_name="addLambdaEventSelector")
    def add_lambda_event_selector(
        self,
        handlers: typing.Sequence[_IFunction_6adb0ab8],
        *,
        exclude_management_event_sources: typing.Optional[typing.Sequence[ManagementEventSources]] = None,
        include_management_events: typing.Optional[builtins.bool] = None,
        read_write_type: typing.Optional[ReadWriteType] = None,
    ) -> None:
        '''When an event occurs in your account, CloudTrail evaluates whether the event matches the settings for your trails.

        Only events that match your trail settings are delivered to your Amazon S3 bucket and Amazon CloudWatch Logs log group.

        This method adds a Lambda Data Event Selector for filtering events that match Lambda function operations.

        Data events: These events provide insight into the resource operations performed on or within a resource.
        These are also known as data plane operations.

        :param handlers: the list of lambda function handlers whose data events should be logged (maximum 250 entries).
        :param exclude_management_event_sources: An optional list of service event sources from which you do not want management events to be logged on your trail. Default: []
        :param include_management_events: Specifies whether the event selector includes management events for the trail. Default: true
        :param read_write_type: Specifies whether to log read-only events, write-only events, or all events. Default: ReadWriteType.All
        '''
        options = AddEventSelectorOptions(
            exclude_management_event_sources=exclude_management_event_sources,
            include_management_events=include_management_events,
            read_write_type=read_write_type,
        )

        return typing.cast(None, jsii.invoke(self, "addLambdaEventSelector", [handlers, options]))

    @jsii.member(jsii_name="addS3EventSelector")
    def add_s3_event_selector(
        self,
        s3_selector: typing.Sequence[S3EventSelector],
        *,
        exclude_management_event_sources: typing.Optional[typing.Sequence[ManagementEventSources]] = None,
        include_management_events: typing.Optional[builtins.bool] = None,
        read_write_type: typing.Optional[ReadWriteType] = None,
    ) -> None:
        '''When an event occurs in your account, CloudTrail evaluates whether the event matches the settings for your trails.

        Only events that match your trail settings are delivered to your Amazon S3 bucket and Amazon CloudWatch Logs log group.

        This method adds an S3 Data Event Selector for filtering events that match S3 operations.

        Data events: These events provide insight into the resource operations performed on or within a resource.
        These are also known as data plane operations.

        :param s3_selector: the list of S3 bucket with optional prefix to include in logging (maximum 250 entries).
        :param exclude_management_event_sources: An optional list of service event sources from which you do not want management events to be logged on your trail. Default: []
        :param include_management_events: Specifies whether the event selector includes management events for the trail. Default: true
        :param read_write_type: Specifies whether to log read-only events, write-only events, or all events. Default: ReadWriteType.All
        '''
        options = AddEventSelectorOptions(
            exclude_management_event_sources=exclude_management_event_sources,
            include_management_events=include_management_events,
            read_write_type=read_write_type,
        )

        return typing.cast(None, jsii.invoke(self, "addS3EventSelector", [s3_selector, options]))

    @jsii.member(jsii_name="logAllLambdaDataEvents")
    def log_all_lambda_data_events(
        self,
        *,
        exclude_management_event_sources: typing.Optional[typing.Sequence[ManagementEventSources]] = None,
        include_management_events: typing.Optional[builtins.bool] = None,
        read_write_type: typing.Optional[ReadWriteType] = None,
    ) -> None:
        '''Log all Lamda data events for all lambda functions the account.

        :param exclude_management_event_sources: An optional list of service event sources from which you do not want management events to be logged on your trail. Default: []
        :param include_management_events: Specifies whether the event selector includes management events for the trail. Default: true
        :param read_write_type: Specifies whether to log read-only events, write-only events, or all events. Default: ReadWriteType.All

        :default: false

        :see: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html
        '''
        options = AddEventSelectorOptions(
            exclude_management_event_sources=exclude_management_event_sources,
            include_management_events=include_management_events,
            read_write_type=read_write_type,
        )

        return typing.cast(None, jsii.invoke(self, "logAllLambdaDataEvents", [options]))

    @jsii.member(jsii_name="logAllS3DataEvents")
    def log_all_s3_data_events(
        self,
        *,
        exclude_management_event_sources: typing.Optional[typing.Sequence[ManagementEventSources]] = None,
        include_management_events: typing.Optional[builtins.bool] = None,
        read_write_type: typing.Optional[ReadWriteType] = None,
    ) -> None:
        '''Log all S3 data events for all objects for all buckets in the account.

        :param exclude_management_event_sources: An optional list of service event sources from which you do not want management events to be logged on your trail. Default: []
        :param include_management_events: Specifies whether the event selector includes management events for the trail. Default: true
        :param read_write_type: Specifies whether to log read-only events, write-only events, or all events. Default: ReadWriteType.All

        :default: false

        :see: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html
        '''
        options = AddEventSelectorOptions(
            exclude_management_event_sources=exclude_management_event_sources,
            include_management_events=include_management_events,
            read_write_type=read_write_type,
        )

        return typing.cast(None, jsii.invoke(self, "logAllS3DataEvents", [options]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="trailArn")
    def trail_arn(self) -> builtins.str:
        '''ARN of the CloudTrail trail i.e. arn:aws:cloudtrail:us-east-2:123456789012:trail/myCloudTrail.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "trailArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="trailSnsTopicArn")
    def trail_sns_topic_arn(self) -> builtins.str:
        '''ARN of the Amazon SNS topic that's associated with the CloudTrail trail, i.e. arn:aws:sns:us-east-2:123456789012:mySNSTopic.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "trailSnsTopicArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logGroup")
    def log_group(self) -> typing.Optional[_ILogGroup_3c4fa718]:
        '''The CloudWatch log group to which CloudTrail events are sent.

        ``undefined`` if ``sendToCloudWatchLogs`` property is false.
        '''
        return typing.cast(typing.Optional[_ILogGroup_3c4fa718], jsii.get(self, "logGroup"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cloudtrail.TrailProps",
    jsii_struct_bases=[],
    name_mapping={
        "bucket": "bucket",
        "cloud_watch_log_group": "cloudWatchLogGroup",
        "cloud_watch_logs_retention": "cloudWatchLogsRetention",
        "enable_file_validation": "enableFileValidation",
        "encryption_key": "encryptionKey",
        "include_global_service_events": "includeGlobalServiceEvents",
        "is_multi_region_trail": "isMultiRegionTrail",
        "management_events": "managementEvents",
        "s3_key_prefix": "s3KeyPrefix",
        "send_to_cloud_watch_logs": "sendToCloudWatchLogs",
        "sns_topic": "snsTopic",
        "trail_name": "trailName",
    },
)
class TrailProps:
    def __init__(
        self,
        *,
        bucket: typing.Optional[_IBucket_42e086fd] = None,
        cloud_watch_log_group: typing.Optional[_ILogGroup_3c4fa718] = None,
        cloud_watch_logs_retention: typing.Optional[_RetentionDays_070f99f0] = None,
        enable_file_validation: typing.Optional[builtins.bool] = None,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        include_global_service_events: typing.Optional[builtins.bool] = None,
        is_multi_region_trail: typing.Optional[builtins.bool] = None,
        management_events: typing.Optional[ReadWriteType] = None,
        s3_key_prefix: typing.Optional[builtins.str] = None,
        send_to_cloud_watch_logs: typing.Optional[builtins.bool] = None,
        sns_topic: typing.Optional[_ITopic_9eca4852] = None,
        trail_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for an AWS CloudTrail trail.

        :param bucket: The Amazon S3 bucket. Default: - if not supplied a bucket will be created with all the correct permisions
        :param cloud_watch_log_group: Log Group to which CloudTrail to push logs to. Ignored if sendToCloudWatchLogs is set to false. Default: - a new log group is created and used.
        :param cloud_watch_logs_retention: How long to retain logs in CloudWatchLogs. Ignored if sendToCloudWatchLogs is false or if cloudWatchLogGroup is set. Default: logs.RetentionDays.ONE_YEAR
        :param enable_file_validation: To determine whether a log file was modified, deleted, or unchanged after CloudTrail delivered it, you can use CloudTrail log file integrity validation. This feature is built using industry standard algorithms: SHA-256 for hashing and SHA-256 with RSA for digital signing. This makes it computationally infeasible to modify, delete or forge CloudTrail log files without detection. You can use the AWS CLI to validate the files in the location where CloudTrail delivered them. Default: true
        :param encryption_key: The AWS Key Management Service (AWS KMS) key ID that you want to use to encrypt CloudTrail logs. Default: - No encryption.
        :param include_global_service_events: For most services, events are recorded in the region where the action occurred. For global services such as AWS Identity and Access Management (IAM), AWS STS, Amazon CloudFront, and Route 53, events are delivered to any trail that includes global services, and are logged as occurring in US East (N. Virginia) Region. Default: true
        :param is_multi_region_trail: Whether or not this trail delivers log files from multiple regions to a single S3 bucket for a single account. Default: true
        :param management_events: When an event occurs in your account, CloudTrail evaluates whether the event matches the settings for your trails. Only events that match your trail settings are delivered to your Amazon S3 bucket and Amazon CloudWatch Logs log group. This method sets the management configuration for this trail. Management events provide insight into management operations that are performed on resources in your AWS account. These are also known as control plane operations. Management events can also include non-API events that occur in your account. For example, when a user logs in to your account, CloudTrail logs the ConsoleLogin event. Default: ReadWriteType.ALL
        :param s3_key_prefix: An Amazon S3 object key prefix that precedes the name of all log files. Default: - No prefix.
        :param send_to_cloud_watch_logs: If CloudTrail pushes logs to CloudWatch Logs in addition to S3. Disabled for cost out of the box. Default: false
        :param sns_topic: SNS topic that is notified when new log files are published. Default: - No notifications.
        :param trail_name: The name of the trail. We recommend customers do not set an explicit name. Default: - AWS CloudFormation generated name.

        :exampleMetadata: infused

        Example::

            trail = cloudtrail.Trail(self, "CloudTrail",
                # ...
                management_events=cloudtrail.ReadWriteType.READ_ONLY
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if bucket is not None:
            self._values["bucket"] = bucket
        if cloud_watch_log_group is not None:
            self._values["cloud_watch_log_group"] = cloud_watch_log_group
        if cloud_watch_logs_retention is not None:
            self._values["cloud_watch_logs_retention"] = cloud_watch_logs_retention
        if enable_file_validation is not None:
            self._values["enable_file_validation"] = enable_file_validation
        if encryption_key is not None:
            self._values["encryption_key"] = encryption_key
        if include_global_service_events is not None:
            self._values["include_global_service_events"] = include_global_service_events
        if is_multi_region_trail is not None:
            self._values["is_multi_region_trail"] = is_multi_region_trail
        if management_events is not None:
            self._values["management_events"] = management_events
        if s3_key_prefix is not None:
            self._values["s3_key_prefix"] = s3_key_prefix
        if send_to_cloud_watch_logs is not None:
            self._values["send_to_cloud_watch_logs"] = send_to_cloud_watch_logs
        if sns_topic is not None:
            self._values["sns_topic"] = sns_topic
        if trail_name is not None:
            self._values["trail_name"] = trail_name

    @builtins.property
    def bucket(self) -> typing.Optional[_IBucket_42e086fd]:
        '''The Amazon S3 bucket.

        :default: - if not supplied a bucket will be created with all the correct permisions
        '''
        result = self._values.get("bucket")
        return typing.cast(typing.Optional[_IBucket_42e086fd], result)

    @builtins.property
    def cloud_watch_log_group(self) -> typing.Optional[_ILogGroup_3c4fa718]:
        '''Log Group to which CloudTrail to push logs to.

        Ignored if sendToCloudWatchLogs is set to false.

        :default: - a new log group is created and used.
        '''
        result = self._values.get("cloud_watch_log_group")
        return typing.cast(typing.Optional[_ILogGroup_3c4fa718], result)

    @builtins.property
    def cloud_watch_logs_retention(self) -> typing.Optional[_RetentionDays_070f99f0]:
        '''How long to retain logs in CloudWatchLogs.

        Ignored if sendToCloudWatchLogs is false or if cloudWatchLogGroup is set.

        :default: logs.RetentionDays.ONE_YEAR
        '''
        result = self._values.get("cloud_watch_logs_retention")
        return typing.cast(typing.Optional[_RetentionDays_070f99f0], result)

    @builtins.property
    def enable_file_validation(self) -> typing.Optional[builtins.bool]:
        '''To determine whether a log file was modified, deleted, or unchanged after CloudTrail delivered it, you can use CloudTrail log file integrity validation.

        This feature is built using industry standard algorithms: SHA-256 for hashing and SHA-256 with RSA for digital signing.
        This makes it computationally infeasible to modify, delete or forge CloudTrail log files without detection.
        You can use the AWS CLI to validate the files in the location where CloudTrail delivered them.

        :default: true
        '''
        result = self._values.get("enable_file_validation")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''The AWS Key Management Service (AWS KMS) key ID that you want to use to encrypt CloudTrail logs.

        :default: - No encryption.
        '''
        result = self._values.get("encryption_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def include_global_service_events(self) -> typing.Optional[builtins.bool]:
        '''For most services, events are recorded in the region where the action occurred.

        For global services such as AWS Identity and Access Management (IAM), AWS STS, Amazon CloudFront, and Route 53,
        events are delivered to any trail that includes global services, and are logged as occurring in US East (N. Virginia) Region.

        :default: true
        '''
        result = self._values.get("include_global_service_events")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def is_multi_region_trail(self) -> typing.Optional[builtins.bool]:
        '''Whether or not this trail delivers log files from multiple regions to a single S3 bucket for a single account.

        :default: true
        '''
        result = self._values.get("is_multi_region_trail")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def management_events(self) -> typing.Optional[ReadWriteType]:
        '''When an event occurs in your account, CloudTrail evaluates whether the event matches the settings for your trails.

        Only events that match your trail settings are delivered to your Amazon S3 bucket and Amazon CloudWatch Logs log group.

        This method sets the management configuration for this trail.

        Management events provide insight into management operations that are performed on resources in your AWS account.
        These are also known as control plane operations.
        Management events can also include non-API events that occur in your account.
        For example, when a user logs in to your account, CloudTrail logs the ConsoleLogin event.

        :default: ReadWriteType.ALL
        '''
        result = self._values.get("management_events")
        return typing.cast(typing.Optional[ReadWriteType], result)

    @builtins.property
    def s3_key_prefix(self) -> typing.Optional[builtins.str]:
        '''An Amazon S3 object key prefix that precedes the name of all log files.

        :default: - No prefix.
        '''
        result = self._values.get("s3_key_prefix")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def send_to_cloud_watch_logs(self) -> typing.Optional[builtins.bool]:
        '''If CloudTrail pushes logs to CloudWatch Logs in addition to S3.

        Disabled for cost out of the box.

        :default: false
        '''
        result = self._values.get("send_to_cloud_watch_logs")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def sns_topic(self) -> typing.Optional[_ITopic_9eca4852]:
        '''SNS topic that is notified when new log files are published.

        :default: - No notifications.
        '''
        result = self._values.get("sns_topic")
        return typing.cast(typing.Optional[_ITopic_9eca4852], result)

    @builtins.property
    def trail_name(self) -> typing.Optional[builtins.str]:
        '''The name of the trail.

        We recommend customers do not set an explicit name.

        :default: - AWS CloudFormation generated name.
        '''
        result = self._values.get("trail_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "TrailProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "AddEventSelectorOptions",
    "CfnTrail",
    "CfnTrailProps",
    "DataResourceType",
    "ManagementEventSources",
    "ReadWriteType",
    "S3EventSelector",
    "Trail",
    "TrailProps",
]

publication.publish()
