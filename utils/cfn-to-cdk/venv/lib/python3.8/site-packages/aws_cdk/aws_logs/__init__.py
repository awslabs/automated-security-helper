'''
# Amazon CloudWatch Logs Construct Library

This library supplies constructs for working with CloudWatch Logs.

## Log Groups/Streams

The basic unit of CloudWatch is a *Log Group*. Every log group typically has the
same kind of data logged to it, in the same format. If there are multiple
applications or services logging into the Log Group, each of them creates a new
*Log Stream*.

Every log operation creates a "log event", which can consist of a simple string
or a single-line JSON object. JSON objects have the advantage that they afford
more filtering abilities (see below).

The only configurable attribute for log streams is the retention period, which
configures after how much time the events in the log stream expire and are
deleted.

The default retention period if not supplied is 2 years, but it can be set to
one of the values in the `RetentionDays` enum to configure a different
retention period (including infinite retention).

```python
# Configure log group for short retention
log_group = LogGroup(stack, "LogGroup",
    retention=RetentionDays.ONE_WEEK
)# Configure log group for infinite retention
log_group = LogGroup(stack, "LogGroup",
    retention=Infinity
)
```

## LogRetention

The `LogRetention` construct is a way to control the retention period of log groups that are created outside of the CDK. The construct is usually
used on log groups that are auto created by AWS services, such as [AWS
lambda](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs.html).

This is implemented using a [CloudFormation custom
resource](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cfn-customresource.html)
which pre-creates the log group if it doesn't exist, and sets the specified log retention period (never expire, by default).

By default, the log group will be created in the same region as the stack. The `logGroupRegion` property can be used to configure
log groups in other regions. This is typically useful when controlling retention for log groups auto-created by global services that
publish their log group to a specific region, such as AWS Chatbot creating a log group in `us-east-1`.

## Resource Policy

CloudWatch Resource Policies allow other AWS services or IAM Principals to put log events into the log groups.
A resource policy is automatically created when `addToResourcePolicy` is called on the LogGroup for the first time:

```python
log_group = logs.LogGroup(self, "LogGroup")
log_group.add_to_resource_policy(iam.PolicyStatement(
    actions=["logs:CreateLogStream", "logs:PutLogEvents"],
    principals=[iam.ServicePrincipal("es.amazonaws.com")],
    resources=[log_group.log_group_arn]
))
```

Or more conveniently, write permissions to the log group can be granted as follows which gives same result as in the above example.

```python
log_group = logs.LogGroup(self, "LogGroup")
log_group.grant_write(iam.ServicePrincipal("es.amazonaws.com"))
```

## Encrypting Log Groups

By default, log group data is always encrypted in CloudWatch Logs. You have the
option to encrypt log group data using a AWS KMS customer master key (CMK) should
you not wish to use the default AWS encryption. Keep in mind that if you decide to
encrypt a log group, any service or IAM identity that needs to read the encrypted
log streams in the future will require the same CMK to decrypt the data.

Here's a simple example of creating an encrypted Log Group using a KMS CMK.

```python
import aws_cdk.aws_kms as kms


logs.LogGroup(self, "LogGroup",
    encryption_key=kms.Key(self, "Key")
)
```

See the AWS documentation for more detailed information about [encrypting CloudWatch
Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html).

## Subscriptions and Destinations

Log events matching a particular filter can be sent to either a Lambda function
or a Kinesis stream.

If the Kinesis stream lives in a different account, a `CrossAccountDestination`
object needs to be added in the destination account which will act as a proxy
for the remote Kinesis stream. This object is automatically created for you
if you use the CDK Kinesis library.

Create a `SubscriptionFilter`, initialize it with an appropriate `Pattern` (see
below) and supply the intended destination:

```python
import aws_cdk.aws_logs_destinations as destinations
# fn: lambda.Function
# log_group: logs.LogGroup


logs.SubscriptionFilter(self, "Subscription",
    log_group=log_group,
    destination=destinations.LambdaDestination(fn),
    filter_pattern=logs.FilterPattern.all_terms("ERROR", "MainThread")
)
```

## Metric Filters

CloudWatch Logs can extract and emit metrics based on a textual log stream.
Depending on your needs, this may be a more convenient way of generating metrics
for you application than making calls to CloudWatch Metrics yourself.

A `MetricFilter` either emits a fixed number every time it sees a log event
matching a particular pattern (see below), or extracts a number from the log
event and uses that as the metric value.

Example:

```python
MetricFilter(self, "MetricFilter",
    log_group=log_group,
    metric_namespace="MyApp",
    metric_name="Latency",
    filter_pattern=FilterPattern.exists("$.latency"),
    metric_value="$.latency"
)
```

Remember that if you want to use a value from the log event as the metric value,
you must mention it in your pattern somewhere.

A very simple MetricFilter can be created by using the `logGroup.extractMetric()`
helper function:

```python
# log_group: logs.LogGroup

log_group.extract_metric("$.jsonField", "Namespace", "MetricName")
```

Will extract the value of `jsonField` wherever it occurs in JSON-structed
log records in the LogGroup, and emit them to CloudWatch Metrics under
the name `Namespace/MetricName`.

### Exposing Metric on a Metric Filter

You can expose a metric on a metric filter by calling the `MetricFilter.metric()` API.
This has a default of `statistic = 'avg'` if the statistic is not set in the `props`.

```python
# log_group: logs.LogGroup

mf = logs.MetricFilter(self, "MetricFilter",
    log_group=log_group,
    metric_namespace="MyApp",
    metric_name="Latency",
    filter_pattern=logs.FilterPattern.exists("$.latency"),
    metric_value="$.latency"
)

# expose a metric from the metric filter
metric = mf.metric()

# you can use the metric to create a new alarm
cloudwatch.Alarm(self, "alarm from metric filter",
    metric=metric,
    threshold=100,
    evaluation_periods=2
)
```

## Patterns

Patterns describe which log events match a subscription or metric filter. There
are three types of patterns:

* Text patterns
* JSON patterns
* Space-delimited table patterns

All patterns are constructed by using static functions on the `FilterPattern`
class.

In addition to the patterns above, the following special patterns exist:

* `FilterPattern.allEvents()`: matches all log events.
* `FilterPattern.literal(string)`: if you already know what pattern expression to
  use, this function takes a string and will use that as the log pattern. For
  more information, see the [Filter and Pattern
  Syntax](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html).

### Text Patterns

Text patterns match if the literal strings appear in the text form of the log
line.

* `FilterPattern.allTerms(term, term, ...)`: matches if all of the given terms
  (substrings) appear in the log event.
* `FilterPattern.anyTerm(term, term, ...)`: matches if all of the given terms
  (substrings) appear in the log event.
* `FilterPattern.anyTermGroup([term, term, ...], [term, term, ...], ...)`: matches if
  all of the terms in any of the groups (specified as arrays) matches. This is
  an OR match.

Examples:

```python
# Search for lines that contain both "ERROR" and "MainThread"
pattern1 = logs.FilterPattern.all_terms("ERROR", "MainThread")

# Search for lines that either contain both "ERROR" and "MainThread", or
# both "WARN" and "Deadlock".
pattern2 = logs.FilterPattern.any_term_group(["ERROR", "MainThread"], ["WARN", "Deadlock"])
```

## JSON Patterns

JSON patterns apply if the log event is the JSON representation of an object
(without any other characters, so it cannot include a prefix such as timestamp
or log level). JSON patterns can make comparisons on the values inside the
fields.

* **Strings**: the comparison operators allowed for strings are `=` and `!=`.
  String values can start or end with a `*` wildcard.
* **Numbers**: the comparison operators allowed for numbers are `=`, `!=`,
  `<`, `<=`, `>`, `>=`.

Fields in the JSON structure are identified by identifier the complete object as `$`
and then descending into it, such as `$.field` or `$.list[0].field`.

* `FilterPattern.stringValue(field, comparison, string)`: matches if the given
  field compares as indicated with the given string value.
* `FilterPattern.numberValue(field, comparison, number)`: matches if the given
  field compares as indicated with the given numerical value.
* `FilterPattern.isNull(field)`: matches if the given field exists and has the
  value `null`.
* `FilterPattern.notExists(field)`: matches if the given field is not in the JSON
  structure.
* `FilterPattern.exists(field)`: matches if the given field is in the JSON
  structure.
* `FilterPattern.booleanValue(field, boolean)`: matches if the given field
  is exactly the given boolean value.
* `FilterPattern.all(jsonPattern, jsonPattern, ...)`: matches if all of the
  given JSON patterns match. This makes an AND combination of the given
  patterns.
* `FilterPattern.any(jsonPattern, jsonPattern, ...)`: matches if any of the
  given JSON patterns match. This makes an OR combination of the given
  patterns.

Example:

```python
# Search for all events where the component field is equal to
# "HttpServer" and either error is true or the latency is higher
# than 1000.
pattern = logs.FilterPattern.all(
    logs.FilterPattern.string_value("$.component", "=", "HttpServer"),
    logs.FilterPattern.any(
        logs.FilterPattern.boolean_value("$.error", True),
        logs.FilterPattern.number_value("$.latency", ">", 1000)))
```

## Space-delimited table patterns

If the log events are rows of a space-delimited table, this pattern can be used
to identify the columns in that structure and add conditions on any of them. The
canonical example where you would apply this type of pattern is Apache server
logs.

Text that is surrounded by `"..."` quotes or `[...]` square brackets will
be treated as one column.

* `FilterPattern.spaceDelimited(column, column, ...)`: construct a
  `SpaceDelimitedTextPattern` object with the indicated columns. The columns
  map one-by-one the columns found in the log event. The string `"..."` may
  be used to specify an arbitrary number of unnamed columns anywhere in the
  name list (but may only be specified once).

After constructing a `SpaceDelimitedTextPattern`, you can use the following
two members to add restrictions:

* `pattern.whereString(field, comparison, string)`: add a string condition.
  The rules are the same as for JSON patterns.
* `pattern.whereNumber(field, comparison, number)`: add a numerical condition.
  The rules are the same as for JSON patterns.

Multiple restrictions can be added on the same column; they must all apply.

Example:

```python
# Search for all events where the component is "HttpServer" and the
# result code is not equal to 200.
pattern = logs.FilterPattern.space_delimited("time", "component", "...", "result_code", "latency").where_string("component", "=", "HttpServer").where_number("result_code", "!=", 200)
```

## Notes

Be aware that Log Group ARNs will always have the string `:*` appended to
them, to match the behavior of [the CloudFormation `AWS::Logs::LogGroup`
resource](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html#aws-resource-logs-loggroup-return-values).
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
    Duration as _Duration_4839e8c3,
    IInspectable as _IInspectable_c2943556,
    IResolvable as _IResolvable_da3f097b,
    IResource as _IResource_c80c4260,
    RemovalPolicy as _RemovalPolicy_9f93c814,
    Resource as _Resource_45bc6135,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_cloudwatch import (
    Metric as _Metric_e396a4dc,
    MetricOptions as _MetricOptions_1788b62f,
    Unit as _Unit_61bc6f70,
)
from ..aws_iam import (
    AddToResourcePolicyResult as _AddToResourcePolicyResult_1d0a53ad,
    Grant as _Grant_a7ae64f8,
    IGrantable as _IGrantable_71c4f5de,
    IResourceWithPolicy as _IResourceWithPolicy_720d64fc,
    IRole as _IRole_235f5d8e,
    PolicyDocument as _PolicyDocument_3ac34393,
    PolicyStatement as _PolicyStatement_0fe33853,
)
from ..aws_kms import IKey as _IKey_5f11635f


@jsii.implements(_IInspectable_c2943556)
class CfnDestination(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.CfnDestination",
):
    '''A CloudFormation ``AWS::Logs::Destination``.

    The AWS::Logs::Destination resource specifies a CloudWatch Logs destination. A destination encapsulates a physical resource (such as an Amazon Kinesis data stream) and enables you to subscribe that resource to a stream of log events.

    :cloudformationResource: AWS::Logs::Destination
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-destination.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_logs as logs
        
        cfn_destination = logs.CfnDestination(self, "MyCfnDestination",
            destination_name="destinationName",
            destination_policy="destinationPolicy",
            role_arn="roleArn",
            target_arn="targetArn"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        destination_name: builtins.str,
        destination_policy: builtins.str,
        role_arn: builtins.str,
        target_arn: builtins.str,
    ) -> None:
        '''Create a new ``AWS::Logs::Destination``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param destination_name: The name of the destination.
        :param destination_policy: An IAM policy document that governs which AWS accounts can create subscription filters against this destination.
        :param role_arn: The ARN of an IAM role that permits CloudWatch Logs to send data to the specified AWS resource.
        :param target_arn: The Amazon Resource Name (ARN) of the physical target where the log events are delivered (for example, a Kinesis stream).
        '''
        props = CfnDestinationProps(
            destination_name=destination_name,
            destination_policy=destination_policy,
            role_arn=role_arn,
            target_arn=target_arn,
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
        '''The ARN of the CloudWatch Logs destination, such as ``arn:aws:logs:us-west-1:123456789012:destination:MyDestination`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="destinationName")
    def destination_name(self) -> builtins.str:
        '''The name of the destination.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-destination.html#cfn-logs-destination-destinationname
        '''
        return typing.cast(builtins.str, jsii.get(self, "destinationName"))

    @destination_name.setter
    def destination_name(self, value: builtins.str) -> None:
        jsii.set(self, "destinationName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="destinationPolicy")
    def destination_policy(self) -> builtins.str:
        '''An IAM policy document that governs which AWS accounts can create subscription filters against this destination.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-destination.html#cfn-logs-destination-destinationpolicy
        '''
        return typing.cast(builtins.str, jsii.get(self, "destinationPolicy"))

    @destination_policy.setter
    def destination_policy(self, value: builtins.str) -> None:
        jsii.set(self, "destinationPolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''The ARN of an IAM role that permits CloudWatch Logs to send data to the specified AWS resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-destination.html#cfn-logs-destination-rolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "roleArn"))

    @role_arn.setter
    def role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "roleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetArn")
    def target_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the physical target where the log events are delivered (for example, a Kinesis stream).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-destination.html#cfn-logs-destination-targetarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "targetArn"))

    @target_arn.setter
    def target_arn(self, value: builtins.str) -> None:
        jsii.set(self, "targetArn", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.CfnDestinationProps",
    jsii_struct_bases=[],
    name_mapping={
        "destination_name": "destinationName",
        "destination_policy": "destinationPolicy",
        "role_arn": "roleArn",
        "target_arn": "targetArn",
    },
)
class CfnDestinationProps:
    def __init__(
        self,
        *,
        destination_name: builtins.str,
        destination_policy: builtins.str,
        role_arn: builtins.str,
        target_arn: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnDestination``.

        :param destination_name: The name of the destination.
        :param destination_policy: An IAM policy document that governs which AWS accounts can create subscription filters against this destination.
        :param role_arn: The ARN of an IAM role that permits CloudWatch Logs to send data to the specified AWS resource.
        :param target_arn: The Amazon Resource Name (ARN) of the physical target where the log events are delivered (for example, a Kinesis stream).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-destination.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_logs as logs
            
            cfn_destination_props = logs.CfnDestinationProps(
                destination_name="destinationName",
                destination_policy="destinationPolicy",
                role_arn="roleArn",
                target_arn="targetArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "destination_name": destination_name,
            "destination_policy": destination_policy,
            "role_arn": role_arn,
            "target_arn": target_arn,
        }

    @builtins.property
    def destination_name(self) -> builtins.str:
        '''The name of the destination.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-destination.html#cfn-logs-destination-destinationname
        '''
        result = self._values.get("destination_name")
        assert result is not None, "Required property 'destination_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def destination_policy(self) -> builtins.str:
        '''An IAM policy document that governs which AWS accounts can create subscription filters against this destination.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-destination.html#cfn-logs-destination-destinationpolicy
        '''
        result = self._values.get("destination_policy")
        assert result is not None, "Required property 'destination_policy' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def role_arn(self) -> builtins.str:
        '''The ARN of an IAM role that permits CloudWatch Logs to send data to the specified AWS resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-destination.html#cfn-logs-destination-rolearn
        '''
        result = self._values.get("role_arn")
        assert result is not None, "Required property 'role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def target_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the physical target where the log events are delivered (for example, a Kinesis stream).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-destination.html#cfn-logs-destination-targetarn
        '''
        result = self._values.get("target_arn")
        assert result is not None, "Required property 'target_arn' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDestinationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnLogGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.CfnLogGroup",
):
    '''A CloudFormation ``AWS::Logs::LogGroup``.

    The ``AWS::Logs::LogGroup`` resource specifies a log group. A log group defines common properties for log streams, such as their retention and access control rules. Each log stream must belong to one log group.

    You can create up to 1,000,000 log groups per Region per account. You must use the following guidelines when naming a log group:

    - Log group names must be unique within a Region for an AWS account.
    - Log group names can be between 1 and 512 characters long.
    - Log group names consist of the following characters: a-z, A-Z, 0-9, '_' (underscore), '-' (hyphen), '/' (forward slash), and '.' (period).

    :cloudformationResource: AWS::Logs::LogGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_logs as logs
        
        cfn_log_group = logs.CfnLogGroup(self, "MyCfnLogGroup",
            kms_key_id="kmsKeyId",
            log_group_name="logGroupName",
            retention_in_days=123,
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
        kms_key_id: typing.Optional[builtins.str] = None,
        log_group_name: typing.Optional[builtins.str] = None,
        retention_in_days: typing.Optional[jsii.Number] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Logs::LogGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param kms_key_id: The Amazon Resource Name (ARN) of the AWS KMS key to use when encrypting log data. To associate an AWS KMS key with the log group, specify the ARN of that KMS key here. If you do so, ingested data is encrypted using this key. This association is stored as long as the data encrypted with the KMS key is still within CloudWatch Logs . This enables CloudWatch Logs to decrypt this data whenever it is requested. If you attempt to associate a KMS key with the log group but the KMS key doesn't exist or is deactivated, you will receive an ``InvalidParameterException`` error. Log group data is always encrypted in CloudWatch Logs . If you omit this key, the encryption does not use AWS KMS . For more information, see `Encrypt log data in CloudWatch Logs using AWS Key Management Service <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html>`_
        :param log_group_name: The name of the log group. If you don't specify a name, AWS CloudFormation generates a unique ID for the log group.
        :param retention_in_days: The number of days to retain the log events in the specified log group. Possible values are: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, and 3653. To set a log group to never have log events expire, use `DeleteRetentionPolicy <https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DeleteRetentionPolicy.html>`_ .
        :param tags: An array of key-value pairs to apply to the log group. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnLogGroupProps(
            kms_key_id=kms_key_id,
            log_group_name=log_group_name,
            retention_in_days=retention_in_days,
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
        '''The ARN of the log group, such as ``arn:aws:logs:us-west-1:123456789012:log-group:/mystack-testgroup-12ABC1AB12A1:*``.

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
        '''An array of key-value pairs to apply to the log group.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html#cfn-logs-loggroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKeyId")
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the AWS KMS key to use when encrypting log data.

        To associate an AWS KMS key with the log group, specify the ARN of that KMS key here. If you do so, ingested data is encrypted using this key. This association is stored as long as the data encrypted with the KMS key is still within CloudWatch Logs . This enables CloudWatch Logs to decrypt this data whenever it is requested.

        If you attempt to associate a KMS key with the log group but the KMS key doesn't exist or is deactivated, you will receive an ``InvalidParameterException`` error.

        Log group data is always encrypted in CloudWatch Logs . If you omit this key, the encryption does not use AWS KMS . For more information, see `Encrypt log data in CloudWatch Logs using AWS Key Management Service <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html>`_

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html#cfn-logs-loggroup-kmskeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKeyId"))

    @kms_key_id.setter
    def kms_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKeyId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logGroupName")
    def log_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the log group.

        If you don't specify a name, AWS CloudFormation generates a unique ID for the log group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html#cfn-logs-loggroup-loggroupname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "logGroupName"))

    @log_group_name.setter
    def log_group_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "logGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="retentionInDays")
    def retention_in_days(self) -> typing.Optional[jsii.Number]:
        '''The number of days to retain the log events in the specified log group.

        Possible values are: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, and 3653.

        To set a log group to never have log events expire, use `DeleteRetentionPolicy <https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DeleteRetentionPolicy.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html#cfn-logs-loggroup-retentionindays
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "retentionInDays"))

    @retention_in_days.setter
    def retention_in_days(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "retentionInDays", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.CfnLogGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "kms_key_id": "kmsKeyId",
        "log_group_name": "logGroupName",
        "retention_in_days": "retentionInDays",
        "tags": "tags",
    },
)
class CfnLogGroupProps:
    def __init__(
        self,
        *,
        kms_key_id: typing.Optional[builtins.str] = None,
        log_group_name: typing.Optional[builtins.str] = None,
        retention_in_days: typing.Optional[jsii.Number] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnLogGroup``.

        :param kms_key_id: The Amazon Resource Name (ARN) of the AWS KMS key to use when encrypting log data. To associate an AWS KMS key with the log group, specify the ARN of that KMS key here. If you do so, ingested data is encrypted using this key. This association is stored as long as the data encrypted with the KMS key is still within CloudWatch Logs . This enables CloudWatch Logs to decrypt this data whenever it is requested. If you attempt to associate a KMS key with the log group but the KMS key doesn't exist or is deactivated, you will receive an ``InvalidParameterException`` error. Log group data is always encrypted in CloudWatch Logs . If you omit this key, the encryption does not use AWS KMS . For more information, see `Encrypt log data in CloudWatch Logs using AWS Key Management Service <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html>`_
        :param log_group_name: The name of the log group. If you don't specify a name, AWS CloudFormation generates a unique ID for the log group.
        :param retention_in_days: The number of days to retain the log events in the specified log group. Possible values are: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, and 3653. To set a log group to never have log events expire, use `DeleteRetentionPolicy <https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DeleteRetentionPolicy.html>`_ .
        :param tags: An array of key-value pairs to apply to the log group. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_logs as logs
            
            cfn_log_group_props = logs.CfnLogGroupProps(
                kms_key_id="kmsKeyId",
                log_group_name="logGroupName",
                retention_in_days=123,
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if kms_key_id is not None:
            self._values["kms_key_id"] = kms_key_id
        if log_group_name is not None:
            self._values["log_group_name"] = log_group_name
        if retention_in_days is not None:
            self._values["retention_in_days"] = retention_in_days
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the AWS KMS key to use when encrypting log data.

        To associate an AWS KMS key with the log group, specify the ARN of that KMS key here. If you do so, ingested data is encrypted using this key. This association is stored as long as the data encrypted with the KMS key is still within CloudWatch Logs . This enables CloudWatch Logs to decrypt this data whenever it is requested.

        If you attempt to associate a KMS key with the log group but the KMS key doesn't exist or is deactivated, you will receive an ``InvalidParameterException`` error.

        Log group data is always encrypted in CloudWatch Logs . If you omit this key, the encryption does not use AWS KMS . For more information, see `Encrypt log data in CloudWatch Logs using AWS Key Management Service <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html>`_

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html#cfn-logs-loggroup-kmskeyid
        '''
        result = self._values.get("kms_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def log_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the log group.

        If you don't specify a name, AWS CloudFormation generates a unique ID for the log group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html#cfn-logs-loggroup-loggroupname
        '''
        result = self._values.get("log_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def retention_in_days(self) -> typing.Optional[jsii.Number]:
        '''The number of days to retain the log events in the specified log group.

        Possible values are: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, and 3653.

        To set a log group to never have log events expire, use `DeleteRetentionPolicy <https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DeleteRetentionPolicy.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html#cfn-logs-loggroup-retentionindays
        '''
        result = self._values.get("retention_in_days")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An array of key-value pairs to apply to the log group.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html#cfn-logs-loggroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnLogGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnLogStream(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.CfnLogStream",
):
    '''A CloudFormation ``AWS::Logs::LogStream``.

    The ``AWS::Logs::LogStream`` resource specifies an Amazon CloudWatch Logs log stream in a specific log group. A log stream represents the sequence of events coming from an application instance or resource that you are monitoring.

    There is no limit on the number of log streams that you can create for a log group.

    You must use the following guidelines when naming a log stream:

    - Log stream names must be unique within the log group.
    - Log stream names can be between 1 and 512 characters long.
    - The ':' (colon) and '*' (asterisk) characters are not allowed.

    :cloudformationResource: AWS::Logs::LogStream
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-logstream.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_logs as logs
        
        cfn_log_stream = logs.CfnLogStream(self, "MyCfnLogStream",
            log_group_name="logGroupName",
        
            # the properties below are optional
            log_stream_name="logStreamName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        log_group_name: builtins.str,
        log_stream_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Logs::LogStream``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param log_group_name: The name of the log group where the log stream is created.
        :param log_stream_name: The name of the log stream. The name must be unique within the log group.
        '''
        props = CfnLogStreamProps(
            log_group_name=log_group_name, log_stream_name=log_stream_name
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
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logGroupName")
    def log_group_name(self) -> builtins.str:
        '''The name of the log group where the log stream is created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-logstream.html#cfn-logs-logstream-loggroupname
        '''
        return typing.cast(builtins.str, jsii.get(self, "logGroupName"))

    @log_group_name.setter
    def log_group_name(self, value: builtins.str) -> None:
        jsii.set(self, "logGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logStreamName")
    def log_stream_name(self) -> typing.Optional[builtins.str]:
        '''The name of the log stream.

        The name must be unique within the log group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-logstream.html#cfn-logs-logstream-logstreamname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "logStreamName"))

    @log_stream_name.setter
    def log_stream_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "logStreamName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.CfnLogStreamProps",
    jsii_struct_bases=[],
    name_mapping={
        "log_group_name": "logGroupName",
        "log_stream_name": "logStreamName",
    },
)
class CfnLogStreamProps:
    def __init__(
        self,
        *,
        log_group_name: builtins.str,
        log_stream_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnLogStream``.

        :param log_group_name: The name of the log group where the log stream is created.
        :param log_stream_name: The name of the log stream. The name must be unique within the log group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-logstream.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_logs as logs
            
            cfn_log_stream_props = logs.CfnLogStreamProps(
                log_group_name="logGroupName",
            
                # the properties below are optional
                log_stream_name="logStreamName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "log_group_name": log_group_name,
        }
        if log_stream_name is not None:
            self._values["log_stream_name"] = log_stream_name

    @builtins.property
    def log_group_name(self) -> builtins.str:
        '''The name of the log group where the log stream is created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-logstream.html#cfn-logs-logstream-loggroupname
        '''
        result = self._values.get("log_group_name")
        assert result is not None, "Required property 'log_group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def log_stream_name(self) -> typing.Optional[builtins.str]:
        '''The name of the log stream.

        The name must be unique within the log group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-logstream.html#cfn-logs-logstream-logstreamname
        '''
        result = self._values.get("log_stream_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnLogStreamProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnMetricFilter(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.CfnMetricFilter",
):
    '''A CloudFormation ``AWS::Logs::MetricFilter``.

    The ``AWS::Logs::MetricFilter`` resource specifies a metric filter that describes how CloudWatch Logs extracts information from logs and transforms it into Amazon CloudWatch metrics. If you have multiple metric filters that are associated with a log group, all the filters are applied to the log streams in that group.

    The maximum number of metric filters that can be associated with a log group is 100.

    :cloudformationResource: AWS::Logs::MetricFilter
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-metricfilter.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_logs as logs
        
        cfn_metric_filter = logs.CfnMetricFilter(self, "MyCfnMetricFilter",
            filter_pattern="filterPattern",
            log_group_name="logGroupName",
            metric_transformations=[logs.CfnMetricFilter.MetricTransformationProperty(
                metric_name="metricName",
                metric_namespace="metricNamespace",
                metric_value="metricValue",
        
                # the properties below are optional
                default_value=123
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        filter_pattern: builtins.str,
        log_group_name: builtins.str,
        metric_transformations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnMetricFilter.MetricTransformationProperty", _IResolvable_da3f097b]]],
    ) -> None:
        '''Create a new ``AWS::Logs::MetricFilter``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param filter_pattern: A filter pattern for extracting metric data out of ingested log events. For more information, see `Filter and Pattern Syntax <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html>`_ .
        :param log_group_name: The name of an existing log group that you want to associate with this metric filter.
        :param metric_transformations: The metric transformations.
        '''
        props = CfnMetricFilterProps(
            filter_pattern=filter_pattern,
            log_group_name=log_group_name,
            metric_transformations=metric_transformations,
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
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="filterPattern")
    def filter_pattern(self) -> builtins.str:
        '''A filter pattern for extracting metric data out of ingested log events.

        For more information, see `Filter and Pattern Syntax <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-metricfilter.html#cfn-cwl-metricfilter-filterpattern
        '''
        return typing.cast(builtins.str, jsii.get(self, "filterPattern"))

    @filter_pattern.setter
    def filter_pattern(self, value: builtins.str) -> None:
        jsii.set(self, "filterPattern", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logGroupName")
    def log_group_name(self) -> builtins.str:
        '''The name of an existing log group that you want to associate with this metric filter.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-metricfilter.html#cfn-cwl-metricfilter-loggroupname
        '''
        return typing.cast(builtins.str, jsii.get(self, "logGroupName"))

    @log_group_name.setter
    def log_group_name(self, value: builtins.str) -> None:
        jsii.set(self, "logGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="metricTransformations")
    def metric_transformations(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnMetricFilter.MetricTransformationProperty", _IResolvable_da3f097b]]]:
        '''The metric transformations.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-metricfilter.html#cfn-cwl-metricfilter-metrictransformations
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnMetricFilter.MetricTransformationProperty", _IResolvable_da3f097b]]], jsii.get(self, "metricTransformations"))

    @metric_transformations.setter
    def metric_transformations(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnMetricFilter.MetricTransformationProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "metricTransformations", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_logs.CfnMetricFilter.MetricTransformationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "metric_name": "metricName",
            "metric_namespace": "metricNamespace",
            "metric_value": "metricValue",
            "default_value": "defaultValue",
        },
    )
    class MetricTransformationProperty:
        def __init__(
            self,
            *,
            metric_name: builtins.str,
            metric_namespace: builtins.str,
            metric_value: builtins.str,
            default_value: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``MetricTransformation`` is a property of the ``AWS::Logs::MetricFilter`` resource that describes how to transform log streams into a CloudWatch metric.

            :param metric_name: The name of the CloudWatch metric.
            :param metric_namespace: A custom namespace to contain your metric in CloudWatch. Use namespaces to group together metrics that are similar. For more information, see `Namespaces <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#Namespace>`_ .
            :param metric_value: The value that is published to the CloudWatch metric. For example, if you're counting the occurrences of a particular term like ``Error`` , specify 1 for the metric value. If you're counting the number of bytes transferred, reference the value that is in the log event by using $ followed by the name of the field that you specified in the filter pattern, such as ``$.size`` .
            :param default_value: (Optional) The value to emit when a filter pattern does not match a log event. This value can be null.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-logs-metricfilter-metrictransformation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_logs as logs
                
                metric_transformation_property = logs.CfnMetricFilter.MetricTransformationProperty(
                    metric_name="metricName",
                    metric_namespace="metricNamespace",
                    metric_value="metricValue",
                
                    # the properties below are optional
                    default_value=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "metric_name": metric_name,
                "metric_namespace": metric_namespace,
                "metric_value": metric_value,
            }
            if default_value is not None:
                self._values["default_value"] = default_value

        @builtins.property
        def metric_name(self) -> builtins.str:
            '''The name of the CloudWatch metric.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-logs-metricfilter-metrictransformation.html#cfn-cwl-metricfilter-metrictransformation-metricname
            '''
            result = self._values.get("metric_name")
            assert result is not None, "Required property 'metric_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def metric_namespace(self) -> builtins.str:
            '''A custom namespace to contain your metric in CloudWatch.

            Use namespaces to group together metrics that are similar. For more information, see `Namespaces <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#Namespace>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-logs-metricfilter-metrictransformation.html#cfn-cwl-metricfilter-metrictransformation-metricnamespace
            '''
            result = self._values.get("metric_namespace")
            assert result is not None, "Required property 'metric_namespace' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def metric_value(self) -> builtins.str:
            '''The value that is published to the CloudWatch metric.

            For example, if you're counting the occurrences of a particular term like ``Error`` , specify 1 for the metric value. If you're counting the number of bytes transferred, reference the value that is in the log event by using $ followed by the name of the field that you specified in the filter pattern, such as ``$.size`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-logs-metricfilter-metrictransformation.html#cfn-cwl-metricfilter-metrictransformation-metricvalue
            '''
            result = self._values.get("metric_value")
            assert result is not None, "Required property 'metric_value' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def default_value(self) -> typing.Optional[jsii.Number]:
            '''(Optional) The value to emit when a filter pattern does not match a log event.

            This value can be null.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-logs-metricfilter-metrictransformation.html#cfn-cwl-metricfilter-metrictransformation-defaultvalue
            '''
            result = self._values.get("default_value")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MetricTransformationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.CfnMetricFilterProps",
    jsii_struct_bases=[],
    name_mapping={
        "filter_pattern": "filterPattern",
        "log_group_name": "logGroupName",
        "metric_transformations": "metricTransformations",
    },
)
class CfnMetricFilterProps:
    def __init__(
        self,
        *,
        filter_pattern: builtins.str,
        log_group_name: builtins.str,
        metric_transformations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnMetricFilter.MetricTransformationProperty, _IResolvable_da3f097b]]],
    ) -> None:
        '''Properties for defining a ``CfnMetricFilter``.

        :param filter_pattern: A filter pattern for extracting metric data out of ingested log events. For more information, see `Filter and Pattern Syntax <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html>`_ .
        :param log_group_name: The name of an existing log group that you want to associate with this metric filter.
        :param metric_transformations: The metric transformations.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-metricfilter.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_logs as logs
            
            cfn_metric_filter_props = logs.CfnMetricFilterProps(
                filter_pattern="filterPattern",
                log_group_name="logGroupName",
                metric_transformations=[logs.CfnMetricFilter.MetricTransformationProperty(
                    metric_name="metricName",
                    metric_namespace="metricNamespace",
                    metric_value="metricValue",
            
                    # the properties below are optional
                    default_value=123
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "filter_pattern": filter_pattern,
            "log_group_name": log_group_name,
            "metric_transformations": metric_transformations,
        }

    @builtins.property
    def filter_pattern(self) -> builtins.str:
        '''A filter pattern for extracting metric data out of ingested log events.

        For more information, see `Filter and Pattern Syntax <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-metricfilter.html#cfn-cwl-metricfilter-filterpattern
        '''
        result = self._values.get("filter_pattern")
        assert result is not None, "Required property 'filter_pattern' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def log_group_name(self) -> builtins.str:
        '''The name of an existing log group that you want to associate with this metric filter.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-metricfilter.html#cfn-cwl-metricfilter-loggroupname
        '''
        result = self._values.get("log_group_name")
        assert result is not None, "Required property 'log_group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def metric_transformations(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnMetricFilter.MetricTransformationProperty, _IResolvable_da3f097b]]]:
        '''The metric transformations.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-metricfilter.html#cfn-cwl-metricfilter-metrictransformations
        '''
        result = self._values.get("metric_transformations")
        assert result is not None, "Required property 'metric_transformations' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnMetricFilter.MetricTransformationProperty, _IResolvable_da3f097b]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnMetricFilterProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnQueryDefinition(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.CfnQueryDefinition",
):
    '''A CloudFormation ``AWS::Logs::QueryDefinition``.

    Creates a query definition for CloudWatch Logs Insights. For more information, see `Analyzing Log Data with CloudWatch Logs Insights <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/AnalyzingLogData.html>`_ .

    :cloudformationResource: AWS::Logs::QueryDefinition
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-querydefinition.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_logs as logs
        
        cfn_query_definition = logs.CfnQueryDefinition(self, "MyCfnQueryDefinition",
            name="name",
            query_string="queryString",
        
            # the properties below are optional
            log_group_names=["logGroupNames"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        query_string: builtins.str,
        log_group_names: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::Logs::QueryDefinition``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: A name for the query definition.
        :param query_string: The query string to use for this query definition. For more information, see `CloudWatch Logs Insights Query Syntax <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html>`_ .
        :param log_group_names: Use this parameter if you want the query to query only certain log groups.
        '''
        props = CfnQueryDefinitionProps(
            name=name, query_string=query_string, log_group_names=log_group_names
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
    @jsii.member(jsii_name="attrQueryDefinitionId")
    def attr_query_definition_id(self) -> builtins.str:
        '''The ID of the query definition.

        :cloudformationAttribute: QueryDefinitionId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrQueryDefinitionId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''A name for the query definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-querydefinition.html#cfn-logs-querydefinition-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queryString")
    def query_string(self) -> builtins.str:
        '''The query string to use for this query definition.

        For more information, see `CloudWatch Logs Insights Query Syntax <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-querydefinition.html#cfn-logs-querydefinition-querystring
        '''
        return typing.cast(builtins.str, jsii.get(self, "queryString"))

    @query_string.setter
    def query_string(self, value: builtins.str) -> None:
        jsii.set(self, "queryString", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logGroupNames")
    def log_group_names(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Use this parameter if you want the query to query only certain log groups.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-querydefinition.html#cfn-logs-querydefinition-loggroupnames
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "logGroupNames"))

    @log_group_names.setter
    def log_group_names(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "logGroupNames", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.CfnQueryDefinitionProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "query_string": "queryString",
        "log_group_names": "logGroupNames",
    },
)
class CfnQueryDefinitionProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        query_string: builtins.str,
        log_group_names: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnQueryDefinition``.

        :param name: A name for the query definition.
        :param query_string: The query string to use for this query definition. For more information, see `CloudWatch Logs Insights Query Syntax <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html>`_ .
        :param log_group_names: Use this parameter if you want the query to query only certain log groups.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-querydefinition.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_logs as logs
            
            cfn_query_definition_props = logs.CfnQueryDefinitionProps(
                name="name",
                query_string="queryString",
            
                # the properties below are optional
                log_group_names=["logGroupNames"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
            "query_string": query_string,
        }
        if log_group_names is not None:
            self._values["log_group_names"] = log_group_names

    @builtins.property
    def name(self) -> builtins.str:
        '''A name for the query definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-querydefinition.html#cfn-logs-querydefinition-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def query_string(self) -> builtins.str:
        '''The query string to use for this query definition.

        For more information, see `CloudWatch Logs Insights Query Syntax <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-querydefinition.html#cfn-logs-querydefinition-querystring
        '''
        result = self._values.get("query_string")
        assert result is not None, "Required property 'query_string' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def log_group_names(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Use this parameter if you want the query to query only certain log groups.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-querydefinition.html#cfn-logs-querydefinition-loggroupnames
        '''
        result = self._values.get("log_group_names")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnQueryDefinitionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnResourcePolicy(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.CfnResourcePolicy",
):
    '''A CloudFormation ``AWS::Logs::ResourcePolicy``.

    Creates or updates a resource policy that allows other AWS services to put log events to this account. An account can have up to 10 resource policies per AWS Region.

    :cloudformationResource: AWS::Logs::ResourcePolicy
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-resourcepolicy.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_logs as logs
        
        cfn_resource_policy = logs.CfnResourcePolicy(self, "MyCfnResourcePolicy",
            policy_document="policyDocument",
            policy_name="policyName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        policy_document: builtins.str,
        policy_name: builtins.str,
    ) -> None:
        '''Create a new ``AWS::Logs::ResourcePolicy``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param policy_document: The details of the policy. It must be formatted in JSON, and you must use backslashes to escape characters that need to be escaped in JSON strings, such as double quote marks.
        :param policy_name: The name of the resource policy.
        '''
        props = CfnResourcePolicyProps(
            policy_document=policy_document, policy_name=policy_name
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
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyDocument")
    def policy_document(self) -> builtins.str:
        '''The details of the policy.

        It must be formatted in JSON, and you must use backslashes to escape characters that need to be escaped in JSON strings, such as double quote marks.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-resourcepolicy.html#cfn-logs-resourcepolicy-policydocument
        '''
        return typing.cast(builtins.str, jsii.get(self, "policyDocument"))

    @policy_document.setter
    def policy_document(self, value: builtins.str) -> None:
        jsii.set(self, "policyDocument", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyName")
    def policy_name(self) -> builtins.str:
        '''The name of the resource policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-resourcepolicy.html#cfn-logs-resourcepolicy-policyname
        '''
        return typing.cast(builtins.str, jsii.get(self, "policyName"))

    @policy_name.setter
    def policy_name(self, value: builtins.str) -> None:
        jsii.set(self, "policyName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.CfnResourcePolicyProps",
    jsii_struct_bases=[],
    name_mapping={"policy_document": "policyDocument", "policy_name": "policyName"},
)
class CfnResourcePolicyProps:
    def __init__(
        self,
        *,
        policy_document: builtins.str,
        policy_name: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnResourcePolicy``.

        :param policy_document: The details of the policy. It must be formatted in JSON, and you must use backslashes to escape characters that need to be escaped in JSON strings, such as double quote marks.
        :param policy_name: The name of the resource policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-resourcepolicy.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_logs as logs
            
            cfn_resource_policy_props = logs.CfnResourcePolicyProps(
                policy_document="policyDocument",
                policy_name="policyName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "policy_document": policy_document,
            "policy_name": policy_name,
        }

    @builtins.property
    def policy_document(self) -> builtins.str:
        '''The details of the policy.

        It must be formatted in JSON, and you must use backslashes to escape characters that need to be escaped in JSON strings, such as double quote marks.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-resourcepolicy.html#cfn-logs-resourcepolicy-policydocument
        '''
        result = self._values.get("policy_document")
        assert result is not None, "Required property 'policy_document' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def policy_name(self) -> builtins.str:
        '''The name of the resource policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-resourcepolicy.html#cfn-logs-resourcepolicy-policyname
        '''
        result = self._values.get("policy_name")
        assert result is not None, "Required property 'policy_name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnResourcePolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSubscriptionFilter(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.CfnSubscriptionFilter",
):
    '''A CloudFormation ``AWS::Logs::SubscriptionFilter``.

    The ``AWS::Logs::SubscriptionFilter`` resource specifies a subscription filter and associates it with the specified log group. Subscription filters allow you to subscribe to a real-time stream of log events and have them delivered to a specific destination. Currently, the supported destinations are:

    - An Amazon Kinesis data stream belonging to the same account as the subscription filter, for same-account delivery.
    - A logical destination that belongs to a different account, for cross-account delivery.
    - An Amazon Kinesis Firehose delivery stream that belongs to the same account as the subscription filter, for same-account delivery.
    - An AWS Lambda function that belongs to the same account as the subscription filter, for same-account delivery.

    There can as many as two subscription filters associated with a log group.

    :cloudformationResource: AWS::Logs::SubscriptionFilter
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-subscriptionfilter.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_logs as logs
        
        cfn_subscription_filter = logs.CfnSubscriptionFilter(self, "MyCfnSubscriptionFilter",
            destination_arn="destinationArn",
            filter_pattern="filterPattern",
            log_group_name="logGroupName",
        
            # the properties below are optional
            role_arn="roleArn"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        destination_arn: builtins.str,
        filter_pattern: builtins.str,
        log_group_name: builtins.str,
        role_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Logs::SubscriptionFilter``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param destination_arn: The Amazon Resource Name (ARN) of the destination.
        :param filter_pattern: The filtering expressions that restrict what gets delivered to the destination AWS resource. For more information about the filter pattern syntax, see `Filter and Pattern Syntax <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html>`_ .
        :param log_group_name: The log group to associate with the subscription filter. All log events that are uploaded to this log group are filtered and delivered to the specified AWS resource if the filter pattern matches the log events.
        :param role_arn: The ARN of an IAM role that grants CloudWatch Logs permissions to deliver ingested log events to the destination stream. You don't need to provide the ARN when you are working with a logical destination for cross-account delivery.
        '''
        props = CfnSubscriptionFilterProps(
            destination_arn=destination_arn,
            filter_pattern=filter_pattern,
            log_group_name=log_group_name,
            role_arn=role_arn,
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
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="destinationArn")
    def destination_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the destination.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-subscriptionfilter.html#cfn-cwl-subscriptionfilter-destinationarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "destinationArn"))

    @destination_arn.setter
    def destination_arn(self, value: builtins.str) -> None:
        jsii.set(self, "destinationArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="filterPattern")
    def filter_pattern(self) -> builtins.str:
        '''The filtering expressions that restrict what gets delivered to the destination AWS resource.

        For more information about the filter pattern syntax, see `Filter and Pattern Syntax <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-subscriptionfilter.html#cfn-cwl-subscriptionfilter-filterpattern
        '''
        return typing.cast(builtins.str, jsii.get(self, "filterPattern"))

    @filter_pattern.setter
    def filter_pattern(self, value: builtins.str) -> None:
        jsii.set(self, "filterPattern", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logGroupName")
    def log_group_name(self) -> builtins.str:
        '''The log group to associate with the subscription filter.

        All log events that are uploaded to this log group are filtered and delivered to the specified AWS resource if the filter pattern matches the log events.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-subscriptionfilter.html#cfn-cwl-subscriptionfilter-loggroupname
        '''
        return typing.cast(builtins.str, jsii.get(self, "logGroupName"))

    @log_group_name.setter
    def log_group_name(self, value: builtins.str) -> None:
        jsii.set(self, "logGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of an IAM role that grants CloudWatch Logs permissions to deliver ingested log events to the destination stream.

        You don't need to provide the ARN when you are working with a logical destination for cross-account delivery.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-subscriptionfilter.html#cfn-cwl-subscriptionfilter-rolearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "roleArn"))

    @role_arn.setter
    def role_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "roleArn", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.CfnSubscriptionFilterProps",
    jsii_struct_bases=[],
    name_mapping={
        "destination_arn": "destinationArn",
        "filter_pattern": "filterPattern",
        "log_group_name": "logGroupName",
        "role_arn": "roleArn",
    },
)
class CfnSubscriptionFilterProps:
    def __init__(
        self,
        *,
        destination_arn: builtins.str,
        filter_pattern: builtins.str,
        log_group_name: builtins.str,
        role_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnSubscriptionFilter``.

        :param destination_arn: The Amazon Resource Name (ARN) of the destination.
        :param filter_pattern: The filtering expressions that restrict what gets delivered to the destination AWS resource. For more information about the filter pattern syntax, see `Filter and Pattern Syntax <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html>`_ .
        :param log_group_name: The log group to associate with the subscription filter. All log events that are uploaded to this log group are filtered and delivered to the specified AWS resource if the filter pattern matches the log events.
        :param role_arn: The ARN of an IAM role that grants CloudWatch Logs permissions to deliver ingested log events to the destination stream. You don't need to provide the ARN when you are working with a logical destination for cross-account delivery.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-subscriptionfilter.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_logs as logs
            
            cfn_subscription_filter_props = logs.CfnSubscriptionFilterProps(
                destination_arn="destinationArn",
                filter_pattern="filterPattern",
                log_group_name="logGroupName",
            
                # the properties below are optional
                role_arn="roleArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "destination_arn": destination_arn,
            "filter_pattern": filter_pattern,
            "log_group_name": log_group_name,
        }
        if role_arn is not None:
            self._values["role_arn"] = role_arn

    @builtins.property
    def destination_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the destination.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-subscriptionfilter.html#cfn-cwl-subscriptionfilter-destinationarn
        '''
        result = self._values.get("destination_arn")
        assert result is not None, "Required property 'destination_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def filter_pattern(self) -> builtins.str:
        '''The filtering expressions that restrict what gets delivered to the destination AWS resource.

        For more information about the filter pattern syntax, see `Filter and Pattern Syntax <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-subscriptionfilter.html#cfn-cwl-subscriptionfilter-filterpattern
        '''
        result = self._values.get("filter_pattern")
        assert result is not None, "Required property 'filter_pattern' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def log_group_name(self) -> builtins.str:
        '''The log group to associate with the subscription filter.

        All log events that are uploaded to this log group are filtered and delivered to the specified AWS resource if the filter pattern matches the log events.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-subscriptionfilter.html#cfn-cwl-subscriptionfilter-loggroupname
        '''
        result = self._values.get("log_group_name")
        assert result is not None, "Required property 'log_group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def role_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of an IAM role that grants CloudWatch Logs permissions to deliver ingested log events to the destination stream.

        You don't need to provide the ARN when you are working with a logical destination for cross-account delivery.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-subscriptionfilter.html#cfn-cwl-subscriptionfilter-rolearn
        '''
        result = self._values.get("role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSubscriptionFilterProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.ColumnRestriction",
    jsii_struct_bases=[],
    name_mapping={
        "comparison": "comparison",
        "number_value": "numberValue",
        "string_value": "stringValue",
    },
)
class ColumnRestriction:
    def __init__(
        self,
        *,
        comparison: builtins.str,
        number_value: typing.Optional[jsii.Number] = None,
        string_value: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param comparison: Comparison operator to use.
        :param number_value: Number value to compare to. Exactly one of 'stringValue' and 'numberValue' must be set.
        :param string_value: String value to compare to. Exactly one of 'stringValue' and 'numberValue' must be set.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_logs as logs
            
            column_restriction = logs.ColumnRestriction(
                comparison="comparison",
            
                # the properties below are optional
                number_value=123,
                string_value="stringValue"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "comparison": comparison,
        }
        if number_value is not None:
            self._values["number_value"] = number_value
        if string_value is not None:
            self._values["string_value"] = string_value

    @builtins.property
    def comparison(self) -> builtins.str:
        '''Comparison operator to use.'''
        result = self._values.get("comparison")
        assert result is not None, "Required property 'comparison' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def number_value(self) -> typing.Optional[jsii.Number]:
        '''Number value to compare to.

        Exactly one of 'stringValue' and 'numberValue' must be set.
        '''
        result = self._values.get("number_value")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def string_value(self) -> typing.Optional[builtins.str]:
        '''String value to compare to.

        Exactly one of 'stringValue' and 'numberValue' must be set.
        '''
        result = self._values.get("string_value")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ColumnRestriction(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.CrossAccountDestinationProps",
    jsii_struct_bases=[],
    name_mapping={
        "role": "role",
        "target_arn": "targetArn",
        "destination_name": "destinationName",
    },
)
class CrossAccountDestinationProps:
    def __init__(
        self,
        *,
        role: _IRole_235f5d8e,
        target_arn: builtins.str,
        destination_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for a CrossAccountDestination.

        :param role: The role to assume that grants permissions to write to 'target'. The role must be assumable by 'logs.{REGION}.amazonaws.com'.
        :param target_arn: The log destination target's ARN.
        :param destination_name: The name of the log destination. Default: Automatically generated

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            from aws_cdk import aws_logs as logs
            
            # role: iam.Role
            
            cross_account_destination_props = logs.CrossAccountDestinationProps(
                role=role,
                target_arn="targetArn",
            
                # the properties below are optional
                destination_name="destinationName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "role": role,
            "target_arn": target_arn,
        }
        if destination_name is not None:
            self._values["destination_name"] = destination_name

    @builtins.property
    def role(self) -> _IRole_235f5d8e:
        '''The role to assume that grants permissions to write to 'target'.

        The role must be assumable by 'logs.{REGION}.amazonaws.com'.
        '''
        result = self._values.get("role")
        assert result is not None, "Required property 'role' is missing"
        return typing.cast(_IRole_235f5d8e, result)

    @builtins.property
    def target_arn(self) -> builtins.str:
        '''The log destination target's ARN.'''
        result = self._values.get("target_arn")
        assert result is not None, "Required property 'target_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def destination_name(self) -> typing.Optional[builtins.str]:
        '''The name of the log destination.

        :default: Automatically generated
        '''
        result = self._values.get("destination_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CrossAccountDestinationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class FilterPattern(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.FilterPattern",
):
    '''A collection of static methods to generate appropriate ILogPatterns.

    :exampleMetadata: infused

    Example::

        # Search for lines that contain both "ERROR" and "MainThread"
        pattern1 = logs.FilterPattern.all_terms("ERROR", "MainThread")
        
        # Search for lines that either contain both "ERROR" and "MainThread", or
        # both "WARN" and "Deadlock".
        pattern2 = logs.FilterPattern.any_term_group(["ERROR", "MainThread"], ["WARN", "Deadlock"])
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="all") # type: ignore[misc]
    @builtins.classmethod
    def all(cls, *patterns: "JsonPattern") -> "JsonPattern":
        '''A JSON log pattern that matches if all given JSON log patterns match.

        :param patterns: -
        '''
        return typing.cast("JsonPattern", jsii.sinvoke(cls, "all", [*patterns]))

    @jsii.member(jsii_name="allEvents") # type: ignore[misc]
    @builtins.classmethod
    def all_events(cls) -> "IFilterPattern":
        '''A log pattern that matches all events.'''
        return typing.cast("IFilterPattern", jsii.sinvoke(cls, "allEvents", []))

    @jsii.member(jsii_name="allTerms") # type: ignore[misc]
    @builtins.classmethod
    def all_terms(cls, *terms: builtins.str) -> "IFilterPattern":
        '''A log pattern that matches if all the strings given appear in the event.

        :param terms: The words to search for. All terms must match.
        '''
        return typing.cast("IFilterPattern", jsii.sinvoke(cls, "allTerms", [*terms]))

    @jsii.member(jsii_name="any") # type: ignore[misc]
    @builtins.classmethod
    def any(cls, *patterns: "JsonPattern") -> "JsonPattern":
        '''A JSON log pattern that matches if any of the given JSON log patterns match.

        :param patterns: -
        '''
        return typing.cast("JsonPattern", jsii.sinvoke(cls, "any", [*patterns]))

    @jsii.member(jsii_name="anyTerm") # type: ignore[misc]
    @builtins.classmethod
    def any_term(cls, *terms: builtins.str) -> "IFilterPattern":
        '''A log pattern that matches if any of the strings given appear in the event.

        :param terms: The words to search for. Any terms must match.
        '''
        return typing.cast("IFilterPattern", jsii.sinvoke(cls, "anyTerm", [*terms]))

    @jsii.member(jsii_name="anyTermGroup") # type: ignore[misc]
    @builtins.classmethod
    def any_term_group(
        cls,
        *term_groups: typing.List[builtins.str],
    ) -> "IFilterPattern":
        '''A log pattern that matches if any of the given term groups matches the event.

        A term group matches an event if all the terms in it appear in the event string.

        :param term_groups: A list of term groups to search for. Any one of the clauses must match.
        '''
        return typing.cast("IFilterPattern", jsii.sinvoke(cls, "anyTermGroup", [*term_groups]))

    @jsii.member(jsii_name="booleanValue") # type: ignore[misc]
    @builtins.classmethod
    def boolean_value(
        cls,
        json_field: builtins.str,
        value: builtins.bool,
    ) -> "JsonPattern":
        '''A JSON log pattern that matches if the field exists and equals the boolean value.

        :param json_field: Field inside JSON. Example: "$.myField"
        :param value: The value to match.
        '''
        return typing.cast("JsonPattern", jsii.sinvoke(cls, "booleanValue", [json_field, value]))

    @jsii.member(jsii_name="exists") # type: ignore[misc]
    @builtins.classmethod
    def exists(cls, json_field: builtins.str) -> "JsonPattern":
        '''A JSON log patter that matches if the field exists.

        This is a readable convenience wrapper over 'field = *'

        :param json_field: Field inside JSON. Example: "$.myField"
        '''
        return typing.cast("JsonPattern", jsii.sinvoke(cls, "exists", [json_field]))

    @jsii.member(jsii_name="isNull") # type: ignore[misc]
    @builtins.classmethod
    def is_null(cls, json_field: builtins.str) -> "JsonPattern":
        '''A JSON log pattern that matches if the field exists and has the special value 'null'.

        :param json_field: Field inside JSON. Example: "$.myField"
        '''
        return typing.cast("JsonPattern", jsii.sinvoke(cls, "isNull", [json_field]))

    @jsii.member(jsii_name="literal") # type: ignore[misc]
    @builtins.classmethod
    def literal(cls, log_pattern_string: builtins.str) -> "IFilterPattern":
        '''Use the given string as log pattern.

        See https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html
        for information on writing log patterns.

        :param log_pattern_string: The pattern string to use.
        '''
        return typing.cast("IFilterPattern", jsii.sinvoke(cls, "literal", [log_pattern_string]))

    @jsii.member(jsii_name="notExists") # type: ignore[misc]
    @builtins.classmethod
    def not_exists(cls, json_field: builtins.str) -> "JsonPattern":
        '''A JSON log pattern that matches if the field does not exist.

        :param json_field: Field inside JSON. Example: "$.myField"
        '''
        return typing.cast("JsonPattern", jsii.sinvoke(cls, "notExists", [json_field]))

    @jsii.member(jsii_name="numberValue") # type: ignore[misc]
    @builtins.classmethod
    def number_value(
        cls,
        json_field: builtins.str,
        comparison: builtins.str,
        value: jsii.Number,
    ) -> "JsonPattern":
        '''A JSON log pattern that compares numerical values.

        This pattern only matches if the event is a JSON event, and the indicated field inside
        compares with the value in the indicated way.

        Use '$' to indicate the root of the JSON structure. The comparison operator can only
        compare equality or inequality. The '*' wildcard may appear in the value may at the
        start or at the end.

        For more information, see:

        https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html

        :param json_field: Field inside JSON. Example: "$.myField"
        :param comparison: Comparison to carry out. One of =, !=, <, <=, >, >=.
        :param value: The numerical value to compare to.
        '''
        return typing.cast("JsonPattern", jsii.sinvoke(cls, "numberValue", [json_field, comparison, value]))

    @jsii.member(jsii_name="spaceDelimited") # type: ignore[misc]
    @builtins.classmethod
    def space_delimited(cls, *columns: builtins.str) -> "SpaceDelimitedTextPattern":
        '''A space delimited log pattern matcher.

        The log event is divided into space-delimited columns (optionally
        enclosed by "" or [] to capture spaces into column values), and names
        are given to each column.

        '...' may be specified once to match any number of columns.

        Afterwards, conditions may be added to individual columns.

        :param columns: The columns in the space-delimited log stream.
        '''
        return typing.cast("SpaceDelimitedTextPattern", jsii.sinvoke(cls, "spaceDelimited", [*columns]))

    @jsii.member(jsii_name="stringValue") # type: ignore[misc]
    @builtins.classmethod
    def string_value(
        cls,
        json_field: builtins.str,
        comparison: builtins.str,
        value: builtins.str,
    ) -> "JsonPattern":
        '''A JSON log pattern that compares string values.

        This pattern only matches if the event is a JSON event, and the indicated field inside
        compares with the string value.

        Use '$' to indicate the root of the JSON structure. The comparison operator can only
        compare equality or inequality. The '*' wildcard may appear in the value may at the
        start or at the end.

        For more information, see:

        https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html

        :param json_field: Field inside JSON. Example: "$.myField"
        :param comparison: Comparison to carry out. Either = or !=.
        :param value: The string value to compare to. May use '*' as wildcard at start or end of string.
        '''
        return typing.cast("JsonPattern", jsii.sinvoke(cls, "stringValue", [json_field, comparison, value]))


@jsii.interface(jsii_type="aws-cdk-lib.aws_logs.IFilterPattern")
class IFilterPattern(typing_extensions.Protocol):
    '''Interface for objects that can render themselves to log patterns.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logPatternString")
    def log_pattern_string(self) -> builtins.str:
        ...


class _IFilterPatternProxy:
    '''Interface for objects that can render themselves to log patterns.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_logs.IFilterPattern"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logPatternString")
    def log_pattern_string(self) -> builtins.str:
        return typing.cast(builtins.str, jsii.get(self, "logPatternString"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IFilterPattern).__jsii_proxy_class__ = lambda : _IFilterPatternProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_logs.ILogGroup")
class ILogGroup(_IResourceWithPolicy_720d64fc, typing_extensions.Protocol):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logGroupArn")
    def log_group_arn(self) -> builtins.str:
        '''The ARN of this log group, with ':*' appended.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logGroupName")
    def log_group_name(self) -> builtins.str:
        '''The name of this log group.

        :attribute: true
        '''
        ...

    @jsii.member(jsii_name="addMetricFilter")
    def add_metric_filter(
        self,
        id: builtins.str,
        *,
        filter_pattern: IFilterPattern,
        metric_name: builtins.str,
        metric_namespace: builtins.str,
        default_value: typing.Optional[jsii.Number] = None,
        metric_value: typing.Optional[builtins.str] = None,
    ) -> "MetricFilter":
        '''Create a new Metric Filter on this Log Group.

        :param id: Unique identifier for the construct in its parent.
        :param filter_pattern: Pattern to search for log events.
        :param metric_name: The name of the metric to emit.
        :param metric_namespace: The namespace of the metric to emit.
        :param default_value: The value to emit if the pattern does not match a particular event. Default: No metric emitted.
        :param metric_value: The value to emit for the metric. Can either be a literal number (typically "1"), or the name of a field in the structure to take the value from the matched event. If you are using a field value, the field value must have been matched using the pattern. If you want to specify a field from a matched JSON structure, use '$.fieldName', and make sure the field is in the pattern (if only as '$.fieldName = *'). If you want to specify a field from a matched space-delimited structure, use '$fieldName'. Default: "1"
        '''
        ...

    @jsii.member(jsii_name="addStream")
    def add_stream(
        self,
        id: builtins.str,
        *,
        log_stream_name: typing.Optional[builtins.str] = None,
    ) -> "LogStream":
        '''Create a new Log Stream for this Log Group.

        :param id: Unique identifier for the construct in its parent.
        :param log_stream_name: The name of the log stream to create. The name must be unique within the log group. Default: Automatically generated
        '''
        ...

    @jsii.member(jsii_name="addSubscriptionFilter")
    def add_subscription_filter(
        self,
        id: builtins.str,
        *,
        destination: "ILogSubscriptionDestination",
        filter_pattern: IFilterPattern,
    ) -> "SubscriptionFilter":
        '''Create a new Subscription Filter on this Log Group.

        :param id: Unique identifier for the construct in its parent.
        :param destination: The destination to send the filtered events to. For example, a Kinesis stream or a Lambda function.
        :param filter_pattern: Log events matching this pattern will be sent to the destination.
        '''
        ...

    @jsii.member(jsii_name="extractMetric")
    def extract_metric(
        self,
        json_field: builtins.str,
        metric_namespace: builtins.str,
        metric_name: builtins.str,
    ) -> _Metric_e396a4dc:
        '''Extract a metric from structured log events in the LogGroup.

        Creates a MetricFilter on this LogGroup that will extract the value
        of the indicated JSON field in all records where it occurs.

        The metric will be available in CloudWatch Metrics under the
        indicated namespace and name.

        :param json_field: JSON field to extract (example: '$.myfield').
        :param metric_namespace: Namespace to emit the metric under.
        :param metric_name: Name to emit the metric under.

        :return: A Metric object representing the extracted metric
        '''
        ...

    @jsii.member(jsii_name="grant")
    def grant(
        self,
        grantee: _IGrantable_71c4f5de,
        *actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Give the indicated permissions on this log group and all streams.

        :param grantee: -
        :param actions: -
        '''
        ...

    @jsii.member(jsii_name="grantWrite")
    def grant_write(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Give permissions to write to create and write to streams in this log group.

        :param grantee: -
        '''
        ...

    @jsii.member(jsii_name="logGroupPhysicalName")
    def log_group_physical_name(self) -> builtins.str:
        '''Public method to get the physical name of this log group.'''
        ...


class _ILogGroupProxy(
    jsii.proxy_for(_IResourceWithPolicy_720d64fc) # type: ignore[misc]
):
    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_logs.ILogGroup"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logGroupArn")
    def log_group_arn(self) -> builtins.str:
        '''The ARN of this log group, with ':*' appended.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "logGroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logGroupName")
    def log_group_name(self) -> builtins.str:
        '''The name of this log group.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "logGroupName"))

    @jsii.member(jsii_name="addMetricFilter")
    def add_metric_filter(
        self,
        id: builtins.str,
        *,
        filter_pattern: IFilterPattern,
        metric_name: builtins.str,
        metric_namespace: builtins.str,
        default_value: typing.Optional[jsii.Number] = None,
        metric_value: typing.Optional[builtins.str] = None,
    ) -> "MetricFilter":
        '''Create a new Metric Filter on this Log Group.

        :param id: Unique identifier for the construct in its parent.
        :param filter_pattern: Pattern to search for log events.
        :param metric_name: The name of the metric to emit.
        :param metric_namespace: The namespace of the metric to emit.
        :param default_value: The value to emit if the pattern does not match a particular event. Default: No metric emitted.
        :param metric_value: The value to emit for the metric. Can either be a literal number (typically "1"), or the name of a field in the structure to take the value from the matched event. If you are using a field value, the field value must have been matched using the pattern. If you want to specify a field from a matched JSON structure, use '$.fieldName', and make sure the field is in the pattern (if only as '$.fieldName = *'). If you want to specify a field from a matched space-delimited structure, use '$fieldName'. Default: "1"
        '''
        props = MetricFilterOptions(
            filter_pattern=filter_pattern,
            metric_name=metric_name,
            metric_namespace=metric_namespace,
            default_value=default_value,
            metric_value=metric_value,
        )

        return typing.cast("MetricFilter", jsii.invoke(self, "addMetricFilter", [id, props]))

    @jsii.member(jsii_name="addStream")
    def add_stream(
        self,
        id: builtins.str,
        *,
        log_stream_name: typing.Optional[builtins.str] = None,
    ) -> "LogStream":
        '''Create a new Log Stream for this Log Group.

        :param id: Unique identifier for the construct in its parent.
        :param log_stream_name: The name of the log stream to create. The name must be unique within the log group. Default: Automatically generated
        '''
        props = StreamOptions(log_stream_name=log_stream_name)

        return typing.cast("LogStream", jsii.invoke(self, "addStream", [id, props]))

    @jsii.member(jsii_name="addSubscriptionFilter")
    def add_subscription_filter(
        self,
        id: builtins.str,
        *,
        destination: "ILogSubscriptionDestination",
        filter_pattern: IFilterPattern,
    ) -> "SubscriptionFilter":
        '''Create a new Subscription Filter on this Log Group.

        :param id: Unique identifier for the construct in its parent.
        :param destination: The destination to send the filtered events to. For example, a Kinesis stream or a Lambda function.
        :param filter_pattern: Log events matching this pattern will be sent to the destination.
        '''
        props = SubscriptionFilterOptions(
            destination=destination, filter_pattern=filter_pattern
        )

        return typing.cast("SubscriptionFilter", jsii.invoke(self, "addSubscriptionFilter", [id, props]))

    @jsii.member(jsii_name="extractMetric")
    def extract_metric(
        self,
        json_field: builtins.str,
        metric_namespace: builtins.str,
        metric_name: builtins.str,
    ) -> _Metric_e396a4dc:
        '''Extract a metric from structured log events in the LogGroup.

        Creates a MetricFilter on this LogGroup that will extract the value
        of the indicated JSON field in all records where it occurs.

        The metric will be available in CloudWatch Metrics under the
        indicated namespace and name.

        :param json_field: JSON field to extract (example: '$.myfield').
        :param metric_namespace: Namespace to emit the metric under.
        :param metric_name: Name to emit the metric under.

        :return: A Metric object representing the extracted metric
        '''
        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "extractMetric", [json_field, metric_namespace, metric_name]))

    @jsii.member(jsii_name="grant")
    def grant(
        self,
        grantee: _IGrantable_71c4f5de,
        *actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Give the indicated permissions on this log group and all streams.

        :param grantee: -
        :param actions: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grant", [grantee, *actions]))

    @jsii.member(jsii_name="grantWrite")
    def grant_write(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Give permissions to write to create and write to streams in this log group.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantWrite", [grantee]))

    @jsii.member(jsii_name="logGroupPhysicalName")
    def log_group_physical_name(self) -> builtins.str:
        '''Public method to get the physical name of this log group.'''
        return typing.cast(builtins.str, jsii.invoke(self, "logGroupPhysicalName", []))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ILogGroup).__jsii_proxy_class__ = lambda : _ILogGroupProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_logs.ILogStream")
class ILogStream(_IResource_c80c4260, typing_extensions.Protocol):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logStreamName")
    def log_stream_name(self) -> builtins.str:
        '''The name of this log stream.

        :attribute: true
        '''
        ...


class _ILogStreamProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_logs.ILogStream"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logStreamName")
    def log_stream_name(self) -> builtins.str:
        '''The name of this log stream.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "logStreamName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ILogStream).__jsii_proxy_class__ = lambda : _ILogStreamProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_logs.ILogSubscriptionDestination")
class ILogSubscriptionDestination(typing_extensions.Protocol):
    '''Interface for classes that can be the destination of a log Subscription.'''

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        scope: constructs.Construct,
        source_log_group: ILogGroup,
    ) -> "LogSubscriptionDestinationConfig":
        '''Return the properties required to send subscription events to this destination.

        If necessary, the destination can use the properties of the SubscriptionFilter
        object itself to configure its permissions to allow the subscription to write
        to it.

        The destination may reconfigure its own permissions in response to this
        function call.

        :param scope: -
        :param source_log_group: -
        '''
        ...


class _ILogSubscriptionDestinationProxy:
    '''Interface for classes that can be the destination of a log Subscription.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_logs.ILogSubscriptionDestination"

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        scope: constructs.Construct,
        source_log_group: ILogGroup,
    ) -> "LogSubscriptionDestinationConfig":
        '''Return the properties required to send subscription events to this destination.

        If necessary, the destination can use the properties of the SubscriptionFilter
        object itself to configure its permissions to allow the subscription to write
        to it.

        The destination may reconfigure its own permissions in response to this
        function call.

        :param scope: -
        :param source_log_group: -
        '''
        return typing.cast("LogSubscriptionDestinationConfig", jsii.invoke(self, "bind", [scope, source_log_group]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ILogSubscriptionDestination).__jsii_proxy_class__ = lambda : _ILogSubscriptionDestinationProxy


@jsii.implements(IFilterPattern)
class JsonPattern(
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_logs.JsonPattern",
):
    '''Base class for patterns that only match JSON log events.

    :exampleMetadata: infused

    Example::

        # Search for all events where the component field is equal to
        # "HttpServer" and either error is true or the latency is higher
        # than 1000.
        pattern = logs.FilterPattern.all(
            logs.FilterPattern.string_value("$.component", "=", "HttpServer"),
            logs.FilterPattern.any(
                logs.FilterPattern.boolean_value("$.error", True),
                logs.FilterPattern.number_value("$.latency", ">", 1000)))
    '''

    def __init__(self, json_pattern_string: builtins.str) -> None:
        '''
        :param json_pattern_string: -
        '''
        jsii.create(self.__class__, self, [json_pattern_string])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="jsonPatternString")
    def json_pattern_string(self) -> builtins.str:
        return typing.cast(builtins.str, jsii.get(self, "jsonPatternString"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logPatternString")
    def log_pattern_string(self) -> builtins.str:
        return typing.cast(builtins.str, jsii.get(self, "logPatternString"))


class _JsonPatternProxy(JsonPattern):
    pass

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, JsonPattern).__jsii_proxy_class__ = lambda : _JsonPatternProxy


@jsii.implements(ILogGroup)
class LogGroup(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.LogGroup",
):
    '''Define a CloudWatch Log Group.

    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_logs as logs
        
        
        log_group = logs.LogGroup(self, "Log Group")
        log_bucket = s3.Bucket(self, "S3 Bucket")
        
        tasks.EmrContainersStartJobRun(self, "EMR Containers Start Job Run",
            virtual_cluster=tasks.VirtualClusterInput.from_virtual_cluster_id("de92jdei2910fwedz"),
            release_label=tasks.ReleaseLabel.EMR_6_2_0,
            job_driver=tasks.JobDriver(
                spark_submit_job_driver=tasks.SparkSubmitJobDriver(
                    entry_point=sfn.TaskInput.from_text("local:///usr/lib/spark/examples/src/main/python/pi.py"),
                    spark_submit_parameters="--conf spark.executor.instances=2 --conf spark.executor.memory=2G --conf spark.executor.cores=2 --conf spark.driver.cores=1"
                )
            ),
            monitoring=tasks.Monitoring(
                log_group=log_group,
                log_bucket=log_bucket
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        log_group_name: typing.Optional[builtins.str] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        retention: typing.Optional["RetentionDays"] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param encryption_key: The KMS Key to encrypt the log group with. Default: - log group is encrypted with the default master key
        :param log_group_name: Name of the log group. Default: Automatically generated
        :param removal_policy: Determine the removal policy of this log group. Normally you want to retain the log group so you can diagnose issues from logs even after a deployment that no longer includes the log group. In that case, use the normal date-based retention policy to age out your logs. Default: RemovalPolicy.Retain
        :param retention: How long, in days, the log contents will be retained. To retain all logs, set this value to RetentionDays.INFINITE. Default: RetentionDays.TWO_YEARS
        '''
        props = LogGroupProps(
            encryption_key=encryption_key,
            log_group_name=log_group_name,
            removal_policy=removal_policy,
            retention=retention,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromLogGroupArn") # type: ignore[misc]
    @builtins.classmethod
    def from_log_group_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        log_group_arn: builtins.str,
    ) -> ILogGroup:
        '''Import an existing LogGroup given its ARN.

        :param scope: -
        :param id: -
        :param log_group_arn: -
        '''
        return typing.cast(ILogGroup, jsii.sinvoke(cls, "fromLogGroupArn", [scope, id, log_group_arn]))

    @jsii.member(jsii_name="fromLogGroupName") # type: ignore[misc]
    @builtins.classmethod
    def from_log_group_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        log_group_name: builtins.str,
    ) -> ILogGroup:
        '''Import an existing LogGroup given its name.

        :param scope: -
        :param id: -
        :param log_group_name: -
        '''
        return typing.cast(ILogGroup, jsii.sinvoke(cls, "fromLogGroupName", [scope, id, log_group_name]))

    @jsii.member(jsii_name="addMetricFilter")
    def add_metric_filter(
        self,
        id: builtins.str,
        *,
        filter_pattern: IFilterPattern,
        metric_name: builtins.str,
        metric_namespace: builtins.str,
        default_value: typing.Optional[jsii.Number] = None,
        metric_value: typing.Optional[builtins.str] = None,
    ) -> "MetricFilter":
        '''Create a new Metric Filter on this Log Group.

        :param id: Unique identifier for the construct in its parent.
        :param filter_pattern: Pattern to search for log events.
        :param metric_name: The name of the metric to emit.
        :param metric_namespace: The namespace of the metric to emit.
        :param default_value: The value to emit if the pattern does not match a particular event. Default: No metric emitted.
        :param metric_value: The value to emit for the metric. Can either be a literal number (typically "1"), or the name of a field in the structure to take the value from the matched event. If you are using a field value, the field value must have been matched using the pattern. If you want to specify a field from a matched JSON structure, use '$.fieldName', and make sure the field is in the pattern (if only as '$.fieldName = *'). If you want to specify a field from a matched space-delimited structure, use '$fieldName'. Default: "1"
        '''
        props = MetricFilterOptions(
            filter_pattern=filter_pattern,
            metric_name=metric_name,
            metric_namespace=metric_namespace,
            default_value=default_value,
            metric_value=metric_value,
        )

        return typing.cast("MetricFilter", jsii.invoke(self, "addMetricFilter", [id, props]))

    @jsii.member(jsii_name="addStream")
    def add_stream(
        self,
        id: builtins.str,
        *,
        log_stream_name: typing.Optional[builtins.str] = None,
    ) -> "LogStream":
        '''Create a new Log Stream for this Log Group.

        :param id: Unique identifier for the construct in its parent.
        :param log_stream_name: The name of the log stream to create. The name must be unique within the log group. Default: Automatically generated
        '''
        props = StreamOptions(log_stream_name=log_stream_name)

        return typing.cast("LogStream", jsii.invoke(self, "addStream", [id, props]))

    @jsii.member(jsii_name="addSubscriptionFilter")
    def add_subscription_filter(
        self,
        id: builtins.str,
        *,
        destination: ILogSubscriptionDestination,
        filter_pattern: IFilterPattern,
    ) -> "SubscriptionFilter":
        '''Create a new Subscription Filter on this Log Group.

        :param id: Unique identifier for the construct in its parent.
        :param destination: The destination to send the filtered events to. For example, a Kinesis stream or a Lambda function.
        :param filter_pattern: Log events matching this pattern will be sent to the destination.
        '''
        props = SubscriptionFilterOptions(
            destination=destination, filter_pattern=filter_pattern
        )

        return typing.cast("SubscriptionFilter", jsii.invoke(self, "addSubscriptionFilter", [id, props]))

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        statement: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Adds a statement to the resource policy associated with this log group.

        A resource policy will be automatically created upon the first call to ``addToResourcePolicy``.

        :param statement: The policy statement to add.
        '''
        return typing.cast(_AddToResourcePolicyResult_1d0a53ad, jsii.invoke(self, "addToResourcePolicy", [statement]))

    @jsii.member(jsii_name="extractMetric")
    def extract_metric(
        self,
        json_field: builtins.str,
        metric_namespace: builtins.str,
        metric_name: builtins.str,
    ) -> _Metric_e396a4dc:
        '''Extract a metric from structured log events in the LogGroup.

        Creates a MetricFilter on this LogGroup that will extract the value
        of the indicated JSON field in all records where it occurs.

        The metric will be available in CloudWatch Metrics under the
        indicated namespace and name.

        :param json_field: JSON field to extract (example: '$.myfield').
        :param metric_namespace: Namespace to emit the metric under.
        :param metric_name: Name to emit the metric under.

        :return: A Metric object representing the extracted metric
        '''
        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "extractMetric", [json_field, metric_namespace, metric_name]))

    @jsii.member(jsii_name="grant")
    def grant(
        self,
        grantee: _IGrantable_71c4f5de,
        *actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Give the indicated permissions on this log group and all streams.

        :param grantee: -
        :param actions: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grant", [grantee, *actions]))

    @jsii.member(jsii_name="grantWrite")
    def grant_write(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Give permissions to create and write to streams in this log group.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantWrite", [grantee]))

    @jsii.member(jsii_name="logGroupPhysicalName")
    def log_group_physical_name(self) -> builtins.str:
        '''Public method to get the physical name of this log group.

        :return: Physical name of log group
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "logGroupPhysicalName", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logGroupArn")
    def log_group_arn(self) -> builtins.str:
        '''The ARN of this log group.'''
        return typing.cast(builtins.str, jsii.get(self, "logGroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logGroupName")
    def log_group_name(self) -> builtins.str:
        '''The name of this log group.'''
        return typing.cast(builtins.str, jsii.get(self, "logGroupName"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.LogGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "encryption_key": "encryptionKey",
        "log_group_name": "logGroupName",
        "removal_policy": "removalPolicy",
        "retention": "retention",
    },
)
class LogGroupProps:
    def __init__(
        self,
        *,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        log_group_name: typing.Optional[builtins.str] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        retention: typing.Optional["RetentionDays"] = None,
    ) -> None:
        '''Properties for a LogGroup.

        :param encryption_key: The KMS Key to encrypt the log group with. Default: - log group is encrypted with the default master key
        :param log_group_name: Name of the log group. Default: Automatically generated
        :param removal_policy: Determine the removal policy of this log group. Normally you want to retain the log group so you can diagnose issues from logs even after a deployment that no longer includes the log group. In that case, use the normal date-based retention policy to age out your logs. Default: RemovalPolicy.Retain
        :param retention: How long, in days, the log contents will be retained. To retain all logs, set this value to RetentionDays.INFINITE. Default: RetentionDays.TWO_YEARS

        :exampleMetadata: infused

        Example::

            # vpc: ec2.Vpc
            
            kms_key = kms.Key(self, "KmsKey")
            
            # Pass the KMS key in the `encryptionKey` field to associate the key to the log group
            log_group = logs.LogGroup(self, "LogGroup",
                encryption_key=kms_key
            )
            
            # Pass the KMS key in the `encryptionKey` field to associate the key to the S3 bucket
            exec_bucket = s3.Bucket(self, "EcsExecBucket",
                encryption_key=kms_key
            )
            
            cluster = ecs.Cluster(self, "Cluster",
                vpc=vpc,
                execute_command_configuration=ecs.ExecuteCommandConfiguration(
                    kms_key=kms_key,
                    log_configuration=ecs.ExecuteCommandLogConfiguration(
                        cloud_watch_log_group=log_group,
                        cloud_watch_encryption_enabled=True,
                        s3_bucket=exec_bucket,
                        s3_encryption_enabled=True,
                        s3_key_prefix="exec-command-output"
                    ),
                    logging=ecs.ExecuteCommandLogging.OVERRIDE
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if encryption_key is not None:
            self._values["encryption_key"] = encryption_key
        if log_group_name is not None:
            self._values["log_group_name"] = log_group_name
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy
        if retention is not None:
            self._values["retention"] = retention

    @builtins.property
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''The KMS Key to encrypt the log group with.

        :default: - log group is encrypted with the default master key
        '''
        result = self._values.get("encryption_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def log_group_name(self) -> typing.Optional[builtins.str]:
        '''Name of the log group.

        :default: Automatically generated
        '''
        result = self._values.get("log_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''Determine the removal policy of this log group.

        Normally you want to retain the log group so you can diagnose issues
        from logs even after a deployment that no longer includes the log group.
        In that case, use the normal date-based retention policy to age out your
        logs.

        :default: RemovalPolicy.Retain
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    @builtins.property
    def retention(self) -> typing.Optional["RetentionDays"]:
        '''How long, in days, the log contents will be retained.

        To retain all logs, set this value to RetentionDays.INFINITE.

        :default: RetentionDays.TWO_YEARS
        '''
        result = self._values.get("retention")
        return typing.cast(typing.Optional["RetentionDays"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LogGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class LogRetention(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.LogRetention",
):
    '''Creates a custom resource to control the retention policy of a CloudWatch Logs log group.

    The log group is created if it doesn't already exist. The policy
    is removed when ``retentionDays`` is ``undefined`` or equal to ``Infinity``.
    Log group can be created in the region that is different from stack region by
    specifying ``logGroupRegion``

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_iam as iam
        from aws_cdk import aws_logs as logs
        
        # role: iam.Role
        
        log_retention = logs.LogRetention(self, "MyLogRetention",
            log_group_name="logGroupName",
            retention=logs.RetentionDays.ONE_DAY,
        
            # the properties below are optional
            log_group_region="logGroupRegion",
            log_retention_retry_options=logs.LogRetentionRetryOptions(
                base=cdk.Duration.minutes(30),
                max_retries=123
            ),
            role=role
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        log_group_name: builtins.str,
        retention: "RetentionDays",
        log_group_region: typing.Optional[builtins.str] = None,
        log_retention_retry_options: typing.Optional["LogRetentionRetryOptions"] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param log_group_name: The log group name.
        :param retention: The number of days log events are kept in CloudWatch Logs.
        :param log_group_region: The region where the log group should be created. Default: - same region as the stack
        :param log_retention_retry_options: Retry options for all AWS API calls. Default: - AWS SDK default retry options
        :param role: The IAM role for the Lambda function associated with the custom resource. Default: - A new role is created
        '''
        props = LogRetentionProps(
            log_group_name=log_group_name,
            retention=retention,
            log_group_region=log_group_region,
            log_retention_retry_options=log_retention_retry_options,
            role=role,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logGroupArn")
    def log_group_arn(self) -> builtins.str:
        '''The ARN of the LogGroup.'''
        return typing.cast(builtins.str, jsii.get(self, "logGroupArn"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.LogRetentionProps",
    jsii_struct_bases=[],
    name_mapping={
        "log_group_name": "logGroupName",
        "retention": "retention",
        "log_group_region": "logGroupRegion",
        "log_retention_retry_options": "logRetentionRetryOptions",
        "role": "role",
    },
)
class LogRetentionProps:
    def __init__(
        self,
        *,
        log_group_name: builtins.str,
        retention: "RetentionDays",
        log_group_region: typing.Optional[builtins.str] = None,
        log_retention_retry_options: typing.Optional["LogRetentionRetryOptions"] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> None:
        '''Construction properties for a LogRetention.

        :param log_group_name: The log group name.
        :param retention: The number of days log events are kept in CloudWatch Logs.
        :param log_group_region: The region where the log group should be created. Default: - same region as the stack
        :param log_retention_retry_options: Retry options for all AWS API calls. Default: - AWS SDK default retry options
        :param role: The IAM role for the Lambda function associated with the custom resource. Default: - A new role is created

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_iam as iam
            from aws_cdk import aws_logs as logs
            
            # role: iam.Role
            
            log_retention_props = logs.LogRetentionProps(
                log_group_name="logGroupName",
                retention=logs.RetentionDays.ONE_DAY,
            
                # the properties below are optional
                log_group_region="logGroupRegion",
                log_retention_retry_options=logs.LogRetentionRetryOptions(
                    base=cdk.Duration.minutes(30),
                    max_retries=123
                ),
                role=role
            )
        '''
        if isinstance(log_retention_retry_options, dict):
            log_retention_retry_options = LogRetentionRetryOptions(**log_retention_retry_options)
        self._values: typing.Dict[str, typing.Any] = {
            "log_group_name": log_group_name,
            "retention": retention,
        }
        if log_group_region is not None:
            self._values["log_group_region"] = log_group_region
        if log_retention_retry_options is not None:
            self._values["log_retention_retry_options"] = log_retention_retry_options
        if role is not None:
            self._values["role"] = role

    @builtins.property
    def log_group_name(self) -> builtins.str:
        '''The log group name.'''
        result = self._values.get("log_group_name")
        assert result is not None, "Required property 'log_group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def retention(self) -> "RetentionDays":
        '''The number of days log events are kept in CloudWatch Logs.'''
        result = self._values.get("retention")
        assert result is not None, "Required property 'retention' is missing"
        return typing.cast("RetentionDays", result)

    @builtins.property
    def log_group_region(self) -> typing.Optional[builtins.str]:
        '''The region where the log group should be created.

        :default: - same region as the stack
        '''
        result = self._values.get("log_group_region")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def log_retention_retry_options(
        self,
    ) -> typing.Optional["LogRetentionRetryOptions"]:
        '''Retry options for all AWS API calls.

        :default: - AWS SDK default retry options
        '''
        result = self._values.get("log_retention_retry_options")
        return typing.cast(typing.Optional["LogRetentionRetryOptions"], result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The IAM role for the Lambda function associated with the custom resource.

        :default: - A new role is created
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LogRetentionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.LogRetentionRetryOptions",
    jsii_struct_bases=[],
    name_mapping={"base": "base", "max_retries": "maxRetries"},
)
class LogRetentionRetryOptions:
    def __init__(
        self,
        *,
        base: typing.Optional[_Duration_4839e8c3] = None,
        max_retries: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Retry options for all AWS API calls.

        :param base: The base duration to use in the exponential backoff for operation retries. Default: Duration.millis(100) (AWS SDK default)
        :param max_retries: The maximum amount of retries. Default: 3 (AWS SDK default)

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_logs as logs
            
            log_retention_retry_options = logs.LogRetentionRetryOptions(
                base=cdk.Duration.minutes(30),
                max_retries=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if base is not None:
            self._values["base"] = base
        if max_retries is not None:
            self._values["max_retries"] = max_retries

    @builtins.property
    def base(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The base duration to use in the exponential backoff for operation retries.

        :default: Duration.millis(100) (AWS SDK default)
        '''
        result = self._values.get("base")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def max_retries(self) -> typing.Optional[jsii.Number]:
        '''The maximum amount of retries.

        :default: 3 (AWS SDK default)
        '''
        result = self._values.get("max_retries")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LogRetentionRetryOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(ILogStream)
class LogStream(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.LogStream",
):
    '''Define a Log Stream in a Log Group.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_logs as logs
        
        # log_group: logs.LogGroup
        
        log_stream = logs.LogStream(self, "MyLogStream",
            log_group=log_group,
        
            # the properties below are optional
            log_stream_name="logStreamName",
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        log_group: ILogGroup,
        log_stream_name: typing.Optional[builtins.str] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param log_group: The log group to create a log stream for.
        :param log_stream_name: The name of the log stream to create. The name must be unique within the log group. Default: Automatically generated
        :param removal_policy: Determine what happens when the log stream resource is removed from the app. Normally you want to retain the log stream so you can diagnose issues from logs even after a deployment that no longer includes the log stream. The date-based retention policy of your log group will age out the logs after a certain time. Default: RemovalPolicy.Retain
        '''
        props = LogStreamProps(
            log_group=log_group,
            log_stream_name=log_stream_name,
            removal_policy=removal_policy,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromLogStreamName") # type: ignore[misc]
    @builtins.classmethod
    def from_log_stream_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        log_stream_name: builtins.str,
    ) -> ILogStream:
        '''Import an existing LogGroup.

        :param scope: -
        :param id: -
        :param log_stream_name: -
        '''
        return typing.cast(ILogStream, jsii.sinvoke(cls, "fromLogStreamName", [scope, id, log_stream_name]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logStreamName")
    def log_stream_name(self) -> builtins.str:
        '''The name of this log stream.'''
        return typing.cast(builtins.str, jsii.get(self, "logStreamName"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.LogStreamProps",
    jsii_struct_bases=[],
    name_mapping={
        "log_group": "logGroup",
        "log_stream_name": "logStreamName",
        "removal_policy": "removalPolicy",
    },
)
class LogStreamProps:
    def __init__(
        self,
        *,
        log_group: ILogGroup,
        log_stream_name: typing.Optional[builtins.str] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
    ) -> None:
        '''Properties for a LogStream.

        :param log_group: The log group to create a log stream for.
        :param log_stream_name: The name of the log stream to create. The name must be unique within the log group. Default: Automatically generated
        :param removal_policy: Determine what happens when the log stream resource is removed from the app. Normally you want to retain the log stream so you can diagnose issues from logs even after a deployment that no longer includes the log stream. The date-based retention policy of your log group will age out the logs after a certain time. Default: RemovalPolicy.Retain

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_logs as logs
            
            # log_group: logs.LogGroup
            
            log_stream_props = logs.LogStreamProps(
                log_group=log_group,
            
                # the properties below are optional
                log_stream_name="logStreamName",
                removal_policy=cdk.RemovalPolicy.DESTROY
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "log_group": log_group,
        }
        if log_stream_name is not None:
            self._values["log_stream_name"] = log_stream_name
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy

    @builtins.property
    def log_group(self) -> ILogGroup:
        '''The log group to create a log stream for.'''
        result = self._values.get("log_group")
        assert result is not None, "Required property 'log_group' is missing"
        return typing.cast(ILogGroup, result)

    @builtins.property
    def log_stream_name(self) -> typing.Optional[builtins.str]:
        '''The name of the log stream to create.

        The name must be unique within the log group.

        :default: Automatically generated
        '''
        result = self._values.get("log_stream_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''Determine what happens when the log stream resource is removed from the app.

        Normally you want to retain the log stream so you can diagnose issues from
        logs even after a deployment that no longer includes the log stream.

        The date-based retention policy of your log group will age out the logs
        after a certain time.

        :default: RemovalPolicy.Retain
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LogStreamProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.LogSubscriptionDestinationConfig",
    jsii_struct_bases=[],
    name_mapping={"arn": "arn", "role": "role"},
)
class LogSubscriptionDestinationConfig:
    def __init__(
        self,
        *,
        arn: builtins.str,
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> None:
        '''Properties returned by a Subscription destination.

        :param arn: The ARN of the subscription's destination.
        :param role: The role to assume to write log events to the destination. Default: No role assumed

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            from aws_cdk import aws_logs as logs
            
            # role: iam.Role
            
            log_subscription_destination_config = logs.LogSubscriptionDestinationConfig(
                arn="arn",
            
                # the properties below are optional
                role=role
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "arn": arn,
        }
        if role is not None:
            self._values["role"] = role

    @builtins.property
    def arn(self) -> builtins.str:
        '''The ARN of the subscription's destination.'''
        result = self._values.get("arn")
        assert result is not None, "Required property 'arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The role to assume to write log events to the destination.

        :default: No role assumed
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LogSubscriptionDestinationConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class MetricFilter(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.MetricFilter",
):
    '''A filter that extracts information from CloudWatch Logs and emits to CloudWatch Metrics.

    :exampleMetadata: lit=aws-logs/test/integ.metricfilter.lit.ts infused

    Example::

        MetricFilter(self, "MetricFilter",
            log_group=log_group,
            metric_namespace="MyApp",
            metric_name="Latency",
            filter_pattern=FilterPattern.exists("$.latency"),
            metric_value="$.latency"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        log_group: ILogGroup,
        filter_pattern: IFilterPattern,
        metric_name: builtins.str,
        metric_namespace: builtins.str,
        default_value: typing.Optional[jsii.Number] = None,
        metric_value: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param log_group: The log group to create the filter on.
        :param filter_pattern: Pattern to search for log events.
        :param metric_name: The name of the metric to emit.
        :param metric_namespace: The namespace of the metric to emit.
        :param default_value: The value to emit if the pattern does not match a particular event. Default: No metric emitted.
        :param metric_value: The value to emit for the metric. Can either be a literal number (typically "1"), or the name of a field in the structure to take the value from the matched event. If you are using a field value, the field value must have been matched using the pattern. If you want to specify a field from a matched JSON structure, use '$.fieldName', and make sure the field is in the pattern (if only as '$.fieldName = *'). If you want to specify a field from a matched space-delimited structure, use '$fieldName'. Default: "1"
        '''
        props = MetricFilterProps(
            log_group=log_group,
            filter_pattern=filter_pattern,
            metric_name=metric_name,
            metric_namespace=metric_namespace,
            default_value=default_value,
            metric_value=metric_value,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="metric")
    def metric(
        self,
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
        '''Return the given named metric for this Metric Filter.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: avg over 5 minutes
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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metric", [props]))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.MetricFilterOptions",
    jsii_struct_bases=[],
    name_mapping={
        "filter_pattern": "filterPattern",
        "metric_name": "metricName",
        "metric_namespace": "metricNamespace",
        "default_value": "defaultValue",
        "metric_value": "metricValue",
    },
)
class MetricFilterOptions:
    def __init__(
        self,
        *,
        filter_pattern: IFilterPattern,
        metric_name: builtins.str,
        metric_namespace: builtins.str,
        default_value: typing.Optional[jsii.Number] = None,
        metric_value: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for a MetricFilter created from a LogGroup.

        :param filter_pattern: Pattern to search for log events.
        :param metric_name: The name of the metric to emit.
        :param metric_namespace: The namespace of the metric to emit.
        :param default_value: The value to emit if the pattern does not match a particular event. Default: No metric emitted.
        :param metric_value: The value to emit for the metric. Can either be a literal number (typically "1"), or the name of a field in the structure to take the value from the matched event. If you are using a field value, the field value must have been matched using the pattern. If you want to specify a field from a matched JSON structure, use '$.fieldName', and make sure the field is in the pattern (if only as '$.fieldName = *'). If you want to specify a field from a matched space-delimited structure, use '$fieldName'. Default: "1"

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_logs as logs
            
            # filter_pattern: logs.IFilterPattern
            
            metric_filter_options = logs.MetricFilterOptions(
                filter_pattern=filter_pattern,
                metric_name="metricName",
                metric_namespace="metricNamespace",
            
                # the properties below are optional
                default_value=123,
                metric_value="metricValue"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "filter_pattern": filter_pattern,
            "metric_name": metric_name,
            "metric_namespace": metric_namespace,
        }
        if default_value is not None:
            self._values["default_value"] = default_value
        if metric_value is not None:
            self._values["metric_value"] = metric_value

    @builtins.property
    def filter_pattern(self) -> IFilterPattern:
        '''Pattern to search for log events.'''
        result = self._values.get("filter_pattern")
        assert result is not None, "Required property 'filter_pattern' is missing"
        return typing.cast(IFilterPattern, result)

    @builtins.property
    def metric_name(self) -> builtins.str:
        '''The name of the metric to emit.'''
        result = self._values.get("metric_name")
        assert result is not None, "Required property 'metric_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def metric_namespace(self) -> builtins.str:
        '''The namespace of the metric to emit.'''
        result = self._values.get("metric_namespace")
        assert result is not None, "Required property 'metric_namespace' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def default_value(self) -> typing.Optional[jsii.Number]:
        '''The value to emit if the pattern does not match a particular event.

        :default: No metric emitted.
        '''
        result = self._values.get("default_value")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def metric_value(self) -> typing.Optional[builtins.str]:
        '''The value to emit for the metric.

        Can either be a literal number (typically "1"), or the name of a field in the structure
        to take the value from the matched event. If you are using a field value, the field
        value must have been matched using the pattern.

        If you want to specify a field from a matched JSON structure, use '$.fieldName',
        and make sure the field is in the pattern (if only as '$.fieldName = *').

        If you want to specify a field from a matched space-delimited structure,
        use '$fieldName'.

        :default: "1"
        '''
        result = self._values.get("metric_value")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "MetricFilterOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.MetricFilterProps",
    jsii_struct_bases=[MetricFilterOptions],
    name_mapping={
        "filter_pattern": "filterPattern",
        "metric_name": "metricName",
        "metric_namespace": "metricNamespace",
        "default_value": "defaultValue",
        "metric_value": "metricValue",
        "log_group": "logGroup",
    },
)
class MetricFilterProps(MetricFilterOptions):
    def __init__(
        self,
        *,
        filter_pattern: IFilterPattern,
        metric_name: builtins.str,
        metric_namespace: builtins.str,
        default_value: typing.Optional[jsii.Number] = None,
        metric_value: typing.Optional[builtins.str] = None,
        log_group: ILogGroup,
    ) -> None:
        '''Properties for a MetricFilter.

        :param filter_pattern: Pattern to search for log events.
        :param metric_name: The name of the metric to emit.
        :param metric_namespace: The namespace of the metric to emit.
        :param default_value: The value to emit if the pattern does not match a particular event. Default: No metric emitted.
        :param metric_value: The value to emit for the metric. Can either be a literal number (typically "1"), or the name of a field in the structure to take the value from the matched event. If you are using a field value, the field value must have been matched using the pattern. If you want to specify a field from a matched JSON structure, use '$.fieldName', and make sure the field is in the pattern (if only as '$.fieldName = *'). If you want to specify a field from a matched space-delimited structure, use '$fieldName'. Default: "1"
        :param log_group: The log group to create the filter on.

        :exampleMetadata: lit=aws-logs/test/integ.metricfilter.lit.ts infused

        Example::

            MetricFilter(self, "MetricFilter",
                log_group=log_group,
                metric_namespace="MyApp",
                metric_name="Latency",
                filter_pattern=FilterPattern.exists("$.latency"),
                metric_value="$.latency"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "filter_pattern": filter_pattern,
            "metric_name": metric_name,
            "metric_namespace": metric_namespace,
            "log_group": log_group,
        }
        if default_value is not None:
            self._values["default_value"] = default_value
        if metric_value is not None:
            self._values["metric_value"] = metric_value

    @builtins.property
    def filter_pattern(self) -> IFilterPattern:
        '''Pattern to search for log events.'''
        result = self._values.get("filter_pattern")
        assert result is not None, "Required property 'filter_pattern' is missing"
        return typing.cast(IFilterPattern, result)

    @builtins.property
    def metric_name(self) -> builtins.str:
        '''The name of the metric to emit.'''
        result = self._values.get("metric_name")
        assert result is not None, "Required property 'metric_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def metric_namespace(self) -> builtins.str:
        '''The namespace of the metric to emit.'''
        result = self._values.get("metric_namespace")
        assert result is not None, "Required property 'metric_namespace' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def default_value(self) -> typing.Optional[jsii.Number]:
        '''The value to emit if the pattern does not match a particular event.

        :default: No metric emitted.
        '''
        result = self._values.get("default_value")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def metric_value(self) -> typing.Optional[builtins.str]:
        '''The value to emit for the metric.

        Can either be a literal number (typically "1"), or the name of a field in the structure
        to take the value from the matched event. If you are using a field value, the field
        value must have been matched using the pattern.

        If you want to specify a field from a matched JSON structure, use '$.fieldName',
        and make sure the field is in the pattern (if only as '$.fieldName = *').

        If you want to specify a field from a matched space-delimited structure,
        use '$fieldName'.

        :default: "1"
        '''
        result = self._values.get("metric_value")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def log_group(self) -> ILogGroup:
        '''The log group to create the filter on.'''
        result = self._values.get("log_group")
        assert result is not None, "Required property 'log_group' is missing"
        return typing.cast(ILogGroup, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "MetricFilterProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class ResourcePolicy(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.ResourcePolicy",
):
    '''Resource Policy for CloudWatch Log Groups.

    Policies define the operations that are allowed on this resource.

    You almost never need to define this construct directly.

    All AWS resources that support resource policies have a method called
    ``addToResourcePolicy()``, which will automatically create a new resource
    policy if one doesn't exist yet, otherwise it will add to the existing
    policy.

    Prefer to use ``addToResourcePolicy()`` instead.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        from aws_cdk import aws_logs as logs
        
        # policy_statement: iam.PolicyStatement
        
        resource_policy = logs.ResourcePolicy(self, "MyResourcePolicy",
            policy_statements=[policy_statement],
            resource_policy_name="resourcePolicyName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        policy_statements: typing.Optional[typing.Sequence[_PolicyStatement_0fe33853]] = None,
        resource_policy_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param policy_statements: Initial statements to add to the resource policy. Default: - No statements
        :param resource_policy_name: Name of the log group resource policy. Default: - Uses a unique id based on the construct path
        '''
        props = ResourcePolicyProps(
            policy_statements=policy_statements,
            resource_policy_name=resource_policy_name,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="document")
    def document(self) -> _PolicyDocument_3ac34393:
        '''The IAM policy document for this resource policy.'''
        return typing.cast(_PolicyDocument_3ac34393, jsii.get(self, "document"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.ResourcePolicyProps",
    jsii_struct_bases=[],
    name_mapping={
        "policy_statements": "policyStatements",
        "resource_policy_name": "resourcePolicyName",
    },
)
class ResourcePolicyProps:
    def __init__(
        self,
        *,
        policy_statements: typing.Optional[typing.Sequence[_PolicyStatement_0fe33853]] = None,
        resource_policy_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties to define Cloudwatch log group resource policy.

        :param policy_statements: Initial statements to add to the resource policy. Default: - No statements
        :param resource_policy_name: Name of the log group resource policy. Default: - Uses a unique id based on the construct path

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            from aws_cdk import aws_logs as logs
            
            # policy_statement: iam.PolicyStatement
            
            resource_policy_props = logs.ResourcePolicyProps(
                policy_statements=[policy_statement],
                resource_policy_name="resourcePolicyName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if policy_statements is not None:
            self._values["policy_statements"] = policy_statements
        if resource_policy_name is not None:
            self._values["resource_policy_name"] = resource_policy_name

    @builtins.property
    def policy_statements(
        self,
    ) -> typing.Optional[typing.List[_PolicyStatement_0fe33853]]:
        '''Initial statements to add to the resource policy.

        :default: - No statements
        '''
        result = self._values.get("policy_statements")
        return typing.cast(typing.Optional[typing.List[_PolicyStatement_0fe33853]], result)

    @builtins.property
    def resource_policy_name(self) -> typing.Optional[builtins.str]:
        '''Name of the log group resource policy.

        :default: - Uses a unique id based on the construct path
        '''
        result = self._values.get("resource_policy_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ResourcePolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_logs.RetentionDays")
class RetentionDays(enum.Enum):
    '''How long, in days, the log contents will be retained.

    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_logs as logs
        # my_logs_publishing_role: iam.Role
        # vpc: ec2.Vpc
        
        
        # Exporting logs from a cluster
        cluster = rds.DatabaseCluster(self, "Database",
            engine=rds.DatabaseClusterEngine.aurora(
                version=rds.AuroraEngineVersion.VER_1_17_9
            ),
            instance_props=rds.InstanceProps(
                vpc=vpc
            ),
            cloudwatch_logs_exports=["error", "general", "slowquery", "audit"],  # Export all available MySQL-based logs
            cloudwatch_logs_retention=logs.RetentionDays.THREE_MONTHS,  # Optional - default is to never expire logs
            cloudwatch_logs_retention_role=my_logs_publishing_role
        )
        
        # Exporting logs from an instance
        instance = rds.DatabaseInstance(self, "Instance",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_12_3
            ),
            vpc=vpc,
            cloudwatch_logs_exports=["postgresql"]
        )
    '''

    ONE_DAY = "ONE_DAY"
    '''1 day.'''
    THREE_DAYS = "THREE_DAYS"
    '''3 days.'''
    FIVE_DAYS = "FIVE_DAYS"
    '''5 days.'''
    ONE_WEEK = "ONE_WEEK"
    '''1 week.'''
    TWO_WEEKS = "TWO_WEEKS"
    '''2 weeks.'''
    ONE_MONTH = "ONE_MONTH"
    '''1 month.'''
    TWO_MONTHS = "TWO_MONTHS"
    '''2 months.'''
    THREE_MONTHS = "THREE_MONTHS"
    '''3 months.'''
    FOUR_MONTHS = "FOUR_MONTHS"
    '''4 months.'''
    FIVE_MONTHS = "FIVE_MONTHS"
    '''5 months.'''
    SIX_MONTHS = "SIX_MONTHS"
    '''6 months.'''
    ONE_YEAR = "ONE_YEAR"
    '''1 year.'''
    THIRTEEN_MONTHS = "THIRTEEN_MONTHS"
    '''13 months.'''
    EIGHTEEN_MONTHS = "EIGHTEEN_MONTHS"
    '''18 months.'''
    TWO_YEARS = "TWO_YEARS"
    '''2 years.'''
    FIVE_YEARS = "FIVE_YEARS"
    '''5 years.'''
    TEN_YEARS = "TEN_YEARS"
    '''10 years.'''
    INFINITE = "INFINITE"
    '''Retain logs forever.'''


@jsii.implements(IFilterPattern)
class SpaceDelimitedTextPattern(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.SpaceDelimitedTextPattern",
):
    '''Space delimited text pattern.

    :exampleMetadata: infused

    Example::

        # Search for all events where the component is "HttpServer" and the
        # result code is not equal to 200.
        pattern = logs.FilterPattern.space_delimited("time", "component", "...", "result_code", "latency").where_string("component", "=", "HttpServer").where_number("result_code", "!=", 200)
    '''

    def __init__(
        self,
        columns: typing.Sequence[builtins.str],
        restrictions: typing.Mapping[builtins.str, typing.Sequence[ColumnRestriction]],
    ) -> None:
        '''
        :param columns: -
        :param restrictions: -
        '''
        jsii.create(self.__class__, self, [columns, restrictions])

    @jsii.member(jsii_name="construct") # type: ignore[misc]
    @builtins.classmethod
    def construct(
        cls,
        columns: typing.Sequence[builtins.str],
    ) -> "SpaceDelimitedTextPattern":
        '''Construct a new instance of a space delimited text pattern.

        Since this class must be public, we can't rely on the user only creating it through
        the ``LogPattern.spaceDelimited()`` factory function. We must therefore validate the
        argument in the constructor. Since we're returning a copy on every mutation, and we
        don't want to re-validate the same things on every construction, we provide a limited
        set of mutator functions and only validate the new data every time.

        :param columns: -
        '''
        return typing.cast("SpaceDelimitedTextPattern", jsii.sinvoke(cls, "construct", [columns]))

    @jsii.member(jsii_name="whereNumber")
    def where_number(
        self,
        column_name: builtins.str,
        comparison: builtins.str,
        value: jsii.Number,
    ) -> "SpaceDelimitedTextPattern":
        '''Restrict where the pattern applies.

        :param column_name: -
        :param comparison: -
        :param value: -
        '''
        return typing.cast("SpaceDelimitedTextPattern", jsii.invoke(self, "whereNumber", [column_name, comparison, value]))

    @jsii.member(jsii_name="whereString")
    def where_string(
        self,
        column_name: builtins.str,
        comparison: builtins.str,
        value: builtins.str,
    ) -> "SpaceDelimitedTextPattern":
        '''Restrict where the pattern applies.

        :param column_name: -
        :param comparison: -
        :param value: -
        '''
        return typing.cast("SpaceDelimitedTextPattern", jsii.invoke(self, "whereString", [column_name, comparison, value]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logPatternString")
    def log_pattern_string(self) -> builtins.str:
        return typing.cast(builtins.str, jsii.get(self, "logPatternString"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.StreamOptions",
    jsii_struct_bases=[],
    name_mapping={"log_stream_name": "logStreamName"},
)
class StreamOptions:
    def __init__(
        self,
        *,
        log_stream_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for a new LogStream created from a LogGroup.

        :param log_stream_name: The name of the log stream to create. The name must be unique within the log group. Default: Automatically generated

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_logs as logs
            
            stream_options = logs.StreamOptions(
                log_stream_name="logStreamName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if log_stream_name is not None:
            self._values["log_stream_name"] = log_stream_name

    @builtins.property
    def log_stream_name(self) -> typing.Optional[builtins.str]:
        '''The name of the log stream to create.

        The name must be unique within the log group.

        :default: Automatically generated
        '''
        result = self._values.get("log_stream_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StreamOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class SubscriptionFilter(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.SubscriptionFilter",
):
    '''A new Subscription on a CloudWatch log group.

    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_logs_destinations as destinations
        # fn: lambda.Function
        # log_group: logs.LogGroup
        
        
        logs.SubscriptionFilter(self, "Subscription",
            log_group=log_group,
            destination=destinations.LambdaDestination(fn),
            filter_pattern=logs.FilterPattern.all_terms("ERROR", "MainThread")
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        log_group: ILogGroup,
        destination: ILogSubscriptionDestination,
        filter_pattern: IFilterPattern,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param log_group: The log group to create the subscription on.
        :param destination: The destination to send the filtered events to. For example, a Kinesis stream or a Lambda function.
        :param filter_pattern: Log events matching this pattern will be sent to the destination.
        '''
        props = SubscriptionFilterProps(
            log_group=log_group, destination=destination, filter_pattern=filter_pattern
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.SubscriptionFilterOptions",
    jsii_struct_bases=[],
    name_mapping={"destination": "destination", "filter_pattern": "filterPattern"},
)
class SubscriptionFilterOptions:
    def __init__(
        self,
        *,
        destination: ILogSubscriptionDestination,
        filter_pattern: IFilterPattern,
    ) -> None:
        '''Properties for a new SubscriptionFilter created from a LogGroup.

        :param destination: The destination to send the filtered events to. For example, a Kinesis stream or a Lambda function.
        :param filter_pattern: Log events matching this pattern will be sent to the destination.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_logs as logs
            
            # filter_pattern: logs.IFilterPattern
            # log_subscription_destination: logs.ILogSubscriptionDestination
            
            subscription_filter_options = logs.SubscriptionFilterOptions(
                destination=log_subscription_destination,
                filter_pattern=filter_pattern
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "destination": destination,
            "filter_pattern": filter_pattern,
        }

    @builtins.property
    def destination(self) -> ILogSubscriptionDestination:
        '''The destination to send the filtered events to.

        For example, a Kinesis stream or a Lambda function.
        '''
        result = self._values.get("destination")
        assert result is not None, "Required property 'destination' is missing"
        return typing.cast(ILogSubscriptionDestination, result)

    @builtins.property
    def filter_pattern(self) -> IFilterPattern:
        '''Log events matching this pattern will be sent to the destination.'''
        result = self._values.get("filter_pattern")
        assert result is not None, "Required property 'filter_pattern' is missing"
        return typing.cast(IFilterPattern, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SubscriptionFilterOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_logs.SubscriptionFilterProps",
    jsii_struct_bases=[SubscriptionFilterOptions],
    name_mapping={
        "destination": "destination",
        "filter_pattern": "filterPattern",
        "log_group": "logGroup",
    },
)
class SubscriptionFilterProps(SubscriptionFilterOptions):
    def __init__(
        self,
        *,
        destination: ILogSubscriptionDestination,
        filter_pattern: IFilterPattern,
        log_group: ILogGroup,
    ) -> None:
        '''Properties for a SubscriptionFilter.

        :param destination: The destination to send the filtered events to. For example, a Kinesis stream or a Lambda function.
        :param filter_pattern: Log events matching this pattern will be sent to the destination.
        :param log_group: The log group to create the subscription on.

        :exampleMetadata: infused

        Example::

            import aws_cdk.aws_logs_destinations as destinations
            # fn: lambda.Function
            # log_group: logs.LogGroup
            
            
            logs.SubscriptionFilter(self, "Subscription",
                log_group=log_group,
                destination=destinations.LambdaDestination(fn),
                filter_pattern=logs.FilterPattern.all_terms("ERROR", "MainThread")
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "destination": destination,
            "filter_pattern": filter_pattern,
            "log_group": log_group,
        }

    @builtins.property
    def destination(self) -> ILogSubscriptionDestination:
        '''The destination to send the filtered events to.

        For example, a Kinesis stream or a Lambda function.
        '''
        result = self._values.get("destination")
        assert result is not None, "Required property 'destination' is missing"
        return typing.cast(ILogSubscriptionDestination, result)

    @builtins.property
    def filter_pattern(self) -> IFilterPattern:
        '''Log events matching this pattern will be sent to the destination.'''
        result = self._values.get("filter_pattern")
        assert result is not None, "Required property 'filter_pattern' is missing"
        return typing.cast(IFilterPattern, result)

    @builtins.property
    def log_group(self) -> ILogGroup:
        '''The log group to create the subscription on.'''
        result = self._values.get("log_group")
        assert result is not None, "Required property 'log_group' is missing"
        return typing.cast(ILogGroup, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SubscriptionFilterProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(ILogSubscriptionDestination)
class CrossAccountDestination(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_logs.CrossAccountDestination",
):
    '''A new CloudWatch Logs Destination for use in cross-account scenarios.

    CrossAccountDestinations are used to subscribe a Kinesis stream in a
    different account to a CloudWatch Subscription.

    Consumers will hardly ever need to use this class. Instead, directly
    subscribe a Kinesis stream using the integration class in the
    ``@aws-cdk/aws-logs-destinations`` package; if necessary, a
    ``CrossAccountDestination`` will be created automatically.

    :resource: AWS::Logs::Destination
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        from aws_cdk import aws_logs as logs
        
        # role: iam.Role
        
        cross_account_destination = logs.CrossAccountDestination(self, "MyCrossAccountDestination",
            role=role,
            target_arn="targetArn",
        
            # the properties below are optional
            destination_name="destinationName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        role: _IRole_235f5d8e,
        target_arn: builtins.str,
        destination_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param role: The role to assume that grants permissions to write to 'target'. The role must be assumable by 'logs.{REGION}.amazonaws.com'.
        :param target_arn: The log destination target's ARN.
        :param destination_name: The name of the log destination. Default: Automatically generated
        '''
        props = CrossAccountDestinationProps(
            role=role, target_arn=target_arn, destination_name=destination_name
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="addToPolicy")
    def add_to_policy(self, statement: _PolicyStatement_0fe33853) -> None:
        '''
        :param statement: -
        '''
        return typing.cast(None, jsii.invoke(self, "addToPolicy", [statement]))

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        _scope: constructs.Construct,
        _source_log_group: ILogGroup,
    ) -> LogSubscriptionDestinationConfig:
        '''Return the properties required to send subscription events to this destination.

        If necessary, the destination can use the properties of the SubscriptionFilter
        object itself to configure its permissions to allow the subscription to write
        to it.

        The destination may reconfigure its own permissions in response to this
        function call.

        :param _scope: -
        :param _source_log_group: -
        '''
        return typing.cast(LogSubscriptionDestinationConfig, jsii.invoke(self, "bind", [_scope, _source_log_group]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="destinationArn")
    def destination_arn(self) -> builtins.str:
        '''The ARN of this CrossAccountDestination object.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "destinationArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="destinationName")
    def destination_name(self) -> builtins.str:
        '''The name of this CrossAccountDestination object.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "destinationName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyDocument")
    def policy_document(self) -> _PolicyDocument_3ac34393:
        '''Policy object of this CrossAccountDestination object.'''
        return typing.cast(_PolicyDocument_3ac34393, jsii.get(self, "policyDocument"))


__all__ = [
    "CfnDestination",
    "CfnDestinationProps",
    "CfnLogGroup",
    "CfnLogGroupProps",
    "CfnLogStream",
    "CfnLogStreamProps",
    "CfnMetricFilter",
    "CfnMetricFilterProps",
    "CfnQueryDefinition",
    "CfnQueryDefinitionProps",
    "CfnResourcePolicy",
    "CfnResourcePolicyProps",
    "CfnSubscriptionFilter",
    "CfnSubscriptionFilterProps",
    "ColumnRestriction",
    "CrossAccountDestination",
    "CrossAccountDestinationProps",
    "FilterPattern",
    "IFilterPattern",
    "ILogGroup",
    "ILogStream",
    "ILogSubscriptionDestination",
    "JsonPattern",
    "LogGroup",
    "LogGroupProps",
    "LogRetention",
    "LogRetentionProps",
    "LogRetentionRetryOptions",
    "LogStream",
    "LogStreamProps",
    "LogSubscriptionDestinationConfig",
    "MetricFilter",
    "MetricFilterOptions",
    "MetricFilterProps",
    "ResourcePolicy",
    "ResourcePolicyProps",
    "RetentionDays",
    "SpaceDelimitedTextPattern",
    "StreamOptions",
    "SubscriptionFilter",
    "SubscriptionFilterOptions",
    "SubscriptionFilterProps",
]

publication.publish()
