'''
# Amazon Simple Queue Service Construct Library

Amazon Simple Queue Service (SQS) is a fully managed message queuing service that
enables you to decouple and scale microservices, distributed systems, and serverless
applications. SQS eliminates the complexity and overhead associated with managing and
operating message oriented middleware, and empowers developers to focus on differentiating work.
Using SQS, you can send, store, and receive messages between software components at any volume,
without losing messages or requiring other services to be available.

## Installation

Import to your project:

```python
import aws_cdk.aws_sqs as sqs
```

## Basic usage

Here's how to add a basic queue to your application:

```python
sqs.Queue(self, "Queue")
```

## Encryption

If you want to encrypt the queue contents, set the `encryption` property. You can have
the messages encrypted with a key that SQS manages for you, or a key that you
can manage yourself.

```python
# Use managed key
sqs.Queue(self, "Queue",
    encryption=sqs.QueueEncryption.KMS_MANAGED
)

# Use custom key
my_key = kms.Key(self, "Key")

sqs.Queue(self, "Queue",
    encryption=sqs.QueueEncryption.KMS,
    encryption_master_key=my_key
)
```

## First-In-First-Out (FIFO) queues

FIFO queues give guarantees on the order in which messages are dequeued, and have additional
features in order to help guarantee exactly-once processing. For more information, see
the SQS manual. Note that FIFO queues are not available in all AWS regions.

A queue can be made a FIFO queue by either setting `fifo: true`, giving it a name which ends
in `".fifo"`, or by enabling a FIFO specific feature such as: content-based deduplication,
deduplication scope or fifo throughput limit.
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
    ResourceProps as _ResourceProps_15a65b4e,
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
    PolicyDocument as _PolicyDocument_3ac34393,
    PolicyStatement as _PolicyStatement_0fe33853,
)
from ..aws_kms import IKey as _IKey_5f11635f


@jsii.implements(_IInspectable_c2943556)
class CfnQueue(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_sqs.CfnQueue",
):
    '''A CloudFormation ``AWS::SQS::Queue``.

    The ``AWS::SQS::Queue`` resource creates an Amazon SQS standard or FIFO queue.

    Keep the following caveats in mind:

    - If you don't specify the ``FifoQueue`` property, Amazon SQS creates a standard queue.

    .. epigraph::

       You can't change the queue type after you create it and you can't convert an existing standard queue into a FIFO queue. You must either create a new FIFO queue for your application or delete your existing standard queue and recreate it as a FIFO queue. For more information, see `Moving from a standard queue to a FIFO queue <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues-moving.html>`_ in the *Amazon SQS Developer Guide* .

    - If you don't provide a value for a property, the queue is created with the default value for the property.
    - If you delete a queue, you must wait at least 60 seconds before creating a queue with the same name.
    - To successfully create a new queue, you must provide a queue name that adheres to the `limits related to queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/limits-queues.html>`_ and is unique within the scope of your queues.

    For more information about creating FIFO (first-in-first-out) queues, see `Creating an Amazon SQS queue ( AWS CloudFormation ) <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/screate-queue-cloudformation.html>`_ in the *Amazon SQS Developer Guide* .

    :cloudformationResource: AWS::SQS::Queue
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_sqs as sqs
        
        # redrive_allow_policy: Any
        # redrive_policy: Any
        
        cfn_queue = sqs.CfnQueue(self, "MyCfnQueue",
            content_based_deduplication=False,
            deduplication_scope="deduplicationScope",
            delay_seconds=123,
            fifo_queue=False,
            fifo_throughput_limit="fifoThroughputLimit",
            kms_data_key_reuse_period_seconds=123,
            kms_master_key_id="kmsMasterKeyId",
            maximum_message_size=123,
            message_retention_period=123,
            queue_name="queueName",
            receive_message_wait_time_seconds=123,
            redrive_allow_policy=redrive_allow_policy,
            redrive_policy=redrive_policy,
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            visibility_timeout=123
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        content_based_deduplication: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        deduplication_scope: typing.Optional[builtins.str] = None,
        delay_seconds: typing.Optional[jsii.Number] = None,
        fifo_queue: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        fifo_throughput_limit: typing.Optional[builtins.str] = None,
        kms_data_key_reuse_period_seconds: typing.Optional[jsii.Number] = None,
        kms_master_key_id: typing.Optional[builtins.str] = None,
        maximum_message_size: typing.Optional[jsii.Number] = None,
        message_retention_period: typing.Optional[jsii.Number] = None,
        queue_name: typing.Optional[builtins.str] = None,
        receive_message_wait_time_seconds: typing.Optional[jsii.Number] = None,
        redrive_allow_policy: typing.Any = None,
        redrive_policy: typing.Any = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        visibility_timeout: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Create a new ``AWS::SQS::Queue``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param content_based_deduplication: For first-in-first-out (FIFO) queues, specifies whether to enable content-based deduplication. During the deduplication interval, Amazon SQS treats messages that are sent with identical content as duplicates and delivers only one copy of the message. For more information, see the ``ContentBasedDeduplication`` attribute for the ``[CreateQueue](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html)`` action in the *Amazon SQS API Reference* .
        :param deduplication_scope: For high throughput for FIFO queues, specifies whether message deduplication occurs at the message group or queue level. Valid values are ``messageGroup`` and ``queue`` . To enable high throughput for a FIFO queue, set this attribute to ``messageGroup`` *and* set the ``FifoThroughputLimit`` attribute to ``perMessageGroupId`` . If you set these attributes to anything other than these values, normal throughput is in effect and deduplication occurs as specified. For more information, see `High throughput for FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/high-throughput-fifo.html>`_ and `Quotas related to messages <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html>`_ in the *Amazon SQS Developer Guide* .
        :param delay_seconds: The time in seconds for which the delivery of all messages in the queue is delayed. You can specify an integer value of ``0`` to ``900`` (15 minutes). The default value is ``0`` .
        :param fifo_queue: If set to true, creates a FIFO queue. If you don't specify this property, Amazon SQS creates a standard queue. For more information, see `FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html>`_ in the *Amazon SQS Developer Guide* .
        :param fifo_throughput_limit: For high throughput for FIFO queues, specifies whether the FIFO queue throughput quota applies to the entire queue or per message group. Valid values are ``perQueue`` and ``perMessageGroupId`` . To enable high throughput for a FIFO queue, set this attribute to ``perMessageGroupId`` *and* set the ``DeduplicationScope`` attribute to ``messageGroup`` . If you set these attributes to anything other than these values, normal throughput is in effect and deduplication occurs as specified. For more information, see `High throughput for FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/high-throughput-fifo.html>`_ and `Quotas related to messages <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html>`_ in the *Amazon SQS Developer Guide* .
        :param kms_data_key_reuse_period_seconds: The length of time in seconds for which Amazon SQS can reuse a data key to encrypt or decrypt messages before calling AWS KMS again. The value must be an integer between 60 (1 minute) and 86,400 (24 hours). The default is 300 (5 minutes). .. epigraph:: A shorter time period provides better security, but results in more calls to AWS KMS , which might incur charges after Free Tier. For more information, see `Encryption at rest <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html#sqs-how-does-the-data-key-reuse-period-work>`_ in the *Amazon SQS Developer Guide* .
        :param kms_master_key_id: The ID of an AWS managed customer master key (CMK) for Amazon SQS or a custom CMK. To use the AWS managed CMK for Amazon SQS , specify the (default) alias ``alias/aws/sqs`` . For more information, see the following: - `Encryption at rest <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html>`_ in the *Amazon SQS Developer Guide* - `CreateQueue <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html>`_ in the *Amazon SQS API Reference* - The Customer Master Keys section of the `AWS Key Management Service Best Practices <https://docs.aws.amazon.com/https://d0.awsstatic.com/whitepapers/aws-kms-best-practices.pdf>`_ whitepaper
        :param maximum_message_size: The limit of how many bytes that a message can contain before Amazon SQS rejects it. You can specify an integer value from ``1,024`` bytes (1 KiB) to ``262,144`` bytes (256 KiB). The default value is ``262,144`` (256 KiB).
        :param message_retention_period: The number of seconds that Amazon SQS retains a message. You can specify an integer value from ``60`` seconds (1 minute) to ``1,209,600`` seconds (14 days). The default value is ``345,600`` seconds (4 days).
        :param queue_name: A name for the queue. To create a FIFO queue, the name of your FIFO queue must end with the ``.fifo`` suffix. For more information, see `FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html>`_ in the *Amazon SQS Developer Guide* . If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the queue name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ in the *AWS CloudFormation User Guide* . .. epigraph:: If you specify a name, you can't perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.
        :param receive_message_wait_time_seconds: Specifies the duration, in seconds, that the ReceiveMessage action call waits until a message is in the queue in order to include it in the response, rather than returning an empty response if a message isn't yet available. You can specify an integer from 1 to 20. Short polling is used as the default or when you specify 0 for this property. For more information, see `Consuming messages using long polling <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-short-and-long-polling.html#sqs-long-polling>`_ in the *Amazon SQS Developer Guide* .
        :param redrive_allow_policy: The string that includes the parameters for the permissions for the dead-letter queue redrive permission and which source queues can specify dead-letter queues as a JSON object. The parameters are as follows: - ``redrivePermission`` : The permission type that defines which source queues can specify the current queue as the dead-letter queue. Valid values are: - ``allowAll`` : (Default) Any source queues in this AWS account in the same Region can specify this queue as the dead-letter queue. - ``denyAll`` : No source queues can specify this queue as the dead-letter queue. - ``byQueue`` : Only queues specified by the ``sourceQueueArns`` parameter can specify this queue as the dead-letter queue. - ``sourceQueueArns`` : The Amazon Resource Names (ARN)s of the source queues that can specify this queue as the dead-letter queue and redrive messages. You can specify this parameter only when the ``redrivePermission`` parameter is set to ``byQueue`` . You can specify up to 10 source queue ARNs. To allow more than 10 source queues to specify dead-letter queues, set the ``redrivePermission`` parameter to ``allowAll`` .
        :param redrive_policy: The string that includes the parameters for the dead-letter queue functionality of the source queue as a JSON object. The parameters are as follows: - ``deadLetterTargetArn`` : The Amazon Resource Name (ARN) of the dead-letter queue to which Amazon SQS moves messages after the value of ``maxReceiveCount`` is exceeded. - ``maxReceiveCount`` : The number of times a message is delivered to the source queue before being moved to the dead-letter queue. When the ``ReceiveCount`` for a message exceeds the ``maxReceiveCount`` for a queue, Amazon SQS moves the message to the dead-letter-queue. .. epigraph:: The dead-letter queue of a FIFO queue must also be a FIFO queue. Similarly, the dead-letter queue of a standard queue must also be a standard queue. *JSON* ``{ "deadLetterTargetArn" : *String* , "maxReceiveCount" : *Integer* }`` *YAML* ``deadLetterTargetArn : *String*`` ``maxReceiveCount : *Integer*``
        :param tags: The tags that you attach to this queue. For more information, see `Resource tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ in the *AWS CloudFormation User Guide* .
        :param visibility_timeout: The length of time during which a message will be unavailable after a message is delivered from the queue. This blocks other components from receiving the same message and gives the initial component time to process and delete the message from the queue. Values must be from 0 to 43,200 seconds (12 hours). If you don't specify a value, AWS CloudFormation uses the default value of 30 seconds. For more information about Amazon SQS queue visibility timeouts, see `Visibility timeout <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html>`_ in the *Amazon SQS Developer Guide* .
        '''
        props = CfnQueueProps(
            content_based_deduplication=content_based_deduplication,
            deduplication_scope=deduplication_scope,
            delay_seconds=delay_seconds,
            fifo_queue=fifo_queue,
            fifo_throughput_limit=fifo_throughput_limit,
            kms_data_key_reuse_period_seconds=kms_data_key_reuse_period_seconds,
            kms_master_key_id=kms_master_key_id,
            maximum_message_size=maximum_message_size,
            message_retention_period=message_retention_period,
            queue_name=queue_name,
            receive_message_wait_time_seconds=receive_message_wait_time_seconds,
            redrive_allow_policy=redrive_allow_policy,
            redrive_policy=redrive_policy,
            tags=tags,
            visibility_timeout=visibility_timeout,
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
        '''Returns the Amazon Resource Name (ARN) of the queue.

        For example: ``arn:aws:sqs:us-east-2:123456789012:mystack-myqueue-15PG5C2FC1CW8`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrQueueName")
    def attr_queue_name(self) -> builtins.str:
        '''Returns the queue name.

        For example: ``mystack-myqueue-1VF9BKQH5BJVI`` .

        :cloudformationAttribute: QueueName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrQueueName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrQueueUrl")
    def attr_queue_url(self) -> builtins.str:
        '''
        :cloudformationAttribute: QueueUrl
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrQueueUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags that you attach to this queue.

        For more information, see `Resource tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ in the *AWS CloudFormation User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="redriveAllowPolicy")
    def redrive_allow_policy(self) -> typing.Any:
        '''The string that includes the parameters for the permissions for the dead-letter queue redrive permission and which source queues can specify dead-letter queues as a JSON object.

        The parameters are as follows:

        - ``redrivePermission`` : The permission type that defines which source queues can specify the current queue as the dead-letter queue. Valid values are:
        - ``allowAll`` : (Default) Any source queues in this AWS account in the same Region can specify this queue as the dead-letter queue.
        - ``denyAll`` : No source queues can specify this queue as the dead-letter queue.
        - ``byQueue`` : Only queues specified by the ``sourceQueueArns`` parameter can specify this queue as the dead-letter queue.
        - ``sourceQueueArns`` : The Amazon Resource Names (ARN)s of the source queues that can specify this queue as the dead-letter queue and redrive messages. You can specify this parameter only when the ``redrivePermission`` parameter is set to ``byQueue`` . You can specify up to 10 source queue ARNs. To allow more than 10 source queues to specify dead-letter queues, set the ``redrivePermission`` parameter to ``allowAll`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-redriveallowpolicy
        '''
        return typing.cast(typing.Any, jsii.get(self, "redriveAllowPolicy"))

    @redrive_allow_policy.setter
    def redrive_allow_policy(self, value: typing.Any) -> None:
        jsii.set(self, "redriveAllowPolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="redrivePolicy")
    def redrive_policy(self) -> typing.Any:
        '''The string that includes the parameters for the dead-letter queue functionality of the source queue as a JSON object.

        The parameters are as follows:

        - ``deadLetterTargetArn`` : The Amazon Resource Name (ARN) of the dead-letter queue to which Amazon SQS moves messages after the value of ``maxReceiveCount`` is exceeded.
        - ``maxReceiveCount`` : The number of times a message is delivered to the source queue before being moved to the dead-letter queue. When the ``ReceiveCount`` for a message exceeds the ``maxReceiveCount`` for a queue, Amazon SQS moves the message to the dead-letter-queue.

        .. epigraph::

           The dead-letter queue of a FIFO queue must also be a FIFO queue. Similarly, the dead-letter queue of a standard queue must also be a standard queue.

        *JSON*

        ``{ "deadLetterTargetArn" : *String* , "maxReceiveCount" : *Integer* }``

        *YAML*

        ``deadLetterTargetArn : *String*``

        ``maxReceiveCount : *Integer*``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-redrivepolicy
        '''
        return typing.cast(typing.Any, jsii.get(self, "redrivePolicy"))

    @redrive_policy.setter
    def redrive_policy(self, value: typing.Any) -> None:
        jsii.set(self, "redrivePolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="contentBasedDeduplication")
    def content_based_deduplication(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''For first-in-first-out (FIFO) queues, specifies whether to enable content-based deduplication.

        During the deduplication interval, Amazon SQS treats messages that are sent with identical content as duplicates and delivers only one copy of the message. For more information, see the ``ContentBasedDeduplication`` attribute for the ``[CreateQueue](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html)`` action in the *Amazon SQS API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-contentbaseddeduplication
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "contentBasedDeduplication"))

    @content_based_deduplication.setter
    def content_based_deduplication(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "contentBasedDeduplication", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="deduplicationScope")
    def deduplication_scope(self) -> typing.Optional[builtins.str]:
        '''For high throughput for FIFO queues, specifies whether message deduplication occurs at the message group or queue level.

        Valid values are ``messageGroup`` and ``queue`` .

        To enable high throughput for a FIFO queue, set this attribute to ``messageGroup`` *and* set the ``FifoThroughputLimit`` attribute to ``perMessageGroupId`` . If you set these attributes to anything other than these values, normal throughput is in effect and deduplication occurs as specified. For more information, see `High throughput for FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/high-throughput-fifo.html>`_ and `Quotas related to messages <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-deduplicationscope
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "deduplicationScope"))

    @deduplication_scope.setter
    def deduplication_scope(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "deduplicationScope", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="delaySeconds")
    def delay_seconds(self) -> typing.Optional[jsii.Number]:
        '''The time in seconds for which the delivery of all messages in the queue is delayed.

        You can specify an integer value of ``0`` to ``900`` (15 minutes). The default value is ``0`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-delayseconds
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "delaySeconds"))

    @delay_seconds.setter
    def delay_seconds(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "delaySeconds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fifoQueue")
    def fifo_queue(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''If set to true, creates a FIFO queue.

        If you don't specify this property, Amazon SQS creates a standard queue. For more information, see `FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-fifoqueue
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "fifoQueue"))

    @fifo_queue.setter
    def fifo_queue(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "fifoQueue", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fifoThroughputLimit")
    def fifo_throughput_limit(self) -> typing.Optional[builtins.str]:
        '''For high throughput for FIFO queues, specifies whether the FIFO queue throughput quota applies to the entire queue or per message group.

        Valid values are ``perQueue`` and ``perMessageGroupId`` .

        To enable high throughput for a FIFO queue, set this attribute to ``perMessageGroupId`` *and* set the ``DeduplicationScope`` attribute to ``messageGroup`` . If you set these attributes to anything other than these values, normal throughput is in effect and deduplication occurs as specified. For more information, see `High throughput for FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/high-throughput-fifo.html>`_ and `Quotas related to messages <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-fifothroughputlimit
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "fifoThroughputLimit"))

    @fifo_throughput_limit.setter
    def fifo_throughput_limit(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "fifoThroughputLimit", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsDataKeyReusePeriodSeconds")
    def kms_data_key_reuse_period_seconds(self) -> typing.Optional[jsii.Number]:
        '''The length of time in seconds for which Amazon SQS can reuse a data key to encrypt or decrypt messages before calling AWS KMS again.

        The value must be an integer between 60 (1 minute) and 86,400 (24 hours). The default is 300 (5 minutes).
        .. epigraph::

           A shorter time period provides better security, but results in more calls to AWS KMS , which might incur charges after Free Tier. For more information, see `Encryption at rest <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html#sqs-how-does-the-data-key-reuse-period-work>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-kmsdatakeyreuseperiodseconds
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "kmsDataKeyReusePeriodSeconds"))

    @kms_data_key_reuse_period_seconds.setter
    def kms_data_key_reuse_period_seconds(
        self,
        value: typing.Optional[jsii.Number],
    ) -> None:
        jsii.set(self, "kmsDataKeyReusePeriodSeconds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsMasterKeyId")
    def kms_master_key_id(self) -> typing.Optional[builtins.str]:
        '''The ID of an AWS managed customer master key (CMK) for Amazon SQS or a custom CMK.

        To use the AWS managed CMK for Amazon SQS , specify the (default) alias ``alias/aws/sqs`` . For more information, see the following:

        - `Encryption at rest <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html>`_ in the *Amazon SQS Developer Guide*
        - `CreateQueue <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html>`_ in the *Amazon SQS API Reference*
        - The Customer Master Keys section of the `AWS Key Management Service Best Practices <https://docs.aws.amazon.com/https://d0.awsstatic.com/whitepapers/aws-kms-best-practices.pdf>`_ whitepaper

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-kmsmasterkeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsMasterKeyId"))

    @kms_master_key_id.setter
    def kms_master_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsMasterKeyId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maximumMessageSize")
    def maximum_message_size(self) -> typing.Optional[jsii.Number]:
        '''The limit of how many bytes that a message can contain before Amazon SQS rejects it.

        You can specify an integer value from ``1,024`` bytes (1 KiB) to ``262,144`` bytes (256 KiB). The default value is ``262,144`` (256 KiB).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-maximummessagesize
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "maximumMessageSize"))

    @maximum_message_size.setter
    def maximum_message_size(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "maximumMessageSize", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="messageRetentionPeriod")
    def message_retention_period(self) -> typing.Optional[jsii.Number]:
        '''The number of seconds that Amazon SQS retains a message.

        You can specify an integer value from ``60`` seconds (1 minute) to ``1,209,600`` seconds (14 days). The default value is ``345,600`` seconds (4 days).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-messageretentionperiod
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "messageRetentionPeriod"))

    @message_retention_period.setter
    def message_retention_period(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "messageRetentionPeriod", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueName")
    def queue_name(self) -> typing.Optional[builtins.str]:
        '''A name for the queue.

        To create a FIFO queue, the name of your FIFO queue must end with the ``.fifo`` suffix. For more information, see `FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html>`_ in the *Amazon SQS Developer Guide* .

        If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the queue name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ in the *AWS CloudFormation User Guide* .
        .. epigraph::

           If you specify a name, you can't perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-queuename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "queueName"))

    @queue_name.setter
    def queue_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "queueName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="receiveMessageWaitTimeSeconds")
    def receive_message_wait_time_seconds(self) -> typing.Optional[jsii.Number]:
        '''Specifies the duration, in seconds, that the ReceiveMessage action call waits until a message is in the queue in order to include it in the response, rather than returning an empty response if a message isn't yet available.

        You can specify an integer from 1 to 20. Short polling is used as the default or when you specify 0 for this property. For more information, see `Consuming messages using long polling <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-short-and-long-polling.html#sqs-long-polling>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-receivemessagewaittimeseconds
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "receiveMessageWaitTimeSeconds"))

    @receive_message_wait_time_seconds.setter
    def receive_message_wait_time_seconds(
        self,
        value: typing.Optional[jsii.Number],
    ) -> None:
        jsii.set(self, "receiveMessageWaitTimeSeconds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="visibilityTimeout")
    def visibility_timeout(self) -> typing.Optional[jsii.Number]:
        '''The length of time during which a message will be unavailable after a message is delivered from the queue.

        This blocks other components from receiving the same message and gives the initial component time to process and delete the message from the queue.

        Values must be from 0 to 43,200 seconds (12 hours). If you don't specify a value, AWS CloudFormation uses the default value of 30 seconds.

        For more information about Amazon SQS queue visibility timeouts, see `Visibility timeout <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-visibilitytimeout
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "visibilityTimeout"))

    @visibility_timeout.setter
    def visibility_timeout(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "visibilityTimeout", value)


@jsii.implements(_IInspectable_c2943556)
class CfnQueuePolicy(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_sqs.CfnQueuePolicy",
):
    '''A CloudFormation ``AWS::SQS::QueuePolicy``.

    The ``AWS::SQS::QueuePolicy`` type applies a policy to Amazon SQS queues. For an example snippet, see `Declaring an Amazon SQS policy <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-iam.html#scenario-sqs-policy>`_ in the *AWS CloudFormation User Guide* .

    :cloudformationResource: AWS::SQS::QueuePolicy
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_sqs as sqs
        
        # policy_document: Any
        
        cfn_queue_policy = sqs.CfnQueuePolicy(self, "MyCfnQueuePolicy",
            policy_document=policy_document,
            queues=["queues"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        policy_document: typing.Any,
        queues: typing.Sequence[builtins.str],
    ) -> None:
        '''Create a new ``AWS::SQS::QueuePolicy``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param policy_document: A policy document that contains the permissions for the specified Amazon SQS queues. For more information about Amazon SQS policies, see `Using custom policies with the Amazon SQS access policy language <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies.html>`_ in the *Amazon SQS Developer Guide* .
        :param queues: The URLs of the queues to which you want to add the policy. You can use the ``[Ref](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html)`` function to specify an ``[AWS::SQS::Queue](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html)`` resource.
        '''
        props = CfnQueuePolicyProps(policy_document=policy_document, queues=queues)

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
        '''
        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyDocument")
    def policy_document(self) -> typing.Any:
        '''A policy document that contains the permissions for the specified Amazon SQS queues.

        For more information about Amazon SQS policies, see `Using custom policies with the Amazon SQS access policy language <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies.html>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html#cfn-sqs-queuepolicy-policydocument
        '''
        return typing.cast(typing.Any, jsii.get(self, "policyDocument"))

    @policy_document.setter
    def policy_document(self, value: typing.Any) -> None:
        jsii.set(self, "policyDocument", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queues")
    def queues(self) -> typing.List[builtins.str]:
        '''The URLs of the queues to which you want to add the policy.

        You can use the ``[Ref](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html)`` function to specify an ``[AWS::SQS::Queue](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html)`` resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html#cfn-sqs-queuepolicy-queues
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "queues"))

    @queues.setter
    def queues(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "queues", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_sqs.CfnQueuePolicyProps",
    jsii_struct_bases=[],
    name_mapping={"policy_document": "policyDocument", "queues": "queues"},
)
class CfnQueuePolicyProps:
    def __init__(
        self,
        *,
        policy_document: typing.Any,
        queues: typing.Sequence[builtins.str],
    ) -> None:
        '''Properties for defining a ``CfnQueuePolicy``.

        :param policy_document: A policy document that contains the permissions for the specified Amazon SQS queues. For more information about Amazon SQS policies, see `Using custom policies with the Amazon SQS access policy language <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies.html>`_ in the *Amazon SQS Developer Guide* .
        :param queues: The URLs of the queues to which you want to add the policy. You can use the ``[Ref](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html)`` function to specify an ``[AWS::SQS::Queue](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html)`` resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_sqs as sqs
            
            # policy_document: Any
            
            cfn_queue_policy_props = sqs.CfnQueuePolicyProps(
                policy_document=policy_document,
                queues=["queues"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "policy_document": policy_document,
            "queues": queues,
        }

    @builtins.property
    def policy_document(self) -> typing.Any:
        '''A policy document that contains the permissions for the specified Amazon SQS queues.

        For more information about Amazon SQS policies, see `Using custom policies with the Amazon SQS access policy language <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies.html>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html#cfn-sqs-queuepolicy-policydocument
        '''
        result = self._values.get("policy_document")
        assert result is not None, "Required property 'policy_document' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def queues(self) -> typing.List[builtins.str]:
        '''The URLs of the queues to which you want to add the policy.

        You can use the ``[Ref](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html)`` function to specify an ``[AWS::SQS::Queue](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html)`` resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html#cfn-sqs-queuepolicy-queues
        '''
        result = self._values.get("queues")
        assert result is not None, "Required property 'queues' is missing"
        return typing.cast(typing.List[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnQueuePolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_sqs.CfnQueueProps",
    jsii_struct_bases=[],
    name_mapping={
        "content_based_deduplication": "contentBasedDeduplication",
        "deduplication_scope": "deduplicationScope",
        "delay_seconds": "delaySeconds",
        "fifo_queue": "fifoQueue",
        "fifo_throughput_limit": "fifoThroughputLimit",
        "kms_data_key_reuse_period_seconds": "kmsDataKeyReusePeriodSeconds",
        "kms_master_key_id": "kmsMasterKeyId",
        "maximum_message_size": "maximumMessageSize",
        "message_retention_period": "messageRetentionPeriod",
        "queue_name": "queueName",
        "receive_message_wait_time_seconds": "receiveMessageWaitTimeSeconds",
        "redrive_allow_policy": "redriveAllowPolicy",
        "redrive_policy": "redrivePolicy",
        "tags": "tags",
        "visibility_timeout": "visibilityTimeout",
    },
)
class CfnQueueProps:
    def __init__(
        self,
        *,
        content_based_deduplication: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        deduplication_scope: typing.Optional[builtins.str] = None,
        delay_seconds: typing.Optional[jsii.Number] = None,
        fifo_queue: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        fifo_throughput_limit: typing.Optional[builtins.str] = None,
        kms_data_key_reuse_period_seconds: typing.Optional[jsii.Number] = None,
        kms_master_key_id: typing.Optional[builtins.str] = None,
        maximum_message_size: typing.Optional[jsii.Number] = None,
        message_retention_period: typing.Optional[jsii.Number] = None,
        queue_name: typing.Optional[builtins.str] = None,
        receive_message_wait_time_seconds: typing.Optional[jsii.Number] = None,
        redrive_allow_policy: typing.Any = None,
        redrive_policy: typing.Any = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        visibility_timeout: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Properties for defining a ``CfnQueue``.

        :param content_based_deduplication: For first-in-first-out (FIFO) queues, specifies whether to enable content-based deduplication. During the deduplication interval, Amazon SQS treats messages that are sent with identical content as duplicates and delivers only one copy of the message. For more information, see the ``ContentBasedDeduplication`` attribute for the ``[CreateQueue](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html)`` action in the *Amazon SQS API Reference* .
        :param deduplication_scope: For high throughput for FIFO queues, specifies whether message deduplication occurs at the message group or queue level. Valid values are ``messageGroup`` and ``queue`` . To enable high throughput for a FIFO queue, set this attribute to ``messageGroup`` *and* set the ``FifoThroughputLimit`` attribute to ``perMessageGroupId`` . If you set these attributes to anything other than these values, normal throughput is in effect and deduplication occurs as specified. For more information, see `High throughput for FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/high-throughput-fifo.html>`_ and `Quotas related to messages <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html>`_ in the *Amazon SQS Developer Guide* .
        :param delay_seconds: The time in seconds for which the delivery of all messages in the queue is delayed. You can specify an integer value of ``0`` to ``900`` (15 minutes). The default value is ``0`` .
        :param fifo_queue: If set to true, creates a FIFO queue. If you don't specify this property, Amazon SQS creates a standard queue. For more information, see `FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html>`_ in the *Amazon SQS Developer Guide* .
        :param fifo_throughput_limit: For high throughput for FIFO queues, specifies whether the FIFO queue throughput quota applies to the entire queue or per message group. Valid values are ``perQueue`` and ``perMessageGroupId`` . To enable high throughput for a FIFO queue, set this attribute to ``perMessageGroupId`` *and* set the ``DeduplicationScope`` attribute to ``messageGroup`` . If you set these attributes to anything other than these values, normal throughput is in effect and deduplication occurs as specified. For more information, see `High throughput for FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/high-throughput-fifo.html>`_ and `Quotas related to messages <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html>`_ in the *Amazon SQS Developer Guide* .
        :param kms_data_key_reuse_period_seconds: The length of time in seconds for which Amazon SQS can reuse a data key to encrypt or decrypt messages before calling AWS KMS again. The value must be an integer between 60 (1 minute) and 86,400 (24 hours). The default is 300 (5 minutes). .. epigraph:: A shorter time period provides better security, but results in more calls to AWS KMS , which might incur charges after Free Tier. For more information, see `Encryption at rest <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html#sqs-how-does-the-data-key-reuse-period-work>`_ in the *Amazon SQS Developer Guide* .
        :param kms_master_key_id: The ID of an AWS managed customer master key (CMK) for Amazon SQS or a custom CMK. To use the AWS managed CMK for Amazon SQS , specify the (default) alias ``alias/aws/sqs`` . For more information, see the following: - `Encryption at rest <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html>`_ in the *Amazon SQS Developer Guide* - `CreateQueue <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html>`_ in the *Amazon SQS API Reference* - The Customer Master Keys section of the `AWS Key Management Service Best Practices <https://docs.aws.amazon.com/https://d0.awsstatic.com/whitepapers/aws-kms-best-practices.pdf>`_ whitepaper
        :param maximum_message_size: The limit of how many bytes that a message can contain before Amazon SQS rejects it. You can specify an integer value from ``1,024`` bytes (1 KiB) to ``262,144`` bytes (256 KiB). The default value is ``262,144`` (256 KiB).
        :param message_retention_period: The number of seconds that Amazon SQS retains a message. You can specify an integer value from ``60`` seconds (1 minute) to ``1,209,600`` seconds (14 days). The default value is ``345,600`` seconds (4 days).
        :param queue_name: A name for the queue. To create a FIFO queue, the name of your FIFO queue must end with the ``.fifo`` suffix. For more information, see `FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html>`_ in the *Amazon SQS Developer Guide* . If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the queue name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ in the *AWS CloudFormation User Guide* . .. epigraph:: If you specify a name, you can't perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.
        :param receive_message_wait_time_seconds: Specifies the duration, in seconds, that the ReceiveMessage action call waits until a message is in the queue in order to include it in the response, rather than returning an empty response if a message isn't yet available. You can specify an integer from 1 to 20. Short polling is used as the default or when you specify 0 for this property. For more information, see `Consuming messages using long polling <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-short-and-long-polling.html#sqs-long-polling>`_ in the *Amazon SQS Developer Guide* .
        :param redrive_allow_policy: The string that includes the parameters for the permissions for the dead-letter queue redrive permission and which source queues can specify dead-letter queues as a JSON object. The parameters are as follows: - ``redrivePermission`` : The permission type that defines which source queues can specify the current queue as the dead-letter queue. Valid values are: - ``allowAll`` : (Default) Any source queues in this AWS account in the same Region can specify this queue as the dead-letter queue. - ``denyAll`` : No source queues can specify this queue as the dead-letter queue. - ``byQueue`` : Only queues specified by the ``sourceQueueArns`` parameter can specify this queue as the dead-letter queue. - ``sourceQueueArns`` : The Amazon Resource Names (ARN)s of the source queues that can specify this queue as the dead-letter queue and redrive messages. You can specify this parameter only when the ``redrivePermission`` parameter is set to ``byQueue`` . You can specify up to 10 source queue ARNs. To allow more than 10 source queues to specify dead-letter queues, set the ``redrivePermission`` parameter to ``allowAll`` .
        :param redrive_policy: The string that includes the parameters for the dead-letter queue functionality of the source queue as a JSON object. The parameters are as follows: - ``deadLetterTargetArn`` : The Amazon Resource Name (ARN) of the dead-letter queue to which Amazon SQS moves messages after the value of ``maxReceiveCount`` is exceeded. - ``maxReceiveCount`` : The number of times a message is delivered to the source queue before being moved to the dead-letter queue. When the ``ReceiveCount`` for a message exceeds the ``maxReceiveCount`` for a queue, Amazon SQS moves the message to the dead-letter-queue. .. epigraph:: The dead-letter queue of a FIFO queue must also be a FIFO queue. Similarly, the dead-letter queue of a standard queue must also be a standard queue. *JSON* ``{ "deadLetterTargetArn" : *String* , "maxReceiveCount" : *Integer* }`` *YAML* ``deadLetterTargetArn : *String*`` ``maxReceiveCount : *Integer*``
        :param tags: The tags that you attach to this queue. For more information, see `Resource tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ in the *AWS CloudFormation User Guide* .
        :param visibility_timeout: The length of time during which a message will be unavailable after a message is delivered from the queue. This blocks other components from receiving the same message and gives the initial component time to process and delete the message from the queue. Values must be from 0 to 43,200 seconds (12 hours). If you don't specify a value, AWS CloudFormation uses the default value of 30 seconds. For more information about Amazon SQS queue visibility timeouts, see `Visibility timeout <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_sqs as sqs
            
            # redrive_allow_policy: Any
            # redrive_policy: Any
            
            cfn_queue_props = sqs.CfnQueueProps(
                content_based_deduplication=False,
                deduplication_scope="deduplicationScope",
                delay_seconds=123,
                fifo_queue=False,
                fifo_throughput_limit="fifoThroughputLimit",
                kms_data_key_reuse_period_seconds=123,
                kms_master_key_id="kmsMasterKeyId",
                maximum_message_size=123,
                message_retention_period=123,
                queue_name="queueName",
                receive_message_wait_time_seconds=123,
                redrive_allow_policy=redrive_allow_policy,
                redrive_policy=redrive_policy,
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                visibility_timeout=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if content_based_deduplication is not None:
            self._values["content_based_deduplication"] = content_based_deduplication
        if deduplication_scope is not None:
            self._values["deduplication_scope"] = deduplication_scope
        if delay_seconds is not None:
            self._values["delay_seconds"] = delay_seconds
        if fifo_queue is not None:
            self._values["fifo_queue"] = fifo_queue
        if fifo_throughput_limit is not None:
            self._values["fifo_throughput_limit"] = fifo_throughput_limit
        if kms_data_key_reuse_period_seconds is not None:
            self._values["kms_data_key_reuse_period_seconds"] = kms_data_key_reuse_period_seconds
        if kms_master_key_id is not None:
            self._values["kms_master_key_id"] = kms_master_key_id
        if maximum_message_size is not None:
            self._values["maximum_message_size"] = maximum_message_size
        if message_retention_period is not None:
            self._values["message_retention_period"] = message_retention_period
        if queue_name is not None:
            self._values["queue_name"] = queue_name
        if receive_message_wait_time_seconds is not None:
            self._values["receive_message_wait_time_seconds"] = receive_message_wait_time_seconds
        if redrive_allow_policy is not None:
            self._values["redrive_allow_policy"] = redrive_allow_policy
        if redrive_policy is not None:
            self._values["redrive_policy"] = redrive_policy
        if tags is not None:
            self._values["tags"] = tags
        if visibility_timeout is not None:
            self._values["visibility_timeout"] = visibility_timeout

    @builtins.property
    def content_based_deduplication(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''For first-in-first-out (FIFO) queues, specifies whether to enable content-based deduplication.

        During the deduplication interval, Amazon SQS treats messages that are sent with identical content as duplicates and delivers only one copy of the message. For more information, see the ``ContentBasedDeduplication`` attribute for the ``[CreateQueue](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html)`` action in the *Amazon SQS API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-contentbaseddeduplication
        '''
        result = self._values.get("content_based_deduplication")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def deduplication_scope(self) -> typing.Optional[builtins.str]:
        '''For high throughput for FIFO queues, specifies whether message deduplication occurs at the message group or queue level.

        Valid values are ``messageGroup`` and ``queue`` .

        To enable high throughput for a FIFO queue, set this attribute to ``messageGroup`` *and* set the ``FifoThroughputLimit`` attribute to ``perMessageGroupId`` . If you set these attributes to anything other than these values, normal throughput is in effect and deduplication occurs as specified. For more information, see `High throughput for FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/high-throughput-fifo.html>`_ and `Quotas related to messages <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-deduplicationscope
        '''
        result = self._values.get("deduplication_scope")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def delay_seconds(self) -> typing.Optional[jsii.Number]:
        '''The time in seconds for which the delivery of all messages in the queue is delayed.

        You can specify an integer value of ``0`` to ``900`` (15 minutes). The default value is ``0`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-delayseconds
        '''
        result = self._values.get("delay_seconds")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def fifo_queue(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''If set to true, creates a FIFO queue.

        If you don't specify this property, Amazon SQS creates a standard queue. For more information, see `FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-fifoqueue
        '''
        result = self._values.get("fifo_queue")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def fifo_throughput_limit(self) -> typing.Optional[builtins.str]:
        '''For high throughput for FIFO queues, specifies whether the FIFO queue throughput quota applies to the entire queue or per message group.

        Valid values are ``perQueue`` and ``perMessageGroupId`` .

        To enable high throughput for a FIFO queue, set this attribute to ``perMessageGroupId`` *and* set the ``DeduplicationScope`` attribute to ``messageGroup`` . If you set these attributes to anything other than these values, normal throughput is in effect and deduplication occurs as specified. For more information, see `High throughput for FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/high-throughput-fifo.html>`_ and `Quotas related to messages <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-fifothroughputlimit
        '''
        result = self._values.get("fifo_throughput_limit")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kms_data_key_reuse_period_seconds(self) -> typing.Optional[jsii.Number]:
        '''The length of time in seconds for which Amazon SQS can reuse a data key to encrypt or decrypt messages before calling AWS KMS again.

        The value must be an integer between 60 (1 minute) and 86,400 (24 hours). The default is 300 (5 minutes).
        .. epigraph::

           A shorter time period provides better security, but results in more calls to AWS KMS , which might incur charges after Free Tier. For more information, see `Encryption at rest <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html#sqs-how-does-the-data-key-reuse-period-work>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-kmsdatakeyreuseperiodseconds
        '''
        result = self._values.get("kms_data_key_reuse_period_seconds")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def kms_master_key_id(self) -> typing.Optional[builtins.str]:
        '''The ID of an AWS managed customer master key (CMK) for Amazon SQS or a custom CMK.

        To use the AWS managed CMK for Amazon SQS , specify the (default) alias ``alias/aws/sqs`` . For more information, see the following:

        - `Encryption at rest <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html>`_ in the *Amazon SQS Developer Guide*
        - `CreateQueue <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html>`_ in the *Amazon SQS API Reference*
        - The Customer Master Keys section of the `AWS Key Management Service Best Practices <https://docs.aws.amazon.com/https://d0.awsstatic.com/whitepapers/aws-kms-best-practices.pdf>`_ whitepaper

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-kmsmasterkeyid
        '''
        result = self._values.get("kms_master_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def maximum_message_size(self) -> typing.Optional[jsii.Number]:
        '''The limit of how many bytes that a message can contain before Amazon SQS rejects it.

        You can specify an integer value from ``1,024`` bytes (1 KiB) to ``262,144`` bytes (256 KiB). The default value is ``262,144`` (256 KiB).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-maximummessagesize
        '''
        result = self._values.get("maximum_message_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def message_retention_period(self) -> typing.Optional[jsii.Number]:
        '''The number of seconds that Amazon SQS retains a message.

        You can specify an integer value from ``60`` seconds (1 minute) to ``1,209,600`` seconds (14 days). The default value is ``345,600`` seconds (4 days).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-messageretentionperiod
        '''
        result = self._values.get("message_retention_period")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def queue_name(self) -> typing.Optional[builtins.str]:
        '''A name for the queue.

        To create a FIFO queue, the name of your FIFO queue must end with the ``.fifo`` suffix. For more information, see `FIFO queues <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html>`_ in the *Amazon SQS Developer Guide* .

        If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the queue name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ in the *AWS CloudFormation User Guide* .
        .. epigraph::

           If you specify a name, you can't perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-queuename
        '''
        result = self._values.get("queue_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def receive_message_wait_time_seconds(self) -> typing.Optional[jsii.Number]:
        '''Specifies the duration, in seconds, that the ReceiveMessage action call waits until a message is in the queue in order to include it in the response, rather than returning an empty response if a message isn't yet available.

        You can specify an integer from 1 to 20. Short polling is used as the default or when you specify 0 for this property. For more information, see `Consuming messages using long polling <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-short-and-long-polling.html#sqs-long-polling>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-receivemessagewaittimeseconds
        '''
        result = self._values.get("receive_message_wait_time_seconds")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def redrive_allow_policy(self) -> typing.Any:
        '''The string that includes the parameters for the permissions for the dead-letter queue redrive permission and which source queues can specify dead-letter queues as a JSON object.

        The parameters are as follows:

        - ``redrivePermission`` : The permission type that defines which source queues can specify the current queue as the dead-letter queue. Valid values are:
        - ``allowAll`` : (Default) Any source queues in this AWS account in the same Region can specify this queue as the dead-letter queue.
        - ``denyAll`` : No source queues can specify this queue as the dead-letter queue.
        - ``byQueue`` : Only queues specified by the ``sourceQueueArns`` parameter can specify this queue as the dead-letter queue.
        - ``sourceQueueArns`` : The Amazon Resource Names (ARN)s of the source queues that can specify this queue as the dead-letter queue and redrive messages. You can specify this parameter only when the ``redrivePermission`` parameter is set to ``byQueue`` . You can specify up to 10 source queue ARNs. To allow more than 10 source queues to specify dead-letter queues, set the ``redrivePermission`` parameter to ``allowAll`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-redriveallowpolicy
        '''
        result = self._values.get("redrive_allow_policy")
        return typing.cast(typing.Any, result)

    @builtins.property
    def redrive_policy(self) -> typing.Any:
        '''The string that includes the parameters for the dead-letter queue functionality of the source queue as a JSON object.

        The parameters are as follows:

        - ``deadLetterTargetArn`` : The Amazon Resource Name (ARN) of the dead-letter queue to which Amazon SQS moves messages after the value of ``maxReceiveCount`` is exceeded.
        - ``maxReceiveCount`` : The number of times a message is delivered to the source queue before being moved to the dead-letter queue. When the ``ReceiveCount`` for a message exceeds the ``maxReceiveCount`` for a queue, Amazon SQS moves the message to the dead-letter-queue.

        .. epigraph::

           The dead-letter queue of a FIFO queue must also be a FIFO queue. Similarly, the dead-letter queue of a standard queue must also be a standard queue.

        *JSON*

        ``{ "deadLetterTargetArn" : *String* , "maxReceiveCount" : *Integer* }``

        *YAML*

        ``deadLetterTargetArn : *String*``

        ``maxReceiveCount : *Integer*``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-redrivepolicy
        '''
        result = self._values.get("redrive_policy")
        return typing.cast(typing.Any, result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags that you attach to this queue.

        For more information, see `Resource tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ in the *AWS CloudFormation User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def visibility_timeout(self) -> typing.Optional[jsii.Number]:
        '''The length of time during which a message will be unavailable after a message is delivered from the queue.

        This blocks other components from receiving the same message and gives the initial component time to process and delete the message from the queue.

        Values must be from 0 to 43,200 seconds (12 hours). If you don't specify a value, AWS CloudFormation uses the default value of 30 seconds.

        For more information about Amazon SQS queue visibility timeouts, see `Visibility timeout <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html>`_ in the *Amazon SQS Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html#cfn-sqs-queue-visibilitytimeout
        '''
        result = self._values.get("visibility_timeout")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnQueueProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_sqs.DeadLetterQueue",
    jsii_struct_bases=[],
    name_mapping={"max_receive_count": "maxReceiveCount", "queue": "queue"},
)
class DeadLetterQueue:
    def __init__(self, *, max_receive_count: jsii.Number, queue: "IQueue") -> None:
        '''Dead letter queue settings.

        :param max_receive_count: The number of times a message can be unsuccesfully dequeued before being moved to the dead-letter queue.
        :param queue: The dead-letter queue to which Amazon SQS moves messages after the value of maxReceiveCount is exceeded.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_sqs as sqs
            
            # queue: sqs.Queue
            
            dead_letter_queue = sqs.DeadLetterQueue(
                max_receive_count=123,
                queue=queue
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "max_receive_count": max_receive_count,
            "queue": queue,
        }

    @builtins.property
    def max_receive_count(self) -> jsii.Number:
        '''The number of times a message can be unsuccesfully dequeued before being moved to the dead-letter queue.'''
        result = self._values.get("max_receive_count")
        assert result is not None, "Required property 'max_receive_count' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def queue(self) -> "IQueue":
        '''The dead-letter queue to which Amazon SQS moves messages after the value of maxReceiveCount is exceeded.'''
        result = self._values.get("queue")
        assert result is not None, "Required property 'queue' is missing"
        return typing.cast("IQueue", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DeadLetterQueue(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_sqs.DeduplicationScope")
class DeduplicationScope(enum.Enum):
    '''What kind of deduplication scope to apply.'''

    MESSAGE_GROUP = "MESSAGE_GROUP"
    '''Deduplication occurs at the message group level.'''
    QUEUE = "QUEUE"
    '''Deduplication occurs at the message queue level.'''


@jsii.enum(jsii_type="aws-cdk-lib.aws_sqs.FifoThroughputLimit")
class FifoThroughputLimit(enum.Enum):
    '''Whether the FIFO queue throughput quota applies to the entire queue or per message group.'''

    PER_QUEUE = "PER_QUEUE"
    '''Throughput quota applies per queue.'''
    PER_MESSAGE_GROUP_ID = "PER_MESSAGE_GROUP_ID"
    '''Throughput quota applies per message group id.'''


@jsii.interface(jsii_type="aws-cdk-lib.aws_sqs.IQueue")
class IQueue(_IResource_c80c4260, typing_extensions.Protocol):
    '''Represents an SQS queue.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fifo")
    def fifo(self) -> builtins.bool:
        '''Whether this queue is an Amazon SQS FIFO queue.

        If false, this is a standard queue.
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueArn")
    def queue_arn(self) -> builtins.str:
        '''The ARN of this queue.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueName")
    def queue_name(self) -> builtins.str:
        '''The name of this queue.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueUrl")
    def queue_url(self) -> builtins.str:
        '''The URL of this queue.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionMasterKey")
    def encryption_master_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''If this queue is server-side encrypted, this is the KMS encryption key.'''
        ...

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        statement: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Adds a statement to the IAM resource policy associated with this queue.

        If this queue was created in this stack (``new Queue``), a queue policy
        will be automatically created upon the first call to ``addToPolicy``. If
        the queue is imported (``Queue.import``), then this is a no-op.

        :param statement: -
        '''
        ...

    @jsii.member(jsii_name="grant")
    def grant(
        self,
        grantee: _IGrantable_71c4f5de,
        *queue_actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Grant the actions defined in queueActions to the identity Principal given on this SQS queue resource.

        :param grantee: Principal to grant right to.
        :param queue_actions: The actions to grant.
        '''
        ...

    @jsii.member(jsii_name="grantConsumeMessages")
    def grant_consume_messages(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant permissions to consume messages from a queue.

        This will grant the following permissions:

        - sqs:ChangeMessageVisibility
        - sqs:DeleteMessage
        - sqs:ReceiveMessage
        - sqs:GetQueueAttributes
        - sqs:GetQueueUrl

        :param grantee: Principal to grant consume rights to.
        '''
        ...

    @jsii.member(jsii_name="grantPurge")
    def grant_purge(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant an IAM principal permissions to purge all messages from the queue.

        This will grant the following permissions:

        - sqs:PurgeQueue
        - sqs:GetQueueAttributes
        - sqs:GetQueueUrl

        :param grantee: Principal to grant send rights to.
        '''
        ...

    @jsii.member(jsii_name="grantSendMessages")
    def grant_send_messages(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant access to send messages to a queue to the given identity.

        This will grant the following permissions:

        - sqs:SendMessage
        - sqs:GetQueueAttributes
        - sqs:GetQueueUrl

        :param grantee: Principal to grant send rights to.
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
        '''Return the given named metric for this Queue.

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

    @jsii.member(jsii_name="metricApproximateAgeOfOldestMessage")
    def metric_approximate_age_of_oldest_message(
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
        '''The approximate age of the oldest non-deleted message in the queue.

        Maximum over 5 minutes

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

    @jsii.member(jsii_name="metricApproximateNumberOfMessagesDelayed")
    def metric_approximate_number_of_messages_delayed(
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
        '''The number of messages in the queue that are delayed and not available for reading immediately.

        Maximum over 5 minutes

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

    @jsii.member(jsii_name="metricApproximateNumberOfMessagesNotVisible")
    def metric_approximate_number_of_messages_not_visible(
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
        '''The number of messages that are in flight.

        Maximum over 5 minutes

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

    @jsii.member(jsii_name="metricApproximateNumberOfMessagesVisible")
    def metric_approximate_number_of_messages_visible(
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
        '''The number of messages available for retrieval from the queue.

        Maximum over 5 minutes

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

    @jsii.member(jsii_name="metricNumberOfEmptyReceives")
    def metric_number_of_empty_receives(
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
        '''The number of ReceiveMessage API calls that did not return a message.

        Sum over 5 minutes

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

    @jsii.member(jsii_name="metricNumberOfMessagesDeleted")
    def metric_number_of_messages_deleted(
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
        '''The number of messages deleted from the queue.

        Sum over 5 minutes

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

    @jsii.member(jsii_name="metricNumberOfMessagesReceived")
    def metric_number_of_messages_received(
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
        '''The number of messages returned by calls to the ReceiveMessage action.

        Sum over 5 minutes

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

    @jsii.member(jsii_name="metricNumberOfMessagesSent")
    def metric_number_of_messages_sent(
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
        '''The number of messages added to a queue.

        Sum over 5 minutes

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

    @jsii.member(jsii_name="metricSentMessageSize")
    def metric_sent_message_size(
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
        '''The size of messages added to a queue.

        Average over 5 minutes

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


class _IQueueProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Represents an SQS queue.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_sqs.IQueue"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fifo")
    def fifo(self) -> builtins.bool:
        '''Whether this queue is an Amazon SQS FIFO queue.

        If false, this is a standard queue.
        '''
        return typing.cast(builtins.bool, jsii.get(self, "fifo"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueArn")
    def queue_arn(self) -> builtins.str:
        '''The ARN of this queue.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "queueArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueName")
    def queue_name(self) -> builtins.str:
        '''The name of this queue.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "queueName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueUrl")
    def queue_url(self) -> builtins.str:
        '''The URL of this queue.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "queueUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionMasterKey")
    def encryption_master_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''If this queue is server-side encrypted, this is the KMS encryption key.'''
        return typing.cast(typing.Optional[_IKey_5f11635f], jsii.get(self, "encryptionMasterKey"))

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        statement: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Adds a statement to the IAM resource policy associated with this queue.

        If this queue was created in this stack (``new Queue``), a queue policy
        will be automatically created upon the first call to ``addToPolicy``. If
        the queue is imported (``Queue.import``), then this is a no-op.

        :param statement: -
        '''
        return typing.cast(_AddToResourcePolicyResult_1d0a53ad, jsii.invoke(self, "addToResourcePolicy", [statement]))

    @jsii.member(jsii_name="grant")
    def grant(
        self,
        grantee: _IGrantable_71c4f5de,
        *queue_actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Grant the actions defined in queueActions to the identity Principal given on this SQS queue resource.

        :param grantee: Principal to grant right to.
        :param queue_actions: The actions to grant.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grant", [grantee, *queue_actions]))

    @jsii.member(jsii_name="grantConsumeMessages")
    def grant_consume_messages(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant permissions to consume messages from a queue.

        This will grant the following permissions:

        - sqs:ChangeMessageVisibility
        - sqs:DeleteMessage
        - sqs:ReceiveMessage
        - sqs:GetQueueAttributes
        - sqs:GetQueueUrl

        :param grantee: Principal to grant consume rights to.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantConsumeMessages", [grantee]))

    @jsii.member(jsii_name="grantPurge")
    def grant_purge(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant an IAM principal permissions to purge all messages from the queue.

        This will grant the following permissions:

        - sqs:PurgeQueue
        - sqs:GetQueueAttributes
        - sqs:GetQueueUrl

        :param grantee: Principal to grant send rights to.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPurge", [grantee]))

    @jsii.member(jsii_name="grantSendMessages")
    def grant_send_messages(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant access to send messages to a queue to the given identity.

        This will grant the following permissions:

        - sqs:SendMessage
        - sqs:GetQueueAttributes
        - sqs:GetQueueUrl

        :param grantee: Principal to grant send rights to.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantSendMessages", [grantee]))

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
        '''Return the given named metric for this Queue.

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

    @jsii.member(jsii_name="metricApproximateAgeOfOldestMessage")
    def metric_approximate_age_of_oldest_message(
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
        '''The approximate age of the oldest non-deleted message in the queue.

        Maximum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricApproximateAgeOfOldestMessage", [props]))

    @jsii.member(jsii_name="metricApproximateNumberOfMessagesDelayed")
    def metric_approximate_number_of_messages_delayed(
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
        '''The number of messages in the queue that are delayed and not available for reading immediately.

        Maximum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricApproximateNumberOfMessagesDelayed", [props]))

    @jsii.member(jsii_name="metricApproximateNumberOfMessagesNotVisible")
    def metric_approximate_number_of_messages_not_visible(
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
        '''The number of messages that are in flight.

        Maximum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricApproximateNumberOfMessagesNotVisible", [props]))

    @jsii.member(jsii_name="metricApproximateNumberOfMessagesVisible")
    def metric_approximate_number_of_messages_visible(
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
        '''The number of messages available for retrieval from the queue.

        Maximum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricApproximateNumberOfMessagesVisible", [props]))

    @jsii.member(jsii_name="metricNumberOfEmptyReceives")
    def metric_number_of_empty_receives(
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
        '''The number of ReceiveMessage API calls that did not return a message.

        Sum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricNumberOfEmptyReceives", [props]))

    @jsii.member(jsii_name="metricNumberOfMessagesDeleted")
    def metric_number_of_messages_deleted(
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
        '''The number of messages deleted from the queue.

        Sum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricNumberOfMessagesDeleted", [props]))

    @jsii.member(jsii_name="metricNumberOfMessagesReceived")
    def metric_number_of_messages_received(
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
        '''The number of messages returned by calls to the ReceiveMessage action.

        Sum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricNumberOfMessagesReceived", [props]))

    @jsii.member(jsii_name="metricNumberOfMessagesSent")
    def metric_number_of_messages_sent(
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
        '''The number of messages added to a queue.

        Sum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricNumberOfMessagesSent", [props]))

    @jsii.member(jsii_name="metricSentMessageSize")
    def metric_sent_message_size(
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
        '''The size of messages added to a queue.

        Average over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricSentMessageSize", [props]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IQueue).__jsii_proxy_class__ = lambda : _IQueueProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_sqs.QueueAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "queue_arn": "queueArn",
        "fifo": "fifo",
        "key_arn": "keyArn",
        "queue_name": "queueName",
        "queue_url": "queueUrl",
    },
)
class QueueAttributes:
    def __init__(
        self,
        *,
        queue_arn: builtins.str,
        fifo: typing.Optional[builtins.bool] = None,
        key_arn: typing.Optional[builtins.str] = None,
        queue_name: typing.Optional[builtins.str] = None,
        queue_url: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Reference to a queue.

        :param queue_arn: The ARN of the queue.
        :param fifo: Whether this queue is an Amazon SQS FIFO queue. If false, this is a standard queue. In case of a FIFO queue which is imported from a token, this value has to be explicitly set to true. Default: - if fifo is not specified, the property will be determined based on the queue name (not possible for FIFO queues imported from a token)
        :param key_arn: KMS encryption key, if this queue is server-side encrypted by a KMS key. Default: - None
        :param queue_name: The name of the queue. Default: if queue name is not specified, the name will be derived from the queue ARN
        :param queue_url: The URL of the queue. Default: - 'https://sqs.//'

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_sqs as sqs
            
            queue_attributes = sqs.QueueAttributes(
                queue_arn="queueArn",
            
                # the properties below are optional
                fifo=False,
                key_arn="keyArn",
                queue_name="queueName",
                queue_url="queueUrl"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "queue_arn": queue_arn,
        }
        if fifo is not None:
            self._values["fifo"] = fifo
        if key_arn is not None:
            self._values["key_arn"] = key_arn
        if queue_name is not None:
            self._values["queue_name"] = queue_name
        if queue_url is not None:
            self._values["queue_url"] = queue_url

    @builtins.property
    def queue_arn(self) -> builtins.str:
        '''The ARN of the queue.'''
        result = self._values.get("queue_arn")
        assert result is not None, "Required property 'queue_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def fifo(self) -> typing.Optional[builtins.bool]:
        '''Whether this queue is an Amazon SQS FIFO queue. If false, this is a standard queue.

        In case of a FIFO queue which is imported from a token, this value has to be explicitly set to true.

        :default: - if fifo is not specified, the property will be determined based on the queue name (not possible for FIFO queues imported from a token)
        '''
        result = self._values.get("fifo")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def key_arn(self) -> typing.Optional[builtins.str]:
        '''KMS encryption key, if this queue is server-side encrypted by a KMS key.

        :default: - None
        '''
        result = self._values.get("key_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def queue_name(self) -> typing.Optional[builtins.str]:
        '''The name of the queue.

        :default: if queue name is not specified, the name will be derived from the queue ARN
        '''
        result = self._values.get("queue_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def queue_url(self) -> typing.Optional[builtins.str]:
        '''The URL of the queue.

        :default: - 'https://sqs.//'

        :see: https://docs.aws.amazon.com/sdk-for-net/v2/developer-guide/QueueURL.html
        '''
        result = self._values.get("queue_url")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "QueueAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IQueue)
class QueueBase(
    _Resource_45bc6135,
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_sqs.QueueBase",
):
    '''Reference to a new or existing Amazon SQS queue.'''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        account: typing.Optional[builtins.str] = None,
        environment_from_arn: typing.Optional[builtins.str] = None,
        physical_name: typing.Optional[builtins.str] = None,
        region: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param account: The AWS account ID this resource belongs to. Default: - the resource is in the same account as the stack it belongs to
        :param environment_from_arn: ARN to deduce region and account from. The ARN is parsed and the account and region are taken from the ARN. This should be used for imported resources. Cannot be supplied together with either ``account`` or ``region``. Default: - take environment from ``account``, ``region`` parameters, or use Stack environment.
        :param physical_name: The value passed in by users to the physical name prop of the resource. - ``undefined`` implies that a physical name will be allocated by CloudFormation during deployment. - a concrete value implies a specific physical name - ``PhysicalName.GENERATE_IF_NEEDED`` is a marker that indicates that a physical will only be generated by the CDK if it is needed for cross-environment references. Otherwise, it will be allocated by CloudFormation. Default: - The physical name will be allocated by CloudFormation at deployment time
        :param region: The AWS region this resource belongs to. Default: - the resource is in the same region as the stack it belongs to
        '''
        props = _ResourceProps_15a65b4e(
            account=account,
            environment_from_arn=environment_from_arn,
            physical_name=physical_name,
            region=region,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        statement: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Adds a statement to the IAM resource policy associated with this queue.

        If this queue was created in this stack (``new Queue``), a queue policy
        will be automatically created upon the first call to ``addToPolicy``. If
        the queue is imported (``Queue.import``), then this is a no-op.

        :param statement: -
        '''
        return typing.cast(_AddToResourcePolicyResult_1d0a53ad, jsii.invoke(self, "addToResourcePolicy", [statement]))

    @jsii.member(jsii_name="grant")
    def grant(
        self,
        grantee: _IGrantable_71c4f5de,
        *actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Grant the actions defined in queueActions to the identity Principal given on this SQS queue resource.

        :param grantee: Principal to grant right to.
        :param actions: The actions to grant.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grant", [grantee, *actions]))

    @jsii.member(jsii_name="grantConsumeMessages")
    def grant_consume_messages(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant permissions to consume messages from a queue.

        This will grant the following permissions:

        - sqs:ChangeMessageVisibility
        - sqs:DeleteMessage
        - sqs:ReceiveMessage
        - sqs:GetQueueAttributes
        - sqs:GetQueueUrl

        :param grantee: Principal to grant consume rights to.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantConsumeMessages", [grantee]))

    @jsii.member(jsii_name="grantPurge")
    def grant_purge(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant an IAM principal permissions to purge all messages from the queue.

        This will grant the following permissions:

        - sqs:PurgeQueue
        - sqs:GetQueueAttributes
        - sqs:GetQueueUrl

        :param grantee: Principal to grant send rights to.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPurge", [grantee]))

    @jsii.member(jsii_name="grantSendMessages")
    def grant_send_messages(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant access to send messages to a queue to the given identity.

        This will grant the following permissions:

        - sqs:SendMessage
        - sqs:GetQueueAttributes
        - sqs:GetQueueUrl

        :param grantee: Principal to grant send rights to.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantSendMessages", [grantee]))

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
        '''Return the given named metric for this Queue.

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

    @jsii.member(jsii_name="metricApproximateAgeOfOldestMessage")
    def metric_approximate_age_of_oldest_message(
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
        '''The approximate age of the oldest non-deleted message in the queue.

        Maximum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricApproximateAgeOfOldestMessage", [props]))

    @jsii.member(jsii_name="metricApproximateNumberOfMessagesDelayed")
    def metric_approximate_number_of_messages_delayed(
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
        '''The number of messages in the queue that are delayed and not available for reading immediately.

        Maximum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricApproximateNumberOfMessagesDelayed", [props]))

    @jsii.member(jsii_name="metricApproximateNumberOfMessagesNotVisible")
    def metric_approximate_number_of_messages_not_visible(
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
        '''The number of messages that are in flight.

        Maximum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricApproximateNumberOfMessagesNotVisible", [props]))

    @jsii.member(jsii_name="metricApproximateNumberOfMessagesVisible")
    def metric_approximate_number_of_messages_visible(
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
        '''The number of messages available for retrieval from the queue.

        Maximum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricApproximateNumberOfMessagesVisible", [props]))

    @jsii.member(jsii_name="metricNumberOfEmptyReceives")
    def metric_number_of_empty_receives(
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
        '''The number of ReceiveMessage API calls that did not return a message.

        Sum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricNumberOfEmptyReceives", [props]))

    @jsii.member(jsii_name="metricNumberOfMessagesDeleted")
    def metric_number_of_messages_deleted(
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
        '''The number of messages deleted from the queue.

        Sum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricNumberOfMessagesDeleted", [props]))

    @jsii.member(jsii_name="metricNumberOfMessagesReceived")
    def metric_number_of_messages_received(
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
        '''The number of messages returned by calls to the ReceiveMessage action.

        Sum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricNumberOfMessagesReceived", [props]))

    @jsii.member(jsii_name="metricNumberOfMessagesSent")
    def metric_number_of_messages_sent(
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
        '''The number of messages added to a queue.

        Sum over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricNumberOfMessagesSent", [props]))

    @jsii.member(jsii_name="metricSentMessageSize")
    def metric_sent_message_size(
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
        '''The size of messages added to a queue.

        Average over 5 minutes

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

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricSentMessageSize", [props]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoCreatePolicy")
    @abc.abstractmethod
    def _auto_create_policy(self) -> builtins.bool:
        '''Controls automatic creation of policy objects.

        Set by subclasses.
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fifo")
    @abc.abstractmethod
    def fifo(self) -> builtins.bool:
        '''Whether this queue is an Amazon SQS FIFO queue.

        If false, this is a standard queue.
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueArn")
    @abc.abstractmethod
    def queue_arn(self) -> builtins.str:
        '''The ARN of this queue.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueName")
    @abc.abstractmethod
    def queue_name(self) -> builtins.str:
        '''The name of this queue.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueUrl")
    @abc.abstractmethod
    def queue_url(self) -> builtins.str:
        '''The URL of this queue.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionMasterKey")
    @abc.abstractmethod
    def encryption_master_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''If this queue is server-side encrypted, this is the KMS encryption key.'''
        ...


class _QueueBaseProxy(
    QueueBase, jsii.proxy_for(_Resource_45bc6135) # type: ignore[misc]
):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoCreatePolicy")
    def _auto_create_policy(self) -> builtins.bool:
        '''Controls automatic creation of policy objects.

        Set by subclasses.
        '''
        return typing.cast(builtins.bool, jsii.get(self, "autoCreatePolicy"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fifo")
    def fifo(self) -> builtins.bool:
        '''Whether this queue is an Amazon SQS FIFO queue.

        If false, this is a standard queue.
        '''
        return typing.cast(builtins.bool, jsii.get(self, "fifo"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueArn")
    def queue_arn(self) -> builtins.str:
        '''The ARN of this queue.'''
        return typing.cast(builtins.str, jsii.get(self, "queueArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueName")
    def queue_name(self) -> builtins.str:
        '''The name of this queue.'''
        return typing.cast(builtins.str, jsii.get(self, "queueName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueUrl")
    def queue_url(self) -> builtins.str:
        '''The URL of this queue.'''
        return typing.cast(builtins.str, jsii.get(self, "queueUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionMasterKey")
    def encryption_master_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''If this queue is server-side encrypted, this is the KMS encryption key.'''
        return typing.cast(typing.Optional[_IKey_5f11635f], jsii.get(self, "encryptionMasterKey"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, QueueBase).__jsii_proxy_class__ = lambda : _QueueBaseProxy


@jsii.enum(jsii_type="aws-cdk-lib.aws_sqs.QueueEncryption")
class QueueEncryption(enum.Enum):
    '''What kind of encryption to apply to this queue.

    :exampleMetadata: infused

    Example::

        # Use managed key
        sqs.Queue(self, "Queue",
            encryption=sqs.QueueEncryption.KMS_MANAGED
        )
        
        # Use custom key
        my_key = kms.Key(self, "Key")
        
        sqs.Queue(self, "Queue",
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=my_key
        )
    '''

    UNENCRYPTED = "UNENCRYPTED"
    '''Messages in the queue are not encrypted.'''
    KMS_MANAGED = "KMS_MANAGED"
    '''Server-side KMS encryption with a master key managed by SQS.'''
    KMS = "KMS"
    '''Server-side encryption with a KMS key managed by the user.

    If ``encryptionKey`` is specified, this key will be used, otherwise, one will be defined.
    '''


class QueuePolicy(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_sqs.QueuePolicy",
):
    '''The policy for an SQS Queue.

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
        from aws_cdk import aws_sqs as sqs
        
        # queue: sqs.Queue
        
        queue_policy = sqs.QueuePolicy(self, "MyQueuePolicy",
            queues=[queue]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        queues: typing.Sequence[IQueue],
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param queues: The set of queues this policy applies to.
        '''
        props = QueuePolicyProps(queues=queues)

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="document")
    def document(self) -> _PolicyDocument_3ac34393:
        '''The IAM policy document for this policy.'''
        return typing.cast(_PolicyDocument_3ac34393, jsii.get(self, "document"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queuePolicyId")
    def queue_policy_id(self) -> builtins.str:
        '''Not currently supported by AWS CloudFormation.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "queuePolicyId"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_sqs.QueuePolicyProps",
    jsii_struct_bases=[],
    name_mapping={"queues": "queues"},
)
class QueuePolicyProps:
    def __init__(self, *, queues: typing.Sequence[IQueue]) -> None:
        '''Properties to associate SQS queues with a policy.

        :param queues: The set of queues this policy applies to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_sqs as sqs
            
            # queue: sqs.Queue
            
            queue_policy_props = sqs.QueuePolicyProps(
                queues=[queue]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "queues": queues,
        }

    @builtins.property
    def queues(self) -> typing.List[IQueue]:
        '''The set of queues this policy applies to.'''
        result = self._values.get("queues")
        assert result is not None, "Required property 'queues' is missing"
        return typing.cast(typing.List[IQueue], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "QueuePolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_sqs.QueueProps",
    jsii_struct_bases=[],
    name_mapping={
        "content_based_deduplication": "contentBasedDeduplication",
        "data_key_reuse": "dataKeyReuse",
        "dead_letter_queue": "deadLetterQueue",
        "deduplication_scope": "deduplicationScope",
        "delivery_delay": "deliveryDelay",
        "encryption": "encryption",
        "encryption_master_key": "encryptionMasterKey",
        "fifo": "fifo",
        "fifo_throughput_limit": "fifoThroughputLimit",
        "max_message_size_bytes": "maxMessageSizeBytes",
        "queue_name": "queueName",
        "receive_message_wait_time": "receiveMessageWaitTime",
        "removal_policy": "removalPolicy",
        "retention_period": "retentionPeriod",
        "visibility_timeout": "visibilityTimeout",
    },
)
class QueueProps:
    def __init__(
        self,
        *,
        content_based_deduplication: typing.Optional[builtins.bool] = None,
        data_key_reuse: typing.Optional[_Duration_4839e8c3] = None,
        dead_letter_queue: typing.Optional[DeadLetterQueue] = None,
        deduplication_scope: typing.Optional[DeduplicationScope] = None,
        delivery_delay: typing.Optional[_Duration_4839e8c3] = None,
        encryption: typing.Optional[QueueEncryption] = None,
        encryption_master_key: typing.Optional[_IKey_5f11635f] = None,
        fifo: typing.Optional[builtins.bool] = None,
        fifo_throughput_limit: typing.Optional[FifoThroughputLimit] = None,
        max_message_size_bytes: typing.Optional[jsii.Number] = None,
        queue_name: typing.Optional[builtins.str] = None,
        receive_message_wait_time: typing.Optional[_Duration_4839e8c3] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        retention_period: typing.Optional[_Duration_4839e8c3] = None,
        visibility_timeout: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Properties for creating a new Queue.

        :param content_based_deduplication: Specifies whether to enable content-based deduplication. During the deduplication interval (5 minutes), Amazon SQS treats messages that are sent with identical content (excluding attributes) as duplicates and delivers only one copy of the message. If you don't enable content-based deduplication and you want to deduplicate messages, provide an explicit deduplication ID in your SendMessage() call. (Only applies to FIFO queues.) Default: false
        :param data_key_reuse: The length of time that Amazon SQS reuses a data key before calling KMS again. The value must be an integer between 60 (1 minute) and 86,400 (24 hours). The default is 300 (5 minutes). Default: Duration.minutes(5)
        :param dead_letter_queue: Send messages to this queue if they were unsuccessfully dequeued a number of times. Default: no dead-letter queue
        :param deduplication_scope: For high throughput for FIFO queues, specifies whether message deduplication occurs at the message group or queue level. (Only applies to FIFO queues.) Default: DeduplicationScope.QUEUE
        :param delivery_delay: The time in seconds that the delivery of all messages in the queue is delayed. You can specify an integer value of 0 to 900 (15 minutes). The default value is 0. Default: 0
        :param encryption: Whether the contents of the queue are encrypted, and by what type of key. Be aware that encryption is not available in all regions, please see the docs for current availability details. Default: Unencrypted
        :param encryption_master_key: External KMS master key to use for queue encryption. Individual messages will be encrypted using data keys. The data keys in turn will be encrypted using this key, and reused for a maximum of ``dataKeyReuseSecs`` seconds. If the 'encryptionMasterKey' property is set, 'encryption' type will be implicitly set to "KMS". Default: If encryption is set to KMS and not specified, a key will be created.
        :param fifo: Whether this a first-in-first-out (FIFO) queue. Default: false, unless queueName ends in '.fifo' or 'contentBasedDeduplication' is true.
        :param fifo_throughput_limit: For high throughput for FIFO queues, specifies whether the FIFO queue throughput quota applies to the entire queue or per message group. (Only applies to FIFO queues.) Default: FifoThroughputLimit.PER_QUEUE
        :param max_message_size_bytes: The limit of how many bytes that a message can contain before Amazon SQS rejects it. You can specify an integer value from 1024 bytes (1 KiB) to 262144 bytes (256 KiB). The default value is 262144 (256 KiB). Default: 256KiB
        :param queue_name: A name for the queue. If specified and this is a FIFO queue, must end in the string '.fifo'. Default: CloudFormation-generated name
        :param receive_message_wait_time: Default wait time for ReceiveMessage calls. Does not wait if set to 0, otherwise waits this amount of seconds by default for messages to arrive. For more information, see Amazon SQS Long Poll. Default: 0
        :param removal_policy: Policy to apply when the user pool is removed from the stack. Even though queues are technically stateful, their contents are transient and it is common to add and remove Queues while rearchitecting your application. The default is therefore ``DESTROY``. Change it to ``RETAIN`` if the messages are so valuable that accidentally losing them would be unacceptable. Default: RemovalPolicy.DESTROY
        :param retention_period: The number of seconds that Amazon SQS retains a message. You can specify an integer value from 60 seconds (1 minute) to 1209600 seconds (14 days). The default value is 345600 seconds (4 days). Default: Duration.days(4)
        :param visibility_timeout: Timeout of processing a single message. After dequeuing, the processor has this much time to handle the message and delete it from the queue before it becomes visible again for dequeueing by another processor. Values must be from 0 to 43200 seconds (12 hours). If you don't specify a value, AWS CloudFormation uses the default value of 30 seconds. Default: Duration.seconds(30)

        :exampleMetadata: infused

        Example::

            # Use managed key
            sqs.Queue(self, "Queue",
                encryption=sqs.QueueEncryption.KMS_MANAGED
            )
            
            # Use custom key
            my_key = kms.Key(self, "Key")
            
            sqs.Queue(self, "Queue",
                encryption=sqs.QueueEncryption.KMS,
                encryption_master_key=my_key
            )
        '''
        if isinstance(dead_letter_queue, dict):
            dead_letter_queue = DeadLetterQueue(**dead_letter_queue)
        self._values: typing.Dict[str, typing.Any] = {}
        if content_based_deduplication is not None:
            self._values["content_based_deduplication"] = content_based_deduplication
        if data_key_reuse is not None:
            self._values["data_key_reuse"] = data_key_reuse
        if dead_letter_queue is not None:
            self._values["dead_letter_queue"] = dead_letter_queue
        if deduplication_scope is not None:
            self._values["deduplication_scope"] = deduplication_scope
        if delivery_delay is not None:
            self._values["delivery_delay"] = delivery_delay
        if encryption is not None:
            self._values["encryption"] = encryption
        if encryption_master_key is not None:
            self._values["encryption_master_key"] = encryption_master_key
        if fifo is not None:
            self._values["fifo"] = fifo
        if fifo_throughput_limit is not None:
            self._values["fifo_throughput_limit"] = fifo_throughput_limit
        if max_message_size_bytes is not None:
            self._values["max_message_size_bytes"] = max_message_size_bytes
        if queue_name is not None:
            self._values["queue_name"] = queue_name
        if receive_message_wait_time is not None:
            self._values["receive_message_wait_time"] = receive_message_wait_time
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy
        if retention_period is not None:
            self._values["retention_period"] = retention_period
        if visibility_timeout is not None:
            self._values["visibility_timeout"] = visibility_timeout

    @builtins.property
    def content_based_deduplication(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether to enable content-based deduplication.

        During the deduplication interval (5 minutes), Amazon SQS treats
        messages that are sent with identical content (excluding attributes) as
        duplicates and delivers only one copy of the message.

        If you don't enable content-based deduplication and you want to deduplicate
        messages, provide an explicit deduplication ID in your SendMessage() call.

        (Only applies to FIFO queues.)

        :default: false
        '''
        result = self._values.get("content_based_deduplication")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def data_key_reuse(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The length of time that Amazon SQS reuses a data key before calling KMS again.

        The value must be an integer between 60 (1 minute) and 86,400 (24
        hours). The default is 300 (5 minutes).

        :default: Duration.minutes(5)
        '''
        result = self._values.get("data_key_reuse")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def dead_letter_queue(self) -> typing.Optional[DeadLetterQueue]:
        '''Send messages to this queue if they were unsuccessfully dequeued a number of times.

        :default: no dead-letter queue
        '''
        result = self._values.get("dead_letter_queue")
        return typing.cast(typing.Optional[DeadLetterQueue], result)

    @builtins.property
    def deduplication_scope(self) -> typing.Optional[DeduplicationScope]:
        '''For high throughput for FIFO queues, specifies whether message deduplication occurs at the message group or queue level.

        (Only applies to FIFO queues.)

        :default: DeduplicationScope.QUEUE
        '''
        result = self._values.get("deduplication_scope")
        return typing.cast(typing.Optional[DeduplicationScope], result)

    @builtins.property
    def delivery_delay(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The time in seconds that the delivery of all messages in the queue is delayed.

        You can specify an integer value of 0 to 900 (15 minutes). The default
        value is 0.

        :default: 0
        '''
        result = self._values.get("delivery_delay")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def encryption(self) -> typing.Optional[QueueEncryption]:
        '''Whether the contents of the queue are encrypted, and by what type of key.

        Be aware that encryption is not available in all regions, please see the docs
        for current availability details.

        :default: Unencrypted
        '''
        result = self._values.get("encryption")
        return typing.cast(typing.Optional[QueueEncryption], result)

    @builtins.property
    def encryption_master_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''External KMS master key to use for queue encryption.

        Individual messages will be encrypted using data keys. The data keys in
        turn will be encrypted using this key, and reused for a maximum of
        ``dataKeyReuseSecs`` seconds.

        If the 'encryptionMasterKey' property is set, 'encryption' type will be
        implicitly set to "KMS".

        :default: If encryption is set to KMS and not specified, a key will be created.
        '''
        result = self._values.get("encryption_master_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def fifo(self) -> typing.Optional[builtins.bool]:
        '''Whether this a first-in-first-out (FIFO) queue.

        :default: false, unless queueName ends in '.fifo' or 'contentBasedDeduplication' is true.
        '''
        result = self._values.get("fifo")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def fifo_throughput_limit(self) -> typing.Optional[FifoThroughputLimit]:
        '''For high throughput for FIFO queues, specifies whether the FIFO queue throughput quota applies to the entire queue or per message group.

        (Only applies to FIFO queues.)

        :default: FifoThroughputLimit.PER_QUEUE
        '''
        result = self._values.get("fifo_throughput_limit")
        return typing.cast(typing.Optional[FifoThroughputLimit], result)

    @builtins.property
    def max_message_size_bytes(self) -> typing.Optional[jsii.Number]:
        '''The limit of how many bytes that a message can contain before Amazon SQS rejects it.

        You can specify an integer value from 1024 bytes (1 KiB) to 262144 bytes
        (256 KiB). The default value is 262144 (256 KiB).

        :default: 256KiB
        '''
        result = self._values.get("max_message_size_bytes")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def queue_name(self) -> typing.Optional[builtins.str]:
        '''A name for the queue.

        If specified and this is a FIFO queue, must end in the string '.fifo'.

        :default: CloudFormation-generated name
        '''
        result = self._values.get("queue_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def receive_message_wait_time(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Default wait time for ReceiveMessage calls.

        Does not wait if set to 0, otherwise waits this amount of seconds
        by default for messages to arrive.

        For more information, see Amazon SQS Long Poll.

        :default: 0
        '''
        result = self._values.get("receive_message_wait_time")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''Policy to apply when the user pool is removed from the stack.

        Even though queues are technically stateful, their contents are transient and it
        is common to add and remove Queues while rearchitecting your application. The
        default is therefore ``DESTROY``. Change it to ``RETAIN`` if the messages are so
        valuable that accidentally losing them would be unacceptable.

        :default: RemovalPolicy.DESTROY
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    @builtins.property
    def retention_period(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The number of seconds that Amazon SQS retains a message.

        You can specify an integer value from 60 seconds (1 minute) to 1209600
        seconds (14 days). The default value is 345600 seconds (4 days).

        :default: Duration.days(4)
        '''
        result = self._values.get("retention_period")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def visibility_timeout(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Timeout of processing a single message.

        After dequeuing, the processor has this much time to handle the message
        and delete it from the queue before it becomes visible again for dequeueing
        by another processor.

        Values must be from 0 to 43200 seconds (12 hours). If you don't specify
        a value, AWS CloudFormation uses the default value of 30 seconds.

        :default: Duration.seconds(30)
        '''
        result = self._values.get("visibility_timeout")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "QueueProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class Queue(QueueBase, metaclass=jsii.JSIIMeta, jsii_type="aws-cdk-lib.aws_sqs.Queue"):
    '''A new Amazon SQS queue.

    :exampleMetadata: infused

    Example::

        # An sqs queue for unsuccessful invocations of a lambda function
        import aws_cdk.aws_sqs as sqs
        
        
        dead_letter_queue = sqs.Queue(self, "DeadLetterQueue")
        
        my_fn = lambda_.Function(self, "Fn",
            runtime=lambda_.Runtime.NODEJS_12_X,
            handler="index.handler",
            code=lambda_.Code.from_inline("// your code"),
            # sqs queue for unsuccessful invocations
            on_failure=destinations.SqsDestination(dead_letter_queue)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        content_based_deduplication: typing.Optional[builtins.bool] = None,
        data_key_reuse: typing.Optional[_Duration_4839e8c3] = None,
        dead_letter_queue: typing.Optional[DeadLetterQueue] = None,
        deduplication_scope: typing.Optional[DeduplicationScope] = None,
        delivery_delay: typing.Optional[_Duration_4839e8c3] = None,
        encryption: typing.Optional[QueueEncryption] = None,
        encryption_master_key: typing.Optional[_IKey_5f11635f] = None,
        fifo: typing.Optional[builtins.bool] = None,
        fifo_throughput_limit: typing.Optional[FifoThroughputLimit] = None,
        max_message_size_bytes: typing.Optional[jsii.Number] = None,
        queue_name: typing.Optional[builtins.str] = None,
        receive_message_wait_time: typing.Optional[_Duration_4839e8c3] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        retention_period: typing.Optional[_Duration_4839e8c3] = None,
        visibility_timeout: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param content_based_deduplication: Specifies whether to enable content-based deduplication. During the deduplication interval (5 minutes), Amazon SQS treats messages that are sent with identical content (excluding attributes) as duplicates and delivers only one copy of the message. If you don't enable content-based deduplication and you want to deduplicate messages, provide an explicit deduplication ID in your SendMessage() call. (Only applies to FIFO queues.) Default: false
        :param data_key_reuse: The length of time that Amazon SQS reuses a data key before calling KMS again. The value must be an integer between 60 (1 minute) and 86,400 (24 hours). The default is 300 (5 minutes). Default: Duration.minutes(5)
        :param dead_letter_queue: Send messages to this queue if they were unsuccessfully dequeued a number of times. Default: no dead-letter queue
        :param deduplication_scope: For high throughput for FIFO queues, specifies whether message deduplication occurs at the message group or queue level. (Only applies to FIFO queues.) Default: DeduplicationScope.QUEUE
        :param delivery_delay: The time in seconds that the delivery of all messages in the queue is delayed. You can specify an integer value of 0 to 900 (15 minutes). The default value is 0. Default: 0
        :param encryption: Whether the contents of the queue are encrypted, and by what type of key. Be aware that encryption is not available in all regions, please see the docs for current availability details. Default: Unencrypted
        :param encryption_master_key: External KMS master key to use for queue encryption. Individual messages will be encrypted using data keys. The data keys in turn will be encrypted using this key, and reused for a maximum of ``dataKeyReuseSecs`` seconds. If the 'encryptionMasterKey' property is set, 'encryption' type will be implicitly set to "KMS". Default: If encryption is set to KMS and not specified, a key will be created.
        :param fifo: Whether this a first-in-first-out (FIFO) queue. Default: false, unless queueName ends in '.fifo' or 'contentBasedDeduplication' is true.
        :param fifo_throughput_limit: For high throughput for FIFO queues, specifies whether the FIFO queue throughput quota applies to the entire queue or per message group. (Only applies to FIFO queues.) Default: FifoThroughputLimit.PER_QUEUE
        :param max_message_size_bytes: The limit of how many bytes that a message can contain before Amazon SQS rejects it. You can specify an integer value from 1024 bytes (1 KiB) to 262144 bytes (256 KiB). The default value is 262144 (256 KiB). Default: 256KiB
        :param queue_name: A name for the queue. If specified and this is a FIFO queue, must end in the string '.fifo'. Default: CloudFormation-generated name
        :param receive_message_wait_time: Default wait time for ReceiveMessage calls. Does not wait if set to 0, otherwise waits this amount of seconds by default for messages to arrive. For more information, see Amazon SQS Long Poll. Default: 0
        :param removal_policy: Policy to apply when the user pool is removed from the stack. Even though queues are technically stateful, their contents are transient and it is common to add and remove Queues while rearchitecting your application. The default is therefore ``DESTROY``. Change it to ``RETAIN`` if the messages are so valuable that accidentally losing them would be unacceptable. Default: RemovalPolicy.DESTROY
        :param retention_period: The number of seconds that Amazon SQS retains a message. You can specify an integer value from 60 seconds (1 minute) to 1209600 seconds (14 days). The default value is 345600 seconds (4 days). Default: Duration.days(4)
        :param visibility_timeout: Timeout of processing a single message. After dequeuing, the processor has this much time to handle the message and delete it from the queue before it becomes visible again for dequeueing by another processor. Values must be from 0 to 43200 seconds (12 hours). If you don't specify a value, AWS CloudFormation uses the default value of 30 seconds. Default: Duration.seconds(30)
        '''
        props = QueueProps(
            content_based_deduplication=content_based_deduplication,
            data_key_reuse=data_key_reuse,
            dead_letter_queue=dead_letter_queue,
            deduplication_scope=deduplication_scope,
            delivery_delay=delivery_delay,
            encryption=encryption,
            encryption_master_key=encryption_master_key,
            fifo=fifo,
            fifo_throughput_limit=fifo_throughput_limit,
            max_message_size_bytes=max_message_size_bytes,
            queue_name=queue_name,
            receive_message_wait_time=receive_message_wait_time,
            removal_policy=removal_policy,
            retention_period=retention_period,
            visibility_timeout=visibility_timeout,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromQueueArn") # type: ignore[misc]
    @builtins.classmethod
    def from_queue_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        queue_arn: builtins.str,
    ) -> IQueue:
        '''Import an existing SQS queue provided an ARN.

        :param scope: The parent creating construct.
        :param id: The construct's name.
        :param queue_arn: queue ARN (i.e. arn:aws:sqs:us-east-2:444455556666:queue1).
        '''
        return typing.cast(IQueue, jsii.sinvoke(cls, "fromQueueArn", [scope, id, queue_arn]))

    @jsii.member(jsii_name="fromQueueAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_queue_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        queue_arn: builtins.str,
        fifo: typing.Optional[builtins.bool] = None,
        key_arn: typing.Optional[builtins.str] = None,
        queue_name: typing.Optional[builtins.str] = None,
        queue_url: typing.Optional[builtins.str] = None,
    ) -> IQueue:
        '''Import an existing queue.

        :param scope: -
        :param id: -
        :param queue_arn: The ARN of the queue.
        :param fifo: Whether this queue is an Amazon SQS FIFO queue. If false, this is a standard queue. In case of a FIFO queue which is imported from a token, this value has to be explicitly set to true. Default: - if fifo is not specified, the property will be determined based on the queue name (not possible for FIFO queues imported from a token)
        :param key_arn: KMS encryption key, if this queue is server-side encrypted by a KMS key. Default: - None
        :param queue_name: The name of the queue. Default: if queue name is not specified, the name will be derived from the queue ARN
        :param queue_url: The URL of the queue. Default: - 'https://sqs.//'
        '''
        attrs = QueueAttributes(
            queue_arn=queue_arn,
            fifo=fifo,
            key_arn=key_arn,
            queue_name=queue_name,
            queue_url=queue_url,
        )

        return typing.cast(IQueue, jsii.sinvoke(cls, "fromQueueAttributes", [scope, id, attrs]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoCreatePolicy")
    def _auto_create_policy(self) -> builtins.bool:
        '''Controls automatic creation of policy objects.

        Set by subclasses.
        '''
        return typing.cast(builtins.bool, jsii.get(self, "autoCreatePolicy"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fifo")
    def fifo(self) -> builtins.bool:
        '''Whether this queue is an Amazon SQS FIFO queue.

        If false, this is a standard queue.
        '''
        return typing.cast(builtins.bool, jsii.get(self, "fifo"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueArn")
    def queue_arn(self) -> builtins.str:
        '''The ARN of this queue.'''
        return typing.cast(builtins.str, jsii.get(self, "queueArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueName")
    def queue_name(self) -> builtins.str:
        '''The name of this queue.'''
        return typing.cast(builtins.str, jsii.get(self, "queueName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queueUrl")
    def queue_url(self) -> builtins.str:
        '''The URL of this queue.'''
        return typing.cast(builtins.str, jsii.get(self, "queueUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="deadLetterQueue")
    def dead_letter_queue(self) -> typing.Optional[DeadLetterQueue]:
        '''If this queue is configured with a dead-letter queue, this is the dead-letter queue settings.'''
        return typing.cast(typing.Optional[DeadLetterQueue], jsii.get(self, "deadLetterQueue"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionMasterKey")
    def encryption_master_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''If this queue is encrypted, this is the KMS key.'''
        return typing.cast(typing.Optional[_IKey_5f11635f], jsii.get(self, "encryptionMasterKey"))


__all__ = [
    "CfnQueue",
    "CfnQueuePolicy",
    "CfnQueuePolicyProps",
    "CfnQueueProps",
    "DeadLetterQueue",
    "DeduplicationScope",
    "FifoThroughputLimit",
    "IQueue",
    "Queue",
    "QueueAttributes",
    "QueueBase",
    "QueueEncryption",
    "QueuePolicy",
    "QueuePolicyProps",
    "QueueProps",
]

publication.publish()
