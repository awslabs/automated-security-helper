'''
# AWS::IoTEvents Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_iotevents as iotevents
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-iotevents-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::IoTEvents](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_IoTEvents.html).

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
class CfnDetectorModel(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel",
):
    '''A CloudFormation ``AWS::IoTEvents::DetectorModel``.

    The AWS::IoTEvents::DetectorModel resource creates a detector model. You create a *detector model* (a model of your equipment or process) using *states* . For each state, you define conditional (Boolean) logic that evaluates the incoming inputs to detect significant events. When an event is detected, it can change the state or trigger custom-built or predefined actions using other AWS services. You can define additional events that trigger actions when entering or exiting a state and, optionally, when a condition is met. For more information, see `How to Use AWS IoT Events <https://docs.aws.amazon.com/iotevents/latest/developerguide/how-to-use-iotevents.html>`_ in the *AWS IoT Events Developer Guide* .
    .. epigraph::

       When you successfully update a detector model (using the AWS IoT Events console, AWS IoT Events API or CLI commands, or AWS CloudFormation ) all detector instances created by the model are reset to their initial states. (The detector's ``state`` , and the values of any variables and timers are reset.)

       When you successfully update a detector model (using the AWS IoT Events console, AWS IoT Events API or CLI commands, or AWS CloudFormation ) the version number of the detector model is incremented. (A detector model with version number 1 before the update has version number 2 after the update succeeds.)

       If you attempt to update a detector model using AWS CloudFormation and the update does not succeed, the system may, in some cases, restore the original detector model. When this occurs, the detector model's version is incremented twice (for example, from version 1 to version 3) and the detector instances are reset.

       Also, be aware that if you attempt to update several detector models at once using AWS CloudFormation , some updates may succeed and others fail. In this case, the effects on each detector model's detector instances and version number depend on whether the update succeeded or failed, with the results as stated.

    :cloudformationResource: AWS::IoTEvents::DetectorModel
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotevents as iotevents
        
        cfn_detector_model = iotevents.CfnDetectorModel(self, "MyCfnDetectorModel",
            detector_model_definition=iotevents.CfnDetectorModel.DetectorModelDefinitionProperty(
                initial_state_name="initialStateName",
                states=[iotevents.CfnDetectorModel.StateProperty(
                    state_name="stateName",
        
                    # the properties below are optional
                    on_enter=iotevents.CfnDetectorModel.OnEnterProperty(
                        events=[iotevents.CfnDetectorModel.EventProperty(
                            event_name="eventName",
        
                            # the properties below are optional
                            actions=[iotevents.CfnDetectorModel.ActionProperty(
                                clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                    timer_name="timerName"
                                ),
                                dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                    hash_key_field="hashKeyField",
                                    hash_key_value="hashKeyValue",
                                    table_name="tableName",
        
                                    # the properties below are optional
                                    hash_key_type="hashKeyType",
                                    operation="operation",
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    payload_field="payloadField",
                                    range_key_field="rangeKeyField",
                                    range_key_type="rangeKeyType",
                                    range_key_value="rangeKeyValue"
                                ),
                                dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                    table_name="tableName",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                    delivery_stream_name="deliveryStreamName",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    separator="separator"
                                ),
                                iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                    input_name="inputName",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                    property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                        value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                            boolean_value="booleanValue",
                                            double_value="doubleValue",
                                            integer_value="integerValue",
                                            string_value="stringValue"
                                        ),
        
                                        # the properties below are optional
                                        quality="quality",
                                        timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                            time_in_seconds="timeInSeconds",
        
                                            # the properties below are optional
                                            offset_in_nanos="offsetInNanos"
                                        )
                                    ),
        
                                    # the properties below are optional
                                    asset_id="assetId",
                                    entry_id="entryId",
                                    property_alias="propertyAlias",
                                    property_id="propertyId"
                                ),
                                iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                    mqtt_topic="mqttTopic",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                    function_arn="functionArn",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                    timer_name="timerName"
                                ),
                                set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                    timer_name="timerName",
        
                                    # the properties below are optional
                                    duration_expression="durationExpression",
                                    seconds=123
                                ),
                                set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                    value="value",
                                    variable_name="variableName"
                                ),
                                sns=iotevents.CfnDetectorModel.SnsProperty(
                                    target_arn="targetArn",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                sqs=iotevents.CfnDetectorModel.SqsProperty(
                                    queue_url="queueUrl",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    use_base64=False
                                )
                            )],
                            condition="condition"
                        )]
                    ),
                    on_exit=iotevents.CfnDetectorModel.OnExitProperty(
                        events=[iotevents.CfnDetectorModel.EventProperty(
                            event_name="eventName",
        
                            # the properties below are optional
                            actions=[iotevents.CfnDetectorModel.ActionProperty(
                                clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                    timer_name="timerName"
                                ),
                                dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                    hash_key_field="hashKeyField",
                                    hash_key_value="hashKeyValue",
                                    table_name="tableName",
        
                                    # the properties below are optional
                                    hash_key_type="hashKeyType",
                                    operation="operation",
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    payload_field="payloadField",
                                    range_key_field="rangeKeyField",
                                    range_key_type="rangeKeyType",
                                    range_key_value="rangeKeyValue"
                                ),
                                dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                    table_name="tableName",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                    delivery_stream_name="deliveryStreamName",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    separator="separator"
                                ),
                                iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                    input_name="inputName",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                    property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                        value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                            boolean_value="booleanValue",
                                            double_value="doubleValue",
                                            integer_value="integerValue",
                                            string_value="stringValue"
                                        ),
        
                                        # the properties below are optional
                                        quality="quality",
                                        timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                            time_in_seconds="timeInSeconds",
        
                                            # the properties below are optional
                                            offset_in_nanos="offsetInNanos"
                                        )
                                    ),
        
                                    # the properties below are optional
                                    asset_id="assetId",
                                    entry_id="entryId",
                                    property_alias="propertyAlias",
                                    property_id="propertyId"
                                ),
                                iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                    mqtt_topic="mqttTopic",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                    function_arn="functionArn",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                    timer_name="timerName"
                                ),
                                set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                    timer_name="timerName",
        
                                    # the properties below are optional
                                    duration_expression="durationExpression",
                                    seconds=123
                                ),
                                set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                    value="value",
                                    variable_name="variableName"
                                ),
                                sns=iotevents.CfnDetectorModel.SnsProperty(
                                    target_arn="targetArn",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                sqs=iotevents.CfnDetectorModel.SqsProperty(
                                    queue_url="queueUrl",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    use_base64=False
                                )
                            )],
                            condition="condition"
                        )]
                    ),
                    on_input=iotevents.CfnDetectorModel.OnInputProperty(
                        events=[iotevents.CfnDetectorModel.EventProperty(
                            event_name="eventName",
        
                            # the properties below are optional
                            actions=[iotevents.CfnDetectorModel.ActionProperty(
                                clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                    timer_name="timerName"
                                ),
                                dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                    hash_key_field="hashKeyField",
                                    hash_key_value="hashKeyValue",
                                    table_name="tableName",
        
                                    # the properties below are optional
                                    hash_key_type="hashKeyType",
                                    operation="operation",
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    payload_field="payloadField",
                                    range_key_field="rangeKeyField",
                                    range_key_type="rangeKeyType",
                                    range_key_value="rangeKeyValue"
                                ),
                                dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                    table_name="tableName",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                    delivery_stream_name="deliveryStreamName",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    separator="separator"
                                ),
                                iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                    input_name="inputName",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                    property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                        value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                            boolean_value="booleanValue",
                                            double_value="doubleValue",
                                            integer_value="integerValue",
                                            string_value="stringValue"
                                        ),
        
                                        # the properties below are optional
                                        quality="quality",
                                        timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                            time_in_seconds="timeInSeconds",
        
                                            # the properties below are optional
                                            offset_in_nanos="offsetInNanos"
                                        )
                                    ),
        
                                    # the properties below are optional
                                    asset_id="assetId",
                                    entry_id="entryId",
                                    property_alias="propertyAlias",
                                    property_id="propertyId"
                                ),
                                iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                    mqtt_topic="mqttTopic",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                    function_arn="functionArn",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                    timer_name="timerName"
                                ),
                                set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                    timer_name="timerName",
        
                                    # the properties below are optional
                                    duration_expression="durationExpression",
                                    seconds=123
                                ),
                                set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                    value="value",
                                    variable_name="variableName"
                                ),
                                sns=iotevents.CfnDetectorModel.SnsProperty(
                                    target_arn="targetArn",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                sqs=iotevents.CfnDetectorModel.SqsProperty(
                                    queue_url="queueUrl",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    use_base64=False
                                )
                            )],
                            condition="condition"
                        )],
                        transition_events=[iotevents.CfnDetectorModel.TransitionEventProperty(
                            condition="condition",
                            event_name="eventName",
                            next_state="nextState",
        
                            # the properties below are optional
                            actions=[iotevents.CfnDetectorModel.ActionProperty(
                                clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                    timer_name="timerName"
                                ),
                                dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                    hash_key_field="hashKeyField",
                                    hash_key_value="hashKeyValue",
                                    table_name="tableName",
        
                                    # the properties below are optional
                                    hash_key_type="hashKeyType",
                                    operation="operation",
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    payload_field="payloadField",
                                    range_key_field="rangeKeyField",
                                    range_key_type="rangeKeyType",
                                    range_key_value="rangeKeyValue"
                                ),
                                dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                    table_name="tableName",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                    delivery_stream_name="deliveryStreamName",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    separator="separator"
                                ),
                                iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                    input_name="inputName",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                    property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                        value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                            boolean_value="booleanValue",
                                            double_value="doubleValue",
                                            integer_value="integerValue",
                                            string_value="stringValue"
                                        ),
        
                                        # the properties below are optional
                                        quality="quality",
                                        timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                            time_in_seconds="timeInSeconds",
        
                                            # the properties below are optional
                                            offset_in_nanos="offsetInNanos"
                                        )
                                    ),
        
                                    # the properties below are optional
                                    asset_id="assetId",
                                    entry_id="entryId",
                                    property_alias="propertyAlias",
                                    property_id="propertyId"
                                ),
                                iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                    mqtt_topic="mqttTopic",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                    function_arn="functionArn",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                    timer_name="timerName"
                                ),
                                set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                    timer_name="timerName",
        
                                    # the properties below are optional
                                    duration_expression="durationExpression",
                                    seconds=123
                                ),
                                set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                    value="value",
                                    variable_name="variableName"
                                ),
                                sns=iotevents.CfnDetectorModel.SnsProperty(
                                    target_arn="targetArn",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                sqs=iotevents.CfnDetectorModel.SqsProperty(
                                    queue_url="queueUrl",
        
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    use_base64=False
                                )
                            )]
                        )]
                    )
                )]
            ),
            role_arn="roleArn",
        
            # the properties below are optional
            detector_model_description="detectorModelDescription",
            detector_model_name="detectorModelName",
            evaluation_method="evaluationMethod",
            key="key",
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
        detector_model_definition: typing.Union["CfnDetectorModel.DetectorModelDefinitionProperty", _IResolvable_da3f097b],
        role_arn: builtins.str,
        detector_model_description: typing.Optional[builtins.str] = None,
        detector_model_name: typing.Optional[builtins.str] = None,
        evaluation_method: typing.Optional[builtins.str] = None,
        key: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::IoTEvents::DetectorModel``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param detector_model_definition: Information that defines how a detector operates.
        :param role_arn: The ARN of the role that grants permission to AWS IoT Events to perform its operations.
        :param detector_model_description: A brief description of the detector model.
        :param detector_model_name: The name of the detector model.
        :param evaluation_method: Information about the order in which events are evaluated and how actions are executed.
        :param key: The value used to identify a detector instance. When a device or system sends input, a new detector instance with a unique key value is created. AWS IoT Events can continue to route input to its corresponding detector instance based on this identifying information. This parameter uses a JSON-path expression to select the attribute-value pair in the message payload that is used for identification. To route the message to the correct detector instance, the device must send a message payload that contains the same attribute-value.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnDetectorModelProps(
            detector_model_definition=detector_model_definition,
            role_arn=role_arn,
            detector_model_description=detector_model_description,
            detector_model_name=detector_model_name,
            evaluation_method=evaluation_method,
            key=key,
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
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html#cfn-iotevents-detectormodel-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="detectorModelDefinition")
    def detector_model_definition(
        self,
    ) -> typing.Union["CfnDetectorModel.DetectorModelDefinitionProperty", _IResolvable_da3f097b]:
        '''Information that defines how a detector operates.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html#cfn-iotevents-detectormodel-detectormodeldefinition
        '''
        return typing.cast(typing.Union["CfnDetectorModel.DetectorModelDefinitionProperty", _IResolvable_da3f097b], jsii.get(self, "detectorModelDefinition"))

    @detector_model_definition.setter
    def detector_model_definition(
        self,
        value: typing.Union["CfnDetectorModel.DetectorModelDefinitionProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "detectorModelDefinition", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''The ARN of the role that grants permission to AWS IoT Events to perform its operations.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html#cfn-iotevents-detectormodel-rolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "roleArn"))

    @role_arn.setter
    def role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "roleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="detectorModelDescription")
    def detector_model_description(self) -> typing.Optional[builtins.str]:
        '''A brief description of the detector model.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html#cfn-iotevents-detectormodel-detectormodeldescription
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "detectorModelDescription"))

    @detector_model_description.setter
    def detector_model_description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "detectorModelDescription", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="detectorModelName")
    def detector_model_name(self) -> typing.Optional[builtins.str]:
        '''The name of the detector model.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html#cfn-iotevents-detectormodel-detectormodelname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "detectorModelName"))

    @detector_model_name.setter
    def detector_model_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "detectorModelName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="evaluationMethod")
    def evaluation_method(self) -> typing.Optional[builtins.str]:
        '''Information about the order in which events are evaluated and how actions are executed.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html#cfn-iotevents-detectormodel-evaluationmethod
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "evaluationMethod"))

    @evaluation_method.setter
    def evaluation_method(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "evaluationMethod", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="key")
    def key(self) -> typing.Optional[builtins.str]:
        '''The value used to identify a detector instance.

        When a device or system sends input, a new detector instance with a unique key value is created. AWS IoT Events can continue to route input to its corresponding detector instance based on this identifying information.

        This parameter uses a JSON-path expression to select the attribute-value pair in the message payload that is used for identification. To route the message to the correct detector instance, the device must send a message payload that contains the same attribute-value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html#cfn-iotevents-detectormodel-key
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "key"))

    @key.setter
    def key(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "key", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.ActionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "clear_timer": "clearTimer",
            "dynamo_db": "dynamoDb",
            "dynamo_d_bv2": "dynamoDBv2",
            "firehose": "firehose",
            "iot_events": "iotEvents",
            "iot_site_wise": "iotSiteWise",
            "iot_topic_publish": "iotTopicPublish",
            "lambda_": "lambda",
            "reset_timer": "resetTimer",
            "set_timer": "setTimer",
            "set_variable": "setVariable",
            "sns": "sns",
            "sqs": "sqs",
        },
    )
    class ActionProperty:
        def __init__(
            self,
            *,
            clear_timer: typing.Optional[typing.Union["CfnDetectorModel.ClearTimerProperty", _IResolvable_da3f097b]] = None,
            dynamo_db: typing.Optional[typing.Union["CfnDetectorModel.DynamoDBProperty", _IResolvable_da3f097b]] = None,
            dynamo_d_bv2: typing.Optional[typing.Union["CfnDetectorModel.DynamoDBv2Property", _IResolvable_da3f097b]] = None,
            firehose: typing.Optional[typing.Union["CfnDetectorModel.FirehoseProperty", _IResolvable_da3f097b]] = None,
            iot_events: typing.Optional[typing.Union["CfnDetectorModel.IotEventsProperty", _IResolvable_da3f097b]] = None,
            iot_site_wise: typing.Optional[typing.Union["CfnDetectorModel.IotSiteWiseProperty", _IResolvable_da3f097b]] = None,
            iot_topic_publish: typing.Optional[typing.Union["CfnDetectorModel.IotTopicPublishProperty", _IResolvable_da3f097b]] = None,
            lambda_: typing.Optional[typing.Union["CfnDetectorModel.LambdaProperty", _IResolvable_da3f097b]] = None,
            reset_timer: typing.Optional[typing.Union["CfnDetectorModel.ResetTimerProperty", _IResolvable_da3f097b]] = None,
            set_timer: typing.Optional[typing.Union["CfnDetectorModel.SetTimerProperty", _IResolvable_da3f097b]] = None,
            set_variable: typing.Optional[typing.Union["CfnDetectorModel.SetVariableProperty", _IResolvable_da3f097b]] = None,
            sns: typing.Optional[typing.Union["CfnDetectorModel.SnsProperty", _IResolvable_da3f097b]] = None,
            sqs: typing.Optional[typing.Union["CfnDetectorModel.SqsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''An action to be performed when the ``condition`` is TRUE.

            :param clear_timer: Information needed to clear the timer.
            :param dynamo_db: Writes to the DynamoDB table that you created. The default action payload contains all attribute-value pairs that have the information about the detector model instance and the event that triggered the action. You can customize the `payload <https://docs.aws.amazon.com/iotevents/latest/apireference/API_Payload.html>`_ . One column of the DynamoDB table receives all attribute-value pairs in the payload that you specify. For more information, see `Actions <https://docs.aws.amazon.com/iotevents/latest/developerguide/iotevents-event-actions.html>`_ in *AWS IoT Events Developer Guide* .
            :param dynamo_d_bv2: Writes to the DynamoDB table that you created. The default action payload contains all attribute-value pairs that have the information about the detector model instance and the event that triggered the action. You can customize the `payload <https://docs.aws.amazon.com/iotevents/latest/apireference/API_Payload.html>`_ . A separate column of the DynamoDB table receives one attribute-value pair in the payload that you specify. For more information, see `Actions <https://docs.aws.amazon.com/iotevents/latest/developerguide/iotevents-event-actions.html>`_ in *AWS IoT Events Developer Guide* .
            :param firehose: Sends information about the detector model instance and the event that triggered the action to an Amazon Kinesis Data Firehose delivery stream.
            :param iot_events: Sends AWS IoT Events input, which passes information about the detector model instance and the event that triggered the action.
            :param iot_site_wise: Sends information about the detector model instance and the event that triggered the action to an asset property in AWS IoT SiteWise .
            :param iot_topic_publish: Publishes an MQTT message with the given topic to the AWS IoT message broker.
            :param lambda_: Calls a Lambda function, passing in information about the detector model instance and the event that triggered the action.
            :param reset_timer: Information needed to reset the timer.
            :param set_timer: Information needed to set the timer.
            :param set_variable: Sets a variable to a specified value.
            :param sns: Sends an Amazon SNS message.
            :param sqs: Sends an Amazon SNS message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-action.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                action_property = iotevents.CfnDetectorModel.ActionProperty(
                    clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                        timer_name="timerName"
                    ),
                    dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                        hash_key_field="hashKeyField",
                        hash_key_value="hashKeyValue",
                        table_name="tableName",
                
                        # the properties below are optional
                        hash_key_type="hashKeyType",
                        operation="operation",
                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                            content_expression="contentExpression",
                            type="type"
                        ),
                        payload_field="payloadField",
                        range_key_field="rangeKeyField",
                        range_key_type="rangeKeyType",
                        range_key_value="rangeKeyValue"
                    ),
                    dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                        table_name="tableName",
                
                        # the properties below are optional
                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                            content_expression="contentExpression",
                            type="type"
                        )
                    ),
                    firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                        delivery_stream_name="deliveryStreamName",
                
                        # the properties below are optional
                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                            content_expression="contentExpression",
                            type="type"
                        ),
                        separator="separator"
                    ),
                    iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                        input_name="inputName",
                
                        # the properties below are optional
                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                            content_expression="contentExpression",
                            type="type"
                        )
                    ),
                    iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                        property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                            value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                boolean_value="booleanValue",
                                double_value="doubleValue",
                                integer_value="integerValue",
                                string_value="stringValue"
                            ),
                
                            # the properties below are optional
                            quality="quality",
                            timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                time_in_seconds="timeInSeconds",
                
                                # the properties below are optional
                                offset_in_nanos="offsetInNanos"
                            )
                        ),
                
                        # the properties below are optional
                        asset_id="assetId",
                        entry_id="entryId",
                        property_alias="propertyAlias",
                        property_id="propertyId"
                    ),
                    iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                        mqtt_topic="mqttTopic",
                
                        # the properties below are optional
                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                            content_expression="contentExpression",
                            type="type"
                        )
                    ),
                    lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                        function_arn="functionArn",
                
                        # the properties below are optional
                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                            content_expression="contentExpression",
                            type="type"
                        )
                    ),
                    reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                        timer_name="timerName"
                    ),
                    set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                        timer_name="timerName",
                
                        # the properties below are optional
                        duration_expression="durationExpression",
                        seconds=123
                    ),
                    set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                        value="value",
                        variable_name="variableName"
                    ),
                    sns=iotevents.CfnDetectorModel.SnsProperty(
                        target_arn="targetArn",
                
                        # the properties below are optional
                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                            content_expression="contentExpression",
                            type="type"
                        )
                    ),
                    sqs=iotevents.CfnDetectorModel.SqsProperty(
                        queue_url="queueUrl",
                
                        # the properties below are optional
                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                            content_expression="contentExpression",
                            type="type"
                        ),
                        use_base64=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if clear_timer is not None:
                self._values["clear_timer"] = clear_timer
            if dynamo_db is not None:
                self._values["dynamo_db"] = dynamo_db
            if dynamo_d_bv2 is not None:
                self._values["dynamo_d_bv2"] = dynamo_d_bv2
            if firehose is not None:
                self._values["firehose"] = firehose
            if iot_events is not None:
                self._values["iot_events"] = iot_events
            if iot_site_wise is not None:
                self._values["iot_site_wise"] = iot_site_wise
            if iot_topic_publish is not None:
                self._values["iot_topic_publish"] = iot_topic_publish
            if lambda_ is not None:
                self._values["lambda_"] = lambda_
            if reset_timer is not None:
                self._values["reset_timer"] = reset_timer
            if set_timer is not None:
                self._values["set_timer"] = set_timer
            if set_variable is not None:
                self._values["set_variable"] = set_variable
            if sns is not None:
                self._values["sns"] = sns
            if sqs is not None:
                self._values["sqs"] = sqs

        @builtins.property
        def clear_timer(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.ClearTimerProperty", _IResolvable_da3f097b]]:
            '''Information needed to clear the timer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-action.html#cfn-iotevents-detectormodel-action-cleartimer
            '''
            result = self._values.get("clear_timer")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.ClearTimerProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def dynamo_db(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.DynamoDBProperty", _IResolvable_da3f097b]]:
            '''Writes to the DynamoDB table that you created.

            The default action payload contains all attribute-value pairs that have the information about the detector model instance and the event that triggered the action. You can customize the `payload <https://docs.aws.amazon.com/iotevents/latest/apireference/API_Payload.html>`_ . One column of the DynamoDB table receives all attribute-value pairs in the payload that you specify. For more information, see `Actions <https://docs.aws.amazon.com/iotevents/latest/developerguide/iotevents-event-actions.html>`_ in *AWS IoT Events Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-action.html#cfn-iotevents-detectormodel-action-dynamodb
            '''
            result = self._values.get("dynamo_db")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.DynamoDBProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def dynamo_d_bv2(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.DynamoDBv2Property", _IResolvable_da3f097b]]:
            '''Writes to the DynamoDB table that you created.

            The default action payload contains all attribute-value pairs that have the information about the detector model instance and the event that triggered the action. You can customize the `payload <https://docs.aws.amazon.com/iotevents/latest/apireference/API_Payload.html>`_ . A separate column of the DynamoDB table receives one attribute-value pair in the payload that you specify. For more information, see `Actions <https://docs.aws.amazon.com/iotevents/latest/developerguide/iotevents-event-actions.html>`_ in *AWS IoT Events Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-action.html#cfn-iotevents-detectormodel-action-dynamodbv2
            '''
            result = self._values.get("dynamo_d_bv2")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.DynamoDBv2Property", _IResolvable_da3f097b]], result)

        @builtins.property
        def firehose(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.FirehoseProperty", _IResolvable_da3f097b]]:
            '''Sends information about the detector model instance and the event that triggered the action to an Amazon Kinesis Data Firehose delivery stream.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-action.html#cfn-iotevents-detectormodel-action-firehose
            '''
            result = self._values.get("firehose")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.FirehoseProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def iot_events(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.IotEventsProperty", _IResolvable_da3f097b]]:
            '''Sends AWS IoT Events input, which passes information about the detector model instance and the event that triggered the action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-action.html#cfn-iotevents-detectormodel-action-iotevents
            '''
            result = self._values.get("iot_events")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.IotEventsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def iot_site_wise(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.IotSiteWiseProperty", _IResolvable_da3f097b]]:
            '''Sends information about the detector model instance and the event that triggered the action to an asset property in AWS IoT SiteWise .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-action.html#cfn-iotevents-detectormodel-action-iotsitewise
            '''
            result = self._values.get("iot_site_wise")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.IotSiteWiseProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def iot_topic_publish(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.IotTopicPublishProperty", _IResolvable_da3f097b]]:
            '''Publishes an MQTT message with the given topic to the AWS IoT message broker.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-action.html#cfn-iotevents-detectormodel-action-iottopicpublish
            '''
            result = self._values.get("iot_topic_publish")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.IotTopicPublishProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def lambda_(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.LambdaProperty", _IResolvable_da3f097b]]:
            '''Calls a Lambda function, passing in information about the detector model instance and the event that triggered the action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-action.html#cfn-iotevents-detectormodel-action-lambda
            '''
            result = self._values.get("lambda_")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.LambdaProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def reset_timer(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.ResetTimerProperty", _IResolvable_da3f097b]]:
            '''Information needed to reset the timer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-action.html#cfn-iotevents-detectormodel-action-resettimer
            '''
            result = self._values.get("reset_timer")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.ResetTimerProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def set_timer(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.SetTimerProperty", _IResolvable_da3f097b]]:
            '''Information needed to set the timer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-action.html#cfn-iotevents-detectormodel-action-settimer
            '''
            result = self._values.get("set_timer")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.SetTimerProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def set_variable(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.SetVariableProperty", _IResolvable_da3f097b]]:
            '''Sets a variable to a specified value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-action.html#cfn-iotevents-detectormodel-action-setvariable
            '''
            result = self._values.get("set_variable")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.SetVariableProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sns(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.SnsProperty", _IResolvable_da3f097b]]:
            '''Sends an Amazon SNS message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-action.html#cfn-iotevents-detectormodel-action-sns
            '''
            result = self._values.get("sns")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.SnsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sqs(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.SqsProperty", _IResolvable_da3f097b]]:
            '''Sends an Amazon SNS message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-action.html#cfn-iotevents-detectormodel-action-sqs
            '''
            result = self._values.get("sqs")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.SqsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.AssetPropertyTimestampProperty",
        jsii_struct_bases=[],
        name_mapping={
            "time_in_seconds": "timeInSeconds",
            "offset_in_nanos": "offsetInNanos",
        },
    )
    class AssetPropertyTimestampProperty:
        def __init__(
            self,
            *,
            time_in_seconds: builtins.str,
            offset_in_nanos: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A structure that contains timestamp information. For more information, see `TimeInNanos <https://docs.aws.amazon.com/iot-sitewise/latest/APIReference/API_TimeInNanos.html>`_ in the *AWS IoT SiteWise API Reference* .

            You must use expressions for all parameters in ``AssetPropertyTimestamp`` . The expressions accept literals, operators, functions, references, and substitution templates.

            **Examples** - For literal values, the expressions must contain single quotes. For example, the value for the ``timeInSeconds`` parameter can be ``'1586400675'`` .

            - For references, you must specify either variables or input values. For example, the value for the ``offsetInNanos`` parameter can be ``$variable.time`` .
            - For a substitution template, you must use ``${}`` , and the template must be in single quotes. A substitution template can also contain a combination of literals, operators, functions, references, and substitution templates.

            In the following example, the value for the ``timeInSeconds`` parameter uses a substitution template.

            ``'${$input.TemperatureInput.sensorData.timestamp / 1000}'``

            For more information, see `Expressions <https://docs.aws.amazon.com/iotevents/latest/developerguide/iotevents-expressions.html>`_ in the *AWS IoT Events Developer Guide* .

            :param time_in_seconds: The timestamp, in seconds, in the Unix epoch format. The valid range is between 1-31556889864403199.
            :param offset_in_nanos: The nanosecond offset converted from ``timeInSeconds`` . The valid range is between 0-999999999.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-assetpropertytimestamp.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                asset_property_timestamp_property = iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                    time_in_seconds="timeInSeconds",
                
                    # the properties below are optional
                    offset_in_nanos="offsetInNanos"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "time_in_seconds": time_in_seconds,
            }
            if offset_in_nanos is not None:
                self._values["offset_in_nanos"] = offset_in_nanos

        @builtins.property
        def time_in_seconds(self) -> builtins.str:
            '''The timestamp, in seconds, in the Unix epoch format.

            The valid range is between 1-31556889864403199.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-assetpropertytimestamp.html#cfn-iotevents-detectormodel-assetpropertytimestamp-timeinseconds
            '''
            result = self._values.get("time_in_seconds")
            assert result is not None, "Required property 'time_in_seconds' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def offset_in_nanos(self) -> typing.Optional[builtins.str]:
            '''The nanosecond offset converted from ``timeInSeconds`` .

            The valid range is between 0-999999999.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-assetpropertytimestamp.html#cfn-iotevents-detectormodel-assetpropertytimestamp-offsetinnanos
            '''
            result = self._values.get("offset_in_nanos")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AssetPropertyTimestampProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.AssetPropertyValueProperty",
        jsii_struct_bases=[],
        name_mapping={
            "value": "value",
            "quality": "quality",
            "timestamp": "timestamp",
        },
    )
    class AssetPropertyValueProperty:
        def __init__(
            self,
            *,
            value: typing.Union["CfnDetectorModel.AssetPropertyVariantProperty", _IResolvable_da3f097b],
            quality: typing.Optional[builtins.str] = None,
            timestamp: typing.Optional[typing.Union["CfnDetectorModel.AssetPropertyTimestampProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A structure that contains value information. For more information, see `AssetPropertyValue <https://docs.aws.amazon.com/iot-sitewise/latest/APIReference/API_AssetPropertyValue.html>`_ in the *AWS IoT SiteWise API Reference* .

            You must use expressions for all parameters in ``AssetPropertyValue`` . The expressions accept literals, operators, functions, references, and substitution templates.

            **Examples** - For literal values, the expressions must contain single quotes. For example, the value for the ``quality`` parameter can be ``'GOOD'`` .

            - For references, you must specify either variables or input values. For example, the value for the ``quality`` parameter can be ``$input.TemperatureInput.sensorData.quality`` .

            For more information, see `Expressions <https://docs.aws.amazon.com/iotevents/latest/developerguide/iotevents-expressions.html>`_ in the *AWS IoT Events Developer Guide* .

            :param value: The value to send to an asset property.
            :param quality: The quality of the asset property value. The value must be ``'GOOD'`` , ``'BAD'`` , or ``'UNCERTAIN'`` .
            :param timestamp: The timestamp associated with the asset property value. The default is the current event time.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-assetpropertyvalue.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                asset_property_value_property = iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                    value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                        boolean_value="booleanValue",
                        double_value="doubleValue",
                        integer_value="integerValue",
                        string_value="stringValue"
                    ),
                
                    # the properties below are optional
                    quality="quality",
                    timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                        time_in_seconds="timeInSeconds",
                
                        # the properties below are optional
                        offset_in_nanos="offsetInNanos"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "value": value,
            }
            if quality is not None:
                self._values["quality"] = quality
            if timestamp is not None:
                self._values["timestamp"] = timestamp

        @builtins.property
        def value(
            self,
        ) -> typing.Union["CfnDetectorModel.AssetPropertyVariantProperty", _IResolvable_da3f097b]:
            '''The value to send to an asset property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-assetpropertyvalue.html#cfn-iotevents-detectormodel-assetpropertyvalue-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(typing.Union["CfnDetectorModel.AssetPropertyVariantProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def quality(self) -> typing.Optional[builtins.str]:
            '''The quality of the asset property value.

            The value must be ``'GOOD'`` , ``'BAD'`` , or ``'UNCERTAIN'`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-assetpropertyvalue.html#cfn-iotevents-detectormodel-assetpropertyvalue-quality
            '''
            result = self._values.get("quality")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def timestamp(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.AssetPropertyTimestampProperty", _IResolvable_da3f097b]]:
            '''The timestamp associated with the asset property value.

            The default is the current event time.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-assetpropertyvalue.html#cfn-iotevents-detectormodel-assetpropertyvalue-timestamp
            '''
            result = self._values.get("timestamp")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.AssetPropertyTimestampProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AssetPropertyValueProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.AssetPropertyVariantProperty",
        jsii_struct_bases=[],
        name_mapping={
            "boolean_value": "booleanValue",
            "double_value": "doubleValue",
            "integer_value": "integerValue",
            "string_value": "stringValue",
        },
    )
    class AssetPropertyVariantProperty:
        def __init__(
            self,
            *,
            boolean_value: typing.Optional[builtins.str] = None,
            double_value: typing.Optional[builtins.str] = None,
            integer_value: typing.Optional[builtins.str] = None,
            string_value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A structure that contains an asset property value.

            For more information, see `Variant <https://docs.aws.amazon.com/iot-sitewise/latest/APIReference/API_Variant.html>`_ in the *AWS IoT SiteWise API Reference* .

            You must use expressions for all parameters in ``AssetPropertyVariant`` . The expressions accept literals, operators, functions, references, and substitution templates.

            **Examples** - For literal values, the expressions must contain single quotes. For example, the value for the ``integerValue`` parameter can be ``'100'`` .

            - For references, you must specify either variables or parameters. For example, the value for the ``booleanValue`` parameter can be ``$variable.offline`` .
            - For a substitution template, you must use ``${}`` , and the template must be in single quotes. A substitution template can also contain a combination of literals, operators, functions, references, and substitution templates.

            In the following example, the value for the ``doubleValue`` parameter uses a substitution template.

            ``'${$input.TemperatureInput.sensorData.temperature * 6 / 5 + 32}'``

            For more information, see `Expressions <https://docs.aws.amazon.com/iotevents/latest/developerguide/iotevents-expressions.html>`_ in the *AWS IoT Events Developer Guide* .

            You must specify one of the following value types, depending on the ``dataType`` of the specified asset property. For more information, see `AssetProperty <https://docs.aws.amazon.com/iot-sitewise/latest/APIReference/API_AssetProperty.html>`_ in the *AWS IoT SiteWise API Reference* .

            :param boolean_value: The asset property value is a Boolean value that must be ``'TRUE'`` or ``'FALSE'`` . You must use an expression, and the evaluated result should be a Boolean value.
            :param double_value: The asset property value is a double. You must use an expression, and the evaluated result should be a double.
            :param integer_value: The asset property value is an integer. You must use an expression, and the evaluated result should be an integer.
            :param string_value: The asset property value is a string. You must use an expression, and the evaluated result should be a string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-assetpropertyvariant.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                asset_property_variant_property = iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                    boolean_value="booleanValue",
                    double_value="doubleValue",
                    integer_value="integerValue",
                    string_value="stringValue"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if boolean_value is not None:
                self._values["boolean_value"] = boolean_value
            if double_value is not None:
                self._values["double_value"] = double_value
            if integer_value is not None:
                self._values["integer_value"] = integer_value
            if string_value is not None:
                self._values["string_value"] = string_value

        @builtins.property
        def boolean_value(self) -> typing.Optional[builtins.str]:
            '''The asset property value is a Boolean value that must be ``'TRUE'`` or ``'FALSE'`` .

            You must use an expression, and the evaluated result should be a Boolean value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-assetpropertyvariant.html#cfn-iotevents-detectormodel-assetpropertyvariant-booleanvalue
            '''
            result = self._values.get("boolean_value")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def double_value(self) -> typing.Optional[builtins.str]:
            '''The asset property value is a double.

            You must use an expression, and the evaluated result should be a double.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-assetpropertyvariant.html#cfn-iotevents-detectormodel-assetpropertyvariant-doublevalue
            '''
            result = self._values.get("double_value")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def integer_value(self) -> typing.Optional[builtins.str]:
            '''The asset property value is an integer.

            You must use an expression, and the evaluated result should be an integer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-assetpropertyvariant.html#cfn-iotevents-detectormodel-assetpropertyvariant-integervalue
            '''
            result = self._values.get("integer_value")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def string_value(self) -> typing.Optional[builtins.str]:
            '''The asset property value is a string.

            You must use an expression, and the evaluated result should be a string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-assetpropertyvariant.html#cfn-iotevents-detectormodel-assetpropertyvariant-stringvalue
            '''
            result = self._values.get("string_value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AssetPropertyVariantProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.ClearTimerProperty",
        jsii_struct_bases=[],
        name_mapping={"timer_name": "timerName"},
    )
    class ClearTimerProperty:
        def __init__(self, *, timer_name: builtins.str) -> None:
            '''Information needed to clear the timer.

            :param timer_name: The name of the timer to clear.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-cleartimer.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                clear_timer_property = iotevents.CfnDetectorModel.ClearTimerProperty(
                    timer_name="timerName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "timer_name": timer_name,
            }

        @builtins.property
        def timer_name(self) -> builtins.str:
            '''The name of the timer to clear.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-cleartimer.html#cfn-iotevents-detectormodel-cleartimer-timername
            '''
            result = self._values.get("timer_name")
            assert result is not None, "Required property 'timer_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ClearTimerProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.DetectorModelDefinitionProperty",
        jsii_struct_bases=[],
        name_mapping={"initial_state_name": "initialStateName", "states": "states"},
    )
    class DetectorModelDefinitionProperty:
        def __init__(
            self,
            *,
            initial_state_name: builtins.str,
            states: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDetectorModel.StateProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''Information that defines how a detector operates.

            :param initial_state_name: The state that is entered at the creation of each detector (instance).
            :param states: Information about the states of the detector.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-detectormodeldefinition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                detector_model_definition_property = iotevents.CfnDetectorModel.DetectorModelDefinitionProperty(
                    initial_state_name="initialStateName",
                    states=[iotevents.CfnDetectorModel.StateProperty(
                        state_name="stateName",
                
                        # the properties below are optional
                        on_enter=iotevents.CfnDetectorModel.OnEnterProperty(
                            events=[iotevents.CfnDetectorModel.EventProperty(
                                event_name="eventName",
                
                                # the properties below are optional
                                actions=[iotevents.CfnDetectorModel.ActionProperty(
                                    clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                        hash_key_field="hashKeyField",
                                        hash_key_value="hashKeyValue",
                                        table_name="tableName",
                
                                        # the properties below are optional
                                        hash_key_type="hashKeyType",
                                        operation="operation",
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        payload_field="payloadField",
                                        range_key_field="rangeKeyField",
                                        range_key_type="rangeKeyType",
                                        range_key_value="rangeKeyValue"
                                    ),
                                    dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                        table_name="tableName",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                        delivery_stream_name="deliveryStreamName",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        separator="separator"
                                    ),
                                    iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                        input_name="inputName",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                        property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                            value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                                boolean_value="booleanValue",
                                                double_value="doubleValue",
                                                integer_value="integerValue",
                                                string_value="stringValue"
                                            ),
                
                                            # the properties below are optional
                                            quality="quality",
                                            timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                                time_in_seconds="timeInSeconds",
                
                                                # the properties below are optional
                                                offset_in_nanos="offsetInNanos"
                                            )
                                        ),
                
                                        # the properties below are optional
                                        asset_id="assetId",
                                        entry_id="entryId",
                                        property_alias="propertyAlias",
                                        property_id="propertyId"
                                    ),
                                    iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                        mqtt_topic="mqttTopic",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                        function_arn="functionArn",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                        timer_name="timerName",
                
                                        # the properties below are optional
                                        duration_expression="durationExpression",
                                        seconds=123
                                    ),
                                    set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                        value="value",
                                        variable_name="variableName"
                                    ),
                                    sns=iotevents.CfnDetectorModel.SnsProperty(
                                        target_arn="targetArn",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    sqs=iotevents.CfnDetectorModel.SqsProperty(
                                        queue_url="queueUrl",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        use_base64=False
                                    )
                                )],
                                condition="condition"
                            )]
                        ),
                        on_exit=iotevents.CfnDetectorModel.OnExitProperty(
                            events=[iotevents.CfnDetectorModel.EventProperty(
                                event_name="eventName",
                
                                # the properties below are optional
                                actions=[iotevents.CfnDetectorModel.ActionProperty(
                                    clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                        hash_key_field="hashKeyField",
                                        hash_key_value="hashKeyValue",
                                        table_name="tableName",
                
                                        # the properties below are optional
                                        hash_key_type="hashKeyType",
                                        operation="operation",
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        payload_field="payloadField",
                                        range_key_field="rangeKeyField",
                                        range_key_type="rangeKeyType",
                                        range_key_value="rangeKeyValue"
                                    ),
                                    dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                        table_name="tableName",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                        delivery_stream_name="deliveryStreamName",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        separator="separator"
                                    ),
                                    iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                        input_name="inputName",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                        property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                            value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                                boolean_value="booleanValue",
                                                double_value="doubleValue",
                                                integer_value="integerValue",
                                                string_value="stringValue"
                                            ),
                
                                            # the properties below are optional
                                            quality="quality",
                                            timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                                time_in_seconds="timeInSeconds",
                
                                                # the properties below are optional
                                                offset_in_nanos="offsetInNanos"
                                            )
                                        ),
                
                                        # the properties below are optional
                                        asset_id="assetId",
                                        entry_id="entryId",
                                        property_alias="propertyAlias",
                                        property_id="propertyId"
                                    ),
                                    iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                        mqtt_topic="mqttTopic",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                        function_arn="functionArn",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                        timer_name="timerName",
                
                                        # the properties below are optional
                                        duration_expression="durationExpression",
                                        seconds=123
                                    ),
                                    set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                        value="value",
                                        variable_name="variableName"
                                    ),
                                    sns=iotevents.CfnDetectorModel.SnsProperty(
                                        target_arn="targetArn",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    sqs=iotevents.CfnDetectorModel.SqsProperty(
                                        queue_url="queueUrl",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        use_base64=False
                                    )
                                )],
                                condition="condition"
                            )]
                        ),
                        on_input=iotevents.CfnDetectorModel.OnInputProperty(
                            events=[iotevents.CfnDetectorModel.EventProperty(
                                event_name="eventName",
                
                                # the properties below are optional
                                actions=[iotevents.CfnDetectorModel.ActionProperty(
                                    clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                        hash_key_field="hashKeyField",
                                        hash_key_value="hashKeyValue",
                                        table_name="tableName",
                
                                        # the properties below are optional
                                        hash_key_type="hashKeyType",
                                        operation="operation",
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        payload_field="payloadField",
                                        range_key_field="rangeKeyField",
                                        range_key_type="rangeKeyType",
                                        range_key_value="rangeKeyValue"
                                    ),
                                    dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                        table_name="tableName",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                        delivery_stream_name="deliveryStreamName",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        separator="separator"
                                    ),
                                    iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                        input_name="inputName",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                        property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                            value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                                boolean_value="booleanValue",
                                                double_value="doubleValue",
                                                integer_value="integerValue",
                                                string_value="stringValue"
                                            ),
                
                                            # the properties below are optional
                                            quality="quality",
                                            timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                                time_in_seconds="timeInSeconds",
                
                                                # the properties below are optional
                                                offset_in_nanos="offsetInNanos"
                                            )
                                        ),
                
                                        # the properties below are optional
                                        asset_id="assetId",
                                        entry_id="entryId",
                                        property_alias="propertyAlias",
                                        property_id="propertyId"
                                    ),
                                    iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                        mqtt_topic="mqttTopic",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                        function_arn="functionArn",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                        timer_name="timerName",
                
                                        # the properties below are optional
                                        duration_expression="durationExpression",
                                        seconds=123
                                    ),
                                    set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                        value="value",
                                        variable_name="variableName"
                                    ),
                                    sns=iotevents.CfnDetectorModel.SnsProperty(
                                        target_arn="targetArn",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    sqs=iotevents.CfnDetectorModel.SqsProperty(
                                        queue_url="queueUrl",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        use_base64=False
                                    )
                                )],
                                condition="condition"
                            )],
                            transition_events=[iotevents.CfnDetectorModel.TransitionEventProperty(
                                condition="condition",
                                event_name="eventName",
                                next_state="nextState",
                
                                # the properties below are optional
                                actions=[iotevents.CfnDetectorModel.ActionProperty(
                                    clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                        hash_key_field="hashKeyField",
                                        hash_key_value="hashKeyValue",
                                        table_name="tableName",
                
                                        # the properties below are optional
                                        hash_key_type="hashKeyType",
                                        operation="operation",
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        payload_field="payloadField",
                                        range_key_field="rangeKeyField",
                                        range_key_type="rangeKeyType",
                                        range_key_value="rangeKeyValue"
                                    ),
                                    dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                        table_name="tableName",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                        delivery_stream_name="deliveryStreamName",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        separator="separator"
                                    ),
                                    iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                        input_name="inputName",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                        property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                            value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                                boolean_value="booleanValue",
                                                double_value="doubleValue",
                                                integer_value="integerValue",
                                                string_value="stringValue"
                                            ),
                
                                            # the properties below are optional
                                            quality="quality",
                                            timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                                time_in_seconds="timeInSeconds",
                
                                                # the properties below are optional
                                                offset_in_nanos="offsetInNanos"
                                            )
                                        ),
                
                                        # the properties below are optional
                                        asset_id="assetId",
                                        entry_id="entryId",
                                        property_alias="propertyAlias",
                                        property_id="propertyId"
                                    ),
                                    iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                        mqtt_topic="mqttTopic",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                        function_arn="functionArn",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                        timer_name="timerName",
                
                                        # the properties below are optional
                                        duration_expression="durationExpression",
                                        seconds=123
                                    ),
                                    set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                        value="value",
                                        variable_name="variableName"
                                    ),
                                    sns=iotevents.CfnDetectorModel.SnsProperty(
                                        target_arn="targetArn",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    sqs=iotevents.CfnDetectorModel.SqsProperty(
                                        queue_url="queueUrl",
                
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        use_base64=False
                                    )
                                )]
                            )]
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "initial_state_name": initial_state_name,
                "states": states,
            }

        @builtins.property
        def initial_state_name(self) -> builtins.str:
            '''The state that is entered at the creation of each detector (instance).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-detectormodeldefinition.html#cfn-iotevents-detectormodel-detectormodeldefinition-initialstatename
            '''
            result = self._values.get("initial_state_name")
            assert result is not None, "Required property 'initial_state_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def states(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDetectorModel.StateProperty", _IResolvable_da3f097b]]]:
            '''Information about the states of the detector.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-detectormodeldefinition.html#cfn-iotevents-detectormodel-detectormodeldefinition-states
            '''
            result = self._values.get("states")
            assert result is not None, "Required property 'states' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDetectorModel.StateProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DetectorModelDefinitionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.DynamoDBProperty",
        jsii_struct_bases=[],
        name_mapping={
            "hash_key_field": "hashKeyField",
            "hash_key_value": "hashKeyValue",
            "table_name": "tableName",
            "hash_key_type": "hashKeyType",
            "operation": "operation",
            "payload": "payload",
            "payload_field": "payloadField",
            "range_key_field": "rangeKeyField",
            "range_key_type": "rangeKeyType",
            "range_key_value": "rangeKeyValue",
        },
    )
    class DynamoDBProperty:
        def __init__(
            self,
            *,
            hash_key_field: builtins.str,
            hash_key_value: builtins.str,
            table_name: builtins.str,
            hash_key_type: typing.Optional[builtins.str] = None,
            operation: typing.Optional[builtins.str] = None,
            payload: typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]] = None,
            payload_field: typing.Optional[builtins.str] = None,
            range_key_field: typing.Optional[builtins.str] = None,
            range_key_type: typing.Optional[builtins.str] = None,
            range_key_value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Defines an action to write to the Amazon DynamoDB table that you created.

            The standard action payload contains all the information about the detector model instance and the event that triggered the action. You can customize the `payload <https://docs.aws.amazon.com/iotevents/latest/apireference/API_Payload.html>`_ . One column of the DynamoDB table receives all attribute-value pairs in the payload that you specify.

            You must use expressions for all parameters in ``DynamoDBAction`` . The expressions accept literals, operators, functions, references, and substitution templates.

            **Examples** - For literal values, the expressions must contain single quotes. For example, the value for the ``hashKeyType`` parameter can be ``'STRING'`` .

            - For references, you must specify either variables or input values. For example, the value for the ``hashKeyField`` parameter can be ``$input.GreenhouseInput.name`` .
            - For a substitution template, you must use ``${}`` , and the template must be in single quotes. A substitution template can also contain a combination of literals, operators, functions, references, and substitution templates.

            In the following example, the value for the ``hashKeyValue`` parameter uses a substitution template.

            ``'${$input.GreenhouseInput.temperature * 6 / 5 + 32} in Fahrenheit'``

            - For a string concatenation, you must use ``+`` . A string concatenation can also contain a combination of literals, operators, functions, references, and substitution templates.

            In the following example, the value for the ``tableName`` parameter uses a string concatenation.

            ``'GreenhouseTemperatureTable ' + $input.GreenhouseInput.date``

            For more information, see `Expressions <https://docs.aws.amazon.com/iotevents/latest/developerguide/iotevents-expressions.html>`_ in the *AWS IoT Events Developer Guide* .

            If the defined payload type is a string, ``DynamoDBAction`` writes non-JSON data to the DynamoDB table as binary data. The DynamoDB console displays the data as Base64-encoded text. The value for the ``payloadField`` parameter is ``<payload-field>_raw`` .

            :param hash_key_field: The name of the hash key (also called the partition key). The ``hashKeyField`` value must match the partition key of the target DynamoDB table.
            :param hash_key_value: The value of the hash key (also called the partition key).
            :param table_name: The name of the DynamoDB table. The ``tableName`` value must match the table name of the target DynamoDB table.
            :param hash_key_type: The data type for the hash key (also called the partition key). You can specify the following values:. - ``'STRING'`` - The hash key is a string. - ``'NUMBER'`` - The hash key is a number. If you don't specify ``hashKeyType`` , the default value is ``'STRING'`` .
            :param operation: The type of operation to perform. You can specify the following values:. - ``'INSERT'`` - Insert data as a new item into the DynamoDB table. This item uses the specified hash key as a partition key. If you specified a range key, the item uses the range key as a sort key. - ``'UPDATE'`` - Update an existing item of the DynamoDB table with new data. This item's partition key must match the specified hash key. If you specified a range key, the range key must match the item's sort key. - ``'DELETE'`` - Delete an existing item of the DynamoDB table. This item's partition key must match the specified hash key. If you specified a range key, the range key must match the item's sort key. If you don't specify this parameter, AWS IoT Events triggers the ``'INSERT'`` operation.
            :param payload: Information needed to configure the payload. By default, AWS IoT Events generates a standard payload in JSON for any action. This action payload contains all attribute-value pairs that have the information about the detector model instance and the event triggered the action. To configure the action payload, you can use ``contentExpression`` .
            :param payload_field: The name of the DynamoDB column that receives the action payload. If you don't specify this parameter, the name of the DynamoDB column is ``payload`` .
            :param range_key_field: The name of the range key (also called the sort key). The ``rangeKeyField`` value must match the sort key of the target DynamoDB table.
            :param range_key_type: The data type for the range key (also called the sort key), You can specify the following values:. - ``'STRING'`` - The range key is a string. - ``'NUMBER'`` - The range key is number. If you don't specify ``rangeKeyField`` , the default value is ``'STRING'`` .
            :param range_key_value: The value of the range key (also called the sort key).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-dynamodb.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                dynamo_dBProperty = iotevents.CfnDetectorModel.DynamoDBProperty(
                    hash_key_field="hashKeyField",
                    hash_key_value="hashKeyValue",
                    table_name="tableName",
                
                    # the properties below are optional
                    hash_key_type="hashKeyType",
                    operation="operation",
                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                        content_expression="contentExpression",
                        type="type"
                    ),
                    payload_field="payloadField",
                    range_key_field="rangeKeyField",
                    range_key_type="rangeKeyType",
                    range_key_value="rangeKeyValue"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "hash_key_field": hash_key_field,
                "hash_key_value": hash_key_value,
                "table_name": table_name,
            }
            if hash_key_type is not None:
                self._values["hash_key_type"] = hash_key_type
            if operation is not None:
                self._values["operation"] = operation
            if payload is not None:
                self._values["payload"] = payload
            if payload_field is not None:
                self._values["payload_field"] = payload_field
            if range_key_field is not None:
                self._values["range_key_field"] = range_key_field
            if range_key_type is not None:
                self._values["range_key_type"] = range_key_type
            if range_key_value is not None:
                self._values["range_key_value"] = range_key_value

        @builtins.property
        def hash_key_field(self) -> builtins.str:
            '''The name of the hash key (also called the partition key).

            The ``hashKeyField`` value must match the partition key of the target DynamoDB table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-dynamodb.html#cfn-iotevents-detectormodel-dynamodb-hashkeyfield
            '''
            result = self._values.get("hash_key_field")
            assert result is not None, "Required property 'hash_key_field' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def hash_key_value(self) -> builtins.str:
            '''The value of the hash key (also called the partition key).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-dynamodb.html#cfn-iotevents-detectormodel-dynamodb-hashkeyvalue
            '''
            result = self._values.get("hash_key_value")
            assert result is not None, "Required property 'hash_key_value' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def table_name(self) -> builtins.str:
            '''The name of the DynamoDB table.

            The ``tableName`` value must match the table name of the target DynamoDB table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-dynamodb.html#cfn-iotevents-detectormodel-dynamodb-tablename
            '''
            result = self._values.get("table_name")
            assert result is not None, "Required property 'table_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def hash_key_type(self) -> typing.Optional[builtins.str]:
            '''The data type for the hash key (also called the partition key). You can specify the following values:.

            - ``'STRING'`` - The hash key is a string.
            - ``'NUMBER'`` - The hash key is a number.

            If you don't specify ``hashKeyType`` , the default value is ``'STRING'`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-dynamodb.html#cfn-iotevents-detectormodel-dynamodb-hashkeytype
            '''
            result = self._values.get("hash_key_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def operation(self) -> typing.Optional[builtins.str]:
            '''The type of operation to perform. You can specify the following values:.

            - ``'INSERT'`` - Insert data as a new item into the DynamoDB table. This item uses the specified hash key as a partition key. If you specified a range key, the item uses the range key as a sort key.
            - ``'UPDATE'`` - Update an existing item of the DynamoDB table with new data. This item's partition key must match the specified hash key. If you specified a range key, the range key must match the item's sort key.
            - ``'DELETE'`` - Delete an existing item of the DynamoDB table. This item's partition key must match the specified hash key. If you specified a range key, the range key must match the item's sort key.

            If you don't specify this parameter, AWS IoT Events triggers the ``'INSERT'`` operation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-dynamodb.html#cfn-iotevents-detectormodel-dynamodb-operation
            '''
            result = self._values.get("operation")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def payload(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]]:
            '''Information needed to configure the payload.

            By default, AWS IoT Events generates a standard payload in JSON for any action. This action payload contains all attribute-value pairs that have the information about the detector model instance and the event triggered the action. To configure the action payload, you can use ``contentExpression`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-dynamodb.html#cfn-iotevents-detectormodel-dynamodb-payload
            '''
            result = self._values.get("payload")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def payload_field(self) -> typing.Optional[builtins.str]:
            '''The name of the DynamoDB column that receives the action payload.

            If you don't specify this parameter, the name of the DynamoDB column is ``payload`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-dynamodb.html#cfn-iotevents-detectormodel-dynamodb-payloadfield
            '''
            result = self._values.get("payload_field")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def range_key_field(self) -> typing.Optional[builtins.str]:
            '''The name of the range key (also called the sort key).

            The ``rangeKeyField`` value must match the sort key of the target DynamoDB table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-dynamodb.html#cfn-iotevents-detectormodel-dynamodb-rangekeyfield
            '''
            result = self._values.get("range_key_field")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def range_key_type(self) -> typing.Optional[builtins.str]:
            '''The data type for the range key (also called the sort key), You can specify the following values:.

            - ``'STRING'`` - The range key is a string.
            - ``'NUMBER'`` - The range key is number.

            If you don't specify ``rangeKeyField`` , the default value is ``'STRING'`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-dynamodb.html#cfn-iotevents-detectormodel-dynamodb-rangekeytype
            '''
            result = self._values.get("range_key_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def range_key_value(self) -> typing.Optional[builtins.str]:
            '''The value of the range key (also called the sort key).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-dynamodb.html#cfn-iotevents-detectormodel-dynamodb-rangekeyvalue
            '''
            result = self._values.get("range_key_value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DynamoDBProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.DynamoDBv2Property",
        jsii_struct_bases=[],
        name_mapping={"table_name": "tableName", "payload": "payload"},
    )
    class DynamoDBv2Property:
        def __init__(
            self,
            *,
            table_name: builtins.str,
            payload: typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Defines an action to write to the Amazon DynamoDB table that you created.

            The default action payload contains all the information about the detector model instance and the event that triggered the action. You can customize the `payload <https://docs.aws.amazon.com/iotevents/latest/apireference/API_Payload.html>`_ . A separate column of the DynamoDB table receives one attribute-value pair in the payload that you specify.

            You must use expressions for all parameters in ``DynamoDBv2Action`` . The expressions accept literals, operators, functions, references, and substitution templates.

            **Examples** - For literal values, the expressions must contain single quotes. For example, the value for the ``tableName`` parameter can be ``'GreenhouseTemperatureTable'`` .

            - For references, you must specify either variables or input values. For example, the value for the ``tableName`` parameter can be ``$variable.ddbtableName`` .
            - For a substitution template, you must use ``${}`` , and the template must be in single quotes. A substitution template can also contain a combination of literals, operators, functions, references, and substitution templates.

            In the following example, the value for the ``contentExpression`` parameter in ``Payload`` uses a substitution template.

            ``'{\\"sensorID\\": \\"${$input.GreenhouseInput.sensor_id}\\", \\"temperature\\": \\"${$input.GreenhouseInput.temperature * 9 / 5 + 32}\\"}'``

            - For a string concatenation, you must use ``+`` . A string concatenation can also contain a combination of literals, operators, functions, references, and substitution templates.

            In the following example, the value for the ``tableName`` parameter uses a string concatenation.

            ``'GreenhouseTemperatureTable ' + $input.GreenhouseInput.date``

            For more information, see `Expressions <https://docs.aws.amazon.com/iotevents/latest/developerguide/iotevents-expressions.html>`_ in the *AWS IoT Events Developer Guide* .

            The value for the ``type`` parameter in ``Payload`` must be ``JSON`` .

            :param table_name: The name of the DynamoDB table.
            :param payload: Information needed to configure the payload. By default, AWS IoT Events generates a standard payload in JSON for any action. This action payload contains all attribute-value pairs that have the information about the detector model instance and the event triggered the action. To configure the action payload, you can use ``contentExpression`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-dynamodbv2.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                dynamo_dBv2_property = iotevents.CfnDetectorModel.DynamoDBv2Property(
                    table_name="tableName",
                
                    # the properties below are optional
                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                        content_expression="contentExpression",
                        type="type"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "table_name": table_name,
            }
            if payload is not None:
                self._values["payload"] = payload

        @builtins.property
        def table_name(self) -> builtins.str:
            '''The name of the DynamoDB table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-dynamodbv2.html#cfn-iotevents-detectormodel-dynamodbv2-tablename
            '''
            result = self._values.get("table_name")
            assert result is not None, "Required property 'table_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def payload(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]]:
            '''Information needed to configure the payload.

            By default, AWS IoT Events generates a standard payload in JSON for any action. This action payload contains all attribute-value pairs that have the information about the detector model instance and the event triggered the action. To configure the action payload, you can use ``contentExpression`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-dynamodbv2.html#cfn-iotevents-detectormodel-dynamodbv2-payload
            '''
            result = self._values.get("payload")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DynamoDBv2Property(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.EventProperty",
        jsii_struct_bases=[],
        name_mapping={
            "event_name": "eventName",
            "actions": "actions",
            "condition": "condition",
        },
    )
    class EventProperty:
        def __init__(
            self,
            *,
            event_name: builtins.str,
            actions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDetectorModel.ActionProperty", _IResolvable_da3f097b]]]] = None,
            condition: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies the ``actions`` to be performed when the ``condition`` evaluates to TRUE.

            :param event_name: The name of the event.
            :param actions: The actions to be performed.
            :param condition: Optional. The Boolean expression that, when TRUE, causes the ``actions`` to be performed. If not present, the actions are performed (=TRUE). If the expression result is not a Boolean value, the actions are not performed (=FALSE).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-event.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                event_property = iotevents.CfnDetectorModel.EventProperty(
                    event_name="eventName",
                
                    # the properties below are optional
                    actions=[iotevents.CfnDetectorModel.ActionProperty(
                        clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                            timer_name="timerName"
                        ),
                        dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                            hash_key_field="hashKeyField",
                            hash_key_value="hashKeyValue",
                            table_name="tableName",
                
                            # the properties below are optional
                            hash_key_type="hashKeyType",
                            operation="operation",
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            ),
                            payload_field="payloadField",
                            range_key_field="rangeKeyField",
                            range_key_type="rangeKeyType",
                            range_key_value="rangeKeyValue"
                        ),
                        dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                            table_name="tableName",
                
                            # the properties below are optional
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            )
                        ),
                        firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                            delivery_stream_name="deliveryStreamName",
                
                            # the properties below are optional
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            ),
                            separator="separator"
                        ),
                        iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                            input_name="inputName",
                
                            # the properties below are optional
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            )
                        ),
                        iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                            property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                    boolean_value="booleanValue",
                                    double_value="doubleValue",
                                    integer_value="integerValue",
                                    string_value="stringValue"
                                ),
                
                                # the properties below are optional
                                quality="quality",
                                timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                    time_in_seconds="timeInSeconds",
                
                                    # the properties below are optional
                                    offset_in_nanos="offsetInNanos"
                                )
                            ),
                
                            # the properties below are optional
                            asset_id="assetId",
                            entry_id="entryId",
                            property_alias="propertyAlias",
                            property_id="propertyId"
                        ),
                        iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                            mqtt_topic="mqttTopic",
                
                            # the properties below are optional
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            )
                        ),
                        lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                            function_arn="functionArn",
                
                            # the properties below are optional
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            )
                        ),
                        reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                            timer_name="timerName"
                        ),
                        set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                            timer_name="timerName",
                
                            # the properties below are optional
                            duration_expression="durationExpression",
                            seconds=123
                        ),
                        set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                            value="value",
                            variable_name="variableName"
                        ),
                        sns=iotevents.CfnDetectorModel.SnsProperty(
                            target_arn="targetArn",
                
                            # the properties below are optional
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            )
                        ),
                        sqs=iotevents.CfnDetectorModel.SqsProperty(
                            queue_url="queueUrl",
                
                            # the properties below are optional
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            ),
                            use_base64=False
                        )
                    )],
                    condition="condition"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "event_name": event_name,
            }
            if actions is not None:
                self._values["actions"] = actions
            if condition is not None:
                self._values["condition"] = condition

        @builtins.property
        def event_name(self) -> builtins.str:
            '''The name of the event.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-event.html#cfn-iotevents-detectormodel-event-eventname
            '''
            result = self._values.get("event_name")
            assert result is not None, "Required property 'event_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def actions(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDetectorModel.ActionProperty", _IResolvable_da3f097b]]]]:
            '''The actions to be performed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-event.html#cfn-iotevents-detectormodel-event-actions
            '''
            result = self._values.get("actions")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDetectorModel.ActionProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def condition(self) -> typing.Optional[builtins.str]:
            '''Optional.

            The Boolean expression that, when TRUE, causes the ``actions`` to be performed. If not present, the actions are performed (=TRUE). If the expression result is not a Boolean value, the actions are not performed (=FALSE).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-event.html#cfn-iotevents-detectormodel-event-condition
            '''
            result = self._values.get("condition")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EventProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.FirehoseProperty",
        jsii_struct_bases=[],
        name_mapping={
            "delivery_stream_name": "deliveryStreamName",
            "payload": "payload",
            "separator": "separator",
        },
    )
    class FirehoseProperty:
        def __init__(
            self,
            *,
            delivery_stream_name: builtins.str,
            payload: typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]] = None,
            separator: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Sends information about the detector model instance and the event that triggered the action to an Amazon Kinesis Data Firehose delivery stream.

            :param delivery_stream_name: The name of the Kinesis Data Firehose delivery stream where the data is written.
            :param payload: You can configure the action payload when you send a message to an Amazon Kinesis Data Firehose delivery stream.
            :param separator: A character separator that is used to separate records written to the Kinesis Data Firehose delivery stream. Valid values are: '\\n' (newline), '\\t' (tab), '\\r\\n' (Windows newline), ',' (comma).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-firehose.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                firehose_property = iotevents.CfnDetectorModel.FirehoseProperty(
                    delivery_stream_name="deliveryStreamName",
                
                    # the properties below are optional
                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                        content_expression="contentExpression",
                        type="type"
                    ),
                    separator="separator"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "delivery_stream_name": delivery_stream_name,
            }
            if payload is not None:
                self._values["payload"] = payload
            if separator is not None:
                self._values["separator"] = separator

        @builtins.property
        def delivery_stream_name(self) -> builtins.str:
            '''The name of the Kinesis Data Firehose delivery stream where the data is written.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-firehose.html#cfn-iotevents-detectormodel-firehose-deliverystreamname
            '''
            result = self._values.get("delivery_stream_name")
            assert result is not None, "Required property 'delivery_stream_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def payload(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]]:
            '''You can configure the action payload when you send a message to an Amazon Kinesis Data Firehose delivery stream.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-firehose.html#cfn-iotevents-detectormodel-firehose-payload
            '''
            result = self._values.get("payload")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def separator(self) -> typing.Optional[builtins.str]:
            '''A character separator that is used to separate records written to the Kinesis Data Firehose delivery stream.

            Valid values are: '\\n' (newline), '\\t' (tab), '\\r\\n' (Windows newline), ',' (comma).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-firehose.html#cfn-iotevents-detectormodel-firehose-separator
            '''
            result = self._values.get("separator")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FirehoseProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.IotEventsProperty",
        jsii_struct_bases=[],
        name_mapping={"input_name": "inputName", "payload": "payload"},
    )
    class IotEventsProperty:
        def __init__(
            self,
            *,
            input_name: builtins.str,
            payload: typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Sends an AWS IoT Events input, passing in information about the detector model instance and the event that triggered the action.

            :param input_name: The name of the AWS IoT Events input where the data is sent.
            :param payload: You can configure the action payload when you send a message to an AWS IoT Events input.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-iotevents.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                iot_events_property = iotevents.CfnDetectorModel.IotEventsProperty(
                    input_name="inputName",
                
                    # the properties below are optional
                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                        content_expression="contentExpression",
                        type="type"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "input_name": input_name,
            }
            if payload is not None:
                self._values["payload"] = payload

        @builtins.property
        def input_name(self) -> builtins.str:
            '''The name of the AWS IoT Events input where the data is sent.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-iotevents.html#cfn-iotevents-detectormodel-iotevents-inputname
            '''
            result = self._values.get("input_name")
            assert result is not None, "Required property 'input_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def payload(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]]:
            '''You can configure the action payload when you send a message to an AWS IoT Events input.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-iotevents.html#cfn-iotevents-detectormodel-iotevents-payload
            '''
            result = self._values.get("payload")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IotEventsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.IotSiteWiseProperty",
        jsii_struct_bases=[],
        name_mapping={
            "property_value": "propertyValue",
            "asset_id": "assetId",
            "entry_id": "entryId",
            "property_alias": "propertyAlias",
            "property_id": "propertyId",
        },
    )
    class IotSiteWiseProperty:
        def __init__(
            self,
            *,
            property_value: typing.Union["CfnDetectorModel.AssetPropertyValueProperty", _IResolvable_da3f097b],
            asset_id: typing.Optional[builtins.str] = None,
            entry_id: typing.Optional[builtins.str] = None,
            property_alias: typing.Optional[builtins.str] = None,
            property_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Sends information about the detector model instance and the event that triggered the action to a specified asset property in AWS IoT SiteWise .

            You must use expressions for all parameters in ``IotSiteWiseAction`` . The expressions accept literals, operators, functions, references, and substitutions templates.

            **Examples** - For literal values, the expressions must contain single quotes. For example, the value for the ``propertyAlias`` parameter can be ``'/company/windfarm/3/turbine/7/temperature'`` .

            - For references, you must specify either variables or input values. For example, the value for the ``assetId`` parameter can be ``$input.TurbineInput.assetId1`` .
            - For a substitution template, you must use ``${}`` , and the template must be in single quotes. A substitution template can also contain a combination of literals, operators, functions, references, and substitution templates.

            In the following example, the value for the ``propertyAlias`` parameter uses a substitution template.

            ``'company/windfarm/${$input.TemperatureInput.sensorData.windfarmID}/turbine/ ${$input.TemperatureInput.sensorData.turbineID}/temperature'``

            You must specify either ``propertyAlias`` or both ``assetId`` and ``propertyId`` to identify the target asset property in AWS IoT SiteWise .

            For more information, see `Expressions <https://docs.aws.amazon.com/iotevents/latest/developerguide/iotevents-expressions.html>`_ in the *AWS IoT Events Developer Guide* .

            :param property_value: The value to send to the asset property. This value contains timestamp, quality, and value (TQV) information.
            :param asset_id: The ID of the asset that has the specified property.
            :param entry_id: A unique identifier for this entry. You can use the entry ID to track which data entry causes an error in case of failure. The default is a new unique identifier.
            :param property_alias: The alias of the asset property.
            :param property_id: The ID of the asset property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-iotsitewise.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                iot_site_wise_property = iotevents.CfnDetectorModel.IotSiteWiseProperty(
                    property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                        value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                            boolean_value="booleanValue",
                            double_value="doubleValue",
                            integer_value="integerValue",
                            string_value="stringValue"
                        ),
                
                        # the properties below are optional
                        quality="quality",
                        timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                            time_in_seconds="timeInSeconds",
                
                            # the properties below are optional
                            offset_in_nanos="offsetInNanos"
                        )
                    ),
                
                    # the properties below are optional
                    asset_id="assetId",
                    entry_id="entryId",
                    property_alias="propertyAlias",
                    property_id="propertyId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "property_value": property_value,
            }
            if asset_id is not None:
                self._values["asset_id"] = asset_id
            if entry_id is not None:
                self._values["entry_id"] = entry_id
            if property_alias is not None:
                self._values["property_alias"] = property_alias
            if property_id is not None:
                self._values["property_id"] = property_id

        @builtins.property
        def property_value(
            self,
        ) -> typing.Union["CfnDetectorModel.AssetPropertyValueProperty", _IResolvable_da3f097b]:
            '''The value to send to the asset property.

            This value contains timestamp, quality, and value (TQV) information.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-iotsitewise.html#cfn-iotevents-detectormodel-iotsitewise-propertyvalue
            '''
            result = self._values.get("property_value")
            assert result is not None, "Required property 'property_value' is missing"
            return typing.cast(typing.Union["CfnDetectorModel.AssetPropertyValueProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def asset_id(self) -> typing.Optional[builtins.str]:
            '''The ID of the asset that has the specified property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-iotsitewise.html#cfn-iotevents-detectormodel-iotsitewise-assetid
            '''
            result = self._values.get("asset_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def entry_id(self) -> typing.Optional[builtins.str]:
            '''A unique identifier for this entry.

            You can use the entry ID to track which data entry causes an error in case of failure. The default is a new unique identifier.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-iotsitewise.html#cfn-iotevents-detectormodel-iotsitewise-entryid
            '''
            result = self._values.get("entry_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def property_alias(self) -> typing.Optional[builtins.str]:
            '''The alias of the asset property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-iotsitewise.html#cfn-iotevents-detectormodel-iotsitewise-propertyalias
            '''
            result = self._values.get("property_alias")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def property_id(self) -> typing.Optional[builtins.str]:
            '''The ID of the asset property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-iotsitewise.html#cfn-iotevents-detectormodel-iotsitewise-propertyid
            '''
            result = self._values.get("property_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IotSiteWiseProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.IotTopicPublishProperty",
        jsii_struct_bases=[],
        name_mapping={"mqtt_topic": "mqttTopic", "payload": "payload"},
    )
    class IotTopicPublishProperty:
        def __init__(
            self,
            *,
            mqtt_topic: builtins.str,
            payload: typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Information required to publish the MQTT message through the AWS IoT message broker.

            :param mqtt_topic: The MQTT topic of the message. You can use a string expression that includes variables ( ``$variable.<variable-name>`` ) and input values ( ``$input.<input-name>.<path-to-datum>`` ) as the topic string.
            :param payload: You can configure the action payload when you publish a message to an AWS IoT Core topic.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-iottopicpublish.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                iot_topic_publish_property = iotevents.CfnDetectorModel.IotTopicPublishProperty(
                    mqtt_topic="mqttTopic",
                
                    # the properties below are optional
                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                        content_expression="contentExpression",
                        type="type"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "mqtt_topic": mqtt_topic,
            }
            if payload is not None:
                self._values["payload"] = payload

        @builtins.property
        def mqtt_topic(self) -> builtins.str:
            '''The MQTT topic of the message.

            You can use a string expression that includes variables ( ``$variable.<variable-name>`` ) and input values ( ``$input.<input-name>.<path-to-datum>`` ) as the topic string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-iottopicpublish.html#cfn-iotevents-detectormodel-iottopicpublish-mqtttopic
            '''
            result = self._values.get("mqtt_topic")
            assert result is not None, "Required property 'mqtt_topic' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def payload(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]]:
            '''You can configure the action payload when you publish a message to an AWS IoT Core topic.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-iottopicpublish.html#cfn-iotevents-detectormodel-iottopicpublish-payload
            '''
            result = self._values.get("payload")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IotTopicPublishProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.LambdaProperty",
        jsii_struct_bases=[],
        name_mapping={"function_arn": "functionArn", "payload": "payload"},
    )
    class LambdaProperty:
        def __init__(
            self,
            *,
            function_arn: builtins.str,
            payload: typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Calls a Lambda function, passing in information about the detector model instance and the event that triggered the action.

            :param function_arn: The ARN of the Lambda function that is executed.
            :param payload: You can configure the action payload when you send a message to a Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-lambda.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                lambda_property = iotevents.CfnDetectorModel.LambdaProperty(
                    function_arn="functionArn",
                
                    # the properties below are optional
                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                        content_expression="contentExpression",
                        type="type"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "function_arn": function_arn,
            }
            if payload is not None:
                self._values["payload"] = payload

        @builtins.property
        def function_arn(self) -> builtins.str:
            '''The ARN of the Lambda function that is executed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-lambda.html#cfn-iotevents-detectormodel-lambda-functionarn
            '''
            result = self._values.get("function_arn")
            assert result is not None, "Required property 'function_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def payload(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]]:
            '''You can configure the action payload when you send a message to a Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-lambda.html#cfn-iotevents-detectormodel-lambda-payload
            '''
            result = self._values.get("payload")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LambdaProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.OnEnterProperty",
        jsii_struct_bases=[],
        name_mapping={"events": "events"},
    )
    class OnEnterProperty:
        def __init__(
            self,
            *,
            events: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDetectorModel.EventProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''When entering this state, perform these ``actions`` if the ``condition`` is TRUE.

            :param events: Specifies the actions that are performed when the state is entered and the ``condition`` is ``TRUE`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-onenter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                on_enter_property = iotevents.CfnDetectorModel.OnEnterProperty(
                    events=[iotevents.CfnDetectorModel.EventProperty(
                        event_name="eventName",
                
                        # the properties below are optional
                        actions=[iotevents.CfnDetectorModel.ActionProperty(
                            clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                timer_name="timerName"
                            ),
                            dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                hash_key_field="hashKeyField",
                                hash_key_value="hashKeyValue",
                                table_name="tableName",
                
                                # the properties below are optional
                                hash_key_type="hashKeyType",
                                operation="operation",
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                ),
                                payload_field="payloadField",
                                range_key_field="rangeKeyField",
                                range_key_type="rangeKeyType",
                                range_key_value="rangeKeyValue"
                            ),
                            dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                table_name="tableName",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                delivery_stream_name="deliveryStreamName",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                ),
                                separator="separator"
                            ),
                            iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                input_name="inputName",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                    value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                        boolean_value="booleanValue",
                                        double_value="doubleValue",
                                        integer_value="integerValue",
                                        string_value="stringValue"
                                    ),
                
                                    # the properties below are optional
                                    quality="quality",
                                    timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                        time_in_seconds="timeInSeconds",
                
                                        # the properties below are optional
                                        offset_in_nanos="offsetInNanos"
                                    )
                                ),
                
                                # the properties below are optional
                                asset_id="assetId",
                                entry_id="entryId",
                                property_alias="propertyAlias",
                                property_id="propertyId"
                            ),
                            iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                mqtt_topic="mqttTopic",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                function_arn="functionArn",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                timer_name="timerName"
                            ),
                            set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                timer_name="timerName",
                
                                # the properties below are optional
                                duration_expression="durationExpression",
                                seconds=123
                            ),
                            set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                value="value",
                                variable_name="variableName"
                            ),
                            sns=iotevents.CfnDetectorModel.SnsProperty(
                                target_arn="targetArn",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            sqs=iotevents.CfnDetectorModel.SqsProperty(
                                queue_url="queueUrl",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                ),
                                use_base64=False
                            )
                        )],
                        condition="condition"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if events is not None:
                self._values["events"] = events

        @builtins.property
        def events(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDetectorModel.EventProperty", _IResolvable_da3f097b]]]]:
            '''Specifies the actions that are performed when the state is entered and the ``condition`` is ``TRUE`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-onenter.html#cfn-iotevents-detectormodel-onenter-events
            '''
            result = self._values.get("events")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDetectorModel.EventProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OnEnterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.OnExitProperty",
        jsii_struct_bases=[],
        name_mapping={"events": "events"},
    )
    class OnExitProperty:
        def __init__(
            self,
            *,
            events: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDetectorModel.EventProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''When exiting this state, perform these ``actions`` if the specified ``condition`` is ``TRUE`` .

            :param events: Specifies the ``actions`` that are performed when the state is exited and the ``condition`` is ``TRUE`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-onexit.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                on_exit_property = iotevents.CfnDetectorModel.OnExitProperty(
                    events=[iotevents.CfnDetectorModel.EventProperty(
                        event_name="eventName",
                
                        # the properties below are optional
                        actions=[iotevents.CfnDetectorModel.ActionProperty(
                            clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                timer_name="timerName"
                            ),
                            dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                hash_key_field="hashKeyField",
                                hash_key_value="hashKeyValue",
                                table_name="tableName",
                
                                # the properties below are optional
                                hash_key_type="hashKeyType",
                                operation="operation",
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                ),
                                payload_field="payloadField",
                                range_key_field="rangeKeyField",
                                range_key_type="rangeKeyType",
                                range_key_value="rangeKeyValue"
                            ),
                            dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                table_name="tableName",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                delivery_stream_name="deliveryStreamName",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                ),
                                separator="separator"
                            ),
                            iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                input_name="inputName",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                    value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                        boolean_value="booleanValue",
                                        double_value="doubleValue",
                                        integer_value="integerValue",
                                        string_value="stringValue"
                                    ),
                
                                    # the properties below are optional
                                    quality="quality",
                                    timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                        time_in_seconds="timeInSeconds",
                
                                        # the properties below are optional
                                        offset_in_nanos="offsetInNanos"
                                    )
                                ),
                
                                # the properties below are optional
                                asset_id="assetId",
                                entry_id="entryId",
                                property_alias="propertyAlias",
                                property_id="propertyId"
                            ),
                            iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                mqtt_topic="mqttTopic",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                function_arn="functionArn",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                timer_name="timerName"
                            ),
                            set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                timer_name="timerName",
                
                                # the properties below are optional
                                duration_expression="durationExpression",
                                seconds=123
                            ),
                            set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                value="value",
                                variable_name="variableName"
                            ),
                            sns=iotevents.CfnDetectorModel.SnsProperty(
                                target_arn="targetArn",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            sqs=iotevents.CfnDetectorModel.SqsProperty(
                                queue_url="queueUrl",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                ),
                                use_base64=False
                            )
                        )],
                        condition="condition"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if events is not None:
                self._values["events"] = events

        @builtins.property
        def events(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDetectorModel.EventProperty", _IResolvable_da3f097b]]]]:
            '''Specifies the ``actions`` that are performed when the state is exited and the ``condition`` is ``TRUE`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-onexit.html#cfn-iotevents-detectormodel-onexit-events
            '''
            result = self._values.get("events")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDetectorModel.EventProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OnExitProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.OnInputProperty",
        jsii_struct_bases=[],
        name_mapping={"events": "events", "transition_events": "transitionEvents"},
    )
    class OnInputProperty:
        def __init__(
            self,
            *,
            events: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDetectorModel.EventProperty", _IResolvable_da3f097b]]]] = None,
            transition_events: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDetectorModel.TransitionEventProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Specifies the actions performed when the ``condition`` evaluates to TRUE.

            :param events: Specifies the actions performed when the ``condition`` evaluates to TRUE.
            :param transition_events: Specifies the actions performed, and the next state entered, when a ``condition`` evaluates to TRUE.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-oninput.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                on_input_property = iotevents.CfnDetectorModel.OnInputProperty(
                    events=[iotevents.CfnDetectorModel.EventProperty(
                        event_name="eventName",
                
                        # the properties below are optional
                        actions=[iotevents.CfnDetectorModel.ActionProperty(
                            clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                timer_name="timerName"
                            ),
                            dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                hash_key_field="hashKeyField",
                                hash_key_value="hashKeyValue",
                                table_name="tableName",
                
                                # the properties below are optional
                                hash_key_type="hashKeyType",
                                operation="operation",
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                ),
                                payload_field="payloadField",
                                range_key_field="rangeKeyField",
                                range_key_type="rangeKeyType",
                                range_key_value="rangeKeyValue"
                            ),
                            dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                table_name="tableName",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                delivery_stream_name="deliveryStreamName",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                ),
                                separator="separator"
                            ),
                            iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                input_name="inputName",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                    value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                        boolean_value="booleanValue",
                                        double_value="doubleValue",
                                        integer_value="integerValue",
                                        string_value="stringValue"
                                    ),
                
                                    # the properties below are optional
                                    quality="quality",
                                    timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                        time_in_seconds="timeInSeconds",
                
                                        # the properties below are optional
                                        offset_in_nanos="offsetInNanos"
                                    )
                                ),
                
                                # the properties below are optional
                                asset_id="assetId",
                                entry_id="entryId",
                                property_alias="propertyAlias",
                                property_id="propertyId"
                            ),
                            iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                mqtt_topic="mqttTopic",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                function_arn="functionArn",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                timer_name="timerName"
                            ),
                            set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                timer_name="timerName",
                
                                # the properties below are optional
                                duration_expression="durationExpression",
                                seconds=123
                            ),
                            set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                value="value",
                                variable_name="variableName"
                            ),
                            sns=iotevents.CfnDetectorModel.SnsProperty(
                                target_arn="targetArn",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            sqs=iotevents.CfnDetectorModel.SqsProperty(
                                queue_url="queueUrl",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                ),
                                use_base64=False
                            )
                        )],
                        condition="condition"
                    )],
                    transition_events=[iotevents.CfnDetectorModel.TransitionEventProperty(
                        condition="condition",
                        event_name="eventName",
                        next_state="nextState",
                
                        # the properties below are optional
                        actions=[iotevents.CfnDetectorModel.ActionProperty(
                            clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                timer_name="timerName"
                            ),
                            dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                hash_key_field="hashKeyField",
                                hash_key_value="hashKeyValue",
                                table_name="tableName",
                
                                # the properties below are optional
                                hash_key_type="hashKeyType",
                                operation="operation",
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                ),
                                payload_field="payloadField",
                                range_key_field="rangeKeyField",
                                range_key_type="rangeKeyType",
                                range_key_value="rangeKeyValue"
                            ),
                            dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                table_name="tableName",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                delivery_stream_name="deliveryStreamName",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                ),
                                separator="separator"
                            ),
                            iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                input_name="inputName",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                    value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                        boolean_value="booleanValue",
                                        double_value="doubleValue",
                                        integer_value="integerValue",
                                        string_value="stringValue"
                                    ),
                
                                    # the properties below are optional
                                    quality="quality",
                                    timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                        time_in_seconds="timeInSeconds",
                
                                        # the properties below are optional
                                        offset_in_nanos="offsetInNanos"
                                    )
                                ),
                
                                # the properties below are optional
                                asset_id="assetId",
                                entry_id="entryId",
                                property_alias="propertyAlias",
                                property_id="propertyId"
                            ),
                            iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                mqtt_topic="mqttTopic",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                function_arn="functionArn",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                timer_name="timerName"
                            ),
                            set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                timer_name="timerName",
                
                                # the properties below are optional
                                duration_expression="durationExpression",
                                seconds=123
                            ),
                            set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                value="value",
                                variable_name="variableName"
                            ),
                            sns=iotevents.CfnDetectorModel.SnsProperty(
                                target_arn="targetArn",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                )
                            ),
                            sqs=iotevents.CfnDetectorModel.SqsProperty(
                                queue_url="queueUrl",
                
                                # the properties below are optional
                                payload=iotevents.CfnDetectorModel.PayloadProperty(
                                    content_expression="contentExpression",
                                    type="type"
                                ),
                                use_base64=False
                            )
                        )]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if events is not None:
                self._values["events"] = events
            if transition_events is not None:
                self._values["transition_events"] = transition_events

        @builtins.property
        def events(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDetectorModel.EventProperty", _IResolvable_da3f097b]]]]:
            '''Specifies the actions performed when the ``condition`` evaluates to TRUE.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-oninput.html#cfn-iotevents-detectormodel-oninput-events
            '''
            result = self._values.get("events")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDetectorModel.EventProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def transition_events(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDetectorModel.TransitionEventProperty", _IResolvable_da3f097b]]]]:
            '''Specifies the actions performed, and the next state entered, when a ``condition`` evaluates to TRUE.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-oninput.html#cfn-iotevents-detectormodel-oninput-transitionevents
            '''
            result = self._values.get("transition_events")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDetectorModel.TransitionEventProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OnInputProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.PayloadProperty",
        jsii_struct_bases=[],
        name_mapping={"content_expression": "contentExpression", "type": "type"},
    )
    class PayloadProperty:
        def __init__(
            self,
            *,
            content_expression: builtins.str,
            type: builtins.str,
        ) -> None:
            '''Information needed to configure the payload.

            By default, AWS IoT Events generates a standard payload in JSON for any action. This action payload contains all attribute-value pairs that have the information about the detector model instance and the event triggered the action. To configure the action payload, you can use ``contentExpression`` .

            :param content_expression: The content of the payload. You can use a string expression that includes quoted strings ( ``'<string>'`` ), variables ( ``$variable.<variable-name>`` ), input values ( ``$input.<input-name>.<path-to-datum>`` ), string concatenations, and quoted strings that contain ``${}`` as the content. The recommended maximum size of a content expression is 1 KB.
            :param type: The value of the payload type can be either ``STRING`` or ``JSON`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-payload.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                payload_property = iotevents.CfnDetectorModel.PayloadProperty(
                    content_expression="contentExpression",
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "content_expression": content_expression,
                "type": type,
            }

        @builtins.property
        def content_expression(self) -> builtins.str:
            '''The content of the payload.

            You can use a string expression that includes quoted strings ( ``'<string>'`` ), variables ( ``$variable.<variable-name>`` ), input values ( ``$input.<input-name>.<path-to-datum>`` ), string concatenations, and quoted strings that contain ``${}`` as the content. The recommended maximum size of a content expression is 1 KB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-payload.html#cfn-iotevents-detectormodel-payload-contentexpression
            '''
            result = self._values.get("content_expression")
            assert result is not None, "Required property 'content_expression' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def type(self) -> builtins.str:
            '''The value of the payload type can be either ``STRING`` or ``JSON`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-payload.html#cfn-iotevents-detectormodel-payload-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PayloadProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.ResetTimerProperty",
        jsii_struct_bases=[],
        name_mapping={"timer_name": "timerName"},
    )
    class ResetTimerProperty:
        def __init__(self, *, timer_name: builtins.str) -> None:
            '''Information required to reset the timer.

            The timer is reset to the previously evaluated result of the duration. The duration expression isn't reevaluated when you reset the timer.

            :param timer_name: The name of the timer to reset.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-resettimer.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                reset_timer_property = iotevents.CfnDetectorModel.ResetTimerProperty(
                    timer_name="timerName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "timer_name": timer_name,
            }

        @builtins.property
        def timer_name(self) -> builtins.str:
            '''The name of the timer to reset.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-resettimer.html#cfn-iotevents-detectormodel-resettimer-timername
            '''
            result = self._values.get("timer_name")
            assert result is not None, "Required property 'timer_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResetTimerProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.SetTimerProperty",
        jsii_struct_bases=[],
        name_mapping={
            "timer_name": "timerName",
            "duration_expression": "durationExpression",
            "seconds": "seconds",
        },
    )
    class SetTimerProperty:
        def __init__(
            self,
            *,
            timer_name: builtins.str,
            duration_expression: typing.Optional[builtins.str] = None,
            seconds: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Information needed to set the timer.

            :param timer_name: The name of the timer.
            :param duration_expression: The duration of the timer, in seconds. You can use a string expression that includes numbers, variables ( ``$variable.<variable-name>`` ), and input values ( ``$input.<input-name>.<path-to-datum>`` ) as the duration. The range of the duration is 1-31622400 seconds. To ensure accuracy, the minimum duration is 60 seconds. The evaluated result of the duration is rounded down to the nearest whole number.
            :param seconds: The number of seconds until the timer expires. The minimum value is 60 seconds to ensure accuracy. The maximum value is 31622400 seconds.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-settimer.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                set_timer_property = iotevents.CfnDetectorModel.SetTimerProperty(
                    timer_name="timerName",
                
                    # the properties below are optional
                    duration_expression="durationExpression",
                    seconds=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "timer_name": timer_name,
            }
            if duration_expression is not None:
                self._values["duration_expression"] = duration_expression
            if seconds is not None:
                self._values["seconds"] = seconds

        @builtins.property
        def timer_name(self) -> builtins.str:
            '''The name of the timer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-settimer.html#cfn-iotevents-detectormodel-settimer-timername
            '''
            result = self._values.get("timer_name")
            assert result is not None, "Required property 'timer_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def duration_expression(self) -> typing.Optional[builtins.str]:
            '''The duration of the timer, in seconds.

            You can use a string expression that includes numbers, variables ( ``$variable.<variable-name>`` ), and input values ( ``$input.<input-name>.<path-to-datum>`` ) as the duration. The range of the duration is 1-31622400 seconds. To ensure accuracy, the minimum duration is 60 seconds. The evaluated result of the duration is rounded down to the nearest whole number.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-settimer.html#cfn-iotevents-detectormodel-settimer-durationexpression
            '''
            result = self._values.get("duration_expression")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def seconds(self) -> typing.Optional[jsii.Number]:
            '''The number of seconds until the timer expires.

            The minimum value is 60 seconds to ensure accuracy. The maximum value is 31622400 seconds.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-settimer.html#cfn-iotevents-detectormodel-settimer-seconds
            '''
            result = self._values.get("seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SetTimerProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.SetVariableProperty",
        jsii_struct_bases=[],
        name_mapping={"value": "value", "variable_name": "variableName"},
    )
    class SetVariableProperty:
        def __init__(self, *, value: builtins.str, variable_name: builtins.str) -> None:
            '''Information about the variable and its new value.

            :param value: The new value of the variable.
            :param variable_name: The name of the variable.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-setvariable.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                set_variable_property = iotevents.CfnDetectorModel.SetVariableProperty(
                    value="value",
                    variable_name="variableName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "value": value,
                "variable_name": variable_name,
            }

        @builtins.property
        def value(self) -> builtins.str:
            '''The new value of the variable.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-setvariable.html#cfn-iotevents-detectormodel-setvariable-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def variable_name(self) -> builtins.str:
            '''The name of the variable.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-setvariable.html#cfn-iotevents-detectormodel-setvariable-variablename
            '''
            result = self._values.get("variable_name")
            assert result is not None, "Required property 'variable_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SetVariableProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.SnsProperty",
        jsii_struct_bases=[],
        name_mapping={"target_arn": "targetArn", "payload": "payload"},
    )
    class SnsProperty:
        def __init__(
            self,
            *,
            target_arn: builtins.str,
            payload: typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Information required to publish the Amazon SNS message.

            :param target_arn: The ARN of the Amazon SNS target where the message is sent.
            :param payload: You can configure the action payload when you send a message as an Amazon SNS push notification.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-sns.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                sns_property = iotevents.CfnDetectorModel.SnsProperty(
                    target_arn="targetArn",
                
                    # the properties below are optional
                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                        content_expression="contentExpression",
                        type="type"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "target_arn": target_arn,
            }
            if payload is not None:
                self._values["payload"] = payload

        @builtins.property
        def target_arn(self) -> builtins.str:
            '''The ARN of the Amazon SNS target where the message is sent.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-sns.html#cfn-iotevents-detectormodel-sns-targetarn
            '''
            result = self._values.get("target_arn")
            assert result is not None, "Required property 'target_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def payload(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]]:
            '''You can configure the action payload when you send a message as an Amazon SNS push notification.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-sns.html#cfn-iotevents-detectormodel-sns-payload
            '''
            result = self._values.get("payload")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SnsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.SqsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "queue_url": "queueUrl",
            "payload": "payload",
            "use_base64": "useBase64",
        },
    )
    class SqsProperty:
        def __init__(
            self,
            *,
            queue_url: builtins.str,
            payload: typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]] = None,
            use_base64: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Sends information about the detector model instance and the event that triggered the action to an Amazon SQS queue.

            :param queue_url: The URL of the SQS queue where the data is written.
            :param payload: You can configure the action payload when you send a message to an Amazon SQS queue.
            :param use_base64: Set this to TRUE if you want the data to be base-64 encoded before it is written to the queue. Otherwise, set this to FALSE.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-sqs.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                sqs_property = iotevents.CfnDetectorModel.SqsProperty(
                    queue_url="queueUrl",
                
                    # the properties below are optional
                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                        content_expression="contentExpression",
                        type="type"
                    ),
                    use_base64=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "queue_url": queue_url,
            }
            if payload is not None:
                self._values["payload"] = payload
            if use_base64 is not None:
                self._values["use_base64"] = use_base64

        @builtins.property
        def queue_url(self) -> builtins.str:
            '''The URL of the SQS queue where the data is written.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-sqs.html#cfn-iotevents-detectormodel-sqs-queueurl
            '''
            result = self._values.get("queue_url")
            assert result is not None, "Required property 'queue_url' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def payload(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]]:
            '''You can configure the action payload when you send a message to an Amazon SQS queue.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-sqs.html#cfn-iotevents-detectormodel-sqs-payload
            '''
            result = self._values.get("payload")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.PayloadProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def use_base64(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Set this to TRUE if you want the data to be base-64 encoded before it is written to the queue.

            Otherwise, set this to FALSE.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-sqs.html#cfn-iotevents-detectormodel-sqs-usebase64
            '''
            result = self._values.get("use_base64")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SqsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.StateProperty",
        jsii_struct_bases=[],
        name_mapping={
            "state_name": "stateName",
            "on_enter": "onEnter",
            "on_exit": "onExit",
            "on_input": "onInput",
        },
    )
    class StateProperty:
        def __init__(
            self,
            *,
            state_name: builtins.str,
            on_enter: typing.Optional[typing.Union["CfnDetectorModel.OnEnterProperty", _IResolvable_da3f097b]] = None,
            on_exit: typing.Optional[typing.Union["CfnDetectorModel.OnExitProperty", _IResolvable_da3f097b]] = None,
            on_input: typing.Optional[typing.Union["CfnDetectorModel.OnInputProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Information that defines a state of a detector.

            :param state_name: The name of the state.
            :param on_enter: When entering this state, perform these ``actions`` if the ``condition`` is TRUE.
            :param on_exit: When exiting this state, perform these ``actions`` if the specified ``condition`` is ``TRUE`` .
            :param on_input: When an input is received and the ``condition`` is TRUE, perform the specified ``actions`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-state.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                state_property = iotevents.CfnDetectorModel.StateProperty(
                    state_name="stateName",
                
                    # the properties below are optional
                    on_enter=iotevents.CfnDetectorModel.OnEnterProperty(
                        events=[iotevents.CfnDetectorModel.EventProperty(
                            event_name="eventName",
                
                            # the properties below are optional
                            actions=[iotevents.CfnDetectorModel.ActionProperty(
                                clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                    timer_name="timerName"
                                ),
                                dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                    hash_key_field="hashKeyField",
                                    hash_key_value="hashKeyValue",
                                    table_name="tableName",
                
                                    # the properties below are optional
                                    hash_key_type="hashKeyType",
                                    operation="operation",
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    payload_field="payloadField",
                                    range_key_field="rangeKeyField",
                                    range_key_type="rangeKeyType",
                                    range_key_value="rangeKeyValue"
                                ),
                                dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                    table_name="tableName",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                    delivery_stream_name="deliveryStreamName",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    separator="separator"
                                ),
                                iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                    input_name="inputName",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                    property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                        value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                            boolean_value="booleanValue",
                                            double_value="doubleValue",
                                            integer_value="integerValue",
                                            string_value="stringValue"
                                        ),
                
                                        # the properties below are optional
                                        quality="quality",
                                        timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                            time_in_seconds="timeInSeconds",
                
                                            # the properties below are optional
                                            offset_in_nanos="offsetInNanos"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    asset_id="assetId",
                                    entry_id="entryId",
                                    property_alias="propertyAlias",
                                    property_id="propertyId"
                                ),
                                iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                    mqtt_topic="mqttTopic",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                    function_arn="functionArn",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                    timer_name="timerName"
                                ),
                                set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                    timer_name="timerName",
                
                                    # the properties below are optional
                                    duration_expression="durationExpression",
                                    seconds=123
                                ),
                                set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                    value="value",
                                    variable_name="variableName"
                                ),
                                sns=iotevents.CfnDetectorModel.SnsProperty(
                                    target_arn="targetArn",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                sqs=iotevents.CfnDetectorModel.SqsProperty(
                                    queue_url="queueUrl",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    use_base64=False
                                )
                            )],
                            condition="condition"
                        )]
                    ),
                    on_exit=iotevents.CfnDetectorModel.OnExitProperty(
                        events=[iotevents.CfnDetectorModel.EventProperty(
                            event_name="eventName",
                
                            # the properties below are optional
                            actions=[iotevents.CfnDetectorModel.ActionProperty(
                                clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                    timer_name="timerName"
                                ),
                                dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                    hash_key_field="hashKeyField",
                                    hash_key_value="hashKeyValue",
                                    table_name="tableName",
                
                                    # the properties below are optional
                                    hash_key_type="hashKeyType",
                                    operation="operation",
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    payload_field="payloadField",
                                    range_key_field="rangeKeyField",
                                    range_key_type="rangeKeyType",
                                    range_key_value="rangeKeyValue"
                                ),
                                dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                    table_name="tableName",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                    delivery_stream_name="deliveryStreamName",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    separator="separator"
                                ),
                                iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                    input_name="inputName",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                    property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                        value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                            boolean_value="booleanValue",
                                            double_value="doubleValue",
                                            integer_value="integerValue",
                                            string_value="stringValue"
                                        ),
                
                                        # the properties below are optional
                                        quality="quality",
                                        timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                            time_in_seconds="timeInSeconds",
                
                                            # the properties below are optional
                                            offset_in_nanos="offsetInNanos"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    asset_id="assetId",
                                    entry_id="entryId",
                                    property_alias="propertyAlias",
                                    property_id="propertyId"
                                ),
                                iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                    mqtt_topic="mqttTopic",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                    function_arn="functionArn",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                    timer_name="timerName"
                                ),
                                set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                    timer_name="timerName",
                
                                    # the properties below are optional
                                    duration_expression="durationExpression",
                                    seconds=123
                                ),
                                set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                    value="value",
                                    variable_name="variableName"
                                ),
                                sns=iotevents.CfnDetectorModel.SnsProperty(
                                    target_arn="targetArn",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                sqs=iotevents.CfnDetectorModel.SqsProperty(
                                    queue_url="queueUrl",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    use_base64=False
                                )
                            )],
                            condition="condition"
                        )]
                    ),
                    on_input=iotevents.CfnDetectorModel.OnInputProperty(
                        events=[iotevents.CfnDetectorModel.EventProperty(
                            event_name="eventName",
                
                            # the properties below are optional
                            actions=[iotevents.CfnDetectorModel.ActionProperty(
                                clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                    timer_name="timerName"
                                ),
                                dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                    hash_key_field="hashKeyField",
                                    hash_key_value="hashKeyValue",
                                    table_name="tableName",
                
                                    # the properties below are optional
                                    hash_key_type="hashKeyType",
                                    operation="operation",
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    payload_field="payloadField",
                                    range_key_field="rangeKeyField",
                                    range_key_type="rangeKeyType",
                                    range_key_value="rangeKeyValue"
                                ),
                                dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                    table_name="tableName",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                    delivery_stream_name="deliveryStreamName",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    separator="separator"
                                ),
                                iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                    input_name="inputName",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                    property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                        value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                            boolean_value="booleanValue",
                                            double_value="doubleValue",
                                            integer_value="integerValue",
                                            string_value="stringValue"
                                        ),
                
                                        # the properties below are optional
                                        quality="quality",
                                        timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                            time_in_seconds="timeInSeconds",
                
                                            # the properties below are optional
                                            offset_in_nanos="offsetInNanos"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    asset_id="assetId",
                                    entry_id="entryId",
                                    property_alias="propertyAlias",
                                    property_id="propertyId"
                                ),
                                iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                    mqtt_topic="mqttTopic",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                    function_arn="functionArn",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                    timer_name="timerName"
                                ),
                                set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                    timer_name="timerName",
                
                                    # the properties below are optional
                                    duration_expression="durationExpression",
                                    seconds=123
                                ),
                                set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                    value="value",
                                    variable_name="variableName"
                                ),
                                sns=iotevents.CfnDetectorModel.SnsProperty(
                                    target_arn="targetArn",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                sqs=iotevents.CfnDetectorModel.SqsProperty(
                                    queue_url="queueUrl",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    use_base64=False
                                )
                            )],
                            condition="condition"
                        )],
                        transition_events=[iotevents.CfnDetectorModel.TransitionEventProperty(
                            condition="condition",
                            event_name="eventName",
                            next_state="nextState",
                
                            # the properties below are optional
                            actions=[iotevents.CfnDetectorModel.ActionProperty(
                                clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                    timer_name="timerName"
                                ),
                                dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                    hash_key_field="hashKeyField",
                                    hash_key_value="hashKeyValue",
                                    table_name="tableName",
                
                                    # the properties below are optional
                                    hash_key_type="hashKeyType",
                                    operation="operation",
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    payload_field="payloadField",
                                    range_key_field="rangeKeyField",
                                    range_key_type="rangeKeyType",
                                    range_key_value="rangeKeyValue"
                                ),
                                dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                    table_name="tableName",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                    delivery_stream_name="deliveryStreamName",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    separator="separator"
                                ),
                                iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                    input_name="inputName",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                    property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                        value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                            boolean_value="booleanValue",
                                            double_value="doubleValue",
                                            integer_value="integerValue",
                                            string_value="stringValue"
                                        ),
                
                                        # the properties below are optional
                                        quality="quality",
                                        timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                            time_in_seconds="timeInSeconds",
                
                                            # the properties below are optional
                                            offset_in_nanos="offsetInNanos"
                                        )
                                    ),
                
                                    # the properties below are optional
                                    asset_id="assetId",
                                    entry_id="entryId",
                                    property_alias="propertyAlias",
                                    property_id="propertyId"
                                ),
                                iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                    mqtt_topic="mqttTopic",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                    function_arn="functionArn",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                    timer_name="timerName"
                                ),
                                set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                    timer_name="timerName",
                
                                    # the properties below are optional
                                    duration_expression="durationExpression",
                                    seconds=123
                                ),
                                set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                    value="value",
                                    variable_name="variableName"
                                ),
                                sns=iotevents.CfnDetectorModel.SnsProperty(
                                    target_arn="targetArn",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    )
                                ),
                                sqs=iotevents.CfnDetectorModel.SqsProperty(
                                    queue_url="queueUrl",
                
                                    # the properties below are optional
                                    payload=iotevents.CfnDetectorModel.PayloadProperty(
                                        content_expression="contentExpression",
                                        type="type"
                                    ),
                                    use_base64=False
                                )
                            )]
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "state_name": state_name,
            }
            if on_enter is not None:
                self._values["on_enter"] = on_enter
            if on_exit is not None:
                self._values["on_exit"] = on_exit
            if on_input is not None:
                self._values["on_input"] = on_input

        @builtins.property
        def state_name(self) -> builtins.str:
            '''The name of the state.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-state.html#cfn-iotevents-detectormodel-state-statename
            '''
            result = self._values.get("state_name")
            assert result is not None, "Required property 'state_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def on_enter(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.OnEnterProperty", _IResolvable_da3f097b]]:
            '''When entering this state, perform these ``actions`` if the ``condition`` is TRUE.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-state.html#cfn-iotevents-detectormodel-state-onenter
            '''
            result = self._values.get("on_enter")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.OnEnterProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def on_exit(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.OnExitProperty", _IResolvable_da3f097b]]:
            '''When exiting this state, perform these ``actions`` if the specified ``condition`` is ``TRUE`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-state.html#cfn-iotevents-detectormodel-state-onexit
            '''
            result = self._values.get("on_exit")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.OnExitProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def on_input(
            self,
        ) -> typing.Optional[typing.Union["CfnDetectorModel.OnInputProperty", _IResolvable_da3f097b]]:
            '''When an input is received and the ``condition`` is TRUE, perform the specified ``actions`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-state.html#cfn-iotevents-detectormodel-state-oninput
            '''
            result = self._values.get("on_input")
            return typing.cast(typing.Optional[typing.Union["CfnDetectorModel.OnInputProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StateProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModel.TransitionEventProperty",
        jsii_struct_bases=[],
        name_mapping={
            "condition": "condition",
            "event_name": "eventName",
            "next_state": "nextState",
            "actions": "actions",
        },
    )
    class TransitionEventProperty:
        def __init__(
            self,
            *,
            condition: builtins.str,
            event_name: builtins.str,
            next_state: builtins.str,
            actions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDetectorModel.ActionProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Specifies the actions performed and the next state entered when a ``condition`` evaluates to TRUE.

            :param condition: Required. A Boolean expression that when TRUE causes the actions to be performed and the ``nextState`` to be entered.
            :param event_name: The name of the transition event.
            :param next_state: The next state to enter.
            :param actions: The actions to be performed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-transitionevent.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                transition_event_property = iotevents.CfnDetectorModel.TransitionEventProperty(
                    condition="condition",
                    event_name="eventName",
                    next_state="nextState",
                
                    # the properties below are optional
                    actions=[iotevents.CfnDetectorModel.ActionProperty(
                        clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                            timer_name="timerName"
                        ),
                        dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                            hash_key_field="hashKeyField",
                            hash_key_value="hashKeyValue",
                            table_name="tableName",
                
                            # the properties below are optional
                            hash_key_type="hashKeyType",
                            operation="operation",
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            ),
                            payload_field="payloadField",
                            range_key_field="rangeKeyField",
                            range_key_type="rangeKeyType",
                            range_key_value="rangeKeyValue"
                        ),
                        dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                            table_name="tableName",
                
                            # the properties below are optional
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            )
                        ),
                        firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                            delivery_stream_name="deliveryStreamName",
                
                            # the properties below are optional
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            ),
                            separator="separator"
                        ),
                        iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                            input_name="inputName",
                
                            # the properties below are optional
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            )
                        ),
                        iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                            property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                    boolean_value="booleanValue",
                                    double_value="doubleValue",
                                    integer_value="integerValue",
                                    string_value="stringValue"
                                ),
                
                                # the properties below are optional
                                quality="quality",
                                timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                    time_in_seconds="timeInSeconds",
                
                                    # the properties below are optional
                                    offset_in_nanos="offsetInNanos"
                                )
                            ),
                
                            # the properties below are optional
                            asset_id="assetId",
                            entry_id="entryId",
                            property_alias="propertyAlias",
                            property_id="propertyId"
                        ),
                        iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                            mqtt_topic="mqttTopic",
                
                            # the properties below are optional
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            )
                        ),
                        lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                            function_arn="functionArn",
                
                            # the properties below are optional
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            )
                        ),
                        reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                            timer_name="timerName"
                        ),
                        set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                            timer_name="timerName",
                
                            # the properties below are optional
                            duration_expression="durationExpression",
                            seconds=123
                        ),
                        set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                            value="value",
                            variable_name="variableName"
                        ),
                        sns=iotevents.CfnDetectorModel.SnsProperty(
                            target_arn="targetArn",
                
                            # the properties below are optional
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            )
                        ),
                        sqs=iotevents.CfnDetectorModel.SqsProperty(
                            queue_url="queueUrl",
                
                            # the properties below are optional
                            payload=iotevents.CfnDetectorModel.PayloadProperty(
                                content_expression="contentExpression",
                                type="type"
                            ),
                            use_base64=False
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "condition": condition,
                "event_name": event_name,
                "next_state": next_state,
            }
            if actions is not None:
                self._values["actions"] = actions

        @builtins.property
        def condition(self) -> builtins.str:
            '''Required.

            A Boolean expression that when TRUE causes the actions to be performed and the ``nextState`` to be entered.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-transitionevent.html#cfn-iotevents-detectormodel-transitionevent-condition
            '''
            result = self._values.get("condition")
            assert result is not None, "Required property 'condition' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def event_name(self) -> builtins.str:
            '''The name of the transition event.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-transitionevent.html#cfn-iotevents-detectormodel-transitionevent-eventname
            '''
            result = self._values.get("event_name")
            assert result is not None, "Required property 'event_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def next_state(self) -> builtins.str:
            '''The next state to enter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-transitionevent.html#cfn-iotevents-detectormodel-transitionevent-nextstate
            '''
            result = self._values.get("next_state")
            assert result is not None, "Required property 'next_state' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def actions(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDetectorModel.ActionProperty", _IResolvable_da3f097b]]]]:
            '''The actions to be performed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-detectormodel-transitionevent.html#cfn-iotevents-detectormodel-transitionevent-actions
            '''
            result = self._values.get("actions")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDetectorModel.ActionProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TransitionEventProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotevents.CfnDetectorModelProps",
    jsii_struct_bases=[],
    name_mapping={
        "detector_model_definition": "detectorModelDefinition",
        "role_arn": "roleArn",
        "detector_model_description": "detectorModelDescription",
        "detector_model_name": "detectorModelName",
        "evaluation_method": "evaluationMethod",
        "key": "key",
        "tags": "tags",
    },
)
class CfnDetectorModelProps:
    def __init__(
        self,
        *,
        detector_model_definition: typing.Union[CfnDetectorModel.DetectorModelDefinitionProperty, _IResolvable_da3f097b],
        role_arn: builtins.str,
        detector_model_description: typing.Optional[builtins.str] = None,
        detector_model_name: typing.Optional[builtins.str] = None,
        evaluation_method: typing.Optional[builtins.str] = None,
        key: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDetectorModel``.

        :param detector_model_definition: Information that defines how a detector operates.
        :param role_arn: The ARN of the role that grants permission to AWS IoT Events to perform its operations.
        :param detector_model_description: A brief description of the detector model.
        :param detector_model_name: The name of the detector model.
        :param evaluation_method: Information about the order in which events are evaluated and how actions are executed.
        :param key: The value used to identify a detector instance. When a device or system sends input, a new detector instance with a unique key value is created. AWS IoT Events can continue to route input to its corresponding detector instance based on this identifying information. This parameter uses a JSON-path expression to select the attribute-value pair in the message payload that is used for identification. To route the message to the correct detector instance, the device must send a message payload that contains the same attribute-value.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotevents as iotevents
            
            cfn_detector_model_props = iotevents.CfnDetectorModelProps(
                detector_model_definition=iotevents.CfnDetectorModel.DetectorModelDefinitionProperty(
                    initial_state_name="initialStateName",
                    states=[iotevents.CfnDetectorModel.StateProperty(
                        state_name="stateName",
            
                        # the properties below are optional
                        on_enter=iotevents.CfnDetectorModel.OnEnterProperty(
                            events=[iotevents.CfnDetectorModel.EventProperty(
                                event_name="eventName",
            
                                # the properties below are optional
                                actions=[iotevents.CfnDetectorModel.ActionProperty(
                                    clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                        hash_key_field="hashKeyField",
                                        hash_key_value="hashKeyValue",
                                        table_name="tableName",
            
                                        # the properties below are optional
                                        hash_key_type="hashKeyType",
                                        operation="operation",
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        payload_field="payloadField",
                                        range_key_field="rangeKeyField",
                                        range_key_type="rangeKeyType",
                                        range_key_value="rangeKeyValue"
                                    ),
                                    dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                        table_name="tableName",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                        delivery_stream_name="deliveryStreamName",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        separator="separator"
                                    ),
                                    iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                        input_name="inputName",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                        property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                            value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                                boolean_value="booleanValue",
                                                double_value="doubleValue",
                                                integer_value="integerValue",
                                                string_value="stringValue"
                                            ),
            
                                            # the properties below are optional
                                            quality="quality",
                                            timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                                time_in_seconds="timeInSeconds",
            
                                                # the properties below are optional
                                                offset_in_nanos="offsetInNanos"
                                            )
                                        ),
            
                                        # the properties below are optional
                                        asset_id="assetId",
                                        entry_id="entryId",
                                        property_alias="propertyAlias",
                                        property_id="propertyId"
                                    ),
                                    iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                        mqtt_topic="mqttTopic",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                        function_arn="functionArn",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                        timer_name="timerName",
            
                                        # the properties below are optional
                                        duration_expression="durationExpression",
                                        seconds=123
                                    ),
                                    set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                        value="value",
                                        variable_name="variableName"
                                    ),
                                    sns=iotevents.CfnDetectorModel.SnsProperty(
                                        target_arn="targetArn",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    sqs=iotevents.CfnDetectorModel.SqsProperty(
                                        queue_url="queueUrl",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        use_base64=False
                                    )
                                )],
                                condition="condition"
                            )]
                        ),
                        on_exit=iotevents.CfnDetectorModel.OnExitProperty(
                            events=[iotevents.CfnDetectorModel.EventProperty(
                                event_name="eventName",
            
                                # the properties below are optional
                                actions=[iotevents.CfnDetectorModel.ActionProperty(
                                    clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                        hash_key_field="hashKeyField",
                                        hash_key_value="hashKeyValue",
                                        table_name="tableName",
            
                                        # the properties below are optional
                                        hash_key_type="hashKeyType",
                                        operation="operation",
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        payload_field="payloadField",
                                        range_key_field="rangeKeyField",
                                        range_key_type="rangeKeyType",
                                        range_key_value="rangeKeyValue"
                                    ),
                                    dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                        table_name="tableName",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                        delivery_stream_name="deliveryStreamName",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        separator="separator"
                                    ),
                                    iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                        input_name="inputName",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                        property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                            value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                                boolean_value="booleanValue",
                                                double_value="doubleValue",
                                                integer_value="integerValue",
                                                string_value="stringValue"
                                            ),
            
                                            # the properties below are optional
                                            quality="quality",
                                            timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                                time_in_seconds="timeInSeconds",
            
                                                # the properties below are optional
                                                offset_in_nanos="offsetInNanos"
                                            )
                                        ),
            
                                        # the properties below are optional
                                        asset_id="assetId",
                                        entry_id="entryId",
                                        property_alias="propertyAlias",
                                        property_id="propertyId"
                                    ),
                                    iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                        mqtt_topic="mqttTopic",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                        function_arn="functionArn",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                        timer_name="timerName",
            
                                        # the properties below are optional
                                        duration_expression="durationExpression",
                                        seconds=123
                                    ),
                                    set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                        value="value",
                                        variable_name="variableName"
                                    ),
                                    sns=iotevents.CfnDetectorModel.SnsProperty(
                                        target_arn="targetArn",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    sqs=iotevents.CfnDetectorModel.SqsProperty(
                                        queue_url="queueUrl",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        use_base64=False
                                    )
                                )],
                                condition="condition"
                            )]
                        ),
                        on_input=iotevents.CfnDetectorModel.OnInputProperty(
                            events=[iotevents.CfnDetectorModel.EventProperty(
                                event_name="eventName",
            
                                # the properties below are optional
                                actions=[iotevents.CfnDetectorModel.ActionProperty(
                                    clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                        hash_key_field="hashKeyField",
                                        hash_key_value="hashKeyValue",
                                        table_name="tableName",
            
                                        # the properties below are optional
                                        hash_key_type="hashKeyType",
                                        operation="operation",
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        payload_field="payloadField",
                                        range_key_field="rangeKeyField",
                                        range_key_type="rangeKeyType",
                                        range_key_value="rangeKeyValue"
                                    ),
                                    dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                        table_name="tableName",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                        delivery_stream_name="deliveryStreamName",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        separator="separator"
                                    ),
                                    iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                        input_name="inputName",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                        property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                            value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                                boolean_value="booleanValue",
                                                double_value="doubleValue",
                                                integer_value="integerValue",
                                                string_value="stringValue"
                                            ),
            
                                            # the properties below are optional
                                            quality="quality",
                                            timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                                time_in_seconds="timeInSeconds",
            
                                                # the properties below are optional
                                                offset_in_nanos="offsetInNanos"
                                            )
                                        ),
            
                                        # the properties below are optional
                                        asset_id="assetId",
                                        entry_id="entryId",
                                        property_alias="propertyAlias",
                                        property_id="propertyId"
                                    ),
                                    iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                        mqtt_topic="mqttTopic",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                        function_arn="functionArn",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                        timer_name="timerName",
            
                                        # the properties below are optional
                                        duration_expression="durationExpression",
                                        seconds=123
                                    ),
                                    set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                        value="value",
                                        variable_name="variableName"
                                    ),
                                    sns=iotevents.CfnDetectorModel.SnsProperty(
                                        target_arn="targetArn",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    sqs=iotevents.CfnDetectorModel.SqsProperty(
                                        queue_url="queueUrl",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        use_base64=False
                                    )
                                )],
                                condition="condition"
                            )],
                            transition_events=[iotevents.CfnDetectorModel.TransitionEventProperty(
                                condition="condition",
                                event_name="eventName",
                                next_state="nextState",
            
                                # the properties below are optional
                                actions=[iotevents.CfnDetectorModel.ActionProperty(
                                    clear_timer=iotevents.CfnDetectorModel.ClearTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    dynamo_db=iotevents.CfnDetectorModel.DynamoDBProperty(
                                        hash_key_field="hashKeyField",
                                        hash_key_value="hashKeyValue",
                                        table_name="tableName",
            
                                        # the properties below are optional
                                        hash_key_type="hashKeyType",
                                        operation="operation",
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        payload_field="payloadField",
                                        range_key_field="rangeKeyField",
                                        range_key_type="rangeKeyType",
                                        range_key_value="rangeKeyValue"
                                    ),
                                    dynamo_dBv2=iotevents.CfnDetectorModel.DynamoDBv2Property(
                                        table_name="tableName",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    firehose=iotevents.CfnDetectorModel.FirehoseProperty(
                                        delivery_stream_name="deliveryStreamName",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        separator="separator"
                                    ),
                                    iot_events=iotevents.CfnDetectorModel.IotEventsProperty(
                                        input_name="inputName",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    iot_site_wise=iotevents.CfnDetectorModel.IotSiteWiseProperty(
                                        property_value=iotevents.CfnDetectorModel.AssetPropertyValueProperty(
                                            value=iotevents.CfnDetectorModel.AssetPropertyVariantProperty(
                                                boolean_value="booleanValue",
                                                double_value="doubleValue",
                                                integer_value="integerValue",
                                                string_value="stringValue"
                                            ),
            
                                            # the properties below are optional
                                            quality="quality",
                                            timestamp=iotevents.CfnDetectorModel.AssetPropertyTimestampProperty(
                                                time_in_seconds="timeInSeconds",
            
                                                # the properties below are optional
                                                offset_in_nanos="offsetInNanos"
                                            )
                                        ),
            
                                        # the properties below are optional
                                        asset_id="assetId",
                                        entry_id="entryId",
                                        property_alias="propertyAlias",
                                        property_id="propertyId"
                                    ),
                                    iot_topic_publish=iotevents.CfnDetectorModel.IotTopicPublishProperty(
                                        mqtt_topic="mqttTopic",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    lambda_=iotevents.CfnDetectorModel.LambdaProperty(
                                        function_arn="functionArn",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    reset_timer=iotevents.CfnDetectorModel.ResetTimerProperty(
                                        timer_name="timerName"
                                    ),
                                    set_timer=iotevents.CfnDetectorModel.SetTimerProperty(
                                        timer_name="timerName",
            
                                        # the properties below are optional
                                        duration_expression="durationExpression",
                                        seconds=123
                                    ),
                                    set_variable=iotevents.CfnDetectorModel.SetVariableProperty(
                                        value="value",
                                        variable_name="variableName"
                                    ),
                                    sns=iotevents.CfnDetectorModel.SnsProperty(
                                        target_arn="targetArn",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        )
                                    ),
                                    sqs=iotevents.CfnDetectorModel.SqsProperty(
                                        queue_url="queueUrl",
            
                                        # the properties below are optional
                                        payload=iotevents.CfnDetectorModel.PayloadProperty(
                                            content_expression="contentExpression",
                                            type="type"
                                        ),
                                        use_base64=False
                                    )
                                )]
                            )]
                        )
                    )]
                ),
                role_arn="roleArn",
            
                # the properties below are optional
                detector_model_description="detectorModelDescription",
                detector_model_name="detectorModelName",
                evaluation_method="evaluationMethod",
                key="key",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "detector_model_definition": detector_model_definition,
            "role_arn": role_arn,
        }
        if detector_model_description is not None:
            self._values["detector_model_description"] = detector_model_description
        if detector_model_name is not None:
            self._values["detector_model_name"] = detector_model_name
        if evaluation_method is not None:
            self._values["evaluation_method"] = evaluation_method
        if key is not None:
            self._values["key"] = key
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def detector_model_definition(
        self,
    ) -> typing.Union[CfnDetectorModel.DetectorModelDefinitionProperty, _IResolvable_da3f097b]:
        '''Information that defines how a detector operates.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html#cfn-iotevents-detectormodel-detectormodeldefinition
        '''
        result = self._values.get("detector_model_definition")
        assert result is not None, "Required property 'detector_model_definition' is missing"
        return typing.cast(typing.Union[CfnDetectorModel.DetectorModelDefinitionProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def role_arn(self) -> builtins.str:
        '''The ARN of the role that grants permission to AWS IoT Events to perform its operations.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html#cfn-iotevents-detectormodel-rolearn
        '''
        result = self._values.get("role_arn")
        assert result is not None, "Required property 'role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def detector_model_description(self) -> typing.Optional[builtins.str]:
        '''A brief description of the detector model.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html#cfn-iotevents-detectormodel-detectormodeldescription
        '''
        result = self._values.get("detector_model_description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def detector_model_name(self) -> typing.Optional[builtins.str]:
        '''The name of the detector model.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html#cfn-iotevents-detectormodel-detectormodelname
        '''
        result = self._values.get("detector_model_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def evaluation_method(self) -> typing.Optional[builtins.str]:
        '''Information about the order in which events are evaluated and how actions are executed.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html#cfn-iotevents-detectormodel-evaluationmethod
        '''
        result = self._values.get("evaluation_method")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''The value used to identify a detector instance.

        When a device or system sends input, a new detector instance with a unique key value is created. AWS IoT Events can continue to route input to its corresponding detector instance based on this identifying information.

        This parameter uses a JSON-path expression to select the attribute-value pair in the message payload that is used for identification. To route the message to the correct detector instance, the device must send a message payload that contains the same attribute-value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html#cfn-iotevents-detectormodel-key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-detectormodel.html#cfn-iotevents-detectormodel-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDetectorModelProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnInput(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iotevents.CfnInput",
):
    '''A CloudFormation ``AWS::IoTEvents::Input``.

    The AWS::IoTEvents::Input resource creates an input. To monitor your devices and processes, they must have a way to get telemetry data into AWS IoT Events . This is done by sending messages as *inputs* to AWS IoT Events . For more information, see `How to Use AWS IoT Events <https://docs.aws.amazon.com/iotevents/latest/developerguide/how-to-use-iotevents.html>`_ in the *AWS IoT Events Developer Guide* .

    :cloudformationResource: AWS::IoTEvents::Input
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-input.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iotevents as iotevents
        
        cfn_input = iotevents.CfnInput(self, "MyCfnInput",
            input_definition=iotevents.CfnInput.InputDefinitionProperty(
                attributes=[iotevents.CfnInput.AttributeProperty(
                    json_path="jsonPath"
                )]
            ),
        
            # the properties below are optional
            input_description="inputDescription",
            input_name="inputName",
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
        input_definition: typing.Union["CfnInput.InputDefinitionProperty", _IResolvable_da3f097b],
        input_description: typing.Optional[builtins.str] = None,
        input_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::IoTEvents::Input``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param input_definition: The definition of the input.
        :param input_description: A brief description of the input.
        :param input_name: The name of the input.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnInputProps(
            input_definition=input_definition,
            input_description=input_description,
            input_name=input_name,
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
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-input.html#cfn-iotevents-input-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="inputDefinition")
    def input_definition(
        self,
    ) -> typing.Union["CfnInput.InputDefinitionProperty", _IResolvable_da3f097b]:
        '''The definition of the input.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-input.html#cfn-iotevents-input-inputdefinition
        '''
        return typing.cast(typing.Union["CfnInput.InputDefinitionProperty", _IResolvable_da3f097b], jsii.get(self, "inputDefinition"))

    @input_definition.setter
    def input_definition(
        self,
        value: typing.Union["CfnInput.InputDefinitionProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "inputDefinition", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="inputDescription")
    def input_description(self) -> typing.Optional[builtins.str]:
        '''A brief description of the input.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-input.html#cfn-iotevents-input-inputdescription
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "inputDescription"))

    @input_description.setter
    def input_description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "inputDescription", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="inputName")
    def input_name(self) -> typing.Optional[builtins.str]:
        '''The name of the input.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-input.html#cfn-iotevents-input-inputname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "inputName"))

    @input_name.setter
    def input_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "inputName", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnInput.AttributeProperty",
        jsii_struct_bases=[],
        name_mapping={"json_path": "jsonPath"},
    )
    class AttributeProperty:
        def __init__(self, *, json_path: builtins.str) -> None:
            '''The attributes from the JSON payload that are made available by the input.

            Inputs are derived from messages sent to the AWS IoT Events system using ``BatchPutMessage`` . Each such message contains a JSON payload. Those attributes (and their paired values) specified here are available for use in the ``condition`` expressions used by detectors.

            :param json_path: An expression that specifies an attribute-value pair in a JSON structure. Use this to specify an attribute from the JSON payload that is made available by the input. Inputs are derived from messages sent to AWS IoT Events ( ``BatchPutMessage`` ). Each such message contains a JSON payload. The attribute (and its paired value) specified here are available for use in the ``condition`` expressions used by detectors. Syntax: ``<field-name>.<field-name>...``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-input-attribute.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                attribute_property = iotevents.CfnInput.AttributeProperty(
                    json_path="jsonPath"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "json_path": json_path,
            }

        @builtins.property
        def json_path(self) -> builtins.str:
            '''An expression that specifies an attribute-value pair in a JSON structure.

            Use this to specify an attribute from the JSON payload that is made available by the input. Inputs are derived from messages sent to AWS IoT Events ( ``BatchPutMessage`` ). Each such message contains a JSON payload. The attribute (and its paired value) specified here are available for use in the ``condition`` expressions used by detectors.

            Syntax: ``<field-name>.<field-name>...``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-input-attribute.html#cfn-iotevents-input-attribute-jsonpath
            '''
            result = self._values.get("json_path")
            assert result is not None, "Required property 'json_path' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AttributeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iotevents.CfnInput.InputDefinitionProperty",
        jsii_struct_bases=[],
        name_mapping={"attributes": "attributes"},
    )
    class InputDefinitionProperty:
        def __init__(
            self,
            *,
            attributes: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnInput.AttributeProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''The definition of the input.

            :param attributes: The attributes from the JSON payload that are made available by the input. Inputs are derived from messages sent to the AWS IoT Events system using ``BatchPutMessage`` . Each such message contains a JSON payload, and those attributes (and their paired values) specified here are available for use in the ``condition`` expressions used by detectors that monitor this input.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-input-inputdefinition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iotevents as iotevents
                
                input_definition_property = iotevents.CfnInput.InputDefinitionProperty(
                    attributes=[iotevents.CfnInput.AttributeProperty(
                        json_path="jsonPath"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "attributes": attributes,
            }

        @builtins.property
        def attributes(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInput.AttributeProperty", _IResolvable_da3f097b]]]:
            '''The attributes from the JSON payload that are made available by the input.

            Inputs are derived from messages sent to the AWS IoT Events system using ``BatchPutMessage`` . Each such message contains a JSON payload, and those attributes (and their paired values) specified here are available for use in the ``condition`` expressions used by detectors that monitor this input.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iotevents-input-inputdefinition.html#cfn-iotevents-input-inputdefinition-attributes
            '''
            result = self._values.get("attributes")
            assert result is not None, "Required property 'attributes' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInput.AttributeProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InputDefinitionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iotevents.CfnInputProps",
    jsii_struct_bases=[],
    name_mapping={
        "input_definition": "inputDefinition",
        "input_description": "inputDescription",
        "input_name": "inputName",
        "tags": "tags",
    },
)
class CfnInputProps:
    def __init__(
        self,
        *,
        input_definition: typing.Union[CfnInput.InputDefinitionProperty, _IResolvable_da3f097b],
        input_description: typing.Optional[builtins.str] = None,
        input_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnInput``.

        :param input_definition: The definition of the input.
        :param input_description: A brief description of the input.
        :param input_name: The name of the input.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-input.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iotevents as iotevents
            
            cfn_input_props = iotevents.CfnInputProps(
                input_definition=iotevents.CfnInput.InputDefinitionProperty(
                    attributes=[iotevents.CfnInput.AttributeProperty(
                        json_path="jsonPath"
                    )]
                ),
            
                # the properties below are optional
                input_description="inputDescription",
                input_name="inputName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "input_definition": input_definition,
        }
        if input_description is not None:
            self._values["input_description"] = input_description
        if input_name is not None:
            self._values["input_name"] = input_name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def input_definition(
        self,
    ) -> typing.Union[CfnInput.InputDefinitionProperty, _IResolvable_da3f097b]:
        '''The definition of the input.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-input.html#cfn-iotevents-input-inputdefinition
        '''
        result = self._values.get("input_definition")
        assert result is not None, "Required property 'input_definition' is missing"
        return typing.cast(typing.Union[CfnInput.InputDefinitionProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def input_description(self) -> typing.Optional[builtins.str]:
        '''A brief description of the input.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-input.html#cfn-iotevents-input-inputdescription
        '''
        result = self._values.get("input_description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def input_name(self) -> typing.Optional[builtins.str]:
        '''The name of the input.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-input.html#cfn-iotevents-input-inputname
        '''
        result = self._values.get("input_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iotevents-input.html#cfn-iotevents-input-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnInputProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnDetectorModel",
    "CfnDetectorModelProps",
    "CfnInput",
    "CfnInputProps",
]

publication.publish()
