'''
# AWS::CE Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_ce as ce
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-ce-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::CE](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_CE.html).

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
class CfnAnomalyMonitor(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ce.CfnAnomalyMonitor",
):
    '''A CloudFormation ``AWS::CE::AnomalyMonitor``.

    The ``AWS::CE::AnomalyMonitor`` resource is a Cost Explorer resource type that continuously inspects your account's cost data for anomalies, based on ``MonitorType`` and ``MonitorSpecification`` . The content consists of detailed metadata and the current status of the monitor object.

    :cloudformationResource: AWS::CE::AnomalyMonitor
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalymonitor.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_ce as ce
        
        cfn_anomaly_monitor = ce.CfnAnomalyMonitor(self, "MyCfnAnomalyMonitor",
            monitor_name="monitorName",
            monitor_type="monitorType",
        
            # the properties below are optional
            monitor_dimension="monitorDimension",
            monitor_specification="monitorSpecification"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        monitor_name: builtins.str,
        monitor_type: builtins.str,
        monitor_dimension: typing.Optional[builtins.str] = None,
        monitor_specification: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::CE::AnomalyMonitor``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param monitor_name: The name of the monitor.
        :param monitor_type: The possible type values.
        :param monitor_dimension: The dimensions to evaluate.
        :param monitor_specification: The array of ``MonitorSpecification`` in JSON array format. For instance, you can use ``MonitorSpecification`` to specify a tag, Cost Category, or linked account for your custom anomaly monitor. For further information, see the `Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalymonitor.html#aws-resource-ce-anomalymonitor--examples>`_ section of this page.
        '''
        props = CfnAnomalyMonitorProps(
            monitor_name=monitor_name,
            monitor_type=monitor_type,
            monitor_dimension=monitor_dimension,
            monitor_specification=monitor_specification,
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
    @jsii.member(jsii_name="attrCreationDate")
    def attr_creation_date(self) -> builtins.str:
        '''The date when the monitor was created.

        :cloudformationAttribute: CreationDate
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreationDate"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDimensionalValueCount")
    def attr_dimensional_value_count(self) -> jsii.Number:
        '''The value for evaluated dimensions.

        :cloudformationAttribute: DimensionalValueCount
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrDimensionalValueCount"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLastEvaluatedDate")
    def attr_last_evaluated_date(self) -> builtins.str:
        '''The date when the monitor last evaluated for anomalies.

        :cloudformationAttribute: LastEvaluatedDate
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLastEvaluatedDate"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLastUpdatedDate")
    def attr_last_updated_date(self) -> builtins.str:
        '''The date when the monitor was last updated.

        :cloudformationAttribute: LastUpdatedDate
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLastUpdatedDate"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrMonitorArn")
    def attr_monitor_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) value for the monitor.

        :cloudformationAttribute: MonitorArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrMonitorArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="monitorName")
    def monitor_name(self) -> builtins.str:
        '''The name of the monitor.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalymonitor.html#cfn-ce-anomalymonitor-monitorname
        '''
        return typing.cast(builtins.str, jsii.get(self, "monitorName"))

    @monitor_name.setter
    def monitor_name(self, value: builtins.str) -> None:
        jsii.set(self, "monitorName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="monitorType")
    def monitor_type(self) -> builtins.str:
        '''The possible type values.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalymonitor.html#cfn-ce-anomalymonitor-monitortype
        '''
        return typing.cast(builtins.str, jsii.get(self, "monitorType"))

    @monitor_type.setter
    def monitor_type(self, value: builtins.str) -> None:
        jsii.set(self, "monitorType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="monitorDimension")
    def monitor_dimension(self) -> typing.Optional[builtins.str]:
        '''The dimensions to evaluate.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalymonitor.html#cfn-ce-anomalymonitor-monitordimension
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "monitorDimension"))

    @monitor_dimension.setter
    def monitor_dimension(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "monitorDimension", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="monitorSpecification")
    def monitor_specification(self) -> typing.Optional[builtins.str]:
        '''The array of ``MonitorSpecification`` in JSON array format.

        For instance, you can use ``MonitorSpecification`` to specify a tag, Cost Category, or linked account for your custom anomaly monitor. For further information, see the `Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalymonitor.html#aws-resource-ce-anomalymonitor--examples>`_ section of this page.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalymonitor.html#cfn-ce-anomalymonitor-monitorspecification
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "monitorSpecification"))

    @monitor_specification.setter
    def monitor_specification(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "monitorSpecification", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ce.CfnAnomalyMonitorProps",
    jsii_struct_bases=[],
    name_mapping={
        "monitor_name": "monitorName",
        "monitor_type": "monitorType",
        "monitor_dimension": "monitorDimension",
        "monitor_specification": "monitorSpecification",
    },
)
class CfnAnomalyMonitorProps:
    def __init__(
        self,
        *,
        monitor_name: builtins.str,
        monitor_type: builtins.str,
        monitor_dimension: typing.Optional[builtins.str] = None,
        monitor_specification: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnAnomalyMonitor``.

        :param monitor_name: The name of the monitor.
        :param monitor_type: The possible type values.
        :param monitor_dimension: The dimensions to evaluate.
        :param monitor_specification: The array of ``MonitorSpecification`` in JSON array format. For instance, you can use ``MonitorSpecification`` to specify a tag, Cost Category, or linked account for your custom anomaly monitor. For further information, see the `Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalymonitor.html#aws-resource-ce-anomalymonitor--examples>`_ section of this page.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalymonitor.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ce as ce
            
            cfn_anomaly_monitor_props = ce.CfnAnomalyMonitorProps(
                monitor_name="monitorName",
                monitor_type="monitorType",
            
                # the properties below are optional
                monitor_dimension="monitorDimension",
                monitor_specification="monitorSpecification"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "monitor_name": monitor_name,
            "monitor_type": monitor_type,
        }
        if monitor_dimension is not None:
            self._values["monitor_dimension"] = monitor_dimension
        if monitor_specification is not None:
            self._values["monitor_specification"] = monitor_specification

    @builtins.property
    def monitor_name(self) -> builtins.str:
        '''The name of the monitor.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalymonitor.html#cfn-ce-anomalymonitor-monitorname
        '''
        result = self._values.get("monitor_name")
        assert result is not None, "Required property 'monitor_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def monitor_type(self) -> builtins.str:
        '''The possible type values.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalymonitor.html#cfn-ce-anomalymonitor-monitortype
        '''
        result = self._values.get("monitor_type")
        assert result is not None, "Required property 'monitor_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def monitor_dimension(self) -> typing.Optional[builtins.str]:
        '''The dimensions to evaluate.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalymonitor.html#cfn-ce-anomalymonitor-monitordimension
        '''
        result = self._values.get("monitor_dimension")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def monitor_specification(self) -> typing.Optional[builtins.str]:
        '''The array of ``MonitorSpecification`` in JSON array format.

        For instance, you can use ``MonitorSpecification`` to specify a tag, Cost Category, or linked account for your custom anomaly monitor. For further information, see the `Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalymonitor.html#aws-resource-ce-anomalymonitor--examples>`_ section of this page.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalymonitor.html#cfn-ce-anomalymonitor-monitorspecification
        '''
        result = self._values.get("monitor_specification")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAnomalyMonitorProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnAnomalySubscription(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ce.CfnAnomalySubscription",
):
    '''A CloudFormation ``AWS::CE::AnomalySubscription``.

    The ``AWS::CE::AnomalySubscription`` resource is a Cost Explorer resource type that associates a monitor, threshold, and list of subscribers. It delivers notifications about anomalies detected by a monitor that exceeds a threshold. The content consists of the detailed metadata and the current status of the ``AnomalySubscription`` object.

    :cloudformationResource: AWS::CE::AnomalySubscription
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalysubscription.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_ce as ce
        
        cfn_anomaly_subscription = ce.CfnAnomalySubscription(self, "MyCfnAnomalySubscription",
            frequency="frequency",
            monitor_arn_list=["monitorArnList"],
            subscribers=[ce.CfnAnomalySubscription.SubscriberProperty(
                address="address",
                type="type",
        
                # the properties below are optional
                status="status"
            )],
            subscription_name="subscriptionName",
            threshold=123
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        frequency: builtins.str,
        monitor_arn_list: typing.Sequence[builtins.str],
        subscribers: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnAnomalySubscription.SubscriberProperty", _IResolvable_da3f097b]]],
        subscription_name: builtins.str,
        threshold: jsii.Number,
    ) -> None:
        '''Create a new ``AWS::CE::AnomalySubscription``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param frequency: The frequency that anomaly reports are sent over email.
        :param monitor_arn_list: A list of cost anomaly monitors.
        :param subscribers: A list of subscribers to notify.
        :param subscription_name: The name for the subscription.
        :param threshold: The dollar value that triggers a notification if the threshold is exceeded.
        '''
        props = CfnAnomalySubscriptionProps(
            frequency=frequency,
            monitor_arn_list=monitor_arn_list,
            subscribers=subscribers,
            subscription_name=subscription_name,
            threshold=threshold,
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
    @jsii.member(jsii_name="attrAccountId")
    def attr_account_id(self) -> builtins.str:
        '''Your unique account identifier.

        :cloudformationAttribute: AccountId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAccountId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSubscriptionArn")
    def attr_subscription_arn(self) -> builtins.str:
        '''The ``AnomalySubscription`` Amazon Resource Name (ARN).

        :cloudformationAttribute: SubscriptionArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSubscriptionArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="frequency")
    def frequency(self) -> builtins.str:
        '''The frequency that anomaly reports are sent over email.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalysubscription.html#cfn-ce-anomalysubscription-frequency
        '''
        return typing.cast(builtins.str, jsii.get(self, "frequency"))

    @frequency.setter
    def frequency(self, value: builtins.str) -> None:
        jsii.set(self, "frequency", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="monitorArnList")
    def monitor_arn_list(self) -> typing.List[builtins.str]:
        '''A list of cost anomaly monitors.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalysubscription.html#cfn-ce-anomalysubscription-monitorarnlist
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "monitorArnList"))

    @monitor_arn_list.setter
    def monitor_arn_list(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "monitorArnList", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subscribers")
    def subscribers(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnomalySubscription.SubscriberProperty", _IResolvable_da3f097b]]]:
        '''A list of subscribers to notify.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalysubscription.html#cfn-ce-anomalysubscription-subscribers
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnomalySubscription.SubscriberProperty", _IResolvable_da3f097b]]], jsii.get(self, "subscribers"))

    @subscribers.setter
    def subscribers(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnomalySubscription.SubscriberProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "subscribers", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subscriptionName")
    def subscription_name(self) -> builtins.str:
        '''The name for the subscription.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalysubscription.html#cfn-ce-anomalysubscription-subscriptionname
        '''
        return typing.cast(builtins.str, jsii.get(self, "subscriptionName"))

    @subscription_name.setter
    def subscription_name(self, value: builtins.str) -> None:
        jsii.set(self, "subscriptionName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="threshold")
    def threshold(self) -> jsii.Number:
        '''The dollar value that triggers a notification if the threshold is exceeded.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalysubscription.html#cfn-ce-anomalysubscription-threshold
        '''
        return typing.cast(jsii.Number, jsii.get(self, "threshold"))

    @threshold.setter
    def threshold(self, value: jsii.Number) -> None:
        jsii.set(self, "threshold", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_ce.CfnAnomalySubscription.SubscriberProperty",
        jsii_struct_bases=[],
        name_mapping={"address": "address", "type": "type", "status": "status"},
    )
    class SubscriberProperty:
        def __init__(
            self,
            *,
            address: builtins.str,
            type: builtins.str,
            status: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The recipient of ``AnomalySubscription`` notifications.

            :param address: The email address or SNS Topic Amazon Resource Name (ARN), depending on the ``Type`` .
            :param type: The notification delivery channel.
            :param status: Indicates if the subscriber accepts the notifications.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ce-anomalysubscription-subscriber.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_ce as ce
                
                subscriber_property = ce.CfnAnomalySubscription.SubscriberProperty(
                    address="address",
                    type="type",
                
                    # the properties below are optional
                    status="status"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "address": address,
                "type": type,
            }
            if status is not None:
                self._values["status"] = status

        @builtins.property
        def address(self) -> builtins.str:
            '''The email address or SNS Topic Amazon Resource Name (ARN), depending on the ``Type`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ce-anomalysubscription-subscriber.html#cfn-ce-anomalysubscription-subscriber-address
            '''
            result = self._values.get("address")
            assert result is not None, "Required property 'address' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def type(self) -> builtins.str:
            '''The notification delivery channel.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ce-anomalysubscription-subscriber.html#cfn-ce-anomalysubscription-subscriber-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def status(self) -> typing.Optional[builtins.str]:
            '''Indicates if the subscriber accepts the notifications.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ce-anomalysubscription-subscriber.html#cfn-ce-anomalysubscription-subscriber-status
            '''
            result = self._values.get("status")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SubscriberProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ce.CfnAnomalySubscriptionProps",
    jsii_struct_bases=[],
    name_mapping={
        "frequency": "frequency",
        "monitor_arn_list": "monitorArnList",
        "subscribers": "subscribers",
        "subscription_name": "subscriptionName",
        "threshold": "threshold",
    },
)
class CfnAnomalySubscriptionProps:
    def __init__(
        self,
        *,
        frequency: builtins.str,
        monitor_arn_list: typing.Sequence[builtins.str],
        subscribers: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnAnomalySubscription.SubscriberProperty, _IResolvable_da3f097b]]],
        subscription_name: builtins.str,
        threshold: jsii.Number,
    ) -> None:
        '''Properties for defining a ``CfnAnomalySubscription``.

        :param frequency: The frequency that anomaly reports are sent over email.
        :param monitor_arn_list: A list of cost anomaly monitors.
        :param subscribers: A list of subscribers to notify.
        :param subscription_name: The name for the subscription.
        :param threshold: The dollar value that triggers a notification if the threshold is exceeded.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalysubscription.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ce as ce
            
            cfn_anomaly_subscription_props = ce.CfnAnomalySubscriptionProps(
                frequency="frequency",
                monitor_arn_list=["monitorArnList"],
                subscribers=[ce.CfnAnomalySubscription.SubscriberProperty(
                    address="address",
                    type="type",
            
                    # the properties below are optional
                    status="status"
                )],
                subscription_name="subscriptionName",
                threshold=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "frequency": frequency,
            "monitor_arn_list": monitor_arn_list,
            "subscribers": subscribers,
            "subscription_name": subscription_name,
            "threshold": threshold,
        }

    @builtins.property
    def frequency(self) -> builtins.str:
        '''The frequency that anomaly reports are sent over email.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalysubscription.html#cfn-ce-anomalysubscription-frequency
        '''
        result = self._values.get("frequency")
        assert result is not None, "Required property 'frequency' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def monitor_arn_list(self) -> typing.List[builtins.str]:
        '''A list of cost anomaly monitors.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalysubscription.html#cfn-ce-anomalysubscription-monitorarnlist
        '''
        result = self._values.get("monitor_arn_list")
        assert result is not None, "Required property 'monitor_arn_list' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def subscribers(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnAnomalySubscription.SubscriberProperty, _IResolvable_da3f097b]]]:
        '''A list of subscribers to notify.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalysubscription.html#cfn-ce-anomalysubscription-subscribers
        '''
        result = self._values.get("subscribers")
        assert result is not None, "Required property 'subscribers' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnAnomalySubscription.SubscriberProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def subscription_name(self) -> builtins.str:
        '''The name for the subscription.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalysubscription.html#cfn-ce-anomalysubscription-subscriptionname
        '''
        result = self._values.get("subscription_name")
        assert result is not None, "Required property 'subscription_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def threshold(self) -> jsii.Number:
        '''The dollar value that triggers a notification if the threshold is exceeded.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-anomalysubscription.html#cfn-ce-anomalysubscription-threshold
        '''
        result = self._values.get("threshold")
        assert result is not None, "Required property 'threshold' is missing"
        return typing.cast(jsii.Number, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAnomalySubscriptionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnCostCategory(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ce.CfnCostCategory",
):
    '''A CloudFormation ``AWS::CE::CostCategory``.

    The ``AWS::CE::CostCategory`` resource creates groupings of cost that you can use across products in the AWS Billing and Cost Management console, such as Cost Explorer and AWS Budgets. For more information, see `Managing Your Costs with Cost Categories <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/manage-cost-categories.html>`_ in the *AWS Billing and Cost Management User Guide* .

    :cloudformationResource: AWS::CE::CostCategory
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-costcategory.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_ce as ce
        
        cfn_cost_category = ce.CfnCostCategory(self, "MyCfnCostCategory",
            name="name",
            rules="rules",
            rule_version="ruleVersion",
        
            # the properties below are optional
            default_value="defaultValue",
            split_charge_rules="splitChargeRules"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        rules: builtins.str,
        rule_version: builtins.str,
        default_value: typing.Optional[builtins.str] = None,
        split_charge_rules: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::CE::CostCategory``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The unique name of the Cost Category.
        :param rules: The array of CostCategoryRule in JSON array format. .. epigraph:: Rules are processed in order. If there are multiple rules that match the line item, then the first rule to match is used to determine that Cost Category value.
        :param rule_version: The rule schema version in this particular Cost Category.
        :param default_value: The default value for the cost category.
        :param split_charge_rules: The split charge rules that are used to allocate your charges between your Cost Category values.
        '''
        props = CfnCostCategoryProps(
            name=name,
            rules=rules,
            rule_version=rule_version,
            default_value=default_value,
            split_charge_rules=split_charge_rules,
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
        '''The unique identifier for your Cost Category.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrEffectiveStart")
    def attr_effective_start(self) -> builtins.str:
        '''The Cost Category's effective start date.

        :cloudformationAttribute: EffectiveStart
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrEffectiveStart"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The unique name of the Cost Category.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-costcategory.html#cfn-ce-costcategory-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="rules")
    def rules(self) -> builtins.str:
        '''The array of CostCategoryRule in JSON array format.

        .. epigraph::

           Rules are processed in order. If there are multiple rules that match the line item, then the first rule to match is used to determine that Cost Category value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-costcategory.html#cfn-ce-costcategory-rules
        '''
        return typing.cast(builtins.str, jsii.get(self, "rules"))

    @rules.setter
    def rules(self, value: builtins.str) -> None:
        jsii.set(self, "rules", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ruleVersion")
    def rule_version(self) -> builtins.str:
        '''The rule schema version in this particular Cost Category.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-costcategory.html#cfn-ce-costcategory-ruleversion
        '''
        return typing.cast(builtins.str, jsii.get(self, "ruleVersion"))

    @rule_version.setter
    def rule_version(self, value: builtins.str) -> None:
        jsii.set(self, "ruleVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultValue")
    def default_value(self) -> typing.Optional[builtins.str]:
        '''The default value for the cost category.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-costcategory.html#cfn-ce-costcategory-defaultvalue
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "defaultValue"))

    @default_value.setter
    def default_value(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "defaultValue", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="splitChargeRules")
    def split_charge_rules(self) -> typing.Optional[builtins.str]:
        '''The split charge rules that are used to allocate your charges between your Cost Category values.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-costcategory.html#cfn-ce-costcategory-splitchargerules
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "splitChargeRules"))

    @split_charge_rules.setter
    def split_charge_rules(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "splitChargeRules", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ce.CfnCostCategoryProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "rules": "rules",
        "rule_version": "ruleVersion",
        "default_value": "defaultValue",
        "split_charge_rules": "splitChargeRules",
    },
)
class CfnCostCategoryProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        rules: builtins.str,
        rule_version: builtins.str,
        default_value: typing.Optional[builtins.str] = None,
        split_charge_rules: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnCostCategory``.

        :param name: The unique name of the Cost Category.
        :param rules: The array of CostCategoryRule in JSON array format. .. epigraph:: Rules are processed in order. If there are multiple rules that match the line item, then the first rule to match is used to determine that Cost Category value.
        :param rule_version: The rule schema version in this particular Cost Category.
        :param default_value: The default value for the cost category.
        :param split_charge_rules: The split charge rules that are used to allocate your charges between your Cost Category values.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-costcategory.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ce as ce
            
            cfn_cost_category_props = ce.CfnCostCategoryProps(
                name="name",
                rules="rules",
                rule_version="ruleVersion",
            
                # the properties below are optional
                default_value="defaultValue",
                split_charge_rules="splitChargeRules"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
            "rules": rules,
            "rule_version": rule_version,
        }
        if default_value is not None:
            self._values["default_value"] = default_value
        if split_charge_rules is not None:
            self._values["split_charge_rules"] = split_charge_rules

    @builtins.property
    def name(self) -> builtins.str:
        '''The unique name of the Cost Category.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-costcategory.html#cfn-ce-costcategory-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def rules(self) -> builtins.str:
        '''The array of CostCategoryRule in JSON array format.

        .. epigraph::

           Rules are processed in order. If there are multiple rules that match the line item, then the first rule to match is used to determine that Cost Category value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-costcategory.html#cfn-ce-costcategory-rules
        '''
        result = self._values.get("rules")
        assert result is not None, "Required property 'rules' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def rule_version(self) -> builtins.str:
        '''The rule schema version in this particular Cost Category.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-costcategory.html#cfn-ce-costcategory-ruleversion
        '''
        result = self._values.get("rule_version")
        assert result is not None, "Required property 'rule_version' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def default_value(self) -> typing.Optional[builtins.str]:
        '''The default value for the cost category.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-costcategory.html#cfn-ce-costcategory-defaultvalue
        '''
        result = self._values.get("default_value")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def split_charge_rules(self) -> typing.Optional[builtins.str]:
        '''The split charge rules that are used to allocate your charges between your Cost Category values.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ce-costcategory.html#cfn-ce-costcategory-splitchargerules
        '''
        result = self._values.get("split_charge_rules")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnCostCategoryProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnAnomalyMonitor",
    "CfnAnomalyMonitorProps",
    "CfnAnomalySubscription",
    "CfnAnomalySubscriptionProps",
    "CfnCostCategory",
    "CfnCostCategoryProps",
]

publication.publish()
