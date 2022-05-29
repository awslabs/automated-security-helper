'''
# AWS::MediaConvert Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_mediaconvert as mediaconvert
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-mediaconvert-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::MediaConvert](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_MediaConvert.html).

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
class CfnJobTemplate(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_mediaconvert.CfnJobTemplate",
):
    '''A CloudFormation ``AWS::MediaConvert::JobTemplate``.

    The AWS::MediaConvert::JobTemplate resource is an AWS Elemental MediaConvert resource type that you can use to generate transcoding jobs.

    When you declare this entity in your AWS CloudFormation template, you pass in your transcoding job settings in JSON or YAML format. This settings specification must be formed in a particular way that conforms to AWS Elemental MediaConvert job validation. For more information about creating a job template model for the ``SettingsJson`` property, see the Remarks section later in this topic.

    For information about job templates, see `Working with AWS Elemental MediaConvert Job Templates <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-job-templates.html>`_ in the ** .

    :cloudformationResource: AWS::MediaConvert::JobTemplate
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_mediaconvert as mediaconvert
        
        # settings_json: Any
        # tags: Any
        
        cfn_job_template = mediaconvert.CfnJobTemplate(self, "MyCfnJobTemplate",
            settings_json=settings_json,
        
            # the properties below are optional
            acceleration_settings=mediaconvert.CfnJobTemplate.AccelerationSettingsProperty(
                mode="mode"
            ),
            category="category",
            description="description",
            hop_destinations=[mediaconvert.CfnJobTemplate.HopDestinationProperty(
                priority=123,
                queue="queue",
                wait_minutes=123
            )],
            name="name",
            priority=123,
            queue="queue",
            status_update_interval="statusUpdateInterval",
            tags=tags
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        settings_json: typing.Any,
        acceleration_settings: typing.Optional[typing.Union["CfnJobTemplate.AccelerationSettingsProperty", _IResolvable_da3f097b]] = None,
        category: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        hop_destinations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnJobTemplate.HopDestinationProperty", _IResolvable_da3f097b]]]] = None,
        name: typing.Optional[builtins.str] = None,
        priority: typing.Optional[jsii.Number] = None,
        queue: typing.Optional[builtins.str] = None,
        status_update_interval: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::MediaConvert::JobTemplate``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param settings_json: Specify, in JSON format, the transcoding job settings for this job template. This specification must conform to the AWS Elemental MediaConvert job validation. For information about forming this specification, see the Remarks section later in this topic. For more information about MediaConvert job templates, see `Working with AWS Elemental MediaConvert Job Templates <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-job-templates.html>`_ in the ** .
        :param acceleration_settings: Accelerated transcoding can significantly speed up jobs with long, visually complex content. Outputs that use this feature incur pro-tier pricing. For information about feature limitations, For more information, see `Job Limitations for Accelerated Transcoding in AWS Elemental MediaConvert <https://docs.aws.amazon.com/mediaconvert/latest/ug/job-requirements.html>`_ in the *AWS Elemental MediaConvert User Guide* .
        :param category: Optional. A category for the job template you are creating
        :param description: Optional. A description of the job template you are creating.
        :param hop_destinations: Optional. Configuration for a destination queue to which the job can hop once a customer-defined minimum wait time has passed. For more information, see `Setting Up Queue Hopping to Avoid Long Waits <https://docs.aws.amazon.com/mediaconvert/latest/ug/setting-up-queue-hopping-to-avoid-long-waits.html>`_ in the *AWS Elemental MediaConvert User Guide* .
        :param name: The name of the job template you are creating.
        :param priority: Specify the relative priority for this job. In any given queue, the service begins processing the job with the highest value first. When more than one job has the same priority, the service begins processing the job that you submitted first. If you don't specify a priority, the service uses the default value 0. Minimum: -50 Maximum: 50
        :param queue: Optional. The queue that jobs created from this template are assigned to. Specify the Amazon Resource Name (ARN) of the queue. For example, arn:aws:mediaconvert:us-west-2:505474453218:queues/Default. If you don't specify this, jobs will go to the default queue.
        :param status_update_interval: Specify how often MediaConvert sends STATUS_UPDATE events to Amazon CloudWatch Events. Set the interval, in seconds, between status updates. MediaConvert sends an update at this interval from the time the service begins processing your job to the time it completes the transcode or encounters an error. Specify one of the following enums: SECONDS_10 SECONDS_12 SECONDS_15 SECONDS_20 SECONDS_30 SECONDS_60 SECONDS_120 SECONDS_180 SECONDS_240 SECONDS_300 SECONDS_360 SECONDS_420 SECONDS_480 SECONDS_540 SECONDS_600
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnJobTemplateProps(
            settings_json=settings_json,
            acceleration_settings=acceleration_settings,
            category=category,
            description=description,
            hop_destinations=hop_destinations,
            name=name,
            priority=priority,
            queue=queue,
            status_update_interval=status_update_interval,
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
        '''The Amazon Resource Name (ARN) of the job template, such as ``arn:aws:mediaconvert:us-west-2:123456789012`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the job template, such as ``Streaming stack DASH`` .

        :cloudformationAttribute: Name
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="settingsJson")
    def settings_json(self) -> typing.Any:
        '''Specify, in JSON format, the transcoding job settings for this job template.

        This specification must conform to the AWS Elemental MediaConvert job validation. For information about forming this specification, see the Remarks section later in this topic.

        For more information about MediaConvert job templates, see `Working with AWS Elemental MediaConvert Job Templates <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-job-templates.html>`_ in the ** .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-settingsjson
        '''
        return typing.cast(typing.Any, jsii.get(self, "settingsJson"))

    @settings_json.setter
    def settings_json(self, value: typing.Any) -> None:
        jsii.set(self, "settingsJson", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accelerationSettings")
    def acceleration_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnJobTemplate.AccelerationSettingsProperty", _IResolvable_da3f097b]]:
        '''Accelerated transcoding can significantly speed up jobs with long, visually complex content.

        Outputs that use this feature incur pro-tier pricing. For information about feature limitations, For more information, see `Job Limitations for Accelerated Transcoding in AWS Elemental MediaConvert <https://docs.aws.amazon.com/mediaconvert/latest/ug/job-requirements.html>`_ in the *AWS Elemental MediaConvert User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-accelerationsettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnJobTemplate.AccelerationSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "accelerationSettings"))

    @acceleration_settings.setter
    def acceleration_settings(
        self,
        value: typing.Optional[typing.Union["CfnJobTemplate.AccelerationSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "accelerationSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="category")
    def category(self) -> typing.Optional[builtins.str]:
        '''Optional.

        A category for the job template you are creating

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-category
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "category"))

    @category.setter
    def category(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "category", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''Optional.

        A description of the job template you are creating.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hopDestinations")
    def hop_destinations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobTemplate.HopDestinationProperty", _IResolvable_da3f097b]]]]:
        '''Optional.

        Configuration for a destination queue to which the job can hop once a customer-defined minimum wait time has passed. For more information, see `Setting Up Queue Hopping to Avoid Long Waits <https://docs.aws.amazon.com/mediaconvert/latest/ug/setting-up-queue-hopping-to-avoid-long-waits.html>`_ in the *AWS Elemental MediaConvert User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-hopdestinations
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobTemplate.HopDestinationProperty", _IResolvable_da3f097b]]]], jsii.get(self, "hopDestinations"))

    @hop_destinations.setter
    def hop_destinations(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobTemplate.HopDestinationProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "hopDestinations", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the job template you are creating.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="priority")
    def priority(self) -> typing.Optional[jsii.Number]:
        '''Specify the relative priority for this job.

        In any given queue, the service begins processing the job with the highest value first. When more than one job has the same priority, the service begins processing the job that you submitted first. If you don't specify a priority, the service uses the default value 0. Minimum: -50 Maximum: 50

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-priority
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "priority"))

    @priority.setter
    def priority(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "priority", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queue")
    def queue(self) -> typing.Optional[builtins.str]:
        '''Optional.

        The queue that jobs created from this template are assigned to. Specify the Amazon Resource Name (ARN) of the queue. For example, arn:aws:mediaconvert:us-west-2:505474453218:queues/Default. If you don't specify this, jobs will go to the default queue.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-queue
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "queue"))

    @queue.setter
    def queue(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "queue", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="statusUpdateInterval")
    def status_update_interval(self) -> typing.Optional[builtins.str]:
        '''Specify how often MediaConvert sends STATUS_UPDATE events to Amazon CloudWatch Events.

        Set the interval, in seconds, between status updates. MediaConvert sends an update at this interval from the time the service begins processing your job to the time it completes the transcode or encounters an error.

        Specify one of the following enums:

        SECONDS_10

        SECONDS_12

        SECONDS_15

        SECONDS_20

        SECONDS_30

        SECONDS_60

        SECONDS_120

        SECONDS_180

        SECONDS_240

        SECONDS_300

        SECONDS_360

        SECONDS_420

        SECONDS_480

        SECONDS_540

        SECONDS_600

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-statusupdateinterval
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "statusUpdateInterval"))

    @status_update_interval.setter
    def status_update_interval(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "statusUpdateInterval", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediaconvert.CfnJobTemplate.AccelerationSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={"mode": "mode"},
    )
    class AccelerationSettingsProperty:
        def __init__(self, *, mode: builtins.str) -> None:
            '''Accelerated transcoding can significantly speed up jobs with long, visually complex content.

            Outputs that use this feature incur pro-tier pricing. For information about feature limitations, For more information, see `Job Limitations for Accelerated Transcoding in AWS Elemental MediaConvert <https://docs.aws.amazon.com/mediaconvert/latest/ug/job-requirements.html>`_ in the *AWS Elemental MediaConvert User Guide* .

            :param mode: Specify the conditions when the service will run your job with accelerated transcoding.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediaconvert-jobtemplate-accelerationsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediaconvert as mediaconvert
                
                acceleration_settings_property = mediaconvert.CfnJobTemplate.AccelerationSettingsProperty(
                    mode="mode"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "mode": mode,
            }

        @builtins.property
        def mode(self) -> builtins.str:
            '''Specify the conditions when the service will run your job with accelerated transcoding.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediaconvert-jobtemplate-accelerationsettings.html#cfn-mediaconvert-jobtemplate-accelerationsettings-mode
            '''
            result = self._values.get("mode")
            assert result is not None, "Required property 'mode' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AccelerationSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mediaconvert.CfnJobTemplate.HopDestinationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "priority": "priority",
            "queue": "queue",
            "wait_minutes": "waitMinutes",
        },
    )
    class HopDestinationProperty:
        def __init__(
            self,
            *,
            priority: typing.Optional[jsii.Number] = None,
            queue: typing.Optional[builtins.str] = None,
            wait_minutes: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Optional.

            Configuration for a destination queue to which the job can hop once a customer-defined minimum wait time has passed. For more information, see `Setting Up Queue Hopping to Avoid Long Waits <https://docs.aws.amazon.com/mediaconvert/latest/ug/setting-up-queue-hopping-to-avoid-long-waits.html>`_ in the *AWS Elemental MediaConvert User Guide* .

            :param priority: Optional. When you set up a job to use queue hopping, you can specify a different relative priority for the job in the destination queue. If you don't specify, the relative priority will remain the same as in the previous queue.
            :param queue: Optional unless the job is submitted on the default queue. When you set up a job to use queue hopping, you can specify a destination queue. This queue cannot be the original queue to which the job is submitted. If the original queue isn't the default queue and you don't specify the destination queue, the job will move to the default queue.
            :param wait_minutes: Required for setting up a job to use queue hopping. Minimum wait time in minutes until the job can hop to the destination queue. Valid range is 1 to 1440 minutes, inclusive.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediaconvert-jobtemplate-hopdestination.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mediaconvert as mediaconvert
                
                hop_destination_property = mediaconvert.CfnJobTemplate.HopDestinationProperty(
                    priority=123,
                    queue="queue",
                    wait_minutes=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if priority is not None:
                self._values["priority"] = priority
            if queue is not None:
                self._values["queue"] = queue
            if wait_minutes is not None:
                self._values["wait_minutes"] = wait_minutes

        @builtins.property
        def priority(self) -> typing.Optional[jsii.Number]:
            '''Optional.

            When you set up a job to use queue hopping, you can specify a different relative priority for the job in the destination queue. If you don't specify, the relative priority will remain the same as in the previous queue.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediaconvert-jobtemplate-hopdestination.html#cfn-mediaconvert-jobtemplate-hopdestination-priority
            '''
            result = self._values.get("priority")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def queue(self) -> typing.Optional[builtins.str]:
            '''Optional unless the job is submitted on the default queue.

            When you set up a job to use queue hopping, you can specify a destination queue. This queue cannot be the original queue to which the job is submitted. If the original queue isn't the default queue and you don't specify the destination queue, the job will move to the default queue.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediaconvert-jobtemplate-hopdestination.html#cfn-mediaconvert-jobtemplate-hopdestination-queue
            '''
            result = self._values.get("queue")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def wait_minutes(self) -> typing.Optional[jsii.Number]:
            '''Required for setting up a job to use queue hopping.

            Minimum wait time in minutes until the job can hop to the destination queue. Valid range is 1 to 1440 minutes, inclusive.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mediaconvert-jobtemplate-hopdestination.html#cfn-mediaconvert-jobtemplate-hopdestination-waitminutes
            '''
            result = self._values.get("wait_minutes")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HopDestinationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_mediaconvert.CfnJobTemplateProps",
    jsii_struct_bases=[],
    name_mapping={
        "settings_json": "settingsJson",
        "acceleration_settings": "accelerationSettings",
        "category": "category",
        "description": "description",
        "hop_destinations": "hopDestinations",
        "name": "name",
        "priority": "priority",
        "queue": "queue",
        "status_update_interval": "statusUpdateInterval",
        "tags": "tags",
    },
)
class CfnJobTemplateProps:
    def __init__(
        self,
        *,
        settings_json: typing.Any,
        acceleration_settings: typing.Optional[typing.Union[CfnJobTemplate.AccelerationSettingsProperty, _IResolvable_da3f097b]] = None,
        category: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        hop_destinations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnJobTemplate.HopDestinationProperty, _IResolvable_da3f097b]]]] = None,
        name: typing.Optional[builtins.str] = None,
        priority: typing.Optional[jsii.Number] = None,
        queue: typing.Optional[builtins.str] = None,
        status_update_interval: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnJobTemplate``.

        :param settings_json: Specify, in JSON format, the transcoding job settings for this job template. This specification must conform to the AWS Elemental MediaConvert job validation. For information about forming this specification, see the Remarks section later in this topic. For more information about MediaConvert job templates, see `Working with AWS Elemental MediaConvert Job Templates <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-job-templates.html>`_ in the ** .
        :param acceleration_settings: Accelerated transcoding can significantly speed up jobs with long, visually complex content. Outputs that use this feature incur pro-tier pricing. For information about feature limitations, For more information, see `Job Limitations for Accelerated Transcoding in AWS Elemental MediaConvert <https://docs.aws.amazon.com/mediaconvert/latest/ug/job-requirements.html>`_ in the *AWS Elemental MediaConvert User Guide* .
        :param category: Optional. A category for the job template you are creating
        :param description: Optional. A description of the job template you are creating.
        :param hop_destinations: Optional. Configuration for a destination queue to which the job can hop once a customer-defined minimum wait time has passed. For more information, see `Setting Up Queue Hopping to Avoid Long Waits <https://docs.aws.amazon.com/mediaconvert/latest/ug/setting-up-queue-hopping-to-avoid-long-waits.html>`_ in the *AWS Elemental MediaConvert User Guide* .
        :param name: The name of the job template you are creating.
        :param priority: Specify the relative priority for this job. In any given queue, the service begins processing the job with the highest value first. When more than one job has the same priority, the service begins processing the job that you submitted first. If you don't specify a priority, the service uses the default value 0. Minimum: -50 Maximum: 50
        :param queue: Optional. The queue that jobs created from this template are assigned to. Specify the Amazon Resource Name (ARN) of the queue. For example, arn:aws:mediaconvert:us-west-2:505474453218:queues/Default. If you don't specify this, jobs will go to the default queue.
        :param status_update_interval: Specify how often MediaConvert sends STATUS_UPDATE events to Amazon CloudWatch Events. Set the interval, in seconds, between status updates. MediaConvert sends an update at this interval from the time the service begins processing your job to the time it completes the transcode or encounters an error. Specify one of the following enums: SECONDS_10 SECONDS_12 SECONDS_15 SECONDS_20 SECONDS_30 SECONDS_60 SECONDS_120 SECONDS_180 SECONDS_240 SECONDS_300 SECONDS_360 SECONDS_420 SECONDS_480 SECONDS_540 SECONDS_600
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_mediaconvert as mediaconvert
            
            # settings_json: Any
            # tags: Any
            
            cfn_job_template_props = mediaconvert.CfnJobTemplateProps(
                settings_json=settings_json,
            
                # the properties below are optional
                acceleration_settings=mediaconvert.CfnJobTemplate.AccelerationSettingsProperty(
                    mode="mode"
                ),
                category="category",
                description="description",
                hop_destinations=[mediaconvert.CfnJobTemplate.HopDestinationProperty(
                    priority=123,
                    queue="queue",
                    wait_minutes=123
                )],
                name="name",
                priority=123,
                queue="queue",
                status_update_interval="statusUpdateInterval",
                tags=tags
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "settings_json": settings_json,
        }
        if acceleration_settings is not None:
            self._values["acceleration_settings"] = acceleration_settings
        if category is not None:
            self._values["category"] = category
        if description is not None:
            self._values["description"] = description
        if hop_destinations is not None:
            self._values["hop_destinations"] = hop_destinations
        if name is not None:
            self._values["name"] = name
        if priority is not None:
            self._values["priority"] = priority
        if queue is not None:
            self._values["queue"] = queue
        if status_update_interval is not None:
            self._values["status_update_interval"] = status_update_interval
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def settings_json(self) -> typing.Any:
        '''Specify, in JSON format, the transcoding job settings for this job template.

        This specification must conform to the AWS Elemental MediaConvert job validation. For information about forming this specification, see the Remarks section later in this topic.

        For more information about MediaConvert job templates, see `Working with AWS Elemental MediaConvert Job Templates <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-job-templates.html>`_ in the ** .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-settingsjson
        '''
        result = self._values.get("settings_json")
        assert result is not None, "Required property 'settings_json' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def acceleration_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnJobTemplate.AccelerationSettingsProperty, _IResolvable_da3f097b]]:
        '''Accelerated transcoding can significantly speed up jobs with long, visually complex content.

        Outputs that use this feature incur pro-tier pricing. For information about feature limitations, For more information, see `Job Limitations for Accelerated Transcoding in AWS Elemental MediaConvert <https://docs.aws.amazon.com/mediaconvert/latest/ug/job-requirements.html>`_ in the *AWS Elemental MediaConvert User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-accelerationsettings
        '''
        result = self._values.get("acceleration_settings")
        return typing.cast(typing.Optional[typing.Union[CfnJobTemplate.AccelerationSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def category(self) -> typing.Optional[builtins.str]:
        '''Optional.

        A category for the job template you are creating

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-category
        '''
        result = self._values.get("category")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''Optional.

        A description of the job template you are creating.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def hop_destinations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnJobTemplate.HopDestinationProperty, _IResolvable_da3f097b]]]]:
        '''Optional.

        Configuration for a destination queue to which the job can hop once a customer-defined minimum wait time has passed. For more information, see `Setting Up Queue Hopping to Avoid Long Waits <https://docs.aws.amazon.com/mediaconvert/latest/ug/setting-up-queue-hopping-to-avoid-long-waits.html>`_ in the *AWS Elemental MediaConvert User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-hopdestinations
        '''
        result = self._values.get("hop_destinations")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnJobTemplate.HopDestinationProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the job template you are creating.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def priority(self) -> typing.Optional[jsii.Number]:
        '''Specify the relative priority for this job.

        In any given queue, the service begins processing the job with the highest value first. When more than one job has the same priority, the service begins processing the job that you submitted first. If you don't specify a priority, the service uses the default value 0. Minimum: -50 Maximum: 50

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-priority
        '''
        result = self._values.get("priority")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def queue(self) -> typing.Optional[builtins.str]:
        '''Optional.

        The queue that jobs created from this template are assigned to. Specify the Amazon Resource Name (ARN) of the queue. For example, arn:aws:mediaconvert:us-west-2:505474453218:queues/Default. If you don't specify this, jobs will go to the default queue.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-queue
        '''
        result = self._values.get("queue")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def status_update_interval(self) -> typing.Optional[builtins.str]:
        '''Specify how often MediaConvert sends STATUS_UPDATE events to Amazon CloudWatch Events.

        Set the interval, in seconds, between status updates. MediaConvert sends an update at this interval from the time the service begins processing your job to the time it completes the transcode or encounters an error.

        Specify one of the following enums:

        SECONDS_10

        SECONDS_12

        SECONDS_15

        SECONDS_20

        SECONDS_30

        SECONDS_60

        SECONDS_120

        SECONDS_180

        SECONDS_240

        SECONDS_300

        SECONDS_360

        SECONDS_420

        SECONDS_480

        SECONDS_540

        SECONDS_600

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-statusupdateinterval
        '''
        result = self._values.get("status_update_interval")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-jobtemplate.html#cfn-mediaconvert-jobtemplate-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnJobTemplateProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnPreset(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_mediaconvert.CfnPreset",
):
    '''A CloudFormation ``AWS::MediaConvert::Preset``.

    The AWS::MediaConvert::Preset resource is an AWS Elemental MediaConvert resource type that you can use to specify encoding settings for a single output in a transcoding job.

    When you declare this entity in your AWS CloudFormation template, you pass in your transcoding job settings in JSON or YAML format. This settings specification must be formed in a particular way that conforms to AWS Elemental MediaConvert job validation. For more information about creating an output preset model for the ``SettingsJson`` property, see the Remarks section later in this topic.

    For more information about output MediaConvert presets, see `Working with AWS Elemental MediaConvert Output Presets <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-presets.html>`_ in the ** .

    :cloudformationResource: AWS::MediaConvert::Preset
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-preset.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_mediaconvert as mediaconvert
        
        # settings_json: Any
        # tags: Any
        
        cfn_preset = mediaconvert.CfnPreset(self, "MyCfnPreset",
            settings_json=settings_json,
        
            # the properties below are optional
            category="category",
            description="description",
            name="name",
            tags=tags
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        settings_json: typing.Any,
        category: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::MediaConvert::Preset``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param settings_json: Specify, in JSON format, the transcoding job settings for this output preset. This specification must conform to the AWS Elemental MediaConvert job validation. For information about forming this specification, see the Remarks section later in this topic. For more information about MediaConvert output presets, see `Working with AWS Elemental MediaConvert Output Presets <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-presets.html>`_ in the ** .
        :param category: The new category for the preset, if you are changing it.
        :param description: The new description for the preset, if you are changing it.
        :param name: The name of the preset that you are modifying.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnPresetProps(
            settings_json=settings_json,
            category=category,
            description=description,
            name=name,
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
        '''The Amazon Resource Name (ARN) of the output preset, such as ``arn:aws:mediaconvert:us-west-2:123456789012`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the output preset, such as ``HEVC high res`` .

        :cloudformationAttribute: Name
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-preset.html#cfn-mediaconvert-preset-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="settingsJson")
    def settings_json(self) -> typing.Any:
        '''Specify, in JSON format, the transcoding job settings for this output preset.

        This specification must conform to the AWS Elemental MediaConvert job validation. For information about forming this specification, see the Remarks section later in this topic.

        For more information about MediaConvert output presets, see `Working with AWS Elemental MediaConvert Output Presets <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-presets.html>`_ in the ** .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-preset.html#cfn-mediaconvert-preset-settingsjson
        '''
        return typing.cast(typing.Any, jsii.get(self, "settingsJson"))

    @settings_json.setter
    def settings_json(self, value: typing.Any) -> None:
        jsii.set(self, "settingsJson", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="category")
    def category(self) -> typing.Optional[builtins.str]:
        '''The new category for the preset, if you are changing it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-preset.html#cfn-mediaconvert-preset-category
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "category"))

    @category.setter
    def category(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "category", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The new description for the preset, if you are changing it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-preset.html#cfn-mediaconvert-preset-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the preset that you are modifying.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-preset.html#cfn-mediaconvert-preset-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_mediaconvert.CfnPresetProps",
    jsii_struct_bases=[],
    name_mapping={
        "settings_json": "settingsJson",
        "category": "category",
        "description": "description",
        "name": "name",
        "tags": "tags",
    },
)
class CfnPresetProps:
    def __init__(
        self,
        *,
        settings_json: typing.Any,
        category: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnPreset``.

        :param settings_json: Specify, in JSON format, the transcoding job settings for this output preset. This specification must conform to the AWS Elemental MediaConvert job validation. For information about forming this specification, see the Remarks section later in this topic. For more information about MediaConvert output presets, see `Working with AWS Elemental MediaConvert Output Presets <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-presets.html>`_ in the ** .
        :param category: The new category for the preset, if you are changing it.
        :param description: The new description for the preset, if you are changing it.
        :param name: The name of the preset that you are modifying.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-preset.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_mediaconvert as mediaconvert
            
            # settings_json: Any
            # tags: Any
            
            cfn_preset_props = mediaconvert.CfnPresetProps(
                settings_json=settings_json,
            
                # the properties below are optional
                category="category",
                description="description",
                name="name",
                tags=tags
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "settings_json": settings_json,
        }
        if category is not None:
            self._values["category"] = category
        if description is not None:
            self._values["description"] = description
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def settings_json(self) -> typing.Any:
        '''Specify, in JSON format, the transcoding job settings for this output preset.

        This specification must conform to the AWS Elemental MediaConvert job validation. For information about forming this specification, see the Remarks section later in this topic.

        For more information about MediaConvert output presets, see `Working with AWS Elemental MediaConvert Output Presets <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-presets.html>`_ in the ** .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-preset.html#cfn-mediaconvert-preset-settingsjson
        '''
        result = self._values.get("settings_json")
        assert result is not None, "Required property 'settings_json' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def category(self) -> typing.Optional[builtins.str]:
        '''The new category for the preset, if you are changing it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-preset.html#cfn-mediaconvert-preset-category
        '''
        result = self._values.get("category")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The new description for the preset, if you are changing it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-preset.html#cfn-mediaconvert-preset-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the preset that you are modifying.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-preset.html#cfn-mediaconvert-preset-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-preset.html#cfn-mediaconvert-preset-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPresetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnQueue(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_mediaconvert.CfnQueue",
):
    '''A CloudFormation ``AWS::MediaConvert::Queue``.

    The AWS::MediaConvert::Queue resource is an AWS Elemental MediaConvert resource type that you can use to manage the resources that are available to your account for parallel processing of jobs. For more information about queues, see `Working with AWS Elemental MediaConvert Queues <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-queues.html>`_ in the ** .

    :cloudformationResource: AWS::MediaConvert::Queue
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-queue.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_mediaconvert as mediaconvert
        
        # tags: Any
        
        cfn_queue = mediaconvert.CfnQueue(self, "MyCfnQueue",
            description="description",
            name="name",
            pricing_plan="pricingPlan",
            status="status",
            tags=tags
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        pricing_plan: typing.Optional[builtins.str] = None,
        status: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::MediaConvert::Queue``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param description: Optional. A description of the queue that you are creating.
        :param name: The name of the queue that you are creating.
        :param pricing_plan: When you use AWS CloudFormation , you can create only on-demand queues. Therefore, always set ``PricingPlan`` to the value "ON_DEMAND" when declaring an AWS::MediaConvert::Queue in your AWS CloudFormation template. To create a reserved queue, use the AWS Elemental MediaConvert console at https://console.aws.amazon.com/mediaconvert to set up a contract. For more information, see `Working with AWS Elemental MediaConvert Queues <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-queues.html>`_ in the ** .
        :param status: Initial state of the queue. Queues can be either ACTIVE or PAUSED. If you create a paused queue, then jobs that you send to that queue won't begin.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnQueueProps(
            description=description,
            name=name,
            pricing_plan=pricing_plan,
            status=status,
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
        '''The Amazon Resource Name (ARN) of the queue, such as ``arn:aws:mediaconvert:us-west-2:123456789012`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the queue, such as ``Queue 2`` .

        :cloudformationAttribute: Name
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-queue.html#cfn-mediaconvert-queue-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''Optional.

        A description of the queue that you are creating.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-queue.html#cfn-mediaconvert-queue-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the queue that you are creating.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-queue.html#cfn-mediaconvert-queue-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="pricingPlan")
    def pricing_plan(self) -> typing.Optional[builtins.str]:
        '''When you use AWS CloudFormation , you can create only on-demand queues.

        Therefore, always set ``PricingPlan`` to the value "ON_DEMAND" when declaring an AWS::MediaConvert::Queue in your AWS CloudFormation template.

        To create a reserved queue, use the AWS Elemental MediaConvert console at https://console.aws.amazon.com/mediaconvert to set up a contract. For more information, see `Working with AWS Elemental MediaConvert Queues <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-queues.html>`_ in the ** .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-queue.html#cfn-mediaconvert-queue-pricingplan
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "pricingPlan"))

    @pricing_plan.setter
    def pricing_plan(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "pricingPlan", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="status")
    def status(self) -> typing.Optional[builtins.str]:
        '''Initial state of the queue.

        Queues can be either ACTIVE or PAUSED. If you create a paused queue, then jobs that you send to that queue won't begin.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-queue.html#cfn-mediaconvert-queue-status
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "status"))

    @status.setter
    def status(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "status", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_mediaconvert.CfnQueueProps",
    jsii_struct_bases=[],
    name_mapping={
        "description": "description",
        "name": "name",
        "pricing_plan": "pricingPlan",
        "status": "status",
        "tags": "tags",
    },
)
class CfnQueueProps:
    def __init__(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        pricing_plan: typing.Optional[builtins.str] = None,
        status: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnQueue``.

        :param description: Optional. A description of the queue that you are creating.
        :param name: The name of the queue that you are creating.
        :param pricing_plan: When you use AWS CloudFormation , you can create only on-demand queues. Therefore, always set ``PricingPlan`` to the value "ON_DEMAND" when declaring an AWS::MediaConvert::Queue in your AWS CloudFormation template. To create a reserved queue, use the AWS Elemental MediaConvert console at https://console.aws.amazon.com/mediaconvert to set up a contract. For more information, see `Working with AWS Elemental MediaConvert Queues <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-queues.html>`_ in the ** .
        :param status: Initial state of the queue. Queues can be either ACTIVE or PAUSED. If you create a paused queue, then jobs that you send to that queue won't begin.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-queue.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_mediaconvert as mediaconvert
            
            # tags: Any
            
            cfn_queue_props = mediaconvert.CfnQueueProps(
                description="description",
                name="name",
                pricing_plan="pricingPlan",
                status="status",
                tags=tags
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if description is not None:
            self._values["description"] = description
        if name is not None:
            self._values["name"] = name
        if pricing_plan is not None:
            self._values["pricing_plan"] = pricing_plan
        if status is not None:
            self._values["status"] = status
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''Optional.

        A description of the queue that you are creating.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-queue.html#cfn-mediaconvert-queue-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the queue that you are creating.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-queue.html#cfn-mediaconvert-queue-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def pricing_plan(self) -> typing.Optional[builtins.str]:
        '''When you use AWS CloudFormation , you can create only on-demand queues.

        Therefore, always set ``PricingPlan`` to the value "ON_DEMAND" when declaring an AWS::MediaConvert::Queue in your AWS CloudFormation template.

        To create a reserved queue, use the AWS Elemental MediaConvert console at https://console.aws.amazon.com/mediaconvert to set up a contract. For more information, see `Working with AWS Elemental MediaConvert Queues <https://docs.aws.amazon.com/mediaconvert/latest/ug/working-with-queues.html>`_ in the ** .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-queue.html#cfn-mediaconvert-queue-pricingplan
        '''
        result = self._values.get("pricing_plan")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def status(self) -> typing.Optional[builtins.str]:
        '''Initial state of the queue.

        Queues can be either ACTIVE or PAUSED. If you create a paused queue, then jobs that you send to that queue won't begin.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-queue.html#cfn-mediaconvert-queue-status
        '''
        result = self._values.get("status")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mediaconvert-queue.html#cfn-mediaconvert-queue-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnQueueProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnJobTemplate",
    "CfnJobTemplateProps",
    "CfnPreset",
    "CfnPresetProps",
    "CfnQueue",
    "CfnQueueProps",
]

publication.publish()
