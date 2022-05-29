'''
# AWS::CodeGuruProfiler Construct Library

Amazon CodeGuru Profiler collects runtime performance data from your live applications, and provides recommendations that can help you fine-tune your application performance.

## Installation

Import to your project:

```python
import aws_cdk.aws_codeguruprofiler as codeguruprofiler
```

## Basic usage

Here's how to setup a profiling group and give your compute role permissions to publish to the profiling group to the profiling agent can publish profiling information:

```python
# The execution role of your application that publishes to the ProfilingGroup via CodeGuru Profiler Profiling Agent. (the following is merely an example)
publish_app_role = iam.Role(self, "PublishAppRole",
    assumed_by=iam.AccountRootPrincipal()
)

profiling_group = codeguruprofiler.ProfilingGroup(self, "MyProfilingGroup")
profiling_group.grant_publish(publish_app_role)
```

## Compute Platform configuration

Code Guru Profiler supports multiple compute environments.
They can be configured when creating a Profiling Group by using the `computePlatform` property:

```python
profiling_group = codeguruprofiler.ProfilingGroup(self, "MyProfilingGroup",
    compute_platform=codeguruprofiler.ComputePlatform.AWS_LAMBDA
)
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
    IResource as _IResource_c80c4260,
    Resource as _Resource_45bc6135,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_iam import Grant as _Grant_a7ae64f8, IGrantable as _IGrantable_71c4f5de


@jsii.implements(_IInspectable_c2943556)
class CfnProfilingGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_codeguruprofiler.CfnProfilingGroup",
):
    '''A CloudFormation ``AWS::CodeGuruProfiler::ProfilingGroup``.

    Creates a profiling group.

    :cloudformationResource: AWS::CodeGuruProfiler::ProfilingGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codeguruprofiler-profilinggroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_codeguruprofiler as codeguruprofiler
        
        # agent_permissions: Any
        
        cfn_profiling_group = codeguruprofiler.CfnProfilingGroup(self, "MyCfnProfilingGroup",
            profiling_group_name="profilingGroupName",
        
            # the properties below are optional
            agent_permissions=agent_permissions,
            anomaly_detection_notification_configuration=[codeguruprofiler.CfnProfilingGroup.ChannelProperty(
                channel_uri="channelUri",
        
                # the properties below are optional
                channel_id="channelId"
            )],
            compute_platform="computePlatform",
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
        profiling_group_name: builtins.str,
        agent_permissions: typing.Any = None,
        anomaly_detection_notification_configuration: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnProfilingGroup.ChannelProperty", _IResolvable_da3f097b]]]] = None,
        compute_platform: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::CodeGuruProfiler::ProfilingGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param profiling_group_name: The name of the profiling group.
        :param agent_permissions: The agent permissions attached to this profiling group. This action group grants ``ConfigureAgent`` and ``PostAgentProfile`` permissions to perform actions required by the profiling agent. The Json consists of key ``Principals`` . *Principals* : A list of string ARNs for the roles and users you want to grant access to the profiling group. Wildcards are not supported in the ARNs. You are allowed to provide up to 50 ARNs. An empty list is not permitted. This is a required key. For more information, see `Resource-based policies in CodeGuru Profiler <https://docs.aws.amazon.com/codeguru/latest/profiler-ug/resource-based-policies.html>`_ in the *Amazon CodeGuru Profiler user guide* , `ConfigureAgent <https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_ConfigureAgent.html>`_ , and `PostAgentProfile <https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_PostAgentProfile.html>`_ .
        :param anomaly_detection_notification_configuration: Adds anomaly notifications for a profiling group.
        :param compute_platform: The compute platform of the profiling group. Use ``AWSLambda`` if your application runs on AWS Lambda. Use ``Default`` if your application runs on a compute platform that is not AWS Lambda , such an Amazon EC2 instance, an on-premises server, or a different platform. If not specified, ``Default`` is used. This property is immutable.
        :param tags: A list of tags to add to the created profiling group.
        '''
        props = CfnProfilingGroupProps(
            profiling_group_name=profiling_group_name,
            agent_permissions=agent_permissions,
            anomaly_detection_notification_configuration=anomaly_detection_notification_configuration,
            compute_platform=compute_platform,
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
        '''The full Amazon Resource Name (ARN) for that profiling group.

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
        '''A list of tags to add to the created profiling group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codeguruprofiler-profilinggroup.html#cfn-codeguruprofiler-profilinggroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="agentPermissions")
    def agent_permissions(self) -> typing.Any:
        '''The agent permissions attached to this profiling group.

        This action group grants ``ConfigureAgent`` and ``PostAgentProfile`` permissions to perform actions required by the profiling agent. The Json consists of key ``Principals`` .

        *Principals* : A list of string ARNs for the roles and users you want to grant access to the profiling group. Wildcards are not supported in the ARNs. You are allowed to provide up to 50 ARNs. An empty list is not permitted. This is a required key.

        For more information, see `Resource-based policies in CodeGuru Profiler <https://docs.aws.amazon.com/codeguru/latest/profiler-ug/resource-based-policies.html>`_ in the *Amazon CodeGuru Profiler user guide* , `ConfigureAgent <https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_ConfigureAgent.html>`_ , and `PostAgentProfile <https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_PostAgentProfile.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codeguruprofiler-profilinggroup.html#cfn-codeguruprofiler-profilinggroup-agentpermissions
        '''
        return typing.cast(typing.Any, jsii.get(self, "agentPermissions"))

    @agent_permissions.setter
    def agent_permissions(self, value: typing.Any) -> None:
        jsii.set(self, "agentPermissions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="profilingGroupName")
    def profiling_group_name(self) -> builtins.str:
        '''The name of the profiling group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codeguruprofiler-profilinggroup.html#cfn-codeguruprofiler-profilinggroup-profilinggroupname
        '''
        return typing.cast(builtins.str, jsii.get(self, "profilingGroupName"))

    @profiling_group_name.setter
    def profiling_group_name(self, value: builtins.str) -> None:
        jsii.set(self, "profilingGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="anomalyDetectionNotificationConfiguration")
    def anomaly_detection_notification_configuration(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnProfilingGroup.ChannelProperty", _IResolvable_da3f097b]]]]:
        '''Adds anomaly notifications for a profiling group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codeguruprofiler-profilinggroup.html#cfn-codeguruprofiler-profilinggroup-anomalydetectionnotificationconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnProfilingGroup.ChannelProperty", _IResolvable_da3f097b]]]], jsii.get(self, "anomalyDetectionNotificationConfiguration"))

    @anomaly_detection_notification_configuration.setter
    def anomaly_detection_notification_configuration(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnProfilingGroup.ChannelProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "anomalyDetectionNotificationConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="computePlatform")
    def compute_platform(self) -> typing.Optional[builtins.str]:
        '''The compute platform of the profiling group.

        Use ``AWSLambda`` if your application runs on AWS Lambda. Use ``Default`` if your application runs on a compute platform that is not AWS Lambda , such an Amazon EC2 instance, an on-premises server, or a different platform. If not specified, ``Default`` is used. This property is immutable.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codeguruprofiler-profilinggroup.html#cfn-codeguruprofiler-profilinggroup-computeplatform
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "computePlatform"))

    @compute_platform.setter
    def compute_platform(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "computePlatform", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_codeguruprofiler.CfnProfilingGroup.ChannelProperty",
        jsii_struct_bases=[],
        name_mapping={"channel_uri": "channelUri", "channel_id": "channelId"},
    )
    class ChannelProperty:
        def __init__(
            self,
            *,
            channel_uri: builtins.str,
            channel_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Notification medium for users to get alerted for events that occur in application profile.

            We support SNS topic as a notification channel.

            :param channel_uri: The channel URI.
            :param channel_id: The channel ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codeguruprofiler-profilinggroup-channel.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_codeguruprofiler as codeguruprofiler
                
                channel_property = codeguruprofiler.CfnProfilingGroup.ChannelProperty(
                    channel_uri="channelUri",
                
                    # the properties below are optional
                    channel_id="channelId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "channel_uri": channel_uri,
            }
            if channel_id is not None:
                self._values["channel_id"] = channel_id

        @builtins.property
        def channel_uri(self) -> builtins.str:
            '''The channel URI.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codeguruprofiler-profilinggroup-channel.html#cfn-codeguruprofiler-profilinggroup-channel-channeluri
            '''
            result = self._values.get("channel_uri")
            assert result is not None, "Required property 'channel_uri' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def channel_id(self) -> typing.Optional[builtins.str]:
            '''The channel ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codeguruprofiler-profilinggroup-channel.html#cfn-codeguruprofiler-profilinggroup-channel-channelid
            '''
            result = self._values.get("channel_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ChannelProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_codeguruprofiler.CfnProfilingGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "profiling_group_name": "profilingGroupName",
        "agent_permissions": "agentPermissions",
        "anomaly_detection_notification_configuration": "anomalyDetectionNotificationConfiguration",
        "compute_platform": "computePlatform",
        "tags": "tags",
    },
)
class CfnProfilingGroupProps:
    def __init__(
        self,
        *,
        profiling_group_name: builtins.str,
        agent_permissions: typing.Any = None,
        anomaly_detection_notification_configuration: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnProfilingGroup.ChannelProperty, _IResolvable_da3f097b]]]] = None,
        compute_platform: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnProfilingGroup``.

        :param profiling_group_name: The name of the profiling group.
        :param agent_permissions: The agent permissions attached to this profiling group. This action group grants ``ConfigureAgent`` and ``PostAgentProfile`` permissions to perform actions required by the profiling agent. The Json consists of key ``Principals`` . *Principals* : A list of string ARNs for the roles and users you want to grant access to the profiling group. Wildcards are not supported in the ARNs. You are allowed to provide up to 50 ARNs. An empty list is not permitted. This is a required key. For more information, see `Resource-based policies in CodeGuru Profiler <https://docs.aws.amazon.com/codeguru/latest/profiler-ug/resource-based-policies.html>`_ in the *Amazon CodeGuru Profiler user guide* , `ConfigureAgent <https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_ConfigureAgent.html>`_ , and `PostAgentProfile <https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_PostAgentProfile.html>`_ .
        :param anomaly_detection_notification_configuration: Adds anomaly notifications for a profiling group.
        :param compute_platform: The compute platform of the profiling group. Use ``AWSLambda`` if your application runs on AWS Lambda. Use ``Default`` if your application runs on a compute platform that is not AWS Lambda , such an Amazon EC2 instance, an on-premises server, or a different platform. If not specified, ``Default`` is used. This property is immutable.
        :param tags: A list of tags to add to the created profiling group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codeguruprofiler-profilinggroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_codeguruprofiler as codeguruprofiler
            
            # agent_permissions: Any
            
            cfn_profiling_group_props = codeguruprofiler.CfnProfilingGroupProps(
                profiling_group_name="profilingGroupName",
            
                # the properties below are optional
                agent_permissions=agent_permissions,
                anomaly_detection_notification_configuration=[codeguruprofiler.CfnProfilingGroup.ChannelProperty(
                    channel_uri="channelUri",
            
                    # the properties below are optional
                    channel_id="channelId"
                )],
                compute_platform="computePlatform",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "profiling_group_name": profiling_group_name,
        }
        if agent_permissions is not None:
            self._values["agent_permissions"] = agent_permissions
        if anomaly_detection_notification_configuration is not None:
            self._values["anomaly_detection_notification_configuration"] = anomaly_detection_notification_configuration
        if compute_platform is not None:
            self._values["compute_platform"] = compute_platform
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def profiling_group_name(self) -> builtins.str:
        '''The name of the profiling group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codeguruprofiler-profilinggroup.html#cfn-codeguruprofiler-profilinggroup-profilinggroupname
        '''
        result = self._values.get("profiling_group_name")
        assert result is not None, "Required property 'profiling_group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def agent_permissions(self) -> typing.Any:
        '''The agent permissions attached to this profiling group.

        This action group grants ``ConfigureAgent`` and ``PostAgentProfile`` permissions to perform actions required by the profiling agent. The Json consists of key ``Principals`` .

        *Principals* : A list of string ARNs for the roles and users you want to grant access to the profiling group. Wildcards are not supported in the ARNs. You are allowed to provide up to 50 ARNs. An empty list is not permitted. This is a required key.

        For more information, see `Resource-based policies in CodeGuru Profiler <https://docs.aws.amazon.com/codeguru/latest/profiler-ug/resource-based-policies.html>`_ in the *Amazon CodeGuru Profiler user guide* , `ConfigureAgent <https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_ConfigureAgent.html>`_ , and `PostAgentProfile <https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_PostAgentProfile.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codeguruprofiler-profilinggroup.html#cfn-codeguruprofiler-profilinggroup-agentpermissions
        '''
        result = self._values.get("agent_permissions")
        return typing.cast(typing.Any, result)

    @builtins.property
    def anomaly_detection_notification_configuration(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnProfilingGroup.ChannelProperty, _IResolvable_da3f097b]]]]:
        '''Adds anomaly notifications for a profiling group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codeguruprofiler-profilinggroup.html#cfn-codeguruprofiler-profilinggroup-anomalydetectionnotificationconfiguration
        '''
        result = self._values.get("anomaly_detection_notification_configuration")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnProfilingGroup.ChannelProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def compute_platform(self) -> typing.Optional[builtins.str]:
        '''The compute platform of the profiling group.

        Use ``AWSLambda`` if your application runs on AWS Lambda. Use ``Default`` if your application runs on a compute platform that is not AWS Lambda , such an Amazon EC2 instance, an on-premises server, or a different platform. If not specified, ``Default`` is used. This property is immutable.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codeguruprofiler-profilinggroup.html#cfn-codeguruprofiler-profilinggroup-computeplatform
        '''
        result = self._values.get("compute_platform")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of tags to add to the created profiling group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codeguruprofiler-profilinggroup.html#cfn-codeguruprofiler-profilinggroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnProfilingGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_codeguruprofiler.ComputePlatform")
class ComputePlatform(enum.Enum):
    '''The compute platform of the profiling group.

    :exampleMetadata: infused

    Example::

        profiling_group = codeguruprofiler.ProfilingGroup(self, "MyProfilingGroup",
            compute_platform=codeguruprofiler.ComputePlatform.AWS_LAMBDA
        )
    '''

    AWS_LAMBDA = "AWS_LAMBDA"
    '''Use AWS_LAMBDA if your application runs on AWS Lambda.'''
    DEFAULT = "DEFAULT"
    '''Use Default if your application runs on a compute platform that is not AWS Lambda, such an Amazon EC2 instance, an on-premises server, or a different platform.'''


@jsii.interface(jsii_type="aws-cdk-lib.aws_codeguruprofiler.IProfilingGroup")
class IProfilingGroup(_IResource_c80c4260, typing_extensions.Protocol):
    '''IResource represents a Profiling Group.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="profilingGroupName")
    def profiling_group_name(self) -> builtins.str:
        '''A name for the profiling group.

        :attribute: true
        '''
        ...

    @jsii.member(jsii_name="grantPublish")
    def grant_publish(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant access to publish profiling information to the Profiling Group to the given identity.

        This will grant the following permissions:

        - codeguru-profiler:ConfigureAgent
        - codeguru-profiler:PostAgentProfile

        :param grantee: Principal to grant publish rights to.
        '''
        ...

    @jsii.member(jsii_name="grantRead")
    def grant_read(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant access to read profiling information from the Profiling Group to the given identity.

        This will grant the following permissions:

        - codeguru-profiler:GetProfile
        - codeguru-profiler:DescribeProfilingGroup

        :param grantee: Principal to grant read rights to.
        '''
        ...


class _IProfilingGroupProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''IResource represents a Profiling Group.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_codeguruprofiler.IProfilingGroup"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="profilingGroupName")
    def profiling_group_name(self) -> builtins.str:
        '''A name for the profiling group.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "profilingGroupName"))

    @jsii.member(jsii_name="grantPublish")
    def grant_publish(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant access to publish profiling information to the Profiling Group to the given identity.

        This will grant the following permissions:

        - codeguru-profiler:ConfigureAgent
        - codeguru-profiler:PostAgentProfile

        :param grantee: Principal to grant publish rights to.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPublish", [grantee]))

    @jsii.member(jsii_name="grantRead")
    def grant_read(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant access to read profiling information from the Profiling Group to the given identity.

        This will grant the following permissions:

        - codeguru-profiler:GetProfile
        - codeguru-profiler:DescribeProfilingGroup

        :param grantee: Principal to grant read rights to.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantRead", [grantee]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IProfilingGroup).__jsii_proxy_class__ = lambda : _IProfilingGroupProxy


@jsii.implements(IProfilingGroup)
class ProfilingGroup(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_codeguruprofiler.ProfilingGroup",
):
    '''A new Profiling Group.

    :exampleMetadata: infused

    Example::

        # The execution role of your application that publishes to the ProfilingGroup via CodeGuru Profiler Profiling Agent. (the following is merely an example)
        publish_app_role = iam.Role(self, "PublishAppRole",
            assumed_by=iam.AccountRootPrincipal()
        )
        
        profiling_group = codeguruprofiler.ProfilingGroup(self, "MyProfilingGroup")
        profiling_group.grant_publish(publish_app_role)
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        compute_platform: typing.Optional[ComputePlatform] = None,
        profiling_group_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param compute_platform: The compute platform of the profiling group. Default: ComputePlatform.DEFAULT
        :param profiling_group_name: A name for the profiling group. Default: - automatically generated name.
        '''
        props = ProfilingGroupProps(
            compute_platform=compute_platform,
            profiling_group_name=profiling_group_name,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromProfilingGroupArn") # type: ignore[misc]
    @builtins.classmethod
    def from_profiling_group_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        profiling_group_arn: builtins.str,
    ) -> IProfilingGroup:
        '''Import an existing Profiling Group provided an ARN.

        :param scope: The parent creating construct.
        :param id: The construct's name.
        :param profiling_group_arn: Profiling Group ARN.
        '''
        return typing.cast(IProfilingGroup, jsii.sinvoke(cls, "fromProfilingGroupArn", [scope, id, profiling_group_arn]))

    @jsii.member(jsii_name="fromProfilingGroupName") # type: ignore[misc]
    @builtins.classmethod
    def from_profiling_group_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        profiling_group_name: builtins.str,
    ) -> IProfilingGroup:
        '''Import an existing Profiling Group provided a Profiling Group Name.

        :param scope: The parent creating construct.
        :param id: The construct's name.
        :param profiling_group_name: Profiling Group Name.
        '''
        return typing.cast(IProfilingGroup, jsii.sinvoke(cls, "fromProfilingGroupName", [scope, id, profiling_group_name]))

    @jsii.member(jsii_name="grantPublish")
    def grant_publish(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant access to publish profiling information to the Profiling Group to the given identity.

        This will grant the following permissions:

        - codeguru-profiler:ConfigureAgent
        - codeguru-profiler:PostAgentProfile

        :param grantee: Principal to grant publish rights to.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPublish", [grantee]))

    @jsii.member(jsii_name="grantRead")
    def grant_read(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant access to read profiling information from the Profiling Group to the given identity.

        This will grant the following permissions:

        - codeguru-profiler:GetProfile
        - codeguru-profiler:DescribeProfilingGroup

        :param grantee: Principal to grant read rights to.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantRead", [grantee]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="profilingGroupArn")
    def profiling_group_arn(self) -> builtins.str:
        '''The ARN of the Profiling Group.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "profilingGroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="profilingGroupName")
    def profiling_group_name(self) -> builtins.str:
        '''The name of the Profiling Group.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "profilingGroupName"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_codeguruprofiler.ProfilingGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "compute_platform": "computePlatform",
        "profiling_group_name": "profilingGroupName",
    },
)
class ProfilingGroupProps:
    def __init__(
        self,
        *,
        compute_platform: typing.Optional[ComputePlatform] = None,
        profiling_group_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for creating a new Profiling Group.

        :param compute_platform: The compute platform of the profiling group. Default: ComputePlatform.DEFAULT
        :param profiling_group_name: A name for the profiling group. Default: - automatically generated name.

        :exampleMetadata: infused

        Example::

            profiling_group = codeguruprofiler.ProfilingGroup(self, "MyProfilingGroup",
                compute_platform=codeguruprofiler.ComputePlatform.AWS_LAMBDA
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if compute_platform is not None:
            self._values["compute_platform"] = compute_platform
        if profiling_group_name is not None:
            self._values["profiling_group_name"] = profiling_group_name

    @builtins.property
    def compute_platform(self) -> typing.Optional[ComputePlatform]:
        '''The compute platform of the profiling group.

        :default: ComputePlatform.DEFAULT
        '''
        result = self._values.get("compute_platform")
        return typing.cast(typing.Optional[ComputePlatform], result)

    @builtins.property
    def profiling_group_name(self) -> typing.Optional[builtins.str]:
        '''A name for the profiling group.

        :default: - automatically generated name.
        '''
        result = self._values.get("profiling_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ProfilingGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnProfilingGroup",
    "CfnProfilingGroupProps",
    "ComputePlatform",
    "IProfilingGroup",
    "ProfilingGroup",
    "ProfilingGroupProps",
]

publication.publish()
