'''
# AWS::NimbleStudio Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_nimblestudio as nimblestudio
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-nimblestudio-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::NimbleStudio](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_NimbleStudio.html).

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
class CfnLaunchProfile(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_nimblestudio.CfnLaunchProfile",
):
    '''A CloudFormation ``AWS::NimbleStudio::LaunchProfile``.

    The ``AWS::NimbleStudio::LaunchProfile`` resource represents access permissions for a set of studio components, including types of workstations, render farms, and shared file systems. Launch profiles are shared with studio users to give them access to the set of studio components.

    :cloudformationResource: AWS::NimbleStudio::LaunchProfile
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_nimblestudio as nimblestudio
        
        cfn_launch_profile = nimblestudio.CfnLaunchProfile(self, "MyCfnLaunchProfile",
            ec2_subnet_ids=["ec2SubnetIds"],
            launch_profile_protocol_versions=["launchProfileProtocolVersions"],
            name="name",
            stream_configuration=nimblestudio.CfnLaunchProfile.StreamConfigurationProperty(
                clipboard_mode="clipboardMode",
                ec2_instance_types=["ec2InstanceTypes"],
                streaming_image_ids=["streamingImageIds"],
        
                # the properties below are optional
                max_session_length_in_minutes=123,
                max_stopped_session_length_in_minutes=123,
                session_storage=nimblestudio.CfnLaunchProfile.StreamConfigurationSessionStorageProperty(
                    mode=["mode"],
                    root=nimblestudio.CfnLaunchProfile.StreamingSessionStorageRootProperty(
                        linux="linux",
                        windows="windows"
                    )
                )
            ),
            studio_component_ids=["studioComponentIds"],
            studio_id="studioId",
        
            # the properties below are optional
            description="description",
            tags={
                "tags_key": "tags"
            }
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        ec2_subnet_ids: typing.Sequence[builtins.str],
        launch_profile_protocol_versions: typing.Sequence[builtins.str],
        name: builtins.str,
        stream_configuration: typing.Union["CfnLaunchProfile.StreamConfigurationProperty", _IResolvable_da3f097b],
        studio_component_ids: typing.Sequence[builtins.str],
        studio_id: builtins.str,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::NimbleStudio::LaunchProfile``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param ec2_subnet_ids: Unique identifiers for a collection of EC2 subnets.
        :param launch_profile_protocol_versions: The version number of the protocol that is used by the launch profile. The only valid version is "2021-03-31".
        :param name: A friendly name for the launch profile.
        :param stream_configuration: A configuration for a streaming session.
        :param studio_component_ids: Unique identifiers for a collection of studio components that can be used with this launch profile.
        :param studio_id: The unique identifier for a studio resource. In Nimble Studio , all other resources are contained in a studio resource.
        :param description: A human-readable description of the launch profile.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnLaunchProfileProps(
            ec2_subnet_ids=ec2_subnet_ids,
            launch_profile_protocol_versions=launch_profile_protocol_versions,
            name=name,
            stream_configuration=stream_configuration,
            studio_component_ids=studio_component_ids,
            studio_id=studio_id,
            description=description,
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
    @jsii.member(jsii_name="attrLaunchProfileId")
    def attr_launch_profile_id(self) -> builtins.str:
        '''The unique identifier for the launch profile resource.

        :cloudformationAttribute: LaunchProfileId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLaunchProfileId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ec2SubnetIds")
    def ec2_subnet_ids(self) -> typing.List[builtins.str]:
        '''Unique identifiers for a collection of EC2 subnets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-ec2subnetids
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "ec2SubnetIds"))

    @ec2_subnet_ids.setter
    def ec2_subnet_ids(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "ec2SubnetIds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="launchProfileProtocolVersions")
    def launch_profile_protocol_versions(self) -> typing.List[builtins.str]:
        '''The version number of the protocol that is used by the launch profile.

        The only valid version is "2021-03-31".

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-launchprofileprotocolversions
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "launchProfileProtocolVersions"))

    @launch_profile_protocol_versions.setter
    def launch_profile_protocol_versions(
        self,
        value: typing.List[builtins.str],
    ) -> None:
        jsii.set(self, "launchProfileProtocolVersions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''A friendly name for the launch profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="streamConfiguration")
    def stream_configuration(
        self,
    ) -> typing.Union["CfnLaunchProfile.StreamConfigurationProperty", _IResolvable_da3f097b]:
        '''A configuration for a streaming session.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-streamconfiguration
        '''
        return typing.cast(typing.Union["CfnLaunchProfile.StreamConfigurationProperty", _IResolvable_da3f097b], jsii.get(self, "streamConfiguration"))

    @stream_configuration.setter
    def stream_configuration(
        self,
        value: typing.Union["CfnLaunchProfile.StreamConfigurationProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "streamConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="studioComponentIds")
    def studio_component_ids(self) -> typing.List[builtins.str]:
        '''Unique identifiers for a collection of studio components that can be used with this launch profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-studiocomponentids
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "studioComponentIds"))

    @studio_component_ids.setter
    def studio_component_ids(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "studioComponentIds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="studioId")
    def studio_id(self) -> builtins.str:
        '''The unique identifier for a studio resource.

        In Nimble Studio , all other resources are contained in a studio resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-studioid
        '''
        return typing.cast(builtins.str, jsii.get(self, "studioId"))

    @studio_id.setter
    def studio_id(self, value: builtins.str) -> None:
        jsii.set(self, "studioId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A human-readable description of the launch profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_nimblestudio.CfnLaunchProfile.StreamConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "clipboard_mode": "clipboardMode",
            "ec2_instance_types": "ec2InstanceTypes",
            "streaming_image_ids": "streamingImageIds",
            "max_session_length_in_minutes": "maxSessionLengthInMinutes",
            "max_stopped_session_length_in_minutes": "maxStoppedSessionLengthInMinutes",
            "session_storage": "sessionStorage",
        },
    )
    class StreamConfigurationProperty:
        def __init__(
            self,
            *,
            clipboard_mode: builtins.str,
            ec2_instance_types: typing.Sequence[builtins.str],
            streaming_image_ids: typing.Sequence[builtins.str],
            max_session_length_in_minutes: typing.Optional[jsii.Number] = None,
            max_stopped_session_length_in_minutes: typing.Optional[jsii.Number] = None,
            session_storage: typing.Optional[typing.Union["CfnLaunchProfile.StreamConfigurationSessionStorageProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A configuration for a streaming session.

            :param clipboard_mode: Enable or disable the use of the system clipboard to copy and paste between the streaming session and streaming client.
            :param ec2_instance_types: The EC2 instance types that users can select from when launching a streaming session with this launch profile.
            :param streaming_image_ids: The streaming images that users can select from when launching a streaming session with this launch profile.
            :param max_session_length_in_minutes: The length of time, in minutes, that a streaming session can be active before it is stopped or terminated. After this point, Nimble Studio automatically terminates or stops the session. The default length of time is 690 minutes, and the maximum length of time is 30 days.
            :param max_stopped_session_length_in_minutes: Integer that determines if you can start and stop your sessions and how long a session can stay in the STOPPED state. The default value is 0. The maximum value is 5760. If the value is missing or set to 0, your sessions can’t be stopped. If you then call ``StopStreamingSession`` , the session fails. If the time that a session stays in the READY state exceeds the ``maxSessionLengthInMinutes`` value, the session will automatically be terminated (instead of stopped). If the value is set to a positive number, the session can be stopped. You can call ``StopStreamingSession`` to stop sessions in the READY state. If the time that a session stays in the READY state exceeds the ``maxSessionLengthInMinutes`` value, the session will automatically be stopped (instead of terminated).
            :param session_storage: (Optional) The upload storage for a streaming session.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-launchprofile-streamconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_nimblestudio as nimblestudio
                
                stream_configuration_property = nimblestudio.CfnLaunchProfile.StreamConfigurationProperty(
                    clipboard_mode="clipboardMode",
                    ec2_instance_types=["ec2InstanceTypes"],
                    streaming_image_ids=["streamingImageIds"],
                
                    # the properties below are optional
                    max_session_length_in_minutes=123,
                    max_stopped_session_length_in_minutes=123,
                    session_storage=nimblestudio.CfnLaunchProfile.StreamConfigurationSessionStorageProperty(
                        mode=["mode"],
                        root=nimblestudio.CfnLaunchProfile.StreamingSessionStorageRootProperty(
                            linux="linux",
                            windows="windows"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "clipboard_mode": clipboard_mode,
                "ec2_instance_types": ec2_instance_types,
                "streaming_image_ids": streaming_image_ids,
            }
            if max_session_length_in_minutes is not None:
                self._values["max_session_length_in_minutes"] = max_session_length_in_minutes
            if max_stopped_session_length_in_minutes is not None:
                self._values["max_stopped_session_length_in_minutes"] = max_stopped_session_length_in_minutes
            if session_storage is not None:
                self._values["session_storage"] = session_storage

        @builtins.property
        def clipboard_mode(self) -> builtins.str:
            '''Enable or disable the use of the system clipboard to copy and paste between the streaming session and streaming client.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-launchprofile-streamconfiguration.html#cfn-nimblestudio-launchprofile-streamconfiguration-clipboardmode
            '''
            result = self._values.get("clipboard_mode")
            assert result is not None, "Required property 'clipboard_mode' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def ec2_instance_types(self) -> typing.List[builtins.str]:
            '''The EC2 instance types that users can select from when launching a streaming session with this launch profile.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-launchprofile-streamconfiguration.html#cfn-nimblestudio-launchprofile-streamconfiguration-ec2instancetypes
            '''
            result = self._values.get("ec2_instance_types")
            assert result is not None, "Required property 'ec2_instance_types' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def streaming_image_ids(self) -> typing.List[builtins.str]:
            '''The streaming images that users can select from when launching a streaming session with this launch profile.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-launchprofile-streamconfiguration.html#cfn-nimblestudio-launchprofile-streamconfiguration-streamingimageids
            '''
            result = self._values.get("streaming_image_ids")
            assert result is not None, "Required property 'streaming_image_ids' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def max_session_length_in_minutes(self) -> typing.Optional[jsii.Number]:
            '''The length of time, in minutes, that a streaming session can be active before it is stopped or terminated.

            After this point, Nimble Studio automatically terminates or stops the session. The default length of time is 690 minutes, and the maximum length of time is 30 days.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-launchprofile-streamconfiguration.html#cfn-nimblestudio-launchprofile-streamconfiguration-maxsessionlengthinminutes
            '''
            result = self._values.get("max_session_length_in_minutes")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def max_stopped_session_length_in_minutes(self) -> typing.Optional[jsii.Number]:
            '''Integer that determines if you can start and stop your sessions and how long a session can stay in the STOPPED state.

            The default value is 0. The maximum value is 5760.

            If the value is missing or set to 0, your sessions can’t be stopped. If you then call ``StopStreamingSession`` , the session fails. If the time that a session stays in the READY state exceeds the ``maxSessionLengthInMinutes`` value, the session will automatically be terminated (instead of stopped).

            If the value is set to a positive number, the session can be stopped. You can call ``StopStreamingSession`` to stop sessions in the READY state. If the time that a session stays in the READY state exceeds the ``maxSessionLengthInMinutes`` value, the session will automatically be stopped (instead of terminated).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-launchprofile-streamconfiguration.html#cfn-nimblestudio-launchprofile-streamconfiguration-maxstoppedsessionlengthinminutes
            '''
            result = self._values.get("max_stopped_session_length_in_minutes")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def session_storage(
            self,
        ) -> typing.Optional[typing.Union["CfnLaunchProfile.StreamConfigurationSessionStorageProperty", _IResolvable_da3f097b]]:
            '''(Optional) The upload storage for a streaming session.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-launchprofile-streamconfiguration.html#cfn-nimblestudio-launchprofile-streamconfiguration-sessionstorage
            '''
            result = self._values.get("session_storage")
            return typing.cast(typing.Optional[typing.Union["CfnLaunchProfile.StreamConfigurationSessionStorageProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StreamConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_nimblestudio.CfnLaunchProfile.StreamConfigurationSessionStorageProperty",
        jsii_struct_bases=[],
        name_mapping={"mode": "mode", "root": "root"},
    )
    class StreamConfigurationSessionStorageProperty:
        def __init__(
            self,
            *,
            mode: typing.Optional[typing.Sequence[builtins.str]] = None,
            root: typing.Optional[typing.Union["CfnLaunchProfile.StreamingSessionStorageRootProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The configuration for a streaming session’s upload storage.

            :param mode: Allows artists to upload files to their workstations. The only valid option is ``UPLOAD`` .
            :param root: The configuration for the upload storage root of the streaming session.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-launchprofile-streamconfigurationsessionstorage.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_nimblestudio as nimblestudio
                
                stream_configuration_session_storage_property = nimblestudio.CfnLaunchProfile.StreamConfigurationSessionStorageProperty(
                    mode=["mode"],
                    root=nimblestudio.CfnLaunchProfile.StreamingSessionStorageRootProperty(
                        linux="linux",
                        windows="windows"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if mode is not None:
                self._values["mode"] = mode
            if root is not None:
                self._values["root"] = root

        @builtins.property
        def mode(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Allows artists to upload files to their workstations.

            The only valid option is ``UPLOAD`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-launchprofile-streamconfigurationsessionstorage.html#cfn-nimblestudio-launchprofile-streamconfigurationsessionstorage-mode
            '''
            result = self._values.get("mode")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def root(
            self,
        ) -> typing.Optional[typing.Union["CfnLaunchProfile.StreamingSessionStorageRootProperty", _IResolvable_da3f097b]]:
            '''The configuration for the upload storage root of the streaming session.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-launchprofile-streamconfigurationsessionstorage.html#cfn-nimblestudio-launchprofile-streamconfigurationsessionstorage-root
            '''
            result = self._values.get("root")
            return typing.cast(typing.Optional[typing.Union["CfnLaunchProfile.StreamingSessionStorageRootProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StreamConfigurationSessionStorageProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_nimblestudio.CfnLaunchProfile.StreamingSessionStorageRootProperty",
        jsii_struct_bases=[],
        name_mapping={"linux": "linux", "windows": "windows"},
    )
    class StreamingSessionStorageRootProperty:
        def __init__(
            self,
            *,
            linux: typing.Optional[builtins.str] = None,
            windows: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The upload storage root location (folder) on streaming workstations where files are uploaded.

            :param linux: The folder path in Linux workstations where files are uploaded.
            :param windows: The folder path in Windows workstations where files are uploaded.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-launchprofile-streamingsessionstorageroot.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_nimblestudio as nimblestudio
                
                streaming_session_storage_root_property = nimblestudio.CfnLaunchProfile.StreamingSessionStorageRootProperty(
                    linux="linux",
                    windows="windows"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if linux is not None:
                self._values["linux"] = linux
            if windows is not None:
                self._values["windows"] = windows

        @builtins.property
        def linux(self) -> typing.Optional[builtins.str]:
            '''The folder path in Linux workstations where files are uploaded.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-launchprofile-streamingsessionstorageroot.html#cfn-nimblestudio-launchprofile-streamingsessionstorageroot-linux
            '''
            result = self._values.get("linux")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def windows(self) -> typing.Optional[builtins.str]:
            '''The folder path in Windows workstations where files are uploaded.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-launchprofile-streamingsessionstorageroot.html#cfn-nimblestudio-launchprofile-streamingsessionstorageroot-windows
            '''
            result = self._values.get("windows")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StreamingSessionStorageRootProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_nimblestudio.CfnLaunchProfileProps",
    jsii_struct_bases=[],
    name_mapping={
        "ec2_subnet_ids": "ec2SubnetIds",
        "launch_profile_protocol_versions": "launchProfileProtocolVersions",
        "name": "name",
        "stream_configuration": "streamConfiguration",
        "studio_component_ids": "studioComponentIds",
        "studio_id": "studioId",
        "description": "description",
        "tags": "tags",
    },
)
class CfnLaunchProfileProps:
    def __init__(
        self,
        *,
        ec2_subnet_ids: typing.Sequence[builtins.str],
        launch_profile_protocol_versions: typing.Sequence[builtins.str],
        name: builtins.str,
        stream_configuration: typing.Union[CfnLaunchProfile.StreamConfigurationProperty, _IResolvable_da3f097b],
        studio_component_ids: typing.Sequence[builtins.str],
        studio_id: builtins.str,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnLaunchProfile``.

        :param ec2_subnet_ids: Unique identifiers for a collection of EC2 subnets.
        :param launch_profile_protocol_versions: The version number of the protocol that is used by the launch profile. The only valid version is "2021-03-31".
        :param name: A friendly name for the launch profile.
        :param stream_configuration: A configuration for a streaming session.
        :param studio_component_ids: Unique identifiers for a collection of studio components that can be used with this launch profile.
        :param studio_id: The unique identifier for a studio resource. In Nimble Studio , all other resources are contained in a studio resource.
        :param description: A human-readable description of the launch profile.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_nimblestudio as nimblestudio
            
            cfn_launch_profile_props = nimblestudio.CfnLaunchProfileProps(
                ec2_subnet_ids=["ec2SubnetIds"],
                launch_profile_protocol_versions=["launchProfileProtocolVersions"],
                name="name",
                stream_configuration=nimblestudio.CfnLaunchProfile.StreamConfigurationProperty(
                    clipboard_mode="clipboardMode",
                    ec2_instance_types=["ec2InstanceTypes"],
                    streaming_image_ids=["streamingImageIds"],
            
                    # the properties below are optional
                    max_session_length_in_minutes=123,
                    max_stopped_session_length_in_minutes=123,
                    session_storage=nimblestudio.CfnLaunchProfile.StreamConfigurationSessionStorageProperty(
                        mode=["mode"],
                        root=nimblestudio.CfnLaunchProfile.StreamingSessionStorageRootProperty(
                            linux="linux",
                            windows="windows"
                        )
                    )
                ),
                studio_component_ids=["studioComponentIds"],
                studio_id="studioId",
            
                # the properties below are optional
                description="description",
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "ec2_subnet_ids": ec2_subnet_ids,
            "launch_profile_protocol_versions": launch_profile_protocol_versions,
            "name": name,
            "stream_configuration": stream_configuration,
            "studio_component_ids": studio_component_ids,
            "studio_id": studio_id,
        }
        if description is not None:
            self._values["description"] = description
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def ec2_subnet_ids(self) -> typing.List[builtins.str]:
        '''Unique identifiers for a collection of EC2 subnets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-ec2subnetids
        '''
        result = self._values.get("ec2_subnet_ids")
        assert result is not None, "Required property 'ec2_subnet_ids' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def launch_profile_protocol_versions(self) -> typing.List[builtins.str]:
        '''The version number of the protocol that is used by the launch profile.

        The only valid version is "2021-03-31".

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-launchprofileprotocolversions
        '''
        result = self._values.get("launch_profile_protocol_versions")
        assert result is not None, "Required property 'launch_profile_protocol_versions' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def name(self) -> builtins.str:
        '''A friendly name for the launch profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def stream_configuration(
        self,
    ) -> typing.Union[CfnLaunchProfile.StreamConfigurationProperty, _IResolvable_da3f097b]:
        '''A configuration for a streaming session.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-streamconfiguration
        '''
        result = self._values.get("stream_configuration")
        assert result is not None, "Required property 'stream_configuration' is missing"
        return typing.cast(typing.Union[CfnLaunchProfile.StreamConfigurationProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def studio_component_ids(self) -> typing.List[builtins.str]:
        '''Unique identifiers for a collection of studio components that can be used with this launch profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-studiocomponentids
        '''
        result = self._values.get("studio_component_ids")
        assert result is not None, "Required property 'studio_component_ids' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def studio_id(self) -> builtins.str:
        '''The unique identifier for a studio resource.

        In Nimble Studio , all other resources are contained in a studio resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-studioid
        '''
        result = self._values.get("studio_id")
        assert result is not None, "Required property 'studio_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A human-readable description of the launch profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-launchprofile.html#cfn-nimblestudio-launchprofile-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnLaunchProfileProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnStreamingImage(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStreamingImage",
):
    '''A CloudFormation ``AWS::NimbleStudio::StreamingImage``.

    The ``AWS::NimbleStudio::StreamingImage`` resource creates a streaming image in a studio. A streaming image defines the operating system and software to be used in an  streaming session.

    :cloudformationResource: AWS::NimbleStudio::StreamingImage
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-streamingimage.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_nimblestudio as nimblestudio
        
        cfn_streaming_image = nimblestudio.CfnStreamingImage(self, "MyCfnStreamingImage",
            ec2_image_id="ec2ImageId",
            name="name",
            studio_id="studioId",
        
            # the properties below are optional
            description="description",
            tags={
                "tags_key": "tags"
            }
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        ec2_image_id: builtins.str,
        name: builtins.str,
        studio_id: builtins.str,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::NimbleStudio::StreamingImage``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param ec2_image_id: The ID of an EC2 machine image with which to create the streaming image.
        :param name: A friendly name for a streaming image resource.
        :param studio_id: The unique identifier for a studio resource. In Nimble Studio , all other resources are contained in a studio resource.
        :param description: A human-readable description of the streaming image.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnStreamingImageProps(
            ec2_image_id=ec2_image_id,
            name=name,
            studio_id=studio_id,
            description=description,
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
    @jsii.member(jsii_name="attrEulaIds")
    def attr_eula_ids(self) -> typing.List[builtins.str]:
        '''The list of IDs of EULAs that must be accepted before a streaming session can be started using this streaming image.

        :cloudformationAttribute: EulaIds
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrEulaIds"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrOwner")
    def attr_owner(self) -> builtins.str:
        '''The owner of the streaming image, either the studioId that contains the streaming image or 'amazon' for images that are provided by  .

        :cloudformationAttribute: Owner
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrOwner"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrPlatform")
    def attr_platform(self) -> builtins.str:
        '''The platform of the streaming image, either WINDOWS or LINUX.

        :cloudformationAttribute: Platform
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrPlatform"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStreamingImageId")
    def attr_streaming_image_id(self) -> builtins.str:
        '''The unique identifier for the streaming image resource.

        :cloudformationAttribute: StreamingImageId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStreamingImageId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-streamingimage.html#cfn-nimblestudio-streamingimage-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ec2ImageId")
    def ec2_image_id(self) -> builtins.str:
        '''The ID of an EC2 machine image with which to create the streaming image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-streamingimage.html#cfn-nimblestudio-streamingimage-ec2imageid
        '''
        return typing.cast(builtins.str, jsii.get(self, "ec2ImageId"))

    @ec2_image_id.setter
    def ec2_image_id(self, value: builtins.str) -> None:
        jsii.set(self, "ec2ImageId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''A friendly name for a streaming image resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-streamingimage.html#cfn-nimblestudio-streamingimage-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="studioId")
    def studio_id(self) -> builtins.str:
        '''The unique identifier for a studio resource.

        In Nimble Studio , all other resources are contained in a studio resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-streamingimage.html#cfn-nimblestudio-streamingimage-studioid
        '''
        return typing.cast(builtins.str, jsii.get(self, "studioId"))

    @studio_id.setter
    def studio_id(self, value: builtins.str) -> None:
        jsii.set(self, "studioId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A human-readable description of the streaming image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-streamingimage.html#cfn-nimblestudio-streamingimage-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStreamingImageProps",
    jsii_struct_bases=[],
    name_mapping={
        "ec2_image_id": "ec2ImageId",
        "name": "name",
        "studio_id": "studioId",
        "description": "description",
        "tags": "tags",
    },
)
class CfnStreamingImageProps:
    def __init__(
        self,
        *,
        ec2_image_id: builtins.str,
        name: builtins.str,
        studio_id: builtins.str,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnStreamingImage``.

        :param ec2_image_id: The ID of an EC2 machine image with which to create the streaming image.
        :param name: A friendly name for a streaming image resource.
        :param studio_id: The unique identifier for a studio resource. In Nimble Studio , all other resources are contained in a studio resource.
        :param description: A human-readable description of the streaming image.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-streamingimage.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_nimblestudio as nimblestudio
            
            cfn_streaming_image_props = nimblestudio.CfnStreamingImageProps(
                ec2_image_id="ec2ImageId",
                name="name",
                studio_id="studioId",
            
                # the properties below are optional
                description="description",
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "ec2_image_id": ec2_image_id,
            "name": name,
            "studio_id": studio_id,
        }
        if description is not None:
            self._values["description"] = description
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def ec2_image_id(self) -> builtins.str:
        '''The ID of an EC2 machine image with which to create the streaming image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-streamingimage.html#cfn-nimblestudio-streamingimage-ec2imageid
        '''
        result = self._values.get("ec2_image_id")
        assert result is not None, "Required property 'ec2_image_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''A friendly name for a streaming image resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-streamingimage.html#cfn-nimblestudio-streamingimage-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def studio_id(self) -> builtins.str:
        '''The unique identifier for a studio resource.

        In Nimble Studio , all other resources are contained in a studio resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-streamingimage.html#cfn-nimblestudio-streamingimage-studioid
        '''
        result = self._values.get("studio_id")
        assert result is not None, "Required property 'studio_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A human-readable description of the streaming image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-streamingimage.html#cfn-nimblestudio-streamingimage-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-streamingimage.html#cfn-nimblestudio-streamingimage-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnStreamingImageProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnStudio(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStudio",
):
    '''A CloudFormation ``AWS::NimbleStudio::Studio``.

    The ``AWS::NimbleStudio::Studio`` resource creates a new studio resource. In  , all other resources are contained in a studio.

    When creating a studio, two IAM roles must be provided: the admin role and the user role. These roles are assumed by your users when they log in to the  portal. The user role must have the AmazonNimbleStudio-StudioUser managed policy attached for the portal to function properly. The Admin Role must have the AmazonNimbleStudio-StudioAdmin managed policy attached for the portal to function properly.

    You can optionally specify an AWS Key Management Service key in the StudioEncryptionConfiguration. In Nimble Studio, resource names, descriptions, initialization scripts, and other data you provide are always encrypted at rest using an AWS Key Management Service key. By default, this key is owned by AWS and managed on your behalf. You may provide your own AWS Key Management Service key when calling CreateStudio to encrypt this data using a key that you own and manage. When providing an AWS Key Management Service key during studio creation,  creates AWS Key Management Service grants in your account to provide your studio user and admin roles access to these AWS Key Management Service keys. If you delete this grant, the studio will no longer be accessible to your portal users. If you delete the studio AWS Key Management Service key, your studio will no longer be accessible.

    :cloudformationResource: AWS::NimbleStudio::Studio
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studio.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_nimblestudio as nimblestudio
        
        cfn_studio = nimblestudio.CfnStudio(self, "MyCfnStudio",
            admin_role_arn="adminRoleArn",
            display_name="displayName",
            studio_name="studioName",
            user_role_arn="userRoleArn",
        
            # the properties below are optional
            studio_encryption_configuration=nimblestudio.CfnStudio.StudioEncryptionConfigurationProperty(
                key_type="keyType",
        
                # the properties below are optional
                key_arn="keyArn"
            ),
            tags={
                "tags_key": "tags"
            }
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        admin_role_arn: builtins.str,
        display_name: builtins.str,
        studio_name: builtins.str,
        user_role_arn: builtins.str,
        studio_encryption_configuration: typing.Optional[typing.Union["CfnStudio.StudioEncryptionConfigurationProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::NimbleStudio::Studio``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param admin_role_arn: The IAM role that studio admins assume when logging in to the Nimble Studio portal.
        :param display_name: A friendly name for the studio.
        :param studio_name: The name of the studio, as included in the URL when accessing it in the Nimble Studio portal.
        :param user_role_arn: The IAM role that studio users assume when logging in to the Nimble Studio portal.
        :param studio_encryption_configuration: Configuration of the encryption method that is used for the studio.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnStudioProps(
            admin_role_arn=admin_role_arn,
            display_name=display_name,
            studio_name=studio_name,
            user_role_arn=user_role_arn,
            studio_encryption_configuration=studio_encryption_configuration,
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
    @jsii.member(jsii_name="attrHomeRegion")
    def attr_home_region(self) -> builtins.str:
        '''The AWS Region where the studio resource is located.

        For example, ``us-west-2`` .

        :cloudformationAttribute: HomeRegion
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrHomeRegion"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSsoClientId")
    def attr_sso_client_id(self) -> builtins.str:
        '''The AWS SSO application client ID that is used to integrate with AWS SSO , which enables AWS SSO users to log into the  portal.

        :cloudformationAttribute: SsoClientId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSsoClientId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStudioId")
    def attr_studio_id(self) -> builtins.str:
        '''The unique identifier for the studio resource.

        :cloudformationAttribute: StudioId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStudioId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStudioUrl")
    def attr_studio_url(self) -> builtins.str:
        '''The unique identifier for the studio resource.

        :cloudformationAttribute: StudioUrl
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStudioUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studio.html#cfn-nimblestudio-studio-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="adminRoleArn")
    def admin_role_arn(self) -> builtins.str:
        '''The IAM role that studio admins assume when logging in to the Nimble Studio portal.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studio.html#cfn-nimblestudio-studio-adminrolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "adminRoleArn"))

    @admin_role_arn.setter
    def admin_role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "adminRoleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="displayName")
    def display_name(self) -> builtins.str:
        '''A friendly name for the studio.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studio.html#cfn-nimblestudio-studio-displayname
        '''
        return typing.cast(builtins.str, jsii.get(self, "displayName"))

    @display_name.setter
    def display_name(self, value: builtins.str) -> None:
        jsii.set(self, "displayName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="studioName")
    def studio_name(self) -> builtins.str:
        '''The name of the studio, as included in the URL when accessing it in the Nimble Studio portal.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studio.html#cfn-nimblestudio-studio-studioname
        '''
        return typing.cast(builtins.str, jsii.get(self, "studioName"))

    @studio_name.setter
    def studio_name(self, value: builtins.str) -> None:
        jsii.set(self, "studioName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userRoleArn")
    def user_role_arn(self) -> builtins.str:
        '''The IAM role that studio users assume when logging in to the Nimble Studio portal.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studio.html#cfn-nimblestudio-studio-userrolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "userRoleArn"))

    @user_role_arn.setter
    def user_role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "userRoleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="studioEncryptionConfiguration")
    def studio_encryption_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnStudio.StudioEncryptionConfigurationProperty", _IResolvable_da3f097b]]:
        '''Configuration of the encryption method that is used for the studio.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studio.html#cfn-nimblestudio-studio-studioencryptionconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnStudio.StudioEncryptionConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "studioEncryptionConfiguration"))

    @studio_encryption_configuration.setter
    def studio_encryption_configuration(
        self,
        value: typing.Optional[typing.Union["CfnStudio.StudioEncryptionConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "studioEncryptionConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStudio.StudioEncryptionConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"key_type": "keyType", "key_arn": "keyArn"},
    )
    class StudioEncryptionConfigurationProperty:
        def __init__(
            self,
            *,
            key_type: builtins.str,
            key_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Configuration of the encryption method that is used for the studio.

            :param key_type: The type of KMS key that is used to encrypt studio data.
            :param key_arn: The ARN for a KMS key that is used to encrypt studio data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studio-studioencryptionconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_nimblestudio as nimblestudio
                
                studio_encryption_configuration_property = nimblestudio.CfnStudio.StudioEncryptionConfigurationProperty(
                    key_type="keyType",
                
                    # the properties below are optional
                    key_arn="keyArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "key_type": key_type,
            }
            if key_arn is not None:
                self._values["key_arn"] = key_arn

        @builtins.property
        def key_type(self) -> builtins.str:
            '''The type of KMS key that is used to encrypt studio data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studio-studioencryptionconfiguration.html#cfn-nimblestudio-studio-studioencryptionconfiguration-keytype
            '''
            result = self._values.get("key_type")
            assert result is not None, "Required property 'key_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def key_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN for a KMS key that is used to encrypt studio data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studio-studioencryptionconfiguration.html#cfn-nimblestudio-studio-studioencryptionconfiguration-keyarn
            '''
            result = self._values.get("key_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StudioEncryptionConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnStudioComponent(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStudioComponent",
):
    '''A CloudFormation ``AWS::NimbleStudio::StudioComponent``.

    The ``AWS::NimbleStudio::StudioComponent`` resource represents a network resource that is used by a studio's users and workflows. A typical studio contains studio components for the following: a render farm, an Active Directory, a licensing service, and a shared file system.

    Access to a studio component is managed by specifying security groups for the resource, as well as its endpoint.

    A studio component also has a set of initialization scripts, which are returned by ``GetLaunchProfileInitialization`` . These initialization scripts run on streaming sessions when they start. They provide users with flexibility in controlling how studio resources are configured on a streaming session.

    :cloudformationResource: AWS::NimbleStudio::StudioComponent
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_nimblestudio as nimblestudio
        
        cfn_studio_component = nimblestudio.CfnStudioComponent(self, "MyCfnStudioComponent",
            name="name",
            studio_id="studioId",
            type="type",
        
            # the properties below are optional
            configuration=nimblestudio.CfnStudioComponent.StudioComponentConfigurationProperty(
                active_directory_configuration=nimblestudio.CfnStudioComponent.ActiveDirectoryConfigurationProperty(
                    computer_attributes=[nimblestudio.CfnStudioComponent.ActiveDirectoryComputerAttributeProperty(
                        name="name",
                        value="value"
                    )],
                    directory_id="directoryId",
                    organizational_unit_distinguished_name="organizationalUnitDistinguishedName"
                ),
                compute_farm_configuration=nimblestudio.CfnStudioComponent.ComputeFarmConfigurationProperty(
                    active_directory_user="activeDirectoryUser",
                    endpoint="endpoint"
                ),
                license_service_configuration=nimblestudio.CfnStudioComponent.LicenseServiceConfigurationProperty(
                    endpoint="endpoint"
                ),
                shared_file_system_configuration=nimblestudio.CfnStudioComponent.SharedFileSystemConfigurationProperty(
                    endpoint="endpoint",
                    file_system_id="fileSystemId",
                    linux_mount_point="linuxMountPoint",
                    share_name="shareName",
                    windows_mount_drive="windowsMountDrive"
                )
            ),
            description="description",
            ec2_security_group_ids=["ec2SecurityGroupIds"],
            initialization_scripts=[nimblestudio.CfnStudioComponent.StudioComponentInitializationScriptProperty(
                launch_profile_protocol_version="launchProfileProtocolVersion",
                platform="platform",
                run_context="runContext",
                script="script"
            )],
            script_parameters=[nimblestudio.CfnStudioComponent.ScriptParameterKeyValueProperty(
                key="key",
                value="value"
            )],
            subtype="subtype",
            tags={
                "tags_key": "tags"
            }
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        studio_id: builtins.str,
        type: builtins.str,
        configuration: typing.Optional[typing.Union["CfnStudioComponent.StudioComponentConfigurationProperty", _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        ec2_security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        initialization_scripts: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnStudioComponent.StudioComponentInitializationScriptProperty", _IResolvable_da3f097b]]]] = None,
        script_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnStudioComponent.ScriptParameterKeyValueProperty", _IResolvable_da3f097b]]]] = None,
        subtype: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::NimbleStudio::StudioComponent``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: A friendly name for the studio component resource.
        :param studio_id: The unique identifier for a studio resource. In Nimble Studio , all other resources are contained in a studio resource.
        :param type: The type of the studio component.
        :param configuration: The configuration of the studio component, based on component type.
        :param description: A human-readable description for the studio component resource.
        :param ec2_security_group_ids: The EC2 security groups that control access to the studio component.
        :param initialization_scripts: Initialization scripts for studio components.
        :param script_parameters: Parameters for the studio component scripts.
        :param subtype: The specific subtype of a studio component.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnStudioComponentProps(
            name=name,
            studio_id=studio_id,
            type=type,
            configuration=configuration,
            description=description,
            ec2_security_group_ids=ec2_security_group_ids,
            initialization_scripts=initialization_scripts,
            script_parameters=script_parameters,
            subtype=subtype,
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
    @jsii.member(jsii_name="attrStudioComponentId")
    def attr_studio_component_id(self) -> builtins.str:
        '''The unique identifier for the studio component resource.

        :cloudformationAttribute: StudioComponentId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStudioComponentId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''A friendly name for the studio component resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="studioId")
    def studio_id(self) -> builtins.str:
        '''The unique identifier for a studio resource.

        In Nimble Studio , all other resources are contained in a studio resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-studioid
        '''
        return typing.cast(builtins.str, jsii.get(self, "studioId"))

    @studio_id.setter
    def studio_id(self, value: builtins.str) -> None:
        jsii.set(self, "studioId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> builtins.str:
        '''The type of the studio component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-type
        '''
        return typing.cast(builtins.str, jsii.get(self, "type"))

    @type.setter
    def type(self, value: builtins.str) -> None:
        jsii.set(self, "type", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="configuration")
    def configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnStudioComponent.StudioComponentConfigurationProperty", _IResolvable_da3f097b]]:
        '''The configuration of the studio component, based on component type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-configuration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnStudioComponent.StudioComponentConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "configuration"))

    @configuration.setter
    def configuration(
        self,
        value: typing.Optional[typing.Union["CfnStudioComponent.StudioComponentConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "configuration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A human-readable description for the studio component resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ec2SecurityGroupIds")
    def ec2_security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The EC2 security groups that control access to the studio component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-ec2securitygroupids
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "ec2SecurityGroupIds"))

    @ec2_security_group_ids.setter
    def ec2_security_group_ids(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "ec2SecurityGroupIds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="initializationScripts")
    def initialization_scripts(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStudioComponent.StudioComponentInitializationScriptProperty", _IResolvable_da3f097b]]]]:
        '''Initialization scripts for studio components.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-initializationscripts
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStudioComponent.StudioComponentInitializationScriptProperty", _IResolvable_da3f097b]]]], jsii.get(self, "initializationScripts"))

    @initialization_scripts.setter
    def initialization_scripts(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStudioComponent.StudioComponentInitializationScriptProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "initializationScripts", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scriptParameters")
    def script_parameters(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStudioComponent.ScriptParameterKeyValueProperty", _IResolvable_da3f097b]]]]:
        '''Parameters for the studio component scripts.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-scriptparameters
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStudioComponent.ScriptParameterKeyValueProperty", _IResolvable_da3f097b]]]], jsii.get(self, "scriptParameters"))

    @script_parameters.setter
    def script_parameters(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStudioComponent.ScriptParameterKeyValueProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "scriptParameters", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subtype")
    def subtype(self) -> typing.Optional[builtins.str]:
        '''The specific subtype of a studio component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-subtype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "subtype"))

    @subtype.setter
    def subtype(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "subtype", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStudioComponent.ActiveDirectoryComputerAttributeProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "value": "value"},
    )
    class ActiveDirectoryComputerAttributeProperty:
        def __init__(
            self,
            *,
            name: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''An LDAP attribute of an Active Directory computer account, in the form of a name:value pair.

            :param name: The name for the LDAP attribute.
            :param value: The value for the LDAP attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-activedirectorycomputerattribute.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_nimblestudio as nimblestudio
                
                active_directory_computer_attribute_property = nimblestudio.CfnStudioComponent.ActiveDirectoryComputerAttributeProperty(
                    name="name",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if name is not None:
                self._values["name"] = name
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name for the LDAP attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-activedirectorycomputerattribute.html#cfn-nimblestudio-studiocomponent-activedirectorycomputerattribute-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''The value for the LDAP attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-activedirectorycomputerattribute.html#cfn-nimblestudio-studiocomponent-activedirectorycomputerattribute-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ActiveDirectoryComputerAttributeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStudioComponent.ActiveDirectoryConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "computer_attributes": "computerAttributes",
            "directory_id": "directoryId",
            "organizational_unit_distinguished_name": "organizationalUnitDistinguishedName",
        },
    )
    class ActiveDirectoryConfigurationProperty:
        def __init__(
            self,
            *,
            computer_attributes: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnStudioComponent.ActiveDirectoryComputerAttributeProperty", _IResolvable_da3f097b]]]] = None,
            directory_id: typing.Optional[builtins.str] = None,
            organizational_unit_distinguished_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The configuration for a Microsoft Active Directory (Microsoft AD) studio resource.

            :param computer_attributes: A collection of custom attributes for an Active Directory computer.
            :param directory_id: The directory ID of the Directory Service for Microsoft Active Directory to access using this studio component.
            :param organizational_unit_distinguished_name: The distinguished name (DN) and organizational unit (OU) of an Active Directory computer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-activedirectoryconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_nimblestudio as nimblestudio
                
                active_directory_configuration_property = nimblestudio.CfnStudioComponent.ActiveDirectoryConfigurationProperty(
                    computer_attributes=[nimblestudio.CfnStudioComponent.ActiveDirectoryComputerAttributeProperty(
                        name="name",
                        value="value"
                    )],
                    directory_id="directoryId",
                    organizational_unit_distinguished_name="organizationalUnitDistinguishedName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if computer_attributes is not None:
                self._values["computer_attributes"] = computer_attributes
            if directory_id is not None:
                self._values["directory_id"] = directory_id
            if organizational_unit_distinguished_name is not None:
                self._values["organizational_unit_distinguished_name"] = organizational_unit_distinguished_name

        @builtins.property
        def computer_attributes(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStudioComponent.ActiveDirectoryComputerAttributeProperty", _IResolvable_da3f097b]]]]:
            '''A collection of custom attributes for an Active Directory computer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-activedirectoryconfiguration.html#cfn-nimblestudio-studiocomponent-activedirectoryconfiguration-computerattributes
            '''
            result = self._values.get("computer_attributes")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStudioComponent.ActiveDirectoryComputerAttributeProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def directory_id(self) -> typing.Optional[builtins.str]:
            '''The directory ID of the Directory Service for Microsoft Active Directory to access using this studio component.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-activedirectoryconfiguration.html#cfn-nimblestudio-studiocomponent-activedirectoryconfiguration-directoryid
            '''
            result = self._values.get("directory_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def organizational_unit_distinguished_name(
            self,
        ) -> typing.Optional[builtins.str]:
            '''The distinguished name (DN) and organizational unit (OU) of an Active Directory computer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-activedirectoryconfiguration.html#cfn-nimblestudio-studiocomponent-activedirectoryconfiguration-organizationalunitdistinguishedname
            '''
            result = self._values.get("organizational_unit_distinguished_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ActiveDirectoryConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStudioComponent.ComputeFarmConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "active_directory_user": "activeDirectoryUser",
            "endpoint": "endpoint",
        },
    )
    class ComputeFarmConfigurationProperty:
        def __init__(
            self,
            *,
            active_directory_user: typing.Optional[builtins.str] = None,
            endpoint: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The configuration for a render farm that is associated with a studio resource.

            :param active_directory_user: The name of an Active Directory user that is used on ComputeFarm worker instances.
            :param endpoint: The endpoint of the ComputeFarm that is accessed by the studio component resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-computefarmconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_nimblestudio as nimblestudio
                
                compute_farm_configuration_property = nimblestudio.CfnStudioComponent.ComputeFarmConfigurationProperty(
                    active_directory_user="activeDirectoryUser",
                    endpoint="endpoint"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if active_directory_user is not None:
                self._values["active_directory_user"] = active_directory_user
            if endpoint is not None:
                self._values["endpoint"] = endpoint

        @builtins.property
        def active_directory_user(self) -> typing.Optional[builtins.str]:
            '''The name of an Active Directory user that is used on ComputeFarm worker instances.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-computefarmconfiguration.html#cfn-nimblestudio-studiocomponent-computefarmconfiguration-activedirectoryuser
            '''
            result = self._values.get("active_directory_user")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def endpoint(self) -> typing.Optional[builtins.str]:
            '''The endpoint of the ComputeFarm that is accessed by the studio component resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-computefarmconfiguration.html#cfn-nimblestudio-studiocomponent-computefarmconfiguration-endpoint
            '''
            result = self._values.get("endpoint")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComputeFarmConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStudioComponent.LicenseServiceConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"endpoint": "endpoint"},
    )
    class LicenseServiceConfigurationProperty:
        def __init__(self, *, endpoint: typing.Optional[builtins.str] = None) -> None:
            '''The configuration for a license service that is associated with a studio resource.

            :param endpoint: The endpoint of the license service that is accessed by the studio component resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-licenseserviceconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_nimblestudio as nimblestudio
                
                license_service_configuration_property = nimblestudio.CfnStudioComponent.LicenseServiceConfigurationProperty(
                    endpoint="endpoint"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if endpoint is not None:
                self._values["endpoint"] = endpoint

        @builtins.property
        def endpoint(self) -> typing.Optional[builtins.str]:
            '''The endpoint of the license service that is accessed by the studio component resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-licenseserviceconfiguration.html#cfn-nimblestudio-studiocomponent-licenseserviceconfiguration-endpoint
            '''
            result = self._values.get("endpoint")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LicenseServiceConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStudioComponent.ScriptParameterKeyValueProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class ScriptParameterKeyValueProperty:
        def __init__(
            self,
            *,
            key: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A parameter for a studio component script, in the form of a key:value pair.

            :param key: A script parameter key.
            :param value: A script parameter value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-scriptparameterkeyvalue.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_nimblestudio as nimblestudio
                
                script_parameter_key_value_property = nimblestudio.CfnStudioComponent.ScriptParameterKeyValueProperty(
                    key="key",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if key is not None:
                self._values["key"] = key
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def key(self) -> typing.Optional[builtins.str]:
            '''A script parameter key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-scriptparameterkeyvalue.html#cfn-nimblestudio-studiocomponent-scriptparameterkeyvalue-key
            '''
            result = self._values.get("key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''A script parameter value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-scriptparameterkeyvalue.html#cfn-nimblestudio-studiocomponent-scriptparameterkeyvalue-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScriptParameterKeyValueProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStudioComponent.SharedFileSystemConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "endpoint": "endpoint",
            "file_system_id": "fileSystemId",
            "linux_mount_point": "linuxMountPoint",
            "share_name": "shareName",
            "windows_mount_drive": "windowsMountDrive",
        },
    )
    class SharedFileSystemConfigurationProperty:
        def __init__(
            self,
            *,
            endpoint: typing.Optional[builtins.str] = None,
            file_system_id: typing.Optional[builtins.str] = None,
            linux_mount_point: typing.Optional[builtins.str] = None,
            share_name: typing.Optional[builtins.str] = None,
            windows_mount_drive: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The configuration for a shared file storage system that is associated with a studio resource.

            :param endpoint: The endpoint of the shared file system that is accessed by the studio component resource.
            :param file_system_id: The unique identifier for a file system.
            :param linux_mount_point: The mount location for a shared file system on a Linux virtual workstation.
            :param share_name: The name of the file share.
            :param windows_mount_drive: The mount location for a shared file system on a Windows virtual workstation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-sharedfilesystemconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_nimblestudio as nimblestudio
                
                shared_file_system_configuration_property = nimblestudio.CfnStudioComponent.SharedFileSystemConfigurationProperty(
                    endpoint="endpoint",
                    file_system_id="fileSystemId",
                    linux_mount_point="linuxMountPoint",
                    share_name="shareName",
                    windows_mount_drive="windowsMountDrive"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if endpoint is not None:
                self._values["endpoint"] = endpoint
            if file_system_id is not None:
                self._values["file_system_id"] = file_system_id
            if linux_mount_point is not None:
                self._values["linux_mount_point"] = linux_mount_point
            if share_name is not None:
                self._values["share_name"] = share_name
            if windows_mount_drive is not None:
                self._values["windows_mount_drive"] = windows_mount_drive

        @builtins.property
        def endpoint(self) -> typing.Optional[builtins.str]:
            '''The endpoint of the shared file system that is accessed by the studio component resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-sharedfilesystemconfiguration.html#cfn-nimblestudio-studiocomponent-sharedfilesystemconfiguration-endpoint
            '''
            result = self._values.get("endpoint")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def file_system_id(self) -> typing.Optional[builtins.str]:
            '''The unique identifier for a file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-sharedfilesystemconfiguration.html#cfn-nimblestudio-studiocomponent-sharedfilesystemconfiguration-filesystemid
            '''
            result = self._values.get("file_system_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def linux_mount_point(self) -> typing.Optional[builtins.str]:
            '''The mount location for a shared file system on a Linux virtual workstation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-sharedfilesystemconfiguration.html#cfn-nimblestudio-studiocomponent-sharedfilesystemconfiguration-linuxmountpoint
            '''
            result = self._values.get("linux_mount_point")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def share_name(self) -> typing.Optional[builtins.str]:
            '''The name of the file share.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-sharedfilesystemconfiguration.html#cfn-nimblestudio-studiocomponent-sharedfilesystemconfiguration-sharename
            '''
            result = self._values.get("share_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def windows_mount_drive(self) -> typing.Optional[builtins.str]:
            '''The mount location for a shared file system on a Windows virtual workstation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-sharedfilesystemconfiguration.html#cfn-nimblestudio-studiocomponent-sharedfilesystemconfiguration-windowsmountdrive
            '''
            result = self._values.get("windows_mount_drive")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SharedFileSystemConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStudioComponent.StudioComponentConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "active_directory_configuration": "activeDirectoryConfiguration",
            "compute_farm_configuration": "computeFarmConfiguration",
            "license_service_configuration": "licenseServiceConfiguration",
            "shared_file_system_configuration": "sharedFileSystemConfiguration",
        },
    )
    class StudioComponentConfigurationProperty:
        def __init__(
            self,
            *,
            active_directory_configuration: typing.Optional[typing.Union["CfnStudioComponent.ActiveDirectoryConfigurationProperty", _IResolvable_da3f097b]] = None,
            compute_farm_configuration: typing.Optional[typing.Union["CfnStudioComponent.ComputeFarmConfigurationProperty", _IResolvable_da3f097b]] = None,
            license_service_configuration: typing.Optional[typing.Union["CfnStudioComponent.LicenseServiceConfigurationProperty", _IResolvable_da3f097b]] = None,
            shared_file_system_configuration: typing.Optional[typing.Union["CfnStudioComponent.SharedFileSystemConfigurationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The configuration of the studio component, based on component type.

            :param active_directory_configuration: The configuration for a Microsoft Active Directory (Microsoft AD) studio resource.
            :param compute_farm_configuration: The configuration for a render farm that is associated with a studio resource.
            :param license_service_configuration: The configuration for a license service that is associated with a studio resource.
            :param shared_file_system_configuration: The configuration for a shared file storage system that is associated with a studio resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-studiocomponentconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_nimblestudio as nimblestudio
                
                studio_component_configuration_property = nimblestudio.CfnStudioComponent.StudioComponentConfigurationProperty(
                    active_directory_configuration=nimblestudio.CfnStudioComponent.ActiveDirectoryConfigurationProperty(
                        computer_attributes=[nimblestudio.CfnStudioComponent.ActiveDirectoryComputerAttributeProperty(
                            name="name",
                            value="value"
                        )],
                        directory_id="directoryId",
                        organizational_unit_distinguished_name="organizationalUnitDistinguishedName"
                    ),
                    compute_farm_configuration=nimblestudio.CfnStudioComponent.ComputeFarmConfigurationProperty(
                        active_directory_user="activeDirectoryUser",
                        endpoint="endpoint"
                    ),
                    license_service_configuration=nimblestudio.CfnStudioComponent.LicenseServiceConfigurationProperty(
                        endpoint="endpoint"
                    ),
                    shared_file_system_configuration=nimblestudio.CfnStudioComponent.SharedFileSystemConfigurationProperty(
                        endpoint="endpoint",
                        file_system_id="fileSystemId",
                        linux_mount_point="linuxMountPoint",
                        share_name="shareName",
                        windows_mount_drive="windowsMountDrive"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if active_directory_configuration is not None:
                self._values["active_directory_configuration"] = active_directory_configuration
            if compute_farm_configuration is not None:
                self._values["compute_farm_configuration"] = compute_farm_configuration
            if license_service_configuration is not None:
                self._values["license_service_configuration"] = license_service_configuration
            if shared_file_system_configuration is not None:
                self._values["shared_file_system_configuration"] = shared_file_system_configuration

        @builtins.property
        def active_directory_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnStudioComponent.ActiveDirectoryConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration for a Microsoft Active Directory (Microsoft AD) studio resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-studiocomponentconfiguration.html#cfn-nimblestudio-studiocomponent-studiocomponentconfiguration-activedirectoryconfiguration
            '''
            result = self._values.get("active_directory_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnStudioComponent.ActiveDirectoryConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def compute_farm_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnStudioComponent.ComputeFarmConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration for a render farm that is associated with a studio resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-studiocomponentconfiguration.html#cfn-nimblestudio-studiocomponent-studiocomponentconfiguration-computefarmconfiguration
            '''
            result = self._values.get("compute_farm_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnStudioComponent.ComputeFarmConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def license_service_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnStudioComponent.LicenseServiceConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration for a license service that is associated with a studio resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-studiocomponentconfiguration.html#cfn-nimblestudio-studiocomponent-studiocomponentconfiguration-licenseserviceconfiguration
            '''
            result = self._values.get("license_service_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnStudioComponent.LicenseServiceConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def shared_file_system_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnStudioComponent.SharedFileSystemConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration for a shared file storage system that is associated with a studio resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-studiocomponentconfiguration.html#cfn-nimblestudio-studiocomponent-studiocomponentconfiguration-sharedfilesystemconfiguration
            '''
            result = self._values.get("shared_file_system_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnStudioComponent.SharedFileSystemConfigurationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StudioComponentConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStudioComponent.StudioComponentInitializationScriptProperty",
        jsii_struct_bases=[],
        name_mapping={
            "launch_profile_protocol_version": "launchProfileProtocolVersion",
            "platform": "platform",
            "run_context": "runContext",
            "script": "script",
        },
    )
    class StudioComponentInitializationScriptProperty:
        def __init__(
            self,
            *,
            launch_profile_protocol_version: typing.Optional[builtins.str] = None,
            platform: typing.Optional[builtins.str] = None,
            run_context: typing.Optional[builtins.str] = None,
            script: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Initialization scripts for studio components.

            :param launch_profile_protocol_version: The version number of the protocol that is used by the launch profile. The only valid version is "2021-03-31".
            :param platform: The platform of the initialization script, either WINDOWS or LINUX.
            :param run_context: The method to use when running the initialization script.
            :param script: The initialization script.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-studiocomponentinitializationscript.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_nimblestudio as nimblestudio
                
                studio_component_initialization_script_property = nimblestudio.CfnStudioComponent.StudioComponentInitializationScriptProperty(
                    launch_profile_protocol_version="launchProfileProtocolVersion",
                    platform="platform",
                    run_context="runContext",
                    script="script"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if launch_profile_protocol_version is not None:
                self._values["launch_profile_protocol_version"] = launch_profile_protocol_version
            if platform is not None:
                self._values["platform"] = platform
            if run_context is not None:
                self._values["run_context"] = run_context
            if script is not None:
                self._values["script"] = script

        @builtins.property
        def launch_profile_protocol_version(self) -> typing.Optional[builtins.str]:
            '''The version number of the protocol that is used by the launch profile.

            The only valid version is "2021-03-31".

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-studiocomponentinitializationscript.html#cfn-nimblestudio-studiocomponent-studiocomponentinitializationscript-launchprofileprotocolversion
            '''
            result = self._values.get("launch_profile_protocol_version")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def platform(self) -> typing.Optional[builtins.str]:
            '''The platform of the initialization script, either WINDOWS or LINUX.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-studiocomponentinitializationscript.html#cfn-nimblestudio-studiocomponent-studiocomponentinitializationscript-platform
            '''
            result = self._values.get("platform")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def run_context(self) -> typing.Optional[builtins.str]:
            '''The method to use when running the initialization script.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-studiocomponentinitializationscript.html#cfn-nimblestudio-studiocomponent-studiocomponentinitializationscript-runcontext
            '''
            result = self._values.get("run_context")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def script(self) -> typing.Optional[builtins.str]:
            '''The initialization script.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-nimblestudio-studiocomponent-studiocomponentinitializationscript.html#cfn-nimblestudio-studiocomponent-studiocomponentinitializationscript-script
            '''
            result = self._values.get("script")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StudioComponentInitializationScriptProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStudioComponentProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "studio_id": "studioId",
        "type": "type",
        "configuration": "configuration",
        "description": "description",
        "ec2_security_group_ids": "ec2SecurityGroupIds",
        "initialization_scripts": "initializationScripts",
        "script_parameters": "scriptParameters",
        "subtype": "subtype",
        "tags": "tags",
    },
)
class CfnStudioComponentProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        studio_id: builtins.str,
        type: builtins.str,
        configuration: typing.Optional[typing.Union[CfnStudioComponent.StudioComponentConfigurationProperty, _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        ec2_security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        initialization_scripts: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnStudioComponent.StudioComponentInitializationScriptProperty, _IResolvable_da3f097b]]]] = None,
        script_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnStudioComponent.ScriptParameterKeyValueProperty, _IResolvable_da3f097b]]]] = None,
        subtype: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnStudioComponent``.

        :param name: A friendly name for the studio component resource.
        :param studio_id: The unique identifier for a studio resource. In Nimble Studio , all other resources are contained in a studio resource.
        :param type: The type of the studio component.
        :param configuration: The configuration of the studio component, based on component type.
        :param description: A human-readable description for the studio component resource.
        :param ec2_security_group_ids: The EC2 security groups that control access to the studio component.
        :param initialization_scripts: Initialization scripts for studio components.
        :param script_parameters: Parameters for the studio component scripts.
        :param subtype: The specific subtype of a studio component.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_nimblestudio as nimblestudio
            
            cfn_studio_component_props = nimblestudio.CfnStudioComponentProps(
                name="name",
                studio_id="studioId",
                type="type",
            
                # the properties below are optional
                configuration=nimblestudio.CfnStudioComponent.StudioComponentConfigurationProperty(
                    active_directory_configuration=nimblestudio.CfnStudioComponent.ActiveDirectoryConfigurationProperty(
                        computer_attributes=[nimblestudio.CfnStudioComponent.ActiveDirectoryComputerAttributeProperty(
                            name="name",
                            value="value"
                        )],
                        directory_id="directoryId",
                        organizational_unit_distinguished_name="organizationalUnitDistinguishedName"
                    ),
                    compute_farm_configuration=nimblestudio.CfnStudioComponent.ComputeFarmConfigurationProperty(
                        active_directory_user="activeDirectoryUser",
                        endpoint="endpoint"
                    ),
                    license_service_configuration=nimblestudio.CfnStudioComponent.LicenseServiceConfigurationProperty(
                        endpoint="endpoint"
                    ),
                    shared_file_system_configuration=nimblestudio.CfnStudioComponent.SharedFileSystemConfigurationProperty(
                        endpoint="endpoint",
                        file_system_id="fileSystemId",
                        linux_mount_point="linuxMountPoint",
                        share_name="shareName",
                        windows_mount_drive="windowsMountDrive"
                    )
                ),
                description="description",
                ec2_security_group_ids=["ec2SecurityGroupIds"],
                initialization_scripts=[nimblestudio.CfnStudioComponent.StudioComponentInitializationScriptProperty(
                    launch_profile_protocol_version="launchProfileProtocolVersion",
                    platform="platform",
                    run_context="runContext",
                    script="script"
                )],
                script_parameters=[nimblestudio.CfnStudioComponent.ScriptParameterKeyValueProperty(
                    key="key",
                    value="value"
                )],
                subtype="subtype",
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
            "studio_id": studio_id,
            "type": type,
        }
        if configuration is not None:
            self._values["configuration"] = configuration
        if description is not None:
            self._values["description"] = description
        if ec2_security_group_ids is not None:
            self._values["ec2_security_group_ids"] = ec2_security_group_ids
        if initialization_scripts is not None:
            self._values["initialization_scripts"] = initialization_scripts
        if script_parameters is not None:
            self._values["script_parameters"] = script_parameters
        if subtype is not None:
            self._values["subtype"] = subtype
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''A friendly name for the studio component resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def studio_id(self) -> builtins.str:
        '''The unique identifier for a studio resource.

        In Nimble Studio , all other resources are contained in a studio resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-studioid
        '''
        result = self._values.get("studio_id")
        assert result is not None, "Required property 'studio_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def type(self) -> builtins.str:
        '''The type of the studio component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-type
        '''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnStudioComponent.StudioComponentConfigurationProperty, _IResolvable_da3f097b]]:
        '''The configuration of the studio component, based on component type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-configuration
        '''
        result = self._values.get("configuration")
        return typing.cast(typing.Optional[typing.Union[CfnStudioComponent.StudioComponentConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A human-readable description for the studio component resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ec2_security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The EC2 security groups that control access to the studio component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-ec2securitygroupids
        '''
        result = self._values.get("ec2_security_group_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def initialization_scripts(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnStudioComponent.StudioComponentInitializationScriptProperty, _IResolvable_da3f097b]]]]:
        '''Initialization scripts for studio components.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-initializationscripts
        '''
        result = self._values.get("initialization_scripts")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnStudioComponent.StudioComponentInitializationScriptProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def script_parameters(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnStudioComponent.ScriptParameterKeyValueProperty, _IResolvable_da3f097b]]]]:
        '''Parameters for the studio component scripts.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-scriptparameters
        '''
        result = self._values.get("script_parameters")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnStudioComponent.ScriptParameterKeyValueProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def subtype(self) -> typing.Optional[builtins.str]:
        '''The specific subtype of a studio component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-subtype
        '''
        result = self._values.get("subtype")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studiocomponent.html#cfn-nimblestudio-studiocomponent-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnStudioComponentProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_nimblestudio.CfnStudioProps",
    jsii_struct_bases=[],
    name_mapping={
        "admin_role_arn": "adminRoleArn",
        "display_name": "displayName",
        "studio_name": "studioName",
        "user_role_arn": "userRoleArn",
        "studio_encryption_configuration": "studioEncryptionConfiguration",
        "tags": "tags",
    },
)
class CfnStudioProps:
    def __init__(
        self,
        *,
        admin_role_arn: builtins.str,
        display_name: builtins.str,
        studio_name: builtins.str,
        user_role_arn: builtins.str,
        studio_encryption_configuration: typing.Optional[typing.Union[CfnStudio.StudioEncryptionConfigurationProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnStudio``.

        :param admin_role_arn: The IAM role that studio admins assume when logging in to the Nimble Studio portal.
        :param display_name: A friendly name for the studio.
        :param studio_name: The name of the studio, as included in the URL when accessing it in the Nimble Studio portal.
        :param user_role_arn: The IAM role that studio users assume when logging in to the Nimble Studio portal.
        :param studio_encryption_configuration: Configuration of the encryption method that is used for the studio.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studio.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_nimblestudio as nimblestudio
            
            cfn_studio_props = nimblestudio.CfnStudioProps(
                admin_role_arn="adminRoleArn",
                display_name="displayName",
                studio_name="studioName",
                user_role_arn="userRoleArn",
            
                # the properties below are optional
                studio_encryption_configuration=nimblestudio.CfnStudio.StudioEncryptionConfigurationProperty(
                    key_type="keyType",
            
                    # the properties below are optional
                    key_arn="keyArn"
                ),
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "admin_role_arn": admin_role_arn,
            "display_name": display_name,
            "studio_name": studio_name,
            "user_role_arn": user_role_arn,
        }
        if studio_encryption_configuration is not None:
            self._values["studio_encryption_configuration"] = studio_encryption_configuration
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def admin_role_arn(self) -> builtins.str:
        '''The IAM role that studio admins assume when logging in to the Nimble Studio portal.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studio.html#cfn-nimblestudio-studio-adminrolearn
        '''
        result = self._values.get("admin_role_arn")
        assert result is not None, "Required property 'admin_role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def display_name(self) -> builtins.str:
        '''A friendly name for the studio.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studio.html#cfn-nimblestudio-studio-displayname
        '''
        result = self._values.get("display_name")
        assert result is not None, "Required property 'display_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def studio_name(self) -> builtins.str:
        '''The name of the studio, as included in the URL when accessing it in the Nimble Studio portal.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studio.html#cfn-nimblestudio-studio-studioname
        '''
        result = self._values.get("studio_name")
        assert result is not None, "Required property 'studio_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_role_arn(self) -> builtins.str:
        '''The IAM role that studio users assume when logging in to the Nimble Studio portal.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studio.html#cfn-nimblestudio-studio-userrolearn
        '''
        result = self._values.get("user_role_arn")
        assert result is not None, "Required property 'user_role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def studio_encryption_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnStudio.StudioEncryptionConfigurationProperty, _IResolvable_da3f097b]]:
        '''Configuration of the encryption method that is used for the studio.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studio.html#cfn-nimblestudio-studio-studioencryptionconfiguration
        '''
        result = self._values.get("studio_encryption_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnStudio.StudioEncryptionConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-nimblestudio-studio.html#cfn-nimblestudio-studio-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnStudioProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnLaunchProfile",
    "CfnLaunchProfileProps",
    "CfnStreamingImage",
    "CfnStreamingImageProps",
    "CfnStudio",
    "CfnStudioComponent",
    "CfnStudioComponentProps",
    "CfnStudioProps",
]

publication.publish()
