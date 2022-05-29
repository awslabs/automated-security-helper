'''
# Amazon AppStream 2.0 Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_appstream as appstream
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-appstream-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::AppStream](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_AppStream.html).

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
class CfnAppBlock(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appstream.CfnAppBlock",
):
    '''A CloudFormation ``AWS::AppStream::AppBlock``.

    This resource creates an app block. App blocks store details about the virtual hard disk that contains the files for the application in an S3 bucket. It also stores the setup script with details about how to mount the virtual hard disk. App blocks are only supported for Elastic fleets.

    :cloudformationResource: AWS::AppStream::AppBlock
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-appblock.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appstream as appstream
        
        cfn_app_block = appstream.CfnAppBlock(self, "MyCfnAppBlock",
            name="name",
            setup_script_details=appstream.CfnAppBlock.ScriptDetailsProperty(
                executable_path="executablePath",
                script_s3_location=appstream.CfnAppBlock.S3LocationProperty(
                    s3_bucket="s3Bucket",
                    s3_key="s3Key"
                ),
                timeout_in_seconds=123,
        
                # the properties below are optional
                executable_parameters="executableParameters"
            ),
            source_s3_location=appstream.CfnAppBlock.S3LocationProperty(
                s3_bucket="s3Bucket",
                s3_key="s3Key"
            ),
        
            # the properties below are optional
            description="description",
            display_name="displayName",
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
        name: builtins.str,
        setup_script_details: typing.Union["CfnAppBlock.ScriptDetailsProperty", _IResolvable_da3f097b],
        source_s3_location: typing.Union["CfnAppBlock.S3LocationProperty", _IResolvable_da3f097b],
        description: typing.Optional[builtins.str] = None,
        display_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::AppStream::AppBlock``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the app block. *Pattern* : ``^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}$``
        :param setup_script_details: The setup script details of the app block.
        :param source_s3_location: The source S3 location of the app block.
        :param description: The description of the app block.
        :param display_name: The display name of the app block.
        :param tags: The tags of the app block.
        '''
        props = CfnAppBlockProps(
            name=name,
            setup_script_details=setup_script_details,
            source_s3_location=source_s3_location,
            description=description,
            display_name=display_name,
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
        '''The ARN of the app block.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCreatedTime")
    def attr_created_time(self) -> builtins.str:
        '''The time when the app block was created.

        :cloudformationAttribute: CreatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags of the app block.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-appblock.html#cfn-appstream-appblock-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the app block.

        *Pattern* : ``^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}$``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-appblock.html#cfn-appstream-appblock-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="setupScriptDetails")
    def setup_script_details(
        self,
    ) -> typing.Union["CfnAppBlock.ScriptDetailsProperty", _IResolvable_da3f097b]:
        '''The setup script details of the app block.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-appblock.html#cfn-appstream-appblock-setupscriptdetails
        '''
        return typing.cast(typing.Union["CfnAppBlock.ScriptDetailsProperty", _IResolvable_da3f097b], jsii.get(self, "setupScriptDetails"))

    @setup_script_details.setter
    def setup_script_details(
        self,
        value: typing.Union["CfnAppBlock.ScriptDetailsProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "setupScriptDetails", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceS3Location")
    def source_s3_location(
        self,
    ) -> typing.Union["CfnAppBlock.S3LocationProperty", _IResolvable_da3f097b]:
        '''The source S3 location of the app block.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-appblock.html#cfn-appstream-appblock-sources3location
        '''
        return typing.cast(typing.Union["CfnAppBlock.S3LocationProperty", _IResolvable_da3f097b], jsii.get(self, "sourceS3Location"))

    @source_s3_location.setter
    def source_s3_location(
        self,
        value: typing.Union["CfnAppBlock.S3LocationProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "sourceS3Location", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the app block.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-appblock.html#cfn-appstream-appblock-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="displayName")
    def display_name(self) -> typing.Optional[builtins.str]:
        '''The display name of the app block.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-appblock.html#cfn-appstream-appblock-displayname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "displayName"))

    @display_name.setter
    def display_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "displayName", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnAppBlock.S3LocationProperty",
        jsii_struct_bases=[],
        name_mapping={"s3_bucket": "s3Bucket", "s3_key": "s3Key"},
    )
    class S3LocationProperty:
        def __init__(self, *, s3_bucket: builtins.str, s3_key: builtins.str) -> None:
            '''The S3 location of the app block.

            :param s3_bucket: The S3 bucket of the app block.
            :param s3_key: The S3 key of the S3 object of the virtual hard disk.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-appblock-s3location.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                s3_location_property = appstream.CfnAppBlock.S3LocationProperty(
                    s3_bucket="s3Bucket",
                    s3_key="s3Key"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "s3_bucket": s3_bucket,
                "s3_key": s3_key,
            }

        @builtins.property
        def s3_bucket(self) -> builtins.str:
            '''The S3 bucket of the app block.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-appblock-s3location.html#cfn-appstream-appblock-s3location-s3bucket
            '''
            result = self._values.get("s3_bucket")
            assert result is not None, "Required property 's3_bucket' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_key(self) -> builtins.str:
            '''The S3 key of the S3 object of the virtual hard disk.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-appblock-s3location.html#cfn-appstream-appblock-s3location-s3key
            '''
            result = self._values.get("s3_key")
            assert result is not None, "Required property 's3_key' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3LocationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnAppBlock.ScriptDetailsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "executable_path": "executablePath",
            "script_s3_location": "scriptS3Location",
            "timeout_in_seconds": "timeoutInSeconds",
            "executable_parameters": "executableParameters",
        },
    )
    class ScriptDetailsProperty:
        def __init__(
            self,
            *,
            executable_path: builtins.str,
            script_s3_location: typing.Union["CfnAppBlock.S3LocationProperty", _IResolvable_da3f097b],
            timeout_in_seconds: jsii.Number,
            executable_parameters: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The details of the script.

            :param executable_path: The run path for the script.
            :param script_s3_location: The S3 object location of the script.
            :param timeout_in_seconds: The run timeout, in seconds, for the script.
            :param executable_parameters: The parameters used in the run path for the script.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-appblock-scriptdetails.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                script_details_property = appstream.CfnAppBlock.ScriptDetailsProperty(
                    executable_path="executablePath",
                    script_s3_location=appstream.CfnAppBlock.S3LocationProperty(
                        s3_bucket="s3Bucket",
                        s3_key="s3Key"
                    ),
                    timeout_in_seconds=123,
                
                    # the properties below are optional
                    executable_parameters="executableParameters"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "executable_path": executable_path,
                "script_s3_location": script_s3_location,
                "timeout_in_seconds": timeout_in_seconds,
            }
            if executable_parameters is not None:
                self._values["executable_parameters"] = executable_parameters

        @builtins.property
        def executable_path(self) -> builtins.str:
            '''The run path for the script.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-appblock-scriptdetails.html#cfn-appstream-appblock-scriptdetails-executablepath
            '''
            result = self._values.get("executable_path")
            assert result is not None, "Required property 'executable_path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def script_s3_location(
            self,
        ) -> typing.Union["CfnAppBlock.S3LocationProperty", _IResolvable_da3f097b]:
            '''The S3 object location of the script.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-appblock-scriptdetails.html#cfn-appstream-appblock-scriptdetails-scripts3location
            '''
            result = self._values.get("script_s3_location")
            assert result is not None, "Required property 'script_s3_location' is missing"
            return typing.cast(typing.Union["CfnAppBlock.S3LocationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def timeout_in_seconds(self) -> jsii.Number:
            '''The run timeout, in seconds, for the script.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-appblock-scriptdetails.html#cfn-appstream-appblock-scriptdetails-timeoutinseconds
            '''
            result = self._values.get("timeout_in_seconds")
            assert result is not None, "Required property 'timeout_in_seconds' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def executable_parameters(self) -> typing.Optional[builtins.str]:
            '''The parameters used in the run path for the script.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-appblock-scriptdetails.html#cfn-appstream-appblock-scriptdetails-executableparameters
            '''
            result = self._values.get("executable_parameters")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScriptDetailsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appstream.CfnAppBlockProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "setup_script_details": "setupScriptDetails",
        "source_s3_location": "sourceS3Location",
        "description": "description",
        "display_name": "displayName",
        "tags": "tags",
    },
)
class CfnAppBlockProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        setup_script_details: typing.Union[CfnAppBlock.ScriptDetailsProperty, _IResolvable_da3f097b],
        source_s3_location: typing.Union[CfnAppBlock.S3LocationProperty, _IResolvable_da3f097b],
        description: typing.Optional[builtins.str] = None,
        display_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnAppBlock``.

        :param name: The name of the app block. *Pattern* : ``^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}$``
        :param setup_script_details: The setup script details of the app block.
        :param source_s3_location: The source S3 location of the app block.
        :param description: The description of the app block.
        :param display_name: The display name of the app block.
        :param tags: The tags of the app block.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-appblock.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appstream as appstream
            
            cfn_app_block_props = appstream.CfnAppBlockProps(
                name="name",
                setup_script_details=appstream.CfnAppBlock.ScriptDetailsProperty(
                    executable_path="executablePath",
                    script_s3_location=appstream.CfnAppBlock.S3LocationProperty(
                        s3_bucket="s3Bucket",
                        s3_key="s3Key"
                    ),
                    timeout_in_seconds=123,
            
                    # the properties below are optional
                    executable_parameters="executableParameters"
                ),
                source_s3_location=appstream.CfnAppBlock.S3LocationProperty(
                    s3_bucket="s3Bucket",
                    s3_key="s3Key"
                ),
            
                # the properties below are optional
                description="description",
                display_name="displayName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
            "setup_script_details": setup_script_details,
            "source_s3_location": source_s3_location,
        }
        if description is not None:
            self._values["description"] = description
        if display_name is not None:
            self._values["display_name"] = display_name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the app block.

        *Pattern* : ``^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}$``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-appblock.html#cfn-appstream-appblock-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def setup_script_details(
        self,
    ) -> typing.Union[CfnAppBlock.ScriptDetailsProperty, _IResolvable_da3f097b]:
        '''The setup script details of the app block.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-appblock.html#cfn-appstream-appblock-setupscriptdetails
        '''
        result = self._values.get("setup_script_details")
        assert result is not None, "Required property 'setup_script_details' is missing"
        return typing.cast(typing.Union[CfnAppBlock.ScriptDetailsProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def source_s3_location(
        self,
    ) -> typing.Union[CfnAppBlock.S3LocationProperty, _IResolvable_da3f097b]:
        '''The source S3 location of the app block.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-appblock.html#cfn-appstream-appblock-sources3location
        '''
        result = self._values.get("source_s3_location")
        assert result is not None, "Required property 'source_s3_location' is missing"
        return typing.cast(typing.Union[CfnAppBlock.S3LocationProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the app block.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-appblock.html#cfn-appstream-appblock-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def display_name(self) -> typing.Optional[builtins.str]:
        '''The display name of the app block.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-appblock.html#cfn-appstream-appblock-displayname
        '''
        result = self._values.get("display_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags of the app block.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-appblock.html#cfn-appstream-appblock-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAppBlockProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnApplication(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appstream.CfnApplication",
):
    '''A CloudFormation ``AWS::AppStream::Application``.

    This resource creates an application. Applications store the details about how to launch applications on streaming instances. This is only supported for Elastic fleets.

    :cloudformationResource: AWS::AppStream::Application
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appstream as appstream
        
        cfn_application = appstream.CfnApplication(self, "MyCfnApplication",
            app_block_arn="appBlockArn",
            icon_s3_location=appstream.CfnApplication.S3LocationProperty(
                s3_bucket="s3Bucket",
                s3_key="s3Key"
            ),
            instance_families=["instanceFamilies"],
            launch_path="launchPath",
            name="name",
            platforms=["platforms"],
        
            # the properties below are optional
            attributes_to_delete=["attributesToDelete"],
            description="description",
            display_name="displayName",
            launch_parameters="launchParameters",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            working_directory="workingDirectory"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        app_block_arn: builtins.str,
        icon_s3_location: typing.Union["CfnApplication.S3LocationProperty", _IResolvable_da3f097b],
        instance_families: typing.Sequence[builtins.str],
        launch_path: builtins.str,
        name: builtins.str,
        platforms: typing.Sequence[builtins.str],
        attributes_to_delete: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        display_name: typing.Optional[builtins.str] = None,
        launch_parameters: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        working_directory: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::AppStream::Application``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param app_block_arn: The app block ARN with which the application should be associated.
        :param icon_s3_location: The icon S3 location of the application.
        :param instance_families: The instance families the application supports. *Allowed Values* : ``GENERAL_PURPOSE`` | ``GRAPHICS_G4``
        :param launch_path: The launch path of the application.
        :param name: The name of the application. This name is visible to users when a name is not specified in the DisplayName property. *Pattern* : ``^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}$``
        :param platforms: The platforms the application supports. *Allowed Values* : ``WINDOWS_SERVER_2019`` | ``AMAZON_LINUX2``
        :param attributes_to_delete: A list of attributes to delete from an application.
        :param description: The description of the application.
        :param display_name: The display name of the application. This name is visible to users in the application catalog.
        :param launch_parameters: The launch parameters of the application.
        :param tags: The tags of the application.
        :param working_directory: The working directory of the application.
        '''
        props = CfnApplicationProps(
            app_block_arn=app_block_arn,
            icon_s3_location=icon_s3_location,
            instance_families=instance_families,
            launch_path=launch_path,
            name=name,
            platforms=platforms,
            attributes_to_delete=attributes_to_delete,
            description=description,
            display_name=display_name,
            launch_parameters=launch_parameters,
            tags=tags,
            working_directory=working_directory,
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
        '''The ARN of the application.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCreatedTime")
    def attr_created_time(self) -> builtins.str:
        '''The time when the application was created.

        :cloudformationAttribute: CreatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="appBlockArn")
    def app_block_arn(self) -> builtins.str:
        '''The app block ARN with which the application should be associated.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-appblockarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "appBlockArn"))

    @app_block_arn.setter
    def app_block_arn(self, value: builtins.str) -> None:
        jsii.set(self, "appBlockArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="iconS3Location")
    def icon_s3_location(
        self,
    ) -> typing.Union["CfnApplication.S3LocationProperty", _IResolvable_da3f097b]:
        '''The icon S3 location of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-icons3location
        '''
        return typing.cast(typing.Union["CfnApplication.S3LocationProperty", _IResolvable_da3f097b], jsii.get(self, "iconS3Location"))

    @icon_s3_location.setter
    def icon_s3_location(
        self,
        value: typing.Union["CfnApplication.S3LocationProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "iconS3Location", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceFamilies")
    def instance_families(self) -> typing.List[builtins.str]:
        '''The instance families the application supports.

        *Allowed Values* : ``GENERAL_PURPOSE`` | ``GRAPHICS_G4``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-instancefamilies
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "instanceFamilies"))

    @instance_families.setter
    def instance_families(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "instanceFamilies", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="launchPath")
    def launch_path(self) -> builtins.str:
        '''The launch path of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-launchpath
        '''
        return typing.cast(builtins.str, jsii.get(self, "launchPath"))

    @launch_path.setter
    def launch_path(self, value: builtins.str) -> None:
        jsii.set(self, "launchPath", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the application.

        This name is visible to users when a name is not specified in the DisplayName property.

        *Pattern* : ``^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}$``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="platforms")
    def platforms(self) -> typing.List[builtins.str]:
        '''The platforms the application supports.

        *Allowed Values* : ``WINDOWS_SERVER_2019`` | ``AMAZON_LINUX2``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-platforms
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "platforms"))

    @platforms.setter
    def platforms(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "platforms", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attributesToDelete")
    def attributes_to_delete(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of attributes to delete from an application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-attributestodelete
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "attributesToDelete"))

    @attributes_to_delete.setter
    def attributes_to_delete(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "attributesToDelete", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="displayName")
    def display_name(self) -> typing.Optional[builtins.str]:
        '''The display name of the application.

        This name is visible to users in the application catalog.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-displayname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "displayName"))

    @display_name.setter
    def display_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "displayName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="launchParameters")
    def launch_parameters(self) -> typing.Optional[builtins.str]:
        '''The launch parameters of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-launchparameters
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "launchParameters"))

    @launch_parameters.setter
    def launch_parameters(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "launchParameters", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="workingDirectory")
    def working_directory(self) -> typing.Optional[builtins.str]:
        '''The working directory of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-workingdirectory
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "workingDirectory"))

    @working_directory.setter
    def working_directory(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "workingDirectory", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnApplication.S3LocationProperty",
        jsii_struct_bases=[],
        name_mapping={"s3_bucket": "s3Bucket", "s3_key": "s3Key"},
    )
    class S3LocationProperty:
        def __init__(self, *, s3_bucket: builtins.str, s3_key: builtins.str) -> None:
            '''The S3 location of the application icon.

            :param s3_bucket: The S3 bucket of the S3 object.
            :param s3_key: The S3 key of the S3 object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-application-s3location.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                s3_location_property = appstream.CfnApplication.S3LocationProperty(
                    s3_bucket="s3Bucket",
                    s3_key="s3Key"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "s3_bucket": s3_bucket,
                "s3_key": s3_key,
            }

        @builtins.property
        def s3_bucket(self) -> builtins.str:
            '''The S3 bucket of the S3 object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-application-s3location.html#cfn-appstream-application-s3location-s3bucket
            '''
            result = self._values.get("s3_bucket")
            assert result is not None, "Required property 's3_bucket' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_key(self) -> builtins.str:
            '''The S3 key of the S3 object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-application-s3location.html#cfn-appstream-application-s3location-s3key
            '''
            result = self._values.get("s3_key")
            assert result is not None, "Required property 's3_key' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3LocationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnApplicationEntitlementAssociation(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appstream.CfnApplicationEntitlementAssociation",
):
    '''A CloudFormation ``AWS::AppStream::ApplicationEntitlementAssociation``.

    Associates an application to an entitlement.

    :cloudformationResource: AWS::AppStream::ApplicationEntitlementAssociation
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-applicationentitlementassociation.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appstream as appstream
        
        cfn_application_entitlement_association = appstream.CfnApplicationEntitlementAssociation(self, "MyCfnApplicationEntitlementAssociation",
            application_identifier="applicationIdentifier",
            entitlement_name="entitlementName",
            stack_name="stackName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        application_identifier: builtins.str,
        entitlement_name: builtins.str,
        stack_name: builtins.str,
    ) -> None:
        '''Create a new ``AWS::AppStream::ApplicationEntitlementAssociation``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param application_identifier: The identifier of the application.
        :param entitlement_name: The name of the entitlement.
        :param stack_name: The name of the stack.
        '''
        props = CfnApplicationEntitlementAssociationProps(
            application_identifier=application_identifier,
            entitlement_name=entitlement_name,
            stack_name=stack_name,
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
    @jsii.member(jsii_name="applicationIdentifier")
    def application_identifier(self) -> builtins.str:
        '''The identifier of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-applicationentitlementassociation.html#cfn-appstream-applicationentitlementassociation-applicationidentifier
        '''
        return typing.cast(builtins.str, jsii.get(self, "applicationIdentifier"))

    @application_identifier.setter
    def application_identifier(self, value: builtins.str) -> None:
        jsii.set(self, "applicationIdentifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="entitlementName")
    def entitlement_name(self) -> builtins.str:
        '''The name of the entitlement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-applicationentitlementassociation.html#cfn-appstream-applicationentitlementassociation-entitlementname
        '''
        return typing.cast(builtins.str, jsii.get(self, "entitlementName"))

    @entitlement_name.setter
    def entitlement_name(self, value: builtins.str) -> None:
        jsii.set(self, "entitlementName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="stackName")
    def stack_name(self) -> builtins.str:
        '''The name of the stack.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-applicationentitlementassociation.html#cfn-appstream-applicationentitlementassociation-stackname
        '''
        return typing.cast(builtins.str, jsii.get(self, "stackName"))

    @stack_name.setter
    def stack_name(self, value: builtins.str) -> None:
        jsii.set(self, "stackName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appstream.CfnApplicationEntitlementAssociationProps",
    jsii_struct_bases=[],
    name_mapping={
        "application_identifier": "applicationIdentifier",
        "entitlement_name": "entitlementName",
        "stack_name": "stackName",
    },
)
class CfnApplicationEntitlementAssociationProps:
    def __init__(
        self,
        *,
        application_identifier: builtins.str,
        entitlement_name: builtins.str,
        stack_name: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnApplicationEntitlementAssociation``.

        :param application_identifier: The identifier of the application.
        :param entitlement_name: The name of the entitlement.
        :param stack_name: The name of the stack.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-applicationentitlementassociation.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appstream as appstream
            
            cfn_application_entitlement_association_props = appstream.CfnApplicationEntitlementAssociationProps(
                application_identifier="applicationIdentifier",
                entitlement_name="entitlementName",
                stack_name="stackName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "application_identifier": application_identifier,
            "entitlement_name": entitlement_name,
            "stack_name": stack_name,
        }

    @builtins.property
    def application_identifier(self) -> builtins.str:
        '''The identifier of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-applicationentitlementassociation.html#cfn-appstream-applicationentitlementassociation-applicationidentifier
        '''
        result = self._values.get("application_identifier")
        assert result is not None, "Required property 'application_identifier' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def entitlement_name(self) -> builtins.str:
        '''The name of the entitlement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-applicationentitlementassociation.html#cfn-appstream-applicationentitlementassociation-entitlementname
        '''
        result = self._values.get("entitlement_name")
        assert result is not None, "Required property 'entitlement_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def stack_name(self) -> builtins.str:
        '''The name of the stack.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-applicationentitlementassociation.html#cfn-appstream-applicationentitlementassociation-stackname
        '''
        result = self._values.get("stack_name")
        assert result is not None, "Required property 'stack_name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnApplicationEntitlementAssociationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnApplicationFleetAssociation(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appstream.CfnApplicationFleetAssociation",
):
    '''A CloudFormation ``AWS::AppStream::ApplicationFleetAssociation``.

    This resource associates the specified application with the specified fleet. This is only supported for Elastic fleets.

    :cloudformationResource: AWS::AppStream::ApplicationFleetAssociation
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-applicationfleetassociation.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appstream as appstream
        
        cfn_application_fleet_association = appstream.CfnApplicationFleetAssociation(self, "MyCfnApplicationFleetAssociation",
            application_arn="applicationArn",
            fleet_name="fleetName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        application_arn: builtins.str,
        fleet_name: builtins.str,
    ) -> None:
        '''Create a new ``AWS::AppStream::ApplicationFleetAssociation``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param application_arn: The ARN of the application.
        :param fleet_name: The name of the fleet.
        '''
        props = CfnApplicationFleetAssociationProps(
            application_arn=application_arn, fleet_name=fleet_name
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
    @jsii.member(jsii_name="applicationArn")
    def application_arn(self) -> builtins.str:
        '''The ARN of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-applicationfleetassociation.html#cfn-appstream-applicationfleetassociation-applicationarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "applicationArn"))

    @application_arn.setter
    def application_arn(self, value: builtins.str) -> None:
        jsii.set(self, "applicationArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fleetName")
    def fleet_name(self) -> builtins.str:
        '''The name of the fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-applicationfleetassociation.html#cfn-appstream-applicationfleetassociation-fleetname
        '''
        return typing.cast(builtins.str, jsii.get(self, "fleetName"))

    @fleet_name.setter
    def fleet_name(self, value: builtins.str) -> None:
        jsii.set(self, "fleetName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appstream.CfnApplicationFleetAssociationProps",
    jsii_struct_bases=[],
    name_mapping={"application_arn": "applicationArn", "fleet_name": "fleetName"},
)
class CfnApplicationFleetAssociationProps:
    def __init__(
        self,
        *,
        application_arn: builtins.str,
        fleet_name: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnApplicationFleetAssociation``.

        :param application_arn: The ARN of the application.
        :param fleet_name: The name of the fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-applicationfleetassociation.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appstream as appstream
            
            cfn_application_fleet_association_props = appstream.CfnApplicationFleetAssociationProps(
                application_arn="applicationArn",
                fleet_name="fleetName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "application_arn": application_arn,
            "fleet_name": fleet_name,
        }

    @builtins.property
    def application_arn(self) -> builtins.str:
        '''The ARN of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-applicationfleetassociation.html#cfn-appstream-applicationfleetassociation-applicationarn
        '''
        result = self._values.get("application_arn")
        assert result is not None, "Required property 'application_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def fleet_name(self) -> builtins.str:
        '''The name of the fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-applicationfleetassociation.html#cfn-appstream-applicationfleetassociation-fleetname
        '''
        result = self._values.get("fleet_name")
        assert result is not None, "Required property 'fleet_name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnApplicationFleetAssociationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appstream.CfnApplicationProps",
    jsii_struct_bases=[],
    name_mapping={
        "app_block_arn": "appBlockArn",
        "icon_s3_location": "iconS3Location",
        "instance_families": "instanceFamilies",
        "launch_path": "launchPath",
        "name": "name",
        "platforms": "platforms",
        "attributes_to_delete": "attributesToDelete",
        "description": "description",
        "display_name": "displayName",
        "launch_parameters": "launchParameters",
        "tags": "tags",
        "working_directory": "workingDirectory",
    },
)
class CfnApplicationProps:
    def __init__(
        self,
        *,
        app_block_arn: builtins.str,
        icon_s3_location: typing.Union[CfnApplication.S3LocationProperty, _IResolvable_da3f097b],
        instance_families: typing.Sequence[builtins.str],
        launch_path: builtins.str,
        name: builtins.str,
        platforms: typing.Sequence[builtins.str],
        attributes_to_delete: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        display_name: typing.Optional[builtins.str] = None,
        launch_parameters: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        working_directory: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnApplication``.

        :param app_block_arn: The app block ARN with which the application should be associated.
        :param icon_s3_location: The icon S3 location of the application.
        :param instance_families: The instance families the application supports. *Allowed Values* : ``GENERAL_PURPOSE`` | ``GRAPHICS_G4``
        :param launch_path: The launch path of the application.
        :param name: The name of the application. This name is visible to users when a name is not specified in the DisplayName property. *Pattern* : ``^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}$``
        :param platforms: The platforms the application supports. *Allowed Values* : ``WINDOWS_SERVER_2019`` | ``AMAZON_LINUX2``
        :param attributes_to_delete: A list of attributes to delete from an application.
        :param description: The description of the application.
        :param display_name: The display name of the application. This name is visible to users in the application catalog.
        :param launch_parameters: The launch parameters of the application.
        :param tags: The tags of the application.
        :param working_directory: The working directory of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appstream as appstream
            
            cfn_application_props = appstream.CfnApplicationProps(
                app_block_arn="appBlockArn",
                icon_s3_location=appstream.CfnApplication.S3LocationProperty(
                    s3_bucket="s3Bucket",
                    s3_key="s3Key"
                ),
                instance_families=["instanceFamilies"],
                launch_path="launchPath",
                name="name",
                platforms=["platforms"],
            
                # the properties below are optional
                attributes_to_delete=["attributesToDelete"],
                description="description",
                display_name="displayName",
                launch_parameters="launchParameters",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                working_directory="workingDirectory"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "app_block_arn": app_block_arn,
            "icon_s3_location": icon_s3_location,
            "instance_families": instance_families,
            "launch_path": launch_path,
            "name": name,
            "platforms": platforms,
        }
        if attributes_to_delete is not None:
            self._values["attributes_to_delete"] = attributes_to_delete
        if description is not None:
            self._values["description"] = description
        if display_name is not None:
            self._values["display_name"] = display_name
        if launch_parameters is not None:
            self._values["launch_parameters"] = launch_parameters
        if tags is not None:
            self._values["tags"] = tags
        if working_directory is not None:
            self._values["working_directory"] = working_directory

    @builtins.property
    def app_block_arn(self) -> builtins.str:
        '''The app block ARN with which the application should be associated.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-appblockarn
        '''
        result = self._values.get("app_block_arn")
        assert result is not None, "Required property 'app_block_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def icon_s3_location(
        self,
    ) -> typing.Union[CfnApplication.S3LocationProperty, _IResolvable_da3f097b]:
        '''The icon S3 location of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-icons3location
        '''
        result = self._values.get("icon_s3_location")
        assert result is not None, "Required property 'icon_s3_location' is missing"
        return typing.cast(typing.Union[CfnApplication.S3LocationProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def instance_families(self) -> typing.List[builtins.str]:
        '''The instance families the application supports.

        *Allowed Values* : ``GENERAL_PURPOSE`` | ``GRAPHICS_G4``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-instancefamilies
        '''
        result = self._values.get("instance_families")
        assert result is not None, "Required property 'instance_families' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def launch_path(self) -> builtins.str:
        '''The launch path of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-launchpath
        '''
        result = self._values.get("launch_path")
        assert result is not None, "Required property 'launch_path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the application.

        This name is visible to users when a name is not specified in the DisplayName property.

        *Pattern* : ``^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}$``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def platforms(self) -> typing.List[builtins.str]:
        '''The platforms the application supports.

        *Allowed Values* : ``WINDOWS_SERVER_2019`` | ``AMAZON_LINUX2``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-platforms
        '''
        result = self._values.get("platforms")
        assert result is not None, "Required property 'platforms' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def attributes_to_delete(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of attributes to delete from an application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-attributestodelete
        '''
        result = self._values.get("attributes_to_delete")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def display_name(self) -> typing.Optional[builtins.str]:
        '''The display name of the application.

        This name is visible to users in the application catalog.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-displayname
        '''
        result = self._values.get("display_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def launch_parameters(self) -> typing.Optional[builtins.str]:
        '''The launch parameters of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-launchparameters
        '''
        result = self._values.get("launch_parameters")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def working_directory(self) -> typing.Optional[builtins.str]:
        '''The working directory of the application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-application.html#cfn-appstream-application-workingdirectory
        '''
        result = self._values.get("working_directory")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnApplicationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDirectoryConfig(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appstream.CfnDirectoryConfig",
):
    '''A CloudFormation ``AWS::AppStream::DirectoryConfig``.

    The ``AWS::AppStream::DirectoryConfig`` resource specifies the configuration information required to join Amazon AppStream 2.0 fleets and image builders to Microsoft Active Directory domains.

    :cloudformationResource: AWS::AppStream::DirectoryConfig
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-directoryconfig.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appstream as appstream
        
        cfn_directory_config = appstream.CfnDirectoryConfig(self, "MyCfnDirectoryConfig",
            directory_name="directoryName",
            organizational_unit_distinguished_names=["organizationalUnitDistinguishedNames"],
            service_account_credentials=appstream.CfnDirectoryConfig.ServiceAccountCredentialsProperty(
                account_name="accountName",
                account_password="accountPassword"
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        directory_name: builtins.str,
        organizational_unit_distinguished_names: typing.Sequence[builtins.str],
        service_account_credentials: typing.Union["CfnDirectoryConfig.ServiceAccountCredentialsProperty", _IResolvable_da3f097b],
    ) -> None:
        '''Create a new ``AWS::AppStream::DirectoryConfig``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param directory_name: The fully qualified name of the directory (for example, corp.example.com).
        :param organizational_unit_distinguished_names: The distinguished names of the organizational units for computer accounts.
        :param service_account_credentials: The credentials for the service account used by the streaming instance to connect to the directory. Do not use this parameter directly. Use ``ServiceAccountCredentials`` as an input parameter with ``noEcho`` as shown in the `Parameters <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html>`_ . For best practices information, see `Do Not Embed Credentials in Your Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html#creds>`_ .
        '''
        props = CfnDirectoryConfigProps(
            directory_name=directory_name,
            organizational_unit_distinguished_names=organizational_unit_distinguished_names,
            service_account_credentials=service_account_credentials,
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
    @jsii.member(jsii_name="directoryName")
    def directory_name(self) -> builtins.str:
        '''The fully qualified name of the directory (for example, corp.example.com).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-directoryconfig.html#cfn-appstream-directoryconfig-directoryname
        '''
        return typing.cast(builtins.str, jsii.get(self, "directoryName"))

    @directory_name.setter
    def directory_name(self, value: builtins.str) -> None:
        jsii.set(self, "directoryName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="organizationalUnitDistinguishedNames")
    def organizational_unit_distinguished_names(self) -> typing.List[builtins.str]:
        '''The distinguished names of the organizational units for computer accounts.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-directoryconfig.html#cfn-appstream-directoryconfig-organizationalunitdistinguishednames
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "organizationalUnitDistinguishedNames"))

    @organizational_unit_distinguished_names.setter
    def organizational_unit_distinguished_names(
        self,
        value: typing.List[builtins.str],
    ) -> None:
        jsii.set(self, "organizationalUnitDistinguishedNames", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceAccountCredentials")
    def service_account_credentials(
        self,
    ) -> typing.Union["CfnDirectoryConfig.ServiceAccountCredentialsProperty", _IResolvable_da3f097b]:
        '''The credentials for the service account used by the streaming instance to connect to the directory.

        Do not use this parameter directly. Use ``ServiceAccountCredentials`` as an input parameter with ``noEcho`` as shown in the `Parameters <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html>`_ . For best practices information, see `Do Not Embed Credentials in Your Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html#creds>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-directoryconfig.html#cfn-appstream-directoryconfig-serviceaccountcredentials
        '''
        return typing.cast(typing.Union["CfnDirectoryConfig.ServiceAccountCredentialsProperty", _IResolvable_da3f097b], jsii.get(self, "serviceAccountCredentials"))

    @service_account_credentials.setter
    def service_account_credentials(
        self,
        value: typing.Union["CfnDirectoryConfig.ServiceAccountCredentialsProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "serviceAccountCredentials", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnDirectoryConfig.ServiceAccountCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "account_name": "accountName",
            "account_password": "accountPassword",
        },
    )
    class ServiceAccountCredentialsProperty:
        def __init__(
            self,
            *,
            account_name: builtins.str,
            account_password: builtins.str,
        ) -> None:
            '''The credentials for the service account used by the streaming instance to connect to the directory.

            :param account_name: The user name of the account. This account must have the following privileges: create computer objects, join computers to the domain, and change/reset the password on descendant computer objects for the organizational units specified.
            :param account_password: The password for the account.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-directoryconfig-serviceaccountcredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                service_account_credentials_property = appstream.CfnDirectoryConfig.ServiceAccountCredentialsProperty(
                    account_name="accountName",
                    account_password="accountPassword"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "account_name": account_name,
                "account_password": account_password,
            }

        @builtins.property
        def account_name(self) -> builtins.str:
            '''The user name of the account.

            This account must have the following privileges: create computer objects, join computers to the domain, and change/reset the password on descendant computer objects for the organizational units specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-directoryconfig-serviceaccountcredentials.html#cfn-appstream-directoryconfig-serviceaccountcredentials-accountname
            '''
            result = self._values.get("account_name")
            assert result is not None, "Required property 'account_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def account_password(self) -> builtins.str:
            '''The password for the account.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-directoryconfig-serviceaccountcredentials.html#cfn-appstream-directoryconfig-serviceaccountcredentials-accountpassword
            '''
            result = self._values.get("account_password")
            assert result is not None, "Required property 'account_password' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ServiceAccountCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appstream.CfnDirectoryConfigProps",
    jsii_struct_bases=[],
    name_mapping={
        "directory_name": "directoryName",
        "organizational_unit_distinguished_names": "organizationalUnitDistinguishedNames",
        "service_account_credentials": "serviceAccountCredentials",
    },
)
class CfnDirectoryConfigProps:
    def __init__(
        self,
        *,
        directory_name: builtins.str,
        organizational_unit_distinguished_names: typing.Sequence[builtins.str],
        service_account_credentials: typing.Union[CfnDirectoryConfig.ServiceAccountCredentialsProperty, _IResolvable_da3f097b],
    ) -> None:
        '''Properties for defining a ``CfnDirectoryConfig``.

        :param directory_name: The fully qualified name of the directory (for example, corp.example.com).
        :param organizational_unit_distinguished_names: The distinguished names of the organizational units for computer accounts.
        :param service_account_credentials: The credentials for the service account used by the streaming instance to connect to the directory. Do not use this parameter directly. Use ``ServiceAccountCredentials`` as an input parameter with ``noEcho`` as shown in the `Parameters <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html>`_ . For best practices information, see `Do Not Embed Credentials in Your Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html#creds>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-directoryconfig.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appstream as appstream
            
            cfn_directory_config_props = appstream.CfnDirectoryConfigProps(
                directory_name="directoryName",
                organizational_unit_distinguished_names=["organizationalUnitDistinguishedNames"],
                service_account_credentials=appstream.CfnDirectoryConfig.ServiceAccountCredentialsProperty(
                    account_name="accountName",
                    account_password="accountPassword"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "directory_name": directory_name,
            "organizational_unit_distinguished_names": organizational_unit_distinguished_names,
            "service_account_credentials": service_account_credentials,
        }

    @builtins.property
    def directory_name(self) -> builtins.str:
        '''The fully qualified name of the directory (for example, corp.example.com).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-directoryconfig.html#cfn-appstream-directoryconfig-directoryname
        '''
        result = self._values.get("directory_name")
        assert result is not None, "Required property 'directory_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def organizational_unit_distinguished_names(self) -> typing.List[builtins.str]:
        '''The distinguished names of the organizational units for computer accounts.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-directoryconfig.html#cfn-appstream-directoryconfig-organizationalunitdistinguishednames
        '''
        result = self._values.get("organizational_unit_distinguished_names")
        assert result is not None, "Required property 'organizational_unit_distinguished_names' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def service_account_credentials(
        self,
    ) -> typing.Union[CfnDirectoryConfig.ServiceAccountCredentialsProperty, _IResolvable_da3f097b]:
        '''The credentials for the service account used by the streaming instance to connect to the directory.

        Do not use this parameter directly. Use ``ServiceAccountCredentials`` as an input parameter with ``noEcho`` as shown in the `Parameters <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html>`_ . For best practices information, see `Do Not Embed Credentials in Your Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html#creds>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-directoryconfig.html#cfn-appstream-directoryconfig-serviceaccountcredentials
        '''
        result = self._values.get("service_account_credentials")
        assert result is not None, "Required property 'service_account_credentials' is missing"
        return typing.cast(typing.Union[CfnDirectoryConfig.ServiceAccountCredentialsProperty, _IResolvable_da3f097b], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDirectoryConfigProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnEntitlement(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appstream.CfnEntitlement",
):
    '''A CloudFormation ``AWS::AppStream::Entitlement``.

    Creates an entitlement to control access, based on user attributes, to specific applications within a stack. Entitlements apply to SAML 2.0 federated user identities. Amazon AppStream 2.0 user pool and streaming URL users are entitled to all applications in a stack. Entitlements don't apply to the desktop stream view application or to applications managed by a dynamic app provider using the Dynamic Application Framework.

    :cloudformationResource: AWS::AppStream::Entitlement
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-entitlement.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appstream as appstream
        
        cfn_entitlement = appstream.CfnEntitlement(self, "MyCfnEntitlement",
            app_visibility="appVisibility",
            attributes=[appstream.CfnEntitlement.AttributeProperty(
                name="name",
                value="value"
            )],
            name="name",
            stack_name="stackName",
        
            # the properties below are optional
            description="description"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        app_visibility: builtins.str,
        attributes: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnEntitlement.AttributeProperty", _IResolvable_da3f097b]]],
        name: builtins.str,
        stack_name: builtins.str,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::AppStream::Entitlement``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param app_visibility: Specifies whether to entitle all apps or only selected apps.
        :param attributes: The attributes of the entitlement.
        :param name: The name of the entitlement.
        :param stack_name: The name of the stack.
        :param description: The description of the entitlement.
        '''
        props = CfnEntitlementProps(
            app_visibility=app_visibility,
            attributes=attributes,
            name=name,
            stack_name=stack_name,
            description=description,
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
    @jsii.member(jsii_name="attrCreatedTime")
    def attr_created_time(self) -> builtins.str:
        '''The time when the entitlement was created.

        :cloudformationAttribute: CreatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLastModifiedTime")
    def attr_last_modified_time(self) -> builtins.str:
        '''The time when the entitlement was last modified.

        :cloudformationAttribute: LastModifiedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLastModifiedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="appVisibility")
    def app_visibility(self) -> builtins.str:
        '''Specifies whether to entitle all apps or only selected apps.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-entitlement.html#cfn-appstream-entitlement-appvisibility
        '''
        return typing.cast(builtins.str, jsii.get(self, "appVisibility"))

    @app_visibility.setter
    def app_visibility(self, value: builtins.str) -> None:
        jsii.set(self, "appVisibility", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attributes")
    def attributes(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnEntitlement.AttributeProperty", _IResolvable_da3f097b]]]:
        '''The attributes of the entitlement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-entitlement.html#cfn-appstream-entitlement-attributes
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnEntitlement.AttributeProperty", _IResolvable_da3f097b]]], jsii.get(self, "attributes"))

    @attributes.setter
    def attributes(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnEntitlement.AttributeProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "attributes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the entitlement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-entitlement.html#cfn-appstream-entitlement-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="stackName")
    def stack_name(self) -> builtins.str:
        '''The name of the stack.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-entitlement.html#cfn-appstream-entitlement-stackname
        '''
        return typing.cast(builtins.str, jsii.get(self, "stackName"))

    @stack_name.setter
    def stack_name(self, value: builtins.str) -> None:
        jsii.set(self, "stackName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the entitlement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-entitlement.html#cfn-appstream-entitlement-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnEntitlement.AttributeProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "value": "value"},
    )
    class AttributeProperty:
        def __init__(self, *, name: builtins.str, value: builtins.str) -> None:
            '''An attribute that belongs to an entitlement.

            Application entitlements work by matching a supported SAML 2.0 attribute name to a value when a user identity federates to an AppStream 2.0 SAML application.

            :param name: A supported AWS IAM SAML PrincipalTag attribute that is matched to a value when a user identity federates to an AppStream 2.0 SAML application. The following are supported values: - roles - department - organization - groups - title - costCenter - userType
            :param value: A value that is matched to a supported SAML attribute name when a user identity federates to an AppStream 2.0 SAML application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-entitlement-attribute.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                attribute_property = appstream.CfnEntitlement.AttributeProperty(
                    name="name",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "value": value,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''A supported AWS IAM SAML PrincipalTag attribute that is matched to a value when a user identity federates to an AppStream 2.0 SAML application.

            The following are supported values:

            - roles
            - department
            - organization
            - groups
            - title
            - costCenter
            - userType

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-entitlement-attribute.html#cfn-appstream-entitlement-attribute-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''A value that is matched to a supported SAML attribute name when a user identity federates to an AppStream 2.0 SAML application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-entitlement-attribute.html#cfn-appstream-entitlement-attribute-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
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
    jsii_type="aws-cdk-lib.aws_appstream.CfnEntitlementProps",
    jsii_struct_bases=[],
    name_mapping={
        "app_visibility": "appVisibility",
        "attributes": "attributes",
        "name": "name",
        "stack_name": "stackName",
        "description": "description",
    },
)
class CfnEntitlementProps:
    def __init__(
        self,
        *,
        app_visibility: builtins.str,
        attributes: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnEntitlement.AttributeProperty, _IResolvable_da3f097b]]],
        name: builtins.str,
        stack_name: builtins.str,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnEntitlement``.

        :param app_visibility: Specifies whether to entitle all apps or only selected apps.
        :param attributes: The attributes of the entitlement.
        :param name: The name of the entitlement.
        :param stack_name: The name of the stack.
        :param description: The description of the entitlement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-entitlement.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appstream as appstream
            
            cfn_entitlement_props = appstream.CfnEntitlementProps(
                app_visibility="appVisibility",
                attributes=[appstream.CfnEntitlement.AttributeProperty(
                    name="name",
                    value="value"
                )],
                name="name",
                stack_name="stackName",
            
                # the properties below are optional
                description="description"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "app_visibility": app_visibility,
            "attributes": attributes,
            "name": name,
            "stack_name": stack_name,
        }
        if description is not None:
            self._values["description"] = description

    @builtins.property
    def app_visibility(self) -> builtins.str:
        '''Specifies whether to entitle all apps or only selected apps.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-entitlement.html#cfn-appstream-entitlement-appvisibility
        '''
        result = self._values.get("app_visibility")
        assert result is not None, "Required property 'app_visibility' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def attributes(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnEntitlement.AttributeProperty, _IResolvable_da3f097b]]]:
        '''The attributes of the entitlement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-entitlement.html#cfn-appstream-entitlement-attributes
        '''
        result = self._values.get("attributes")
        assert result is not None, "Required property 'attributes' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnEntitlement.AttributeProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the entitlement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-entitlement.html#cfn-appstream-entitlement-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def stack_name(self) -> builtins.str:
        '''The name of the stack.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-entitlement.html#cfn-appstream-entitlement-stackname
        '''
        result = self._values.get("stack_name")
        assert result is not None, "Required property 'stack_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the entitlement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-entitlement.html#cfn-appstream-entitlement-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnEntitlementProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnFleet(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appstream.CfnFleet",
):
    '''A CloudFormation ``AWS::AppStream::Fleet``.

    The ``AWS::AppStream::Fleet`` resource creates a fleet for Amazon AppStream 2.0. A fleet consists of streaming instances that run a specified image when using Always-On or On-Demand.

    :cloudformationResource: AWS::AppStream::Fleet
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appstream as appstream
        
        cfn_fleet = appstream.CfnFleet(self, "MyCfnFleet",
            instance_type="instanceType",
            name="name",
        
            # the properties below are optional
            compute_capacity=appstream.CfnFleet.ComputeCapacityProperty(
                desired_instances=123
            ),
            description="description",
            disconnect_timeout_in_seconds=123,
            display_name="displayName",
            domain_join_info=appstream.CfnFleet.DomainJoinInfoProperty(
                directory_name="directoryName",
                organizational_unit_distinguished_name="organizationalUnitDistinguishedName"
            ),
            enable_default_internet_access=False,
            fleet_type="fleetType",
            iam_role_arn="iamRoleArn",
            idle_disconnect_timeout_in_seconds=123,
            image_arn="imageArn",
            image_name="imageName",
            max_concurrent_sessions=123,
            max_user_duration_in_seconds=123,
            platform="platform",
            stream_view="streamView",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            usb_device_filter_strings=["usbDeviceFilterStrings"],
            vpc_config=appstream.CfnFleet.VpcConfigProperty(
                security_group_ids=["securityGroupIds"],
                subnet_ids=["subnetIds"]
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        instance_type: builtins.str,
        name: builtins.str,
        compute_capacity: typing.Optional[typing.Union["CfnFleet.ComputeCapacityProperty", _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        disconnect_timeout_in_seconds: typing.Optional[jsii.Number] = None,
        display_name: typing.Optional[builtins.str] = None,
        domain_join_info: typing.Optional[typing.Union["CfnFleet.DomainJoinInfoProperty", _IResolvable_da3f097b]] = None,
        enable_default_internet_access: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        fleet_type: typing.Optional[builtins.str] = None,
        iam_role_arn: typing.Optional[builtins.str] = None,
        idle_disconnect_timeout_in_seconds: typing.Optional[jsii.Number] = None,
        image_arn: typing.Optional[builtins.str] = None,
        image_name: typing.Optional[builtins.str] = None,
        max_concurrent_sessions: typing.Optional[jsii.Number] = None,
        max_user_duration_in_seconds: typing.Optional[jsii.Number] = None,
        platform: typing.Optional[builtins.str] = None,
        stream_view: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        usb_device_filter_strings: typing.Optional[typing.Sequence[builtins.str]] = None,
        vpc_config: typing.Optional[typing.Union["CfnFleet.VpcConfigProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::AppStream::Fleet``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param instance_type: The instance type to use when launching fleet instances. The following instance types are available for non-Elastic fleets:. - stream.standard.small - stream.standard.medium - stream.standard.large - stream.compute.large - stream.compute.xlarge - stream.compute.2xlarge - stream.compute.4xlarge - stream.compute.8xlarge - stream.memory.large - stream.memory.xlarge - stream.memory.2xlarge - stream.memory.4xlarge - stream.memory.8xlarge - stream.memory.z1d.large - stream.memory.z1d.xlarge - stream.memory.z1d.2xlarge - stream.memory.z1d.3xlarge - stream.memory.z1d.6xlarge - stream.memory.z1d.12xlarge - stream.graphics-design.large - stream.graphics-design.xlarge - stream.graphics-design.2xlarge - stream.graphics-design.4xlarge - stream.graphics-desktop.2xlarge - stream.graphics.g4dn.xlarge - stream.graphics.g4dn.2xlarge - stream.graphics.g4dn.4xlarge - stream.graphics.g4dn.8xlarge - stream.graphics.g4dn.12xlarge - stream.graphics.g4dn.16xlarge - stream.graphics-pro.4xlarge - stream.graphics-pro.8xlarge - stream.graphics-pro.16xlarge The following instance types are available for Elastic fleets: - stream.standard.small - stream.standard.medium
        :param name: A unique name for the fleet.
        :param compute_capacity: The desired capacity for the fleet. This is not allowed for Elastic fleets.
        :param description: The description to display.
        :param disconnect_timeout_in_seconds: The amount of time that a streaming session remains active after users disconnect. If users try to reconnect to the streaming session after a disconnection or network interruption within this time interval, they are connected to their previous session. Otherwise, they are connected to a new session with a new streaming instance. Specify a value between 60 and 360000.
        :param display_name: The fleet name to display.
        :param domain_join_info: The name of the directory and organizational unit (OU) to use to join the fleet to a Microsoft Active Directory domain. This is not allowed for Elastic fleets.
        :param enable_default_internet_access: Enables or disables default internet access for the fleet.
        :param fleet_type: The fleet type. - **ALWAYS_ON** - Provides users with instant-on access to their apps. You are charged for all running instances in your fleet, even if no users are streaming apps. - **ON_DEMAND** - Provide users with access to applications after they connect, which takes one to two minutes. You are charged for instance streaming when users are connected and a small hourly fee for instances that are not streaming apps. - **ELASTIC** - The pool of streaming instances is managed by Amazon AppStream 2.0. When a user selects their application or desktop to launch, they will start streaming after the app block has been downloaded and mounted to a streaming instance. *Allowed Values* : ``ALWAYS_ON`` | ``ELASTIC`` | ``ON_DEMAND``
        :param iam_role_arn: The ARN of the IAM role that is applied to the fleet. To assume a role, the fleet instance calls the AWS Security Token Service ``AssumeRole`` API operation and passes the ARN of the role to use. The operation creates a new session with temporary credentials. AppStream 2.0 retrieves the temporary credentials and creates the *appstream_machine_role* credential profile on the instance. For more information, see `Using an IAM Role to Grant Permissions to Applications and Scripts Running on AppStream 2.0 Streaming Instances <https://docs.aws.amazon.com/appstream2/latest/developerguide/using-iam-roles-to-grant-permissions-to-applications-scripts-streaming-instances.html>`_ in the *Amazon AppStream 2.0 Administration Guide* .
        :param idle_disconnect_timeout_in_seconds: The amount of time that users can be idle (inactive) before they are disconnected from their streaming session and the ``DisconnectTimeoutInSeconds`` time interval begins. Users are notified before they are disconnected due to inactivity. If they try to reconnect to the streaming session before the time interval specified in ``DisconnectTimeoutInSeconds`` elapses, they are connected to their previous session. Users are considered idle when they stop providing keyboard or mouse input during their streaming session. File uploads and downloads, audio in, audio out, and pixels changing do not qualify as user activity. If users continue to be idle after the time interval in ``IdleDisconnectTimeoutInSeconds`` elapses, they are disconnected. To prevent users from being disconnected due to inactivity, specify a value of 0. Otherwise, specify a value between 60 and 3600. If you enable this feature, we recommend that you specify a value that corresponds exactly to a whole number of minutes (for example, 60, 120, and 180). If you don't do this, the value is rounded to the nearest minute. For example, if you specify a value of 70, users are disconnected after 1 minute of inactivity. If you specify a value that is at the midpoint between two different minutes, the value is rounded up. For example, if you specify a value of 90, users are disconnected after 2 minutes of inactivity.
        :param image_arn: The ARN of the public, private, or shared image to use.
        :param image_name: The name of the image used to create the fleet.
        :param max_concurrent_sessions: The maximum number of concurrent sessions that can be run on an Elastic fleet. This setting is required for Elastic fleets, but is not used for other fleet types.
        :param max_user_duration_in_seconds: The maximum amount of time that a streaming session can remain active, in seconds. If users are still connected to a streaming instance five minutes before this limit is reached, they are prompted to save any open documents before being disconnected. After this time elapses, the instance is terminated and replaced by a new instance. Specify a value between 600 and 360000.
        :param platform: The platform of the fleet. Platform is a required setting for Elastic fleets, and is not used for other fleet types. *Allowed Values* : ``WINDOWS_SERVER_2019`` | ``AMAZON_LINUX2``
        :param stream_view: The AppStream 2.0 view that is displayed to your users when they stream from the fleet. When ``APP`` is specified, only the windows of applications opened by users display. When ``DESKTOP`` is specified, the standard desktop that is provided by the operating system displays. The default value is ``APP`` .
        :param tags: An array of key-value pairs.
        :param usb_device_filter_strings: The USB device filter strings that specify which USB devices a user can redirect to the fleet streaming session, when using the Windows native client. This is allowed but not required for Elastic fleets.
        :param vpc_config: The VPC configuration for the fleet. This is required for Elastic fleets, but not required for other fleet types.
        '''
        props = CfnFleetProps(
            instance_type=instance_type,
            name=name,
            compute_capacity=compute_capacity,
            description=description,
            disconnect_timeout_in_seconds=disconnect_timeout_in_seconds,
            display_name=display_name,
            domain_join_info=domain_join_info,
            enable_default_internet_access=enable_default_internet_access,
            fleet_type=fleet_type,
            iam_role_arn=iam_role_arn,
            idle_disconnect_timeout_in_seconds=idle_disconnect_timeout_in_seconds,
            image_arn=image_arn,
            image_name=image_name,
            max_concurrent_sessions=max_concurrent_sessions,
            max_user_duration_in_seconds=max_user_duration_in_seconds,
            platform=platform,
            stream_view=stream_view,
            tags=tags,
            usb_device_filter_strings=usb_device_filter_strings,
            vpc_config=vpc_config,
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
        '''An array of key-value pairs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceType")
    def instance_type(self) -> builtins.str:
        '''The instance type to use when launching fleet instances. The following instance types are available for non-Elastic fleets:.

        - stream.standard.small
        - stream.standard.medium
        - stream.standard.large
        - stream.compute.large
        - stream.compute.xlarge
        - stream.compute.2xlarge
        - stream.compute.4xlarge
        - stream.compute.8xlarge
        - stream.memory.large
        - stream.memory.xlarge
        - stream.memory.2xlarge
        - stream.memory.4xlarge
        - stream.memory.8xlarge
        - stream.memory.z1d.large
        - stream.memory.z1d.xlarge
        - stream.memory.z1d.2xlarge
        - stream.memory.z1d.3xlarge
        - stream.memory.z1d.6xlarge
        - stream.memory.z1d.12xlarge
        - stream.graphics-design.large
        - stream.graphics-design.xlarge
        - stream.graphics-design.2xlarge
        - stream.graphics-design.4xlarge
        - stream.graphics-desktop.2xlarge
        - stream.graphics.g4dn.xlarge
        - stream.graphics.g4dn.2xlarge
        - stream.graphics.g4dn.4xlarge
        - stream.graphics.g4dn.8xlarge
        - stream.graphics.g4dn.12xlarge
        - stream.graphics.g4dn.16xlarge
        - stream.graphics-pro.4xlarge
        - stream.graphics-pro.8xlarge
        - stream.graphics-pro.16xlarge

        The following instance types are available for Elastic fleets:

        - stream.standard.small
        - stream.standard.medium

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-instancetype
        '''
        return typing.cast(builtins.str, jsii.get(self, "instanceType"))

    @instance_type.setter
    def instance_type(self, value: builtins.str) -> None:
        jsii.set(self, "instanceType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''A unique name for the fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="computeCapacity")
    def compute_capacity(
        self,
    ) -> typing.Optional[typing.Union["CfnFleet.ComputeCapacityProperty", _IResolvable_da3f097b]]:
        '''The desired capacity for the fleet.

        This is not allowed for Elastic fleets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-computecapacity
        '''
        return typing.cast(typing.Optional[typing.Union["CfnFleet.ComputeCapacityProperty", _IResolvable_da3f097b]], jsii.get(self, "computeCapacity"))

    @compute_capacity.setter
    def compute_capacity(
        self,
        value: typing.Optional[typing.Union["CfnFleet.ComputeCapacityProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "computeCapacity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description to display.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="disconnectTimeoutInSeconds")
    def disconnect_timeout_in_seconds(self) -> typing.Optional[jsii.Number]:
        '''The amount of time that a streaming session remains active after users disconnect.

        If users try to reconnect to the streaming session after a disconnection or network interruption within this time interval, they are connected to their previous session. Otherwise, they are connected to a new session with a new streaming instance.

        Specify a value between 60 and 360000.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-disconnecttimeoutinseconds
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "disconnectTimeoutInSeconds"))

    @disconnect_timeout_in_seconds.setter
    def disconnect_timeout_in_seconds(
        self,
        value: typing.Optional[jsii.Number],
    ) -> None:
        jsii.set(self, "disconnectTimeoutInSeconds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="displayName")
    def display_name(self) -> typing.Optional[builtins.str]:
        '''The fleet name to display.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-displayname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "displayName"))

    @display_name.setter
    def display_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "displayName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainJoinInfo")
    def domain_join_info(
        self,
    ) -> typing.Optional[typing.Union["CfnFleet.DomainJoinInfoProperty", _IResolvable_da3f097b]]:
        '''The name of the directory and organizational unit (OU) to use to join the fleet to a Microsoft Active Directory domain.

        This is not allowed for Elastic fleets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-domainjoininfo
        '''
        return typing.cast(typing.Optional[typing.Union["CfnFleet.DomainJoinInfoProperty", _IResolvable_da3f097b]], jsii.get(self, "domainJoinInfo"))

    @domain_join_info.setter
    def domain_join_info(
        self,
        value: typing.Optional[typing.Union["CfnFleet.DomainJoinInfoProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "domainJoinInfo", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enableDefaultInternetAccess")
    def enable_default_internet_access(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables or disables default internet access for the fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-enabledefaultinternetaccess
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enableDefaultInternetAccess"))

    @enable_default_internet_access.setter
    def enable_default_internet_access(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enableDefaultInternetAccess", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fleetType")
    def fleet_type(self) -> typing.Optional[builtins.str]:
        '''The fleet type.

        - **ALWAYS_ON** - Provides users with instant-on access to their apps. You are charged for all running instances in your fleet, even if no users are streaming apps.
        - **ON_DEMAND** - Provide users with access to applications after they connect, which takes one to two minutes. You are charged for instance streaming when users are connected and a small hourly fee for instances that are not streaming apps.
        - **ELASTIC** - The pool of streaming instances is managed by Amazon AppStream 2.0. When a user selects their application or desktop to launch, they will start streaming after the app block has been downloaded and mounted to a streaming instance.

        *Allowed Values* : ``ALWAYS_ON`` | ``ELASTIC`` | ``ON_DEMAND``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-fleettype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "fleetType"))

    @fleet_type.setter
    def fleet_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "fleetType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="iamRoleArn")
    def iam_role_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the IAM role that is applied to the fleet.

        To assume a role, the fleet instance calls the AWS Security Token Service ``AssumeRole`` API operation and passes the ARN of the role to use. The operation creates a new session with temporary credentials. AppStream 2.0 retrieves the temporary credentials and creates the *appstream_machine_role* credential profile on the instance.

        For more information, see `Using an IAM Role to Grant Permissions to Applications and Scripts Running on AppStream 2.0 Streaming Instances <https://docs.aws.amazon.com/appstream2/latest/developerguide/using-iam-roles-to-grant-permissions-to-applications-scripts-streaming-instances.html>`_ in the *Amazon AppStream 2.0 Administration Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-iamrolearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "iamRoleArn"))

    @iam_role_arn.setter
    def iam_role_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "iamRoleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="idleDisconnectTimeoutInSeconds")
    def idle_disconnect_timeout_in_seconds(self) -> typing.Optional[jsii.Number]:
        '''The amount of time that users can be idle (inactive) before they are disconnected from their streaming session and the ``DisconnectTimeoutInSeconds`` time interval begins.

        Users are notified before they are disconnected due to inactivity. If they try to reconnect to the streaming session before the time interval specified in ``DisconnectTimeoutInSeconds`` elapses, they are connected to their previous session. Users are considered idle when they stop providing keyboard or mouse input during their streaming session. File uploads and downloads, audio in, audio out, and pixels changing do not qualify as user activity. If users continue to be idle after the time interval in ``IdleDisconnectTimeoutInSeconds`` elapses, they are disconnected.

        To prevent users from being disconnected due to inactivity, specify a value of 0. Otherwise, specify a value between 60 and 3600.

        If you enable this feature, we recommend that you specify a value that corresponds exactly to a whole number of minutes (for example, 60, 120, and 180). If you don't do this, the value is rounded to the nearest minute. For example, if you specify a value of 70, users are disconnected after 1 minute of inactivity. If you specify a value that is at the midpoint between two different minutes, the value is rounded up. For example, if you specify a value of 90, users are disconnected after 2 minutes of inactivity.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-idledisconnecttimeoutinseconds
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "idleDisconnectTimeoutInSeconds"))

    @idle_disconnect_timeout_in_seconds.setter
    def idle_disconnect_timeout_in_seconds(
        self,
        value: typing.Optional[jsii.Number],
    ) -> None:
        jsii.set(self, "idleDisconnectTimeoutInSeconds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="imageArn")
    def image_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the public, private, or shared image to use.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-imagearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "imageArn"))

    @image_arn.setter
    def image_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "imageArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="imageName")
    def image_name(self) -> typing.Optional[builtins.str]:
        '''The name of the image used to create the fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-imagename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "imageName"))

    @image_name.setter
    def image_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "imageName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maxConcurrentSessions")
    def max_concurrent_sessions(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of concurrent sessions that can be run on an Elastic fleet.

        This setting is required for Elastic fleets, but is not used for other fleet types.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-maxconcurrentsessions
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "maxConcurrentSessions"))

    @max_concurrent_sessions.setter
    def max_concurrent_sessions(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "maxConcurrentSessions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maxUserDurationInSeconds")
    def max_user_duration_in_seconds(self) -> typing.Optional[jsii.Number]:
        '''The maximum amount of time that a streaming session can remain active, in seconds.

        If users are still connected to a streaming instance five minutes before this limit is reached, they are prompted to save any open documents before being disconnected. After this time elapses, the instance is terminated and replaced by a new instance.

        Specify a value between 600 and 360000.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-maxuserdurationinseconds
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "maxUserDurationInSeconds"))

    @max_user_duration_in_seconds.setter
    def max_user_duration_in_seconds(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "maxUserDurationInSeconds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="platform")
    def platform(self) -> typing.Optional[builtins.str]:
        '''The platform of the fleet.

        Platform is a required setting for Elastic fleets, and is not used for other fleet types.

        *Allowed Values* : ``WINDOWS_SERVER_2019`` | ``AMAZON_LINUX2``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-platform
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "platform"))

    @platform.setter
    def platform(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "platform", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="streamView")
    def stream_view(self) -> typing.Optional[builtins.str]:
        '''The AppStream 2.0 view that is displayed to your users when they stream from the fleet. When ``APP`` is specified, only the windows of applications opened by users display. When ``DESKTOP`` is specified, the standard desktop that is provided by the operating system displays.

        The default value is ``APP`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-streamview
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "streamView"))

    @stream_view.setter
    def stream_view(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "streamView", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="usbDeviceFilterStrings")
    def usb_device_filter_strings(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The USB device filter strings that specify which USB devices a user can redirect to the fleet streaming session, when using the Windows native client.

        This is allowed but not required for Elastic fleets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-usbdevicefilterstrings
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "usbDeviceFilterStrings"))

    @usb_device_filter_strings.setter
    def usb_device_filter_strings(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "usbDeviceFilterStrings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcConfig")
    def vpc_config(
        self,
    ) -> typing.Optional[typing.Union["CfnFleet.VpcConfigProperty", _IResolvable_da3f097b]]:
        '''The VPC configuration for the fleet.

        This is required for Elastic fleets, but not required for other fleet types.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-vpcconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnFleet.VpcConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "vpcConfig"))

    @vpc_config.setter
    def vpc_config(
        self,
        value: typing.Optional[typing.Union["CfnFleet.VpcConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "vpcConfig", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnFleet.ComputeCapacityProperty",
        jsii_struct_bases=[],
        name_mapping={"desired_instances": "desiredInstances"},
    )
    class ComputeCapacityProperty:
        def __init__(self, *, desired_instances: jsii.Number) -> None:
            '''The desired capacity for a fleet.

            :param desired_instances: The desired number of streaming instances.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-fleet-computecapacity.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                compute_capacity_property = appstream.CfnFleet.ComputeCapacityProperty(
                    desired_instances=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "desired_instances": desired_instances,
            }

        @builtins.property
        def desired_instances(self) -> jsii.Number:
            '''The desired number of streaming instances.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-fleet-computecapacity.html#cfn-appstream-fleet-computecapacity-desiredinstances
            '''
            result = self._values.get("desired_instances")
            assert result is not None, "Required property 'desired_instances' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComputeCapacityProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnFleet.DomainJoinInfoProperty",
        jsii_struct_bases=[],
        name_mapping={
            "directory_name": "directoryName",
            "organizational_unit_distinguished_name": "organizationalUnitDistinguishedName",
        },
    )
    class DomainJoinInfoProperty:
        def __init__(
            self,
            *,
            directory_name: typing.Optional[builtins.str] = None,
            organizational_unit_distinguished_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The name of the directory and organizational unit (OU) to use to join a fleet to a Microsoft Active Directory domain.

            :param directory_name: The fully qualified name of the directory (for example, corp.example.com).
            :param organizational_unit_distinguished_name: The distinguished name of the organizational unit for computer accounts.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-fleet-domainjoininfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                domain_join_info_property = appstream.CfnFleet.DomainJoinInfoProperty(
                    directory_name="directoryName",
                    organizational_unit_distinguished_name="organizationalUnitDistinguishedName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if directory_name is not None:
                self._values["directory_name"] = directory_name
            if organizational_unit_distinguished_name is not None:
                self._values["organizational_unit_distinguished_name"] = organizational_unit_distinguished_name

        @builtins.property
        def directory_name(self) -> typing.Optional[builtins.str]:
            '''The fully qualified name of the directory (for example, corp.example.com).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-fleet-domainjoininfo.html#cfn-appstream-fleet-domainjoininfo-directoryname
            '''
            result = self._values.get("directory_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def organizational_unit_distinguished_name(
            self,
        ) -> typing.Optional[builtins.str]:
            '''The distinguished name of the organizational unit for computer accounts.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-fleet-domainjoininfo.html#cfn-appstream-fleet-domainjoininfo-organizationalunitdistinguishedname
            '''
            result = self._values.get("organizational_unit_distinguished_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DomainJoinInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnFleet.VpcConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "security_group_ids": "securityGroupIds",
            "subnet_ids": "subnetIds",
        },
    )
    class VpcConfigProperty:
        def __init__(
            self,
            *,
            security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
            subnet_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''The VPC configuration information for the fleet.

            :param security_group_ids: The identifiers of the security groups for the fleet.
            :param subnet_ids: The identifiers of the subnets to which a network interface is attached from the fleet instance. Fleet instances can use one or two subnets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-fleet-vpcconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                vpc_config_property = appstream.CfnFleet.VpcConfigProperty(
                    security_group_ids=["securityGroupIds"],
                    subnet_ids=["subnetIds"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if security_group_ids is not None:
                self._values["security_group_ids"] = security_group_ids
            if subnet_ids is not None:
                self._values["subnet_ids"] = subnet_ids

        @builtins.property
        def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The identifiers of the security groups for the fleet.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-fleet-vpcconfig.html#cfn-appstream-fleet-vpcconfig-securitygroupids
            '''
            result = self._values.get("security_group_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def subnet_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The identifiers of the subnets to which a network interface is attached from the fleet instance.

            Fleet instances can use one or two subnets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-fleet-vpcconfig.html#cfn-appstream-fleet-vpcconfig-subnetids
            '''
            result = self._values.get("subnet_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VpcConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appstream.CfnFleetProps",
    jsii_struct_bases=[],
    name_mapping={
        "instance_type": "instanceType",
        "name": "name",
        "compute_capacity": "computeCapacity",
        "description": "description",
        "disconnect_timeout_in_seconds": "disconnectTimeoutInSeconds",
        "display_name": "displayName",
        "domain_join_info": "domainJoinInfo",
        "enable_default_internet_access": "enableDefaultInternetAccess",
        "fleet_type": "fleetType",
        "iam_role_arn": "iamRoleArn",
        "idle_disconnect_timeout_in_seconds": "idleDisconnectTimeoutInSeconds",
        "image_arn": "imageArn",
        "image_name": "imageName",
        "max_concurrent_sessions": "maxConcurrentSessions",
        "max_user_duration_in_seconds": "maxUserDurationInSeconds",
        "platform": "platform",
        "stream_view": "streamView",
        "tags": "tags",
        "usb_device_filter_strings": "usbDeviceFilterStrings",
        "vpc_config": "vpcConfig",
    },
)
class CfnFleetProps:
    def __init__(
        self,
        *,
        instance_type: builtins.str,
        name: builtins.str,
        compute_capacity: typing.Optional[typing.Union[CfnFleet.ComputeCapacityProperty, _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        disconnect_timeout_in_seconds: typing.Optional[jsii.Number] = None,
        display_name: typing.Optional[builtins.str] = None,
        domain_join_info: typing.Optional[typing.Union[CfnFleet.DomainJoinInfoProperty, _IResolvable_da3f097b]] = None,
        enable_default_internet_access: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        fleet_type: typing.Optional[builtins.str] = None,
        iam_role_arn: typing.Optional[builtins.str] = None,
        idle_disconnect_timeout_in_seconds: typing.Optional[jsii.Number] = None,
        image_arn: typing.Optional[builtins.str] = None,
        image_name: typing.Optional[builtins.str] = None,
        max_concurrent_sessions: typing.Optional[jsii.Number] = None,
        max_user_duration_in_seconds: typing.Optional[jsii.Number] = None,
        platform: typing.Optional[builtins.str] = None,
        stream_view: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        usb_device_filter_strings: typing.Optional[typing.Sequence[builtins.str]] = None,
        vpc_config: typing.Optional[typing.Union[CfnFleet.VpcConfigProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnFleet``.

        :param instance_type: The instance type to use when launching fleet instances. The following instance types are available for non-Elastic fleets:. - stream.standard.small - stream.standard.medium - stream.standard.large - stream.compute.large - stream.compute.xlarge - stream.compute.2xlarge - stream.compute.4xlarge - stream.compute.8xlarge - stream.memory.large - stream.memory.xlarge - stream.memory.2xlarge - stream.memory.4xlarge - stream.memory.8xlarge - stream.memory.z1d.large - stream.memory.z1d.xlarge - stream.memory.z1d.2xlarge - stream.memory.z1d.3xlarge - stream.memory.z1d.6xlarge - stream.memory.z1d.12xlarge - stream.graphics-design.large - stream.graphics-design.xlarge - stream.graphics-design.2xlarge - stream.graphics-design.4xlarge - stream.graphics-desktop.2xlarge - stream.graphics.g4dn.xlarge - stream.graphics.g4dn.2xlarge - stream.graphics.g4dn.4xlarge - stream.graphics.g4dn.8xlarge - stream.graphics.g4dn.12xlarge - stream.graphics.g4dn.16xlarge - stream.graphics-pro.4xlarge - stream.graphics-pro.8xlarge - stream.graphics-pro.16xlarge The following instance types are available for Elastic fleets: - stream.standard.small - stream.standard.medium
        :param name: A unique name for the fleet.
        :param compute_capacity: The desired capacity for the fleet. This is not allowed for Elastic fleets.
        :param description: The description to display.
        :param disconnect_timeout_in_seconds: The amount of time that a streaming session remains active after users disconnect. If users try to reconnect to the streaming session after a disconnection or network interruption within this time interval, they are connected to their previous session. Otherwise, they are connected to a new session with a new streaming instance. Specify a value between 60 and 360000.
        :param display_name: The fleet name to display.
        :param domain_join_info: The name of the directory and organizational unit (OU) to use to join the fleet to a Microsoft Active Directory domain. This is not allowed for Elastic fleets.
        :param enable_default_internet_access: Enables or disables default internet access for the fleet.
        :param fleet_type: The fleet type. - **ALWAYS_ON** - Provides users with instant-on access to their apps. You are charged for all running instances in your fleet, even if no users are streaming apps. - **ON_DEMAND** - Provide users with access to applications after they connect, which takes one to two minutes. You are charged for instance streaming when users are connected and a small hourly fee for instances that are not streaming apps. - **ELASTIC** - The pool of streaming instances is managed by Amazon AppStream 2.0. When a user selects their application or desktop to launch, they will start streaming after the app block has been downloaded and mounted to a streaming instance. *Allowed Values* : ``ALWAYS_ON`` | ``ELASTIC`` | ``ON_DEMAND``
        :param iam_role_arn: The ARN of the IAM role that is applied to the fleet. To assume a role, the fleet instance calls the AWS Security Token Service ``AssumeRole`` API operation and passes the ARN of the role to use. The operation creates a new session with temporary credentials. AppStream 2.0 retrieves the temporary credentials and creates the *appstream_machine_role* credential profile on the instance. For more information, see `Using an IAM Role to Grant Permissions to Applications and Scripts Running on AppStream 2.0 Streaming Instances <https://docs.aws.amazon.com/appstream2/latest/developerguide/using-iam-roles-to-grant-permissions-to-applications-scripts-streaming-instances.html>`_ in the *Amazon AppStream 2.0 Administration Guide* .
        :param idle_disconnect_timeout_in_seconds: The amount of time that users can be idle (inactive) before they are disconnected from their streaming session and the ``DisconnectTimeoutInSeconds`` time interval begins. Users are notified before they are disconnected due to inactivity. If they try to reconnect to the streaming session before the time interval specified in ``DisconnectTimeoutInSeconds`` elapses, they are connected to their previous session. Users are considered idle when they stop providing keyboard or mouse input during their streaming session. File uploads and downloads, audio in, audio out, and pixels changing do not qualify as user activity. If users continue to be idle after the time interval in ``IdleDisconnectTimeoutInSeconds`` elapses, they are disconnected. To prevent users from being disconnected due to inactivity, specify a value of 0. Otherwise, specify a value between 60 and 3600. If you enable this feature, we recommend that you specify a value that corresponds exactly to a whole number of minutes (for example, 60, 120, and 180). If you don't do this, the value is rounded to the nearest minute. For example, if you specify a value of 70, users are disconnected after 1 minute of inactivity. If you specify a value that is at the midpoint between two different minutes, the value is rounded up. For example, if you specify a value of 90, users are disconnected after 2 minutes of inactivity.
        :param image_arn: The ARN of the public, private, or shared image to use.
        :param image_name: The name of the image used to create the fleet.
        :param max_concurrent_sessions: The maximum number of concurrent sessions that can be run on an Elastic fleet. This setting is required for Elastic fleets, but is not used for other fleet types.
        :param max_user_duration_in_seconds: The maximum amount of time that a streaming session can remain active, in seconds. If users are still connected to a streaming instance five minutes before this limit is reached, they are prompted to save any open documents before being disconnected. After this time elapses, the instance is terminated and replaced by a new instance. Specify a value between 600 and 360000.
        :param platform: The platform of the fleet. Platform is a required setting for Elastic fleets, and is not used for other fleet types. *Allowed Values* : ``WINDOWS_SERVER_2019`` | ``AMAZON_LINUX2``
        :param stream_view: The AppStream 2.0 view that is displayed to your users when they stream from the fleet. When ``APP`` is specified, only the windows of applications opened by users display. When ``DESKTOP`` is specified, the standard desktop that is provided by the operating system displays. The default value is ``APP`` .
        :param tags: An array of key-value pairs.
        :param usb_device_filter_strings: The USB device filter strings that specify which USB devices a user can redirect to the fleet streaming session, when using the Windows native client. This is allowed but not required for Elastic fleets.
        :param vpc_config: The VPC configuration for the fleet. This is required for Elastic fleets, but not required for other fleet types.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appstream as appstream
            
            cfn_fleet_props = appstream.CfnFleetProps(
                instance_type="instanceType",
                name="name",
            
                # the properties below are optional
                compute_capacity=appstream.CfnFleet.ComputeCapacityProperty(
                    desired_instances=123
                ),
                description="description",
                disconnect_timeout_in_seconds=123,
                display_name="displayName",
                domain_join_info=appstream.CfnFleet.DomainJoinInfoProperty(
                    directory_name="directoryName",
                    organizational_unit_distinguished_name="organizationalUnitDistinguishedName"
                ),
                enable_default_internet_access=False,
                fleet_type="fleetType",
                iam_role_arn="iamRoleArn",
                idle_disconnect_timeout_in_seconds=123,
                image_arn="imageArn",
                image_name="imageName",
                max_concurrent_sessions=123,
                max_user_duration_in_seconds=123,
                platform="platform",
                stream_view="streamView",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                usb_device_filter_strings=["usbDeviceFilterStrings"],
                vpc_config=appstream.CfnFleet.VpcConfigProperty(
                    security_group_ids=["securityGroupIds"],
                    subnet_ids=["subnetIds"]
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "instance_type": instance_type,
            "name": name,
        }
        if compute_capacity is not None:
            self._values["compute_capacity"] = compute_capacity
        if description is not None:
            self._values["description"] = description
        if disconnect_timeout_in_seconds is not None:
            self._values["disconnect_timeout_in_seconds"] = disconnect_timeout_in_seconds
        if display_name is not None:
            self._values["display_name"] = display_name
        if domain_join_info is not None:
            self._values["domain_join_info"] = domain_join_info
        if enable_default_internet_access is not None:
            self._values["enable_default_internet_access"] = enable_default_internet_access
        if fleet_type is not None:
            self._values["fleet_type"] = fleet_type
        if iam_role_arn is not None:
            self._values["iam_role_arn"] = iam_role_arn
        if idle_disconnect_timeout_in_seconds is not None:
            self._values["idle_disconnect_timeout_in_seconds"] = idle_disconnect_timeout_in_seconds
        if image_arn is not None:
            self._values["image_arn"] = image_arn
        if image_name is not None:
            self._values["image_name"] = image_name
        if max_concurrent_sessions is not None:
            self._values["max_concurrent_sessions"] = max_concurrent_sessions
        if max_user_duration_in_seconds is not None:
            self._values["max_user_duration_in_seconds"] = max_user_duration_in_seconds
        if platform is not None:
            self._values["platform"] = platform
        if stream_view is not None:
            self._values["stream_view"] = stream_view
        if tags is not None:
            self._values["tags"] = tags
        if usb_device_filter_strings is not None:
            self._values["usb_device_filter_strings"] = usb_device_filter_strings
        if vpc_config is not None:
            self._values["vpc_config"] = vpc_config

    @builtins.property
    def instance_type(self) -> builtins.str:
        '''The instance type to use when launching fleet instances. The following instance types are available for non-Elastic fleets:.

        - stream.standard.small
        - stream.standard.medium
        - stream.standard.large
        - stream.compute.large
        - stream.compute.xlarge
        - stream.compute.2xlarge
        - stream.compute.4xlarge
        - stream.compute.8xlarge
        - stream.memory.large
        - stream.memory.xlarge
        - stream.memory.2xlarge
        - stream.memory.4xlarge
        - stream.memory.8xlarge
        - stream.memory.z1d.large
        - stream.memory.z1d.xlarge
        - stream.memory.z1d.2xlarge
        - stream.memory.z1d.3xlarge
        - stream.memory.z1d.6xlarge
        - stream.memory.z1d.12xlarge
        - stream.graphics-design.large
        - stream.graphics-design.xlarge
        - stream.graphics-design.2xlarge
        - stream.graphics-design.4xlarge
        - stream.graphics-desktop.2xlarge
        - stream.graphics.g4dn.xlarge
        - stream.graphics.g4dn.2xlarge
        - stream.graphics.g4dn.4xlarge
        - stream.graphics.g4dn.8xlarge
        - stream.graphics.g4dn.12xlarge
        - stream.graphics.g4dn.16xlarge
        - stream.graphics-pro.4xlarge
        - stream.graphics-pro.8xlarge
        - stream.graphics-pro.16xlarge

        The following instance types are available for Elastic fleets:

        - stream.standard.small
        - stream.standard.medium

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-instancetype
        '''
        result = self._values.get("instance_type")
        assert result is not None, "Required property 'instance_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''A unique name for the fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def compute_capacity(
        self,
    ) -> typing.Optional[typing.Union[CfnFleet.ComputeCapacityProperty, _IResolvable_da3f097b]]:
        '''The desired capacity for the fleet.

        This is not allowed for Elastic fleets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-computecapacity
        '''
        result = self._values.get("compute_capacity")
        return typing.cast(typing.Optional[typing.Union[CfnFleet.ComputeCapacityProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description to display.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def disconnect_timeout_in_seconds(self) -> typing.Optional[jsii.Number]:
        '''The amount of time that a streaming session remains active after users disconnect.

        If users try to reconnect to the streaming session after a disconnection or network interruption within this time interval, they are connected to their previous session. Otherwise, they are connected to a new session with a new streaming instance.

        Specify a value between 60 and 360000.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-disconnecttimeoutinseconds
        '''
        result = self._values.get("disconnect_timeout_in_seconds")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def display_name(self) -> typing.Optional[builtins.str]:
        '''The fleet name to display.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-displayname
        '''
        result = self._values.get("display_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def domain_join_info(
        self,
    ) -> typing.Optional[typing.Union[CfnFleet.DomainJoinInfoProperty, _IResolvable_da3f097b]]:
        '''The name of the directory and organizational unit (OU) to use to join the fleet to a Microsoft Active Directory domain.

        This is not allowed for Elastic fleets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-domainjoininfo
        '''
        result = self._values.get("domain_join_info")
        return typing.cast(typing.Optional[typing.Union[CfnFleet.DomainJoinInfoProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def enable_default_internet_access(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables or disables default internet access for the fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-enabledefaultinternetaccess
        '''
        result = self._values.get("enable_default_internet_access")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def fleet_type(self) -> typing.Optional[builtins.str]:
        '''The fleet type.

        - **ALWAYS_ON** - Provides users with instant-on access to their apps. You are charged for all running instances in your fleet, even if no users are streaming apps.
        - **ON_DEMAND** - Provide users with access to applications after they connect, which takes one to two minutes. You are charged for instance streaming when users are connected and a small hourly fee for instances that are not streaming apps.
        - **ELASTIC** - The pool of streaming instances is managed by Amazon AppStream 2.0. When a user selects their application or desktop to launch, they will start streaming after the app block has been downloaded and mounted to a streaming instance.

        *Allowed Values* : ``ALWAYS_ON`` | ``ELASTIC`` | ``ON_DEMAND``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-fleettype
        '''
        result = self._values.get("fleet_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def iam_role_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the IAM role that is applied to the fleet.

        To assume a role, the fleet instance calls the AWS Security Token Service ``AssumeRole`` API operation and passes the ARN of the role to use. The operation creates a new session with temporary credentials. AppStream 2.0 retrieves the temporary credentials and creates the *appstream_machine_role* credential profile on the instance.

        For more information, see `Using an IAM Role to Grant Permissions to Applications and Scripts Running on AppStream 2.0 Streaming Instances <https://docs.aws.amazon.com/appstream2/latest/developerguide/using-iam-roles-to-grant-permissions-to-applications-scripts-streaming-instances.html>`_ in the *Amazon AppStream 2.0 Administration Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-iamrolearn
        '''
        result = self._values.get("iam_role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def idle_disconnect_timeout_in_seconds(self) -> typing.Optional[jsii.Number]:
        '''The amount of time that users can be idle (inactive) before they are disconnected from their streaming session and the ``DisconnectTimeoutInSeconds`` time interval begins.

        Users are notified before they are disconnected due to inactivity. If they try to reconnect to the streaming session before the time interval specified in ``DisconnectTimeoutInSeconds`` elapses, they are connected to their previous session. Users are considered idle when they stop providing keyboard or mouse input during their streaming session. File uploads and downloads, audio in, audio out, and pixels changing do not qualify as user activity. If users continue to be idle after the time interval in ``IdleDisconnectTimeoutInSeconds`` elapses, they are disconnected.

        To prevent users from being disconnected due to inactivity, specify a value of 0. Otherwise, specify a value between 60 and 3600.

        If you enable this feature, we recommend that you specify a value that corresponds exactly to a whole number of minutes (for example, 60, 120, and 180). If you don't do this, the value is rounded to the nearest minute. For example, if you specify a value of 70, users are disconnected after 1 minute of inactivity. If you specify a value that is at the midpoint between two different minutes, the value is rounded up. For example, if you specify a value of 90, users are disconnected after 2 minutes of inactivity.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-idledisconnecttimeoutinseconds
        '''
        result = self._values.get("idle_disconnect_timeout_in_seconds")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def image_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the public, private, or shared image to use.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-imagearn
        '''
        result = self._values.get("image_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def image_name(self) -> typing.Optional[builtins.str]:
        '''The name of the image used to create the fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-imagename
        '''
        result = self._values.get("image_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def max_concurrent_sessions(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of concurrent sessions that can be run on an Elastic fleet.

        This setting is required for Elastic fleets, but is not used for other fleet types.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-maxconcurrentsessions
        '''
        result = self._values.get("max_concurrent_sessions")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def max_user_duration_in_seconds(self) -> typing.Optional[jsii.Number]:
        '''The maximum amount of time that a streaming session can remain active, in seconds.

        If users are still connected to a streaming instance five minutes before this limit is reached, they are prompted to save any open documents before being disconnected. After this time elapses, the instance is terminated and replaced by a new instance.

        Specify a value between 600 and 360000.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-maxuserdurationinseconds
        '''
        result = self._values.get("max_user_duration_in_seconds")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def platform(self) -> typing.Optional[builtins.str]:
        '''The platform of the fleet.

        Platform is a required setting for Elastic fleets, and is not used for other fleet types.

        *Allowed Values* : ``WINDOWS_SERVER_2019`` | ``AMAZON_LINUX2``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-platform
        '''
        result = self._values.get("platform")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def stream_view(self) -> typing.Optional[builtins.str]:
        '''The AppStream 2.0 view that is displayed to your users when they stream from the fleet. When ``APP`` is specified, only the windows of applications opened by users display. When ``DESKTOP`` is specified, the standard desktop that is provided by the operating system displays.

        The default value is ``APP`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-streamview
        '''
        result = self._values.get("stream_view")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An array of key-value pairs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def usb_device_filter_strings(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The USB device filter strings that specify which USB devices a user can redirect to the fleet streaming session, when using the Windows native client.

        This is allowed but not required for Elastic fleets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-usbdevicefilterstrings
        '''
        result = self._values.get("usb_device_filter_strings")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def vpc_config(
        self,
    ) -> typing.Optional[typing.Union[CfnFleet.VpcConfigProperty, _IResolvable_da3f097b]]:
        '''The VPC configuration for the fleet.

        This is required for Elastic fleets, but not required for other fleet types.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-fleet.html#cfn-appstream-fleet-vpcconfig
        '''
        result = self._values.get("vpc_config")
        return typing.cast(typing.Optional[typing.Union[CfnFleet.VpcConfigProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnFleetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnImageBuilder(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appstream.CfnImageBuilder",
):
    '''A CloudFormation ``AWS::AppStream::ImageBuilder``.

    The ``AWS::AppStream::ImageBuilder`` resource creates an image builder for Amazon AppStream 2.0. An image builder is a virtual machine that is used to create an image.

    The initial state of the image builder is ``PENDING`` . When it is ready, the state is ``RUNNING`` .

    :cloudformationResource: AWS::AppStream::ImageBuilder
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appstream as appstream
        
        cfn_image_builder = appstream.CfnImageBuilder(self, "MyCfnImageBuilder",
            instance_type="instanceType",
            name="name",
        
            # the properties below are optional
            access_endpoints=[appstream.CfnImageBuilder.AccessEndpointProperty(
                endpoint_type="endpointType",
                vpce_id="vpceId"
            )],
            appstream_agent_version="appstreamAgentVersion",
            description="description",
            display_name="displayName",
            domain_join_info=appstream.CfnImageBuilder.DomainJoinInfoProperty(
                directory_name="directoryName",
                organizational_unit_distinguished_name="organizationalUnitDistinguishedName"
            ),
            enable_default_internet_access=False,
            iam_role_arn="iamRoleArn",
            image_arn="imageArn",
            image_name="imageName",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            vpc_config=appstream.CfnImageBuilder.VpcConfigProperty(
                security_group_ids=["securityGroupIds"],
                subnet_ids=["subnetIds"]
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        instance_type: builtins.str,
        name: builtins.str,
        access_endpoints: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnImageBuilder.AccessEndpointProperty", _IResolvable_da3f097b]]]] = None,
        appstream_agent_version: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        display_name: typing.Optional[builtins.str] = None,
        domain_join_info: typing.Optional[typing.Union["CfnImageBuilder.DomainJoinInfoProperty", _IResolvable_da3f097b]] = None,
        enable_default_internet_access: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        iam_role_arn: typing.Optional[builtins.str] = None,
        image_arn: typing.Optional[builtins.str] = None,
        image_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        vpc_config: typing.Optional[typing.Union["CfnImageBuilder.VpcConfigProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::AppStream::ImageBuilder``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param instance_type: The instance type to use when launching the image builder. The following instance types are available:. - stream.standard.small - stream.standard.medium - stream.standard.large - stream.compute.large - stream.compute.xlarge - stream.compute.2xlarge - stream.compute.4xlarge - stream.compute.8xlarge - stream.memory.large - stream.memory.xlarge - stream.memory.2xlarge - stream.memory.4xlarge - stream.memory.8xlarge - stream.memory.z1d.large - stream.memory.z1d.xlarge - stream.memory.z1d.2xlarge - stream.memory.z1d.3xlarge - stream.memory.z1d.6xlarge - stream.memory.z1d.12xlarge - stream.graphics-design.large - stream.graphics-design.xlarge - stream.graphics-design.2xlarge - stream.graphics-design.4xlarge - stream.graphics-desktop.2xlarge - stream.graphics.g4dn.xlarge - stream.graphics.g4dn.2xlarge - stream.graphics.g4dn.4xlarge - stream.graphics.g4dn.8xlarge - stream.graphics.g4dn.12xlarge - stream.graphics.g4dn.16xlarge - stream.graphics-pro.4xlarge - stream.graphics-pro.8xlarge - stream.graphics-pro.16xlarge
        :param name: A unique name for the image builder.
        :param access_endpoints: The list of virtual private cloud (VPC) interface endpoint objects. Administrators can connect to the image builder only through the specified endpoints.
        :param appstream_agent_version: The version of the AppStream 2.0 agent to use for this image builder. To use the latest version of the AppStream 2.0 agent, specify [LATEST].
        :param description: The description to display.
        :param display_name: The image builder name to display.
        :param domain_join_info: The name of the directory and organizational unit (OU) to use to join the image builder to a Microsoft Active Directory domain.
        :param enable_default_internet_access: Enables or disables default internet access for the image builder.
        :param iam_role_arn: The ARN of the IAM role that is applied to the image builder. To assume a role, the image builder calls the AWS Security Token Service ``AssumeRole`` API operation and passes the ARN of the role to use. The operation creates a new session with temporary credentials. AppStream 2.0 retrieves the temporary credentials and creates the *appstream_machine_role* credential profile on the instance. For more information, see `Using an IAM Role to Grant Permissions to Applications and Scripts Running on AppStream 2.0 Streaming Instances <https://docs.aws.amazon.com/appstream2/latest/developerguide/using-iam-roles-to-grant-permissions-to-applications-scripts-streaming-instances.html>`_ in the *Amazon AppStream 2.0 Administration Guide* .
        :param image_arn: The ARN of the public, private, or shared image to use.
        :param image_name: The name of the image used to create the image builder.
        :param tags: An array of key-value pairs.
        :param vpc_config: The VPC configuration for the image builder. You can specify only one subnet.
        '''
        props = CfnImageBuilderProps(
            instance_type=instance_type,
            name=name,
            access_endpoints=access_endpoints,
            appstream_agent_version=appstream_agent_version,
            description=description,
            display_name=display_name,
            domain_join_info=domain_join_info,
            enable_default_internet_access=enable_default_internet_access,
            iam_role_arn=iam_role_arn,
            image_arn=image_arn,
            image_name=image_name,
            tags=tags,
            vpc_config=vpc_config,
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
    @jsii.member(jsii_name="attrStreamingUrl")
    def attr_streaming_url(self) -> builtins.str:
        '''The URL to start an image builder streaming session, returned as a string.

        :cloudformationAttribute: StreamingUrl
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStreamingUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceType")
    def instance_type(self) -> builtins.str:
        '''The instance type to use when launching the image builder. The following instance types are available:.

        - stream.standard.small
        - stream.standard.medium
        - stream.standard.large
        - stream.compute.large
        - stream.compute.xlarge
        - stream.compute.2xlarge
        - stream.compute.4xlarge
        - stream.compute.8xlarge
        - stream.memory.large
        - stream.memory.xlarge
        - stream.memory.2xlarge
        - stream.memory.4xlarge
        - stream.memory.8xlarge
        - stream.memory.z1d.large
        - stream.memory.z1d.xlarge
        - stream.memory.z1d.2xlarge
        - stream.memory.z1d.3xlarge
        - stream.memory.z1d.6xlarge
        - stream.memory.z1d.12xlarge
        - stream.graphics-design.large
        - stream.graphics-design.xlarge
        - stream.graphics-design.2xlarge
        - stream.graphics-design.4xlarge
        - stream.graphics-desktop.2xlarge
        - stream.graphics.g4dn.xlarge
        - stream.graphics.g4dn.2xlarge
        - stream.graphics.g4dn.4xlarge
        - stream.graphics.g4dn.8xlarge
        - stream.graphics.g4dn.12xlarge
        - stream.graphics.g4dn.16xlarge
        - stream.graphics-pro.4xlarge
        - stream.graphics-pro.8xlarge
        - stream.graphics-pro.16xlarge

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-instancetype
        '''
        return typing.cast(builtins.str, jsii.get(self, "instanceType"))

    @instance_type.setter
    def instance_type(self, value: builtins.str) -> None:
        jsii.set(self, "instanceType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''A unique name for the image builder.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accessEndpoints")
    def access_endpoints(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnImageBuilder.AccessEndpointProperty", _IResolvable_da3f097b]]]]:
        '''The list of virtual private cloud (VPC) interface endpoint objects.

        Administrators can connect to the image builder only through the specified endpoints.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-accessendpoints
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnImageBuilder.AccessEndpointProperty", _IResolvable_da3f097b]]]], jsii.get(self, "accessEndpoints"))

    @access_endpoints.setter
    def access_endpoints(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnImageBuilder.AccessEndpointProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "accessEndpoints", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="appstreamAgentVersion")
    def appstream_agent_version(self) -> typing.Optional[builtins.str]:
        '''The version of the AppStream 2.0 agent to use for this image builder. To use the latest version of the AppStream 2.0 agent, specify [LATEST].

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-appstreamagentversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "appstreamAgentVersion"))

    @appstream_agent_version.setter
    def appstream_agent_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "appstreamAgentVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description to display.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="displayName")
    def display_name(self) -> typing.Optional[builtins.str]:
        '''The image builder name to display.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-displayname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "displayName"))

    @display_name.setter
    def display_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "displayName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainJoinInfo")
    def domain_join_info(
        self,
    ) -> typing.Optional[typing.Union["CfnImageBuilder.DomainJoinInfoProperty", _IResolvable_da3f097b]]:
        '''The name of the directory and organizational unit (OU) to use to join the image builder to a Microsoft Active Directory domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-domainjoininfo
        '''
        return typing.cast(typing.Optional[typing.Union["CfnImageBuilder.DomainJoinInfoProperty", _IResolvable_da3f097b]], jsii.get(self, "domainJoinInfo"))

    @domain_join_info.setter
    def domain_join_info(
        self,
        value: typing.Optional[typing.Union["CfnImageBuilder.DomainJoinInfoProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "domainJoinInfo", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enableDefaultInternetAccess")
    def enable_default_internet_access(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables or disables default internet access for the image builder.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-enabledefaultinternetaccess
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enableDefaultInternetAccess"))

    @enable_default_internet_access.setter
    def enable_default_internet_access(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enableDefaultInternetAccess", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="iamRoleArn")
    def iam_role_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the IAM role that is applied to the image builder.

        To assume a role, the image builder calls the AWS Security Token Service ``AssumeRole`` API operation and passes the ARN of the role to use. The operation creates a new session with temporary credentials. AppStream 2.0 retrieves the temporary credentials and creates the *appstream_machine_role* credential profile on the instance.

        For more information, see `Using an IAM Role to Grant Permissions to Applications and Scripts Running on AppStream 2.0 Streaming Instances <https://docs.aws.amazon.com/appstream2/latest/developerguide/using-iam-roles-to-grant-permissions-to-applications-scripts-streaming-instances.html>`_ in the *Amazon AppStream 2.0 Administration Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-iamrolearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "iamRoleArn"))

    @iam_role_arn.setter
    def iam_role_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "iamRoleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="imageArn")
    def image_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the public, private, or shared image to use.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-imagearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "imageArn"))

    @image_arn.setter
    def image_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "imageArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="imageName")
    def image_name(self) -> typing.Optional[builtins.str]:
        '''The name of the image used to create the image builder.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-imagename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "imageName"))

    @image_name.setter
    def image_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "imageName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcConfig")
    def vpc_config(
        self,
    ) -> typing.Optional[typing.Union["CfnImageBuilder.VpcConfigProperty", _IResolvable_da3f097b]]:
        '''The VPC configuration for the image builder.

        You can specify only one subnet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-vpcconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnImageBuilder.VpcConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "vpcConfig"))

    @vpc_config.setter
    def vpc_config(
        self,
        value: typing.Optional[typing.Union["CfnImageBuilder.VpcConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "vpcConfig", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnImageBuilder.AccessEndpointProperty",
        jsii_struct_bases=[],
        name_mapping={"endpoint_type": "endpointType", "vpce_id": "vpceId"},
    )
    class AccessEndpointProperty:
        def __init__(
            self,
            *,
            endpoint_type: builtins.str,
            vpce_id: builtins.str,
        ) -> None:
            '''Describes an interface VPC endpoint (interface endpoint) that lets you create a private connection between the virtual private cloud (VPC) that you specify and AppStream 2.0. When you specify an interface endpoint for a stack, users of the stack can connect to AppStream 2.0 only through that endpoint. When you specify an interface endpoint for an image builder, administrators can connect to the image builder only through that endpoint.

            :param endpoint_type: The type of interface endpoint.
            :param vpce_id: The identifier (ID) of the VPC in which the interface endpoint is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-imagebuilder-accessendpoint.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                access_endpoint_property = appstream.CfnImageBuilder.AccessEndpointProperty(
                    endpoint_type="endpointType",
                    vpce_id="vpceId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "endpoint_type": endpoint_type,
                "vpce_id": vpce_id,
            }

        @builtins.property
        def endpoint_type(self) -> builtins.str:
            '''The type of interface endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-imagebuilder-accessendpoint.html#cfn-appstream-imagebuilder-accessendpoint-endpointtype
            '''
            result = self._values.get("endpoint_type")
            assert result is not None, "Required property 'endpoint_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def vpce_id(self) -> builtins.str:
            '''The identifier (ID) of the VPC in which the interface endpoint is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-imagebuilder-accessendpoint.html#cfn-appstream-imagebuilder-accessendpoint-vpceid
            '''
            result = self._values.get("vpce_id")
            assert result is not None, "Required property 'vpce_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AccessEndpointProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnImageBuilder.DomainJoinInfoProperty",
        jsii_struct_bases=[],
        name_mapping={
            "directory_name": "directoryName",
            "organizational_unit_distinguished_name": "organizationalUnitDistinguishedName",
        },
    )
    class DomainJoinInfoProperty:
        def __init__(
            self,
            *,
            directory_name: typing.Optional[builtins.str] = None,
            organizational_unit_distinguished_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The name of the directory and organizational unit (OU) to use to join the image builder to a Microsoft Active Directory domain.

            :param directory_name: The fully qualified name of the directory (for example, corp.example.com).
            :param organizational_unit_distinguished_name: The distinguished name of the organizational unit for computer accounts.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-imagebuilder-domainjoininfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                domain_join_info_property = appstream.CfnImageBuilder.DomainJoinInfoProperty(
                    directory_name="directoryName",
                    organizational_unit_distinguished_name="organizationalUnitDistinguishedName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if directory_name is not None:
                self._values["directory_name"] = directory_name
            if organizational_unit_distinguished_name is not None:
                self._values["organizational_unit_distinguished_name"] = organizational_unit_distinguished_name

        @builtins.property
        def directory_name(self) -> typing.Optional[builtins.str]:
            '''The fully qualified name of the directory (for example, corp.example.com).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-imagebuilder-domainjoininfo.html#cfn-appstream-imagebuilder-domainjoininfo-directoryname
            '''
            result = self._values.get("directory_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def organizational_unit_distinguished_name(
            self,
        ) -> typing.Optional[builtins.str]:
            '''The distinguished name of the organizational unit for computer accounts.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-imagebuilder-domainjoininfo.html#cfn-appstream-imagebuilder-domainjoininfo-organizationalunitdistinguishedname
            '''
            result = self._values.get("organizational_unit_distinguished_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DomainJoinInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnImageBuilder.VpcConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "security_group_ids": "securityGroupIds",
            "subnet_ids": "subnetIds",
        },
    )
    class VpcConfigProperty:
        def __init__(
            self,
            *,
            security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
            subnet_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''The VPC configuration for the image builder.

            :param security_group_ids: The identifiers of the security groups for the image builder.
            :param subnet_ids: The identifier of the subnet to which a network interface is attached from the image builder instance. An image builder instance can use one subnet.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-imagebuilder-vpcconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                vpc_config_property = appstream.CfnImageBuilder.VpcConfigProperty(
                    security_group_ids=["securityGroupIds"],
                    subnet_ids=["subnetIds"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if security_group_ids is not None:
                self._values["security_group_ids"] = security_group_ids
            if subnet_ids is not None:
                self._values["subnet_ids"] = subnet_ids

        @builtins.property
        def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The identifiers of the security groups for the image builder.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-imagebuilder-vpcconfig.html#cfn-appstream-imagebuilder-vpcconfig-securitygroupids
            '''
            result = self._values.get("security_group_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def subnet_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The identifier of the subnet to which a network interface is attached from the image builder instance.

            An image builder instance can use one subnet.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-imagebuilder-vpcconfig.html#cfn-appstream-imagebuilder-vpcconfig-subnetids
            '''
            result = self._values.get("subnet_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VpcConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appstream.CfnImageBuilderProps",
    jsii_struct_bases=[],
    name_mapping={
        "instance_type": "instanceType",
        "name": "name",
        "access_endpoints": "accessEndpoints",
        "appstream_agent_version": "appstreamAgentVersion",
        "description": "description",
        "display_name": "displayName",
        "domain_join_info": "domainJoinInfo",
        "enable_default_internet_access": "enableDefaultInternetAccess",
        "iam_role_arn": "iamRoleArn",
        "image_arn": "imageArn",
        "image_name": "imageName",
        "tags": "tags",
        "vpc_config": "vpcConfig",
    },
)
class CfnImageBuilderProps:
    def __init__(
        self,
        *,
        instance_type: builtins.str,
        name: builtins.str,
        access_endpoints: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnImageBuilder.AccessEndpointProperty, _IResolvable_da3f097b]]]] = None,
        appstream_agent_version: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        display_name: typing.Optional[builtins.str] = None,
        domain_join_info: typing.Optional[typing.Union[CfnImageBuilder.DomainJoinInfoProperty, _IResolvable_da3f097b]] = None,
        enable_default_internet_access: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        iam_role_arn: typing.Optional[builtins.str] = None,
        image_arn: typing.Optional[builtins.str] = None,
        image_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        vpc_config: typing.Optional[typing.Union[CfnImageBuilder.VpcConfigProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnImageBuilder``.

        :param instance_type: The instance type to use when launching the image builder. The following instance types are available:. - stream.standard.small - stream.standard.medium - stream.standard.large - stream.compute.large - stream.compute.xlarge - stream.compute.2xlarge - stream.compute.4xlarge - stream.compute.8xlarge - stream.memory.large - stream.memory.xlarge - stream.memory.2xlarge - stream.memory.4xlarge - stream.memory.8xlarge - stream.memory.z1d.large - stream.memory.z1d.xlarge - stream.memory.z1d.2xlarge - stream.memory.z1d.3xlarge - stream.memory.z1d.6xlarge - stream.memory.z1d.12xlarge - stream.graphics-design.large - stream.graphics-design.xlarge - stream.graphics-design.2xlarge - stream.graphics-design.4xlarge - stream.graphics-desktop.2xlarge - stream.graphics.g4dn.xlarge - stream.graphics.g4dn.2xlarge - stream.graphics.g4dn.4xlarge - stream.graphics.g4dn.8xlarge - stream.graphics.g4dn.12xlarge - stream.graphics.g4dn.16xlarge - stream.graphics-pro.4xlarge - stream.graphics-pro.8xlarge - stream.graphics-pro.16xlarge
        :param name: A unique name for the image builder.
        :param access_endpoints: The list of virtual private cloud (VPC) interface endpoint objects. Administrators can connect to the image builder only through the specified endpoints.
        :param appstream_agent_version: The version of the AppStream 2.0 agent to use for this image builder. To use the latest version of the AppStream 2.0 agent, specify [LATEST].
        :param description: The description to display.
        :param display_name: The image builder name to display.
        :param domain_join_info: The name of the directory and organizational unit (OU) to use to join the image builder to a Microsoft Active Directory domain.
        :param enable_default_internet_access: Enables or disables default internet access for the image builder.
        :param iam_role_arn: The ARN of the IAM role that is applied to the image builder. To assume a role, the image builder calls the AWS Security Token Service ``AssumeRole`` API operation and passes the ARN of the role to use. The operation creates a new session with temporary credentials. AppStream 2.0 retrieves the temporary credentials and creates the *appstream_machine_role* credential profile on the instance. For more information, see `Using an IAM Role to Grant Permissions to Applications and Scripts Running on AppStream 2.0 Streaming Instances <https://docs.aws.amazon.com/appstream2/latest/developerguide/using-iam-roles-to-grant-permissions-to-applications-scripts-streaming-instances.html>`_ in the *Amazon AppStream 2.0 Administration Guide* .
        :param image_arn: The ARN of the public, private, or shared image to use.
        :param image_name: The name of the image used to create the image builder.
        :param tags: An array of key-value pairs.
        :param vpc_config: The VPC configuration for the image builder. You can specify only one subnet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appstream as appstream
            
            cfn_image_builder_props = appstream.CfnImageBuilderProps(
                instance_type="instanceType",
                name="name",
            
                # the properties below are optional
                access_endpoints=[appstream.CfnImageBuilder.AccessEndpointProperty(
                    endpoint_type="endpointType",
                    vpce_id="vpceId"
                )],
                appstream_agent_version="appstreamAgentVersion",
                description="description",
                display_name="displayName",
                domain_join_info=appstream.CfnImageBuilder.DomainJoinInfoProperty(
                    directory_name="directoryName",
                    organizational_unit_distinguished_name="organizationalUnitDistinguishedName"
                ),
                enable_default_internet_access=False,
                iam_role_arn="iamRoleArn",
                image_arn="imageArn",
                image_name="imageName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                vpc_config=appstream.CfnImageBuilder.VpcConfigProperty(
                    security_group_ids=["securityGroupIds"],
                    subnet_ids=["subnetIds"]
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "instance_type": instance_type,
            "name": name,
        }
        if access_endpoints is not None:
            self._values["access_endpoints"] = access_endpoints
        if appstream_agent_version is not None:
            self._values["appstream_agent_version"] = appstream_agent_version
        if description is not None:
            self._values["description"] = description
        if display_name is not None:
            self._values["display_name"] = display_name
        if domain_join_info is not None:
            self._values["domain_join_info"] = domain_join_info
        if enable_default_internet_access is not None:
            self._values["enable_default_internet_access"] = enable_default_internet_access
        if iam_role_arn is not None:
            self._values["iam_role_arn"] = iam_role_arn
        if image_arn is not None:
            self._values["image_arn"] = image_arn
        if image_name is not None:
            self._values["image_name"] = image_name
        if tags is not None:
            self._values["tags"] = tags
        if vpc_config is not None:
            self._values["vpc_config"] = vpc_config

    @builtins.property
    def instance_type(self) -> builtins.str:
        '''The instance type to use when launching the image builder. The following instance types are available:.

        - stream.standard.small
        - stream.standard.medium
        - stream.standard.large
        - stream.compute.large
        - stream.compute.xlarge
        - stream.compute.2xlarge
        - stream.compute.4xlarge
        - stream.compute.8xlarge
        - stream.memory.large
        - stream.memory.xlarge
        - stream.memory.2xlarge
        - stream.memory.4xlarge
        - stream.memory.8xlarge
        - stream.memory.z1d.large
        - stream.memory.z1d.xlarge
        - stream.memory.z1d.2xlarge
        - stream.memory.z1d.3xlarge
        - stream.memory.z1d.6xlarge
        - stream.memory.z1d.12xlarge
        - stream.graphics-design.large
        - stream.graphics-design.xlarge
        - stream.graphics-design.2xlarge
        - stream.graphics-design.4xlarge
        - stream.graphics-desktop.2xlarge
        - stream.graphics.g4dn.xlarge
        - stream.graphics.g4dn.2xlarge
        - stream.graphics.g4dn.4xlarge
        - stream.graphics.g4dn.8xlarge
        - stream.graphics.g4dn.12xlarge
        - stream.graphics.g4dn.16xlarge
        - stream.graphics-pro.4xlarge
        - stream.graphics-pro.8xlarge
        - stream.graphics-pro.16xlarge

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-instancetype
        '''
        result = self._values.get("instance_type")
        assert result is not None, "Required property 'instance_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''A unique name for the image builder.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def access_endpoints(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnImageBuilder.AccessEndpointProperty, _IResolvable_da3f097b]]]]:
        '''The list of virtual private cloud (VPC) interface endpoint objects.

        Administrators can connect to the image builder only through the specified endpoints.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-accessendpoints
        '''
        result = self._values.get("access_endpoints")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnImageBuilder.AccessEndpointProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def appstream_agent_version(self) -> typing.Optional[builtins.str]:
        '''The version of the AppStream 2.0 agent to use for this image builder. To use the latest version of the AppStream 2.0 agent, specify [LATEST].

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-appstreamagentversion
        '''
        result = self._values.get("appstream_agent_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description to display.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def display_name(self) -> typing.Optional[builtins.str]:
        '''The image builder name to display.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-displayname
        '''
        result = self._values.get("display_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def domain_join_info(
        self,
    ) -> typing.Optional[typing.Union[CfnImageBuilder.DomainJoinInfoProperty, _IResolvable_da3f097b]]:
        '''The name of the directory and organizational unit (OU) to use to join the image builder to a Microsoft Active Directory domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-domainjoininfo
        '''
        result = self._values.get("domain_join_info")
        return typing.cast(typing.Optional[typing.Union[CfnImageBuilder.DomainJoinInfoProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def enable_default_internet_access(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables or disables default internet access for the image builder.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-enabledefaultinternetaccess
        '''
        result = self._values.get("enable_default_internet_access")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def iam_role_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the IAM role that is applied to the image builder.

        To assume a role, the image builder calls the AWS Security Token Service ``AssumeRole`` API operation and passes the ARN of the role to use. The operation creates a new session with temporary credentials. AppStream 2.0 retrieves the temporary credentials and creates the *appstream_machine_role* credential profile on the instance.

        For more information, see `Using an IAM Role to Grant Permissions to Applications and Scripts Running on AppStream 2.0 Streaming Instances <https://docs.aws.amazon.com/appstream2/latest/developerguide/using-iam-roles-to-grant-permissions-to-applications-scripts-streaming-instances.html>`_ in the *Amazon AppStream 2.0 Administration Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-iamrolearn
        '''
        result = self._values.get("iam_role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def image_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the public, private, or shared image to use.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-imagearn
        '''
        result = self._values.get("image_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def image_name(self) -> typing.Optional[builtins.str]:
        '''The name of the image used to create the image builder.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-imagename
        '''
        result = self._values.get("image_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An array of key-value pairs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def vpc_config(
        self,
    ) -> typing.Optional[typing.Union[CfnImageBuilder.VpcConfigProperty, _IResolvable_da3f097b]]:
        '''The VPC configuration for the image builder.

        You can specify only one subnet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-imagebuilder.html#cfn-appstream-imagebuilder-vpcconfig
        '''
        result = self._values.get("vpc_config")
        return typing.cast(typing.Optional[typing.Union[CfnImageBuilder.VpcConfigProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnImageBuilderProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnStack(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appstream.CfnStack",
):
    '''A CloudFormation ``AWS::AppStream::Stack``.

    The ``AWS::AppStream::Stack`` resource creates a stack to start streaming applications to Amazon AppStream 2.0 users. A stack consists of an associated fleet, user access policies, and storage configurations.

    :cloudformationResource: AWS::AppStream::Stack
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appstream as appstream
        
        cfn_stack = appstream.CfnStack(self, "MyCfnStack",
            access_endpoints=[appstream.CfnStack.AccessEndpointProperty(
                endpoint_type="endpointType",
                vpce_id="vpceId"
            )],
            application_settings=appstream.CfnStack.ApplicationSettingsProperty(
                enabled=False,
        
                # the properties below are optional
                settings_group="settingsGroup"
            ),
            attributes_to_delete=["attributesToDelete"],
            delete_storage_connectors=False,
            description="description",
            display_name="displayName",
            embed_host_domains=["embedHostDomains"],
            feedback_url="feedbackUrl",
            name="name",
            redirect_url="redirectUrl",
            storage_connectors=[appstream.CfnStack.StorageConnectorProperty(
                connector_type="connectorType",
        
                # the properties below are optional
                domains=["domains"],
                resource_identifier="resourceIdentifier"
            )],
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            user_settings=[appstream.CfnStack.UserSettingProperty(
                action="action",
                permission="permission"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        access_endpoints: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnStack.AccessEndpointProperty", _IResolvable_da3f097b]]]] = None,
        application_settings: typing.Optional[typing.Union["CfnStack.ApplicationSettingsProperty", _IResolvable_da3f097b]] = None,
        attributes_to_delete: typing.Optional[typing.Sequence[builtins.str]] = None,
        delete_storage_connectors: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        display_name: typing.Optional[builtins.str] = None,
        embed_host_domains: typing.Optional[typing.Sequence[builtins.str]] = None,
        feedback_url: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        redirect_url: typing.Optional[builtins.str] = None,
        storage_connectors: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnStack.StorageConnectorProperty", _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        user_settings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnStack.UserSettingProperty", _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Create a new ``AWS::AppStream::Stack``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param access_endpoints: The list of virtual private cloud (VPC) interface endpoint objects. Users of the stack can connect to AppStream 2.0 only through the specified endpoints.
        :param application_settings: The persistent application settings for users of the stack. When these settings are enabled, changes that users make to applications and Windows settings are automatically saved after each session and applied to the next session.
        :param attributes_to_delete: The stack attributes to delete.
        :param delete_storage_connectors: *This parameter has been deprecated.*. Deletes the storage connectors currently enabled for the stack.
        :param description: The description to display.
        :param display_name: The stack name to display.
        :param embed_host_domains: The domains where AppStream 2.0 streaming sessions can be embedded in an iframe. You must approve the domains that you want to host embedded AppStream 2.0 streaming sessions.
        :param feedback_url: The URL that users are redirected to after they click the Send Feedback link. If no URL is specified, no Send Feedback link is displayed.
        :param name: The name of the stack.
        :param redirect_url: The URL that users are redirected to after their streaming session ends.
        :param storage_connectors: The storage connectors to enable.
        :param tags: An array of key-value pairs.
        :param user_settings: The actions that are enabled or disabled for users during their streaming sessions. By default, these actions are enabled.
        '''
        props = CfnStackProps(
            access_endpoints=access_endpoints,
            application_settings=application_settings,
            attributes_to_delete=attributes_to_delete,
            delete_storage_connectors=delete_storage_connectors,
            description=description,
            display_name=display_name,
            embed_host_domains=embed_host_domains,
            feedback_url=feedback_url,
            name=name,
            redirect_url=redirect_url,
            storage_connectors=storage_connectors,
            tags=tags,
            user_settings=user_settings,
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
        '''An array of key-value pairs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accessEndpoints")
    def access_endpoints(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStack.AccessEndpointProperty", _IResolvable_da3f097b]]]]:
        '''The list of virtual private cloud (VPC) interface endpoint objects.

        Users of the stack can connect to AppStream 2.0 only through the specified endpoints.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-accessendpoints
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStack.AccessEndpointProperty", _IResolvable_da3f097b]]]], jsii.get(self, "accessEndpoints"))

    @access_endpoints.setter
    def access_endpoints(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStack.AccessEndpointProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "accessEndpoints", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="applicationSettings")
    def application_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnStack.ApplicationSettingsProperty", _IResolvable_da3f097b]]:
        '''The persistent application settings for users of the stack.

        When these settings are enabled, changes that users make to applications and Windows settings are automatically saved after each session and applied to the next session.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-applicationsettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnStack.ApplicationSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "applicationSettings"))

    @application_settings.setter
    def application_settings(
        self,
        value: typing.Optional[typing.Union["CfnStack.ApplicationSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "applicationSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attributesToDelete")
    def attributes_to_delete(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The stack attributes to delete.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-attributestodelete
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "attributesToDelete"))

    @attributes_to_delete.setter
    def attributes_to_delete(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "attributesToDelete", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="deleteStorageConnectors")
    def delete_storage_connectors(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''*This parameter has been deprecated.*.

        Deletes the storage connectors currently enabled for the stack.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-deletestorageconnectors
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "deleteStorageConnectors"))

    @delete_storage_connectors.setter
    def delete_storage_connectors(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "deleteStorageConnectors", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description to display.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="displayName")
    def display_name(self) -> typing.Optional[builtins.str]:
        '''The stack name to display.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-displayname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "displayName"))

    @display_name.setter
    def display_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "displayName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="embedHostDomains")
    def embed_host_domains(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The domains where AppStream 2.0 streaming sessions can be embedded in an iframe. You must approve the domains that you want to host embedded AppStream 2.0 streaming sessions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-embedhostdomains
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "embedHostDomains"))

    @embed_host_domains.setter
    def embed_host_domains(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "embedHostDomains", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="feedbackUrl")
    def feedback_url(self) -> typing.Optional[builtins.str]:
        '''The URL that users are redirected to after they click the Send Feedback link.

        If no URL is specified, no Send Feedback link is displayed.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-feedbackurl
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "feedbackUrl"))

    @feedback_url.setter
    def feedback_url(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "feedbackUrl", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the stack.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="redirectUrl")
    def redirect_url(self) -> typing.Optional[builtins.str]:
        '''The URL that users are redirected to after their streaming session ends.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-redirecturl
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "redirectUrl"))

    @redirect_url.setter
    def redirect_url(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "redirectUrl", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="storageConnectors")
    def storage_connectors(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStack.StorageConnectorProperty", _IResolvable_da3f097b]]]]:
        '''The storage connectors to enable.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-storageconnectors
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStack.StorageConnectorProperty", _IResolvable_da3f097b]]]], jsii.get(self, "storageConnectors"))

    @storage_connectors.setter
    def storage_connectors(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStack.StorageConnectorProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "storageConnectors", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userSettings")
    def user_settings(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStack.UserSettingProperty", _IResolvable_da3f097b]]]]:
        '''The actions that are enabled or disabled for users during their streaming sessions.

        By default, these actions are enabled.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-usersettings
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStack.UserSettingProperty", _IResolvable_da3f097b]]]], jsii.get(self, "userSettings"))

    @user_settings.setter
    def user_settings(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStack.UserSettingProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "userSettings", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnStack.AccessEndpointProperty",
        jsii_struct_bases=[],
        name_mapping={"endpoint_type": "endpointType", "vpce_id": "vpceId"},
    )
    class AccessEndpointProperty:
        def __init__(
            self,
            *,
            endpoint_type: builtins.str,
            vpce_id: builtins.str,
        ) -> None:
            '''Describes an interface VPC endpoint (interface endpoint) that lets you create a private connection between the virtual private cloud (VPC) that you specify and AppStream 2.0. When you specify an interface endpoint for a stack, users of the stack can connect to AppStream 2.0 only through that endpoint. When you specify an interface endpoint for an image builder, administrators can connect to the image builder only through that endpoint.

            :param endpoint_type: The type of interface endpoint.
            :param vpce_id: The identifier (ID) of the VPC in which the interface endpoint is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-stack-accessendpoint.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                access_endpoint_property = appstream.CfnStack.AccessEndpointProperty(
                    endpoint_type="endpointType",
                    vpce_id="vpceId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "endpoint_type": endpoint_type,
                "vpce_id": vpce_id,
            }

        @builtins.property
        def endpoint_type(self) -> builtins.str:
            '''The type of interface endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-stack-accessendpoint.html#cfn-appstream-stack-accessendpoint-endpointtype
            '''
            result = self._values.get("endpoint_type")
            assert result is not None, "Required property 'endpoint_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def vpce_id(self) -> builtins.str:
            '''The identifier (ID) of the VPC in which the interface endpoint is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-stack-accessendpoint.html#cfn-appstream-stack-accessendpoint-vpceid
            '''
            result = self._values.get("vpce_id")
            assert result is not None, "Required property 'vpce_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AccessEndpointProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnStack.ApplicationSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={"enabled": "enabled", "settings_group": "settingsGroup"},
    )
    class ApplicationSettingsProperty:
        def __init__(
            self,
            *,
            enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
            settings_group: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The persistent application settings for users of a stack.

            :param enabled: Enables or disables persistent application settings for users during their streaming sessions.
            :param settings_group: The path prefix for the S3 bucket where users’ persistent application settings are stored. You can allow the same persistent application settings to be used across multiple stacks by specifying the same settings group for each stack.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-stack-applicationsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                application_settings_property = appstream.CfnStack.ApplicationSettingsProperty(
                    enabled=False,
                
                    # the properties below are optional
                    settings_group="settingsGroup"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "enabled": enabled,
            }
            if settings_group is not None:
                self._values["settings_group"] = settings_group

        @builtins.property
        def enabled(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Enables or disables persistent application settings for users during their streaming sessions.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-stack-applicationsettings.html#cfn-appstream-stack-applicationsettings-enabled
            '''
            result = self._values.get("enabled")
            assert result is not None, "Required property 'enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def settings_group(self) -> typing.Optional[builtins.str]:
            '''The path prefix for the S3 bucket where users’ persistent application settings are stored.

            You can allow the same persistent application settings to be used across multiple stacks by specifying the same settings group for each stack.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-stack-applicationsettings.html#cfn-appstream-stack-applicationsettings-settingsgroup
            '''
            result = self._values.get("settings_group")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ApplicationSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnStack.StorageConnectorProperty",
        jsii_struct_bases=[],
        name_mapping={
            "connector_type": "connectorType",
            "domains": "domains",
            "resource_identifier": "resourceIdentifier",
        },
    )
    class StorageConnectorProperty:
        def __init__(
            self,
            *,
            connector_type: builtins.str,
            domains: typing.Optional[typing.Sequence[builtins.str]] = None,
            resource_identifier: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A connector that enables persistent storage for users.

            :param connector_type: The type of storage connector.
            :param domains: The names of the domains for the account.
            :param resource_identifier: The ARN of the storage connector.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-stack-storageconnector.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                storage_connector_property = appstream.CfnStack.StorageConnectorProperty(
                    connector_type="connectorType",
                
                    # the properties below are optional
                    domains=["domains"],
                    resource_identifier="resourceIdentifier"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "connector_type": connector_type,
            }
            if domains is not None:
                self._values["domains"] = domains
            if resource_identifier is not None:
                self._values["resource_identifier"] = resource_identifier

        @builtins.property
        def connector_type(self) -> builtins.str:
            '''The type of storage connector.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-stack-storageconnector.html#cfn-appstream-stack-storageconnector-connectortype
            '''
            result = self._values.get("connector_type")
            assert result is not None, "Required property 'connector_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def domains(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The names of the domains for the account.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-stack-storageconnector.html#cfn-appstream-stack-storageconnector-domains
            '''
            result = self._values.get("domains")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def resource_identifier(self) -> typing.Optional[builtins.str]:
            '''The ARN of the storage connector.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-stack-storageconnector.html#cfn-appstream-stack-storageconnector-resourceidentifier
            '''
            result = self._values.get("resource_identifier")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StorageConnectorProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appstream.CfnStack.UserSettingProperty",
        jsii_struct_bases=[],
        name_mapping={"action": "action", "permission": "permission"},
    )
    class UserSettingProperty:
        def __init__(self, *, action: builtins.str, permission: builtins.str) -> None:
            '''Specifies an action and whether the action is enabled or disabled for users during their streaming sessions.

            :param action: The action that is enabled or disabled.
            :param permission: Indicates whether the action is enabled or disabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-stack-usersetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appstream as appstream
                
                user_setting_property = appstream.CfnStack.UserSettingProperty(
                    action="action",
                    permission="permission"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "action": action,
                "permission": permission,
            }

        @builtins.property
        def action(self) -> builtins.str:
            '''The action that is enabled or disabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-stack-usersetting.html#cfn-appstream-stack-usersetting-action
            '''
            result = self._values.get("action")
            assert result is not None, "Required property 'action' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def permission(self) -> builtins.str:
            '''Indicates whether the action is enabled or disabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appstream-stack-usersetting.html#cfn-appstream-stack-usersetting-permission
            '''
            result = self._values.get("permission")
            assert result is not None, "Required property 'permission' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "UserSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnStackFleetAssociation(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appstream.CfnStackFleetAssociation",
):
    '''A CloudFormation ``AWS::AppStream::StackFleetAssociation``.

    The ``AWS::AppStream::StackFleetAssociation`` resource associates the specified fleet with the specified stack for Amazon AppStream 2.0.

    :cloudformationResource: AWS::AppStream::StackFleetAssociation
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackfleetassociation.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appstream as appstream
        
        cfn_stack_fleet_association = appstream.CfnStackFleetAssociation(self, "MyCfnStackFleetAssociation",
            fleet_name="fleetName",
            stack_name="stackName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        fleet_name: builtins.str,
        stack_name: builtins.str,
    ) -> None:
        '''Create a new ``AWS::AppStream::StackFleetAssociation``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param fleet_name: The name of the fleet. To associate a fleet with a stack, you must specify a dependency on the fleet resource. For more information, see `DependsOn Attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ .
        :param stack_name: The name of the stack. To associate a fleet with a stack, you must specify a dependency on the stack resource. For more information, see `DependsOn Attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ .
        '''
        props = CfnStackFleetAssociationProps(
            fleet_name=fleet_name, stack_name=stack_name
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
    @jsii.member(jsii_name="fleetName")
    def fleet_name(self) -> builtins.str:
        '''The name of the fleet.

        To associate a fleet with a stack, you must specify a dependency on the fleet resource. For more information, see `DependsOn Attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackfleetassociation.html#cfn-appstream-stackfleetassociation-fleetname
        '''
        return typing.cast(builtins.str, jsii.get(self, "fleetName"))

    @fleet_name.setter
    def fleet_name(self, value: builtins.str) -> None:
        jsii.set(self, "fleetName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="stackName")
    def stack_name(self) -> builtins.str:
        '''The name of the stack.

        To associate a fleet with a stack, you must specify a dependency on the stack resource. For more information, see `DependsOn Attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackfleetassociation.html#cfn-appstream-stackfleetassociation-stackname
        '''
        return typing.cast(builtins.str, jsii.get(self, "stackName"))

    @stack_name.setter
    def stack_name(self, value: builtins.str) -> None:
        jsii.set(self, "stackName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appstream.CfnStackFleetAssociationProps",
    jsii_struct_bases=[],
    name_mapping={"fleet_name": "fleetName", "stack_name": "stackName"},
)
class CfnStackFleetAssociationProps:
    def __init__(self, *, fleet_name: builtins.str, stack_name: builtins.str) -> None:
        '''Properties for defining a ``CfnStackFleetAssociation``.

        :param fleet_name: The name of the fleet. To associate a fleet with a stack, you must specify a dependency on the fleet resource. For more information, see `DependsOn Attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ .
        :param stack_name: The name of the stack. To associate a fleet with a stack, you must specify a dependency on the stack resource. For more information, see `DependsOn Attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackfleetassociation.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appstream as appstream
            
            cfn_stack_fleet_association_props = appstream.CfnStackFleetAssociationProps(
                fleet_name="fleetName",
                stack_name="stackName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "fleet_name": fleet_name,
            "stack_name": stack_name,
        }

    @builtins.property
    def fleet_name(self) -> builtins.str:
        '''The name of the fleet.

        To associate a fleet with a stack, you must specify a dependency on the fleet resource. For more information, see `DependsOn Attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackfleetassociation.html#cfn-appstream-stackfleetassociation-fleetname
        '''
        result = self._values.get("fleet_name")
        assert result is not None, "Required property 'fleet_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def stack_name(self) -> builtins.str:
        '''The name of the stack.

        To associate a fleet with a stack, you must specify a dependency on the stack resource. For more information, see `DependsOn Attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackfleetassociation.html#cfn-appstream-stackfleetassociation-stackname
        '''
        result = self._values.get("stack_name")
        assert result is not None, "Required property 'stack_name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnStackFleetAssociationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appstream.CfnStackProps",
    jsii_struct_bases=[],
    name_mapping={
        "access_endpoints": "accessEndpoints",
        "application_settings": "applicationSettings",
        "attributes_to_delete": "attributesToDelete",
        "delete_storage_connectors": "deleteStorageConnectors",
        "description": "description",
        "display_name": "displayName",
        "embed_host_domains": "embedHostDomains",
        "feedback_url": "feedbackUrl",
        "name": "name",
        "redirect_url": "redirectUrl",
        "storage_connectors": "storageConnectors",
        "tags": "tags",
        "user_settings": "userSettings",
    },
)
class CfnStackProps:
    def __init__(
        self,
        *,
        access_endpoints: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnStack.AccessEndpointProperty, _IResolvable_da3f097b]]]] = None,
        application_settings: typing.Optional[typing.Union[CfnStack.ApplicationSettingsProperty, _IResolvable_da3f097b]] = None,
        attributes_to_delete: typing.Optional[typing.Sequence[builtins.str]] = None,
        delete_storage_connectors: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        display_name: typing.Optional[builtins.str] = None,
        embed_host_domains: typing.Optional[typing.Sequence[builtins.str]] = None,
        feedback_url: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        redirect_url: typing.Optional[builtins.str] = None,
        storage_connectors: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnStack.StorageConnectorProperty, _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        user_settings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnStack.UserSettingProperty, _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnStack``.

        :param access_endpoints: The list of virtual private cloud (VPC) interface endpoint objects. Users of the stack can connect to AppStream 2.0 only through the specified endpoints.
        :param application_settings: The persistent application settings for users of the stack. When these settings are enabled, changes that users make to applications and Windows settings are automatically saved after each session and applied to the next session.
        :param attributes_to_delete: The stack attributes to delete.
        :param delete_storage_connectors: *This parameter has been deprecated.*. Deletes the storage connectors currently enabled for the stack.
        :param description: The description to display.
        :param display_name: The stack name to display.
        :param embed_host_domains: The domains where AppStream 2.0 streaming sessions can be embedded in an iframe. You must approve the domains that you want to host embedded AppStream 2.0 streaming sessions.
        :param feedback_url: The URL that users are redirected to after they click the Send Feedback link. If no URL is specified, no Send Feedback link is displayed.
        :param name: The name of the stack.
        :param redirect_url: The URL that users are redirected to after their streaming session ends.
        :param storage_connectors: The storage connectors to enable.
        :param tags: An array of key-value pairs.
        :param user_settings: The actions that are enabled or disabled for users during their streaming sessions. By default, these actions are enabled.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appstream as appstream
            
            cfn_stack_props = appstream.CfnStackProps(
                access_endpoints=[appstream.CfnStack.AccessEndpointProperty(
                    endpoint_type="endpointType",
                    vpce_id="vpceId"
                )],
                application_settings=appstream.CfnStack.ApplicationSettingsProperty(
                    enabled=False,
            
                    # the properties below are optional
                    settings_group="settingsGroup"
                ),
                attributes_to_delete=["attributesToDelete"],
                delete_storage_connectors=False,
                description="description",
                display_name="displayName",
                embed_host_domains=["embedHostDomains"],
                feedback_url="feedbackUrl",
                name="name",
                redirect_url="redirectUrl",
                storage_connectors=[appstream.CfnStack.StorageConnectorProperty(
                    connector_type="connectorType",
            
                    # the properties below are optional
                    domains=["domains"],
                    resource_identifier="resourceIdentifier"
                )],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                user_settings=[appstream.CfnStack.UserSettingProperty(
                    action="action",
                    permission="permission"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if access_endpoints is not None:
            self._values["access_endpoints"] = access_endpoints
        if application_settings is not None:
            self._values["application_settings"] = application_settings
        if attributes_to_delete is not None:
            self._values["attributes_to_delete"] = attributes_to_delete
        if delete_storage_connectors is not None:
            self._values["delete_storage_connectors"] = delete_storage_connectors
        if description is not None:
            self._values["description"] = description
        if display_name is not None:
            self._values["display_name"] = display_name
        if embed_host_domains is not None:
            self._values["embed_host_domains"] = embed_host_domains
        if feedback_url is not None:
            self._values["feedback_url"] = feedback_url
        if name is not None:
            self._values["name"] = name
        if redirect_url is not None:
            self._values["redirect_url"] = redirect_url
        if storage_connectors is not None:
            self._values["storage_connectors"] = storage_connectors
        if tags is not None:
            self._values["tags"] = tags
        if user_settings is not None:
            self._values["user_settings"] = user_settings

    @builtins.property
    def access_endpoints(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnStack.AccessEndpointProperty, _IResolvable_da3f097b]]]]:
        '''The list of virtual private cloud (VPC) interface endpoint objects.

        Users of the stack can connect to AppStream 2.0 only through the specified endpoints.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-accessendpoints
        '''
        result = self._values.get("access_endpoints")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnStack.AccessEndpointProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def application_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnStack.ApplicationSettingsProperty, _IResolvable_da3f097b]]:
        '''The persistent application settings for users of the stack.

        When these settings are enabled, changes that users make to applications and Windows settings are automatically saved after each session and applied to the next session.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-applicationsettings
        '''
        result = self._values.get("application_settings")
        return typing.cast(typing.Optional[typing.Union[CfnStack.ApplicationSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def attributes_to_delete(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The stack attributes to delete.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-attributestodelete
        '''
        result = self._values.get("attributes_to_delete")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def delete_storage_connectors(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''*This parameter has been deprecated.*.

        Deletes the storage connectors currently enabled for the stack.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-deletestorageconnectors
        '''
        result = self._values.get("delete_storage_connectors")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description to display.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def display_name(self) -> typing.Optional[builtins.str]:
        '''The stack name to display.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-displayname
        '''
        result = self._values.get("display_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def embed_host_domains(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The domains where AppStream 2.0 streaming sessions can be embedded in an iframe. You must approve the domains that you want to host embedded AppStream 2.0 streaming sessions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-embedhostdomains
        '''
        result = self._values.get("embed_host_domains")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def feedback_url(self) -> typing.Optional[builtins.str]:
        '''The URL that users are redirected to after they click the Send Feedback link.

        If no URL is specified, no Send Feedback link is displayed.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-feedbackurl
        '''
        result = self._values.get("feedback_url")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the stack.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def redirect_url(self) -> typing.Optional[builtins.str]:
        '''The URL that users are redirected to after their streaming session ends.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-redirecturl
        '''
        result = self._values.get("redirect_url")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def storage_connectors(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnStack.StorageConnectorProperty, _IResolvable_da3f097b]]]]:
        '''The storage connectors to enable.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-storageconnectors
        '''
        result = self._values.get("storage_connectors")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnStack.StorageConnectorProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An array of key-value pairs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def user_settings(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnStack.UserSettingProperty, _IResolvable_da3f097b]]]]:
        '''The actions that are enabled or disabled for users during their streaming sessions.

        By default, these actions are enabled.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stack.html#cfn-appstream-stack-usersettings
        '''
        result = self._values.get("user_settings")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnStack.UserSettingProperty, _IResolvable_da3f097b]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnStackProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnStackUserAssociation(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appstream.CfnStackUserAssociation",
):
    '''A CloudFormation ``AWS::AppStream::StackUserAssociation``.

    The ``AWS::AppStream::StackUserAssociation`` resource associates the specified users with the specified stacks for Amazon AppStream 2.0. Users in an AppStream 2.0 user pool cannot be assigned to stacks with fleets that are joined to an Active Directory domain.

    :cloudformationResource: AWS::AppStream::StackUserAssociation
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackuserassociation.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appstream as appstream
        
        cfn_stack_user_association = appstream.CfnStackUserAssociation(self, "MyCfnStackUserAssociation",
            authentication_type="authenticationType",
            stack_name="stackName",
            user_name="userName",
        
            # the properties below are optional
            send_email_notification=False
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        authentication_type: builtins.str,
        stack_name: builtins.str,
        user_name: builtins.str,
        send_email_notification: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::AppStream::StackUserAssociation``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param authentication_type: The authentication type for the user who is associated with the stack. You must specify USERPOOL.
        :param stack_name: The name of the stack that is associated with the user.
        :param user_name: The email address of the user who is associated with the stack. .. epigraph:: Users' email addresses are case-sensitive.
        :param send_email_notification: Specifies whether a welcome email is sent to a user after the user is created in the user pool.
        '''
        props = CfnStackUserAssociationProps(
            authentication_type=authentication_type,
            stack_name=stack_name,
            user_name=user_name,
            send_email_notification=send_email_notification,
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
    @jsii.member(jsii_name="authenticationType")
    def authentication_type(self) -> builtins.str:
        '''The authentication type for the user who is associated with the stack.

        You must specify USERPOOL.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackuserassociation.html#cfn-appstream-stackuserassociation-authenticationtype
        '''
        return typing.cast(builtins.str, jsii.get(self, "authenticationType"))

    @authentication_type.setter
    def authentication_type(self, value: builtins.str) -> None:
        jsii.set(self, "authenticationType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="stackName")
    def stack_name(self) -> builtins.str:
        '''The name of the stack that is associated with the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackuserassociation.html#cfn-appstream-stackuserassociation-stackname
        '''
        return typing.cast(builtins.str, jsii.get(self, "stackName"))

    @stack_name.setter
    def stack_name(self, value: builtins.str) -> None:
        jsii.set(self, "stackName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userName")
    def user_name(self) -> builtins.str:
        '''The email address of the user who is associated with the stack.

        .. epigraph::

           Users' email addresses are case-sensitive.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackuserassociation.html#cfn-appstream-stackuserassociation-username
        '''
        return typing.cast(builtins.str, jsii.get(self, "userName"))

    @user_name.setter
    def user_name(self, value: builtins.str) -> None:
        jsii.set(self, "userName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sendEmailNotification")
    def send_email_notification(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether a welcome email is sent to a user after the user is created in the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackuserassociation.html#cfn-appstream-stackuserassociation-sendemailnotification
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "sendEmailNotification"))

    @send_email_notification.setter
    def send_email_notification(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "sendEmailNotification", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appstream.CfnStackUserAssociationProps",
    jsii_struct_bases=[],
    name_mapping={
        "authentication_type": "authenticationType",
        "stack_name": "stackName",
        "user_name": "userName",
        "send_email_notification": "sendEmailNotification",
    },
)
class CfnStackUserAssociationProps:
    def __init__(
        self,
        *,
        authentication_type: builtins.str,
        stack_name: builtins.str,
        user_name: builtins.str,
        send_email_notification: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnStackUserAssociation``.

        :param authentication_type: The authentication type for the user who is associated with the stack. You must specify USERPOOL.
        :param stack_name: The name of the stack that is associated with the user.
        :param user_name: The email address of the user who is associated with the stack. .. epigraph:: Users' email addresses are case-sensitive.
        :param send_email_notification: Specifies whether a welcome email is sent to a user after the user is created in the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackuserassociation.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appstream as appstream
            
            cfn_stack_user_association_props = appstream.CfnStackUserAssociationProps(
                authentication_type="authenticationType",
                stack_name="stackName",
                user_name="userName",
            
                # the properties below are optional
                send_email_notification=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "authentication_type": authentication_type,
            "stack_name": stack_name,
            "user_name": user_name,
        }
        if send_email_notification is not None:
            self._values["send_email_notification"] = send_email_notification

    @builtins.property
    def authentication_type(self) -> builtins.str:
        '''The authentication type for the user who is associated with the stack.

        You must specify USERPOOL.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackuserassociation.html#cfn-appstream-stackuserassociation-authenticationtype
        '''
        result = self._values.get("authentication_type")
        assert result is not None, "Required property 'authentication_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def stack_name(self) -> builtins.str:
        '''The name of the stack that is associated with the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackuserassociation.html#cfn-appstream-stackuserassociation-stackname
        '''
        result = self._values.get("stack_name")
        assert result is not None, "Required property 'stack_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_name(self) -> builtins.str:
        '''The email address of the user who is associated with the stack.

        .. epigraph::

           Users' email addresses are case-sensitive.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackuserassociation.html#cfn-appstream-stackuserassociation-username
        '''
        result = self._values.get("user_name")
        assert result is not None, "Required property 'user_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def send_email_notification(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether a welcome email is sent to a user after the user is created in the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-stackuserassociation.html#cfn-appstream-stackuserassociation-sendemailnotification
        '''
        result = self._values.get("send_email_notification")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnStackUserAssociationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnUser(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appstream.CfnUser",
):
    '''A CloudFormation ``AWS::AppStream::User``.

    The ``AWS::AppStream::User`` resource creates a new user in the AppStream 2.0 user pool.

    :cloudformationResource: AWS::AppStream::User
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-user.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appstream as appstream
        
        cfn_user = appstream.CfnUser(self, "MyCfnUser",
            authentication_type="authenticationType",
            user_name="userName",
        
            # the properties below are optional
            first_name="firstName",
            last_name="lastName",
            message_action="messageAction"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        authentication_type: builtins.str,
        user_name: builtins.str,
        first_name: typing.Optional[builtins.str] = None,
        last_name: typing.Optional[builtins.str] = None,
        message_action: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::AppStream::User``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param authentication_type: The authentication type for the user. You must specify USERPOOL.
        :param user_name: The email address of the user. Users' email addresses are case-sensitive. During login, if they specify an email address that doesn't use the same capitalization as the email address specified when their user pool account was created, a "user does not exist" error message displays.
        :param first_name: The first name, or given name, of the user.
        :param last_name: The last name, or surname, of the user.
        :param message_action: The action to take for the welcome email that is sent to a user after the user is created in the user pool. If you specify SUPPRESS, no email is sent. If you specify RESEND, do not specify the first name or last name of the user. If the value is null, the email is sent. .. epigraph:: The temporary password in the welcome email is valid for only 7 days. If users don’t set their passwords within 7 days, you must send them a new welcome email.
        '''
        props = CfnUserProps(
            authentication_type=authentication_type,
            user_name=user_name,
            first_name=first_name,
            last_name=last_name,
            message_action=message_action,
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
    @jsii.member(jsii_name="authenticationType")
    def authentication_type(self) -> builtins.str:
        '''The authentication type for the user.

        You must specify USERPOOL.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-user.html#cfn-appstream-user-authenticationtype
        '''
        return typing.cast(builtins.str, jsii.get(self, "authenticationType"))

    @authentication_type.setter
    def authentication_type(self, value: builtins.str) -> None:
        jsii.set(self, "authenticationType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userName")
    def user_name(self) -> builtins.str:
        '''The email address of the user.

        Users' email addresses are case-sensitive. During login, if they specify an email address that doesn't use the same capitalization as the email address specified when their user pool account was created, a "user does not exist" error message displays.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-user.html#cfn-appstream-user-username
        '''
        return typing.cast(builtins.str, jsii.get(self, "userName"))

    @user_name.setter
    def user_name(self, value: builtins.str) -> None:
        jsii.set(self, "userName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="firstName")
    def first_name(self) -> typing.Optional[builtins.str]:
        '''The first name, or given name, of the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-user.html#cfn-appstream-user-firstname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "firstName"))

    @first_name.setter
    def first_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "firstName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lastName")
    def last_name(self) -> typing.Optional[builtins.str]:
        '''The last name, or surname, of the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-user.html#cfn-appstream-user-lastname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "lastName"))

    @last_name.setter
    def last_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "lastName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="messageAction")
    def message_action(self) -> typing.Optional[builtins.str]:
        '''The action to take for the welcome email that is sent to a user after the user is created in the user pool.

        If you specify SUPPRESS, no email is sent. If you specify RESEND, do not specify the first name or last name of the user. If the value is null, the email is sent.
        .. epigraph::

           The temporary password in the welcome email is valid for only 7 days. If users don’t set their passwords within 7 days, you must send them a new welcome email.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-user.html#cfn-appstream-user-messageaction
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "messageAction"))

    @message_action.setter
    def message_action(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "messageAction", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appstream.CfnUserProps",
    jsii_struct_bases=[],
    name_mapping={
        "authentication_type": "authenticationType",
        "user_name": "userName",
        "first_name": "firstName",
        "last_name": "lastName",
        "message_action": "messageAction",
    },
)
class CfnUserProps:
    def __init__(
        self,
        *,
        authentication_type: builtins.str,
        user_name: builtins.str,
        first_name: typing.Optional[builtins.str] = None,
        last_name: typing.Optional[builtins.str] = None,
        message_action: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnUser``.

        :param authentication_type: The authentication type for the user. You must specify USERPOOL.
        :param user_name: The email address of the user. Users' email addresses are case-sensitive. During login, if they specify an email address that doesn't use the same capitalization as the email address specified when their user pool account was created, a "user does not exist" error message displays.
        :param first_name: The first name, or given name, of the user.
        :param last_name: The last name, or surname, of the user.
        :param message_action: The action to take for the welcome email that is sent to a user after the user is created in the user pool. If you specify SUPPRESS, no email is sent. If you specify RESEND, do not specify the first name or last name of the user. If the value is null, the email is sent. .. epigraph:: The temporary password in the welcome email is valid for only 7 days. If users don’t set their passwords within 7 days, you must send them a new welcome email.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-user.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appstream as appstream
            
            cfn_user_props = appstream.CfnUserProps(
                authentication_type="authenticationType",
                user_name="userName",
            
                # the properties below are optional
                first_name="firstName",
                last_name="lastName",
                message_action="messageAction"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "authentication_type": authentication_type,
            "user_name": user_name,
        }
        if first_name is not None:
            self._values["first_name"] = first_name
        if last_name is not None:
            self._values["last_name"] = last_name
        if message_action is not None:
            self._values["message_action"] = message_action

    @builtins.property
    def authentication_type(self) -> builtins.str:
        '''The authentication type for the user.

        You must specify USERPOOL.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-user.html#cfn-appstream-user-authenticationtype
        '''
        result = self._values.get("authentication_type")
        assert result is not None, "Required property 'authentication_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_name(self) -> builtins.str:
        '''The email address of the user.

        Users' email addresses are case-sensitive. During login, if they specify an email address that doesn't use the same capitalization as the email address specified when their user pool account was created, a "user does not exist" error message displays.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-user.html#cfn-appstream-user-username
        '''
        result = self._values.get("user_name")
        assert result is not None, "Required property 'user_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def first_name(self) -> typing.Optional[builtins.str]:
        '''The first name, or given name, of the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-user.html#cfn-appstream-user-firstname
        '''
        result = self._values.get("first_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def last_name(self) -> typing.Optional[builtins.str]:
        '''The last name, or surname, of the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-user.html#cfn-appstream-user-lastname
        '''
        result = self._values.get("last_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def message_action(self) -> typing.Optional[builtins.str]:
        '''The action to take for the welcome email that is sent to a user after the user is created in the user pool.

        If you specify SUPPRESS, no email is sent. If you specify RESEND, do not specify the first name or last name of the user. If the value is null, the email is sent.
        .. epigraph::

           The temporary password in the welcome email is valid for only 7 days. If users don’t set their passwords within 7 days, you must send them a new welcome email.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appstream-user.html#cfn-appstream-user-messageaction
        '''
        result = self._values.get("message_action")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnAppBlock",
    "CfnAppBlockProps",
    "CfnApplication",
    "CfnApplicationEntitlementAssociation",
    "CfnApplicationEntitlementAssociationProps",
    "CfnApplicationFleetAssociation",
    "CfnApplicationFleetAssociationProps",
    "CfnApplicationProps",
    "CfnDirectoryConfig",
    "CfnDirectoryConfigProps",
    "CfnEntitlement",
    "CfnEntitlementProps",
    "CfnFleet",
    "CfnFleetProps",
    "CfnImageBuilder",
    "CfnImageBuilderProps",
    "CfnStack",
    "CfnStackFleetAssociation",
    "CfnStackFleetAssociationProps",
    "CfnStackProps",
    "CfnStackUserAssociation",
    "CfnStackUserAssociationProps",
    "CfnUser",
    "CfnUserProps",
]

publication.publish()
