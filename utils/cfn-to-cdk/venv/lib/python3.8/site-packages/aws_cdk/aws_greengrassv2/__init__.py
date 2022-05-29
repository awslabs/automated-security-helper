'''
# AWS::GreengrassV2 Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_greengrassv2 as greengrass
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-greengrassv2-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::GreengrassV2](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_GreengrassV2.html).

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
class CfnComponentVersion(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrassv2.CfnComponentVersion",
):
    '''A CloudFormation ``AWS::GreengrassV2::ComponentVersion``.

    Creates a component. Components are software that run on Greengrass core devices. After you develop and test a component on your core device, you can use this operation to upload your component to AWS IoT Greengrass . Then, you can deploy the component to other core devices.

    You can use this operation to do the following:

    - *Create components from recipes*

    Create a component from a recipe, which is a file that defines the component's metadata, parameters, dependencies, lifecycle, artifacts, and platform capability. For more information, see `AWS IoT Greengrass component recipe reference <https://docs.aws.amazon.com/greengrass/v2/developerguide/component-recipe-reference.html>`_ in the *AWS IoT Greengrass V2 Developer Guide* .

    To create a component from a recipe, specify ``inlineRecipe`` when you call this operation.

    - *Create components from Lambda functions*

    Create a component from an AWS Lambda function that runs on AWS IoT Greengrass . This creates a recipe and artifacts from the Lambda function's deployment package. You can use this operation to migrate Lambda functions from AWS IoT Greengrass V1 to AWS IoT Greengrass V2 .

    This function only accepts Lambda functions that use the following runtimes:

    - Python 2.7 – ``python2.7``
    - Python 3.7 – ``python3.7``
    - Python 3.8 – ``python3.8``
    - Java 8 – ``java8``
    - Node.js 10 – ``nodejs10.x``
    - Node.js 12 – ``nodejs12.x``

    To create a component from a Lambda function, specify ``lambdaFunction`` when you call this operation.

    :cloudformationResource: AWS::GreengrassV2::ComponentVersion
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrassv2-componentversion.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrassv2 as greengrassv2
        
        cfn_component_version = greengrassv2.CfnComponentVersion(self, "MyCfnComponentVersion",
            inline_recipe="inlineRecipe",
            lambda_function=greengrassv2.CfnComponentVersion.LambdaFunctionRecipeSourceProperty(
                component_dependencies={
                    "component_dependencies_key": greengrassv2.CfnComponentVersion.ComponentDependencyRequirementProperty(
                        dependency_type="dependencyType",
                        version_requirement="versionRequirement"
                    )
                },
                component_lambda_parameters=greengrassv2.CfnComponentVersion.LambdaExecutionParametersProperty(
                    environment_variables={
                        "environment_variables_key": "environmentVariables"
                    },
                    event_sources=[greengrassv2.CfnComponentVersion.LambdaEventSourceProperty(
                        topic="topic",
                        type="type"
                    )],
                    exec_args=["execArgs"],
                    input_payload_encoding_type="inputPayloadEncodingType",
                    linux_process_params=greengrassv2.CfnComponentVersion.LambdaLinuxProcessParamsProperty(
                        container_params=greengrassv2.CfnComponentVersion.LambdaContainerParamsProperty(
                            devices=[greengrassv2.CfnComponentVersion.LambdaDeviceMountProperty(
                                add_group_owner=False,
                                path="path",
                                permission="permission"
                            )],
                            memory_size_in_kb=123,
                            mount_ro_sysfs=False,
                            volumes=[greengrassv2.CfnComponentVersion.LambdaVolumeMountProperty(
                                add_group_owner=False,
                                destination_path="destinationPath",
                                permission="permission",
                                source_path="sourcePath"
                            )]
                        ),
                        isolation_mode="isolationMode"
                    ),
                    max_idle_time_in_seconds=123,
                    max_instances_count=123,
                    max_queue_size=123,
                    pinned=False,
                    status_timeout_in_seconds=123,
                    timeout_in_seconds=123
                ),
                component_name="componentName",
                component_platforms=[greengrassv2.CfnComponentVersion.ComponentPlatformProperty(
                    attributes={
                        "attributes_key": "attributes"
                    },
                    name="name"
                )],
                component_version="componentVersion",
                lambda_arn="lambdaArn"
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
        inline_recipe: typing.Optional[builtins.str] = None,
        lambda_function: typing.Optional[typing.Union["CfnComponentVersion.LambdaFunctionRecipeSourceProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::GreengrassV2::ComponentVersion``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param inline_recipe: The recipe to use to create the component. The recipe defines the component's metadata, parameters, dependencies, lifecycle, artifacts, and platform compatibility. You must specify either ``InlineRecipe`` or ``LambdaFunction`` .
        :param lambda_function: The parameters to create a component from a Lambda function. You must specify either ``InlineRecipe`` or ``LambdaFunction`` .
        :param tags: Application-specific metadata to attach to the component version. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tag your AWS IoT Greengrass Version 2 resources <https://docs.aws.amazon.com/greengrass/v2/developerguide/tag-resources.html>`_ in the *AWS IoT Greengrass V2 Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }
        '''
        props = CfnComponentVersionProps(
            inline_recipe=inline_recipe, lambda_function=lambda_function, tags=tags
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
        '''The ARN of the component version.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrComponentName")
    def attr_component_name(self) -> builtins.str:
        '''The name of the component.

        :cloudformationAttribute: ComponentName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrComponentName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrComponentVersion")
    def attr_component_version(self) -> builtins.str:
        '''The version of the component.

        :cloudformationAttribute: ComponentVersion
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrComponentVersion"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Application-specific metadata to attach to the component version.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tag your AWS IoT Greengrass Version 2 resources <https://docs.aws.amazon.com/greengrass/v2/developerguide/tag-resources.html>`_ in the *AWS IoT Greengrass V2 Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrassv2-componentversion.html#cfn-greengrassv2-componentversion-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="inlineRecipe")
    def inline_recipe(self) -> typing.Optional[builtins.str]:
        '''The recipe to use to create the component.

        The recipe defines the component's metadata, parameters, dependencies, lifecycle, artifacts, and platform compatibility.

        You must specify either ``InlineRecipe`` or ``LambdaFunction`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrassv2-componentversion.html#cfn-greengrassv2-componentversion-inlinerecipe
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "inlineRecipe"))

    @inline_recipe.setter
    def inline_recipe(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "inlineRecipe", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lambdaFunction")
    def lambda_function(
        self,
    ) -> typing.Optional[typing.Union["CfnComponentVersion.LambdaFunctionRecipeSourceProperty", _IResolvable_da3f097b]]:
        '''The parameters to create a component from a Lambda function.

        You must specify either ``InlineRecipe`` or ``LambdaFunction`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrassv2-componentversion.html#cfn-greengrassv2-componentversion-lambdafunction
        '''
        return typing.cast(typing.Optional[typing.Union["CfnComponentVersion.LambdaFunctionRecipeSourceProperty", _IResolvable_da3f097b]], jsii.get(self, "lambdaFunction"))

    @lambda_function.setter
    def lambda_function(
        self,
        value: typing.Optional[typing.Union["CfnComponentVersion.LambdaFunctionRecipeSourceProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "lambdaFunction", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrassv2.CfnComponentVersion.ComponentDependencyRequirementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "dependency_type": "dependencyType",
            "version_requirement": "versionRequirement",
        },
    )
    class ComponentDependencyRequirementProperty:
        def __init__(
            self,
            *,
            dependency_type: typing.Optional[builtins.str] = None,
            version_requirement: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Contains information about a component dependency for a Lambda function component.

            :param dependency_type: The type of this dependency. Choose from the following options:. - ``SOFT`` – The component doesn't restart if the dependency changes state. - ``HARD`` – The component restarts if the dependency changes state. Default: ``HARD``
            :param version_requirement: The component version requirement for the component dependency. AWS IoT Greengrass uses semantic version constraints. For more information, see `Semantic Versioning <https://docs.aws.amazon.com/https://semver.org/>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-componentdependencyrequirement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrassv2 as greengrassv2
                
                component_dependency_requirement_property = greengrassv2.CfnComponentVersion.ComponentDependencyRequirementProperty(
                    dependency_type="dependencyType",
                    version_requirement="versionRequirement"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if dependency_type is not None:
                self._values["dependency_type"] = dependency_type
            if version_requirement is not None:
                self._values["version_requirement"] = version_requirement

        @builtins.property
        def dependency_type(self) -> typing.Optional[builtins.str]:
            '''The type of this dependency. Choose from the following options:.

            - ``SOFT`` – The component doesn't restart if the dependency changes state.
            - ``HARD`` – The component restarts if the dependency changes state.

            Default: ``HARD``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-componentdependencyrequirement.html#cfn-greengrassv2-componentversion-componentdependencyrequirement-dependencytype
            '''
            result = self._values.get("dependency_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def version_requirement(self) -> typing.Optional[builtins.str]:
            '''The component version requirement for the component dependency.

            AWS IoT Greengrass uses semantic version constraints. For more information, see `Semantic Versioning <https://docs.aws.amazon.com/https://semver.org/>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-componentdependencyrequirement.html#cfn-greengrassv2-componentversion-componentdependencyrequirement-versionrequirement
            '''
            result = self._values.get("version_requirement")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComponentDependencyRequirementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrassv2.CfnComponentVersion.ComponentPlatformProperty",
        jsii_struct_bases=[],
        name_mapping={"attributes": "attributes", "name": "name"},
    )
    class ComponentPlatformProperty:
        def __init__(
            self,
            *,
            attributes: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
            name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Contains information about a platform that a component supports.

            :param attributes: A dictionary of attributes for the platform. The software defines the ``os`` and ``platform`` by default. You can specify additional platform attributes for a core device when you deploy the Greengrass nucleus component. For more information, see the `Greengrass nucleus component <https://docs.aws.amazon.com/greengrass/v2/developerguide/greengrass-nucleus-component.html>`_ in the *AWS IoT Greengrass V2 Developer Guide* .
            :param name: The friendly name of the platform. This name helps you identify the platform. If you omit this parameter, AWS IoT Greengrass creates a friendly name from the ``os`` and ``architecture`` of the platform.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-componentplatform.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrassv2 as greengrassv2
                
                component_platform_property = greengrassv2.CfnComponentVersion.ComponentPlatformProperty(
                    attributes={
                        "attributes_key": "attributes"
                    },
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if attributes is not None:
                self._values["attributes"] = attributes
            if name is not None:
                self._values["name"] = name

        @builtins.property
        def attributes(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''A dictionary of attributes for the platform.

            The  software defines the ``os`` and ``platform`` by default. You can specify additional platform attributes for a core device when you deploy the Greengrass nucleus component. For more information, see the `Greengrass nucleus component <https://docs.aws.amazon.com/greengrass/v2/developerguide/greengrass-nucleus-component.html>`_ in the *AWS IoT Greengrass V2 Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-componentplatform.html#cfn-greengrassv2-componentversion-componentplatform-attributes
            '''
            result = self._values.get("attributes")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The friendly name of the platform. This name helps you identify the platform.

            If you omit this parameter, AWS IoT Greengrass creates a friendly name from the ``os`` and ``architecture`` of the platform.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-componentplatform.html#cfn-greengrassv2-componentversion-componentplatform-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComponentPlatformProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrassv2.CfnComponentVersion.LambdaContainerParamsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "devices": "devices",
            "memory_size_in_kb": "memorySizeInKb",
            "mount_ro_sysfs": "mountRoSysfs",
            "volumes": "volumes",
        },
    )
    class LambdaContainerParamsProperty:
        def __init__(
            self,
            *,
            devices: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnComponentVersion.LambdaDeviceMountProperty", _IResolvable_da3f097b]]]] = None,
            memory_size_in_kb: typing.Optional[jsii.Number] = None,
            mount_ro_sysfs: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            volumes: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnComponentVersion.LambdaVolumeMountProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Contains information about a container in which AWS Lambda functions run on Greengrass core devices.

            :param devices: The list of system devices that the container can access.
            :param memory_size_in_kb: The memory size of the container, expressed in kilobytes. Default: ``16384`` (16 MB)
            :param mount_ro_sysfs: Whether or not the container can read information from the device's ``/sys`` folder. Default: ``false``
            :param volumes: The list of volumes that the container can access.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdacontainerparams.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrassv2 as greengrassv2
                
                lambda_container_params_property = greengrassv2.CfnComponentVersion.LambdaContainerParamsProperty(
                    devices=[greengrassv2.CfnComponentVersion.LambdaDeviceMountProperty(
                        add_group_owner=False,
                        path="path",
                        permission="permission"
                    )],
                    memory_size_in_kb=123,
                    mount_ro_sysfs=False,
                    volumes=[greengrassv2.CfnComponentVersion.LambdaVolumeMountProperty(
                        add_group_owner=False,
                        destination_path="destinationPath",
                        permission="permission",
                        source_path="sourcePath"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if devices is not None:
                self._values["devices"] = devices
            if memory_size_in_kb is not None:
                self._values["memory_size_in_kb"] = memory_size_in_kb
            if mount_ro_sysfs is not None:
                self._values["mount_ro_sysfs"] = mount_ro_sysfs
            if volumes is not None:
                self._values["volumes"] = volumes

        @builtins.property
        def devices(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponentVersion.LambdaDeviceMountProperty", _IResolvable_da3f097b]]]]:
            '''The list of system devices that the container can access.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdacontainerparams.html#cfn-greengrassv2-componentversion-lambdacontainerparams-devices
            '''
            result = self._values.get("devices")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponentVersion.LambdaDeviceMountProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def memory_size_in_kb(self) -> typing.Optional[jsii.Number]:
            '''The memory size of the container, expressed in kilobytes.

            Default: ``16384`` (16 MB)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdacontainerparams.html#cfn-greengrassv2-componentversion-lambdacontainerparams-memorysizeinkb
            '''
            result = self._values.get("memory_size_in_kb")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def mount_ro_sysfs(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Whether or not the container can read information from the device's ``/sys`` folder.

            Default: ``false``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdacontainerparams.html#cfn-greengrassv2-componentversion-lambdacontainerparams-mountrosysfs
            '''
            result = self._values.get("mount_ro_sysfs")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def volumes(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponentVersion.LambdaVolumeMountProperty", _IResolvable_da3f097b]]]]:
            '''The list of volumes that the container can access.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdacontainerparams.html#cfn-greengrassv2-componentversion-lambdacontainerparams-volumes
            '''
            result = self._values.get("volumes")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponentVersion.LambdaVolumeMountProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LambdaContainerParamsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrassv2.CfnComponentVersion.LambdaDeviceMountProperty",
        jsii_struct_bases=[],
        name_mapping={
            "add_group_owner": "addGroupOwner",
            "path": "path",
            "permission": "permission",
        },
    )
    class LambdaDeviceMountProperty:
        def __init__(
            self,
            *,
            add_group_owner: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            path: typing.Optional[builtins.str] = None,
            permission: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Contains information about a device that Linux processes in a container can access.

            :param add_group_owner: Whether or not to add the component's system user as an owner of the device. Default: ``false``
            :param path: The mount path for the device in the file system.
            :param permission: The permission to access the device: read/only ( ``ro`` ) or read/write ( ``rw`` ). Default: ``ro``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdadevicemount.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrassv2 as greengrassv2
                
                lambda_device_mount_property = greengrassv2.CfnComponentVersion.LambdaDeviceMountProperty(
                    add_group_owner=False,
                    path="path",
                    permission="permission"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if add_group_owner is not None:
                self._values["add_group_owner"] = add_group_owner
            if path is not None:
                self._values["path"] = path
            if permission is not None:
                self._values["permission"] = permission

        @builtins.property
        def add_group_owner(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Whether or not to add the component's system user as an owner of the device.

            Default: ``false``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdadevicemount.html#cfn-greengrassv2-componentversion-lambdadevicemount-addgroupowner
            '''
            result = self._values.get("add_group_owner")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def path(self) -> typing.Optional[builtins.str]:
            '''The mount path for the device in the file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdadevicemount.html#cfn-greengrassv2-componentversion-lambdadevicemount-path
            '''
            result = self._values.get("path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def permission(self) -> typing.Optional[builtins.str]:
            '''The permission to access the device: read/only ( ``ro`` ) or read/write ( ``rw`` ).

            Default: ``ro``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdadevicemount.html#cfn-greengrassv2-componentversion-lambdadevicemount-permission
            '''
            result = self._values.get("permission")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LambdaDeviceMountProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrassv2.CfnComponentVersion.LambdaEventSourceProperty",
        jsii_struct_bases=[],
        name_mapping={"topic": "topic", "type": "type"},
    )
    class LambdaEventSourceProperty:
        def __init__(
            self,
            *,
            topic: typing.Optional[builtins.str] = None,
            type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Contains information about an event source for an AWS Lambda function.

            The event source defines the topics on which this Lambda function subscribes to receive messages that run the function.

            :param topic: The topic to which to subscribe to receive event messages.
            :param type: The type of event source. Choose from the following options:. - ``PUB_SUB`` – Subscribe to local publish/subscribe messages. This event source type doesn't support MQTT wildcards ( ``+`` and ``#`` ) in the event source topic. - ``IOT_CORE`` – Subscribe to AWS IoT Core MQTT messages. This event source type supports MQTT wildcards ( ``+`` and ``#`` ) in the event source topic.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaeventsource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrassv2 as greengrassv2
                
                lambda_event_source_property = greengrassv2.CfnComponentVersion.LambdaEventSourceProperty(
                    topic="topic",
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if topic is not None:
                self._values["topic"] = topic
            if type is not None:
                self._values["type"] = type

        @builtins.property
        def topic(self) -> typing.Optional[builtins.str]:
            '''The topic to which to subscribe to receive event messages.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaeventsource.html#cfn-greengrassv2-componentversion-lambdaeventsource-topic
            '''
            result = self._values.get("topic")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''The type of event source. Choose from the following options:.

            - ``PUB_SUB`` – Subscribe to local publish/subscribe messages. This event source type doesn't support MQTT wildcards ( ``+`` and ``#`` ) in the event source topic.
            - ``IOT_CORE`` – Subscribe to AWS IoT Core MQTT messages. This event source type supports MQTT wildcards ( ``+`` and ``#`` ) in the event source topic.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaeventsource.html#cfn-greengrassv2-componentversion-lambdaeventsource-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LambdaEventSourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrassv2.CfnComponentVersion.LambdaExecutionParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "environment_variables": "environmentVariables",
            "event_sources": "eventSources",
            "exec_args": "execArgs",
            "input_payload_encoding_type": "inputPayloadEncodingType",
            "linux_process_params": "linuxProcessParams",
            "max_idle_time_in_seconds": "maxIdleTimeInSeconds",
            "max_instances_count": "maxInstancesCount",
            "max_queue_size": "maxQueueSize",
            "pinned": "pinned",
            "status_timeout_in_seconds": "statusTimeoutInSeconds",
            "timeout_in_seconds": "timeoutInSeconds",
        },
    )
    class LambdaExecutionParametersProperty:
        def __init__(
            self,
            *,
            environment_variables: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
            event_sources: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnComponentVersion.LambdaEventSourceProperty", _IResolvable_da3f097b]]]] = None,
            exec_args: typing.Optional[typing.Sequence[builtins.str]] = None,
            input_payload_encoding_type: typing.Optional[builtins.str] = None,
            linux_process_params: typing.Optional[typing.Union["CfnComponentVersion.LambdaLinuxProcessParamsProperty", _IResolvable_da3f097b]] = None,
            max_idle_time_in_seconds: typing.Optional[jsii.Number] = None,
            max_instances_count: typing.Optional[jsii.Number] = None,
            max_queue_size: typing.Optional[jsii.Number] = None,
            pinned: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            status_timeout_in_seconds: typing.Optional[jsii.Number] = None,
            timeout_in_seconds: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Contains parameters for a Lambda function that runs on AWS IoT Greengrass .

            :param environment_variables: The map of environment variables that are available to the Lambda function when it runs.
            :param event_sources: The list of event sources to which to subscribe to receive work messages. The Lambda function runs when it receives a message from an event source. You can subscribe this function to local publish/subscribe messages and AWS IoT Core MQTT messages.
            :param exec_args: The list of arguments to pass to the Lambda function when it runs.
            :param input_payload_encoding_type: The encoding type that the Lambda function supports. Default: ``json``
            :param linux_process_params: The parameters for the Linux process that contains the Lambda function.
            :param max_idle_time_in_seconds: The maximum amount of time in seconds that a non-pinned Lambda function can idle before the software stops its process.
            :param max_instances_count: The maximum number of instances that a non-pinned Lambda function can run at the same time.
            :param max_queue_size: The maximum size of the message queue for the Lambda function component. The Greengrass core device stores messages in a FIFO (first-in-first-out) queue until it can run the Lambda function to consume each message.
            :param pinned: Whether or not the Lambda function is pinned, or long-lived. - A pinned Lambda function starts when the starts and keeps running in its own container. - A non-pinned Lambda function starts only when it receives a work item and exists after it idles for ``maxIdleTimeInSeconds`` . If the function has multiple work items, the software creates multiple instances of the function. Default: ``true``
            :param status_timeout_in_seconds: The interval in seconds at which a pinned (also known as long-lived) Lambda function component sends status updates to the Lambda manager component.
            :param timeout_in_seconds: The maximum amount of time in seconds that the Lambda function can process a work item.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaexecutionparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrassv2 as greengrassv2
                
                lambda_execution_parameters_property = greengrassv2.CfnComponentVersion.LambdaExecutionParametersProperty(
                    environment_variables={
                        "environment_variables_key": "environmentVariables"
                    },
                    event_sources=[greengrassv2.CfnComponentVersion.LambdaEventSourceProperty(
                        topic="topic",
                        type="type"
                    )],
                    exec_args=["execArgs"],
                    input_payload_encoding_type="inputPayloadEncodingType",
                    linux_process_params=greengrassv2.CfnComponentVersion.LambdaLinuxProcessParamsProperty(
                        container_params=greengrassv2.CfnComponentVersion.LambdaContainerParamsProperty(
                            devices=[greengrassv2.CfnComponentVersion.LambdaDeviceMountProperty(
                                add_group_owner=False,
                                path="path",
                                permission="permission"
                            )],
                            memory_size_in_kb=123,
                            mount_ro_sysfs=False,
                            volumes=[greengrassv2.CfnComponentVersion.LambdaVolumeMountProperty(
                                add_group_owner=False,
                                destination_path="destinationPath",
                                permission="permission",
                                source_path="sourcePath"
                            )]
                        ),
                        isolation_mode="isolationMode"
                    ),
                    max_idle_time_in_seconds=123,
                    max_instances_count=123,
                    max_queue_size=123,
                    pinned=False,
                    status_timeout_in_seconds=123,
                    timeout_in_seconds=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if environment_variables is not None:
                self._values["environment_variables"] = environment_variables
            if event_sources is not None:
                self._values["event_sources"] = event_sources
            if exec_args is not None:
                self._values["exec_args"] = exec_args
            if input_payload_encoding_type is not None:
                self._values["input_payload_encoding_type"] = input_payload_encoding_type
            if linux_process_params is not None:
                self._values["linux_process_params"] = linux_process_params
            if max_idle_time_in_seconds is not None:
                self._values["max_idle_time_in_seconds"] = max_idle_time_in_seconds
            if max_instances_count is not None:
                self._values["max_instances_count"] = max_instances_count
            if max_queue_size is not None:
                self._values["max_queue_size"] = max_queue_size
            if pinned is not None:
                self._values["pinned"] = pinned
            if status_timeout_in_seconds is not None:
                self._values["status_timeout_in_seconds"] = status_timeout_in_seconds
            if timeout_in_seconds is not None:
                self._values["timeout_in_seconds"] = timeout_in_seconds

        @builtins.property
        def environment_variables(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''The map of environment variables that are available to the Lambda function when it runs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaexecutionparameters.html#cfn-greengrassv2-componentversion-lambdaexecutionparameters-environmentvariables
            '''
            result = self._values.get("environment_variables")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        @builtins.property
        def event_sources(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponentVersion.LambdaEventSourceProperty", _IResolvable_da3f097b]]]]:
            '''The list of event sources to which to subscribe to receive work messages.

            The Lambda function runs when it receives a message from an event source. You can subscribe this function to local publish/subscribe messages and AWS IoT Core MQTT messages.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaexecutionparameters.html#cfn-greengrassv2-componentversion-lambdaexecutionparameters-eventsources
            '''
            result = self._values.get("event_sources")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponentVersion.LambdaEventSourceProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def exec_args(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The list of arguments to pass to the Lambda function when it runs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaexecutionparameters.html#cfn-greengrassv2-componentversion-lambdaexecutionparameters-execargs
            '''
            result = self._values.get("exec_args")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def input_payload_encoding_type(self) -> typing.Optional[builtins.str]:
            '''The encoding type that the Lambda function supports.

            Default: ``json``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaexecutionparameters.html#cfn-greengrassv2-componentversion-lambdaexecutionparameters-inputpayloadencodingtype
            '''
            result = self._values.get("input_payload_encoding_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def linux_process_params(
            self,
        ) -> typing.Optional[typing.Union["CfnComponentVersion.LambdaLinuxProcessParamsProperty", _IResolvable_da3f097b]]:
            '''The parameters for the Linux process that contains the Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaexecutionparameters.html#cfn-greengrassv2-componentversion-lambdaexecutionparameters-linuxprocessparams
            '''
            result = self._values.get("linux_process_params")
            return typing.cast(typing.Optional[typing.Union["CfnComponentVersion.LambdaLinuxProcessParamsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def max_idle_time_in_seconds(self) -> typing.Optional[jsii.Number]:
            '''The maximum amount of time in seconds that a non-pinned Lambda function can idle before the  software stops its process.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaexecutionparameters.html#cfn-greengrassv2-componentversion-lambdaexecutionparameters-maxidletimeinseconds
            '''
            result = self._values.get("max_idle_time_in_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def max_instances_count(self) -> typing.Optional[jsii.Number]:
            '''The maximum number of instances that a non-pinned Lambda function can run at the same time.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaexecutionparameters.html#cfn-greengrassv2-componentversion-lambdaexecutionparameters-maxinstancescount
            '''
            result = self._values.get("max_instances_count")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def max_queue_size(self) -> typing.Optional[jsii.Number]:
            '''The maximum size of the message queue for the Lambda function component.

            The Greengrass core device stores messages in a FIFO (first-in-first-out) queue until it can run the Lambda function to consume each message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaexecutionparameters.html#cfn-greengrassv2-componentversion-lambdaexecutionparameters-maxqueuesize
            '''
            result = self._values.get("max_queue_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def pinned(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Whether or not the Lambda function is pinned, or long-lived.

            - A pinned Lambda function starts when the  starts and keeps running in its own container.
            - A non-pinned Lambda function starts only when it receives a work item and exists after it idles for ``maxIdleTimeInSeconds`` . If the function has multiple work items, the  software creates multiple instances of the function.

            Default: ``true``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaexecutionparameters.html#cfn-greengrassv2-componentversion-lambdaexecutionparameters-pinned
            '''
            result = self._values.get("pinned")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def status_timeout_in_seconds(self) -> typing.Optional[jsii.Number]:
            '''The interval in seconds at which a pinned (also known as long-lived) Lambda function component sends status updates to the Lambda manager component.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaexecutionparameters.html#cfn-greengrassv2-componentversion-lambdaexecutionparameters-statustimeoutinseconds
            '''
            result = self._values.get("status_timeout_in_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def timeout_in_seconds(self) -> typing.Optional[jsii.Number]:
            '''The maximum amount of time in seconds that the Lambda function can process a work item.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdaexecutionparameters.html#cfn-greengrassv2-componentversion-lambdaexecutionparameters-timeoutinseconds
            '''
            result = self._values.get("timeout_in_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LambdaExecutionParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrassv2.CfnComponentVersion.LambdaFunctionRecipeSourceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "component_dependencies": "componentDependencies",
            "component_lambda_parameters": "componentLambdaParameters",
            "component_name": "componentName",
            "component_platforms": "componentPlatforms",
            "component_version": "componentVersion",
            "lambda_arn": "lambdaArn",
        },
    )
    class LambdaFunctionRecipeSourceProperty:
        def __init__(
            self,
            *,
            component_dependencies: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponentVersion.ComponentDependencyRequirementProperty", _IResolvable_da3f097b]]]] = None,
            component_lambda_parameters: typing.Optional[typing.Union["CfnComponentVersion.LambdaExecutionParametersProperty", _IResolvable_da3f097b]] = None,
            component_name: typing.Optional[builtins.str] = None,
            component_platforms: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnComponentVersion.ComponentPlatformProperty", _IResolvable_da3f097b]]]] = None,
            component_version: typing.Optional[builtins.str] = None,
            lambda_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Contains information about an AWS Lambda function to import to create a component.

            :param component_dependencies: The component versions on which this Lambda function component depends.
            :param component_lambda_parameters: The system and runtime parameters for the Lambda function as it runs on the Greengrass core device.
            :param component_name: The name of the component. Defaults to the name of the Lambda function.
            :param component_platforms: The platforms that the component version supports.
            :param component_version: The version of the component. Defaults to the version of the Lambda function as a semantic version. For example, if your function version is ``3`` , the component version becomes ``3.0.0`` .
            :param lambda_arn: The ARN of the Lambda function. The ARN must include the version of the function to import. You can't use version aliases like ``$LATEST`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdafunctionrecipesource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrassv2 as greengrassv2
                
                lambda_function_recipe_source_property = greengrassv2.CfnComponentVersion.LambdaFunctionRecipeSourceProperty(
                    component_dependencies={
                        "component_dependencies_key": greengrassv2.CfnComponentVersion.ComponentDependencyRequirementProperty(
                            dependency_type="dependencyType",
                            version_requirement="versionRequirement"
                        )
                    },
                    component_lambda_parameters=greengrassv2.CfnComponentVersion.LambdaExecutionParametersProperty(
                        environment_variables={
                            "environment_variables_key": "environmentVariables"
                        },
                        event_sources=[greengrassv2.CfnComponentVersion.LambdaEventSourceProperty(
                            topic="topic",
                            type="type"
                        )],
                        exec_args=["execArgs"],
                        input_payload_encoding_type="inputPayloadEncodingType",
                        linux_process_params=greengrassv2.CfnComponentVersion.LambdaLinuxProcessParamsProperty(
                            container_params=greengrassv2.CfnComponentVersion.LambdaContainerParamsProperty(
                                devices=[greengrassv2.CfnComponentVersion.LambdaDeviceMountProperty(
                                    add_group_owner=False,
                                    path="path",
                                    permission="permission"
                                )],
                                memory_size_in_kb=123,
                                mount_ro_sysfs=False,
                                volumes=[greengrassv2.CfnComponentVersion.LambdaVolumeMountProperty(
                                    add_group_owner=False,
                                    destination_path="destinationPath",
                                    permission="permission",
                                    source_path="sourcePath"
                                )]
                            ),
                            isolation_mode="isolationMode"
                        ),
                        max_idle_time_in_seconds=123,
                        max_instances_count=123,
                        max_queue_size=123,
                        pinned=False,
                        status_timeout_in_seconds=123,
                        timeout_in_seconds=123
                    ),
                    component_name="componentName",
                    component_platforms=[greengrassv2.CfnComponentVersion.ComponentPlatformProperty(
                        attributes={
                            "attributes_key": "attributes"
                        },
                        name="name"
                    )],
                    component_version="componentVersion",
                    lambda_arn="lambdaArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if component_dependencies is not None:
                self._values["component_dependencies"] = component_dependencies
            if component_lambda_parameters is not None:
                self._values["component_lambda_parameters"] = component_lambda_parameters
            if component_name is not None:
                self._values["component_name"] = component_name
            if component_platforms is not None:
                self._values["component_platforms"] = component_platforms
            if component_version is not None:
                self._values["component_version"] = component_version
            if lambda_arn is not None:
                self._values["lambda_arn"] = lambda_arn

        @builtins.property
        def component_dependencies(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponentVersion.ComponentDependencyRequirementProperty", _IResolvable_da3f097b]]]]:
            '''The component versions on which this Lambda function component depends.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdafunctionrecipesource.html#cfn-greengrassv2-componentversion-lambdafunctionrecipesource-componentdependencies
            '''
            result = self._values.get("component_dependencies")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponentVersion.ComponentDependencyRequirementProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def component_lambda_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnComponentVersion.LambdaExecutionParametersProperty", _IResolvable_da3f097b]]:
            '''The system and runtime parameters for the Lambda function as it runs on the Greengrass core device.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdafunctionrecipesource.html#cfn-greengrassv2-componentversion-lambdafunctionrecipesource-componentlambdaparameters
            '''
            result = self._values.get("component_lambda_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnComponentVersion.LambdaExecutionParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def component_name(self) -> typing.Optional[builtins.str]:
            '''The name of the component.

            Defaults to the name of the Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdafunctionrecipesource.html#cfn-greengrassv2-componentversion-lambdafunctionrecipesource-componentname
            '''
            result = self._values.get("component_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def component_platforms(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponentVersion.ComponentPlatformProperty", _IResolvable_da3f097b]]]]:
            '''The platforms that the component version supports.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdafunctionrecipesource.html#cfn-greengrassv2-componentversion-lambdafunctionrecipesource-componentplatforms
            '''
            result = self._values.get("component_platforms")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponentVersion.ComponentPlatformProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def component_version(self) -> typing.Optional[builtins.str]:
            '''The version of the component.

            Defaults to the version of the Lambda function as a semantic version. For example, if your function version is ``3`` , the component version becomes ``3.0.0`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdafunctionrecipesource.html#cfn-greengrassv2-componentversion-lambdafunctionrecipesource-componentversion
            '''
            result = self._values.get("component_version")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def lambda_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the Lambda function.

            The ARN must include the version of the function to import. You can't use version aliases like ``$LATEST`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdafunctionrecipesource.html#cfn-greengrassv2-componentversion-lambdafunctionrecipesource-lambdaarn
            '''
            result = self._values.get("lambda_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LambdaFunctionRecipeSourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrassv2.CfnComponentVersion.LambdaLinuxProcessParamsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "container_params": "containerParams",
            "isolation_mode": "isolationMode",
        },
    )
    class LambdaLinuxProcessParamsProperty:
        def __init__(
            self,
            *,
            container_params: typing.Optional[typing.Union["CfnComponentVersion.LambdaContainerParamsProperty", _IResolvable_da3f097b]] = None,
            isolation_mode: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Contains parameters for a Linux process that contains an AWS Lambda function.

            :param container_params: The parameters for the container in which the Lambda function runs.
            :param isolation_mode: The isolation mode for the process that contains the Lambda function. The process can run in an isolated runtime environment inside the AWS IoT Greengrass container, or as a regular process outside any container. Default: ``GreengrassContainer``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdalinuxprocessparams.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrassv2 as greengrassv2
                
                lambda_linux_process_params_property = greengrassv2.CfnComponentVersion.LambdaLinuxProcessParamsProperty(
                    container_params=greengrassv2.CfnComponentVersion.LambdaContainerParamsProperty(
                        devices=[greengrassv2.CfnComponentVersion.LambdaDeviceMountProperty(
                            add_group_owner=False,
                            path="path",
                            permission="permission"
                        )],
                        memory_size_in_kb=123,
                        mount_ro_sysfs=False,
                        volumes=[greengrassv2.CfnComponentVersion.LambdaVolumeMountProperty(
                            add_group_owner=False,
                            destination_path="destinationPath",
                            permission="permission",
                            source_path="sourcePath"
                        )]
                    ),
                    isolation_mode="isolationMode"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if container_params is not None:
                self._values["container_params"] = container_params
            if isolation_mode is not None:
                self._values["isolation_mode"] = isolation_mode

        @builtins.property
        def container_params(
            self,
        ) -> typing.Optional[typing.Union["CfnComponentVersion.LambdaContainerParamsProperty", _IResolvable_da3f097b]]:
            '''The parameters for the container in which the Lambda function runs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdalinuxprocessparams.html#cfn-greengrassv2-componentversion-lambdalinuxprocessparams-containerparams
            '''
            result = self._values.get("container_params")
            return typing.cast(typing.Optional[typing.Union["CfnComponentVersion.LambdaContainerParamsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def isolation_mode(self) -> typing.Optional[builtins.str]:
            '''The isolation mode for the process that contains the Lambda function.

            The process can run in an isolated runtime environment inside the AWS IoT Greengrass container, or as a regular process outside any container.

            Default: ``GreengrassContainer``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdalinuxprocessparams.html#cfn-greengrassv2-componentversion-lambdalinuxprocessparams-isolationmode
            '''
            result = self._values.get("isolation_mode")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LambdaLinuxProcessParamsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrassv2.CfnComponentVersion.LambdaVolumeMountProperty",
        jsii_struct_bases=[],
        name_mapping={
            "add_group_owner": "addGroupOwner",
            "destination_path": "destinationPath",
            "permission": "permission",
            "source_path": "sourcePath",
        },
    )
    class LambdaVolumeMountProperty:
        def __init__(
            self,
            *,
            add_group_owner: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            destination_path: typing.Optional[builtins.str] = None,
            permission: typing.Optional[builtins.str] = None,
            source_path: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Contains information about a volume that Linux processes in a container can access.

            When you define a volume, the  software mounts the source files to the destination inside the container.

            :param add_group_owner: Whether or not to add the AWS IoT Greengrass user group as an owner of the volume. Default: ``false``
            :param destination_path: The path to the logical volume in the file system.
            :param permission: The permission to access the volume: read/only ( ``ro`` ) or read/write ( ``rw`` ). Default: ``ro``
            :param source_path: The path to the physical volume in the file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdavolumemount.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrassv2 as greengrassv2
                
                lambda_volume_mount_property = greengrassv2.CfnComponentVersion.LambdaVolumeMountProperty(
                    add_group_owner=False,
                    destination_path="destinationPath",
                    permission="permission",
                    source_path="sourcePath"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if add_group_owner is not None:
                self._values["add_group_owner"] = add_group_owner
            if destination_path is not None:
                self._values["destination_path"] = destination_path
            if permission is not None:
                self._values["permission"] = permission
            if source_path is not None:
                self._values["source_path"] = source_path

        @builtins.property
        def add_group_owner(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Whether or not to add the AWS IoT Greengrass user group as an owner of the volume.

            Default: ``false``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdavolumemount.html#cfn-greengrassv2-componentversion-lambdavolumemount-addgroupowner
            '''
            result = self._values.get("add_group_owner")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def destination_path(self) -> typing.Optional[builtins.str]:
            '''The path to the logical volume in the file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdavolumemount.html#cfn-greengrassv2-componentversion-lambdavolumemount-destinationpath
            '''
            result = self._values.get("destination_path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def permission(self) -> typing.Optional[builtins.str]:
            '''The permission to access the volume: read/only ( ``ro`` ) or read/write ( ``rw`` ).

            Default: ``ro``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdavolumemount.html#cfn-greengrassv2-componentversion-lambdavolumemount-permission
            '''
            result = self._values.get("permission")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def source_path(self) -> typing.Optional[builtins.str]:
            '''The path to the physical volume in the file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrassv2-componentversion-lambdavolumemount.html#cfn-greengrassv2-componentversion-lambdavolumemount-sourcepath
            '''
            result = self._values.get("source_path")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LambdaVolumeMountProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrassv2.CfnComponentVersionProps",
    jsii_struct_bases=[],
    name_mapping={
        "inline_recipe": "inlineRecipe",
        "lambda_function": "lambdaFunction",
        "tags": "tags",
    },
)
class CfnComponentVersionProps:
    def __init__(
        self,
        *,
        inline_recipe: typing.Optional[builtins.str] = None,
        lambda_function: typing.Optional[typing.Union[CfnComponentVersion.LambdaFunctionRecipeSourceProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnComponentVersion``.

        :param inline_recipe: The recipe to use to create the component. The recipe defines the component's metadata, parameters, dependencies, lifecycle, artifacts, and platform compatibility. You must specify either ``InlineRecipe`` or ``LambdaFunction`` .
        :param lambda_function: The parameters to create a component from a Lambda function. You must specify either ``InlineRecipe`` or ``LambdaFunction`` .
        :param tags: Application-specific metadata to attach to the component version. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tag your AWS IoT Greengrass Version 2 resources <https://docs.aws.amazon.com/greengrass/v2/developerguide/tag-resources.html>`_ in the *AWS IoT Greengrass V2 Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrassv2-componentversion.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrassv2 as greengrassv2
            
            cfn_component_version_props = greengrassv2.CfnComponentVersionProps(
                inline_recipe="inlineRecipe",
                lambda_function=greengrassv2.CfnComponentVersion.LambdaFunctionRecipeSourceProperty(
                    component_dependencies={
                        "component_dependencies_key": greengrassv2.CfnComponentVersion.ComponentDependencyRequirementProperty(
                            dependency_type="dependencyType",
                            version_requirement="versionRequirement"
                        )
                    },
                    component_lambda_parameters=greengrassv2.CfnComponentVersion.LambdaExecutionParametersProperty(
                        environment_variables={
                            "environment_variables_key": "environmentVariables"
                        },
                        event_sources=[greengrassv2.CfnComponentVersion.LambdaEventSourceProperty(
                            topic="topic",
                            type="type"
                        )],
                        exec_args=["execArgs"],
                        input_payload_encoding_type="inputPayloadEncodingType",
                        linux_process_params=greengrassv2.CfnComponentVersion.LambdaLinuxProcessParamsProperty(
                            container_params=greengrassv2.CfnComponentVersion.LambdaContainerParamsProperty(
                                devices=[greengrassv2.CfnComponentVersion.LambdaDeviceMountProperty(
                                    add_group_owner=False,
                                    path="path",
                                    permission="permission"
                                )],
                                memory_size_in_kb=123,
                                mount_ro_sysfs=False,
                                volumes=[greengrassv2.CfnComponentVersion.LambdaVolumeMountProperty(
                                    add_group_owner=False,
                                    destination_path="destinationPath",
                                    permission="permission",
                                    source_path="sourcePath"
                                )]
                            ),
                            isolation_mode="isolationMode"
                        ),
                        max_idle_time_in_seconds=123,
                        max_instances_count=123,
                        max_queue_size=123,
                        pinned=False,
                        status_timeout_in_seconds=123,
                        timeout_in_seconds=123
                    ),
                    component_name="componentName",
                    component_platforms=[greengrassv2.CfnComponentVersion.ComponentPlatformProperty(
                        attributes={
                            "attributes_key": "attributes"
                        },
                        name="name"
                    )],
                    component_version="componentVersion",
                    lambda_arn="lambdaArn"
                ),
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if inline_recipe is not None:
            self._values["inline_recipe"] = inline_recipe
        if lambda_function is not None:
            self._values["lambda_function"] = lambda_function
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def inline_recipe(self) -> typing.Optional[builtins.str]:
        '''The recipe to use to create the component.

        The recipe defines the component's metadata, parameters, dependencies, lifecycle, artifacts, and platform compatibility.

        You must specify either ``InlineRecipe`` or ``LambdaFunction`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrassv2-componentversion.html#cfn-greengrassv2-componentversion-inlinerecipe
        '''
        result = self._values.get("inline_recipe")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def lambda_function(
        self,
    ) -> typing.Optional[typing.Union[CfnComponentVersion.LambdaFunctionRecipeSourceProperty, _IResolvable_da3f097b]]:
        '''The parameters to create a component from a Lambda function.

        You must specify either ``InlineRecipe`` or ``LambdaFunction`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrassv2-componentversion.html#cfn-greengrassv2-componentversion-lambdafunction
        '''
        result = self._values.get("lambda_function")
        return typing.cast(typing.Optional[typing.Union[CfnComponentVersion.LambdaFunctionRecipeSourceProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Application-specific metadata to attach to the component version.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tag your AWS IoT Greengrass Version 2 resources <https://docs.aws.amazon.com/greengrass/v2/developerguide/tag-resources.html>`_ in the *AWS IoT Greengrass V2 Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrassv2-componentversion.html#cfn-greengrassv2-componentversion-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnComponentVersionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnComponentVersion",
    "CfnComponentVersionProps",
]

publication.publish()
