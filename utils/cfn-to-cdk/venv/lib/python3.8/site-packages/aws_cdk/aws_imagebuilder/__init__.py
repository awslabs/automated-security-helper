'''
# AWS::ImageBuilder Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_imagebuilder as imagebuilder
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-imagebuilder-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::ImageBuilder](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_ImageBuilder.html).

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
class CfnComponent(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_imagebuilder.CfnComponent",
):
    '''A CloudFormation ``AWS::ImageBuilder::Component``.

    Components are orchestration documents that define a sequence of steps for downloading, installing, and configuring software packages or for defining tests to run on software packages. They also define validation and security hardening steps. A component is defined using a YAML document format. For more information, see `Using Documents in Image Builder <https://docs.aws.amazon.com/imagebuilder/latest/userguide/image-builder-application-documents.html>`_ .

    :cloudformationResource: AWS::ImageBuilder::Component
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_imagebuilder as imagebuilder
        
        cfn_component = imagebuilder.CfnComponent(self, "MyCfnComponent",
            name="name",
            platform="platform",
            version="version",
        
            # the properties below are optional
            change_description="changeDescription",
            data="data",
            description="description",
            kms_key_id="kmsKeyId",
            supported_os_versions=["supportedOsVersions"],
            tags={
                "tags_key": "tags"
            },
            uri="uri"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        platform: builtins.str,
        version: builtins.str,
        change_description: typing.Optional[builtins.str] = None,
        data: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        supported_os_versions: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        uri: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::ImageBuilder::Component``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the component.
        :param platform: The platform of the component. For example, ``Windows`` .
        :param version: The component version. For example, ``1.0.0`` .
        :param change_description: A change description of the component. For example ``initial version`` .
        :param data: The data of the component. For example, ``name: HelloWorldTestingDocument\\ndescription: This is hello world testing document.\\nschemaVersion: 1.0\\n\\nphases:\\n - name: test\\n steps:\\n - name: HelloWorldStep\\n action: ExecuteBash\\n inputs:\\n commands:\\n - echo \\"Hello World! Test.\\"\\n`` . See Examples below for the schema for creating a component using Data.
        :param description: The description of the component.
        :param kms_key_id: The KMS key identifier used to encrypt the component.
        :param supported_os_versions: The operating system (OS) version supported by the component. If the OS information is available, a prefix match is performed against the base image OS version during image recipe creation.
        :param tags: The tags associated with the component.
        :param uri: The ``uri`` of a YAML component document file. This must be an S3 URL ( ``s3://bucket/key`` ), and the requester must have permission to access the S3 bucket it points to. If you use Amazon S3, you can specify component content up to your service quota. Alternatively, you can specify the YAML document inline, using the component ``data`` property. You cannot specify both properties.
        '''
        props = CfnComponentProps(
            name=name,
            platform=platform,
            version=version,
            change_description=change_description,
            data=data,
            description=description,
            kms_key_id=kms_key_id,
            supported_os_versions=supported_os_versions,
            tags=tags,
            uri=uri,
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
        '''Returns the Amazon Resource Name (ARN) of the component.

        The following pattern is applied: ``^arn:aws[^:]*:imagebuilder:[^:]+:(?:\\d{12}|aws):(?:image-recipe|infrastructure-configuration|distribution-configuration|component|image|image-pipeline)/[a-z0-9-_]+(?:/(?:(?:x|\\d+)\\.(?:x|\\d+)\\.(?:x|\\d+))(?:/\\d+)?)?$`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrEncrypted")
    def attr_encrypted(self) -> _IResolvable_da3f097b:
        '''Returns the encryption status of the component.

        For example ``true`` or ``false`` .

        :cloudformationAttribute: Encrypted
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrEncrypted"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''Returns the name of the component.

        :cloudformationAttribute: Name
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrType")
    def attr_type(self) -> builtins.str:
        '''Returns the component type.

        For example, ``BUILD`` or ``TEST`` .

        :cloudformationAttribute: Type
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrType"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags associated with the component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="platform")
    def platform(self) -> builtins.str:
        '''The platform of the component.

        For example, ``Windows`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-platform
        '''
        return typing.cast(builtins.str, jsii.get(self, "platform"))

    @platform.setter
    def platform(self, value: builtins.str) -> None:
        jsii.set(self, "platform", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="version")
    def version(self) -> builtins.str:
        '''The component version.

        For example, ``1.0.0`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-version
        '''
        return typing.cast(builtins.str, jsii.get(self, "version"))

    @version.setter
    def version(self, value: builtins.str) -> None:
        jsii.set(self, "version", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="changeDescription")
    def change_description(self) -> typing.Optional[builtins.str]:
        '''A change description of the component.

        For example ``initial version`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-changedescription
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "changeDescription"))

    @change_description.setter
    def change_description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "changeDescription", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="data")
    def data(self) -> typing.Optional[builtins.str]:
        '''The data of the component.

        For example, ``name: HelloWorldTestingDocument\\ndescription: This is hello world testing document.\\nschemaVersion: 1.0\\n\\nphases:\\n - name: test\\n steps:\\n - name: HelloWorldStep\\n action: ExecuteBash\\n inputs:\\n commands:\\n - echo \\"Hello World! Test.\\"\\n`` . See Examples below for the schema for creating a component using Data.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-data
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "data"))

    @data.setter
    def data(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "data", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKeyId")
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The KMS key identifier used to encrypt the component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-kmskeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKeyId"))

    @kms_key_id.setter
    def kms_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKeyId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="supportedOsVersions")
    def supported_os_versions(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The operating system (OS) version supported by the component.

        If the OS information is available, a prefix match is performed against the base image OS version during image recipe creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-supportedosversions
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "supportedOsVersions"))

    @supported_os_versions.setter
    def supported_os_versions(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "supportedOsVersions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="uri")
    def uri(self) -> typing.Optional[builtins.str]:
        '''The ``uri`` of a YAML component document file.

        This must be an S3 URL ( ``s3://bucket/key`` ), and the requester must have permission to access the S3 bucket it points to. If you use Amazon S3, you can specify component content up to your service quota.

        Alternatively, you can specify the YAML document inline, using the component ``data`` property. You cannot specify both properties.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-uri
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "uri"))

    @uri.setter
    def uri(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "uri", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_imagebuilder.CfnComponentProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "platform": "platform",
        "version": "version",
        "change_description": "changeDescription",
        "data": "data",
        "description": "description",
        "kms_key_id": "kmsKeyId",
        "supported_os_versions": "supportedOsVersions",
        "tags": "tags",
        "uri": "uri",
    },
)
class CfnComponentProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        platform: builtins.str,
        version: builtins.str,
        change_description: typing.Optional[builtins.str] = None,
        data: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        supported_os_versions: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        uri: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnComponent``.

        :param name: The name of the component.
        :param platform: The platform of the component. For example, ``Windows`` .
        :param version: The component version. For example, ``1.0.0`` .
        :param change_description: A change description of the component. For example ``initial version`` .
        :param data: The data of the component. For example, ``name: HelloWorldTestingDocument\\ndescription: This is hello world testing document.\\nschemaVersion: 1.0\\n\\nphases:\\n - name: test\\n steps:\\n - name: HelloWorldStep\\n action: ExecuteBash\\n inputs:\\n commands:\\n - echo \\"Hello World! Test.\\"\\n`` . See Examples below for the schema for creating a component using Data.
        :param description: The description of the component.
        :param kms_key_id: The KMS key identifier used to encrypt the component.
        :param supported_os_versions: The operating system (OS) version supported by the component. If the OS information is available, a prefix match is performed against the base image OS version during image recipe creation.
        :param tags: The tags associated with the component.
        :param uri: The ``uri`` of a YAML component document file. This must be an S3 URL ( ``s3://bucket/key`` ), and the requester must have permission to access the S3 bucket it points to. If you use Amazon S3, you can specify component content up to your service quota. Alternatively, you can specify the YAML document inline, using the component ``data`` property. You cannot specify both properties.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_imagebuilder as imagebuilder
            
            cfn_component_props = imagebuilder.CfnComponentProps(
                name="name",
                platform="platform",
                version="version",
            
                # the properties below are optional
                change_description="changeDescription",
                data="data",
                description="description",
                kms_key_id="kmsKeyId",
                supported_os_versions=["supportedOsVersions"],
                tags={
                    "tags_key": "tags"
                },
                uri="uri"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
            "platform": platform,
            "version": version,
        }
        if change_description is not None:
            self._values["change_description"] = change_description
        if data is not None:
            self._values["data"] = data
        if description is not None:
            self._values["description"] = description
        if kms_key_id is not None:
            self._values["kms_key_id"] = kms_key_id
        if supported_os_versions is not None:
            self._values["supported_os_versions"] = supported_os_versions
        if tags is not None:
            self._values["tags"] = tags
        if uri is not None:
            self._values["uri"] = uri

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def platform(self) -> builtins.str:
        '''The platform of the component.

        For example, ``Windows`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-platform
        '''
        result = self._values.get("platform")
        assert result is not None, "Required property 'platform' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def version(self) -> builtins.str:
        '''The component version.

        For example, ``1.0.0`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-version
        '''
        result = self._values.get("version")
        assert result is not None, "Required property 'version' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def change_description(self) -> typing.Optional[builtins.str]:
        '''A change description of the component.

        For example ``initial version`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-changedescription
        '''
        result = self._values.get("change_description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def data(self) -> typing.Optional[builtins.str]:
        '''The data of the component.

        For example, ``name: HelloWorldTestingDocument\\ndescription: This is hello world testing document.\\nschemaVersion: 1.0\\n\\nphases:\\n - name: test\\n steps:\\n - name: HelloWorldStep\\n action: ExecuteBash\\n inputs:\\n commands:\\n - echo \\"Hello World! Test.\\"\\n`` . See Examples below for the schema for creating a component using Data.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-data
        '''
        result = self._values.get("data")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The KMS key identifier used to encrypt the component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-kmskeyid
        '''
        result = self._values.get("kms_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def supported_os_versions(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The operating system (OS) version supported by the component.

        If the OS information is available, a prefix match is performed against the base image OS version during image recipe creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-supportedosversions
        '''
        result = self._values.get("supported_os_versions")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''The tags associated with the component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def uri(self) -> typing.Optional[builtins.str]:
        '''The ``uri`` of a YAML component document file.

        This must be an S3 URL ( ``s3://bucket/key`` ), and the requester must have permission to access the S3 bucket it points to. If you use Amazon S3, you can specify component content up to your service quota.

        Alternatively, you can specify the YAML document inline, using the component ``data`` property. You cannot specify both properties.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-component.html#cfn-imagebuilder-component-uri
        '''
        result = self._values.get("uri")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnComponentProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnContainerRecipe(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_imagebuilder.CfnContainerRecipe",
):
    '''A CloudFormation ``AWS::ImageBuilder::ContainerRecipe``.

    Creates a new container recipe. Container recipes define how images are configured, tested, and assessed.

    :cloudformationResource: AWS::ImageBuilder::ContainerRecipe
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_imagebuilder as imagebuilder
        
        cfn_container_recipe = imagebuilder.CfnContainerRecipe(self, "MyCfnContainerRecipe",
            components=[imagebuilder.CfnContainerRecipe.ComponentConfigurationProperty(
                component_arn="componentArn"
            )],
            container_type="containerType",
            name="name",
            parent_image="parentImage",
            target_repository=imagebuilder.CfnContainerRecipe.TargetContainerRepositoryProperty(
                repository_name="repositoryName",
                service="service"
            ),
            version="version",
        
            # the properties below are optional
            description="description",
            dockerfile_template_data="dockerfileTemplateData",
            dockerfile_template_uri="dockerfileTemplateUri",
            image_os_version_override="imageOsVersionOverride",
            instance_configuration=imagebuilder.CfnContainerRecipe.InstanceConfigurationProperty(
                block_device_mappings=[imagebuilder.CfnContainerRecipe.InstanceBlockDeviceMappingProperty(
                    device_name="deviceName",
                    ebs=imagebuilder.CfnContainerRecipe.EbsInstanceBlockDeviceSpecificationProperty(
                        delete_on_termination=False,
                        encrypted=False,
                        iops=123,
                        kms_key_id="kmsKeyId",
                        snapshot_id="snapshotId",
                        throughput=123,
                        volume_size=123,
                        volume_type="volumeType"
                    ),
                    no_device="noDevice",
                    virtual_name="virtualName"
                )],
                image="image"
            ),
            kms_key_id="kmsKeyId",
            platform_override="platformOverride",
            tags={
                "tags_key": "tags"
            },
            working_directory="workingDirectory"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        components: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnContainerRecipe.ComponentConfigurationProperty", _IResolvable_da3f097b]]],
        container_type: builtins.str,
        name: builtins.str,
        parent_image: builtins.str,
        target_repository: typing.Union["CfnContainerRecipe.TargetContainerRepositoryProperty", _IResolvable_da3f097b],
        version: builtins.str,
        description: typing.Optional[builtins.str] = None,
        dockerfile_template_data: typing.Optional[builtins.str] = None,
        dockerfile_template_uri: typing.Optional[builtins.str] = None,
        image_os_version_override: typing.Optional[builtins.str] = None,
        instance_configuration: typing.Optional[typing.Union["CfnContainerRecipe.InstanceConfigurationProperty", _IResolvable_da3f097b]] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        platform_override: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        working_directory: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::ImageBuilder::ContainerRecipe``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param components: Components for build and test that are included in the container recipe.
        :param container_type: Specifies the type of container, such as Docker.
        :param name: The name of the container recipe.
        :param parent_image: The base image for the container recipe.
        :param target_repository: The destination repository for the container image.
        :param version: The semantic version of the container recipe. .. epigraph:: The semantic version has four nodes: ../. You can assign values for the first three, and can filter on all of them. *Assignment:* For the first three nodes you can assign any positive integer value, including zero, with an upper limit of 2^30-1, or 1073741823 for each node. Image Builder automatically assigns the build number to the fourth node. *Patterns:* You can use any numeric pattern that adheres to the assignment requirements for the nodes that you can assign. For example, you might choose a software version pattern, such as 1.0.0, or a date, such as 2021.01.01. *Filtering:* With semantic versioning, you have the flexibility to use wildcards (x) to specify the most recent versions or nodes when selecting the base image or components for your recipe. When you use a wildcard in any node, all nodes to the right of the first wildcard must also be wildcards.
        :param description: The description of the container recipe.
        :param dockerfile_template_data: Dockerfiles are text documents that are used to build Docker containers, and ensure that they contain all of the elements required by the application running inside. The template data consists of contextual variables where Image Builder places build information or scripts, based on your container image recipe.
        :param dockerfile_template_uri: The S3 URI for the Dockerfile that will be used to build your container image.
        :param image_os_version_override: Specifies the operating system version for the source image.
        :param instance_configuration: A group of options that can be used to configure an instance for building and testing container images.
        :param kms_key_id: Identifies which KMS key is used to encrypt the container image for distribution to the target Region.
        :param platform_override: Specifies the operating system platform when you use a custom source image.
        :param tags: Tags that are attached to the container recipe.
        :param working_directory: The working directory for use during build and test workflows.
        '''
        props = CfnContainerRecipeProps(
            components=components,
            container_type=container_type,
            name=name,
            parent_image=parent_image,
            target_repository=target_repository,
            version=version,
            description=description,
            dockerfile_template_data=dockerfile_template_data,
            dockerfile_template_uri=dockerfile_template_uri,
            image_os_version_override=image_os_version_override,
            instance_configuration=instance_configuration,
            kms_key_id=kms_key_id,
            platform_override=platform_override,
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
        '''Returns the Amazon Resource Name (ARN) of the container recipe.

        For example, ``arn:aws:imagebuilder:us-east-1:123456789012:container-recipe/mybasicrecipe/2020.12.17`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''Returns the name of the container recipe.

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
        '''Tags that are attached to the container recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="components")
    def components(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnContainerRecipe.ComponentConfigurationProperty", _IResolvable_da3f097b]]]:
        '''Components for build and test that are included in the container recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-components
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnContainerRecipe.ComponentConfigurationProperty", _IResolvable_da3f097b]]], jsii.get(self, "components"))

    @components.setter
    def components(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnContainerRecipe.ComponentConfigurationProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "components", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="containerType")
    def container_type(self) -> builtins.str:
        '''Specifies the type of container, such as Docker.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-containertype
        '''
        return typing.cast(builtins.str, jsii.get(self, "containerType"))

    @container_type.setter
    def container_type(self, value: builtins.str) -> None:
        jsii.set(self, "containerType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the container recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="parentImage")
    def parent_image(self) -> builtins.str:
        '''The base image for the container recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-parentimage
        '''
        return typing.cast(builtins.str, jsii.get(self, "parentImage"))

    @parent_image.setter
    def parent_image(self, value: builtins.str) -> None:
        jsii.set(self, "parentImage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetRepository")
    def target_repository(
        self,
    ) -> typing.Union["CfnContainerRecipe.TargetContainerRepositoryProperty", _IResolvable_da3f097b]:
        '''The destination repository for the container image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-targetrepository
        '''
        return typing.cast(typing.Union["CfnContainerRecipe.TargetContainerRepositoryProperty", _IResolvable_da3f097b], jsii.get(self, "targetRepository"))

    @target_repository.setter
    def target_repository(
        self,
        value: typing.Union["CfnContainerRecipe.TargetContainerRepositoryProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "targetRepository", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="version")
    def version(self) -> builtins.str:
        '''The semantic version of the container recipe.

        .. epigraph::

           The semantic version has four nodes: ../. You can assign values for the first three, and can filter on all of them.

           *Assignment:* For the first three nodes you can assign any positive integer value, including zero, with an upper limit of 2^30-1, or 1073741823 for each node. Image Builder automatically assigns the build number to the fourth node.

           *Patterns:* You can use any numeric pattern that adheres to the assignment requirements for the nodes that you can assign. For example, you might choose a software version pattern, such as 1.0.0, or a date, such as 2021.01.01.

           *Filtering:* With semantic versioning, you have the flexibility to use wildcards (x) to specify the most recent versions or nodes when selecting the base image or components for your recipe. When you use a wildcard in any node, all nodes to the right of the first wildcard must also be wildcards.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-version
        '''
        return typing.cast(builtins.str, jsii.get(self, "version"))

    @version.setter
    def version(self, value: builtins.str) -> None:
        jsii.set(self, "version", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the container recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dockerfileTemplateData")
    def dockerfile_template_data(self) -> typing.Optional[builtins.str]:
        '''Dockerfiles are text documents that are used to build Docker containers, and ensure that they contain all of the elements required by the application running inside.

        The template data consists of contextual variables where Image Builder places build information or scripts, based on your container image recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-dockerfiletemplatedata
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "dockerfileTemplateData"))

    @dockerfile_template_data.setter
    def dockerfile_template_data(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "dockerfileTemplateData", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dockerfileTemplateUri")
    def dockerfile_template_uri(self) -> typing.Optional[builtins.str]:
        '''The S3 URI for the Dockerfile that will be used to build your container image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-dockerfiletemplateuri
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "dockerfileTemplateUri"))

    @dockerfile_template_uri.setter
    def dockerfile_template_uri(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "dockerfileTemplateUri", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="imageOsVersionOverride")
    def image_os_version_override(self) -> typing.Optional[builtins.str]:
        '''Specifies the operating system version for the source image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-imageosversionoverride
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "imageOsVersionOverride"))

    @image_os_version_override.setter
    def image_os_version_override(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "imageOsVersionOverride", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceConfiguration")
    def instance_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnContainerRecipe.InstanceConfigurationProperty", _IResolvable_da3f097b]]:
        '''A group of options that can be used to configure an instance for building and testing container images.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-instanceconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnContainerRecipe.InstanceConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "instanceConfiguration"))

    @instance_configuration.setter
    def instance_configuration(
        self,
        value: typing.Optional[typing.Union["CfnContainerRecipe.InstanceConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "instanceConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKeyId")
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''Identifies which KMS key is used to encrypt the container image for distribution to the target Region.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-kmskeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKeyId"))

    @kms_key_id.setter
    def kms_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKeyId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="platformOverride")
    def platform_override(self) -> typing.Optional[builtins.str]:
        '''Specifies the operating system platform when you use a custom source image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-platformoverride
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "platformOverride"))

    @platform_override.setter
    def platform_override(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "platformOverride", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="workingDirectory")
    def working_directory(self) -> typing.Optional[builtins.str]:
        '''The working directory for use during build and test workflows.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-workingdirectory
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "workingDirectory"))

    @working_directory.setter
    def working_directory(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "workingDirectory", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnContainerRecipe.ComponentConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"component_arn": "componentArn"},
    )
    class ComponentConfigurationProperty:
        def __init__(
            self,
            *,
            component_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Configuration details of the component.

            :param component_arn: The Amazon Resource Name (ARN) of the component.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-componentconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                component_configuration_property = imagebuilder.CfnContainerRecipe.ComponentConfigurationProperty(
                    component_arn="componentArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if component_arn is not None:
                self._values["component_arn"] = component_arn

        @builtins.property
        def component_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the component.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-componentconfiguration.html#cfn-imagebuilder-containerrecipe-componentconfiguration-componentarn
            '''
            result = self._values.get("component_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComponentConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnContainerRecipe.EbsInstanceBlockDeviceSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "delete_on_termination": "deleteOnTermination",
            "encrypted": "encrypted",
            "iops": "iops",
            "kms_key_id": "kmsKeyId",
            "snapshot_id": "snapshotId",
            "throughput": "throughput",
            "volume_size": "volumeSize",
            "volume_type": "volumeType",
        },
    )
    class EbsInstanceBlockDeviceSpecificationProperty:
        def __init__(
            self,
            *,
            delete_on_termination: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            encrypted: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            iops: typing.Optional[jsii.Number] = None,
            kms_key_id: typing.Optional[builtins.str] = None,
            snapshot_id: typing.Optional[builtins.str] = None,
            throughput: typing.Optional[jsii.Number] = None,
            volume_size: typing.Optional[jsii.Number] = None,
            volume_type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Amazon EBS-specific block device mapping specifications.

            :param delete_on_termination: Use to configure delete on termination of the associated device.
            :param encrypted: Use to configure device encryption.
            :param iops: Use to configure device IOPS.
            :param kms_key_id: Use to configure the KMS key to use when encrypting the device.
            :param snapshot_id: The snapshot that defines the device contents.
            :param throughput: *For GP3 volumes only* – The throughput in MiB/s that the volume supports.
            :param volume_size: Use to override the device's volume size.
            :param volume_type: Use to override the device's volume type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                ebs_instance_block_device_specification_property = imagebuilder.CfnContainerRecipe.EbsInstanceBlockDeviceSpecificationProperty(
                    delete_on_termination=False,
                    encrypted=False,
                    iops=123,
                    kms_key_id="kmsKeyId",
                    snapshot_id="snapshotId",
                    throughput=123,
                    volume_size=123,
                    volume_type="volumeType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if delete_on_termination is not None:
                self._values["delete_on_termination"] = delete_on_termination
            if encrypted is not None:
                self._values["encrypted"] = encrypted
            if iops is not None:
                self._values["iops"] = iops
            if kms_key_id is not None:
                self._values["kms_key_id"] = kms_key_id
            if snapshot_id is not None:
                self._values["snapshot_id"] = snapshot_id
            if throughput is not None:
                self._values["throughput"] = throughput
            if volume_size is not None:
                self._values["volume_size"] = volume_size
            if volume_type is not None:
                self._values["volume_type"] = volume_type

        @builtins.property
        def delete_on_termination(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Use to configure delete on termination of the associated device.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification-deleteontermination
            '''
            result = self._values.get("delete_on_termination")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def encrypted(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Use to configure device encryption.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification-encrypted
            '''
            result = self._values.get("encrypted")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def iops(self) -> typing.Optional[jsii.Number]:
            '''Use to configure device IOPS.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification-iops
            '''
            result = self._values.get("iops")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def kms_key_id(self) -> typing.Optional[builtins.str]:
            '''Use to configure the KMS key to use when encrypting the device.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification-kmskeyid
            '''
            result = self._values.get("kms_key_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def snapshot_id(self) -> typing.Optional[builtins.str]:
            '''The snapshot that defines the device contents.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification-snapshotid
            '''
            result = self._values.get("snapshot_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def throughput(self) -> typing.Optional[jsii.Number]:
            '''*For GP3 volumes only* – The throughput in MiB/s that the volume supports.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification-throughput
            '''
            result = self._values.get("throughput")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def volume_size(self) -> typing.Optional[jsii.Number]:
            '''Use to override the device's volume size.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification-volumesize
            '''
            result = self._values.get("volume_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def volume_type(self) -> typing.Optional[builtins.str]:
            '''Use to override the device's volume type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-containerrecipe-ebsinstanceblockdevicespecification-volumetype
            '''
            result = self._values.get("volume_type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EbsInstanceBlockDeviceSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnContainerRecipe.InstanceBlockDeviceMappingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "device_name": "deviceName",
            "ebs": "ebs",
            "no_device": "noDevice",
            "virtual_name": "virtualName",
        },
    )
    class InstanceBlockDeviceMappingProperty:
        def __init__(
            self,
            *,
            device_name: typing.Optional[builtins.str] = None,
            ebs: typing.Optional[typing.Union["CfnContainerRecipe.EbsInstanceBlockDeviceSpecificationProperty", _IResolvable_da3f097b]] = None,
            no_device: typing.Optional[builtins.str] = None,
            virtual_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Defines block device mappings for the instance used to configure your image.

            :param device_name: The device to which these mappings apply.
            :param ebs: Use to manage Amazon EBS-specific configuration for this mapping.
            :param no_device: Use to remove a mapping from the base image.
            :param virtual_name: Use to manage instance ephemeral devices.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-instanceblockdevicemapping.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                instance_block_device_mapping_property = imagebuilder.CfnContainerRecipe.InstanceBlockDeviceMappingProperty(
                    device_name="deviceName",
                    ebs=imagebuilder.CfnContainerRecipe.EbsInstanceBlockDeviceSpecificationProperty(
                        delete_on_termination=False,
                        encrypted=False,
                        iops=123,
                        kms_key_id="kmsKeyId",
                        snapshot_id="snapshotId",
                        throughput=123,
                        volume_size=123,
                        volume_type="volumeType"
                    ),
                    no_device="noDevice",
                    virtual_name="virtualName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if device_name is not None:
                self._values["device_name"] = device_name
            if ebs is not None:
                self._values["ebs"] = ebs
            if no_device is not None:
                self._values["no_device"] = no_device
            if virtual_name is not None:
                self._values["virtual_name"] = virtual_name

        @builtins.property
        def device_name(self) -> typing.Optional[builtins.str]:
            '''The device to which these mappings apply.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-instanceblockdevicemapping.html#cfn-imagebuilder-containerrecipe-instanceblockdevicemapping-devicename
            '''
            result = self._values.get("device_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ebs(
            self,
        ) -> typing.Optional[typing.Union["CfnContainerRecipe.EbsInstanceBlockDeviceSpecificationProperty", _IResolvable_da3f097b]]:
            '''Use to manage Amazon EBS-specific configuration for this mapping.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-instanceblockdevicemapping.html#cfn-imagebuilder-containerrecipe-instanceblockdevicemapping-ebs
            '''
            result = self._values.get("ebs")
            return typing.cast(typing.Optional[typing.Union["CfnContainerRecipe.EbsInstanceBlockDeviceSpecificationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def no_device(self) -> typing.Optional[builtins.str]:
            '''Use to remove a mapping from the base image.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-instanceblockdevicemapping.html#cfn-imagebuilder-containerrecipe-instanceblockdevicemapping-nodevice
            '''
            result = self._values.get("no_device")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def virtual_name(self) -> typing.Optional[builtins.str]:
            '''Use to manage instance ephemeral devices.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-instanceblockdevicemapping.html#cfn-imagebuilder-containerrecipe-instanceblockdevicemapping-virtualname
            '''
            result = self._values.get("virtual_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InstanceBlockDeviceMappingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnContainerRecipe.InstanceConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "block_device_mappings": "blockDeviceMappings",
            "image": "image",
        },
    )
    class InstanceConfigurationProperty:
        def __init__(
            self,
            *,
            block_device_mappings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnContainerRecipe.InstanceBlockDeviceMappingProperty", _IResolvable_da3f097b]]]] = None,
            image: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Defines a custom source AMI and block device mapping configurations of an instance used for building and testing container images.

            :param block_device_mappings: Defines the block devices to attach for building an instance from this Image Builder AMI.
            :param image: The AMI ID to use as the base image for a container build and test instance. If not specified, Image Builder will use the appropriate ECS-optimized AMI as a base image.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-instanceconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                instance_configuration_property = imagebuilder.CfnContainerRecipe.InstanceConfigurationProperty(
                    block_device_mappings=[imagebuilder.CfnContainerRecipe.InstanceBlockDeviceMappingProperty(
                        device_name="deviceName",
                        ebs=imagebuilder.CfnContainerRecipe.EbsInstanceBlockDeviceSpecificationProperty(
                            delete_on_termination=False,
                            encrypted=False,
                            iops=123,
                            kms_key_id="kmsKeyId",
                            snapshot_id="snapshotId",
                            throughput=123,
                            volume_size=123,
                            volume_type="volumeType"
                        ),
                        no_device="noDevice",
                        virtual_name="virtualName"
                    )],
                    image="image"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if block_device_mappings is not None:
                self._values["block_device_mappings"] = block_device_mappings
            if image is not None:
                self._values["image"] = image

        @builtins.property
        def block_device_mappings(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnContainerRecipe.InstanceBlockDeviceMappingProperty", _IResolvable_da3f097b]]]]:
            '''Defines the block devices to attach for building an instance from this Image Builder AMI.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-instanceconfiguration.html#cfn-imagebuilder-containerrecipe-instanceconfiguration-blockdevicemappings
            '''
            result = self._values.get("block_device_mappings")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnContainerRecipe.InstanceBlockDeviceMappingProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def image(self) -> typing.Optional[builtins.str]:
            '''The AMI ID to use as the base image for a container build and test instance.

            If not specified, Image Builder will use the appropriate ECS-optimized AMI as a base image.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-instanceconfiguration.html#cfn-imagebuilder-containerrecipe-instanceconfiguration-image
            '''
            result = self._values.get("image")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InstanceConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnContainerRecipe.TargetContainerRepositoryProperty",
        jsii_struct_bases=[],
        name_mapping={"repository_name": "repositoryName", "service": "service"},
    )
    class TargetContainerRepositoryProperty:
        def __init__(
            self,
            *,
            repository_name: typing.Optional[builtins.str] = None,
            service: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The container repository where the output container image is stored.

            :param repository_name: The name of the container repository where the output container image is stored. This name is prefixed by the repository location.
            :param service: Specifies the service in which this image was registered.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-targetcontainerrepository.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                target_container_repository_property = imagebuilder.CfnContainerRecipe.TargetContainerRepositoryProperty(
                    repository_name="repositoryName",
                    service="service"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if repository_name is not None:
                self._values["repository_name"] = repository_name
            if service is not None:
                self._values["service"] = service

        @builtins.property
        def repository_name(self) -> typing.Optional[builtins.str]:
            '''The name of the container repository where the output container image is stored.

            This name is prefixed by the repository location.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-targetcontainerrepository.html#cfn-imagebuilder-containerrecipe-targetcontainerrepository-repositoryname
            '''
            result = self._values.get("repository_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def service(self) -> typing.Optional[builtins.str]:
            '''Specifies the service in which this image was registered.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-containerrecipe-targetcontainerrepository.html#cfn-imagebuilder-containerrecipe-targetcontainerrepository-service
            '''
            result = self._values.get("service")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TargetContainerRepositoryProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_imagebuilder.CfnContainerRecipeProps",
    jsii_struct_bases=[],
    name_mapping={
        "components": "components",
        "container_type": "containerType",
        "name": "name",
        "parent_image": "parentImage",
        "target_repository": "targetRepository",
        "version": "version",
        "description": "description",
        "dockerfile_template_data": "dockerfileTemplateData",
        "dockerfile_template_uri": "dockerfileTemplateUri",
        "image_os_version_override": "imageOsVersionOverride",
        "instance_configuration": "instanceConfiguration",
        "kms_key_id": "kmsKeyId",
        "platform_override": "platformOverride",
        "tags": "tags",
        "working_directory": "workingDirectory",
    },
)
class CfnContainerRecipeProps:
    def __init__(
        self,
        *,
        components: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnContainerRecipe.ComponentConfigurationProperty, _IResolvable_da3f097b]]],
        container_type: builtins.str,
        name: builtins.str,
        parent_image: builtins.str,
        target_repository: typing.Union[CfnContainerRecipe.TargetContainerRepositoryProperty, _IResolvable_da3f097b],
        version: builtins.str,
        description: typing.Optional[builtins.str] = None,
        dockerfile_template_data: typing.Optional[builtins.str] = None,
        dockerfile_template_uri: typing.Optional[builtins.str] = None,
        image_os_version_override: typing.Optional[builtins.str] = None,
        instance_configuration: typing.Optional[typing.Union[CfnContainerRecipe.InstanceConfigurationProperty, _IResolvable_da3f097b]] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        platform_override: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        working_directory: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnContainerRecipe``.

        :param components: Components for build and test that are included in the container recipe.
        :param container_type: Specifies the type of container, such as Docker.
        :param name: The name of the container recipe.
        :param parent_image: The base image for the container recipe.
        :param target_repository: The destination repository for the container image.
        :param version: The semantic version of the container recipe. .. epigraph:: The semantic version has four nodes: ../. You can assign values for the first three, and can filter on all of them. *Assignment:* For the first three nodes you can assign any positive integer value, including zero, with an upper limit of 2^30-1, or 1073741823 for each node. Image Builder automatically assigns the build number to the fourth node. *Patterns:* You can use any numeric pattern that adheres to the assignment requirements for the nodes that you can assign. For example, you might choose a software version pattern, such as 1.0.0, or a date, such as 2021.01.01. *Filtering:* With semantic versioning, you have the flexibility to use wildcards (x) to specify the most recent versions or nodes when selecting the base image or components for your recipe. When you use a wildcard in any node, all nodes to the right of the first wildcard must also be wildcards.
        :param description: The description of the container recipe.
        :param dockerfile_template_data: Dockerfiles are text documents that are used to build Docker containers, and ensure that they contain all of the elements required by the application running inside. The template data consists of contextual variables where Image Builder places build information or scripts, based on your container image recipe.
        :param dockerfile_template_uri: The S3 URI for the Dockerfile that will be used to build your container image.
        :param image_os_version_override: Specifies the operating system version for the source image.
        :param instance_configuration: A group of options that can be used to configure an instance for building and testing container images.
        :param kms_key_id: Identifies which KMS key is used to encrypt the container image for distribution to the target Region.
        :param platform_override: Specifies the operating system platform when you use a custom source image.
        :param tags: Tags that are attached to the container recipe.
        :param working_directory: The working directory for use during build and test workflows.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_imagebuilder as imagebuilder
            
            cfn_container_recipe_props = imagebuilder.CfnContainerRecipeProps(
                components=[imagebuilder.CfnContainerRecipe.ComponentConfigurationProperty(
                    component_arn="componentArn"
                )],
                container_type="containerType",
                name="name",
                parent_image="parentImage",
                target_repository=imagebuilder.CfnContainerRecipe.TargetContainerRepositoryProperty(
                    repository_name="repositoryName",
                    service="service"
                ),
                version="version",
            
                # the properties below are optional
                description="description",
                dockerfile_template_data="dockerfileTemplateData",
                dockerfile_template_uri="dockerfileTemplateUri",
                image_os_version_override="imageOsVersionOverride",
                instance_configuration=imagebuilder.CfnContainerRecipe.InstanceConfigurationProperty(
                    block_device_mappings=[imagebuilder.CfnContainerRecipe.InstanceBlockDeviceMappingProperty(
                        device_name="deviceName",
                        ebs=imagebuilder.CfnContainerRecipe.EbsInstanceBlockDeviceSpecificationProperty(
                            delete_on_termination=False,
                            encrypted=False,
                            iops=123,
                            kms_key_id="kmsKeyId",
                            snapshot_id="snapshotId",
                            throughput=123,
                            volume_size=123,
                            volume_type="volumeType"
                        ),
                        no_device="noDevice",
                        virtual_name="virtualName"
                    )],
                    image="image"
                ),
                kms_key_id="kmsKeyId",
                platform_override="platformOverride",
                tags={
                    "tags_key": "tags"
                },
                working_directory="workingDirectory"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "components": components,
            "container_type": container_type,
            "name": name,
            "parent_image": parent_image,
            "target_repository": target_repository,
            "version": version,
        }
        if description is not None:
            self._values["description"] = description
        if dockerfile_template_data is not None:
            self._values["dockerfile_template_data"] = dockerfile_template_data
        if dockerfile_template_uri is not None:
            self._values["dockerfile_template_uri"] = dockerfile_template_uri
        if image_os_version_override is not None:
            self._values["image_os_version_override"] = image_os_version_override
        if instance_configuration is not None:
            self._values["instance_configuration"] = instance_configuration
        if kms_key_id is not None:
            self._values["kms_key_id"] = kms_key_id
        if platform_override is not None:
            self._values["platform_override"] = platform_override
        if tags is not None:
            self._values["tags"] = tags
        if working_directory is not None:
            self._values["working_directory"] = working_directory

    @builtins.property
    def components(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnContainerRecipe.ComponentConfigurationProperty, _IResolvable_da3f097b]]]:
        '''Components for build and test that are included in the container recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-components
        '''
        result = self._values.get("components")
        assert result is not None, "Required property 'components' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnContainerRecipe.ComponentConfigurationProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def container_type(self) -> builtins.str:
        '''Specifies the type of container, such as Docker.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-containertype
        '''
        result = self._values.get("container_type")
        assert result is not None, "Required property 'container_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the container recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def parent_image(self) -> builtins.str:
        '''The base image for the container recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-parentimage
        '''
        result = self._values.get("parent_image")
        assert result is not None, "Required property 'parent_image' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def target_repository(
        self,
    ) -> typing.Union[CfnContainerRecipe.TargetContainerRepositoryProperty, _IResolvable_da3f097b]:
        '''The destination repository for the container image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-targetrepository
        '''
        result = self._values.get("target_repository")
        assert result is not None, "Required property 'target_repository' is missing"
        return typing.cast(typing.Union[CfnContainerRecipe.TargetContainerRepositoryProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def version(self) -> builtins.str:
        '''The semantic version of the container recipe.

        .. epigraph::

           The semantic version has four nodes: ../. You can assign values for the first three, and can filter on all of them.

           *Assignment:* For the first three nodes you can assign any positive integer value, including zero, with an upper limit of 2^30-1, or 1073741823 for each node. Image Builder automatically assigns the build number to the fourth node.

           *Patterns:* You can use any numeric pattern that adheres to the assignment requirements for the nodes that you can assign. For example, you might choose a software version pattern, such as 1.0.0, or a date, such as 2021.01.01.

           *Filtering:* With semantic versioning, you have the flexibility to use wildcards (x) to specify the most recent versions or nodes when selecting the base image or components for your recipe. When you use a wildcard in any node, all nodes to the right of the first wildcard must also be wildcards.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-version
        '''
        result = self._values.get("version")
        assert result is not None, "Required property 'version' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the container recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def dockerfile_template_data(self) -> typing.Optional[builtins.str]:
        '''Dockerfiles are text documents that are used to build Docker containers, and ensure that they contain all of the elements required by the application running inside.

        The template data consists of contextual variables where Image Builder places build information or scripts, based on your container image recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-dockerfiletemplatedata
        '''
        result = self._values.get("dockerfile_template_data")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def dockerfile_template_uri(self) -> typing.Optional[builtins.str]:
        '''The S3 URI for the Dockerfile that will be used to build your container image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-dockerfiletemplateuri
        '''
        result = self._values.get("dockerfile_template_uri")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def image_os_version_override(self) -> typing.Optional[builtins.str]:
        '''Specifies the operating system version for the source image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-imageosversionoverride
        '''
        result = self._values.get("image_os_version_override")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def instance_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnContainerRecipe.InstanceConfigurationProperty, _IResolvable_da3f097b]]:
        '''A group of options that can be used to configure an instance for building and testing container images.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-instanceconfiguration
        '''
        result = self._values.get("instance_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnContainerRecipe.InstanceConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''Identifies which KMS key is used to encrypt the container image for distribution to the target Region.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-kmskeyid
        '''
        result = self._values.get("kms_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def platform_override(self) -> typing.Optional[builtins.str]:
        '''Specifies the operating system platform when you use a custom source image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-platformoverride
        '''
        result = self._values.get("platform_override")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Tags that are attached to the container recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def working_directory(self) -> typing.Optional[builtins.str]:
        '''The working directory for use during build and test workflows.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-containerrecipe.html#cfn-imagebuilder-containerrecipe-workingdirectory
        '''
        result = self._values.get("working_directory")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnContainerRecipeProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDistributionConfiguration(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_imagebuilder.CfnDistributionConfiguration",
):
    '''A CloudFormation ``AWS::ImageBuilder::DistributionConfiguration``.

    A distribution configuration allows you to specify the name and description of your output AMI, authorize other AWS account s to launch the AMI, and replicate the AMI to other AWS Regions . It also allows you to export the AMI to Amazon S3 .

    :cloudformationResource: AWS::ImageBuilder::DistributionConfiguration
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-distributionconfiguration.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_imagebuilder as imagebuilder
        
        # ami_distribution_configuration: Any
        # container_distribution_configuration: Any
        
        cfn_distribution_configuration = imagebuilder.CfnDistributionConfiguration(self, "MyCfnDistributionConfiguration",
            distributions=[imagebuilder.CfnDistributionConfiguration.DistributionProperty(
                region="region",
        
                # the properties below are optional
                ami_distribution_configuration=ami_distribution_configuration,
                container_distribution_configuration=container_distribution_configuration,
                launch_template_configurations=[imagebuilder.CfnDistributionConfiguration.LaunchTemplateConfigurationProperty(
                    account_id="accountId",
                    launch_template_id="launchTemplateId",
                    set_default_version=False
                )],
                license_configuration_arns=["licenseConfigurationArns"]
            )],
            name="name",
        
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
        distributions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDistributionConfiguration.DistributionProperty", _IResolvable_da3f097b]]],
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::ImageBuilder::DistributionConfiguration``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param distributions: The distributions of this distribution configuration formatted as an array of Distribution objects.
        :param name: The name of this distribution configuration.
        :param description: The description of this distribution configuration.
        :param tags: The tags of this distribution configuration.
        '''
        props = CfnDistributionConfigurationProps(
            distributions=distributions, name=name, description=description, tags=tags
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
        '''Returns the Amazon Resource Name (ARN) of this distribution configuration.

        The following pattern is applied: ``^arn:aws[^:]*:imagebuilder:[^:]+:(?:\\d{12}|aws):(?:image-recipe|infrastructure-configuration|distribution-configuration|component|image|image-pipeline)/[a-z0-9-_]+(?:/(?:(?:x|\\d+)\\.(?:x|\\d+)\\.(?:x|\\d+))(?:/\\d+)?)?$`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''Returns the name of the distribution configuration.

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
        '''The tags of this distribution configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-distributionconfiguration.html#cfn-imagebuilder-distributionconfiguration-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="distributions")
    def distributions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDistributionConfiguration.DistributionProperty", _IResolvable_da3f097b]]]:
        '''The distributions of this distribution configuration formatted as an array of Distribution objects.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-distributionconfiguration.html#cfn-imagebuilder-distributionconfiguration-distributions
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDistributionConfiguration.DistributionProperty", _IResolvable_da3f097b]]], jsii.get(self, "distributions"))

    @distributions.setter
    def distributions(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDistributionConfiguration.DistributionProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "distributions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of this distribution configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-distributionconfiguration.html#cfn-imagebuilder-distributionconfiguration-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of this distribution configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-distributionconfiguration.html#cfn-imagebuilder-distributionconfiguration-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnDistributionConfiguration.DistributionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "region": "region",
            "ami_distribution_configuration": "amiDistributionConfiguration",
            "container_distribution_configuration": "containerDistributionConfiguration",
            "launch_template_configurations": "launchTemplateConfigurations",
            "license_configuration_arns": "licenseConfigurationArns",
        },
    )
    class DistributionProperty:
        def __init__(
            self,
            *,
            region: builtins.str,
            ami_distribution_configuration: typing.Any = None,
            container_distribution_configuration: typing.Any = None,
            launch_template_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDistributionConfiguration.LaunchTemplateConfigurationProperty", _IResolvable_da3f097b]]]] = None,
            license_configuration_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''The distribution configuration distribution defines the settings for a specific Region in the Distribution Configuration.

            You must specify whether the distribution is for an AMI or a container image. To do so, include exactly one of the following data types for your distribution:

            - amiDistributionConfiguration
            - containerDistributionConfiguration

            :param region: The target Region for the Distribution Configuration. For example, ``eu-west-1`` .
            :param ami_distribution_configuration: The specific AMI settings, such as launch permissions and AMI tags. For details, see example schema below.
            :param container_distribution_configuration: Container distribution settings for encryption, licensing, and sharing in a specific Region. For details, see example schema below.
            :param launch_template_configurations: A group of launchTemplateConfiguration settings that apply to image distribution for specified accounts.
            :param license_configuration_arns: The License Manager Configuration to associate with the AMI in the specified Region. For more information, see the `LicenseConfiguration API <https://docs.aws.amazon.com/license-manager/latest/APIReference/API_LicenseConfiguration.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-distributionconfiguration-distribution.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                # ami_distribution_configuration: Any
                # container_distribution_configuration: Any
                
                distribution_property = imagebuilder.CfnDistributionConfiguration.DistributionProperty(
                    region="region",
                
                    # the properties below are optional
                    ami_distribution_configuration=ami_distribution_configuration,
                    container_distribution_configuration=container_distribution_configuration,
                    launch_template_configurations=[imagebuilder.CfnDistributionConfiguration.LaunchTemplateConfigurationProperty(
                        account_id="accountId",
                        launch_template_id="launchTemplateId",
                        set_default_version=False
                    )],
                    license_configuration_arns=["licenseConfigurationArns"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "region": region,
            }
            if ami_distribution_configuration is not None:
                self._values["ami_distribution_configuration"] = ami_distribution_configuration
            if container_distribution_configuration is not None:
                self._values["container_distribution_configuration"] = container_distribution_configuration
            if launch_template_configurations is not None:
                self._values["launch_template_configurations"] = launch_template_configurations
            if license_configuration_arns is not None:
                self._values["license_configuration_arns"] = license_configuration_arns

        @builtins.property
        def region(self) -> builtins.str:
            '''The target Region for the Distribution Configuration.

            For example, ``eu-west-1`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-distributionconfiguration-distribution.html#cfn-imagebuilder-distributionconfiguration-distribution-region
            '''
            result = self._values.get("region")
            assert result is not None, "Required property 'region' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def ami_distribution_configuration(self) -> typing.Any:
            '''The specific AMI settings, such as launch permissions and AMI tags.

            For details, see example schema below.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-distributionconfiguration-distribution.html#cfn-imagebuilder-distributionconfiguration-distribution-amidistributionconfiguration
            '''
            result = self._values.get("ami_distribution_configuration")
            return typing.cast(typing.Any, result)

        @builtins.property
        def container_distribution_configuration(self) -> typing.Any:
            '''Container distribution settings for encryption, licensing, and sharing in a specific Region.

            For details, see example schema below.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-distributionconfiguration-distribution.html#cfn-imagebuilder-distributionconfiguration-distribution-containerdistributionconfiguration
            '''
            result = self._values.get("container_distribution_configuration")
            return typing.cast(typing.Any, result)

        @builtins.property
        def launch_template_configurations(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDistributionConfiguration.LaunchTemplateConfigurationProperty", _IResolvable_da3f097b]]]]:
            '''A group of launchTemplateConfiguration settings that apply to image distribution for specified accounts.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-distributionconfiguration-distribution.html#cfn-imagebuilder-distributionconfiguration-distribution-launchtemplateconfigurations
            '''
            result = self._values.get("launch_template_configurations")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDistributionConfiguration.LaunchTemplateConfigurationProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def license_configuration_arns(
            self,
        ) -> typing.Optional[typing.List[builtins.str]]:
            '''The License Manager Configuration to associate with the AMI in the specified Region.

            For more information, see the `LicenseConfiguration API <https://docs.aws.amazon.com/license-manager/latest/APIReference/API_LicenseConfiguration.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-distributionconfiguration-distribution.html#cfn-imagebuilder-distributionconfiguration-distribution-licenseconfigurationarns
            '''
            result = self._values.get("license_configuration_arns")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DistributionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnDistributionConfiguration.LaunchTemplateConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "account_id": "accountId",
            "launch_template_id": "launchTemplateId",
            "set_default_version": "setDefaultVersion",
        },
    )
    class LaunchTemplateConfigurationProperty:
        def __init__(
            self,
            *,
            account_id: typing.Optional[builtins.str] = None,
            launch_template_id: typing.Optional[builtins.str] = None,
            set_default_version: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Identifies an Amazon EC2 launch template to use for a specific account.

            :param account_id: The account ID that this configuration applies to.
            :param launch_template_id: Identifies the Amazon EC2 launch template to use.
            :param set_default_version: Set the specified Amazon EC2 launch template as the default launch template for the specified account.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-distributionconfiguration-launchtemplateconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                launch_template_configuration_property = imagebuilder.CfnDistributionConfiguration.LaunchTemplateConfigurationProperty(
                    account_id="accountId",
                    launch_template_id="launchTemplateId",
                    set_default_version=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if account_id is not None:
                self._values["account_id"] = account_id
            if launch_template_id is not None:
                self._values["launch_template_id"] = launch_template_id
            if set_default_version is not None:
                self._values["set_default_version"] = set_default_version

        @builtins.property
        def account_id(self) -> typing.Optional[builtins.str]:
            '''The account ID that this configuration applies to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-distributionconfiguration-launchtemplateconfiguration.html#cfn-imagebuilder-distributionconfiguration-launchtemplateconfiguration-accountid
            '''
            result = self._values.get("account_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def launch_template_id(self) -> typing.Optional[builtins.str]:
            '''Identifies the Amazon EC2 launch template to use.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-distributionconfiguration-launchtemplateconfiguration.html#cfn-imagebuilder-distributionconfiguration-launchtemplateconfiguration-launchtemplateid
            '''
            result = self._values.get("launch_template_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def set_default_version(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Set the specified Amazon EC2 launch template as the default launch template for the specified account.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-distributionconfiguration-launchtemplateconfiguration.html#cfn-imagebuilder-distributionconfiguration-launchtemplateconfiguration-setdefaultversion
            '''
            result = self._values.get("set_default_version")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LaunchTemplateConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_imagebuilder.CfnDistributionConfigurationProps",
    jsii_struct_bases=[],
    name_mapping={
        "distributions": "distributions",
        "name": "name",
        "description": "description",
        "tags": "tags",
    },
)
class CfnDistributionConfigurationProps:
    def __init__(
        self,
        *,
        distributions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnDistributionConfiguration.DistributionProperty, _IResolvable_da3f097b]]],
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDistributionConfiguration``.

        :param distributions: The distributions of this distribution configuration formatted as an array of Distribution objects.
        :param name: The name of this distribution configuration.
        :param description: The description of this distribution configuration.
        :param tags: The tags of this distribution configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-distributionconfiguration.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_imagebuilder as imagebuilder
            
            # ami_distribution_configuration: Any
            # container_distribution_configuration: Any
            
            cfn_distribution_configuration_props = imagebuilder.CfnDistributionConfigurationProps(
                distributions=[imagebuilder.CfnDistributionConfiguration.DistributionProperty(
                    region="region",
            
                    # the properties below are optional
                    ami_distribution_configuration=ami_distribution_configuration,
                    container_distribution_configuration=container_distribution_configuration,
                    launch_template_configurations=[imagebuilder.CfnDistributionConfiguration.LaunchTemplateConfigurationProperty(
                        account_id="accountId",
                        launch_template_id="launchTemplateId",
                        set_default_version=False
                    )],
                    license_configuration_arns=["licenseConfigurationArns"]
                )],
                name="name",
            
                # the properties below are optional
                description="description",
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "distributions": distributions,
            "name": name,
        }
        if description is not None:
            self._values["description"] = description
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def distributions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDistributionConfiguration.DistributionProperty, _IResolvable_da3f097b]]]:
        '''The distributions of this distribution configuration formatted as an array of Distribution objects.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-distributionconfiguration.html#cfn-imagebuilder-distributionconfiguration-distributions
        '''
        result = self._values.get("distributions")
        assert result is not None, "Required property 'distributions' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDistributionConfiguration.DistributionProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of this distribution configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-distributionconfiguration.html#cfn-imagebuilder-distributionconfiguration-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of this distribution configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-distributionconfiguration.html#cfn-imagebuilder-distributionconfiguration-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''The tags of this distribution configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-distributionconfiguration.html#cfn-imagebuilder-distributionconfiguration-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDistributionConfigurationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnImage(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImage",
):
    '''A CloudFormation ``AWS::ImageBuilder::Image``.

    An image build version. An image is a customized, secure, and up-to-date “golden” server image that is pre-installed and pre-configured with software and settings to meet specific IT standards.

    :cloudformationResource: AWS::ImageBuilder::Image
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_imagebuilder as imagebuilder
        
        cfn_image = imagebuilder.CfnImage(self, "MyCfnImage",
            infrastructure_configuration_arn="infrastructureConfigurationArn",
        
            # the properties below are optional
            container_recipe_arn="containerRecipeArn",
            distribution_configuration_arn="distributionConfigurationArn",
            enhanced_image_metadata_enabled=False,
            image_recipe_arn="imageRecipeArn",
            image_tests_configuration=imagebuilder.CfnImage.ImageTestsConfigurationProperty(
                image_tests_enabled=False,
                timeout_minutes=123
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
        infrastructure_configuration_arn: builtins.str,
        container_recipe_arn: typing.Optional[builtins.str] = None,
        distribution_configuration_arn: typing.Optional[builtins.str] = None,
        enhanced_image_metadata_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        image_recipe_arn: typing.Optional[builtins.str] = None,
        image_tests_configuration: typing.Optional[typing.Union["CfnImage.ImageTestsConfigurationProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::ImageBuilder::Image``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param infrastructure_configuration_arn: The Amazon Resource Name (ARN) of the infrastructure configuration associated with this image pipeline.
        :param container_recipe_arn: The Amazon Resource Name (ARN) of the container recipe that is used for this pipeline.
        :param distribution_configuration_arn: The Amazon Resource Name (ARN) of the distribution configuration.
        :param enhanced_image_metadata_enabled: Collects additional information about the image being created, including the operating system (OS) version and package list. This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.
        :param image_recipe_arn: The Amazon Resource Name (ARN) of the image recipe.
        :param image_tests_configuration: The configuration settings for your image test components, which includes a toggle that allows you to turn off tests, and a timeout setting.
        :param tags: The tags of the image.
        '''
        props = CfnImageProps(
            infrastructure_configuration_arn=infrastructure_configuration_arn,
            container_recipe_arn=container_recipe_arn,
            distribution_configuration_arn=distribution_configuration_arn,
            enhanced_image_metadata_enabled=enhanced_image_metadata_enabled,
            image_recipe_arn=image_recipe_arn,
            image_tests_configuration=image_tests_configuration,
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
        '''Returns the Amazon Resource Name (ARN) of the image.

        For example, ``arn:aws:imagebuilder:us-west-2:123456789012:image/mybasicrecipe/2019.12.03/1`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrImageId")
    def attr_image_id(self) -> builtins.str:
        '''Returns the AMI ID of the Amazon EC2 AMI in the Region in which you are using Image Builder.

        :cloudformationAttribute: ImageId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrImageId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''Returns the name of the image.

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
        '''The tags of the image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html#cfn-imagebuilder-image-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="infrastructureConfigurationArn")
    def infrastructure_configuration_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the infrastructure configuration associated with this image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html#cfn-imagebuilder-image-infrastructureconfigurationarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "infrastructureConfigurationArn"))

    @infrastructure_configuration_arn.setter
    def infrastructure_configuration_arn(self, value: builtins.str) -> None:
        jsii.set(self, "infrastructureConfigurationArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="containerRecipeArn")
    def container_recipe_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the container recipe that is used for this pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html#cfn-imagebuilder-image-containerrecipearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "containerRecipeArn"))

    @container_recipe_arn.setter
    def container_recipe_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "containerRecipeArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="distributionConfigurationArn")
    def distribution_configuration_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the distribution configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html#cfn-imagebuilder-image-distributionconfigurationarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "distributionConfigurationArn"))

    @distribution_configuration_arn.setter
    def distribution_configuration_arn(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "distributionConfigurationArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enhancedImageMetadataEnabled")
    def enhanced_image_metadata_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Collects additional information about the image being created, including the operating system (OS) version and package list.

        This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html#cfn-imagebuilder-image-enhancedimagemetadataenabled
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enhancedImageMetadataEnabled"))

    @enhanced_image_metadata_enabled.setter
    def enhanced_image_metadata_enabled(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enhancedImageMetadataEnabled", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="imageRecipeArn")
    def image_recipe_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the image recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html#cfn-imagebuilder-image-imagerecipearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "imageRecipeArn"))

    @image_recipe_arn.setter
    def image_recipe_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "imageRecipeArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="imageTestsConfiguration")
    def image_tests_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnImage.ImageTestsConfigurationProperty", _IResolvable_da3f097b]]:
        '''The configuration settings for your image test components, which includes a toggle that allows you to turn off tests, and a timeout setting.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html#cfn-imagebuilder-image-imagetestsconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnImage.ImageTestsConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "imageTestsConfiguration"))

    @image_tests_configuration.setter
    def image_tests_configuration(
        self,
        value: typing.Optional[typing.Union["CfnImage.ImageTestsConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "imageTestsConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImage.ImageTestsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "image_tests_enabled": "imageTestsEnabled",
            "timeout_minutes": "timeoutMinutes",
        },
    )
    class ImageTestsConfigurationProperty:
        def __init__(
            self,
            *,
            image_tests_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            timeout_minutes: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''When you create an image or container recipe with Image Builder , you can add the build or test components that are used to create the final image.

            You must have at least one build component to create a recipe, but test components are not required. If you have added tests, they run after the image is created, to ensure that the target image is functional and can be used reliably for launching Amazon EC2 instances.

            :param image_tests_enabled: Determines if tests should run after building the image. Image Builder defaults to enable tests to run following the image build, before image distribution.
            :param timeout_minutes: The maximum time in minutes that tests are permitted to run.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-image-imagetestsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                image_tests_configuration_property = imagebuilder.CfnImage.ImageTestsConfigurationProperty(
                    image_tests_enabled=False,
                    timeout_minutes=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if image_tests_enabled is not None:
                self._values["image_tests_enabled"] = image_tests_enabled
            if timeout_minutes is not None:
                self._values["timeout_minutes"] = timeout_minutes

        @builtins.property
        def image_tests_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Determines if tests should run after building the image.

            Image Builder defaults to enable tests to run following the image build, before image distribution.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-image-imagetestsconfiguration.html#cfn-imagebuilder-image-imagetestsconfiguration-imagetestsenabled
            '''
            result = self._values.get("image_tests_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def timeout_minutes(self) -> typing.Optional[jsii.Number]:
            '''The maximum time in minutes that tests are permitted to run.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-image-imagetestsconfiguration.html#cfn-imagebuilder-image-imagetestsconfiguration-timeoutminutes
            '''
            result = self._values.get("timeout_minutes")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ImageTestsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnImagePipeline(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImagePipeline",
):
    '''A CloudFormation ``AWS::ImageBuilder::ImagePipeline``.

    An image pipeline is the automation configuration for building secure OS images on AWS . The Image Builder image pipeline is associated with an image recipe that defines the build, validation, and test phases for an image build lifecycle. An image pipeline can be associated with an infrastructure configuration that defines where your image is built. You can define attributes, such as instance type, subnets, security groups, logging, and other infrastructure-related configurations. You can also associate your image pipeline with a distribution configuration to define how you would like to deploy your image.

    :cloudformationResource: AWS::ImageBuilder::ImagePipeline
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_imagebuilder as imagebuilder
        
        cfn_image_pipeline = imagebuilder.CfnImagePipeline(self, "MyCfnImagePipeline",
            infrastructure_configuration_arn="infrastructureConfigurationArn",
            name="name",
        
            # the properties below are optional
            container_recipe_arn="containerRecipeArn",
            description="description",
            distribution_configuration_arn="distributionConfigurationArn",
            enhanced_image_metadata_enabled=False,
            image_recipe_arn="imageRecipeArn",
            image_tests_configuration=imagebuilder.CfnImagePipeline.ImageTestsConfigurationProperty(
                image_tests_enabled=False,
                timeout_minutes=123
            ),
            schedule=imagebuilder.CfnImagePipeline.ScheduleProperty(
                pipeline_execution_start_condition="pipelineExecutionStartCondition",
                schedule_expression="scheduleExpression"
            ),
            status="status",
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
        infrastructure_configuration_arn: builtins.str,
        name: builtins.str,
        container_recipe_arn: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        distribution_configuration_arn: typing.Optional[builtins.str] = None,
        enhanced_image_metadata_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        image_recipe_arn: typing.Optional[builtins.str] = None,
        image_tests_configuration: typing.Optional[typing.Union["CfnImagePipeline.ImageTestsConfigurationProperty", _IResolvable_da3f097b]] = None,
        schedule: typing.Optional[typing.Union["CfnImagePipeline.ScheduleProperty", _IResolvable_da3f097b]] = None,
        status: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::ImageBuilder::ImagePipeline``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param infrastructure_configuration_arn: The Amazon Resource Name (ARN) of the infrastructure configuration associated with this image pipeline.
        :param name: The name of the image pipeline.
        :param container_recipe_arn: The Amazon Resource Name (ARN) of the container recipe that is used for this pipeline.
        :param description: The description of this image pipeline.
        :param distribution_configuration_arn: The Amazon Resource Name (ARN) of the distribution configuration associated with this image pipeline.
        :param enhanced_image_metadata_enabled: Collects additional information about the image being created, including the operating system (OS) version and package list. This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.
        :param image_recipe_arn: The Amazon Resource Name (ARN) of the image recipe associated with this image pipeline.
        :param image_tests_configuration: The configuration of the image tests that run after image creation to ensure the quality of the image that was created.
        :param schedule: The schedule of the image pipeline. A schedule configures how often and when a pipeline automatically creates a new image.
        :param status: The status of the image pipeline.
        :param tags: The tags of this image pipeline.
        '''
        props = CfnImagePipelineProps(
            infrastructure_configuration_arn=infrastructure_configuration_arn,
            name=name,
            container_recipe_arn=container_recipe_arn,
            description=description,
            distribution_configuration_arn=distribution_configuration_arn,
            enhanced_image_metadata_enabled=enhanced_image_metadata_enabled,
            image_recipe_arn=image_recipe_arn,
            image_tests_configuration=image_tests_configuration,
            schedule=schedule,
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
        '''Returns the Amazon Resource Name (ARN) of the image pipeline.

        For example, ``arn:aws:imagebuilder:us-west-2:123456789012:image-pipeline/mywindows2016pipeline`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''Returns the name of the image pipeline.

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
        '''The tags of this image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="infrastructureConfigurationArn")
    def infrastructure_configuration_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the infrastructure configuration associated with this image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-infrastructureconfigurationarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "infrastructureConfigurationArn"))

    @infrastructure_configuration_arn.setter
    def infrastructure_configuration_arn(self, value: builtins.str) -> None:
        jsii.set(self, "infrastructureConfigurationArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="containerRecipeArn")
    def container_recipe_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the container recipe that is used for this pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-containerrecipearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "containerRecipeArn"))

    @container_recipe_arn.setter
    def container_recipe_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "containerRecipeArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of this image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="distributionConfigurationArn")
    def distribution_configuration_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the distribution configuration associated with this image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-distributionconfigurationarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "distributionConfigurationArn"))

    @distribution_configuration_arn.setter
    def distribution_configuration_arn(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "distributionConfigurationArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enhancedImageMetadataEnabled")
    def enhanced_image_metadata_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Collects additional information about the image being created, including the operating system (OS) version and package list.

        This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-enhancedimagemetadataenabled
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enhancedImageMetadataEnabled"))

    @enhanced_image_metadata_enabled.setter
    def enhanced_image_metadata_enabled(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enhancedImageMetadataEnabled", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="imageRecipeArn")
    def image_recipe_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the image recipe associated with this image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-imagerecipearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "imageRecipeArn"))

    @image_recipe_arn.setter
    def image_recipe_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "imageRecipeArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="imageTestsConfiguration")
    def image_tests_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnImagePipeline.ImageTestsConfigurationProperty", _IResolvable_da3f097b]]:
        '''The configuration of the image tests that run after image creation to ensure the quality of the image that was created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-imagetestsconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnImagePipeline.ImageTestsConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "imageTestsConfiguration"))

    @image_tests_configuration.setter
    def image_tests_configuration(
        self,
        value: typing.Optional[typing.Union["CfnImagePipeline.ImageTestsConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "imageTestsConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="schedule")
    def schedule(
        self,
    ) -> typing.Optional[typing.Union["CfnImagePipeline.ScheduleProperty", _IResolvable_da3f097b]]:
        '''The schedule of the image pipeline.

        A schedule configures how often and when a pipeline automatically creates a new image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-schedule
        '''
        return typing.cast(typing.Optional[typing.Union["CfnImagePipeline.ScheduleProperty", _IResolvable_da3f097b]], jsii.get(self, "schedule"))

    @schedule.setter
    def schedule(
        self,
        value: typing.Optional[typing.Union["CfnImagePipeline.ScheduleProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "schedule", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="status")
    def status(self) -> typing.Optional[builtins.str]:
        '''The status of the image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-status
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "status"))

    @status.setter
    def status(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "status", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImagePipeline.ImageTestsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "image_tests_enabled": "imageTestsEnabled",
            "timeout_minutes": "timeoutMinutes",
        },
    )
    class ImageTestsConfigurationProperty:
        def __init__(
            self,
            *,
            image_tests_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            timeout_minutes: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''When you create an image or container recipe with Image Builder , you can add the build or test components that your image pipeline uses to create the final image.

            You must have at least one build component to create a recipe, but test components are not required. Your pipeline runs tests after it builds the image, to ensure that the target image is functional and can be used reliably for launching Amazon EC2 instances.

            :param image_tests_enabled: Defines if tests should be executed when building this image. For example, ``true`` or ``false`` .
            :param timeout_minutes: The maximum time in minutes that tests are permitted to run.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagepipeline-imagetestsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                image_tests_configuration_property = imagebuilder.CfnImagePipeline.ImageTestsConfigurationProperty(
                    image_tests_enabled=False,
                    timeout_minutes=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if image_tests_enabled is not None:
                self._values["image_tests_enabled"] = image_tests_enabled
            if timeout_minutes is not None:
                self._values["timeout_minutes"] = timeout_minutes

        @builtins.property
        def image_tests_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Defines if tests should be executed when building this image.

            For example, ``true`` or ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagepipeline-imagetestsconfiguration.html#cfn-imagebuilder-imagepipeline-imagetestsconfiguration-imagetestsenabled
            '''
            result = self._values.get("image_tests_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def timeout_minutes(self) -> typing.Optional[jsii.Number]:
            '''The maximum time in minutes that tests are permitted to run.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagepipeline-imagetestsconfiguration.html#cfn-imagebuilder-imagepipeline-imagetestsconfiguration-timeoutminutes
            '''
            result = self._values.get("timeout_minutes")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ImageTestsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImagePipeline.ScheduleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "pipeline_execution_start_condition": "pipelineExecutionStartCondition",
            "schedule_expression": "scheduleExpression",
        },
    )
    class ScheduleProperty:
        def __init__(
            self,
            *,
            pipeline_execution_start_condition: typing.Optional[builtins.str] = None,
            schedule_expression: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A schedule configures how often and when a pipeline will automatically create a new image.

            :param pipeline_execution_start_condition: The condition configures when the pipeline should trigger a new image build. When the ``pipelineExecutionStartCondition`` is set to ``EXPRESSION_MATCH_AND_DEPENDENCY_UPDATES_AVAILABLE`` , and you use semantic version filters on the source image or components in your image recipe, Image Builder will build a new image only when there are new versions of the image or components in your recipe that match the semantic version filter. When it is set to ``EXPRESSION_MATCH_ONLY`` , it will build a new image every time the CRON expression matches the current time. For semantic version syntax, see `CreateComponent <https://docs.aws.amazon.com/imagebuilder/latest/APIReference/API_CreateComponent.html>`_ in the *Image Builder API Reference* .
            :param schedule_expression: The cron expression determines how often EC2 Image Builder evaluates your ``pipelineExecutionStartCondition`` . For information on how to format a cron expression in Image Builder, see `Use cron expressions in EC2 Image Builder <https://docs.aws.amazon.com/imagebuilder/latest/userguide/image-builder-cron.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagepipeline-schedule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                schedule_property = imagebuilder.CfnImagePipeline.ScheduleProperty(
                    pipeline_execution_start_condition="pipelineExecutionStartCondition",
                    schedule_expression="scheduleExpression"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if pipeline_execution_start_condition is not None:
                self._values["pipeline_execution_start_condition"] = pipeline_execution_start_condition
            if schedule_expression is not None:
                self._values["schedule_expression"] = schedule_expression

        @builtins.property
        def pipeline_execution_start_condition(self) -> typing.Optional[builtins.str]:
            '''The condition configures when the pipeline should trigger a new image build.

            When the ``pipelineExecutionStartCondition`` is set to ``EXPRESSION_MATCH_AND_DEPENDENCY_UPDATES_AVAILABLE`` , and you use semantic version filters on the source image or components in your image recipe, Image Builder will build a new image only when there are new versions of the image or components in your recipe that match the semantic version filter. When it is set to ``EXPRESSION_MATCH_ONLY`` , it will build a new image every time the CRON expression matches the current time. For semantic version syntax, see `CreateComponent <https://docs.aws.amazon.com/imagebuilder/latest/APIReference/API_CreateComponent.html>`_ in the *Image Builder API Reference* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagepipeline-schedule.html#cfn-imagebuilder-imagepipeline-schedule-pipelineexecutionstartcondition
            '''
            result = self._values.get("pipeline_execution_start_condition")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def schedule_expression(self) -> typing.Optional[builtins.str]:
            '''The cron expression determines how often EC2 Image Builder evaluates your ``pipelineExecutionStartCondition`` .

            For information on how to format a cron expression in Image Builder, see `Use cron expressions in EC2 Image Builder <https://docs.aws.amazon.com/imagebuilder/latest/userguide/image-builder-cron.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagepipeline-schedule.html#cfn-imagebuilder-imagepipeline-schedule-scheduleexpression
            '''
            result = self._values.get("schedule_expression")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScheduleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImagePipelineProps",
    jsii_struct_bases=[],
    name_mapping={
        "infrastructure_configuration_arn": "infrastructureConfigurationArn",
        "name": "name",
        "container_recipe_arn": "containerRecipeArn",
        "description": "description",
        "distribution_configuration_arn": "distributionConfigurationArn",
        "enhanced_image_metadata_enabled": "enhancedImageMetadataEnabled",
        "image_recipe_arn": "imageRecipeArn",
        "image_tests_configuration": "imageTestsConfiguration",
        "schedule": "schedule",
        "status": "status",
        "tags": "tags",
    },
)
class CfnImagePipelineProps:
    def __init__(
        self,
        *,
        infrastructure_configuration_arn: builtins.str,
        name: builtins.str,
        container_recipe_arn: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        distribution_configuration_arn: typing.Optional[builtins.str] = None,
        enhanced_image_metadata_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        image_recipe_arn: typing.Optional[builtins.str] = None,
        image_tests_configuration: typing.Optional[typing.Union[CfnImagePipeline.ImageTestsConfigurationProperty, _IResolvable_da3f097b]] = None,
        schedule: typing.Optional[typing.Union[CfnImagePipeline.ScheduleProperty, _IResolvable_da3f097b]] = None,
        status: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnImagePipeline``.

        :param infrastructure_configuration_arn: The Amazon Resource Name (ARN) of the infrastructure configuration associated with this image pipeline.
        :param name: The name of the image pipeline.
        :param container_recipe_arn: The Amazon Resource Name (ARN) of the container recipe that is used for this pipeline.
        :param description: The description of this image pipeline.
        :param distribution_configuration_arn: The Amazon Resource Name (ARN) of the distribution configuration associated with this image pipeline.
        :param enhanced_image_metadata_enabled: Collects additional information about the image being created, including the operating system (OS) version and package list. This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.
        :param image_recipe_arn: The Amazon Resource Name (ARN) of the image recipe associated with this image pipeline.
        :param image_tests_configuration: The configuration of the image tests that run after image creation to ensure the quality of the image that was created.
        :param schedule: The schedule of the image pipeline. A schedule configures how often and when a pipeline automatically creates a new image.
        :param status: The status of the image pipeline.
        :param tags: The tags of this image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_imagebuilder as imagebuilder
            
            cfn_image_pipeline_props = imagebuilder.CfnImagePipelineProps(
                infrastructure_configuration_arn="infrastructureConfigurationArn",
                name="name",
            
                # the properties below are optional
                container_recipe_arn="containerRecipeArn",
                description="description",
                distribution_configuration_arn="distributionConfigurationArn",
                enhanced_image_metadata_enabled=False,
                image_recipe_arn="imageRecipeArn",
                image_tests_configuration=imagebuilder.CfnImagePipeline.ImageTestsConfigurationProperty(
                    image_tests_enabled=False,
                    timeout_minutes=123
                ),
                schedule=imagebuilder.CfnImagePipeline.ScheduleProperty(
                    pipeline_execution_start_condition="pipelineExecutionStartCondition",
                    schedule_expression="scheduleExpression"
                ),
                status="status",
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "infrastructure_configuration_arn": infrastructure_configuration_arn,
            "name": name,
        }
        if container_recipe_arn is not None:
            self._values["container_recipe_arn"] = container_recipe_arn
        if description is not None:
            self._values["description"] = description
        if distribution_configuration_arn is not None:
            self._values["distribution_configuration_arn"] = distribution_configuration_arn
        if enhanced_image_metadata_enabled is not None:
            self._values["enhanced_image_metadata_enabled"] = enhanced_image_metadata_enabled
        if image_recipe_arn is not None:
            self._values["image_recipe_arn"] = image_recipe_arn
        if image_tests_configuration is not None:
            self._values["image_tests_configuration"] = image_tests_configuration
        if schedule is not None:
            self._values["schedule"] = schedule
        if status is not None:
            self._values["status"] = status
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def infrastructure_configuration_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the infrastructure configuration associated with this image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-infrastructureconfigurationarn
        '''
        result = self._values.get("infrastructure_configuration_arn")
        assert result is not None, "Required property 'infrastructure_configuration_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def container_recipe_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the container recipe that is used for this pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-containerrecipearn
        '''
        result = self._values.get("container_recipe_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of this image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def distribution_configuration_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the distribution configuration associated with this image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-distributionconfigurationarn
        '''
        result = self._values.get("distribution_configuration_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def enhanced_image_metadata_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Collects additional information about the image being created, including the operating system (OS) version and package list.

        This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-enhancedimagemetadataenabled
        '''
        result = self._values.get("enhanced_image_metadata_enabled")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def image_recipe_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the image recipe associated with this image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-imagerecipearn
        '''
        result = self._values.get("image_recipe_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def image_tests_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnImagePipeline.ImageTestsConfigurationProperty, _IResolvable_da3f097b]]:
        '''The configuration of the image tests that run after image creation to ensure the quality of the image that was created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-imagetestsconfiguration
        '''
        result = self._values.get("image_tests_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnImagePipeline.ImageTestsConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def schedule(
        self,
    ) -> typing.Optional[typing.Union[CfnImagePipeline.ScheduleProperty, _IResolvable_da3f097b]]:
        '''The schedule of the image pipeline.

        A schedule configures how often and when a pipeline automatically creates a new image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-schedule
        '''
        result = self._values.get("schedule")
        return typing.cast(typing.Optional[typing.Union[CfnImagePipeline.ScheduleProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def status(self) -> typing.Optional[builtins.str]:
        '''The status of the image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-status
        '''
        result = self._values.get("status")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''The tags of this image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagepipeline.html#cfn-imagebuilder-imagepipeline-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnImagePipelineProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImageProps",
    jsii_struct_bases=[],
    name_mapping={
        "infrastructure_configuration_arn": "infrastructureConfigurationArn",
        "container_recipe_arn": "containerRecipeArn",
        "distribution_configuration_arn": "distributionConfigurationArn",
        "enhanced_image_metadata_enabled": "enhancedImageMetadataEnabled",
        "image_recipe_arn": "imageRecipeArn",
        "image_tests_configuration": "imageTestsConfiguration",
        "tags": "tags",
    },
)
class CfnImageProps:
    def __init__(
        self,
        *,
        infrastructure_configuration_arn: builtins.str,
        container_recipe_arn: typing.Optional[builtins.str] = None,
        distribution_configuration_arn: typing.Optional[builtins.str] = None,
        enhanced_image_metadata_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        image_recipe_arn: typing.Optional[builtins.str] = None,
        image_tests_configuration: typing.Optional[typing.Union[CfnImage.ImageTestsConfigurationProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnImage``.

        :param infrastructure_configuration_arn: The Amazon Resource Name (ARN) of the infrastructure configuration associated with this image pipeline.
        :param container_recipe_arn: The Amazon Resource Name (ARN) of the container recipe that is used for this pipeline.
        :param distribution_configuration_arn: The Amazon Resource Name (ARN) of the distribution configuration.
        :param enhanced_image_metadata_enabled: Collects additional information about the image being created, including the operating system (OS) version and package list. This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.
        :param image_recipe_arn: The Amazon Resource Name (ARN) of the image recipe.
        :param image_tests_configuration: The configuration settings for your image test components, which includes a toggle that allows you to turn off tests, and a timeout setting.
        :param tags: The tags of the image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_imagebuilder as imagebuilder
            
            cfn_image_props = imagebuilder.CfnImageProps(
                infrastructure_configuration_arn="infrastructureConfigurationArn",
            
                # the properties below are optional
                container_recipe_arn="containerRecipeArn",
                distribution_configuration_arn="distributionConfigurationArn",
                enhanced_image_metadata_enabled=False,
                image_recipe_arn="imageRecipeArn",
                image_tests_configuration=imagebuilder.CfnImage.ImageTestsConfigurationProperty(
                    image_tests_enabled=False,
                    timeout_minutes=123
                ),
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "infrastructure_configuration_arn": infrastructure_configuration_arn,
        }
        if container_recipe_arn is not None:
            self._values["container_recipe_arn"] = container_recipe_arn
        if distribution_configuration_arn is not None:
            self._values["distribution_configuration_arn"] = distribution_configuration_arn
        if enhanced_image_metadata_enabled is not None:
            self._values["enhanced_image_metadata_enabled"] = enhanced_image_metadata_enabled
        if image_recipe_arn is not None:
            self._values["image_recipe_arn"] = image_recipe_arn
        if image_tests_configuration is not None:
            self._values["image_tests_configuration"] = image_tests_configuration
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def infrastructure_configuration_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the infrastructure configuration associated with this image pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html#cfn-imagebuilder-image-infrastructureconfigurationarn
        '''
        result = self._values.get("infrastructure_configuration_arn")
        assert result is not None, "Required property 'infrastructure_configuration_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def container_recipe_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the container recipe that is used for this pipeline.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html#cfn-imagebuilder-image-containerrecipearn
        '''
        result = self._values.get("container_recipe_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def distribution_configuration_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the distribution configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html#cfn-imagebuilder-image-distributionconfigurationarn
        '''
        result = self._values.get("distribution_configuration_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def enhanced_image_metadata_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Collects additional information about the image being created, including the operating system (OS) version and package list.

        This information is used to enhance the overall experience of using EC2 Image Builder. Enabled by default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html#cfn-imagebuilder-image-enhancedimagemetadataenabled
        '''
        result = self._values.get("enhanced_image_metadata_enabled")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def image_recipe_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the image recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html#cfn-imagebuilder-image-imagerecipearn
        '''
        result = self._values.get("image_recipe_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def image_tests_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnImage.ImageTestsConfigurationProperty, _IResolvable_da3f097b]]:
        '''The configuration settings for your image test components, which includes a toggle that allows you to turn off tests, and a timeout setting.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html#cfn-imagebuilder-image-imagetestsconfiguration
        '''
        result = self._values.get("image_tests_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnImage.ImageTestsConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''The tags of the image.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-image.html#cfn-imagebuilder-image-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnImageProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnImageRecipe(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImageRecipe",
):
    '''A CloudFormation ``AWS::ImageBuilder::ImageRecipe``.

    An Image Builder image recipe is a document that defines the source image and the components to be applied to the source image to produce the desired configuration for the output image. You can use an image recipe to duplicate builds. Image Builder image recipes can be shared, branched, and edited using the console wizard, the AWS CLI , or the API. You can use image recipes with your version control software to maintain shareable versioned image recipes.

    :cloudformationResource: AWS::ImageBuilder::ImageRecipe
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_imagebuilder as imagebuilder
        
        cfn_image_recipe = imagebuilder.CfnImageRecipe(self, "MyCfnImageRecipe",
            components=[imagebuilder.CfnImageRecipe.ComponentConfigurationProperty(
                component_arn="componentArn",
                parameters=[imagebuilder.CfnImageRecipe.ComponentParameterProperty(
                    name="name",
                    value=["value"]
                )]
            )],
            name="name",
            parent_image="parentImage",
            version="version",
        
            # the properties below are optional
            additional_instance_configuration=imagebuilder.CfnImageRecipe.AdditionalInstanceConfigurationProperty(
                systems_manager_agent=imagebuilder.CfnImageRecipe.SystemsManagerAgentProperty(
                    uninstall_after_build=False
                ),
                user_data_override="userDataOverride"
            ),
            block_device_mappings=[imagebuilder.CfnImageRecipe.InstanceBlockDeviceMappingProperty(
                device_name="deviceName",
                ebs=imagebuilder.CfnImageRecipe.EbsInstanceBlockDeviceSpecificationProperty(
                    delete_on_termination=False,
                    encrypted=False,
                    iops=123,
                    kms_key_id="kmsKeyId",
                    snapshot_id="snapshotId",
                    throughput=123,
                    volume_size=123,
                    volume_type="volumeType"
                ),
                no_device="noDevice",
                virtual_name="virtualName"
            )],
            description="description",
            tags={
                "tags_key": "tags"
            },
            working_directory="workingDirectory"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        components: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnImageRecipe.ComponentConfigurationProperty", _IResolvable_da3f097b]]],
        name: builtins.str,
        parent_image: builtins.str,
        version: builtins.str,
        additional_instance_configuration: typing.Optional[typing.Union["CfnImageRecipe.AdditionalInstanceConfigurationProperty", _IResolvable_da3f097b]] = None,
        block_device_mappings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnImageRecipe.InstanceBlockDeviceMappingProperty", _IResolvable_da3f097b]]]] = None,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        working_directory: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::ImageBuilder::ImageRecipe``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param components: The components of the image recipe. Components are orchestration documents that define a sequence of steps for downloading, installing, configuring, and testing software packages. They also define validation and security hardening steps. A component is defined using a YAML document format.
        :param name: The name of the image recipe.
        :param parent_image: The parent image of the image recipe. The string must be either an Image ARN (SemVers is ok) or an AMI ID.
        :param version: The semantic version of the image recipe.
        :param additional_instance_configuration: Before you create a new AMI, Image Builder launches temporary Amazon EC2 instances to build and test your image configuration. Instance configuration adds a layer of control over those instances. You can define settings and add scripts to run when an instance is launched from your AMI.
        :param block_device_mappings: The block device mappings to apply when creating images from this recipe.
        :param description: The description of the image recipe.
        :param tags: The tags of the image recipe.
        :param working_directory: The working directory to be used during build and test workflows.
        '''
        props = CfnImageRecipeProps(
            components=components,
            name=name,
            parent_image=parent_image,
            version=version,
            additional_instance_configuration=additional_instance_configuration,
            block_device_mappings=block_device_mappings,
            description=description,
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
        '''Returns the Amazon Resource Name (ARN) of the image recipe.

        For example, ``arn:aws:imagebuilder:us-east-1:123456789012:image-recipe/mybasicrecipe/2019.12.03`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the image recipe.

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
        '''The tags of the image recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="components")
    def components(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnImageRecipe.ComponentConfigurationProperty", _IResolvable_da3f097b]]]:
        '''The components of the image recipe.

        Components are orchestration documents that define a sequence of steps for downloading, installing, configuring, and testing software packages. They also define validation and security hardening steps. A component is defined using a YAML document format.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-components
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnImageRecipe.ComponentConfigurationProperty", _IResolvable_da3f097b]]], jsii.get(self, "components"))

    @components.setter
    def components(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnImageRecipe.ComponentConfigurationProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "components", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the image recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="parentImage")
    def parent_image(self) -> builtins.str:
        '''The parent image of the image recipe.

        The string must be either an Image ARN (SemVers is ok) or an AMI ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-parentimage
        '''
        return typing.cast(builtins.str, jsii.get(self, "parentImage"))

    @parent_image.setter
    def parent_image(self, value: builtins.str) -> None:
        jsii.set(self, "parentImage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="version")
    def version(self) -> builtins.str:
        '''The semantic version of the image recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-version
        '''
        return typing.cast(builtins.str, jsii.get(self, "version"))

    @version.setter
    def version(self, value: builtins.str) -> None:
        jsii.set(self, "version", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="additionalInstanceConfiguration")
    def additional_instance_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnImageRecipe.AdditionalInstanceConfigurationProperty", _IResolvable_da3f097b]]:
        '''Before you create a new AMI, Image Builder launches temporary Amazon EC2 instances to build and test your image configuration.

        Instance configuration adds a layer of control over those instances. You can define settings and add scripts to run when an instance is launched from your AMI.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-additionalinstanceconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnImageRecipe.AdditionalInstanceConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "additionalInstanceConfiguration"))

    @additional_instance_configuration.setter
    def additional_instance_configuration(
        self,
        value: typing.Optional[typing.Union["CfnImageRecipe.AdditionalInstanceConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "additionalInstanceConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="blockDeviceMappings")
    def block_device_mappings(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnImageRecipe.InstanceBlockDeviceMappingProperty", _IResolvable_da3f097b]]]]:
        '''The block device mappings to apply when creating images from this recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-blockdevicemappings
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnImageRecipe.InstanceBlockDeviceMappingProperty", _IResolvable_da3f097b]]]], jsii.get(self, "blockDeviceMappings"))

    @block_device_mappings.setter
    def block_device_mappings(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnImageRecipe.InstanceBlockDeviceMappingProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "blockDeviceMappings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the image recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="workingDirectory")
    def working_directory(self) -> typing.Optional[builtins.str]:
        '''The working directory to be used during build and test workflows.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-workingdirectory
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "workingDirectory"))

    @working_directory.setter
    def working_directory(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "workingDirectory", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImageRecipe.AdditionalInstanceConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "systems_manager_agent": "systemsManagerAgent",
            "user_data_override": "userDataOverride",
        },
    )
    class AdditionalInstanceConfigurationProperty:
        def __init__(
            self,
            *,
            systems_manager_agent: typing.Optional[typing.Union["CfnImageRecipe.SystemsManagerAgentProperty", _IResolvable_da3f097b]] = None,
            user_data_override: typing.Optional[builtins.str] = None,
        ) -> None:
            '''In addition to your infrastruction configuration, these settings provide an extra layer of control over your build instances.

            For instances where Image Builder installs the Systems Manager agent, you can choose whether to keep it for the AMI that you create. You can also specify commands to run on launch for all of your build instances.

            :param systems_manager_agent: Contains settings for the Systems Manager agent on your build instance.
            :param user_data_override: Use this property to provide commands or a command script to run when you launch your build instance. The userDataOverride property replaces any commands that Image Builder might have added to ensure that Systems Manager is installed on your Linux build instance. If you override the user data, make sure that you add commands to install Systems Manager, if it is not pre-installed on your base image. .. epigraph:: The user data is always base 64 encoded. For example, the following commands are encoded as ``IyEvYmluL2Jhc2gKbWtkaXIgLXAgL3Zhci9iYi8KdG91Y2ggL3Zhci$`` : *#!/bin/bash* mkdir -p /var/bb/ touch /var

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-additionalinstanceconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                additional_instance_configuration_property = imagebuilder.CfnImageRecipe.AdditionalInstanceConfigurationProperty(
                    systems_manager_agent=imagebuilder.CfnImageRecipe.SystemsManagerAgentProperty(
                        uninstall_after_build=False
                    ),
                    user_data_override="userDataOverride"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if systems_manager_agent is not None:
                self._values["systems_manager_agent"] = systems_manager_agent
            if user_data_override is not None:
                self._values["user_data_override"] = user_data_override

        @builtins.property
        def systems_manager_agent(
            self,
        ) -> typing.Optional[typing.Union["CfnImageRecipe.SystemsManagerAgentProperty", _IResolvable_da3f097b]]:
            '''Contains settings for the Systems Manager agent on your build instance.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-additionalinstanceconfiguration.html#cfn-imagebuilder-imagerecipe-additionalinstanceconfiguration-systemsmanageragent
            '''
            result = self._values.get("systems_manager_agent")
            return typing.cast(typing.Optional[typing.Union["CfnImageRecipe.SystemsManagerAgentProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def user_data_override(self) -> typing.Optional[builtins.str]:
            '''Use this property to provide commands or a command script to run when you launch your build instance.

            The userDataOverride property replaces any commands that Image Builder might have added to ensure that Systems Manager is installed on your Linux build instance. If you override the user data, make sure that you add commands to install Systems Manager, if it is not pre-installed on your base image.
            .. epigraph::

               The user data is always base 64 encoded. For example, the following commands are encoded as ``IyEvYmluL2Jhc2gKbWtkaXIgLXAgL3Zhci9iYi8KdG91Y2ggL3Zhci$`` :

               *#!/bin/bash*

               mkdir -p /var/bb/

               touch /var

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-additionalinstanceconfiguration.html#cfn-imagebuilder-imagerecipe-additionalinstanceconfiguration-userdataoverride
            '''
            result = self._values.get("user_data_override")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AdditionalInstanceConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImageRecipe.ComponentConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"component_arn": "componentArn", "parameters": "parameters"},
    )
    class ComponentConfigurationProperty:
        def __init__(
            self,
            *,
            component_arn: typing.Optional[builtins.str] = None,
            parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnImageRecipe.ComponentParameterProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Configuration details of the component.

            :param component_arn: The Amazon Resource Name (ARN) of the component.
            :param parameters: A group of parameter settings that are used to configure the component for a specific recipe.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-componentconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                component_configuration_property = imagebuilder.CfnImageRecipe.ComponentConfigurationProperty(
                    component_arn="componentArn",
                    parameters=[imagebuilder.CfnImageRecipe.ComponentParameterProperty(
                        name="name",
                        value=["value"]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if component_arn is not None:
                self._values["component_arn"] = component_arn
            if parameters is not None:
                self._values["parameters"] = parameters

        @builtins.property
        def component_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the component.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-componentconfiguration.html#cfn-imagebuilder-imagerecipe-componentconfiguration-componentarn
            '''
            result = self._values.get("component_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnImageRecipe.ComponentParameterProperty", _IResolvable_da3f097b]]]]:
            '''A group of parameter settings that are used to configure the component for a specific recipe.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-componentconfiguration.html#cfn-imagebuilder-imagerecipe-componentconfiguration-parameters
            '''
            result = self._values.get("parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnImageRecipe.ComponentParameterProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComponentConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImageRecipe.ComponentParameterProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "value": "value"},
    )
    class ComponentParameterProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            value: typing.Sequence[builtins.str],
        ) -> None:
            '''Contains a key/value pair that sets the named component parameter.

            :param name: The name of the component parameter to set.
            :param value: Sets the value for the named component parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-componentparameter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                component_parameter_property = imagebuilder.CfnImageRecipe.ComponentParameterProperty(
                    name="name",
                    value=["value"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "value": value,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the component parameter to set.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-componentparameter.html#cfn-imagebuilder-imagerecipe-componentparameter-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> typing.List[builtins.str]:
            '''Sets the value for the named component parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-componentparameter.html#cfn-imagebuilder-imagerecipe-componentparameter-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(typing.List[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComponentParameterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImageRecipe.EbsInstanceBlockDeviceSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "delete_on_termination": "deleteOnTermination",
            "encrypted": "encrypted",
            "iops": "iops",
            "kms_key_id": "kmsKeyId",
            "snapshot_id": "snapshotId",
            "throughput": "throughput",
            "volume_size": "volumeSize",
            "volume_type": "volumeType",
        },
    )
    class EbsInstanceBlockDeviceSpecificationProperty:
        def __init__(
            self,
            *,
            delete_on_termination: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            encrypted: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            iops: typing.Optional[jsii.Number] = None,
            kms_key_id: typing.Optional[builtins.str] = None,
            snapshot_id: typing.Optional[builtins.str] = None,
            throughput: typing.Optional[jsii.Number] = None,
            volume_size: typing.Optional[jsii.Number] = None,
            volume_type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The image recipe EBS instance block device specification includes the Amazon EBS-specific block device mapping specifications for the image.

            :param delete_on_termination: Configures delete on termination of the associated device.
            :param encrypted: Use to configure device encryption.
            :param iops: Use to configure device IOPS.
            :param kms_key_id: Use to configure the KMS key to use when encrypting the device.
            :param snapshot_id: The snapshot that defines the device contents.
            :param throughput: *For GP3 volumes only* – The throughput in MiB/s that the volume supports.
            :param volume_size: Overrides the volume size of the device.
            :param volume_type: Overrides the volume type of the device.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                ebs_instance_block_device_specification_property = imagebuilder.CfnImageRecipe.EbsInstanceBlockDeviceSpecificationProperty(
                    delete_on_termination=False,
                    encrypted=False,
                    iops=123,
                    kms_key_id="kmsKeyId",
                    snapshot_id="snapshotId",
                    throughput=123,
                    volume_size=123,
                    volume_type="volumeType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if delete_on_termination is not None:
                self._values["delete_on_termination"] = delete_on_termination
            if encrypted is not None:
                self._values["encrypted"] = encrypted
            if iops is not None:
                self._values["iops"] = iops
            if kms_key_id is not None:
                self._values["kms_key_id"] = kms_key_id
            if snapshot_id is not None:
                self._values["snapshot_id"] = snapshot_id
            if throughput is not None:
                self._values["throughput"] = throughput
            if volume_size is not None:
                self._values["volume_size"] = volume_size
            if volume_type is not None:
                self._values["volume_type"] = volume_type

        @builtins.property
        def delete_on_termination(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Configures delete on termination of the associated device.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification-deleteontermination
            '''
            result = self._values.get("delete_on_termination")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def encrypted(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Use to configure device encryption.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification-encrypted
            '''
            result = self._values.get("encrypted")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def iops(self) -> typing.Optional[jsii.Number]:
            '''Use to configure device IOPS.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification-iops
            '''
            result = self._values.get("iops")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def kms_key_id(self) -> typing.Optional[builtins.str]:
            '''Use to configure the KMS key to use when encrypting the device.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification-kmskeyid
            '''
            result = self._values.get("kms_key_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def snapshot_id(self) -> typing.Optional[builtins.str]:
            '''The snapshot that defines the device contents.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification-snapshotid
            '''
            result = self._values.get("snapshot_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def throughput(self) -> typing.Optional[jsii.Number]:
            '''*For GP3 volumes only* – The throughput in MiB/s that the volume supports.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification-throughput
            '''
            result = self._values.get("throughput")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def volume_size(self) -> typing.Optional[jsii.Number]:
            '''Overrides the volume size of the device.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification-volumesize
            '''
            result = self._values.get("volume_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def volume_type(self) -> typing.Optional[builtins.str]:
            '''Overrides the volume type of the device.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification.html#cfn-imagebuilder-imagerecipe-ebsinstanceblockdevicespecification-volumetype
            '''
            result = self._values.get("volume_type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EbsInstanceBlockDeviceSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImageRecipe.InstanceBlockDeviceMappingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "device_name": "deviceName",
            "ebs": "ebs",
            "no_device": "noDevice",
            "virtual_name": "virtualName",
        },
    )
    class InstanceBlockDeviceMappingProperty:
        def __init__(
            self,
            *,
            device_name: typing.Optional[builtins.str] = None,
            ebs: typing.Optional[typing.Union["CfnImageRecipe.EbsInstanceBlockDeviceSpecificationProperty", _IResolvable_da3f097b]] = None,
            no_device: typing.Optional[builtins.str] = None,
            virtual_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Defines block device mappings for the instance used to configure your image.

            :param device_name: The device to which these mappings apply.
            :param ebs: Use to manage Amazon EBS-specific configuration for this mapping.
            :param no_device: Enter an empty string to remove a mapping from the parent image. The following is an example of an empty string value in the ``NoDevice`` field. ``NoDevice:""``
            :param virtual_name: Manages the instance ephemeral devices.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-instanceblockdevicemapping.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                instance_block_device_mapping_property = imagebuilder.CfnImageRecipe.InstanceBlockDeviceMappingProperty(
                    device_name="deviceName",
                    ebs=imagebuilder.CfnImageRecipe.EbsInstanceBlockDeviceSpecificationProperty(
                        delete_on_termination=False,
                        encrypted=False,
                        iops=123,
                        kms_key_id="kmsKeyId",
                        snapshot_id="snapshotId",
                        throughput=123,
                        volume_size=123,
                        volume_type="volumeType"
                    ),
                    no_device="noDevice",
                    virtual_name="virtualName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if device_name is not None:
                self._values["device_name"] = device_name
            if ebs is not None:
                self._values["ebs"] = ebs
            if no_device is not None:
                self._values["no_device"] = no_device
            if virtual_name is not None:
                self._values["virtual_name"] = virtual_name

        @builtins.property
        def device_name(self) -> typing.Optional[builtins.str]:
            '''The device to which these mappings apply.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-instanceblockdevicemapping.html#cfn-imagebuilder-imagerecipe-instanceblockdevicemapping-devicename
            '''
            result = self._values.get("device_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ebs(
            self,
        ) -> typing.Optional[typing.Union["CfnImageRecipe.EbsInstanceBlockDeviceSpecificationProperty", _IResolvable_da3f097b]]:
            '''Use to manage Amazon EBS-specific configuration for this mapping.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-instanceblockdevicemapping.html#cfn-imagebuilder-imagerecipe-instanceblockdevicemapping-ebs
            '''
            result = self._values.get("ebs")
            return typing.cast(typing.Optional[typing.Union["CfnImageRecipe.EbsInstanceBlockDeviceSpecificationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def no_device(self) -> typing.Optional[builtins.str]:
            '''Enter an empty string to remove a mapping from the parent image.

            The following is an example of an empty string value in the ``NoDevice`` field.

            ``NoDevice:""``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-instanceblockdevicemapping.html#cfn-imagebuilder-imagerecipe-instanceblockdevicemapping-nodevice
            '''
            result = self._values.get("no_device")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def virtual_name(self) -> typing.Optional[builtins.str]:
            '''Manages the instance ephemeral devices.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-instanceblockdevicemapping.html#cfn-imagebuilder-imagerecipe-instanceblockdevicemapping-virtualname
            '''
            result = self._values.get("virtual_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InstanceBlockDeviceMappingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImageRecipe.SystemsManagerAgentProperty",
        jsii_struct_bases=[],
        name_mapping={"uninstall_after_build": "uninstallAfterBuild"},
    )
    class SystemsManagerAgentProperty:
        def __init__(
            self,
            *,
            uninstall_after_build: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Contains settings for the Systems Manager agent on your build instance.

            :param uninstall_after_build: Controls whether the Systems Manager agent is removed from your final build image, prior to creating the new AMI. If this is set to true, then the agent is removed from the final image. If it's set to false, then the agent is left in, so that it is included in the new AMI. The default value is false.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-systemsmanageragent.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                systems_manager_agent_property = imagebuilder.CfnImageRecipe.SystemsManagerAgentProperty(
                    uninstall_after_build=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if uninstall_after_build is not None:
                self._values["uninstall_after_build"] = uninstall_after_build

        @builtins.property
        def uninstall_after_build(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Controls whether the Systems Manager agent is removed from your final build image, prior to creating the new AMI.

            If this is set to true, then the agent is removed from the final image. If it's set to false, then the agent is left in, so that it is included in the new AMI. The default value is false.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-imagerecipe-systemsmanageragent.html#cfn-imagebuilder-imagerecipe-systemsmanageragent-uninstallafterbuild
            '''
            result = self._values.get("uninstall_after_build")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SystemsManagerAgentProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_imagebuilder.CfnImageRecipeProps",
    jsii_struct_bases=[],
    name_mapping={
        "components": "components",
        "name": "name",
        "parent_image": "parentImage",
        "version": "version",
        "additional_instance_configuration": "additionalInstanceConfiguration",
        "block_device_mappings": "blockDeviceMappings",
        "description": "description",
        "tags": "tags",
        "working_directory": "workingDirectory",
    },
)
class CfnImageRecipeProps:
    def __init__(
        self,
        *,
        components: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnImageRecipe.ComponentConfigurationProperty, _IResolvable_da3f097b]]],
        name: builtins.str,
        parent_image: builtins.str,
        version: builtins.str,
        additional_instance_configuration: typing.Optional[typing.Union[CfnImageRecipe.AdditionalInstanceConfigurationProperty, _IResolvable_da3f097b]] = None,
        block_device_mappings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnImageRecipe.InstanceBlockDeviceMappingProperty, _IResolvable_da3f097b]]]] = None,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        working_directory: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnImageRecipe``.

        :param components: The components of the image recipe. Components are orchestration documents that define a sequence of steps for downloading, installing, configuring, and testing software packages. They also define validation and security hardening steps. A component is defined using a YAML document format.
        :param name: The name of the image recipe.
        :param parent_image: The parent image of the image recipe. The string must be either an Image ARN (SemVers is ok) or an AMI ID.
        :param version: The semantic version of the image recipe.
        :param additional_instance_configuration: Before you create a new AMI, Image Builder launches temporary Amazon EC2 instances to build and test your image configuration. Instance configuration adds a layer of control over those instances. You can define settings and add scripts to run when an instance is launched from your AMI.
        :param block_device_mappings: The block device mappings to apply when creating images from this recipe.
        :param description: The description of the image recipe.
        :param tags: The tags of the image recipe.
        :param working_directory: The working directory to be used during build and test workflows.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_imagebuilder as imagebuilder
            
            cfn_image_recipe_props = imagebuilder.CfnImageRecipeProps(
                components=[imagebuilder.CfnImageRecipe.ComponentConfigurationProperty(
                    component_arn="componentArn",
                    parameters=[imagebuilder.CfnImageRecipe.ComponentParameterProperty(
                        name="name",
                        value=["value"]
                    )]
                )],
                name="name",
                parent_image="parentImage",
                version="version",
            
                # the properties below are optional
                additional_instance_configuration=imagebuilder.CfnImageRecipe.AdditionalInstanceConfigurationProperty(
                    systems_manager_agent=imagebuilder.CfnImageRecipe.SystemsManagerAgentProperty(
                        uninstall_after_build=False
                    ),
                    user_data_override="userDataOverride"
                ),
                block_device_mappings=[imagebuilder.CfnImageRecipe.InstanceBlockDeviceMappingProperty(
                    device_name="deviceName",
                    ebs=imagebuilder.CfnImageRecipe.EbsInstanceBlockDeviceSpecificationProperty(
                        delete_on_termination=False,
                        encrypted=False,
                        iops=123,
                        kms_key_id="kmsKeyId",
                        snapshot_id="snapshotId",
                        throughput=123,
                        volume_size=123,
                        volume_type="volumeType"
                    ),
                    no_device="noDevice",
                    virtual_name="virtualName"
                )],
                description="description",
                tags={
                    "tags_key": "tags"
                },
                working_directory="workingDirectory"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "components": components,
            "name": name,
            "parent_image": parent_image,
            "version": version,
        }
        if additional_instance_configuration is not None:
            self._values["additional_instance_configuration"] = additional_instance_configuration
        if block_device_mappings is not None:
            self._values["block_device_mappings"] = block_device_mappings
        if description is not None:
            self._values["description"] = description
        if tags is not None:
            self._values["tags"] = tags
        if working_directory is not None:
            self._values["working_directory"] = working_directory

    @builtins.property
    def components(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnImageRecipe.ComponentConfigurationProperty, _IResolvable_da3f097b]]]:
        '''The components of the image recipe.

        Components are orchestration documents that define a sequence of steps for downloading, installing, configuring, and testing software packages. They also define validation and security hardening steps. A component is defined using a YAML document format.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-components
        '''
        result = self._values.get("components")
        assert result is not None, "Required property 'components' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnImageRecipe.ComponentConfigurationProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the image recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def parent_image(self) -> builtins.str:
        '''The parent image of the image recipe.

        The string must be either an Image ARN (SemVers is ok) or an AMI ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-parentimage
        '''
        result = self._values.get("parent_image")
        assert result is not None, "Required property 'parent_image' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def version(self) -> builtins.str:
        '''The semantic version of the image recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-version
        '''
        result = self._values.get("version")
        assert result is not None, "Required property 'version' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def additional_instance_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnImageRecipe.AdditionalInstanceConfigurationProperty, _IResolvable_da3f097b]]:
        '''Before you create a new AMI, Image Builder launches temporary Amazon EC2 instances to build and test your image configuration.

        Instance configuration adds a layer of control over those instances. You can define settings and add scripts to run when an instance is launched from your AMI.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-additionalinstanceconfiguration
        '''
        result = self._values.get("additional_instance_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnImageRecipe.AdditionalInstanceConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def block_device_mappings(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnImageRecipe.InstanceBlockDeviceMappingProperty, _IResolvable_da3f097b]]]]:
        '''The block device mappings to apply when creating images from this recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-blockdevicemappings
        '''
        result = self._values.get("block_device_mappings")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnImageRecipe.InstanceBlockDeviceMappingProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the image recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''The tags of the image recipe.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def working_directory(self) -> typing.Optional[builtins.str]:
        '''The working directory to be used during build and test workflows.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-imagerecipe.html#cfn-imagebuilder-imagerecipe-workingdirectory
        '''
        result = self._values.get("working_directory")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnImageRecipeProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnInfrastructureConfiguration(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_imagebuilder.CfnInfrastructureConfiguration",
):
    '''A CloudFormation ``AWS::ImageBuilder::InfrastructureConfiguration``.

    The infrastructure configuration allows you to specify the infrastructure within which to build and test your image. In the infrastructure configuration, you can specify instance types, subnets, and security groups to associate with your instance. You can also associate an Amazon EC2 key pair with the instance used to build your image. This allows you to log on to your instance to troubleshoot if your build fails and you set terminateInstanceOnFailure to false.

    :cloudformationResource: AWS::ImageBuilder::InfrastructureConfiguration
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_imagebuilder as imagebuilder
        
        cfn_infrastructure_configuration = imagebuilder.CfnInfrastructureConfiguration(self, "MyCfnInfrastructureConfiguration",
            instance_profile_name="instanceProfileName",
            name="name",
        
            # the properties below are optional
            description="description",
            instance_metadata_options=imagebuilder.CfnInfrastructureConfiguration.InstanceMetadataOptionsProperty(
                http_put_response_hop_limit=123,
                http_tokens="httpTokens"
            ),
            instance_types=["instanceTypes"],
            key_pair="keyPair",
            logging=imagebuilder.CfnInfrastructureConfiguration.LoggingProperty(
                s3_logs=imagebuilder.CfnInfrastructureConfiguration.S3LogsProperty(
                    s3_bucket_name="s3BucketName",
                    s3_key_prefix="s3KeyPrefix"
                )
            ),
            resource_tags={
                "resource_tags_key": "resourceTags"
            },
            security_group_ids=["securityGroupIds"],
            sns_topic_arn="snsTopicArn",
            subnet_id="subnetId",
            tags={
                "tags_key": "tags"
            },
            terminate_instance_on_failure=False
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        instance_profile_name: builtins.str,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        instance_metadata_options: typing.Optional[typing.Union["CfnInfrastructureConfiguration.InstanceMetadataOptionsProperty", _IResolvable_da3f097b]] = None,
        instance_types: typing.Optional[typing.Sequence[builtins.str]] = None,
        key_pair: typing.Optional[builtins.str] = None,
        logging: typing.Optional[typing.Union["CfnInfrastructureConfiguration.LoggingProperty", _IResolvable_da3f097b]] = None,
        resource_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
        security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        sns_topic_arn: typing.Optional[builtins.str] = None,
        subnet_id: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        terminate_instance_on_failure: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::ImageBuilder::InfrastructureConfiguration``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param instance_profile_name: The instance profile of the infrastructure configuration.
        :param name: The name of the infrastructure configuration.
        :param description: The description of the infrastructure configuration.
        :param instance_metadata_options: The instance metadata option settings for the infrastructure configuration.
        :param instance_types: The instance types of the infrastructure configuration.
        :param key_pair: The Amazon EC2 key pair of the infrastructure configuration.
        :param logging: The logging configuration defines where Image Builder uploads your logs.
        :param resource_tags: The tags attached to the resource created by Image Builder.
        :param security_group_ids: The security group IDs of the infrastructure configuration.
        :param sns_topic_arn: The Amazon Resource Name (ARN) of the SNS topic for the infrastructure configuration.
        :param subnet_id: The subnet ID of the infrastructure configuration.
        :param tags: The tags of the infrastructure configuration.
        :param terminate_instance_on_failure: The terminate instance on failure configuration of the infrastructure configuration.
        '''
        props = CfnInfrastructureConfigurationProps(
            instance_profile_name=instance_profile_name,
            name=name,
            description=description,
            instance_metadata_options=instance_metadata_options,
            instance_types=instance_types,
            key_pair=key_pair,
            logging=logging,
            resource_tags=resource_tags,
            security_group_ids=security_group_ids,
            sns_topic_arn=sns_topic_arn,
            subnet_id=subnet_id,
            tags=tags,
            terminate_instance_on_failure=terminate_instance_on_failure,
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
        '''Returns the Amazon Resource Name (ARN) of the infrastructure configuration.

        The following pattern is applied: ``^arn:aws[^:]*:imagebuilder:[^:]+:(?:\\d{12}|aws):(?:image-recipe|infrastructure-configuration|distribution-configuration|component|image|image-pipeline)/[a-z0-9-_]+(?:/(?:(?:x|\\d+)\\.(?:x|\\d+)\\.(?:x|\\d+))(?:/\\d+)?)?$`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the infrastructure configuration.

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
        '''The tags of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceProfileName")
    def instance_profile_name(self) -> builtins.str:
        '''The instance profile of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-instanceprofilename
        '''
        return typing.cast(builtins.str, jsii.get(self, "instanceProfileName"))

    @instance_profile_name.setter
    def instance_profile_name(self, value: builtins.str) -> None:
        jsii.set(self, "instanceProfileName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceMetadataOptions")
    def instance_metadata_options(
        self,
    ) -> typing.Optional[typing.Union["CfnInfrastructureConfiguration.InstanceMetadataOptionsProperty", _IResolvable_da3f097b]]:
        '''The instance metadata option settings for the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-instancemetadataoptions
        '''
        return typing.cast(typing.Optional[typing.Union["CfnInfrastructureConfiguration.InstanceMetadataOptionsProperty", _IResolvable_da3f097b]], jsii.get(self, "instanceMetadataOptions"))

    @instance_metadata_options.setter
    def instance_metadata_options(
        self,
        value: typing.Optional[typing.Union["CfnInfrastructureConfiguration.InstanceMetadataOptionsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "instanceMetadataOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceTypes")
    def instance_types(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The instance types of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-instancetypes
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "instanceTypes"))

    @instance_types.setter
    def instance_types(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "instanceTypes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="keyPair")
    def key_pair(self) -> typing.Optional[builtins.str]:
        '''The Amazon EC2 key pair of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-keypair
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "keyPair"))

    @key_pair.setter
    def key_pair(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "keyPair", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logging")
    def logging(
        self,
    ) -> typing.Optional[typing.Union["CfnInfrastructureConfiguration.LoggingProperty", _IResolvable_da3f097b]]:
        '''The logging configuration defines where Image Builder uploads your logs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-logging
        '''
        return typing.cast(typing.Optional[typing.Union["CfnInfrastructureConfiguration.LoggingProperty", _IResolvable_da3f097b]], jsii.get(self, "logging"))

    @logging.setter
    def logging(
        self,
        value: typing.Optional[typing.Union["CfnInfrastructureConfiguration.LoggingProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "logging", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resourceTags")
    def resource_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
        '''The tags attached to the resource created by Image Builder.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-resourcetags
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], jsii.get(self, "resourceTags"))

    @resource_tags.setter
    def resource_tags(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]],
    ) -> None:
        jsii.set(self, "resourceTags", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="securityGroupIds")
    def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The security group IDs of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-securitygroupids
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "securityGroupIds"))

    @security_group_ids.setter
    def security_group_ids(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "securityGroupIds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snsTopicArn")
    def sns_topic_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the SNS topic for the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-snstopicarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "snsTopicArn"))

    @sns_topic_arn.setter
    def sns_topic_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "snsTopicArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subnetId")
    def subnet_id(self) -> typing.Optional[builtins.str]:
        '''The subnet ID of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-subnetid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "subnetId"))

    @subnet_id.setter
    def subnet_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "subnetId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="terminateInstanceOnFailure")
    def terminate_instance_on_failure(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''The terminate instance on failure configuration of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-terminateinstanceonfailure
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "terminateInstanceOnFailure"))

    @terminate_instance_on_failure.setter
    def terminate_instance_on_failure(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "terminateInstanceOnFailure", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnInfrastructureConfiguration.InstanceMetadataOptionsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "http_put_response_hop_limit": "httpPutResponseHopLimit",
            "http_tokens": "httpTokens",
        },
    )
    class InstanceMetadataOptionsProperty:
        def __init__(
            self,
            *,
            http_put_response_hop_limit: typing.Optional[jsii.Number] = None,
            http_tokens: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The instance metadata options that apply to the HTTP requests that pipeline builds use to launch EC2 build and test instances.

            For more information about instance metadata options, see `Configure the instance metadata options <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html>`_ in the **Amazon EC2 User Guide** for Linux instances, or `Configure the instance metadata options <https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/configuring-instance-metadata-options.html>`_ in the **Amazon EC2 Windows Guide** for Windows instances.

            :param http_put_response_hop_limit: Limit the number of hops that an instance metadata request can traverse to reach its destination.
            :param http_tokens: Indicates whether a signed token header is required for instance metadata retrieval requests. The values affect the response as follows: - *required* – When you retrieve the IAM role credentials, version 2.0 credentials are returned in all cases. - *optional* – You can include a signed token header in your request to retrieve instance metadata, or you can leave it out. If you include it, version 2.0 credentials are returned for the IAM role. Otherwise, version 1.0 credentials are returned. The default setting is *optional* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-infrastructureconfiguration-instancemetadataoptions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                instance_metadata_options_property = imagebuilder.CfnInfrastructureConfiguration.InstanceMetadataOptionsProperty(
                    http_put_response_hop_limit=123,
                    http_tokens="httpTokens"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if http_put_response_hop_limit is not None:
                self._values["http_put_response_hop_limit"] = http_put_response_hop_limit
            if http_tokens is not None:
                self._values["http_tokens"] = http_tokens

        @builtins.property
        def http_put_response_hop_limit(self) -> typing.Optional[jsii.Number]:
            '''Limit the number of hops that an instance metadata request can traverse to reach its destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-infrastructureconfiguration-instancemetadataoptions.html#cfn-imagebuilder-infrastructureconfiguration-instancemetadataoptions-httpputresponsehoplimit
            '''
            result = self._values.get("http_put_response_hop_limit")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def http_tokens(self) -> typing.Optional[builtins.str]:
            '''Indicates whether a signed token header is required for instance metadata retrieval requests.

            The values affect the response as follows:

            - *required* – When you retrieve the IAM role credentials, version 2.0 credentials are returned in all cases.
            - *optional* – You can include a signed token header in your request to retrieve instance metadata, or you can leave it out. If you include it, version 2.0 credentials are returned for the IAM role. Otherwise, version 1.0 credentials are returned.

            The default setting is *optional* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-infrastructureconfiguration-instancemetadataoptions.html#cfn-imagebuilder-infrastructureconfiguration-instancemetadataoptions-httptokens
            '''
            result = self._values.get("http_tokens")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InstanceMetadataOptionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnInfrastructureConfiguration.LoggingProperty",
        jsii_struct_bases=[],
        name_mapping={"s3_logs": "s3Logs"},
    )
    class LoggingProperty:
        def __init__(
            self,
            *,
            s3_logs: typing.Optional[typing.Union["CfnInfrastructureConfiguration.S3LogsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Logging configuration defines where Image Builder uploads your logs.

            :param s3_logs: The Amazon S3 logging configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-infrastructureconfiguration-logging.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                logging_property = imagebuilder.CfnInfrastructureConfiguration.LoggingProperty(
                    s3_logs=imagebuilder.CfnInfrastructureConfiguration.S3LogsProperty(
                        s3_bucket_name="s3BucketName",
                        s3_key_prefix="s3KeyPrefix"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if s3_logs is not None:
                self._values["s3_logs"] = s3_logs

        @builtins.property
        def s3_logs(
            self,
        ) -> typing.Optional[typing.Union["CfnInfrastructureConfiguration.S3LogsProperty", _IResolvable_da3f097b]]:
            '''The Amazon S3 logging configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-infrastructureconfiguration-logging.html#cfn-imagebuilder-infrastructureconfiguration-logging-s3logs
            '''
            result = self._values.get("s3_logs")
            return typing.cast(typing.Optional[typing.Union["CfnInfrastructureConfiguration.S3LogsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoggingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_imagebuilder.CfnInfrastructureConfiguration.S3LogsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "s3_bucket_name": "s3BucketName",
            "s3_key_prefix": "s3KeyPrefix",
        },
    )
    class S3LogsProperty:
        def __init__(
            self,
            *,
            s3_bucket_name: typing.Optional[builtins.str] = None,
            s3_key_prefix: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Amazon S3 logging configuration.

            :param s3_bucket_name: The S3 bucket in which to store the logs.
            :param s3_key_prefix: The Amazon S3 path to the bucket where the logs are stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-infrastructureconfiguration-s3logs.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_imagebuilder as imagebuilder
                
                s3_logs_property = imagebuilder.CfnInfrastructureConfiguration.S3LogsProperty(
                    s3_bucket_name="s3BucketName",
                    s3_key_prefix="s3KeyPrefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if s3_bucket_name is not None:
                self._values["s3_bucket_name"] = s3_bucket_name
            if s3_key_prefix is not None:
                self._values["s3_key_prefix"] = s3_key_prefix

        @builtins.property
        def s3_bucket_name(self) -> typing.Optional[builtins.str]:
            '''The S3 bucket in which to store the logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-infrastructureconfiguration-s3logs.html#cfn-imagebuilder-infrastructureconfiguration-s3logs-s3bucketname
            '''
            result = self._values.get("s3_bucket_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def s3_key_prefix(self) -> typing.Optional[builtins.str]:
            '''The Amazon S3 path to the bucket where the logs are stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-imagebuilder-infrastructureconfiguration-s3logs.html#cfn-imagebuilder-infrastructureconfiguration-s3logs-s3keyprefix
            '''
            result = self._values.get("s3_key_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3LogsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_imagebuilder.CfnInfrastructureConfigurationProps",
    jsii_struct_bases=[],
    name_mapping={
        "instance_profile_name": "instanceProfileName",
        "name": "name",
        "description": "description",
        "instance_metadata_options": "instanceMetadataOptions",
        "instance_types": "instanceTypes",
        "key_pair": "keyPair",
        "logging": "logging",
        "resource_tags": "resourceTags",
        "security_group_ids": "securityGroupIds",
        "sns_topic_arn": "snsTopicArn",
        "subnet_id": "subnetId",
        "tags": "tags",
        "terminate_instance_on_failure": "terminateInstanceOnFailure",
    },
)
class CfnInfrastructureConfigurationProps:
    def __init__(
        self,
        *,
        instance_profile_name: builtins.str,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        instance_metadata_options: typing.Optional[typing.Union[CfnInfrastructureConfiguration.InstanceMetadataOptionsProperty, _IResolvable_da3f097b]] = None,
        instance_types: typing.Optional[typing.Sequence[builtins.str]] = None,
        key_pair: typing.Optional[builtins.str] = None,
        logging: typing.Optional[typing.Union[CfnInfrastructureConfiguration.LoggingProperty, _IResolvable_da3f097b]] = None,
        resource_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
        security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        sns_topic_arn: typing.Optional[builtins.str] = None,
        subnet_id: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        terminate_instance_on_failure: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnInfrastructureConfiguration``.

        :param instance_profile_name: The instance profile of the infrastructure configuration.
        :param name: The name of the infrastructure configuration.
        :param description: The description of the infrastructure configuration.
        :param instance_metadata_options: The instance metadata option settings for the infrastructure configuration.
        :param instance_types: The instance types of the infrastructure configuration.
        :param key_pair: The Amazon EC2 key pair of the infrastructure configuration.
        :param logging: The logging configuration defines where Image Builder uploads your logs.
        :param resource_tags: The tags attached to the resource created by Image Builder.
        :param security_group_ids: The security group IDs of the infrastructure configuration.
        :param sns_topic_arn: The Amazon Resource Name (ARN) of the SNS topic for the infrastructure configuration.
        :param subnet_id: The subnet ID of the infrastructure configuration.
        :param tags: The tags of the infrastructure configuration.
        :param terminate_instance_on_failure: The terminate instance on failure configuration of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_imagebuilder as imagebuilder
            
            cfn_infrastructure_configuration_props = imagebuilder.CfnInfrastructureConfigurationProps(
                instance_profile_name="instanceProfileName",
                name="name",
            
                # the properties below are optional
                description="description",
                instance_metadata_options=imagebuilder.CfnInfrastructureConfiguration.InstanceMetadataOptionsProperty(
                    http_put_response_hop_limit=123,
                    http_tokens="httpTokens"
                ),
                instance_types=["instanceTypes"],
                key_pair="keyPair",
                logging=imagebuilder.CfnInfrastructureConfiguration.LoggingProperty(
                    s3_logs=imagebuilder.CfnInfrastructureConfiguration.S3LogsProperty(
                        s3_bucket_name="s3BucketName",
                        s3_key_prefix="s3KeyPrefix"
                    )
                ),
                resource_tags={
                    "resource_tags_key": "resourceTags"
                },
                security_group_ids=["securityGroupIds"],
                sns_topic_arn="snsTopicArn",
                subnet_id="subnetId",
                tags={
                    "tags_key": "tags"
                },
                terminate_instance_on_failure=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "instance_profile_name": instance_profile_name,
            "name": name,
        }
        if description is not None:
            self._values["description"] = description
        if instance_metadata_options is not None:
            self._values["instance_metadata_options"] = instance_metadata_options
        if instance_types is not None:
            self._values["instance_types"] = instance_types
        if key_pair is not None:
            self._values["key_pair"] = key_pair
        if logging is not None:
            self._values["logging"] = logging
        if resource_tags is not None:
            self._values["resource_tags"] = resource_tags
        if security_group_ids is not None:
            self._values["security_group_ids"] = security_group_ids
        if sns_topic_arn is not None:
            self._values["sns_topic_arn"] = sns_topic_arn
        if subnet_id is not None:
            self._values["subnet_id"] = subnet_id
        if tags is not None:
            self._values["tags"] = tags
        if terminate_instance_on_failure is not None:
            self._values["terminate_instance_on_failure"] = terminate_instance_on_failure

    @builtins.property
    def instance_profile_name(self) -> builtins.str:
        '''The instance profile of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-instanceprofilename
        '''
        result = self._values.get("instance_profile_name")
        assert result is not None, "Required property 'instance_profile_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def instance_metadata_options(
        self,
    ) -> typing.Optional[typing.Union[CfnInfrastructureConfiguration.InstanceMetadataOptionsProperty, _IResolvable_da3f097b]]:
        '''The instance metadata option settings for the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-instancemetadataoptions
        '''
        result = self._values.get("instance_metadata_options")
        return typing.cast(typing.Optional[typing.Union[CfnInfrastructureConfiguration.InstanceMetadataOptionsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def instance_types(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The instance types of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-instancetypes
        '''
        result = self._values.get("instance_types")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def key_pair(self) -> typing.Optional[builtins.str]:
        '''The Amazon EC2 key pair of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-keypair
        '''
        result = self._values.get("key_pair")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def logging(
        self,
    ) -> typing.Optional[typing.Union[CfnInfrastructureConfiguration.LoggingProperty, _IResolvable_da3f097b]]:
        '''The logging configuration defines where Image Builder uploads your logs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-logging
        '''
        result = self._values.get("logging")
        return typing.cast(typing.Optional[typing.Union[CfnInfrastructureConfiguration.LoggingProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def resource_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
        '''The tags attached to the resource created by Image Builder.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-resourcetags
        '''
        result = self._values.get("resource_tags")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

    @builtins.property
    def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The security group IDs of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-securitygroupids
        '''
        result = self._values.get("security_group_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def sns_topic_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the SNS topic for the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-snstopicarn
        '''
        result = self._values.get("sns_topic_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def subnet_id(self) -> typing.Optional[builtins.str]:
        '''The subnet ID of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-subnetid
        '''
        result = self._values.get("subnet_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''The tags of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def terminate_instance_on_failure(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''The terminate instance on failure configuration of the infrastructure configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-imagebuilder-infrastructureconfiguration.html#cfn-imagebuilder-infrastructureconfiguration-terminateinstanceonfailure
        '''
        result = self._values.get("terminate_instance_on_failure")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnInfrastructureConfigurationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnComponent",
    "CfnComponentProps",
    "CfnContainerRecipe",
    "CfnContainerRecipeProps",
    "CfnDistributionConfiguration",
    "CfnDistributionConfigurationProps",
    "CfnImage",
    "CfnImagePipeline",
    "CfnImagePipelineProps",
    "CfnImageProps",
    "CfnImageRecipe",
    "CfnImageRecipeProps",
    "CfnInfrastructureConfiguration",
    "CfnInfrastructureConfigurationProps",
]

publication.publish()
