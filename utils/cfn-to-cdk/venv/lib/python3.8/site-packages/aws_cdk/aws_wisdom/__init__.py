'''
# AWS::Wisdom Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_wisdom as wisdom
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-wisdom-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::Wisdom](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_Wisdom.html).

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
class CfnAssistant(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_wisdom.CfnAssistant",
):
    '''A CloudFormation ``AWS::Wisdom::Assistant``.

    Specifies an Amazon Connect Wisdom assistant.

    :cloudformationResource: AWS::Wisdom::Assistant
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistant.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_wisdom as wisdom
        
        cfn_assistant = wisdom.CfnAssistant(self, "MyCfnAssistant",
            name="name",
            type="type",
        
            # the properties below are optional
            description="description",
            server_side_encryption_configuration=wisdom.CfnAssistant.ServerSideEncryptionConfigurationProperty(
                kms_key_id="kmsKeyId"
            ),
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
        type: builtins.str,
        description: typing.Optional[builtins.str] = None,
        server_side_encryption_configuration: typing.Optional[typing.Union["CfnAssistant.ServerSideEncryptionConfigurationProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Wisdom::Assistant``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the assistant.
        :param type: The type of assistant.
        :param description: The description of the assistant.
        :param server_side_encryption_configuration: The KMS key used for encryption.
        :param tags: The tags used to organize, track, or control access for this resource.
        '''
        props = CfnAssistantProps(
            name=name,
            type=type,
            description=description,
            server_side_encryption_configuration=server_side_encryption_configuration,
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
    @jsii.member(jsii_name="attrAssistantArn")
    def attr_assistant_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the assistant.

        :cloudformationAttribute: AssistantArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAssistantArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrAssistantId")
    def attr_assistant_id(self) -> builtins.str:
        '''The ID of the Wisdom assistant.

        :cloudformationAttribute: AssistantId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAssistantId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistant.html#cfn-wisdom-assistant-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the assistant.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistant.html#cfn-wisdom-assistant-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> builtins.str:
        '''The type of assistant.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistant.html#cfn-wisdom-assistant-type
        '''
        return typing.cast(builtins.str, jsii.get(self, "type"))

    @type.setter
    def type(self, value: builtins.str) -> None:
        jsii.set(self, "type", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the assistant.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistant.html#cfn-wisdom-assistant-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serverSideEncryptionConfiguration")
    def server_side_encryption_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnAssistant.ServerSideEncryptionConfigurationProperty", _IResolvable_da3f097b]]:
        '''The KMS key used for encryption.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistant.html#cfn-wisdom-assistant-serversideencryptionconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnAssistant.ServerSideEncryptionConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "serverSideEncryptionConfiguration"))

    @server_side_encryption_configuration.setter
    def server_side_encryption_configuration(
        self,
        value: typing.Optional[typing.Union["CfnAssistant.ServerSideEncryptionConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "serverSideEncryptionConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wisdom.CfnAssistant.ServerSideEncryptionConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"kms_key_id": "kmsKeyId"},
    )
    class ServerSideEncryptionConfigurationProperty:
        def __init__(self, *, kms_key_id: typing.Optional[builtins.str] = None) -> None:
            '''The KMS key used for encryption.

            :param kms_key_id: The KMS key . For information about valid ID values, see `Key identifiers (KeyId) <https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wisdom-assistant-serversideencryptionconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wisdom as wisdom
                
                server_side_encryption_configuration_property = wisdom.CfnAssistant.ServerSideEncryptionConfigurationProperty(
                    kms_key_id="kmsKeyId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if kms_key_id is not None:
                self._values["kms_key_id"] = kms_key_id

        @builtins.property
        def kms_key_id(self) -> typing.Optional[builtins.str]:
            '''The KMS key .

            For information about valid ID values, see `Key identifiers (KeyId) <https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wisdom-assistant-serversideencryptionconfiguration.html#cfn-wisdom-assistant-serversideencryptionconfiguration-kmskeyid
            '''
            result = self._values.get("kms_key_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ServerSideEncryptionConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnAssistantAssociation(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_wisdom.CfnAssistantAssociation",
):
    '''A CloudFormation ``AWS::Wisdom::AssistantAssociation``.

    Specifies an association between an Amazon Connect Wisdom assistant and another resource. Currently, the only supported association is with a knowledge base. An assistant can have only a single association.

    :cloudformationResource: AWS::Wisdom::AssistantAssociation
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistantassociation.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_wisdom as wisdom
        
        cfn_assistant_association = wisdom.CfnAssistantAssociation(self, "MyCfnAssistantAssociation",
            assistant_id="assistantId",
            association=wisdom.CfnAssistantAssociation.AssociationDataProperty(
                knowledge_base_id="knowledgeBaseId"
            ),
            association_type="associationType",
        
            # the properties below are optional
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
        assistant_id: builtins.str,
        association: typing.Union["CfnAssistantAssociation.AssociationDataProperty", _IResolvable_da3f097b],
        association_type: builtins.str,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Wisdom::AssistantAssociation``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param assistant_id: The identifier of the Wisdom assistant.
        :param association: The identifier of the associated resource.
        :param association_type: The type of association.
        :param tags: The tags used to organize, track, or control access for this resource.
        '''
        props = CfnAssistantAssociationProps(
            assistant_id=assistant_id,
            association=association,
            association_type=association_type,
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
    @jsii.member(jsii_name="attrAssistantArn")
    def attr_assistant_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the Wisdom assistant.

        :cloudformationAttribute: AssistantArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAssistantArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrAssistantAssociationArn")
    def attr_assistant_association_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the assistant association.

        :cloudformationAttribute: AssistantAssociationArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAssistantAssociationArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrAssistantAssociationId")
    def attr_assistant_association_id(self) -> builtins.str:
        '''The ID of the association.

        :cloudformationAttribute: AssistantAssociationId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAssistantAssociationId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistantassociation.html#cfn-wisdom-assistantassociation-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assistantId")
    def assistant_id(self) -> builtins.str:
        '''The identifier of the Wisdom assistant.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistantassociation.html#cfn-wisdom-assistantassociation-assistantid
        '''
        return typing.cast(builtins.str, jsii.get(self, "assistantId"))

    @assistant_id.setter
    def assistant_id(self, value: builtins.str) -> None:
        jsii.set(self, "assistantId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="association")
    def association(
        self,
    ) -> typing.Union["CfnAssistantAssociation.AssociationDataProperty", _IResolvable_da3f097b]:
        '''The identifier of the associated resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistantassociation.html#cfn-wisdom-assistantassociation-association
        '''
        return typing.cast(typing.Union["CfnAssistantAssociation.AssociationDataProperty", _IResolvable_da3f097b], jsii.get(self, "association"))

    @association.setter
    def association(
        self,
        value: typing.Union["CfnAssistantAssociation.AssociationDataProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "association", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="associationType")
    def association_type(self) -> builtins.str:
        '''The type of association.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistantassociation.html#cfn-wisdom-assistantassociation-associationtype
        '''
        return typing.cast(builtins.str, jsii.get(self, "associationType"))

    @association_type.setter
    def association_type(self, value: builtins.str) -> None:
        jsii.set(self, "associationType", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wisdom.CfnAssistantAssociation.AssociationDataProperty",
        jsii_struct_bases=[],
        name_mapping={"knowledge_base_id": "knowledgeBaseId"},
    )
    class AssociationDataProperty:
        def __init__(self, *, knowledge_base_id: builtins.str) -> None:
            '''A union type that currently has a single argument, which is the knowledge base ID.

            :param knowledge_base_id: The identifier of the knowledge base.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wisdom-assistantassociation-associationdata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wisdom as wisdom
                
                association_data_property = wisdom.CfnAssistantAssociation.AssociationDataProperty(
                    knowledge_base_id="knowledgeBaseId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "knowledge_base_id": knowledge_base_id,
            }

        @builtins.property
        def knowledge_base_id(self) -> builtins.str:
            '''The identifier of the knowledge base.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wisdom-assistantassociation-associationdata.html#cfn-wisdom-assistantassociation-associationdata-knowledgebaseid
            '''
            result = self._values.get("knowledge_base_id")
            assert result is not None, "Required property 'knowledge_base_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AssociationDataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_wisdom.CfnAssistantAssociationProps",
    jsii_struct_bases=[],
    name_mapping={
        "assistant_id": "assistantId",
        "association": "association",
        "association_type": "associationType",
        "tags": "tags",
    },
)
class CfnAssistantAssociationProps:
    def __init__(
        self,
        *,
        assistant_id: builtins.str,
        association: typing.Union[CfnAssistantAssociation.AssociationDataProperty, _IResolvable_da3f097b],
        association_type: builtins.str,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnAssistantAssociation``.

        :param assistant_id: The identifier of the Wisdom assistant.
        :param association: The identifier of the associated resource.
        :param association_type: The type of association.
        :param tags: The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistantassociation.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_wisdom as wisdom
            
            cfn_assistant_association_props = wisdom.CfnAssistantAssociationProps(
                assistant_id="assistantId",
                association=wisdom.CfnAssistantAssociation.AssociationDataProperty(
                    knowledge_base_id="knowledgeBaseId"
                ),
                association_type="associationType",
            
                # the properties below are optional
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "assistant_id": assistant_id,
            "association": association,
            "association_type": association_type,
        }
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def assistant_id(self) -> builtins.str:
        '''The identifier of the Wisdom assistant.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistantassociation.html#cfn-wisdom-assistantassociation-assistantid
        '''
        result = self._values.get("assistant_id")
        assert result is not None, "Required property 'assistant_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def association(
        self,
    ) -> typing.Union[CfnAssistantAssociation.AssociationDataProperty, _IResolvable_da3f097b]:
        '''The identifier of the associated resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistantassociation.html#cfn-wisdom-assistantassociation-association
        '''
        result = self._values.get("association")
        assert result is not None, "Required property 'association' is missing"
        return typing.cast(typing.Union[CfnAssistantAssociation.AssociationDataProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def association_type(self) -> builtins.str:
        '''The type of association.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistantassociation.html#cfn-wisdom-assistantassociation-associationtype
        '''
        result = self._values.get("association_type")
        assert result is not None, "Required property 'association_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistantassociation.html#cfn-wisdom-assistantassociation-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAssistantAssociationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_wisdom.CfnAssistantProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "type": "type",
        "description": "description",
        "server_side_encryption_configuration": "serverSideEncryptionConfiguration",
        "tags": "tags",
    },
)
class CfnAssistantProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        type: builtins.str,
        description: typing.Optional[builtins.str] = None,
        server_side_encryption_configuration: typing.Optional[typing.Union[CfnAssistant.ServerSideEncryptionConfigurationProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnAssistant``.

        :param name: The name of the assistant.
        :param type: The type of assistant.
        :param description: The description of the assistant.
        :param server_side_encryption_configuration: The KMS key used for encryption.
        :param tags: The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistant.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_wisdom as wisdom
            
            cfn_assistant_props = wisdom.CfnAssistantProps(
                name="name",
                type="type",
            
                # the properties below are optional
                description="description",
                server_side_encryption_configuration=wisdom.CfnAssistant.ServerSideEncryptionConfigurationProperty(
                    kms_key_id="kmsKeyId"
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
            "type": type,
        }
        if description is not None:
            self._values["description"] = description
        if server_side_encryption_configuration is not None:
            self._values["server_side_encryption_configuration"] = server_side_encryption_configuration
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the assistant.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistant.html#cfn-wisdom-assistant-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def type(self) -> builtins.str:
        '''The type of assistant.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistant.html#cfn-wisdom-assistant-type
        '''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the assistant.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistant.html#cfn-wisdom-assistant-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def server_side_encryption_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnAssistant.ServerSideEncryptionConfigurationProperty, _IResolvable_da3f097b]]:
        '''The KMS key used for encryption.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistant.html#cfn-wisdom-assistant-serversideencryptionconfiguration
        '''
        result = self._values.get("server_side_encryption_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnAssistant.ServerSideEncryptionConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-assistant.html#cfn-wisdom-assistant-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAssistantProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnKnowledgeBase(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_wisdom.CfnKnowledgeBase",
):
    '''A CloudFormation ``AWS::Wisdom::KnowledgeBase``.

    Specifies a knowledge base.

    :cloudformationResource: AWS::Wisdom::KnowledgeBase
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_wisdom as wisdom
        
        cfn_knowledge_base = wisdom.CfnKnowledgeBase(self, "MyCfnKnowledgeBase",
            knowledge_base_type="knowledgeBaseType",
            name="name",
        
            # the properties below are optional
            description="description",
            rendering_configuration=wisdom.CfnKnowledgeBase.RenderingConfigurationProperty(
                template_uri="templateUri"
            ),
            server_side_encryption_configuration=wisdom.CfnKnowledgeBase.ServerSideEncryptionConfigurationProperty(
                kms_key_id="kmsKeyId"
            ),
            source_configuration=wisdom.CfnKnowledgeBase.SourceConfigurationProperty(
                app_integrations=wisdom.CfnKnowledgeBase.AppIntegrationsConfigurationProperty(
                    app_integration_arn="appIntegrationArn",
                    object_fields=["objectFields"]
                )
            ),
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
        knowledge_base_type: builtins.str,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        rendering_configuration: typing.Optional[typing.Union["CfnKnowledgeBase.RenderingConfigurationProperty", _IResolvable_da3f097b]] = None,
        server_side_encryption_configuration: typing.Optional[typing.Union["CfnKnowledgeBase.ServerSideEncryptionConfigurationProperty", _IResolvable_da3f097b]] = None,
        source_configuration: typing.Optional[typing.Union["CfnKnowledgeBase.SourceConfigurationProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Wisdom::KnowledgeBase``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param knowledge_base_type: The type of knowledge base. Only CUSTOM knowledge bases allow you to upload your own content. EXTERNAL knowledge bases support integrations with third-party systems whose content is synchronized automatically.
        :param name: The name of the knowledge base.
        :param description: The description.
        :param rendering_configuration: Information about how to render the content.
        :param server_side_encryption_configuration: The KMS key used for encryption.
        :param source_configuration: The source of the knowledge base content. Only set this argument for EXTERNAL knowledge bases.
        :param tags: The tags used to organize, track, or control access for this resource.
        '''
        props = CfnKnowledgeBaseProps(
            knowledge_base_type=knowledge_base_type,
            name=name,
            description=description,
            rendering_configuration=rendering_configuration,
            server_side_encryption_configuration=server_side_encryption_configuration,
            source_configuration=source_configuration,
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
    @jsii.member(jsii_name="attrKnowledgeBaseArn")
    def attr_knowledge_base_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the knowledge base.

        :cloudformationAttribute: KnowledgeBaseArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrKnowledgeBaseArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrKnowledgeBaseId")
    def attr_knowledge_base_id(self) -> builtins.str:
        '''The ID of the knowledge base.

        :cloudformationAttribute: KnowledgeBaseId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrKnowledgeBaseId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html#cfn-wisdom-knowledgebase-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="knowledgeBaseType")
    def knowledge_base_type(self) -> builtins.str:
        '''The type of knowledge base.

        Only CUSTOM knowledge bases allow you to upload your own content. EXTERNAL knowledge bases support integrations with third-party systems whose content is synchronized automatically.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html#cfn-wisdom-knowledgebase-knowledgebasetype
        '''
        return typing.cast(builtins.str, jsii.get(self, "knowledgeBaseType"))

    @knowledge_base_type.setter
    def knowledge_base_type(self, value: builtins.str) -> None:
        jsii.set(self, "knowledgeBaseType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the knowledge base.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html#cfn-wisdom-knowledgebase-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html#cfn-wisdom-knowledgebase-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="renderingConfiguration")
    def rendering_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnKnowledgeBase.RenderingConfigurationProperty", _IResolvable_da3f097b]]:
        '''Information about how to render the content.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html#cfn-wisdom-knowledgebase-renderingconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnKnowledgeBase.RenderingConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "renderingConfiguration"))

    @rendering_configuration.setter
    def rendering_configuration(
        self,
        value: typing.Optional[typing.Union["CfnKnowledgeBase.RenderingConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "renderingConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serverSideEncryptionConfiguration")
    def server_side_encryption_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnKnowledgeBase.ServerSideEncryptionConfigurationProperty", _IResolvable_da3f097b]]:
        '''The KMS key used for encryption.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html#cfn-wisdom-knowledgebase-serversideencryptionconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnKnowledgeBase.ServerSideEncryptionConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "serverSideEncryptionConfiguration"))

    @server_side_encryption_configuration.setter
    def server_side_encryption_configuration(
        self,
        value: typing.Optional[typing.Union["CfnKnowledgeBase.ServerSideEncryptionConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "serverSideEncryptionConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceConfiguration")
    def source_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnKnowledgeBase.SourceConfigurationProperty", _IResolvable_da3f097b]]:
        '''The source of the knowledge base content.

        Only set this argument for EXTERNAL knowledge bases.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html#cfn-wisdom-knowledgebase-sourceconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnKnowledgeBase.SourceConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "sourceConfiguration"))

    @source_configuration.setter
    def source_configuration(
        self,
        value: typing.Optional[typing.Union["CfnKnowledgeBase.SourceConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "sourceConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wisdom.CfnKnowledgeBase.AppIntegrationsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "app_integration_arn": "appIntegrationArn",
            "object_fields": "objectFields",
        },
    )
    class AppIntegrationsConfigurationProperty:
        def __init__(
            self,
            *,
            app_integration_arn: builtins.str,
            object_fields: typing.Sequence[builtins.str],
        ) -> None:
            '''Configuration information for Amazon AppIntegrations to automatically ingest content.

            :param app_integration_arn: The Amazon Resource Name (ARN) of the AppIntegrations DataIntegration to use for ingesting content.
            :param object_fields: The fields from the source that are made available to your agents in Wisdom. - For `Salesforce <https://docs.aws.amazon.com/https://developer.salesforce.com/docs/atlas.en-us.knowledge_dev.meta/knowledge_dev/sforce_api_objects_knowledge__kav.htm>`_ , you must include at least ``Id`` , ``ArticleNumber`` , ``VersionNumber`` , ``Title`` , ``PublishStatus`` , and ``IsDeleted`` . - For `ServiceNow <https://docs.aws.amazon.com/https://developer.servicenow.com/dev.do#!/reference/api/rome/rest/knowledge-management-api>`_ , you must include at least ``number`` , ``short_description`` , ``sys_mod_count`` , ``workflow_state`` , and ``active`` . Make sure to include additional fields. These fields are indexed and used to source recommendations.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wisdom-knowledgebase-appintegrationsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wisdom as wisdom
                
                app_integrations_configuration_property = wisdom.CfnKnowledgeBase.AppIntegrationsConfigurationProperty(
                    app_integration_arn="appIntegrationArn",
                    object_fields=["objectFields"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "app_integration_arn": app_integration_arn,
                "object_fields": object_fields,
            }

        @builtins.property
        def app_integration_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the AppIntegrations DataIntegration to use for ingesting content.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wisdom-knowledgebase-appintegrationsconfiguration.html#cfn-wisdom-knowledgebase-appintegrationsconfiguration-appintegrationarn
            '''
            result = self._values.get("app_integration_arn")
            assert result is not None, "Required property 'app_integration_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def object_fields(self) -> typing.List[builtins.str]:
            '''The fields from the source that are made available to your agents in Wisdom.

            - For `Salesforce <https://docs.aws.amazon.com/https://developer.salesforce.com/docs/atlas.en-us.knowledge_dev.meta/knowledge_dev/sforce_api_objects_knowledge__kav.htm>`_ , you must include at least ``Id`` , ``ArticleNumber`` , ``VersionNumber`` , ``Title`` , ``PublishStatus`` , and ``IsDeleted`` .
            - For `ServiceNow <https://docs.aws.amazon.com/https://developer.servicenow.com/dev.do#!/reference/api/rome/rest/knowledge-management-api>`_ , you must include at least ``number`` , ``short_description`` , ``sys_mod_count`` , ``workflow_state`` , and ``active`` .

            Make sure to include additional fields. These fields are indexed and used to source recommendations.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wisdom-knowledgebase-appintegrationsconfiguration.html#cfn-wisdom-knowledgebase-appintegrationsconfiguration-objectfields
            '''
            result = self._values.get("object_fields")
            assert result is not None, "Required property 'object_fields' is missing"
            return typing.cast(typing.List[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AppIntegrationsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wisdom.CfnKnowledgeBase.RenderingConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"template_uri": "templateUri"},
    )
    class RenderingConfigurationProperty:
        def __init__(
            self,
            *,
            template_uri: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Information about how to render the content.

            :param template_uri: A URI template containing exactly one variable in ``${variableName}`` format. This can only be set for ``EXTERNAL`` knowledge bases. For Salesforce and ServiceNow, the variable must be one of the following: - Salesforce: ``Id`` , ``ArticleNumber`` , ``VersionNumber`` , ``Title`` , ``PublishStatus`` , or ``IsDeleted`` - ServiceNow: ``number`` , ``short_description`` , ``sys_mod_count`` , ``workflow_state`` , or ``active`` The variable is replaced with the actual value for a piece of content when calling `GetContent <https://docs.aws.amazon.com/wisdom/latest/APIReference/API_GetContent.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wisdom-knowledgebase-renderingconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wisdom as wisdom
                
                rendering_configuration_property = wisdom.CfnKnowledgeBase.RenderingConfigurationProperty(
                    template_uri="templateUri"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if template_uri is not None:
                self._values["template_uri"] = template_uri

        @builtins.property
        def template_uri(self) -> typing.Optional[builtins.str]:
            '''A URI template containing exactly one variable in ``${variableName}`` format.

            This can only be set for ``EXTERNAL`` knowledge bases. For Salesforce and ServiceNow, the variable must be one of the following:

            - Salesforce: ``Id`` , ``ArticleNumber`` , ``VersionNumber`` , ``Title`` , ``PublishStatus`` , or ``IsDeleted``
            - ServiceNow: ``number`` , ``short_description`` , ``sys_mod_count`` , ``workflow_state`` , or ``active``

            The variable is replaced with the actual value for a piece of content when calling `GetContent <https://docs.aws.amazon.com/wisdom/latest/APIReference/API_GetContent.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wisdom-knowledgebase-renderingconfiguration.html#cfn-wisdom-knowledgebase-renderingconfiguration-templateuri
            '''
            result = self._values.get("template_uri")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RenderingConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wisdom.CfnKnowledgeBase.ServerSideEncryptionConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"kms_key_id": "kmsKeyId"},
    )
    class ServerSideEncryptionConfigurationProperty:
        def __init__(self, *, kms_key_id: typing.Optional[builtins.str] = None) -> None:
            '''The KMS key used for encryption.

            :param kms_key_id: The KMS key . For information about valid ID values, see `Key identifiers (KeyId) <https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wisdom-knowledgebase-serversideencryptionconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wisdom as wisdom
                
                server_side_encryption_configuration_property = wisdom.CfnKnowledgeBase.ServerSideEncryptionConfigurationProperty(
                    kms_key_id="kmsKeyId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if kms_key_id is not None:
                self._values["kms_key_id"] = kms_key_id

        @builtins.property
        def kms_key_id(self) -> typing.Optional[builtins.str]:
            '''The KMS key .

            For information about valid ID values, see `Key identifiers (KeyId) <https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wisdom-knowledgebase-serversideencryptionconfiguration.html#cfn-wisdom-knowledgebase-serversideencryptionconfiguration-kmskeyid
            '''
            result = self._values.get("kms_key_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ServerSideEncryptionConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wisdom.CfnKnowledgeBase.SourceConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"app_integrations": "appIntegrations"},
    )
    class SourceConfigurationProperty:
        def __init__(
            self,
            *,
            app_integrations: typing.Optional[typing.Union["CfnKnowledgeBase.AppIntegrationsConfigurationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Configuration information about the external data source.

            :param app_integrations: Configuration information for Amazon AppIntegrations to automatically ingest content.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wisdom-knowledgebase-sourceconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wisdom as wisdom
                
                source_configuration_property = wisdom.CfnKnowledgeBase.SourceConfigurationProperty(
                    app_integrations=wisdom.CfnKnowledgeBase.AppIntegrationsConfigurationProperty(
                        app_integration_arn="appIntegrationArn",
                        object_fields=["objectFields"]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if app_integrations is not None:
                self._values["app_integrations"] = app_integrations

        @builtins.property
        def app_integrations(
            self,
        ) -> typing.Optional[typing.Union["CfnKnowledgeBase.AppIntegrationsConfigurationProperty", _IResolvable_da3f097b]]:
            '''Configuration information for Amazon AppIntegrations to automatically ingest content.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wisdom-knowledgebase-sourceconfiguration.html#cfn-wisdom-knowledgebase-sourceconfiguration-appintegrations
            '''
            result = self._values.get("app_integrations")
            return typing.cast(typing.Optional[typing.Union["CfnKnowledgeBase.AppIntegrationsConfigurationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SourceConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_wisdom.CfnKnowledgeBaseProps",
    jsii_struct_bases=[],
    name_mapping={
        "knowledge_base_type": "knowledgeBaseType",
        "name": "name",
        "description": "description",
        "rendering_configuration": "renderingConfiguration",
        "server_side_encryption_configuration": "serverSideEncryptionConfiguration",
        "source_configuration": "sourceConfiguration",
        "tags": "tags",
    },
)
class CfnKnowledgeBaseProps:
    def __init__(
        self,
        *,
        knowledge_base_type: builtins.str,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        rendering_configuration: typing.Optional[typing.Union[CfnKnowledgeBase.RenderingConfigurationProperty, _IResolvable_da3f097b]] = None,
        server_side_encryption_configuration: typing.Optional[typing.Union[CfnKnowledgeBase.ServerSideEncryptionConfigurationProperty, _IResolvable_da3f097b]] = None,
        source_configuration: typing.Optional[typing.Union[CfnKnowledgeBase.SourceConfigurationProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnKnowledgeBase``.

        :param knowledge_base_type: The type of knowledge base. Only CUSTOM knowledge bases allow you to upload your own content. EXTERNAL knowledge bases support integrations with third-party systems whose content is synchronized automatically.
        :param name: The name of the knowledge base.
        :param description: The description.
        :param rendering_configuration: Information about how to render the content.
        :param server_side_encryption_configuration: The KMS key used for encryption.
        :param source_configuration: The source of the knowledge base content. Only set this argument for EXTERNAL knowledge bases.
        :param tags: The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_wisdom as wisdom
            
            cfn_knowledge_base_props = wisdom.CfnKnowledgeBaseProps(
                knowledge_base_type="knowledgeBaseType",
                name="name",
            
                # the properties below are optional
                description="description",
                rendering_configuration=wisdom.CfnKnowledgeBase.RenderingConfigurationProperty(
                    template_uri="templateUri"
                ),
                server_side_encryption_configuration=wisdom.CfnKnowledgeBase.ServerSideEncryptionConfigurationProperty(
                    kms_key_id="kmsKeyId"
                ),
                source_configuration=wisdom.CfnKnowledgeBase.SourceConfigurationProperty(
                    app_integrations=wisdom.CfnKnowledgeBase.AppIntegrationsConfigurationProperty(
                        app_integration_arn="appIntegrationArn",
                        object_fields=["objectFields"]
                    )
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "knowledge_base_type": knowledge_base_type,
            "name": name,
        }
        if description is not None:
            self._values["description"] = description
        if rendering_configuration is not None:
            self._values["rendering_configuration"] = rendering_configuration
        if server_side_encryption_configuration is not None:
            self._values["server_side_encryption_configuration"] = server_side_encryption_configuration
        if source_configuration is not None:
            self._values["source_configuration"] = source_configuration
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def knowledge_base_type(self) -> builtins.str:
        '''The type of knowledge base.

        Only CUSTOM knowledge bases allow you to upload your own content. EXTERNAL knowledge bases support integrations with third-party systems whose content is synchronized automatically.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html#cfn-wisdom-knowledgebase-knowledgebasetype
        '''
        result = self._values.get("knowledge_base_type")
        assert result is not None, "Required property 'knowledge_base_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the knowledge base.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html#cfn-wisdom-knowledgebase-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html#cfn-wisdom-knowledgebase-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def rendering_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnKnowledgeBase.RenderingConfigurationProperty, _IResolvable_da3f097b]]:
        '''Information about how to render the content.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html#cfn-wisdom-knowledgebase-renderingconfiguration
        '''
        result = self._values.get("rendering_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnKnowledgeBase.RenderingConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def server_side_encryption_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnKnowledgeBase.ServerSideEncryptionConfigurationProperty, _IResolvable_da3f097b]]:
        '''The KMS key used for encryption.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html#cfn-wisdom-knowledgebase-serversideencryptionconfiguration
        '''
        result = self._values.get("server_side_encryption_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnKnowledgeBase.ServerSideEncryptionConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def source_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnKnowledgeBase.SourceConfigurationProperty, _IResolvable_da3f097b]]:
        '''The source of the knowledge base content.

        Only set this argument for EXTERNAL knowledge bases.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html#cfn-wisdom-knowledgebase-sourceconfiguration
        '''
        result = self._values.get("source_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnKnowledgeBase.SourceConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wisdom-knowledgebase.html#cfn-wisdom-knowledgebase-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnKnowledgeBaseProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnAssistant",
    "CfnAssistantAssociation",
    "CfnAssistantAssociationProps",
    "CfnAssistantProps",
    "CfnKnowledgeBase",
    "CfnKnowledgeBaseProps",
]

publication.publish()
