'''
# AWS IoT Greengrass Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_greengrass as greengrass
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-greengrass-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::Greengrass](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_Greengrass.html).

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
class CfnConnectorDefinition(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnConnectorDefinition",
):
    '''A CloudFormation ``AWS::Greengrass::ConnectorDefinition``.

    The ``AWS::Greengrass::ConnectorDefinition`` resource represents a connector definition for AWS IoT Greengrass . Connector definitions are used to organize your connector definition versions.

    Connector definitions can reference multiple connector definition versions. All connector definition versions must be associated with a connector definition. Each connector definition version can contain one or more connectors.
    .. epigraph::

       When you create a connector definition, you can optionally include an initial connector definition version. To associate a connector definition version later, create an ```AWS::Greengrass::ConnectorDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinitionversion.html>`_ resource and specify the ID of this connector definition.

       After you create the connector definition version that contains the connectors you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::ConnectorDefinition
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinition.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        # parameters: Any
        # tags: Any
        
        cfn_connector_definition = greengrass.CfnConnectorDefinition(self, "MyCfnConnectorDefinition",
            name="name",
        
            # the properties below are optional
            initial_version=greengrass.CfnConnectorDefinition.ConnectorDefinitionVersionProperty(
                connectors=[greengrass.CfnConnectorDefinition.ConnectorProperty(
                    connector_arn="connectorArn",
                    id="id",
        
                    # the properties below are optional
                    parameters=parameters
                )]
            ),
            tags=tags
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union["CfnConnectorDefinition.ConnectorDefinitionVersionProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Greengrass::ConnectorDefinition``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the connector definition.
        :param initial_version: The connector definition version to include when the connector definition is created. A connector definition version contains a list of ```connector`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinition-connector.html>`_ property types. .. epigraph:: To associate a connector definition version after the connector definition is created, create an ```AWS::Greengrass::ConnectorDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinitionversion.html>`_ resource and specify the ID of this connector definition.
        :param tags: Application-specific metadata to attach to the connector definition. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }
        '''
        props = CfnConnectorDefinitionProps(
            name=name, initial_version=initial_version, tags=tags
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
        '''The Amazon Resource Name (ARN) of the ``ConnectorDefinition`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/connectors/1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the ``ConnectorDefinition`` , such as ``1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLatestVersionArn")
    def attr_latest_version_arn(self) -> builtins.str:
        '''The ARN of the last ``ConnectorDefinitionVersion`` that was added to the ``ConnectorDefinition`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/connectors/1234a5b6-78cd-901e-2fgh-3i45j6k178l9/versions/9876ac30-4bdb-4f9d-95af-b5fdb66be1a2`` .

        :cloudformationAttribute: LatestVersionArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLatestVersionArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the ``ConnectorDefinition`` , such as ``MyConnectorDefinition`` .

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
        '''Application-specific metadata to attach to the connector definition.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinition.html#cfn-greengrass-connectordefinition-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the connector definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinition.html#cfn-greengrass-connectordefinition-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="initialVersion")
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union["CfnConnectorDefinition.ConnectorDefinitionVersionProperty", _IResolvable_da3f097b]]:
        '''The connector definition version to include when the connector definition is created.

        A connector definition version contains a list of ```connector`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinition-connector.html>`_ property types.
        .. epigraph::

           To associate a connector definition version after the connector definition is created, create an ```AWS::Greengrass::ConnectorDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinitionversion.html>`_ resource and specify the ID of this connector definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinition.html#cfn-greengrass-connectordefinition-initialversion
        '''
        return typing.cast(typing.Optional[typing.Union["CfnConnectorDefinition.ConnectorDefinitionVersionProperty", _IResolvable_da3f097b]], jsii.get(self, "initialVersion"))

    @initial_version.setter
    def initial_version(
        self,
        value: typing.Optional[typing.Union["CfnConnectorDefinition.ConnectorDefinitionVersionProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "initialVersion", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnConnectorDefinition.ConnectorDefinitionVersionProperty",
        jsii_struct_bases=[],
        name_mapping={"connectors": "connectors"},
    )
    class ConnectorDefinitionVersionProperty:
        def __init__(
            self,
            *,
            connectors: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnConnectorDefinition.ConnectorProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A connector definition version contains a list of connectors.

            .. epigraph::

               After you create a connector definition version that contains the connectors you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

            In an AWS CloudFormation template, ``ConnectorDefinitionVersion`` is the property type of the ``InitialVersion`` property in the ```AWS::Greengrass::ConnectorDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinition.html>`_ resource.

            :param connectors: The connectors in this version. Only one instance of a given connector can be added to a connector definition version at a time.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinition-connectordefinitionversion.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                # parameters: Any
                
                connector_definition_version_property = greengrass.CfnConnectorDefinition.ConnectorDefinitionVersionProperty(
                    connectors=[greengrass.CfnConnectorDefinition.ConnectorProperty(
                        connector_arn="connectorArn",
                        id="id",
                
                        # the properties below are optional
                        parameters=parameters
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "connectors": connectors,
            }

        @builtins.property
        def connectors(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnConnectorDefinition.ConnectorProperty", _IResolvable_da3f097b]]]:
            '''The connectors in this version.

            Only one instance of a given connector can be added to a connector definition version at a time.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinition-connectordefinitionversion.html#cfn-greengrass-connectordefinition-connectordefinitionversion-connectors
            '''
            result = self._values.get("connectors")
            assert result is not None, "Required property 'connectors' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnConnectorDefinition.ConnectorProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConnectorDefinitionVersionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnConnectorDefinition.ConnectorProperty",
        jsii_struct_bases=[],
        name_mapping={
            "connector_arn": "connectorArn",
            "id": "id",
            "parameters": "parameters",
        },
    )
    class ConnectorProperty:
        def __init__(
            self,
            *,
            connector_arn: builtins.str,
            id: builtins.str,
            parameters: typing.Any = None,
        ) -> None:
            '''Connectors are modules that provide built-in integration with local infrastructure, device protocols, AWS , and other cloud services.

            For more information, see `Integrate with Services and Protocols Using Greengrass Connectors <https://docs.aws.amazon.com/greengrass/latest/developerguide/connectors.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, the ``Connectors`` property of the ```ConnectorDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinition-connectordefinitionversion.html>`_ property type contains a list of ``Connector`` property types.

            :param connector_arn: The Amazon Resource Name (ARN) of the connector. For more information about connectors provided by AWS , see `Greengrass Connectors Provided by AWS <https://docs.aws.amazon.com/greengrass/latest/developerguide/connectors-list.html>`_ .
            :param id: A descriptive or arbitrary ID for the connector. This value must be unique within the connector definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .
            :param parameters: The parameters or configuration used by the connector. For more information about connectors provided by AWS , see `Greengrass Connectors Provided by AWS <https://docs.aws.amazon.com/greengrass/latest/developerguide/connectors-list.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinition-connector.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                # parameters: Any
                
                connector_property = greengrass.CfnConnectorDefinition.ConnectorProperty(
                    connector_arn="connectorArn",
                    id="id",
                
                    # the properties below are optional
                    parameters=parameters
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "connector_arn": connector_arn,
                "id": id,
            }
            if parameters is not None:
                self._values["parameters"] = parameters

        @builtins.property
        def connector_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the connector.

            For more information about connectors provided by AWS , see `Greengrass Connectors Provided by AWS <https://docs.aws.amazon.com/greengrass/latest/developerguide/connectors-list.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinition-connector.html#cfn-greengrass-connectordefinition-connector-connectorarn
            '''
            result = self._values.get("connector_arn")
            assert result is not None, "Required property 'connector_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def id(self) -> builtins.str:
            '''A descriptive or arbitrary ID for the connector.

            This value must be unique within the connector definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinition-connector.html#cfn-greengrass-connectordefinition-connector-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def parameters(self) -> typing.Any:
            '''The parameters or configuration used by the connector.

            For more information about connectors provided by AWS , see `Greengrass Connectors Provided by AWS <https://docs.aws.amazon.com/greengrass/latest/developerguide/connectors-list.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinition-connector.html#cfn-greengrass-connectordefinition-connector-parameters
            '''
            result = self._values.get("parameters")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConnectorProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnConnectorDefinitionProps",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "initial_version": "initialVersion", "tags": "tags"},
)
class CfnConnectorDefinitionProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union[CfnConnectorDefinition.ConnectorDefinitionVersionProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnConnectorDefinition``.

        :param name: The name of the connector definition.
        :param initial_version: The connector definition version to include when the connector definition is created. A connector definition version contains a list of ```connector`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinition-connector.html>`_ property types. .. epigraph:: To associate a connector definition version after the connector definition is created, create an ```AWS::Greengrass::ConnectorDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinitionversion.html>`_ resource and specify the ID of this connector definition.
        :param tags: Application-specific metadata to attach to the connector definition. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinition.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            # parameters: Any
            # tags: Any
            
            cfn_connector_definition_props = greengrass.CfnConnectorDefinitionProps(
                name="name",
            
                # the properties below are optional
                initial_version=greengrass.CfnConnectorDefinition.ConnectorDefinitionVersionProperty(
                    connectors=[greengrass.CfnConnectorDefinition.ConnectorProperty(
                        connector_arn="connectorArn",
                        id="id",
            
                        # the properties below are optional
                        parameters=parameters
                    )]
                ),
                tags=tags
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if initial_version is not None:
            self._values["initial_version"] = initial_version
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the connector definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinition.html#cfn-greengrass-connectordefinition-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union[CfnConnectorDefinition.ConnectorDefinitionVersionProperty, _IResolvable_da3f097b]]:
        '''The connector definition version to include when the connector definition is created.

        A connector definition version contains a list of ```connector`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinition-connector.html>`_ property types.
        .. epigraph::

           To associate a connector definition version after the connector definition is created, create an ```AWS::Greengrass::ConnectorDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinitionversion.html>`_ resource and specify the ID of this connector definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinition.html#cfn-greengrass-connectordefinition-initialversion
        '''
        result = self._values.get("initial_version")
        return typing.cast(typing.Optional[typing.Union[CfnConnectorDefinition.ConnectorDefinitionVersionProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''Application-specific metadata to attach to the connector definition.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinition.html#cfn-greengrass-connectordefinition-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnConnectorDefinitionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnConnectorDefinitionVersion(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnConnectorDefinitionVersion",
):
    '''A CloudFormation ``AWS::Greengrass::ConnectorDefinitionVersion``.

    The ``AWS::Greengrass::ConnectorDefinitionVersion`` resource represents a connector definition version for AWS IoT Greengrass . A connector definition version contains a list of connectors.
    .. epigraph::

       To create a connector definition version, you must specify the ID of the connector definition that you want to associate with the version. For information about creating a connector definition, see ```AWS::Greengrass::ConnectorDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinition.html>`_ .

       After you create a connector definition version that contains the connectors you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::ConnectorDefinitionVersion
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinitionversion.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        # parameters: Any
        
        cfn_connector_definition_version = greengrass.CfnConnectorDefinitionVersion(self, "MyCfnConnectorDefinitionVersion",
            connector_definition_id="connectorDefinitionId",
            connectors=[greengrass.CfnConnectorDefinitionVersion.ConnectorProperty(
                connector_arn="connectorArn",
                id="id",
        
                # the properties below are optional
                parameters=parameters
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        connector_definition_id: builtins.str,
        connectors: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnConnectorDefinitionVersion.ConnectorProperty", _IResolvable_da3f097b]]],
    ) -> None:
        '''Create a new ``AWS::Greengrass::ConnectorDefinitionVersion``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param connector_definition_id: The ID of the connector definition associated with this version. This value is a GUID.
        :param connectors: The connectors in this version. Only one instance of a given connector can be added to the connector definition version at a time.
        '''
        props = CfnConnectorDefinitionVersionProps(
            connector_definition_id=connector_definition_id, connectors=connectors
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
    @jsii.member(jsii_name="connectorDefinitionId")
    def connector_definition_id(self) -> builtins.str:
        '''The ID of the connector definition associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinitionversion.html#cfn-greengrass-connectordefinitionversion-connectordefinitionid
        '''
        return typing.cast(builtins.str, jsii.get(self, "connectorDefinitionId"))

    @connector_definition_id.setter
    def connector_definition_id(self, value: builtins.str) -> None:
        jsii.set(self, "connectorDefinitionId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectors")
    def connectors(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnConnectorDefinitionVersion.ConnectorProperty", _IResolvable_da3f097b]]]:
        '''The connectors in this version.

        Only one instance of a given connector can be added to the connector definition version at a time.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinitionversion.html#cfn-greengrass-connectordefinitionversion-connectors
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnConnectorDefinitionVersion.ConnectorProperty", _IResolvable_da3f097b]]], jsii.get(self, "connectors"))

    @connectors.setter
    def connectors(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnConnectorDefinitionVersion.ConnectorProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "connectors", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnConnectorDefinitionVersion.ConnectorProperty",
        jsii_struct_bases=[],
        name_mapping={
            "connector_arn": "connectorArn",
            "id": "id",
            "parameters": "parameters",
        },
    )
    class ConnectorProperty:
        def __init__(
            self,
            *,
            connector_arn: builtins.str,
            id: builtins.str,
            parameters: typing.Any = None,
        ) -> None:
            '''Connectors are modules that provide built-in integration with local infrastructure, device protocols, AWS , and other cloud services.

            For more information, see `Integrate with Services and Protocols Using Greengrass Connectors <https://docs.aws.amazon.com/greengrass/latest/developerguide/connectors.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, the ``Connectors`` property of the ```AWS::Greengrass::ConnectorDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinitionversion.html>`_ resource contains a list of ``Connector`` property types.

            :param connector_arn: The Amazon Resource Name (ARN) of the connector. For more information about connectors provided by AWS , see `Greengrass Connectors Provided by AWS <https://docs.aws.amazon.com/greengrass/latest/developerguide/connectors-list.html>`_ .
            :param id: A descriptive or arbitrary ID for the connector. This value must be unique within the connector definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .
            :param parameters: The parameters or configuration that the connector uses. For more information about connectors provided by AWS , see `Greengrass Connectors Provided by AWS <https://docs.aws.amazon.com/greengrass/latest/developerguide/connectors-list.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinitionversion-connector.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                # parameters: Any
                
                connector_property = greengrass.CfnConnectorDefinitionVersion.ConnectorProperty(
                    connector_arn="connectorArn",
                    id="id",
                
                    # the properties below are optional
                    parameters=parameters
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "connector_arn": connector_arn,
                "id": id,
            }
            if parameters is not None:
                self._values["parameters"] = parameters

        @builtins.property
        def connector_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the connector.

            For more information about connectors provided by AWS , see `Greengrass Connectors Provided by AWS <https://docs.aws.amazon.com/greengrass/latest/developerguide/connectors-list.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinitionversion-connector.html#cfn-greengrass-connectordefinitionversion-connector-connectorarn
            '''
            result = self._values.get("connector_arn")
            assert result is not None, "Required property 'connector_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def id(self) -> builtins.str:
            '''A descriptive or arbitrary ID for the connector.

            This value must be unique within the connector definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinitionversion-connector.html#cfn-greengrass-connectordefinitionversion-connector-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def parameters(self) -> typing.Any:
            '''The parameters or configuration that the connector uses.

            For more information about connectors provided by AWS , see `Greengrass Connectors Provided by AWS <https://docs.aws.amazon.com/greengrass/latest/developerguide/connectors-list.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-connectordefinitionversion-connector.html#cfn-greengrass-connectordefinitionversion-connector-parameters
            '''
            result = self._values.get("parameters")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConnectorProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnConnectorDefinitionVersionProps",
    jsii_struct_bases=[],
    name_mapping={
        "connector_definition_id": "connectorDefinitionId",
        "connectors": "connectors",
    },
)
class CfnConnectorDefinitionVersionProps:
    def __init__(
        self,
        *,
        connector_definition_id: builtins.str,
        connectors: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnConnectorDefinitionVersion.ConnectorProperty, _IResolvable_da3f097b]]],
    ) -> None:
        '''Properties for defining a ``CfnConnectorDefinitionVersion``.

        :param connector_definition_id: The ID of the connector definition associated with this version. This value is a GUID.
        :param connectors: The connectors in this version. Only one instance of a given connector can be added to the connector definition version at a time.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinitionversion.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            # parameters: Any
            
            cfn_connector_definition_version_props = greengrass.CfnConnectorDefinitionVersionProps(
                connector_definition_id="connectorDefinitionId",
                connectors=[greengrass.CfnConnectorDefinitionVersion.ConnectorProperty(
                    connector_arn="connectorArn",
                    id="id",
            
                    # the properties below are optional
                    parameters=parameters
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "connector_definition_id": connector_definition_id,
            "connectors": connectors,
        }

    @builtins.property
    def connector_definition_id(self) -> builtins.str:
        '''The ID of the connector definition associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinitionversion.html#cfn-greengrass-connectordefinitionversion-connectordefinitionid
        '''
        result = self._values.get("connector_definition_id")
        assert result is not None, "Required property 'connector_definition_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def connectors(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnConnectorDefinitionVersion.ConnectorProperty, _IResolvable_da3f097b]]]:
        '''The connectors in this version.

        Only one instance of a given connector can be added to the connector definition version at a time.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-connectordefinitionversion.html#cfn-greengrass-connectordefinitionversion-connectors
        '''
        result = self._values.get("connectors")
        assert result is not None, "Required property 'connectors' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnConnectorDefinitionVersion.ConnectorProperty, _IResolvable_da3f097b]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnConnectorDefinitionVersionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnCoreDefinition(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnCoreDefinition",
):
    '''A CloudFormation ``AWS::Greengrass::CoreDefinition``.

    The ``AWS::Greengrass::CoreDefinition`` resource represents a core definition for AWS IoT Greengrass . Core definitions are used to organize your core definition versions.

    Core definitions can reference multiple core definition versions. All core definition versions must be associated with a core definition. Each core definition version can contain one Greengrass core.
    .. epigraph::

       When you create a core definition, you can optionally include an initial core definition version. To associate a core definition version later, create an ```AWS::Greengrass::CoreDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinitionversion.html>`_ resource and specify the ID of this core definition.

       After you create the core definition version that contains the core you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::CoreDefinition
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinition.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        # tags: Any
        
        cfn_core_definition = greengrass.CfnCoreDefinition(self, "MyCfnCoreDefinition",
            name="name",
        
            # the properties below are optional
            initial_version=greengrass.CfnCoreDefinition.CoreDefinitionVersionProperty(
                cores=[greengrass.CfnCoreDefinition.CoreProperty(
                    certificate_arn="certificateArn",
                    id="id",
                    thing_arn="thingArn",
        
                    # the properties below are optional
                    sync_shadow=False
                )]
            ),
            tags=tags
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union["CfnCoreDefinition.CoreDefinitionVersionProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Greengrass::CoreDefinition``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the core definition.
        :param initial_version: The core definition version to include when the core definition is created. Currently, a core definition version can contain only one ```core`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinition-core.html>`_ . .. epigraph:: To associate a core definition version after the core definition is created, create an ```AWS::Greengrass::CoreDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinitionversion.html>`_ resource and specify the ID of this core definition.
        :param tags: Application-specific metadata to attach to the core definition. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }
        '''
        props = CfnCoreDefinitionProps(
            name=name, initial_version=initial_version, tags=tags
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
        '''The Amazon Resource Name (ARN) of the ``CoreDefinition`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/cores/1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the ``CoreDefinition`` , such as ``1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLatestVersionArn")
    def attr_latest_version_arn(self) -> builtins.str:
        '''The ARN of the last ``CoreDefinitionVersion`` that was added to the ``CoreDefinition`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/cores/1234a5b6-78cd-901e-2fgh-3i45j6k178l9/versions/9876ac30-4bdb-4f9d-95af-b5fdb66be1a2`` .

        :cloudformationAttribute: LatestVersionArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLatestVersionArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the ``CoreDefinition`` , such as ``MyCoreDefinition`` .

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
        '''Application-specific metadata to attach to the core definition.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinition.html#cfn-greengrass-coredefinition-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the core definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinition.html#cfn-greengrass-coredefinition-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="initialVersion")
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union["CfnCoreDefinition.CoreDefinitionVersionProperty", _IResolvable_da3f097b]]:
        '''The core definition version to include when the core definition is created.

        Currently, a core definition version can contain only one ```core`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinition-core.html>`_ .
        .. epigraph::

           To associate a core definition version after the core definition is created, create an ```AWS::Greengrass::CoreDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinitionversion.html>`_ resource and specify the ID of this core definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinition.html#cfn-greengrass-coredefinition-initialversion
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCoreDefinition.CoreDefinitionVersionProperty", _IResolvable_da3f097b]], jsii.get(self, "initialVersion"))

    @initial_version.setter
    def initial_version(
        self,
        value: typing.Optional[typing.Union["CfnCoreDefinition.CoreDefinitionVersionProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "initialVersion", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnCoreDefinition.CoreDefinitionVersionProperty",
        jsii_struct_bases=[],
        name_mapping={"cores": "cores"},
    )
    class CoreDefinitionVersionProperty:
        def __init__(
            self,
            *,
            cores: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCoreDefinition.CoreProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A core definition version contains a Greengrass `core <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinition-core.html>`_ .

            .. epigraph::

               After you create a core definition version that contains the core you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

            In an AWS CloudFormation template, ``CoreDefinitionVersion`` is the property type of the ``InitialVersion`` property in the ```AWS::Greengrass::CoreDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinition.html>`_ resource.

            :param cores: The Greengrass core in this version. Currently, the ``Cores`` property for a core definition version can contain only one core.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinition-coredefinitionversion.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                core_definition_version_property = greengrass.CfnCoreDefinition.CoreDefinitionVersionProperty(
                    cores=[greengrass.CfnCoreDefinition.CoreProperty(
                        certificate_arn="certificateArn",
                        id="id",
                        thing_arn="thingArn",
                
                        # the properties below are optional
                        sync_shadow=False
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "cores": cores,
            }

        @builtins.property
        def cores(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCoreDefinition.CoreProperty", _IResolvable_da3f097b]]]:
            '''The Greengrass core in this version.

            Currently, the ``Cores`` property for a core definition version can contain only one core.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinition-coredefinitionversion.html#cfn-greengrass-coredefinition-coredefinitionversion-cores
            '''
            result = self._values.get("cores")
            assert result is not None, "Required property 'cores' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCoreDefinition.CoreProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CoreDefinitionVersionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnCoreDefinition.CoreProperty",
        jsii_struct_bases=[],
        name_mapping={
            "certificate_arn": "certificateArn",
            "id": "id",
            "thing_arn": "thingArn",
            "sync_shadow": "syncShadow",
        },
    )
    class CoreProperty:
        def __init__(
            self,
            *,
            certificate_arn: builtins.str,
            id: builtins.str,
            thing_arn: builtins.str,
            sync_shadow: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A core is an AWS IoT device that runs the AWS IoT Greengrass core software and manages local processes for a Greengrass group.

            For more information, see `What Is AWS IoT Greengrass ? <https://docs.aws.amazon.com/greengrass/latest/developerguide/what-is-gg.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, the ``Cores`` property of the ```CoreDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinition-coredefinitionversion.html>`_ property type contains a list of ``Core`` property types. Currently, the list can contain only one core.

            :param certificate_arn: The Amazon Resource Name (ARN) of the device certificate for the core. This X.509 certificate is used to authenticate the core with AWS IoT and AWS IoT Greengrass services.
            :param id: A descriptive or arbitrary ID for the core. This value must be unique within the core definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .
            :param thing_arn: The ARN of the core, which is an AWS IoT device (thing).
            :param sync_shadow: Indicates whether the core's local shadow is synced with the cloud automatically. The default is false.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinition-core.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                core_property = greengrass.CfnCoreDefinition.CoreProperty(
                    certificate_arn="certificateArn",
                    id="id",
                    thing_arn="thingArn",
                
                    # the properties below are optional
                    sync_shadow=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "certificate_arn": certificate_arn,
                "id": id,
                "thing_arn": thing_arn,
            }
            if sync_shadow is not None:
                self._values["sync_shadow"] = sync_shadow

        @builtins.property
        def certificate_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the device certificate for the core.

            This X.509 certificate is used to authenticate the core with AWS IoT and AWS IoT Greengrass services.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinition-core.html#cfn-greengrass-coredefinition-core-certificatearn
            '''
            result = self._values.get("certificate_arn")
            assert result is not None, "Required property 'certificate_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def id(self) -> builtins.str:
            '''A descriptive or arbitrary ID for the core.

            This value must be unique within the core definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinition-core.html#cfn-greengrass-coredefinition-core-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def thing_arn(self) -> builtins.str:
            '''The ARN of the core, which is an AWS IoT device (thing).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinition-core.html#cfn-greengrass-coredefinition-core-thingarn
            '''
            result = self._values.get("thing_arn")
            assert result is not None, "Required property 'thing_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def sync_shadow(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether the core's local shadow is synced with the cloud automatically.

            The default is false.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinition-core.html#cfn-greengrass-coredefinition-core-syncshadow
            '''
            result = self._values.get("sync_shadow")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CoreProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnCoreDefinitionProps",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "initial_version": "initialVersion", "tags": "tags"},
)
class CfnCoreDefinitionProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union[CfnCoreDefinition.CoreDefinitionVersionProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnCoreDefinition``.

        :param name: The name of the core definition.
        :param initial_version: The core definition version to include when the core definition is created. Currently, a core definition version can contain only one ```core`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinition-core.html>`_ . .. epigraph:: To associate a core definition version after the core definition is created, create an ```AWS::Greengrass::CoreDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinitionversion.html>`_ resource and specify the ID of this core definition.
        :param tags: Application-specific metadata to attach to the core definition. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinition.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            # tags: Any
            
            cfn_core_definition_props = greengrass.CfnCoreDefinitionProps(
                name="name",
            
                # the properties below are optional
                initial_version=greengrass.CfnCoreDefinition.CoreDefinitionVersionProperty(
                    cores=[greengrass.CfnCoreDefinition.CoreProperty(
                        certificate_arn="certificateArn",
                        id="id",
                        thing_arn="thingArn",
            
                        # the properties below are optional
                        sync_shadow=False
                    )]
                ),
                tags=tags
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if initial_version is not None:
            self._values["initial_version"] = initial_version
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the core definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinition.html#cfn-greengrass-coredefinition-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union[CfnCoreDefinition.CoreDefinitionVersionProperty, _IResolvable_da3f097b]]:
        '''The core definition version to include when the core definition is created.

        Currently, a core definition version can contain only one ```core`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinition-core.html>`_ .
        .. epigraph::

           To associate a core definition version after the core definition is created, create an ```AWS::Greengrass::CoreDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinitionversion.html>`_ resource and specify the ID of this core definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinition.html#cfn-greengrass-coredefinition-initialversion
        '''
        result = self._values.get("initial_version")
        return typing.cast(typing.Optional[typing.Union[CfnCoreDefinition.CoreDefinitionVersionProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''Application-specific metadata to attach to the core definition.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinition.html#cfn-greengrass-coredefinition-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnCoreDefinitionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnCoreDefinitionVersion(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnCoreDefinitionVersion",
):
    '''A CloudFormation ``AWS::Greengrass::CoreDefinitionVersion``.

    The ``AWS::Greengrass::CoreDefinitionVersion`` resource represents a core definition version for AWS IoT Greengrass . A core definition version contains a Greengrass core.
    .. epigraph::

       To create a core definition version, you must specify the ID of the core definition that you want to associate with the version. For information about creating a core definition, see ```AWS::Greengrass::CoreDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinition.html>`_ .

       After you create a core definition version that contains the core you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::CoreDefinitionVersion
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinitionversion.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        cfn_core_definition_version = greengrass.CfnCoreDefinitionVersion(self, "MyCfnCoreDefinitionVersion",
            core_definition_id="coreDefinitionId",
            cores=[greengrass.CfnCoreDefinitionVersion.CoreProperty(
                certificate_arn="certificateArn",
                id="id",
                thing_arn="thingArn",
        
                # the properties below are optional
                sync_shadow=False
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        core_definition_id: builtins.str,
        cores: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCoreDefinitionVersion.CoreProperty", _IResolvable_da3f097b]]],
    ) -> None:
        '''Create a new ``AWS::Greengrass::CoreDefinitionVersion``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param core_definition_id: The ID of the core definition associated with this version. This value is a GUID.
        :param cores: The Greengrass core in this version. Currently, the ``Cores`` property for a core definition version can contain only one core.
        '''
        props = CfnCoreDefinitionVersionProps(
            core_definition_id=core_definition_id, cores=cores
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
    @jsii.member(jsii_name="coreDefinitionId")
    def core_definition_id(self) -> builtins.str:
        '''The ID of the core definition associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinitionversion.html#cfn-greengrass-coredefinitionversion-coredefinitionid
        '''
        return typing.cast(builtins.str, jsii.get(self, "coreDefinitionId"))

    @core_definition_id.setter
    def core_definition_id(self, value: builtins.str) -> None:
        jsii.set(self, "coreDefinitionId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cores")
    def cores(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCoreDefinitionVersion.CoreProperty", _IResolvable_da3f097b]]]:
        '''The Greengrass core in this version.

        Currently, the ``Cores`` property for a core definition version can contain only one core.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinitionversion.html#cfn-greengrass-coredefinitionversion-cores
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCoreDefinitionVersion.CoreProperty", _IResolvable_da3f097b]]], jsii.get(self, "cores"))

    @cores.setter
    def cores(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCoreDefinitionVersion.CoreProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "cores", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnCoreDefinitionVersion.CoreProperty",
        jsii_struct_bases=[],
        name_mapping={
            "certificate_arn": "certificateArn",
            "id": "id",
            "thing_arn": "thingArn",
            "sync_shadow": "syncShadow",
        },
    )
    class CoreProperty:
        def __init__(
            self,
            *,
            certificate_arn: builtins.str,
            id: builtins.str,
            thing_arn: builtins.str,
            sync_shadow: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A core is an AWS IoT device that runs the AWS IoT Greengrass core software and manages local processes for a Greengrass group.

            For more information, see `What Is AWS IoT Greengrass ? <https://docs.aws.amazon.com/greengrass/latest/developerguide/what-is-gg.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, the ``Cores`` property of the ```AWS::Greengrass::CoreDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinitionversion.html>`_ resource contains a list of ``Core`` property types. Currently, the list can contain only one core.

            :param certificate_arn: The ARN of the device certificate for the core. This X.509 certificate is used to authenticate the core with AWS IoT and AWS IoT Greengrass services.
            :param id: A descriptive or arbitrary ID for the core. This value must be unique within the core definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .
            :param thing_arn: The Amazon Resource Name (ARN) of the core, which is an AWS IoT device (thing).
            :param sync_shadow: Indicates whether the core's local shadow is synced with the cloud automatically. The default is false.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinitionversion-core.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                core_property = greengrass.CfnCoreDefinitionVersion.CoreProperty(
                    certificate_arn="certificateArn",
                    id="id",
                    thing_arn="thingArn",
                
                    # the properties below are optional
                    sync_shadow=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "certificate_arn": certificate_arn,
                "id": id,
                "thing_arn": thing_arn,
            }
            if sync_shadow is not None:
                self._values["sync_shadow"] = sync_shadow

        @builtins.property
        def certificate_arn(self) -> builtins.str:
            '''The ARN of the device certificate for the core.

            This X.509 certificate is used to authenticate the core with AWS IoT and AWS IoT Greengrass services.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinitionversion-core.html#cfn-greengrass-coredefinitionversion-core-certificatearn
            '''
            result = self._values.get("certificate_arn")
            assert result is not None, "Required property 'certificate_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def id(self) -> builtins.str:
            '''A descriptive or arbitrary ID for the core.

            This value must be unique within the core definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinitionversion-core.html#cfn-greengrass-coredefinitionversion-core-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def thing_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the core, which is an AWS IoT device (thing).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinitionversion-core.html#cfn-greengrass-coredefinitionversion-core-thingarn
            '''
            result = self._values.get("thing_arn")
            assert result is not None, "Required property 'thing_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def sync_shadow(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether the core's local shadow is synced with the cloud automatically.

            The default is false.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-coredefinitionversion-core.html#cfn-greengrass-coredefinitionversion-core-syncshadow
            '''
            result = self._values.get("sync_shadow")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CoreProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnCoreDefinitionVersionProps",
    jsii_struct_bases=[],
    name_mapping={"core_definition_id": "coreDefinitionId", "cores": "cores"},
)
class CfnCoreDefinitionVersionProps:
    def __init__(
        self,
        *,
        core_definition_id: builtins.str,
        cores: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnCoreDefinitionVersion.CoreProperty, _IResolvable_da3f097b]]],
    ) -> None:
        '''Properties for defining a ``CfnCoreDefinitionVersion``.

        :param core_definition_id: The ID of the core definition associated with this version. This value is a GUID.
        :param cores: The Greengrass core in this version. Currently, the ``Cores`` property for a core definition version can contain only one core.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinitionversion.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            cfn_core_definition_version_props = greengrass.CfnCoreDefinitionVersionProps(
                core_definition_id="coreDefinitionId",
                cores=[greengrass.CfnCoreDefinitionVersion.CoreProperty(
                    certificate_arn="certificateArn",
                    id="id",
                    thing_arn="thingArn",
            
                    # the properties below are optional
                    sync_shadow=False
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "core_definition_id": core_definition_id,
            "cores": cores,
        }

    @builtins.property
    def core_definition_id(self) -> builtins.str:
        '''The ID of the core definition associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinitionversion.html#cfn-greengrass-coredefinitionversion-coredefinitionid
        '''
        result = self._values.get("core_definition_id")
        assert result is not None, "Required property 'core_definition_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def cores(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCoreDefinitionVersion.CoreProperty, _IResolvable_da3f097b]]]:
        '''The Greengrass core in this version.

        Currently, the ``Cores`` property for a core definition version can contain only one core.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-coredefinitionversion.html#cfn-greengrass-coredefinitionversion-cores
        '''
        result = self._values.get("cores")
        assert result is not None, "Required property 'cores' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCoreDefinitionVersion.CoreProperty, _IResolvable_da3f097b]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnCoreDefinitionVersionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDeviceDefinition(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnDeviceDefinition",
):
    '''A CloudFormation ``AWS::Greengrass::DeviceDefinition``.

    The ``AWS::Greengrass::DeviceDefinition`` resource represents a device definition for AWS IoT Greengrass . Device definitions are used to organize your device definition versions.

    Device definitions can reference multiple device definition versions. All device definition versions must be associated with a device definition. Each device definition version can contain one or more devices.
    .. epigraph::

       When you create a device definition, you can optionally include an initial device definition version. To associate a device definition version later, create an ```AWS::Greengrass::DeviceDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinitionversion.html>`_ resource and specify the ID of this device definition.

       After you create the device definition version that contains the devices you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::DeviceDefinition
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinition.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        # tags: Any
        
        cfn_device_definition = greengrass.CfnDeviceDefinition(self, "MyCfnDeviceDefinition",
            name="name",
        
            # the properties below are optional
            initial_version=greengrass.CfnDeviceDefinition.DeviceDefinitionVersionProperty(
                devices=[greengrass.CfnDeviceDefinition.DeviceProperty(
                    certificate_arn="certificateArn",
                    id="id",
                    thing_arn="thingArn",
        
                    # the properties below are optional
                    sync_shadow=False
                )]
            ),
            tags=tags
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union["CfnDeviceDefinition.DeviceDefinitionVersionProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Greengrass::DeviceDefinition``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the device definition.
        :param initial_version: The device definition version to include when the device definition is created. A device definition version contains a list of ```device`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinition-device.html>`_ property types. .. epigraph:: To associate a device definition version after the device definition is created, create an ```AWS::Greengrass::DeviceDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinitionversion.html>`_ resource and specify the ID of this device definition.
        :param tags: Application-specific metadata to attach to the device definition. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }
        '''
        props = CfnDeviceDefinitionProps(
            name=name, initial_version=initial_version, tags=tags
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
        '''The Amazon Resource Name (ARN) of the ``DeviceDefinition`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/devices/1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the ``DeviceDefinition`` , such as ``1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLatestVersionArn")
    def attr_latest_version_arn(self) -> builtins.str:
        '''The ARN of the last ``DeviceDefinitionVersion`` that was added to the ``DeviceDefinition`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/devices/1234a5b6-78cd-901e-2fgh-3i45j6k178l9/versions/9876ac30-4bdb-4f9d-95af-b5fdb66be1a2`` .

        :cloudformationAttribute: LatestVersionArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLatestVersionArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the device definition.

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
        '''Application-specific metadata to attach to the device definition.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinition.html#cfn-greengrass-devicedefinition-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the device definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinition.html#cfn-greengrass-devicedefinition-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="initialVersion")
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union["CfnDeviceDefinition.DeviceDefinitionVersionProperty", _IResolvable_da3f097b]]:
        '''The device definition version to include when the device definition is created.

        A device definition version contains a list of ```device`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinition-device.html>`_ property types.
        .. epigraph::

           To associate a device definition version after the device definition is created, create an ```AWS::Greengrass::DeviceDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinitionversion.html>`_ resource and specify the ID of this device definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinition.html#cfn-greengrass-devicedefinition-initialversion
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDeviceDefinition.DeviceDefinitionVersionProperty", _IResolvable_da3f097b]], jsii.get(self, "initialVersion"))

    @initial_version.setter
    def initial_version(
        self,
        value: typing.Optional[typing.Union["CfnDeviceDefinition.DeviceDefinitionVersionProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "initialVersion", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnDeviceDefinition.DeviceDefinitionVersionProperty",
        jsii_struct_bases=[],
        name_mapping={"devices": "devices"},
    )
    class DeviceDefinitionVersionProperty:
        def __init__(
            self,
            *,
            devices: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDeviceDefinition.DeviceProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A device definition version contains a list of `devices <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinition-device.html>`_ .

            .. epigraph::

               After you create a device definition version that contains the devices you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

            In an AWS CloudFormation template, ``DeviceDefinitionVersion`` is the property type of the ``InitialVersion`` property in the ```AWS::Greengrass::DeviceDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinition.html>`_ resource.

            :param devices: The devices in this version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinition-devicedefinitionversion.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                device_definition_version_property = greengrass.CfnDeviceDefinition.DeviceDefinitionVersionProperty(
                    devices=[greengrass.CfnDeviceDefinition.DeviceProperty(
                        certificate_arn="certificateArn",
                        id="id",
                        thing_arn="thingArn",
                
                        # the properties below are optional
                        sync_shadow=False
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "devices": devices,
            }

        @builtins.property
        def devices(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDeviceDefinition.DeviceProperty", _IResolvable_da3f097b]]]:
            '''The devices in this version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinition-devicedefinitionversion.html#cfn-greengrass-devicedefinition-devicedefinitionversion-devices
            '''
            result = self._values.get("devices")
            assert result is not None, "Required property 'devices' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDeviceDefinition.DeviceProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DeviceDefinitionVersionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnDeviceDefinition.DeviceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "certificate_arn": "certificateArn",
            "id": "id",
            "thing_arn": "thingArn",
            "sync_shadow": "syncShadow",
        },
    )
    class DeviceProperty:
        def __init__(
            self,
            *,
            certificate_arn: builtins.str,
            id: builtins.str,
            thing_arn: builtins.str,
            sync_shadow: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A device is an AWS IoT device (thing) that's added to a Greengrass group.

            Greengrass devices can communicate with the Greengrass core in the same group. For more information, see `What Is AWS IoT Greengrass ? <https://docs.aws.amazon.com/greengrass/latest/developerguide/what-is-gg.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, the ``Devices`` property of the ```DeviceDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinition-devicedefinitionversion.html>`_ property type contains a list of ``Device`` property types.

            :param certificate_arn: The Amazon Resource Name (ARN) of the device certificate for the device. This X.509 certificate is used to authenticate the device with AWS IoT and AWS IoT Greengrass services.
            :param id: A descriptive or arbitrary ID for the device. This value must be unique within the device definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .
            :param thing_arn: The ARN of the device, which is an AWS IoT device (thing).
            :param sync_shadow: Indicates whether the device's local shadow is synced with the cloud automatically.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinition-device.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                device_property = greengrass.CfnDeviceDefinition.DeviceProperty(
                    certificate_arn="certificateArn",
                    id="id",
                    thing_arn="thingArn",
                
                    # the properties below are optional
                    sync_shadow=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "certificate_arn": certificate_arn,
                "id": id,
                "thing_arn": thing_arn,
            }
            if sync_shadow is not None:
                self._values["sync_shadow"] = sync_shadow

        @builtins.property
        def certificate_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the device certificate for the device.

            This X.509 certificate is used to authenticate the device with AWS IoT and AWS IoT Greengrass services.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinition-device.html#cfn-greengrass-devicedefinition-device-certificatearn
            '''
            result = self._values.get("certificate_arn")
            assert result is not None, "Required property 'certificate_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def id(self) -> builtins.str:
            '''A descriptive or arbitrary ID for the device.

            This value must be unique within the device definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinition-device.html#cfn-greengrass-devicedefinition-device-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def thing_arn(self) -> builtins.str:
            '''The ARN of the device, which is an AWS IoT device (thing).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinition-device.html#cfn-greengrass-devicedefinition-device-thingarn
            '''
            result = self._values.get("thing_arn")
            assert result is not None, "Required property 'thing_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def sync_shadow(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether the device's local shadow is synced with the cloud automatically.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinition-device.html#cfn-greengrass-devicedefinition-device-syncshadow
            '''
            result = self._values.get("sync_shadow")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DeviceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnDeviceDefinitionProps",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "initial_version": "initialVersion", "tags": "tags"},
)
class CfnDeviceDefinitionProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union[CfnDeviceDefinition.DeviceDefinitionVersionProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnDeviceDefinition``.

        :param name: The name of the device definition.
        :param initial_version: The device definition version to include when the device definition is created. A device definition version contains a list of ```device`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinition-device.html>`_ property types. .. epigraph:: To associate a device definition version after the device definition is created, create an ```AWS::Greengrass::DeviceDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinitionversion.html>`_ resource and specify the ID of this device definition.
        :param tags: Application-specific metadata to attach to the device definition. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinition.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            # tags: Any
            
            cfn_device_definition_props = greengrass.CfnDeviceDefinitionProps(
                name="name",
            
                # the properties below are optional
                initial_version=greengrass.CfnDeviceDefinition.DeviceDefinitionVersionProperty(
                    devices=[greengrass.CfnDeviceDefinition.DeviceProperty(
                        certificate_arn="certificateArn",
                        id="id",
                        thing_arn="thingArn",
            
                        # the properties below are optional
                        sync_shadow=False
                    )]
                ),
                tags=tags
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if initial_version is not None:
            self._values["initial_version"] = initial_version
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the device definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinition.html#cfn-greengrass-devicedefinition-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union[CfnDeviceDefinition.DeviceDefinitionVersionProperty, _IResolvable_da3f097b]]:
        '''The device definition version to include when the device definition is created.

        A device definition version contains a list of ```device`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinition-device.html>`_ property types.
        .. epigraph::

           To associate a device definition version after the device definition is created, create an ```AWS::Greengrass::DeviceDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinitionversion.html>`_ resource and specify the ID of this device definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinition.html#cfn-greengrass-devicedefinition-initialversion
        '''
        result = self._values.get("initial_version")
        return typing.cast(typing.Optional[typing.Union[CfnDeviceDefinition.DeviceDefinitionVersionProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''Application-specific metadata to attach to the device definition.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinition.html#cfn-greengrass-devicedefinition-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDeviceDefinitionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDeviceDefinitionVersion(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnDeviceDefinitionVersion",
):
    '''A CloudFormation ``AWS::Greengrass::DeviceDefinitionVersion``.

    The ``AWS::Greengrass::DeviceDefinitionVersion`` resource represents a device definition version for AWS IoT Greengrass . A device definition version contains a list of devices.
    .. epigraph::

       To create a device definition version, you must specify the ID of the device definition that you want to associate with the version. For information about creating a device definition, see ```AWS::Greengrass::DeviceDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinition.html>`_ .

       After you create a device definition version that contains the devices you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::DeviceDefinitionVersion
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinitionversion.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        cfn_device_definition_version = greengrass.CfnDeviceDefinitionVersion(self, "MyCfnDeviceDefinitionVersion",
            device_definition_id="deviceDefinitionId",
            devices=[greengrass.CfnDeviceDefinitionVersion.DeviceProperty(
                certificate_arn="certificateArn",
                id="id",
                thing_arn="thingArn",
        
                # the properties below are optional
                sync_shadow=False
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        device_definition_id: builtins.str,
        devices: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDeviceDefinitionVersion.DeviceProperty", _IResolvable_da3f097b]]],
    ) -> None:
        '''Create a new ``AWS::Greengrass::DeviceDefinitionVersion``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param device_definition_id: The ID of the device definition associated with this version. This value is a GUID.
        :param devices: The devices in this version.
        '''
        props = CfnDeviceDefinitionVersionProps(
            device_definition_id=device_definition_id, devices=devices
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
    @jsii.member(jsii_name="deviceDefinitionId")
    def device_definition_id(self) -> builtins.str:
        '''The ID of the device definition associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinitionversion.html#cfn-greengrass-devicedefinitionversion-devicedefinitionid
        '''
        return typing.cast(builtins.str, jsii.get(self, "deviceDefinitionId"))

    @device_definition_id.setter
    def device_definition_id(self, value: builtins.str) -> None:
        jsii.set(self, "deviceDefinitionId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="devices")
    def devices(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDeviceDefinitionVersion.DeviceProperty", _IResolvable_da3f097b]]]:
        '''The devices in this version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinitionversion.html#cfn-greengrass-devicedefinitionversion-devices
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDeviceDefinitionVersion.DeviceProperty", _IResolvable_da3f097b]]], jsii.get(self, "devices"))

    @devices.setter
    def devices(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDeviceDefinitionVersion.DeviceProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "devices", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnDeviceDefinitionVersion.DeviceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "certificate_arn": "certificateArn",
            "id": "id",
            "thing_arn": "thingArn",
            "sync_shadow": "syncShadow",
        },
    )
    class DeviceProperty:
        def __init__(
            self,
            *,
            certificate_arn: builtins.str,
            id: builtins.str,
            thing_arn: builtins.str,
            sync_shadow: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A device is an AWS IoT device (thing) that's added to a Greengrass group.

            Greengrass devices can communicate with the Greengrass core in the same group. For more information, see `What Is AWS IoT Greengrass ? <https://docs.aws.amazon.com/greengrass/latest/developerguide/what-is-gg.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, the ``Devices`` property of the ```AWS::Greengrass::DeviceDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinitionversion.html>`_ resource contains a list of ``Device`` property types.

            :param certificate_arn: The ARN of the device certificate for the device. This X.509 certificate is used to authenticate the device with AWS IoT and AWS IoT Greengrass services.
            :param id: A descriptive or arbitrary ID for the device. This value must be unique within the device definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .
            :param thing_arn: The Amazon Resource Name (ARN) of the device, which is an AWS IoT device (thing).
            :param sync_shadow: Indicates whether the device's local shadow is synced with the cloud automatically.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinitionversion-device.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                device_property = greengrass.CfnDeviceDefinitionVersion.DeviceProperty(
                    certificate_arn="certificateArn",
                    id="id",
                    thing_arn="thingArn",
                
                    # the properties below are optional
                    sync_shadow=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "certificate_arn": certificate_arn,
                "id": id,
                "thing_arn": thing_arn,
            }
            if sync_shadow is not None:
                self._values["sync_shadow"] = sync_shadow

        @builtins.property
        def certificate_arn(self) -> builtins.str:
            '''The ARN of the device certificate for the device.

            This X.509 certificate is used to authenticate the device with AWS IoT and AWS IoT Greengrass services.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinitionversion-device.html#cfn-greengrass-devicedefinitionversion-device-certificatearn
            '''
            result = self._values.get("certificate_arn")
            assert result is not None, "Required property 'certificate_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def id(self) -> builtins.str:
            '''A descriptive or arbitrary ID for the device.

            This value must be unique within the device definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinitionversion-device.html#cfn-greengrass-devicedefinitionversion-device-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def thing_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the device, which is an AWS IoT device (thing).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinitionversion-device.html#cfn-greengrass-devicedefinitionversion-device-thingarn
            '''
            result = self._values.get("thing_arn")
            assert result is not None, "Required property 'thing_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def sync_shadow(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether the device's local shadow is synced with the cloud automatically.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-devicedefinitionversion-device.html#cfn-greengrass-devicedefinitionversion-device-syncshadow
            '''
            result = self._values.get("sync_shadow")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DeviceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnDeviceDefinitionVersionProps",
    jsii_struct_bases=[],
    name_mapping={"device_definition_id": "deviceDefinitionId", "devices": "devices"},
)
class CfnDeviceDefinitionVersionProps:
    def __init__(
        self,
        *,
        device_definition_id: builtins.str,
        devices: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnDeviceDefinitionVersion.DeviceProperty, _IResolvable_da3f097b]]],
    ) -> None:
        '''Properties for defining a ``CfnDeviceDefinitionVersion``.

        :param device_definition_id: The ID of the device definition associated with this version. This value is a GUID.
        :param devices: The devices in this version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinitionversion.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            cfn_device_definition_version_props = greengrass.CfnDeviceDefinitionVersionProps(
                device_definition_id="deviceDefinitionId",
                devices=[greengrass.CfnDeviceDefinitionVersion.DeviceProperty(
                    certificate_arn="certificateArn",
                    id="id",
                    thing_arn="thingArn",
            
                    # the properties below are optional
                    sync_shadow=False
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "device_definition_id": device_definition_id,
            "devices": devices,
        }

    @builtins.property
    def device_definition_id(self) -> builtins.str:
        '''The ID of the device definition associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinitionversion.html#cfn-greengrass-devicedefinitionversion-devicedefinitionid
        '''
        result = self._values.get("device_definition_id")
        assert result is not None, "Required property 'device_definition_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def devices(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDeviceDefinitionVersion.DeviceProperty, _IResolvable_da3f097b]]]:
        '''The devices in this version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-devicedefinitionversion.html#cfn-greengrass-devicedefinitionversion-devices
        '''
        result = self._values.get("devices")
        assert result is not None, "Required property 'devices' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDeviceDefinitionVersion.DeviceProperty, _IResolvable_da3f097b]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDeviceDefinitionVersionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnFunctionDefinition(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinition",
):
    '''A CloudFormation ``AWS::Greengrass::FunctionDefinition``.

    The ``AWS::Greengrass::FunctionDefinition`` resource represents a function definition for AWS IoT Greengrass . Function definitions are used to organize your function definition versions.

    Function definitions can reference multiple function definition versions. All function definition versions must be associated with a function definition. Each function definition version can contain one or more functions.
    .. epigraph::

       When you create a function definition, you can optionally include an initial function definition version. To associate a function definition version later, create an ```AWS::Greengrass::FunctionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html>`_ resource and specify the ID of this function definition.

       After you create the function definition version that contains the functions you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::FunctionDefinition
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinition.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        # tags: Any
        # variables: Any
        
        cfn_function_definition = greengrass.CfnFunctionDefinition(self, "MyCfnFunctionDefinition",
            name="name",
        
            # the properties below are optional
            initial_version=greengrass.CfnFunctionDefinition.FunctionDefinitionVersionProperty(
                functions=[greengrass.CfnFunctionDefinition.FunctionProperty(
                    function_arn="functionArn",
                    function_configuration=greengrass.CfnFunctionDefinition.FunctionConfigurationProperty(
                        encoding_type="encodingType",
                        environment=greengrass.CfnFunctionDefinition.EnvironmentProperty(
                            access_sysfs=False,
                            execution=greengrass.CfnFunctionDefinition.ExecutionProperty(
                                isolation_mode="isolationMode",
                                run_as=greengrass.CfnFunctionDefinition.RunAsProperty(
                                    gid=123,
                                    uid=123
                                )
                            ),
                            resource_access_policies=[greengrass.CfnFunctionDefinition.ResourceAccessPolicyProperty(
                                resource_id="resourceId",
        
                                # the properties below are optional
                                permission="permission"
                            )],
                            variables=variables
                        ),
                        exec_args="execArgs",
                        executable="executable",
                        memory_size=123,
                        pinned=False,
                        timeout=123
                    ),
                    id="id"
                )],
        
                # the properties below are optional
                default_config=greengrass.CfnFunctionDefinition.DefaultConfigProperty(
                    execution=greengrass.CfnFunctionDefinition.ExecutionProperty(
                        isolation_mode="isolationMode",
                        run_as=greengrass.CfnFunctionDefinition.RunAsProperty(
                            gid=123,
                            uid=123
                        )
                    )
                )
            ),
            tags=tags
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union["CfnFunctionDefinition.FunctionDefinitionVersionProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Greengrass::FunctionDefinition``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the function definition.
        :param initial_version: The function definition version to include when the function definition is created. A function definition version contains a list of ```function`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-function.html>`_ property types. .. epigraph:: To associate a function definition version after the function definition is created, create an ```AWS::Greengrass::FunctionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html>`_ resource and specify the ID of this function definition.
        :param tags: Application-specific metadata to attach to the function definition. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }
        '''
        props = CfnFunctionDefinitionProps(
            name=name, initial_version=initial_version, tags=tags
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
        '''The Amazon Resource Name (ARN) of the ``FunctionDefinition`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/functions/1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the ``FunctionDefinition`` , such as ``1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLatestVersionArn")
    def attr_latest_version_arn(self) -> builtins.str:
        '''The ARN of the last ``FunctionDefinitionVersion`` that was added to the ``FunctionDefinition`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/functions/1234a5b6-78cd-901e-2fgh-3i45j6k178l9/versions/9876ac30-4bdb-4f9d-95af-b5fdb66be1a2`` .

        :cloudformationAttribute: LatestVersionArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLatestVersionArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the ``FunctionDefinition`` , such as ``MyFunctionDefinition`` .

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
        '''Application-specific metadata to attach to the function definition.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinition.html#cfn-greengrass-functiondefinition-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the function definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinition.html#cfn-greengrass-functiondefinition-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="initialVersion")
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union["CfnFunctionDefinition.FunctionDefinitionVersionProperty", _IResolvable_da3f097b]]:
        '''The function definition version to include when the function definition is created.

        A function definition version contains a list of ```function`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-function.html>`_ property types.
        .. epigraph::

           To associate a function definition version after the function definition is created, create an ```AWS::Greengrass::FunctionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html>`_ resource and specify the ID of this function definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinition.html#cfn-greengrass-functiondefinition-initialversion
        '''
        return typing.cast(typing.Optional[typing.Union["CfnFunctionDefinition.FunctionDefinitionVersionProperty", _IResolvable_da3f097b]], jsii.get(self, "initialVersion"))

    @initial_version.setter
    def initial_version(
        self,
        value: typing.Optional[typing.Union["CfnFunctionDefinition.FunctionDefinitionVersionProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "initialVersion", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinition.DefaultConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"execution": "execution"},
    )
    class DefaultConfigProperty:
        def __init__(
            self,
            *,
            execution: typing.Union["CfnFunctionDefinition.ExecutionProperty", _IResolvable_da3f097b],
        ) -> None:
            '''The default configuration that applies to all Lambda functions in the function definition version.

            Individual Lambda functions can override these settings.

            In an AWS CloudFormation template, ``DefaultConfig`` is a property of the ```FunctionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-functiondefinitionversion.html>`_ property type.

            :param execution: Configuration settings for the Lambda execution environment on the AWS IoT Greengrass core.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-defaultconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                default_config_property = greengrass.CfnFunctionDefinition.DefaultConfigProperty(
                    execution=greengrass.CfnFunctionDefinition.ExecutionProperty(
                        isolation_mode="isolationMode",
                        run_as=greengrass.CfnFunctionDefinition.RunAsProperty(
                            gid=123,
                            uid=123
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "execution": execution,
            }

        @builtins.property
        def execution(
            self,
        ) -> typing.Union["CfnFunctionDefinition.ExecutionProperty", _IResolvable_da3f097b]:
            '''Configuration settings for the Lambda execution environment on the AWS IoT Greengrass core.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-defaultconfig.html#cfn-greengrass-functiondefinition-defaultconfig-execution
            '''
            result = self._values.get("execution")
            assert result is not None, "Required property 'execution' is missing"
            return typing.cast(typing.Union["CfnFunctionDefinition.ExecutionProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DefaultConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinition.EnvironmentProperty",
        jsii_struct_bases=[],
        name_mapping={
            "access_sysfs": "accessSysfs",
            "execution": "execution",
            "resource_access_policies": "resourceAccessPolicies",
            "variables": "variables",
        },
    )
    class EnvironmentProperty:
        def __init__(
            self,
            *,
            access_sysfs: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            execution: typing.Optional[typing.Union["CfnFunctionDefinition.ExecutionProperty", _IResolvable_da3f097b]] = None,
            resource_access_policies: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFunctionDefinition.ResourceAccessPolicyProperty", _IResolvable_da3f097b]]]] = None,
            variables: typing.Any = None,
        ) -> None:
            '''The environment configuration for a Lambda function on the AWS IoT Greengrass core.

            In an AWS CloudFormation template, ``Environment`` is a property of the ```FunctionConfiguration`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-functionconfiguration.html>`_ property type.

            :param access_sysfs: Indicates whether the function is allowed to access the ``/sys`` directory on the core device, which allows the read device information from ``/sys`` . .. epigraph:: This property applies only to Lambda functions that run in a Greengrass container.
            :param execution: Settings for the Lambda execution environment in AWS IoT Greengrass .
            :param resource_access_policies: A list of the `resources <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourceinstance.html>`_ in the group that the function can access, with the corresponding read-only or read-write permissions. The maximum is 10 resources. .. epigraph:: This property applies only for Lambda functions that run in a Greengrass container.
            :param variables: Environment variables for the Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-environment.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                # variables: Any
                
                environment_property = greengrass.CfnFunctionDefinition.EnvironmentProperty(
                    access_sysfs=False,
                    execution=greengrass.CfnFunctionDefinition.ExecutionProperty(
                        isolation_mode="isolationMode",
                        run_as=greengrass.CfnFunctionDefinition.RunAsProperty(
                            gid=123,
                            uid=123
                        )
                    ),
                    resource_access_policies=[greengrass.CfnFunctionDefinition.ResourceAccessPolicyProperty(
                        resource_id="resourceId",
                
                        # the properties below are optional
                        permission="permission"
                    )],
                    variables=variables
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if access_sysfs is not None:
                self._values["access_sysfs"] = access_sysfs
            if execution is not None:
                self._values["execution"] = execution
            if resource_access_policies is not None:
                self._values["resource_access_policies"] = resource_access_policies
            if variables is not None:
                self._values["variables"] = variables

        @builtins.property
        def access_sysfs(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether the function is allowed to access the ``/sys`` directory on the core device, which allows the read device information from ``/sys`` .

            .. epigraph::

               This property applies only to Lambda functions that run in a Greengrass container.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-environment.html#cfn-greengrass-functiondefinition-environment-accesssysfs
            '''
            result = self._values.get("access_sysfs")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def execution(
            self,
        ) -> typing.Optional[typing.Union["CfnFunctionDefinition.ExecutionProperty", _IResolvable_da3f097b]]:
            '''Settings for the Lambda execution environment in AWS IoT Greengrass .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-environment.html#cfn-greengrass-functiondefinition-environment-execution
            '''
            result = self._values.get("execution")
            return typing.cast(typing.Optional[typing.Union["CfnFunctionDefinition.ExecutionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def resource_access_policies(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFunctionDefinition.ResourceAccessPolicyProperty", _IResolvable_da3f097b]]]]:
            '''A list of the `resources <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourceinstance.html>`_ in the group that the function can access, with the corresponding read-only or read-write permissions. The maximum is 10 resources.

            .. epigraph::

               This property applies only for Lambda functions that run in a Greengrass container.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-environment.html#cfn-greengrass-functiondefinition-environment-resourceaccesspolicies
            '''
            result = self._values.get("resource_access_policies")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFunctionDefinition.ResourceAccessPolicyProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def variables(self) -> typing.Any:
            '''Environment variables for the Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-environment.html#cfn-greengrass-functiondefinition-environment-variables
            '''
            result = self._values.get("variables")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EnvironmentProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinition.ExecutionProperty",
        jsii_struct_bases=[],
        name_mapping={"isolation_mode": "isolationMode", "run_as": "runAs"},
    )
    class ExecutionProperty:
        def __init__(
            self,
            *,
            isolation_mode: typing.Optional[builtins.str] = None,
            run_as: typing.Optional[typing.Union["CfnFunctionDefinition.RunAsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Configuration settings for the Lambda execution environment on the AWS IoT Greengrass core.

            In an AWS CloudFormation template, ``Execution`` is a property of the ```DefaultConfig`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-defaultconfig.html>`_ property type for a function definition version and the ```Environment`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-environment.html>`_ property type for a function.

            :param isolation_mode: The containerization that the Lambda function runs in. Valid values are ``GreengrassContainer`` or ``NoContainer`` . Typically, this is ``GreengrassContainer`` . For more information, see `Containerization <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-function-containerization>`_ in the *Developer Guide* . - When set on the ```DefaultConfig`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-defaultconfig.html>`_ property of a function definition version, this setting is used as the default containerization for all Lambda functions in the function definition version. - When set on the ```Environment`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html>`_ property of a function, this setting applies to the individual function and overrides the default. Omit this value to run the function with the default containerization. .. epigraph:: We recommend that you run in a Greengrass container unless your business case requires that you run without containerization.
            :param run_as: The user and group permissions used to run the Lambda function. Typically, this is the ggc_user and ggc_group. For more information, see `Run as <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-access-identity.html>`_ in the *Developer Guide* . - When set on the ```DefaultConfig`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-defaultconfig.html>`_ property of a function definition version, this setting is used as the default access identity for all Lambda functions in the function definition version. - When set on the ```Environment`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html>`_ property of a function, this setting applies to the individual function and overrides the default. You can override the user, group, or both. Omit this value to run the function with the default permissions. .. epigraph:: Running as the root user increases risks to your data and device. Do not run as root (UID/GID=0) unless your business case requires it. For more information and requirements, see `Running a Lambda Function as Root <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-running-as-root>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-execution.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                execution_property = greengrass.CfnFunctionDefinition.ExecutionProperty(
                    isolation_mode="isolationMode",
                    run_as=greengrass.CfnFunctionDefinition.RunAsProperty(
                        gid=123,
                        uid=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if isolation_mode is not None:
                self._values["isolation_mode"] = isolation_mode
            if run_as is not None:
                self._values["run_as"] = run_as

        @builtins.property
        def isolation_mode(self) -> typing.Optional[builtins.str]:
            '''The containerization that the Lambda function runs in.

            Valid values are ``GreengrassContainer`` or ``NoContainer`` . Typically, this is ``GreengrassContainer`` . For more information, see `Containerization <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-function-containerization>`_ in the *Developer Guide* .

            - When set on the ```DefaultConfig`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-defaultconfig.html>`_ property of a function definition version, this setting is used as the default containerization for all Lambda functions in the function definition version.
            - When set on the ```Environment`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html>`_ property of a function, this setting applies to the individual function and overrides the default. Omit this value to run the function with the default containerization.

            .. epigraph::

               We recommend that you run in a Greengrass container unless your business case requires that you run without containerization.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-execution.html#cfn-greengrass-functiondefinition-execution-isolationmode
            '''
            result = self._values.get("isolation_mode")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def run_as(
            self,
        ) -> typing.Optional[typing.Union["CfnFunctionDefinition.RunAsProperty", _IResolvable_da3f097b]]:
            '''The user and group permissions used to run the Lambda function.

            Typically, this is the ggc_user and ggc_group. For more information, see `Run as <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-access-identity.html>`_ in the *Developer Guide* .

            - When set on the ```DefaultConfig`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-defaultconfig.html>`_ property of a function definition version, this setting is used as the default access identity for all Lambda functions in the function definition version.
            - When set on the ```Environment`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html>`_ property of a function, this setting applies to the individual function and overrides the default. You can override the user, group, or both. Omit this value to run the function with the default permissions.

            .. epigraph::

               Running as the root user increases risks to your data and device. Do not run as root (UID/GID=0) unless your business case requires it. For more information and requirements, see `Running a Lambda Function as Root <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-running-as-root>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-execution.html#cfn-greengrass-functiondefinition-execution-runas
            '''
            result = self._values.get("run_as")
            return typing.cast(typing.Optional[typing.Union["CfnFunctionDefinition.RunAsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ExecutionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinition.FunctionConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "encoding_type": "encodingType",
            "environment": "environment",
            "exec_args": "execArgs",
            "executable": "executable",
            "memory_size": "memorySize",
            "pinned": "pinned",
            "timeout": "timeout",
        },
    )
    class FunctionConfigurationProperty:
        def __init__(
            self,
            *,
            encoding_type: typing.Optional[builtins.str] = None,
            environment: typing.Optional[typing.Union["CfnFunctionDefinition.EnvironmentProperty", _IResolvable_da3f097b]] = None,
            exec_args: typing.Optional[builtins.str] = None,
            executable: typing.Optional[builtins.str] = None,
            memory_size: typing.Optional[jsii.Number] = None,
            pinned: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            timeout: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The group-specific configuration settings for a Lambda function.

            These settings configure the function's behavior in the Greengrass group. For more information, see `Controlling Execution of Greengrass Lambda Functions by Using Group-Specific Configuration <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, ``FunctionConfiguration`` is a property of the ```Function`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-function.html>`_ property type.

            :param encoding_type: The expected encoding type of the input payload for the function. Valid values are ``json`` (default) and ``binary`` .
            :param environment: The environment configuration of the function.
            :param exec_args: The execution arguments.
            :param executable: The name of the function executable.
            :param memory_size: The memory size (in KB) required by the function. .. epigraph:: This property applies only to Lambda functions that run in a Greengrass container.
            :param pinned: Indicates whether the function is pinned (or *long-lived* ). Pinned functions start when the core starts and process all requests in the same container. The default value is false.
            :param timeout: The allowed execution time (in seconds) after which the function should terminate. For pinned functions, this timeout applies for each request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-functionconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                # variables: Any
                
                function_configuration_property = greengrass.CfnFunctionDefinition.FunctionConfigurationProperty(
                    encoding_type="encodingType",
                    environment=greengrass.CfnFunctionDefinition.EnvironmentProperty(
                        access_sysfs=False,
                        execution=greengrass.CfnFunctionDefinition.ExecutionProperty(
                            isolation_mode="isolationMode",
                            run_as=greengrass.CfnFunctionDefinition.RunAsProperty(
                                gid=123,
                                uid=123
                            )
                        ),
                        resource_access_policies=[greengrass.CfnFunctionDefinition.ResourceAccessPolicyProperty(
                            resource_id="resourceId",
                
                            # the properties below are optional
                            permission="permission"
                        )],
                        variables=variables
                    ),
                    exec_args="execArgs",
                    executable="executable",
                    memory_size=123,
                    pinned=False,
                    timeout=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if encoding_type is not None:
                self._values["encoding_type"] = encoding_type
            if environment is not None:
                self._values["environment"] = environment
            if exec_args is not None:
                self._values["exec_args"] = exec_args
            if executable is not None:
                self._values["executable"] = executable
            if memory_size is not None:
                self._values["memory_size"] = memory_size
            if pinned is not None:
                self._values["pinned"] = pinned
            if timeout is not None:
                self._values["timeout"] = timeout

        @builtins.property
        def encoding_type(self) -> typing.Optional[builtins.str]:
            '''The expected encoding type of the input payload for the function.

            Valid values are ``json`` (default) and ``binary`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-functionconfiguration.html#cfn-greengrass-functiondefinition-functionconfiguration-encodingtype
            '''
            result = self._values.get("encoding_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def environment(
            self,
        ) -> typing.Optional[typing.Union["CfnFunctionDefinition.EnvironmentProperty", _IResolvable_da3f097b]]:
            '''The environment configuration of the function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-functionconfiguration.html#cfn-greengrass-functiondefinition-functionconfiguration-environment
            '''
            result = self._values.get("environment")
            return typing.cast(typing.Optional[typing.Union["CfnFunctionDefinition.EnvironmentProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def exec_args(self) -> typing.Optional[builtins.str]:
            '''The execution arguments.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-functionconfiguration.html#cfn-greengrass-functiondefinition-functionconfiguration-execargs
            '''
            result = self._values.get("exec_args")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def executable(self) -> typing.Optional[builtins.str]:
            '''The name of the function executable.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-functionconfiguration.html#cfn-greengrass-functiondefinition-functionconfiguration-executable
            '''
            result = self._values.get("executable")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def memory_size(self) -> typing.Optional[jsii.Number]:
            '''The memory size (in KB) required by the function.

            .. epigraph::

               This property applies only to Lambda functions that run in a Greengrass container.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-functionconfiguration.html#cfn-greengrass-functiondefinition-functionconfiguration-memorysize
            '''
            result = self._values.get("memory_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def pinned(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether the function is pinned (or *long-lived* ).

            Pinned functions start when the core starts and process all requests in the same container. The default value is false.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-functionconfiguration.html#cfn-greengrass-functiondefinition-functionconfiguration-pinned
            '''
            result = self._values.get("pinned")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def timeout(self) -> typing.Optional[jsii.Number]:
            '''The allowed execution time (in seconds) after which the function should terminate.

            For pinned functions, this timeout applies for each request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-functionconfiguration.html#cfn-greengrass-functiondefinition-functionconfiguration-timeout
            '''
            result = self._values.get("timeout")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FunctionConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinition.FunctionDefinitionVersionProperty",
        jsii_struct_bases=[],
        name_mapping={"functions": "functions", "default_config": "defaultConfig"},
    )
    class FunctionDefinitionVersionProperty:
        def __init__(
            self,
            *,
            functions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFunctionDefinition.FunctionProperty", _IResolvable_da3f097b]]],
            default_config: typing.Optional[typing.Union["CfnFunctionDefinition.DefaultConfigProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A function definition version contains a list of functions.

            .. epigraph::

               After you create a function definition version that contains the functions you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

            In an AWS CloudFormation template, ``FunctionDefinitionVersion`` is the property type of the ``InitialVersion`` property in the ```AWS::Greengrass::FunctionDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinition.html>`_ resource.

            :param functions: The functions in this version.
            :param default_config: The default configuration that applies to all Lambda functions in the group. Individual Lambda functions can override these settings.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-functiondefinitionversion.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                # variables: Any
                
                function_definition_version_property = greengrass.CfnFunctionDefinition.FunctionDefinitionVersionProperty(
                    functions=[greengrass.CfnFunctionDefinition.FunctionProperty(
                        function_arn="functionArn",
                        function_configuration=greengrass.CfnFunctionDefinition.FunctionConfigurationProperty(
                            encoding_type="encodingType",
                            environment=greengrass.CfnFunctionDefinition.EnvironmentProperty(
                                access_sysfs=False,
                                execution=greengrass.CfnFunctionDefinition.ExecutionProperty(
                                    isolation_mode="isolationMode",
                                    run_as=greengrass.CfnFunctionDefinition.RunAsProperty(
                                        gid=123,
                                        uid=123
                                    )
                                ),
                                resource_access_policies=[greengrass.CfnFunctionDefinition.ResourceAccessPolicyProperty(
                                    resource_id="resourceId",
                
                                    # the properties below are optional
                                    permission="permission"
                                )],
                                variables=variables
                            ),
                            exec_args="execArgs",
                            executable="executable",
                            memory_size=123,
                            pinned=False,
                            timeout=123
                        ),
                        id="id"
                    )],
                
                    # the properties below are optional
                    default_config=greengrass.CfnFunctionDefinition.DefaultConfigProperty(
                        execution=greengrass.CfnFunctionDefinition.ExecutionProperty(
                            isolation_mode="isolationMode",
                            run_as=greengrass.CfnFunctionDefinition.RunAsProperty(
                                gid=123,
                                uid=123
                            )
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "functions": functions,
            }
            if default_config is not None:
                self._values["default_config"] = default_config

        @builtins.property
        def functions(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFunctionDefinition.FunctionProperty", _IResolvable_da3f097b]]]:
            '''The functions in this version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-functiondefinitionversion.html#cfn-greengrass-functiondefinition-functiondefinitionversion-functions
            '''
            result = self._values.get("functions")
            assert result is not None, "Required property 'functions' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFunctionDefinition.FunctionProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def default_config(
            self,
        ) -> typing.Optional[typing.Union["CfnFunctionDefinition.DefaultConfigProperty", _IResolvable_da3f097b]]:
            '''The default configuration that applies to all Lambda functions in the group.

            Individual Lambda functions can override these settings.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-functiondefinitionversion.html#cfn-greengrass-functiondefinition-functiondefinitionversion-defaultconfig
            '''
            result = self._values.get("default_config")
            return typing.cast(typing.Optional[typing.Union["CfnFunctionDefinition.DefaultConfigProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FunctionDefinitionVersionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinition.FunctionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "function_arn": "functionArn",
            "function_configuration": "functionConfiguration",
            "id": "id",
        },
    )
    class FunctionProperty:
        def __init__(
            self,
            *,
            function_arn: builtins.str,
            function_configuration: typing.Union["CfnFunctionDefinition.FunctionConfigurationProperty", _IResolvable_da3f097b],
            id: builtins.str,
        ) -> None:
            '''A function is a Lambda function that's referenced from an AWS IoT Greengrass group.

            The function is deployed to a Greengrass core where it runs locally. For more information, see `Run Lambda Functions on the AWS IoT Greengrass Core <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-functions.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, the ``Functions`` property of the ```FunctionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-functiondefinitionversion.html>`_ property type contains a list of ``Function`` property types.

            :param function_arn: The Amazon Resource Name (ARN) of the alias (recommended) or version of the referenced Lambda function.
            :param function_configuration: The group-specific settings of the Lambda function. These settings configure the function's behavior in the Greengrass group.
            :param id: A descriptive or arbitrary ID for the function. This value must be unique within the function definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-function.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                # variables: Any
                
                function_property = greengrass.CfnFunctionDefinition.FunctionProperty(
                    function_arn="functionArn",
                    function_configuration=greengrass.CfnFunctionDefinition.FunctionConfigurationProperty(
                        encoding_type="encodingType",
                        environment=greengrass.CfnFunctionDefinition.EnvironmentProperty(
                            access_sysfs=False,
                            execution=greengrass.CfnFunctionDefinition.ExecutionProperty(
                                isolation_mode="isolationMode",
                                run_as=greengrass.CfnFunctionDefinition.RunAsProperty(
                                    gid=123,
                                    uid=123
                                )
                            ),
                            resource_access_policies=[greengrass.CfnFunctionDefinition.ResourceAccessPolicyProperty(
                                resource_id="resourceId",
                
                                # the properties below are optional
                                permission="permission"
                            )],
                            variables=variables
                        ),
                        exec_args="execArgs",
                        executable="executable",
                        memory_size=123,
                        pinned=False,
                        timeout=123
                    ),
                    id="id"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "function_arn": function_arn,
                "function_configuration": function_configuration,
                "id": id,
            }

        @builtins.property
        def function_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the alias (recommended) or version of the referenced Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-function.html#cfn-greengrass-functiondefinition-function-functionarn
            '''
            result = self._values.get("function_arn")
            assert result is not None, "Required property 'function_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def function_configuration(
            self,
        ) -> typing.Union["CfnFunctionDefinition.FunctionConfigurationProperty", _IResolvable_da3f097b]:
            '''The group-specific settings of the Lambda function.

            These settings configure the function's behavior in the Greengrass group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-function.html#cfn-greengrass-functiondefinition-function-functionconfiguration
            '''
            result = self._values.get("function_configuration")
            assert result is not None, "Required property 'function_configuration' is missing"
            return typing.cast(typing.Union["CfnFunctionDefinition.FunctionConfigurationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def id(self) -> builtins.str:
            '''A descriptive or arbitrary ID for the function.

            This value must be unique within the function definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-function.html#cfn-greengrass-functiondefinition-function-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FunctionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinition.ResourceAccessPolicyProperty",
        jsii_struct_bases=[],
        name_mapping={"resource_id": "resourceId", "permission": "permission"},
    )
    class ResourceAccessPolicyProperty:
        def __init__(
            self,
            *,
            resource_id: builtins.str,
            permission: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A list of the `resources <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourceinstance.html>`_ in the group that the function can access, with the corresponding read-only or read-write permissions. The maximum is 10 resources.

            .. epigraph::

               This property applies only to Lambda functions that run in a Greengrass container.

            In an AWS CloudFormation template, ``ResourceAccessPolicy`` is a property of the ```Environment`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-environment.html>`_ property type.

            :param resource_id: The ID of the resource. This ID is assigned to the resource when you create the resource definition.
            :param permission: The read-only or read-write access that the Lambda function has to the resource. Valid values are ``ro`` or ``rw`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-resourceaccesspolicy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                resource_access_policy_property = greengrass.CfnFunctionDefinition.ResourceAccessPolicyProperty(
                    resource_id="resourceId",
                
                    # the properties below are optional
                    permission="permission"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "resource_id": resource_id,
            }
            if permission is not None:
                self._values["permission"] = permission

        @builtins.property
        def resource_id(self) -> builtins.str:
            '''The ID of the resource.

            This ID is assigned to the resource when you create the resource definition.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-resourceaccesspolicy.html#cfn-greengrass-functiondefinition-resourceaccesspolicy-resourceid
            '''
            result = self._values.get("resource_id")
            assert result is not None, "Required property 'resource_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def permission(self) -> typing.Optional[builtins.str]:
            '''The read-only or read-write access that the Lambda function has to the resource.

            Valid values are ``ro`` or ``rw`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-resourceaccesspolicy.html#cfn-greengrass-functiondefinition-resourceaccesspolicy-permission
            '''
            result = self._values.get("permission")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourceAccessPolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinition.RunAsProperty",
        jsii_struct_bases=[],
        name_mapping={"gid": "gid", "uid": "uid"},
    )
    class RunAsProperty:
        def __init__(
            self,
            *,
            gid: typing.Optional[jsii.Number] = None,
            uid: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The access identity whose permissions are used to run the Lambda function.

            This setting overrides the default access identity that's specified for the group (by default, ggc_user and ggc_group). You can override the user, group, or both. For more information, see `Run as <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-access-identity.html>`_ in the *Developer Guide* .
            .. epigraph::

               Running as the root user increases risks to your data and device. Do not run as root (UID/GID=0) unless your business case requires it. For more information and requirements, see `Running a Lambda Function as Root <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-running-as-root>`_ .

            In an AWS CloudFormation template, ``RunAs`` is a property of the ```Execution`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-execution.html>`_ property type.

            :param gid: The group ID whose permissions are used to run the Lambda function. You can use the ``getent group`` command on your core device to look up the group ID.
            :param uid: The user ID whose permissions are used to run the Lambda function. You can use the ``getent passwd`` command on your core device to look up the user ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-runas.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                run_as_property = greengrass.CfnFunctionDefinition.RunAsProperty(
                    gid=123,
                    uid=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if gid is not None:
                self._values["gid"] = gid
            if uid is not None:
                self._values["uid"] = uid

        @builtins.property
        def gid(self) -> typing.Optional[jsii.Number]:
            '''The group ID whose permissions are used to run the Lambda function.

            You can use the ``getent group`` command on your core device to look up the group ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-runas.html#cfn-greengrass-functiondefinition-runas-gid
            '''
            result = self._values.get("gid")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def uid(self) -> typing.Optional[jsii.Number]:
            '''The user ID whose permissions are used to run the Lambda function.

            You can use the ``getent passwd`` command on your core device to look up the user ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-runas.html#cfn-greengrass-functiondefinition-runas-uid
            '''
            result = self._values.get("uid")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RunAsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinitionProps",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "initial_version": "initialVersion", "tags": "tags"},
)
class CfnFunctionDefinitionProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union[CfnFunctionDefinition.FunctionDefinitionVersionProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnFunctionDefinition``.

        :param name: The name of the function definition.
        :param initial_version: The function definition version to include when the function definition is created. A function definition version contains a list of ```function`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-function.html>`_ property types. .. epigraph:: To associate a function definition version after the function definition is created, create an ```AWS::Greengrass::FunctionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html>`_ resource and specify the ID of this function definition.
        :param tags: Application-specific metadata to attach to the function definition. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinition.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            # tags: Any
            # variables: Any
            
            cfn_function_definition_props = greengrass.CfnFunctionDefinitionProps(
                name="name",
            
                # the properties below are optional
                initial_version=greengrass.CfnFunctionDefinition.FunctionDefinitionVersionProperty(
                    functions=[greengrass.CfnFunctionDefinition.FunctionProperty(
                        function_arn="functionArn",
                        function_configuration=greengrass.CfnFunctionDefinition.FunctionConfigurationProperty(
                            encoding_type="encodingType",
                            environment=greengrass.CfnFunctionDefinition.EnvironmentProperty(
                                access_sysfs=False,
                                execution=greengrass.CfnFunctionDefinition.ExecutionProperty(
                                    isolation_mode="isolationMode",
                                    run_as=greengrass.CfnFunctionDefinition.RunAsProperty(
                                        gid=123,
                                        uid=123
                                    )
                                ),
                                resource_access_policies=[greengrass.CfnFunctionDefinition.ResourceAccessPolicyProperty(
                                    resource_id="resourceId",
            
                                    # the properties below are optional
                                    permission="permission"
                                )],
                                variables=variables
                            ),
                            exec_args="execArgs",
                            executable="executable",
                            memory_size=123,
                            pinned=False,
                            timeout=123
                        ),
                        id="id"
                    )],
            
                    # the properties below are optional
                    default_config=greengrass.CfnFunctionDefinition.DefaultConfigProperty(
                        execution=greengrass.CfnFunctionDefinition.ExecutionProperty(
                            isolation_mode="isolationMode",
                            run_as=greengrass.CfnFunctionDefinition.RunAsProperty(
                                gid=123,
                                uid=123
                            )
                        )
                    )
                ),
                tags=tags
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if initial_version is not None:
            self._values["initial_version"] = initial_version
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the function definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinition.html#cfn-greengrass-functiondefinition-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union[CfnFunctionDefinition.FunctionDefinitionVersionProperty, _IResolvable_da3f097b]]:
        '''The function definition version to include when the function definition is created.

        A function definition version contains a list of ```function`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinition-function.html>`_ property types.
        .. epigraph::

           To associate a function definition version after the function definition is created, create an ```AWS::Greengrass::FunctionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html>`_ resource and specify the ID of this function definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinition.html#cfn-greengrass-functiondefinition-initialversion
        '''
        result = self._values.get("initial_version")
        return typing.cast(typing.Optional[typing.Union[CfnFunctionDefinition.FunctionDefinitionVersionProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''Application-specific metadata to attach to the function definition.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinition.html#cfn-greengrass-functiondefinition-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnFunctionDefinitionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnFunctionDefinitionVersion(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinitionVersion",
):
    '''A CloudFormation ``AWS::Greengrass::FunctionDefinitionVersion``.

    The ``AWS::Greengrass::FunctionDefinitionVersion`` resource represents a function definition version for AWS IoT Greengrass . A function definition version contains contain a list of functions.
    .. epigraph::

       To create a function definition version, you must specify the ID of the function definition that you want to associate with the version. For information about creating a function definition, see ```AWS::Greengrass::FunctionDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinition.html>`_ .

       After you create a function definition version that contains the functions you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::FunctionDefinitionVersion
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        # variables: Any
        
        cfn_function_definition_version = greengrass.CfnFunctionDefinitionVersion(self, "MyCfnFunctionDefinitionVersion",
            function_definition_id="functionDefinitionId",
            functions=[greengrass.CfnFunctionDefinitionVersion.FunctionProperty(
                function_arn="functionArn",
                function_configuration=greengrass.CfnFunctionDefinitionVersion.FunctionConfigurationProperty(
                    encoding_type="encodingType",
                    environment=greengrass.CfnFunctionDefinitionVersion.EnvironmentProperty(
                        access_sysfs=False,
                        execution=greengrass.CfnFunctionDefinitionVersion.ExecutionProperty(
                            isolation_mode="isolationMode",
                            run_as=greengrass.CfnFunctionDefinitionVersion.RunAsProperty(
                                gid=123,
                                uid=123
                            )
                        ),
                        resource_access_policies=[greengrass.CfnFunctionDefinitionVersion.ResourceAccessPolicyProperty(
                            resource_id="resourceId",
        
                            # the properties below are optional
                            permission="permission"
                        )],
                        variables=variables
                    ),
                    exec_args="execArgs",
                    executable="executable",
                    memory_size=123,
                    pinned=False,
                    timeout=123
                ),
                id="id"
            )],
        
            # the properties below are optional
            default_config=greengrass.CfnFunctionDefinitionVersion.DefaultConfigProperty(
                execution=greengrass.CfnFunctionDefinitionVersion.ExecutionProperty(
                    isolation_mode="isolationMode",
                    run_as=greengrass.CfnFunctionDefinitionVersion.RunAsProperty(
                        gid=123,
                        uid=123
                    )
                )
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        function_definition_id: builtins.str,
        functions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFunctionDefinitionVersion.FunctionProperty", _IResolvable_da3f097b]]],
        default_config: typing.Optional[typing.Union["CfnFunctionDefinitionVersion.DefaultConfigProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::Greengrass::FunctionDefinitionVersion``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param function_definition_id: The ID of the function definition associated with this version. This value is a GUID.
        :param functions: The functions in this version.
        :param default_config: The default configuration that applies to all Lambda functions in the group. Individual Lambda functions can override these settings.
        '''
        props = CfnFunctionDefinitionVersionProps(
            function_definition_id=function_definition_id,
            functions=functions,
            default_config=default_config,
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
    @jsii.member(jsii_name="functionDefinitionId")
    def function_definition_id(self) -> builtins.str:
        '''The ID of the function definition associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html#cfn-greengrass-functiondefinitionversion-functiondefinitionid
        '''
        return typing.cast(builtins.str, jsii.get(self, "functionDefinitionId"))

    @function_definition_id.setter
    def function_definition_id(self, value: builtins.str) -> None:
        jsii.set(self, "functionDefinitionId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="functions")
    def functions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFunctionDefinitionVersion.FunctionProperty", _IResolvable_da3f097b]]]:
        '''The functions in this version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html#cfn-greengrass-functiondefinitionversion-functions
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFunctionDefinitionVersion.FunctionProperty", _IResolvable_da3f097b]]], jsii.get(self, "functions"))

    @functions.setter
    def functions(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFunctionDefinitionVersion.FunctionProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "functions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultConfig")
    def default_config(
        self,
    ) -> typing.Optional[typing.Union["CfnFunctionDefinitionVersion.DefaultConfigProperty", _IResolvable_da3f097b]]:
        '''The default configuration that applies to all Lambda functions in the group.

        Individual Lambda functions can override these settings.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html#cfn-greengrass-functiondefinitionversion-defaultconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnFunctionDefinitionVersion.DefaultConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "defaultConfig"))

    @default_config.setter
    def default_config(
        self,
        value: typing.Optional[typing.Union["CfnFunctionDefinitionVersion.DefaultConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "defaultConfig", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinitionVersion.DefaultConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"execution": "execution"},
    )
    class DefaultConfigProperty:
        def __init__(
            self,
            *,
            execution: typing.Union["CfnFunctionDefinitionVersion.ExecutionProperty", _IResolvable_da3f097b],
        ) -> None:
            '''The default configuration that applies to all Lambda functions in the function definition version.

            Individual Lambda functions can override these settings.

            In an AWS CloudFormation template, ``DefaultConfig`` is a property of the ```AWS::Greengrass::FunctionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html>`_ resource.

            :param execution: Configuration settings for the Lambda execution environment on the AWS IoT Greengrass core.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-defaultconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                default_config_property = greengrass.CfnFunctionDefinitionVersion.DefaultConfigProperty(
                    execution=greengrass.CfnFunctionDefinitionVersion.ExecutionProperty(
                        isolation_mode="isolationMode",
                        run_as=greengrass.CfnFunctionDefinitionVersion.RunAsProperty(
                            gid=123,
                            uid=123
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "execution": execution,
            }

        @builtins.property
        def execution(
            self,
        ) -> typing.Union["CfnFunctionDefinitionVersion.ExecutionProperty", _IResolvable_da3f097b]:
            '''Configuration settings for the Lambda execution environment on the AWS IoT Greengrass core.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-defaultconfig.html#cfn-greengrass-functiondefinitionversion-defaultconfig-execution
            '''
            result = self._values.get("execution")
            assert result is not None, "Required property 'execution' is missing"
            return typing.cast(typing.Union["CfnFunctionDefinitionVersion.ExecutionProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DefaultConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinitionVersion.EnvironmentProperty",
        jsii_struct_bases=[],
        name_mapping={
            "access_sysfs": "accessSysfs",
            "execution": "execution",
            "resource_access_policies": "resourceAccessPolicies",
            "variables": "variables",
        },
    )
    class EnvironmentProperty:
        def __init__(
            self,
            *,
            access_sysfs: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            execution: typing.Optional[typing.Union["CfnFunctionDefinitionVersion.ExecutionProperty", _IResolvable_da3f097b]] = None,
            resource_access_policies: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFunctionDefinitionVersion.ResourceAccessPolicyProperty", _IResolvable_da3f097b]]]] = None,
            variables: typing.Any = None,
        ) -> None:
            '''The environment configuration for a Lambda function on the AWS IoT Greengrass core.

            In an AWS CloudFormation template, ``Environment`` is a property of the ```FunctionConfiguration`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-functionconfiguration.html>`_ property type.

            :param access_sysfs: Indicates whether the function is allowed to access the ``/sys`` directory on the core device, which allows the read device information from ``/sys`` . .. epigraph:: This property applies only to Lambda functions that run in a Greengrass container.
            :param execution: Settings for the Lambda execution environment in AWS IoT Greengrass .
            :param resource_access_policies: A list of the `resources <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourceinstance.html>`_ in the group that the function can access, with the corresponding read-only or read-write permissions. The maximum is 10 resources. .. epigraph:: This property applies only to Lambda functions that run in a Greengrass container.
            :param variables: Environment variables for the Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                # variables: Any
                
                environment_property = greengrass.CfnFunctionDefinitionVersion.EnvironmentProperty(
                    access_sysfs=False,
                    execution=greengrass.CfnFunctionDefinitionVersion.ExecutionProperty(
                        isolation_mode="isolationMode",
                        run_as=greengrass.CfnFunctionDefinitionVersion.RunAsProperty(
                            gid=123,
                            uid=123
                        )
                    ),
                    resource_access_policies=[greengrass.CfnFunctionDefinitionVersion.ResourceAccessPolicyProperty(
                        resource_id="resourceId",
                
                        # the properties below are optional
                        permission="permission"
                    )],
                    variables=variables
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if access_sysfs is not None:
                self._values["access_sysfs"] = access_sysfs
            if execution is not None:
                self._values["execution"] = execution
            if resource_access_policies is not None:
                self._values["resource_access_policies"] = resource_access_policies
            if variables is not None:
                self._values["variables"] = variables

        @builtins.property
        def access_sysfs(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether the function is allowed to access the ``/sys`` directory on the core device, which allows the read device information from ``/sys`` .

            .. epigraph::

               This property applies only to Lambda functions that run in a Greengrass container.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html#cfn-greengrass-functiondefinitionversion-environment-accesssysfs
            '''
            result = self._values.get("access_sysfs")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def execution(
            self,
        ) -> typing.Optional[typing.Union["CfnFunctionDefinitionVersion.ExecutionProperty", _IResolvable_da3f097b]]:
            '''Settings for the Lambda execution environment in AWS IoT Greengrass .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html#cfn-greengrass-functiondefinitionversion-environment-execution
            '''
            result = self._values.get("execution")
            return typing.cast(typing.Optional[typing.Union["CfnFunctionDefinitionVersion.ExecutionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def resource_access_policies(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFunctionDefinitionVersion.ResourceAccessPolicyProperty", _IResolvable_da3f097b]]]]:
            '''A list of the `resources <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourceinstance.html>`_ in the group that the function can access, with the corresponding read-only or read-write permissions. The maximum is 10 resources.

            .. epigraph::

               This property applies only to Lambda functions that run in a Greengrass container.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html#cfn-greengrass-functiondefinitionversion-environment-resourceaccesspolicies
            '''
            result = self._values.get("resource_access_policies")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFunctionDefinitionVersion.ResourceAccessPolicyProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def variables(self) -> typing.Any:
            '''Environment variables for the Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html#cfn-greengrass-functiondefinitionversion-environment-variables
            '''
            result = self._values.get("variables")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EnvironmentProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinitionVersion.ExecutionProperty",
        jsii_struct_bases=[],
        name_mapping={"isolation_mode": "isolationMode", "run_as": "runAs"},
    )
    class ExecutionProperty:
        def __init__(
            self,
            *,
            isolation_mode: typing.Optional[builtins.str] = None,
            run_as: typing.Optional[typing.Union["CfnFunctionDefinitionVersion.RunAsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Configuration settings for the Lambda execution environment on the AWS IoT Greengrass core.

            In an AWS CloudFormation template, ``Execution`` is a property of the ```DefaultConfig`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-defaultconfig.html>`_ property type for a function definition version and the ```Environment`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html>`_ property type for a function.

            :param isolation_mode: The containerization that the Lambda function runs in. Valid values are ``GreengrassContainer`` or ``NoContainer`` . Typically, this is ``GreengrassContainer`` . For more information, see `Containerization <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-function-containerization>`_ in the *Developer Guide* . - When set on the ```DefaultConfig`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-defaultconfig.html>`_ property of a function definition version, this setting is used as the default containerization for all Lambda functions in the function definition version. - When set on the ```Environment`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html>`_ property of a function, this setting applies to the individual function and overrides the default. Omit this value to run the function with the default containerization. .. epigraph:: We recommend that you run in a Greengrass container unless your business case requires that you run without containerization.
            :param run_as: The user and group permissions used to run the Lambda function. Typically, this is the ggc_user and ggc_group. For more information, see `Run as <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-access-identity.html>`_ in the *Developer Guide* . - When set on the ```DefaultConfig`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-defaultconfig.html>`_ property of a function definition version, this setting is used as the default access identity for all Lambda functions in the function definition version. - When set on the ```Environment`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html>`_ property of a function, this setting applies to the individual function and overrides the default. You can override the user, group, or both. Omit this value to run the function with the default permissions. .. epigraph:: Running as the root user increases risks to your data and device. Do not run as root (UID/GID=0) unless your business case requires it. For more information and requirements, see `Running a Lambda Function as Root <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-running-as-root>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-execution.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                execution_property = greengrass.CfnFunctionDefinitionVersion.ExecutionProperty(
                    isolation_mode="isolationMode",
                    run_as=greengrass.CfnFunctionDefinitionVersion.RunAsProperty(
                        gid=123,
                        uid=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if isolation_mode is not None:
                self._values["isolation_mode"] = isolation_mode
            if run_as is not None:
                self._values["run_as"] = run_as

        @builtins.property
        def isolation_mode(self) -> typing.Optional[builtins.str]:
            '''The containerization that the Lambda function runs in.

            Valid values are ``GreengrassContainer`` or ``NoContainer`` . Typically, this is ``GreengrassContainer`` . For more information, see `Containerization <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-function-containerization>`_ in the *Developer Guide* .

            - When set on the ```DefaultConfig`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-defaultconfig.html>`_ property of a function definition version, this setting is used as the default containerization for all Lambda functions in the function definition version.
            - When set on the ```Environment`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html>`_ property of a function, this setting applies to the individual function and overrides the default. Omit this value to run the function with the default containerization.

            .. epigraph::

               We recommend that you run in a Greengrass container unless your business case requires that you run without containerization.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-execution.html#cfn-greengrass-functiondefinitionversion-execution-isolationmode
            '''
            result = self._values.get("isolation_mode")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def run_as(
            self,
        ) -> typing.Optional[typing.Union["CfnFunctionDefinitionVersion.RunAsProperty", _IResolvable_da3f097b]]:
            '''The user and group permissions used to run the Lambda function.

            Typically, this is the ggc_user and ggc_group. For more information, see `Run as <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-access-identity.html>`_ in the *Developer Guide* .

            - When set on the ```DefaultConfig`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-defaultconfig.html>`_ property of a function definition version, this setting is used as the default access identity for all Lambda functions in the function definition version.
            - When set on the ```Environment`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html>`_ property of a function, this setting applies to the individual function and overrides the default. You can override the user, group, or both. Omit this value to run the function with the default permissions.

            .. epigraph::

               Running as the root user increases risks to your data and device. Do not run as root (UID/GID=0) unless your business case requires it. For more information and requirements, see `Running a Lambda Function as Root <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-running-as-root>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-execution.html#cfn-greengrass-functiondefinitionversion-execution-runas
            '''
            result = self._values.get("run_as")
            return typing.cast(typing.Optional[typing.Union["CfnFunctionDefinitionVersion.RunAsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ExecutionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinitionVersion.FunctionConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "encoding_type": "encodingType",
            "environment": "environment",
            "exec_args": "execArgs",
            "executable": "executable",
            "memory_size": "memorySize",
            "pinned": "pinned",
            "timeout": "timeout",
        },
    )
    class FunctionConfigurationProperty:
        def __init__(
            self,
            *,
            encoding_type: typing.Optional[builtins.str] = None,
            environment: typing.Optional[typing.Union["CfnFunctionDefinitionVersion.EnvironmentProperty", _IResolvable_da3f097b]] = None,
            exec_args: typing.Optional[builtins.str] = None,
            executable: typing.Optional[builtins.str] = None,
            memory_size: typing.Optional[jsii.Number] = None,
            pinned: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            timeout: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The group-specific configuration settings for a Lambda function.

            These settings configure the function's behavior in the Greengrass group. For more information, see `Controlling Execution of Greengrass Lambda Functions by Using Group-Specific Configuration <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, ``FunctionConfiguration`` is a property of the ```Function`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-function.html>`_ property type.

            :param encoding_type: The expected encoding type of the input payload for the function. Valid values are ``json`` (default) and ``binary`` .
            :param environment: The environment configuration of the function.
            :param exec_args: The execution arguments.
            :param executable: The name of the function executable.
            :param memory_size: The memory size (in KB) required by the function. .. epigraph:: This property applies only to Lambda functions that run in a Greengrass container.
            :param pinned: Indicates whether the function is pinned (or *long-lived* ). Pinned functions start when the core starts and process all requests in the same container. The default value is false.
            :param timeout: The allowed execution time (in seconds) after which the function should terminate. For pinned functions, this timeout applies for each request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-functionconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                # variables: Any
                
                function_configuration_property = greengrass.CfnFunctionDefinitionVersion.FunctionConfigurationProperty(
                    encoding_type="encodingType",
                    environment=greengrass.CfnFunctionDefinitionVersion.EnvironmentProperty(
                        access_sysfs=False,
                        execution=greengrass.CfnFunctionDefinitionVersion.ExecutionProperty(
                            isolation_mode="isolationMode",
                            run_as=greengrass.CfnFunctionDefinitionVersion.RunAsProperty(
                                gid=123,
                                uid=123
                            )
                        ),
                        resource_access_policies=[greengrass.CfnFunctionDefinitionVersion.ResourceAccessPolicyProperty(
                            resource_id="resourceId",
                
                            # the properties below are optional
                            permission="permission"
                        )],
                        variables=variables
                    ),
                    exec_args="execArgs",
                    executable="executable",
                    memory_size=123,
                    pinned=False,
                    timeout=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if encoding_type is not None:
                self._values["encoding_type"] = encoding_type
            if environment is not None:
                self._values["environment"] = environment
            if exec_args is not None:
                self._values["exec_args"] = exec_args
            if executable is not None:
                self._values["executable"] = executable
            if memory_size is not None:
                self._values["memory_size"] = memory_size
            if pinned is not None:
                self._values["pinned"] = pinned
            if timeout is not None:
                self._values["timeout"] = timeout

        @builtins.property
        def encoding_type(self) -> typing.Optional[builtins.str]:
            '''The expected encoding type of the input payload for the function.

            Valid values are ``json`` (default) and ``binary`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-functionconfiguration.html#cfn-greengrass-functiondefinitionversion-functionconfiguration-encodingtype
            '''
            result = self._values.get("encoding_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def environment(
            self,
        ) -> typing.Optional[typing.Union["CfnFunctionDefinitionVersion.EnvironmentProperty", _IResolvable_da3f097b]]:
            '''The environment configuration of the function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-functionconfiguration.html#cfn-greengrass-functiondefinitionversion-functionconfiguration-environment
            '''
            result = self._values.get("environment")
            return typing.cast(typing.Optional[typing.Union["CfnFunctionDefinitionVersion.EnvironmentProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def exec_args(self) -> typing.Optional[builtins.str]:
            '''The execution arguments.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-functionconfiguration.html#cfn-greengrass-functiondefinitionversion-functionconfiguration-execargs
            '''
            result = self._values.get("exec_args")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def executable(self) -> typing.Optional[builtins.str]:
            '''The name of the function executable.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-functionconfiguration.html#cfn-greengrass-functiondefinitionversion-functionconfiguration-executable
            '''
            result = self._values.get("executable")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def memory_size(self) -> typing.Optional[jsii.Number]:
            '''The memory size (in KB) required by the function.

            .. epigraph::

               This property applies only to Lambda functions that run in a Greengrass container.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-functionconfiguration.html#cfn-greengrass-functiondefinitionversion-functionconfiguration-memorysize
            '''
            result = self._values.get("memory_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def pinned(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether the function is pinned (or *long-lived* ).

            Pinned functions start when the core starts and process all requests in the same container. The default value is false.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-functionconfiguration.html#cfn-greengrass-functiondefinitionversion-functionconfiguration-pinned
            '''
            result = self._values.get("pinned")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def timeout(self) -> typing.Optional[jsii.Number]:
            '''The allowed execution time (in seconds) after which the function should terminate.

            For pinned functions, this timeout applies for each request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-functionconfiguration.html#cfn-greengrass-functiondefinitionversion-functionconfiguration-timeout
            '''
            result = self._values.get("timeout")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FunctionConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinitionVersion.FunctionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "function_arn": "functionArn",
            "function_configuration": "functionConfiguration",
            "id": "id",
        },
    )
    class FunctionProperty:
        def __init__(
            self,
            *,
            function_arn: builtins.str,
            function_configuration: typing.Union["CfnFunctionDefinitionVersion.FunctionConfigurationProperty", _IResolvable_da3f097b],
            id: builtins.str,
        ) -> None:
            '''A function is a Lambda function that's referenced from an AWS IoT Greengrass group.

            The function is deployed to a Greengrass core where it runs locally. For more information, see `Run Lambda Functions on the AWS IoT Greengrass Core <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-functions.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, the ``Functions`` property of the ```AWS::Greengrass::FunctionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html>`_ resource contains a list of ``Function`` property types.

            :param function_arn: The Amazon Resource Name (ARN) of the alias (recommended) or version of the referenced Lambda function.
            :param function_configuration: The group-specific settings of the Lambda function. These settings configure the function's behavior in the Greengrass group.
            :param id: A descriptive or arbitrary ID for the function. This value must be unique within the function definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-function.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                # variables: Any
                
                function_property = greengrass.CfnFunctionDefinitionVersion.FunctionProperty(
                    function_arn="functionArn",
                    function_configuration=greengrass.CfnFunctionDefinitionVersion.FunctionConfigurationProperty(
                        encoding_type="encodingType",
                        environment=greengrass.CfnFunctionDefinitionVersion.EnvironmentProperty(
                            access_sysfs=False,
                            execution=greengrass.CfnFunctionDefinitionVersion.ExecutionProperty(
                                isolation_mode="isolationMode",
                                run_as=greengrass.CfnFunctionDefinitionVersion.RunAsProperty(
                                    gid=123,
                                    uid=123
                                )
                            ),
                            resource_access_policies=[greengrass.CfnFunctionDefinitionVersion.ResourceAccessPolicyProperty(
                                resource_id="resourceId",
                
                                # the properties below are optional
                                permission="permission"
                            )],
                            variables=variables
                        ),
                        exec_args="execArgs",
                        executable="executable",
                        memory_size=123,
                        pinned=False,
                        timeout=123
                    ),
                    id="id"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "function_arn": function_arn,
                "function_configuration": function_configuration,
                "id": id,
            }

        @builtins.property
        def function_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the alias (recommended) or version of the referenced Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-function.html#cfn-greengrass-functiondefinitionversion-function-functionarn
            '''
            result = self._values.get("function_arn")
            assert result is not None, "Required property 'function_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def function_configuration(
            self,
        ) -> typing.Union["CfnFunctionDefinitionVersion.FunctionConfigurationProperty", _IResolvable_da3f097b]:
            '''The group-specific settings of the Lambda function.

            These settings configure the function's behavior in the Greengrass group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-function.html#cfn-greengrass-functiondefinitionversion-function-functionconfiguration
            '''
            result = self._values.get("function_configuration")
            assert result is not None, "Required property 'function_configuration' is missing"
            return typing.cast(typing.Union["CfnFunctionDefinitionVersion.FunctionConfigurationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def id(self) -> builtins.str:
            '''A descriptive or arbitrary ID for the function.

            This value must be unique within the function definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-function.html#cfn-greengrass-functiondefinitionversion-function-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FunctionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinitionVersion.ResourceAccessPolicyProperty",
        jsii_struct_bases=[],
        name_mapping={"resource_id": "resourceId", "permission": "permission"},
    )
    class ResourceAccessPolicyProperty:
        def __init__(
            self,
            *,
            resource_id: builtins.str,
            permission: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A list of the `resources <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourceinstance.html>`_ in the group that the function can access, with the corresponding read-only or read-write permissions. The maximum is 10 resources.

            .. epigraph::

               This property applies only to Lambda functions that run in a Greengrass container.

            In an AWS CloudFormation template, ``ResourceAccessPolicy`` is a property of the ```Environment`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-environment.html>`_ property type.

            :param resource_id: The ID of the resource. This ID is assigned to the resource when you create the resource definition.
            :param permission: The read-only or read-write access that the Lambda function has to the resource. Valid values are ``ro`` or ``rw`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-resourceaccesspolicy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                resource_access_policy_property = greengrass.CfnFunctionDefinitionVersion.ResourceAccessPolicyProperty(
                    resource_id="resourceId",
                
                    # the properties below are optional
                    permission="permission"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "resource_id": resource_id,
            }
            if permission is not None:
                self._values["permission"] = permission

        @builtins.property
        def resource_id(self) -> builtins.str:
            '''The ID of the resource.

            This ID is assigned to the resource when you create the resource definition.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-resourceaccesspolicy.html#cfn-greengrass-functiondefinitionversion-resourceaccesspolicy-resourceid
            '''
            result = self._values.get("resource_id")
            assert result is not None, "Required property 'resource_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def permission(self) -> typing.Optional[builtins.str]:
            '''The read-only or read-write access that the Lambda function has to the resource.

            Valid values are ``ro`` or ``rw`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-resourceaccesspolicy.html#cfn-greengrass-functiondefinitionversion-resourceaccesspolicy-permission
            '''
            result = self._values.get("permission")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourceAccessPolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinitionVersion.RunAsProperty",
        jsii_struct_bases=[],
        name_mapping={"gid": "gid", "uid": "uid"},
    )
    class RunAsProperty:
        def __init__(
            self,
            *,
            gid: typing.Optional[jsii.Number] = None,
            uid: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The user and group permissions used to run the Lambda function.

            This setting overrides the default access identity that's specified for the group (by default, ggc_user and ggc_group). You can override the user, group, or both. For more information, see `Run as <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-access-identity.html>`_ in the *Developer Guide* .
            .. epigraph::

               Running as the root user increases risks to your data and device. Do not run as root (UID/GID=0) unless your business case requires it. For more information and requirements, see `Running a Lambda Function as Root <https://docs.aws.amazon.com/greengrass/latest/developerguide/lambda-group-config.html#lambda-running-as-root>`_ .

            In an AWS CloudFormation template, ``RunAs`` is a property of the ```Execution`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-execution.html>`_ property type.

            :param gid: The group ID whose permissions are used to run the Lambda function. You can use the ``getent group`` command on your core device to look up the group ID.
            :param uid: The user ID whose permissions are used to run the Lambda function. You can use the ``getent passwd`` command on your core device to look up the user ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-runas.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                run_as_property = greengrass.CfnFunctionDefinitionVersion.RunAsProperty(
                    gid=123,
                    uid=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if gid is not None:
                self._values["gid"] = gid
            if uid is not None:
                self._values["uid"] = uid

        @builtins.property
        def gid(self) -> typing.Optional[jsii.Number]:
            '''The group ID whose permissions are used to run the Lambda function.

            You can use the ``getent group`` command on your core device to look up the group ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-runas.html#cfn-greengrass-functiondefinitionversion-runas-gid
            '''
            result = self._values.get("gid")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def uid(self) -> typing.Optional[jsii.Number]:
            '''The user ID whose permissions are used to run the Lambda function.

            You can use the ``getent passwd`` command on your core device to look up the user ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-functiondefinitionversion-runas.html#cfn-greengrass-functiondefinitionversion-runas-uid
            '''
            result = self._values.get("uid")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RunAsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnFunctionDefinitionVersionProps",
    jsii_struct_bases=[],
    name_mapping={
        "function_definition_id": "functionDefinitionId",
        "functions": "functions",
        "default_config": "defaultConfig",
    },
)
class CfnFunctionDefinitionVersionProps:
    def __init__(
        self,
        *,
        function_definition_id: builtins.str,
        functions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnFunctionDefinitionVersion.FunctionProperty, _IResolvable_da3f097b]]],
        default_config: typing.Optional[typing.Union[CfnFunctionDefinitionVersion.DefaultConfigProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnFunctionDefinitionVersion``.

        :param function_definition_id: The ID of the function definition associated with this version. This value is a GUID.
        :param functions: The functions in this version.
        :param default_config: The default configuration that applies to all Lambda functions in the group. Individual Lambda functions can override these settings.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            # variables: Any
            
            cfn_function_definition_version_props = greengrass.CfnFunctionDefinitionVersionProps(
                function_definition_id="functionDefinitionId",
                functions=[greengrass.CfnFunctionDefinitionVersion.FunctionProperty(
                    function_arn="functionArn",
                    function_configuration=greengrass.CfnFunctionDefinitionVersion.FunctionConfigurationProperty(
                        encoding_type="encodingType",
                        environment=greengrass.CfnFunctionDefinitionVersion.EnvironmentProperty(
                            access_sysfs=False,
                            execution=greengrass.CfnFunctionDefinitionVersion.ExecutionProperty(
                                isolation_mode="isolationMode",
                                run_as=greengrass.CfnFunctionDefinitionVersion.RunAsProperty(
                                    gid=123,
                                    uid=123
                                )
                            ),
                            resource_access_policies=[greengrass.CfnFunctionDefinitionVersion.ResourceAccessPolicyProperty(
                                resource_id="resourceId",
            
                                # the properties below are optional
                                permission="permission"
                            )],
                            variables=variables
                        ),
                        exec_args="execArgs",
                        executable="executable",
                        memory_size=123,
                        pinned=False,
                        timeout=123
                    ),
                    id="id"
                )],
            
                # the properties below are optional
                default_config=greengrass.CfnFunctionDefinitionVersion.DefaultConfigProperty(
                    execution=greengrass.CfnFunctionDefinitionVersion.ExecutionProperty(
                        isolation_mode="isolationMode",
                        run_as=greengrass.CfnFunctionDefinitionVersion.RunAsProperty(
                            gid=123,
                            uid=123
                        )
                    )
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "function_definition_id": function_definition_id,
            "functions": functions,
        }
        if default_config is not None:
            self._values["default_config"] = default_config

    @builtins.property
    def function_definition_id(self) -> builtins.str:
        '''The ID of the function definition associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html#cfn-greengrass-functiondefinitionversion-functiondefinitionid
        '''
        result = self._values.get("function_definition_id")
        assert result is not None, "Required property 'function_definition_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def functions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnFunctionDefinitionVersion.FunctionProperty, _IResolvable_da3f097b]]]:
        '''The functions in this version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html#cfn-greengrass-functiondefinitionversion-functions
        '''
        result = self._values.get("functions")
        assert result is not None, "Required property 'functions' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnFunctionDefinitionVersion.FunctionProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def default_config(
        self,
    ) -> typing.Optional[typing.Union[CfnFunctionDefinitionVersion.DefaultConfigProperty, _IResolvable_da3f097b]]:
        '''The default configuration that applies to all Lambda functions in the group.

        Individual Lambda functions can override these settings.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-functiondefinitionversion.html#cfn-greengrass-functiondefinitionversion-defaultconfig
        '''
        result = self._values.get("default_config")
        return typing.cast(typing.Optional[typing.Union[CfnFunctionDefinitionVersion.DefaultConfigProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnFunctionDefinitionVersionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnGroup",
):
    '''A CloudFormation ``AWS::Greengrass::Group``.

    AWS IoT Greengrass seamlessly extends AWS to edge devices so they can act locally on the data they generate, while still using the cloud for management, analytics, and durable storage. With AWS IoT Greengrass , connected devices can run AWS Lambda functions, execute predictions based on machine learning models, keep device data in sync, and communicate with other devices securely – even when not connected to the internet. For more information, see the `Developer Guide <https://docs.aws.amazon.com/greengrass/latest/developerguide/what-is-gg.html>`_ .
    .. epigraph::

       For AWS Region support, see `AWS CloudFormation Support for AWS IoT Greengrass <https://docs.aws.amazon.com/greengrass/latest/developerguide/cloudformation-support.html>`_ in the *Developer Guide* .

    The ``AWS::Greengrass::Group`` resource represents a group in AWS IoT Greengrass . In the AWS IoT Greengrass API, groups are used to organize your group versions.

    Groups can reference multiple group versions. All group versions must be associated with a group. A group version references a device definition version, subscription definition version, and other version types that contain the components you want to deploy to a Greengrass core device.

    To deploy a group version, the group version must reference a core definition version that contains one core. Other version types are optionally included, depending on your business need.
    .. epigraph::

       When you create a group, you can optionally include an initial group version. To associate a group version later, create a ```AWS::Greengrass::GroupVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html>`_ resource and specify the ID of this group.

       To change group components (such as devices, subscriptions, or functions), you must create new versions. This is because versions are immutable. For example, to add a function, you create a function definition version that contains the new function (and all other functions that you want to deploy). Then you create a group version that references the new function definition version (and all other version types that you want to deploy).

    *Deploying a Group Version*

    After you create the group version in your AWS CloudFormation template, you can deploy it using the ```aws greengrass create-deployment`` <https://docs.aws.amazon.com/greengrass/latest/apireference/createdeployment-post.html>`_ command in the AWS CLI or from the *Greengrass* node in the AWS IoT console. To deploy a group version, you must have a Greengrass service role associated with your AWS account . For more information, see `AWS CloudFormation Support for AWS IoT Greengrass <https://docs.aws.amazon.com/greengrass/latest/developerguide/cloudformation-support.html>`_ in the *Developer Guide* .

    :cloudformationResource: AWS::Greengrass::Group
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        # tags: Any
        
        cfn_group = greengrass.CfnGroup(self, "MyCfnGroup",
            name="name",
        
            # the properties below are optional
            initial_version=greengrass.CfnGroup.GroupVersionProperty(
                connector_definition_version_arn="connectorDefinitionVersionArn",
                core_definition_version_arn="coreDefinitionVersionArn",
                device_definition_version_arn="deviceDefinitionVersionArn",
                function_definition_version_arn="functionDefinitionVersionArn",
                logger_definition_version_arn="loggerDefinitionVersionArn",
                resource_definition_version_arn="resourceDefinitionVersionArn",
                subscription_definition_version_arn="subscriptionDefinitionVersionArn"
            ),
            role_arn="roleArn",
            tags=tags
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union["CfnGroup.GroupVersionProperty", _IResolvable_da3f097b]] = None,
        role_arn: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Greengrass::Group``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the group.
        :param initial_version: The group version to include when the group is created. A group version references the Amazon Resource Name (ARN) of a core definition version, device definition version, subscription definition version, and other version types. The group version must reference a core definition version that contains one core. Other version types are optionally included, depending on your business need. .. epigraph:: To associate a group version after the group is created, create an ```AWS::Greengrass::GroupVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html>`_ resource and specify the ID of this group.
        :param role_arn: The Amazon Resource Name (ARN) of the IAM role attached to the group. This role contains the permissions that Lambda functions and connectors use to interact with other AWS services.
        :param tags: Application-specific metadata to attach to the group. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }
        '''
        props = CfnGroupProps(
            name=name, initial_version=initial_version, role_arn=role_arn, tags=tags
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
        '''The ARN of the ``Group`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/groups/1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the ``Group`` , such as ``1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLatestVersionArn")
    def attr_latest_version_arn(self) -> builtins.str:
        '''The ARN of the last ``GroupVersion`` that was added to the ``Group`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/groups/1234a5b6-78cd-901e-2fgh-3i45j6k178l9/versions/9876ac30-4bdb-4f9d-95af-b5fdb66be1a2`` .

        :cloudformationAttribute: LatestVersionArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLatestVersionArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the ``Group`` , such as ``MyGroup`` .

        :cloudformationAttribute: Name
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrRoleArn")
    def attr_role_arn(self) -> builtins.str:
        '''The ARN of the IAM role that's attached to the ``Group`` , such as ``arn:aws:iam::  :role/role-name`` .

        :cloudformationAttribute: RoleArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrRoleArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrRoleAttachedAt")
    def attr_role_attached_at(self) -> builtins.str:
        '''The time (in milliseconds since the epoch) when the group role was attached to the ``Group`` .

        :cloudformationAttribute: RoleAttachedAt
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrRoleAttachedAt"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Application-specific metadata to attach to the group.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html#cfn-greengrass-group-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html#cfn-greengrass-group-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="initialVersion")
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union["CfnGroup.GroupVersionProperty", _IResolvable_da3f097b]]:
        '''The group version to include when the group is created.

        A group version references the Amazon Resource Name (ARN) of a core definition version, device definition version, subscription definition version, and other version types. The group version must reference a core definition version that contains one core. Other version types are optionally included, depending on your business need.
        .. epigraph::

           To associate a group version after the group is created, create an ```AWS::Greengrass::GroupVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html>`_ resource and specify the ID of this group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html#cfn-greengrass-group-initialversion
        '''
        return typing.cast(typing.Optional[typing.Union["CfnGroup.GroupVersionProperty", _IResolvable_da3f097b]], jsii.get(self, "initialVersion"))

    @initial_version.setter
    def initial_version(
        self,
        value: typing.Optional[typing.Union["CfnGroup.GroupVersionProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "initialVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the IAM role attached to the group.

        This role contains the permissions that Lambda functions and connectors use to interact with other AWS services.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html#cfn-greengrass-group-rolearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "roleArn"))

    @role_arn.setter
    def role_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "roleArn", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnGroup.GroupVersionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "connector_definition_version_arn": "connectorDefinitionVersionArn",
            "core_definition_version_arn": "coreDefinitionVersionArn",
            "device_definition_version_arn": "deviceDefinitionVersionArn",
            "function_definition_version_arn": "functionDefinitionVersionArn",
            "logger_definition_version_arn": "loggerDefinitionVersionArn",
            "resource_definition_version_arn": "resourceDefinitionVersionArn",
            "subscription_definition_version_arn": "subscriptionDefinitionVersionArn",
        },
    )
    class GroupVersionProperty:
        def __init__(
            self,
            *,
            connector_definition_version_arn: typing.Optional[builtins.str] = None,
            core_definition_version_arn: typing.Optional[builtins.str] = None,
            device_definition_version_arn: typing.Optional[builtins.str] = None,
            function_definition_version_arn: typing.Optional[builtins.str] = None,
            logger_definition_version_arn: typing.Optional[builtins.str] = None,
            resource_definition_version_arn: typing.Optional[builtins.str] = None,
            subscription_definition_version_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A group version in AWS IoT Greengrass , which references of a core definition version, device definition version, subscription definition version, and other version types that contain the components you want to deploy to a Greengrass core device.

            The group version must reference a core definition version that contains one core. Other version types are optionally included, depending on your business need.

            In an AWS CloudFormation template, ``GroupVersion`` is the property type of the ``InitialVersion`` property in the ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ resource.

            :param connector_definition_version_arn: The Amazon Resource Name (ARN) of the connector definition version that contains the connectors you want to deploy with the group version.
            :param core_definition_version_arn: The ARN of the core definition version that contains the core you want to deploy with the group version. Currently, the core definition version can contain only one core.
            :param device_definition_version_arn: The ARN of the device definition version that contains the devices you want to deploy with the group version.
            :param function_definition_version_arn: The ARN of the function definition version that contains the functions you want to deploy with the group version.
            :param logger_definition_version_arn: The ARN of the logger definition version that contains the loggers you want to deploy with the group version.
            :param resource_definition_version_arn: The ARN of the resource definition version that contains the resources you want to deploy with the group version.
            :param subscription_definition_version_arn: The ARN of the subscription definition version that contains the subscriptions you want to deploy with the group version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-group-groupversion.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                group_version_property = greengrass.CfnGroup.GroupVersionProperty(
                    connector_definition_version_arn="connectorDefinitionVersionArn",
                    core_definition_version_arn="coreDefinitionVersionArn",
                    device_definition_version_arn="deviceDefinitionVersionArn",
                    function_definition_version_arn="functionDefinitionVersionArn",
                    logger_definition_version_arn="loggerDefinitionVersionArn",
                    resource_definition_version_arn="resourceDefinitionVersionArn",
                    subscription_definition_version_arn="subscriptionDefinitionVersionArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if connector_definition_version_arn is not None:
                self._values["connector_definition_version_arn"] = connector_definition_version_arn
            if core_definition_version_arn is not None:
                self._values["core_definition_version_arn"] = core_definition_version_arn
            if device_definition_version_arn is not None:
                self._values["device_definition_version_arn"] = device_definition_version_arn
            if function_definition_version_arn is not None:
                self._values["function_definition_version_arn"] = function_definition_version_arn
            if logger_definition_version_arn is not None:
                self._values["logger_definition_version_arn"] = logger_definition_version_arn
            if resource_definition_version_arn is not None:
                self._values["resource_definition_version_arn"] = resource_definition_version_arn
            if subscription_definition_version_arn is not None:
                self._values["subscription_definition_version_arn"] = subscription_definition_version_arn

        @builtins.property
        def connector_definition_version_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the connector definition version that contains the connectors you want to deploy with the group version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-group-groupversion.html#cfn-greengrass-group-groupversion-connectordefinitionversionarn
            '''
            result = self._values.get("connector_definition_version_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def core_definition_version_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the core definition version that contains the core you want to deploy with the group version.

            Currently, the core definition version can contain only one core.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-group-groupversion.html#cfn-greengrass-group-groupversion-coredefinitionversionarn
            '''
            result = self._values.get("core_definition_version_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def device_definition_version_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the device definition version that contains the devices you want to deploy with the group version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-group-groupversion.html#cfn-greengrass-group-groupversion-devicedefinitionversionarn
            '''
            result = self._values.get("device_definition_version_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def function_definition_version_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the function definition version that contains the functions you want to deploy with the group version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-group-groupversion.html#cfn-greengrass-group-groupversion-functiondefinitionversionarn
            '''
            result = self._values.get("function_definition_version_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def logger_definition_version_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the logger definition version that contains the loggers you want to deploy with the group version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-group-groupversion.html#cfn-greengrass-group-groupversion-loggerdefinitionversionarn
            '''
            result = self._values.get("logger_definition_version_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def resource_definition_version_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the resource definition version that contains the resources you want to deploy with the group version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-group-groupversion.html#cfn-greengrass-group-groupversion-resourcedefinitionversionarn
            '''
            result = self._values.get("resource_definition_version_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def subscription_definition_version_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the subscription definition version that contains the subscriptions you want to deploy with the group version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-group-groupversion.html#cfn-greengrass-group-groupversion-subscriptiondefinitionversionarn
            '''
            result = self._values.get("subscription_definition_version_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GroupVersionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "initial_version": "initialVersion",
        "role_arn": "roleArn",
        "tags": "tags",
    },
)
class CfnGroupProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union[CfnGroup.GroupVersionProperty, _IResolvable_da3f097b]] = None,
        role_arn: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnGroup``.

        :param name: The name of the group.
        :param initial_version: The group version to include when the group is created. A group version references the Amazon Resource Name (ARN) of a core definition version, device definition version, subscription definition version, and other version types. The group version must reference a core definition version that contains one core. Other version types are optionally included, depending on your business need. .. epigraph:: To associate a group version after the group is created, create an ```AWS::Greengrass::GroupVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html>`_ resource and specify the ID of this group.
        :param role_arn: The Amazon Resource Name (ARN) of the IAM role attached to the group. This role contains the permissions that Lambda functions and connectors use to interact with other AWS services.
        :param tags: Application-specific metadata to attach to the group. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            # tags: Any
            
            cfn_group_props = greengrass.CfnGroupProps(
                name="name",
            
                # the properties below are optional
                initial_version=greengrass.CfnGroup.GroupVersionProperty(
                    connector_definition_version_arn="connectorDefinitionVersionArn",
                    core_definition_version_arn="coreDefinitionVersionArn",
                    device_definition_version_arn="deviceDefinitionVersionArn",
                    function_definition_version_arn="functionDefinitionVersionArn",
                    logger_definition_version_arn="loggerDefinitionVersionArn",
                    resource_definition_version_arn="resourceDefinitionVersionArn",
                    subscription_definition_version_arn="subscriptionDefinitionVersionArn"
                ),
                role_arn="roleArn",
                tags=tags
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if initial_version is not None:
            self._values["initial_version"] = initial_version
        if role_arn is not None:
            self._values["role_arn"] = role_arn
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html#cfn-greengrass-group-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union[CfnGroup.GroupVersionProperty, _IResolvable_da3f097b]]:
        '''The group version to include when the group is created.

        A group version references the Amazon Resource Name (ARN) of a core definition version, device definition version, subscription definition version, and other version types. The group version must reference a core definition version that contains one core. Other version types are optionally included, depending on your business need.
        .. epigraph::

           To associate a group version after the group is created, create an ```AWS::Greengrass::GroupVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html>`_ resource and specify the ID of this group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html#cfn-greengrass-group-initialversion
        '''
        result = self._values.get("initial_version")
        return typing.cast(typing.Optional[typing.Union[CfnGroup.GroupVersionProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def role_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the IAM role attached to the group.

        This role contains the permissions that Lambda functions and connectors use to interact with other AWS services.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html#cfn-greengrass-group-rolearn
        '''
        result = self._values.get("role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''Application-specific metadata to attach to the group.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html#cfn-greengrass-group-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnGroupVersion(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnGroupVersion",
):
    '''A CloudFormation ``AWS::Greengrass::GroupVersion``.

    The ``AWS::Greengrass::GroupVersion`` resource represents a group version in AWS IoT Greengrass . A group version references a core definition version, device definition version, subscription definition version, and other version types that contain the components you want to deploy to a Greengrass core device. The group version must reference a core definition version that contains one core. Other version types are optionally included, depending on your business need.
    .. epigraph::

       To create a group version, you must specify the ID of the group that you want to associate with the version. For information about creating a group, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::GroupVersion
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        cfn_group_version = greengrass.CfnGroupVersion(self, "MyCfnGroupVersion",
            group_id="groupId",
        
            # the properties below are optional
            connector_definition_version_arn="connectorDefinitionVersionArn",
            core_definition_version_arn="coreDefinitionVersionArn",
            device_definition_version_arn="deviceDefinitionVersionArn",
            function_definition_version_arn="functionDefinitionVersionArn",
            logger_definition_version_arn="loggerDefinitionVersionArn",
            resource_definition_version_arn="resourceDefinitionVersionArn",
            subscription_definition_version_arn="subscriptionDefinitionVersionArn"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        group_id: builtins.str,
        connector_definition_version_arn: typing.Optional[builtins.str] = None,
        core_definition_version_arn: typing.Optional[builtins.str] = None,
        device_definition_version_arn: typing.Optional[builtins.str] = None,
        function_definition_version_arn: typing.Optional[builtins.str] = None,
        logger_definition_version_arn: typing.Optional[builtins.str] = None,
        resource_definition_version_arn: typing.Optional[builtins.str] = None,
        subscription_definition_version_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Greengrass::GroupVersion``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param group_id: The ID of the group associated with this version. This value is a GUID.
        :param connector_definition_version_arn: The Amazon Resource Name (ARN) of the connector definition version that contains the connectors you want to deploy with the group version.
        :param core_definition_version_arn: The ARN of the core definition version that contains the core you want to deploy with the group version. Currently, the core definition version can contain only one core.
        :param device_definition_version_arn: The ARN of the device definition version that contains the devices you want to deploy with the group version.
        :param function_definition_version_arn: The ARN of the function definition version that contains the functions you want to deploy with the group version.
        :param logger_definition_version_arn: The ARN of the logger definition version that contains the loggers you want to deploy with the group version.
        :param resource_definition_version_arn: The ARN of the resource definition version that contains the resources you want to deploy with the group version.
        :param subscription_definition_version_arn: The ARN of the subscription definition version that contains the subscriptions you want to deploy with the group version.
        '''
        props = CfnGroupVersionProps(
            group_id=group_id,
            connector_definition_version_arn=connector_definition_version_arn,
            core_definition_version_arn=core_definition_version_arn,
            device_definition_version_arn=device_definition_version_arn,
            function_definition_version_arn=function_definition_version_arn,
            logger_definition_version_arn=logger_definition_version_arn,
            resource_definition_version_arn=resource_definition_version_arn,
            subscription_definition_version_arn=subscription_definition_version_arn,
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
    @jsii.member(jsii_name="groupId")
    def group_id(self) -> builtins.str:
        '''The ID of the group associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-groupid
        '''
        return typing.cast(builtins.str, jsii.get(self, "groupId"))

    @group_id.setter
    def group_id(self, value: builtins.str) -> None:
        jsii.set(self, "groupId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectorDefinitionVersionArn")
    def connector_definition_version_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the connector definition version that contains the connectors you want to deploy with the group version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-connectordefinitionversionarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "connectorDefinitionVersionArn"))

    @connector_definition_version_arn.setter
    def connector_definition_version_arn(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "connectorDefinitionVersionArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="coreDefinitionVersionArn")
    def core_definition_version_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the core definition version that contains the core you want to deploy with the group version.

        Currently, the core definition version can contain only one core.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-coredefinitionversionarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "coreDefinitionVersionArn"))

    @core_definition_version_arn.setter
    def core_definition_version_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "coreDefinitionVersionArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="deviceDefinitionVersionArn")
    def device_definition_version_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the device definition version that contains the devices you want to deploy with the group version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-devicedefinitionversionarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "deviceDefinitionVersionArn"))

    @device_definition_version_arn.setter
    def device_definition_version_arn(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "deviceDefinitionVersionArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="functionDefinitionVersionArn")
    def function_definition_version_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the function definition version that contains the functions you want to deploy with the group version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-functiondefinitionversionarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "functionDefinitionVersionArn"))

    @function_definition_version_arn.setter
    def function_definition_version_arn(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "functionDefinitionVersionArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loggerDefinitionVersionArn")
    def logger_definition_version_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the logger definition version that contains the loggers you want to deploy with the group version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-loggerdefinitionversionarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "loggerDefinitionVersionArn"))

    @logger_definition_version_arn.setter
    def logger_definition_version_arn(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "loggerDefinitionVersionArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resourceDefinitionVersionArn")
    def resource_definition_version_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the resource definition version that contains the resources you want to deploy with the group version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-resourcedefinitionversionarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "resourceDefinitionVersionArn"))

    @resource_definition_version_arn.setter
    def resource_definition_version_arn(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "resourceDefinitionVersionArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subscriptionDefinitionVersionArn")
    def subscription_definition_version_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the subscription definition version that contains the subscriptions you want to deploy with the group version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-subscriptiondefinitionversionarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "subscriptionDefinitionVersionArn"))

    @subscription_definition_version_arn.setter
    def subscription_definition_version_arn(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "subscriptionDefinitionVersionArn", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnGroupVersionProps",
    jsii_struct_bases=[],
    name_mapping={
        "group_id": "groupId",
        "connector_definition_version_arn": "connectorDefinitionVersionArn",
        "core_definition_version_arn": "coreDefinitionVersionArn",
        "device_definition_version_arn": "deviceDefinitionVersionArn",
        "function_definition_version_arn": "functionDefinitionVersionArn",
        "logger_definition_version_arn": "loggerDefinitionVersionArn",
        "resource_definition_version_arn": "resourceDefinitionVersionArn",
        "subscription_definition_version_arn": "subscriptionDefinitionVersionArn",
    },
)
class CfnGroupVersionProps:
    def __init__(
        self,
        *,
        group_id: builtins.str,
        connector_definition_version_arn: typing.Optional[builtins.str] = None,
        core_definition_version_arn: typing.Optional[builtins.str] = None,
        device_definition_version_arn: typing.Optional[builtins.str] = None,
        function_definition_version_arn: typing.Optional[builtins.str] = None,
        logger_definition_version_arn: typing.Optional[builtins.str] = None,
        resource_definition_version_arn: typing.Optional[builtins.str] = None,
        subscription_definition_version_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnGroupVersion``.

        :param group_id: The ID of the group associated with this version. This value is a GUID.
        :param connector_definition_version_arn: The Amazon Resource Name (ARN) of the connector definition version that contains the connectors you want to deploy with the group version.
        :param core_definition_version_arn: The ARN of the core definition version that contains the core you want to deploy with the group version. Currently, the core definition version can contain only one core.
        :param device_definition_version_arn: The ARN of the device definition version that contains the devices you want to deploy with the group version.
        :param function_definition_version_arn: The ARN of the function definition version that contains the functions you want to deploy with the group version.
        :param logger_definition_version_arn: The ARN of the logger definition version that contains the loggers you want to deploy with the group version.
        :param resource_definition_version_arn: The ARN of the resource definition version that contains the resources you want to deploy with the group version.
        :param subscription_definition_version_arn: The ARN of the subscription definition version that contains the subscriptions you want to deploy with the group version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            cfn_group_version_props = greengrass.CfnGroupVersionProps(
                group_id="groupId",
            
                # the properties below are optional
                connector_definition_version_arn="connectorDefinitionVersionArn",
                core_definition_version_arn="coreDefinitionVersionArn",
                device_definition_version_arn="deviceDefinitionVersionArn",
                function_definition_version_arn="functionDefinitionVersionArn",
                logger_definition_version_arn="loggerDefinitionVersionArn",
                resource_definition_version_arn="resourceDefinitionVersionArn",
                subscription_definition_version_arn="subscriptionDefinitionVersionArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "group_id": group_id,
        }
        if connector_definition_version_arn is not None:
            self._values["connector_definition_version_arn"] = connector_definition_version_arn
        if core_definition_version_arn is not None:
            self._values["core_definition_version_arn"] = core_definition_version_arn
        if device_definition_version_arn is not None:
            self._values["device_definition_version_arn"] = device_definition_version_arn
        if function_definition_version_arn is not None:
            self._values["function_definition_version_arn"] = function_definition_version_arn
        if logger_definition_version_arn is not None:
            self._values["logger_definition_version_arn"] = logger_definition_version_arn
        if resource_definition_version_arn is not None:
            self._values["resource_definition_version_arn"] = resource_definition_version_arn
        if subscription_definition_version_arn is not None:
            self._values["subscription_definition_version_arn"] = subscription_definition_version_arn

    @builtins.property
    def group_id(self) -> builtins.str:
        '''The ID of the group associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-groupid
        '''
        result = self._values.get("group_id")
        assert result is not None, "Required property 'group_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def connector_definition_version_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the connector definition version that contains the connectors you want to deploy with the group version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-connectordefinitionversionarn
        '''
        result = self._values.get("connector_definition_version_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def core_definition_version_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the core definition version that contains the core you want to deploy with the group version.

        Currently, the core definition version can contain only one core.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-coredefinitionversionarn
        '''
        result = self._values.get("core_definition_version_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def device_definition_version_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the device definition version that contains the devices you want to deploy with the group version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-devicedefinitionversionarn
        '''
        result = self._values.get("device_definition_version_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def function_definition_version_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the function definition version that contains the functions you want to deploy with the group version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-functiondefinitionversionarn
        '''
        result = self._values.get("function_definition_version_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def logger_definition_version_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the logger definition version that contains the loggers you want to deploy with the group version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-loggerdefinitionversionarn
        '''
        result = self._values.get("logger_definition_version_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def resource_definition_version_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the resource definition version that contains the resources you want to deploy with the group version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-resourcedefinitionversionarn
        '''
        result = self._values.get("resource_definition_version_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def subscription_definition_version_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the subscription definition version that contains the subscriptions you want to deploy with the group version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-groupversion.html#cfn-greengrass-groupversion-subscriptiondefinitionversionarn
        '''
        result = self._values.get("subscription_definition_version_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnGroupVersionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnLoggerDefinition(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnLoggerDefinition",
):
    '''A CloudFormation ``AWS::Greengrass::LoggerDefinition``.

    The ``AWS::Greengrass::LoggerDefinition`` resource represents a logger definition for AWS IoT Greengrass . Logger definitions are used to organize your logger definition versions.

    Logger definitions can reference multiple logger definition versions. All logger definition versions must be associated with a logger definition. Each logger definition version can contain one or more loggers.
    .. epigraph::

       When you create a logger definition, you can optionally include an initial logger definition version. To associate a logger definition version later, create an ```AWS::Greengrass::LoggerDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinitionversion.html>`_ resource and specify the ID of this logger definition.

       After you create the logger definition version that contains the loggers you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::LoggerDefinition
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinition.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        # tags: Any
        
        cfn_logger_definition = greengrass.CfnLoggerDefinition(self, "MyCfnLoggerDefinition",
            name="name",
        
            # the properties below are optional
            initial_version=greengrass.CfnLoggerDefinition.LoggerDefinitionVersionProperty(
                loggers=[greengrass.CfnLoggerDefinition.LoggerProperty(
                    component="component",
                    id="id",
                    level="level",
                    type="type",
        
                    # the properties below are optional
                    space=123
                )]
            ),
            tags=tags
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union["CfnLoggerDefinition.LoggerDefinitionVersionProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Greengrass::LoggerDefinition``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the logger definition.
        :param initial_version: The logger definition version to include when the logger definition is created. A logger definition version contains a list of ```logger`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinition-logger.html>`_ property types. .. epigraph:: To associate a logger definition version after the logger definition is created, create an ```AWS::Greengrass::LoggerDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinitionversion.html>`_ resource and specify the ID of this logger definition.
        :param tags: Application-specific metadata to attach to the logger definition. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }
        '''
        props = CfnLoggerDefinitionProps(
            name=name, initial_version=initial_version, tags=tags
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
        '''The Amazon Resource Name (ARN) of the ``LoggerDefinition`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/loggers/1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the ``LoggerDefinition`` , such as ``1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLatestVersionArn")
    def attr_latest_version_arn(self) -> builtins.str:
        '''The ARN of the last ``LoggerDefinitionVersion`` that was added to the ``LoggerDefinition`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/loggers/1234a5b6-78cd-901e-2fgh-3i45j6k178l9/versions/9876ac30-4bdb-4f9d-95af-b5fdb66be1a2`` .

        :cloudformationAttribute: LatestVersionArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLatestVersionArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the ``LoggerDefinition`` , such as ``MyLoggerDefinition`` .

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
        '''Application-specific metadata to attach to the logger definition.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinition.html#cfn-greengrass-loggerdefinition-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the logger definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinition.html#cfn-greengrass-loggerdefinition-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="initialVersion")
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union["CfnLoggerDefinition.LoggerDefinitionVersionProperty", _IResolvable_da3f097b]]:
        '''The logger definition version to include when the logger definition is created.

        A logger definition version contains a list of ```logger`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinition-logger.html>`_ property types.
        .. epigraph::

           To associate a logger definition version after the logger definition is created, create an ```AWS::Greengrass::LoggerDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinitionversion.html>`_ resource and specify the ID of this logger definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinition.html#cfn-greengrass-loggerdefinition-initialversion
        '''
        return typing.cast(typing.Optional[typing.Union["CfnLoggerDefinition.LoggerDefinitionVersionProperty", _IResolvable_da3f097b]], jsii.get(self, "initialVersion"))

    @initial_version.setter
    def initial_version(
        self,
        value: typing.Optional[typing.Union["CfnLoggerDefinition.LoggerDefinitionVersionProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "initialVersion", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnLoggerDefinition.LoggerDefinitionVersionProperty",
        jsii_struct_bases=[],
        name_mapping={"loggers": "loggers"},
    )
    class LoggerDefinitionVersionProperty:
        def __init__(
            self,
            *,
            loggers: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnLoggerDefinition.LoggerProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A logger definition version contains a list of `loggers <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinition-logger.html>`_ .

            .. epigraph::

               After you create a logger definition version that contains the loggers you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

            In an AWS CloudFormation template, ``LoggerDefinitionVersion`` is the property type of the ``InitialVersion`` property in the ```AWS::Greengrass::LoggerDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinition.html>`_ resource.

            :param loggers: The loggers in this version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinition-loggerdefinitionversion.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                logger_definition_version_property = greengrass.CfnLoggerDefinition.LoggerDefinitionVersionProperty(
                    loggers=[greengrass.CfnLoggerDefinition.LoggerProperty(
                        component="component",
                        id="id",
                        level="level",
                        type="type",
                
                        # the properties below are optional
                        space=123
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "loggers": loggers,
            }

        @builtins.property
        def loggers(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLoggerDefinition.LoggerProperty", _IResolvable_da3f097b]]]:
            '''The loggers in this version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinition-loggerdefinitionversion.html#cfn-greengrass-loggerdefinition-loggerdefinitionversion-loggers
            '''
            result = self._values.get("loggers")
            assert result is not None, "Required property 'loggers' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLoggerDefinition.LoggerProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoggerDefinitionVersionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnLoggerDefinition.LoggerProperty",
        jsii_struct_bases=[],
        name_mapping={
            "component": "component",
            "id": "id",
            "level": "level",
            "type": "type",
            "space": "space",
        },
    )
    class LoggerProperty:
        def __init__(
            self,
            *,
            component: builtins.str,
            id: builtins.str,
            level: builtins.str,
            type: builtins.str,
            space: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''A logger represents logging settings for the AWS IoT Greengrass group, which can be stored in CloudWatch and the local file system of your core device.

            All log entries include a timestamp, log level, and information about the event. For more information, see `Monitoring with AWS IoT Greengrass Logs <https://docs.aws.amazon.com/greengrass/latest/developerguide/greengrass-logs-overview.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, the ``Loggers`` property of the ```LoggerDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinition-loggerdefinitionversion.html>`_ property type contains a list of ``Logger`` property types.

            :param component: The source of the log event. Valid values are ``GreengrassSystem`` or ``Lambda`` . When ``GreengrassSystem`` is used, events from Greengrass system components are logged. When ``Lambda`` is used, events from user-defined Lambda functions are logged.
            :param id: A descriptive or arbitrary ID for the logger. This value must be unique within the logger definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .
            :param level: The log-level threshold. Log events below this threshold are filtered out and aren't stored. Valid values are ``DEBUG`` , ``INFO`` (recommended), ``WARN`` , ``ERROR`` , or ``FATAL`` .
            :param type: The storage mechanism for log events. Valid values are ``FileSystem`` or ``AWSCloudWatch`` . When ``AWSCloudWatch`` is used, log events are sent to CloudWatch Logs . When ``FileSystem`` is used, log events are stored on the local file system.
            :param space: The amount of file space (in KB) to use when writing logs to the local file system. This property does not apply for CloudWatch Logs .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinition-logger.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                logger_property = greengrass.CfnLoggerDefinition.LoggerProperty(
                    component="component",
                    id="id",
                    level="level",
                    type="type",
                
                    # the properties below are optional
                    space=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "component": component,
                "id": id,
                "level": level,
                "type": type,
            }
            if space is not None:
                self._values["space"] = space

        @builtins.property
        def component(self) -> builtins.str:
            '''The source of the log event.

            Valid values are ``GreengrassSystem`` or ``Lambda`` . When ``GreengrassSystem`` is used, events from Greengrass system components are logged. When ``Lambda`` is used, events from user-defined Lambda functions are logged.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinition-logger.html#cfn-greengrass-loggerdefinition-logger-component
            '''
            result = self._values.get("component")
            assert result is not None, "Required property 'component' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def id(self) -> builtins.str:
            '''A descriptive or arbitrary ID for the logger.

            This value must be unique within the logger definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinition-logger.html#cfn-greengrass-loggerdefinition-logger-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def level(self) -> builtins.str:
            '''The log-level threshold.

            Log events below this threshold are filtered out and aren't stored. Valid values are ``DEBUG`` , ``INFO`` (recommended), ``WARN`` , ``ERROR`` , or ``FATAL`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinition-logger.html#cfn-greengrass-loggerdefinition-logger-level
            '''
            result = self._values.get("level")
            assert result is not None, "Required property 'level' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def type(self) -> builtins.str:
            '''The storage mechanism for log events.

            Valid values are ``FileSystem`` or ``AWSCloudWatch`` . When ``AWSCloudWatch`` is used, log events are sent to CloudWatch Logs . When ``FileSystem`` is used, log events are stored on the local file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinition-logger.html#cfn-greengrass-loggerdefinition-logger-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def space(self) -> typing.Optional[jsii.Number]:
            '''The amount of file space (in KB) to use when writing logs to the local file system.

            This property does not apply for CloudWatch Logs .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinition-logger.html#cfn-greengrass-loggerdefinition-logger-space
            '''
            result = self._values.get("space")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoggerProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnLoggerDefinitionProps",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "initial_version": "initialVersion", "tags": "tags"},
)
class CfnLoggerDefinitionProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union[CfnLoggerDefinition.LoggerDefinitionVersionProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnLoggerDefinition``.

        :param name: The name of the logger definition.
        :param initial_version: The logger definition version to include when the logger definition is created. A logger definition version contains a list of ```logger`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinition-logger.html>`_ property types. .. epigraph:: To associate a logger definition version after the logger definition is created, create an ```AWS::Greengrass::LoggerDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinitionversion.html>`_ resource and specify the ID of this logger definition.
        :param tags: Application-specific metadata to attach to the logger definition. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinition.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            # tags: Any
            
            cfn_logger_definition_props = greengrass.CfnLoggerDefinitionProps(
                name="name",
            
                # the properties below are optional
                initial_version=greengrass.CfnLoggerDefinition.LoggerDefinitionVersionProperty(
                    loggers=[greengrass.CfnLoggerDefinition.LoggerProperty(
                        component="component",
                        id="id",
                        level="level",
                        type="type",
            
                        # the properties below are optional
                        space=123
                    )]
                ),
                tags=tags
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if initial_version is not None:
            self._values["initial_version"] = initial_version
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the logger definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinition.html#cfn-greengrass-loggerdefinition-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union[CfnLoggerDefinition.LoggerDefinitionVersionProperty, _IResolvable_da3f097b]]:
        '''The logger definition version to include when the logger definition is created.

        A logger definition version contains a list of ```logger`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinition-logger.html>`_ property types.
        .. epigraph::

           To associate a logger definition version after the logger definition is created, create an ```AWS::Greengrass::LoggerDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinitionversion.html>`_ resource and specify the ID of this logger definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinition.html#cfn-greengrass-loggerdefinition-initialversion
        '''
        result = self._values.get("initial_version")
        return typing.cast(typing.Optional[typing.Union[CfnLoggerDefinition.LoggerDefinitionVersionProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''Application-specific metadata to attach to the logger definition.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinition.html#cfn-greengrass-loggerdefinition-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnLoggerDefinitionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnLoggerDefinitionVersion(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnLoggerDefinitionVersion",
):
    '''A CloudFormation ``AWS::Greengrass::LoggerDefinitionVersion``.

    The ``AWS::Greengrass::LoggerDefinitionVersion`` resource represents a logger definition version for AWS IoT Greengrass . A logger definition version contains a list of loggers.
    .. epigraph::

       To create a logger definition version, you must specify the ID of the logger definition that you want to associate with the version. For information about creating a logger definition, see ```AWS::Greengrass::LoggerDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinition.html>`_ .

       After you create a logger definition version that contains the loggers you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::LoggerDefinitionVersion
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinitionversion.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        cfn_logger_definition_version = greengrass.CfnLoggerDefinitionVersion(self, "MyCfnLoggerDefinitionVersion",
            logger_definition_id="loggerDefinitionId",
            loggers=[greengrass.CfnLoggerDefinitionVersion.LoggerProperty(
                component="component",
                id="id",
                level="level",
                type="type",
        
                # the properties below are optional
                space=123
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        logger_definition_id: builtins.str,
        loggers: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnLoggerDefinitionVersion.LoggerProperty", _IResolvable_da3f097b]]],
    ) -> None:
        '''Create a new ``AWS::Greengrass::LoggerDefinitionVersion``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param logger_definition_id: The ID of the logger definition associated with this version. This value is a GUID.
        :param loggers: The loggers in this version.
        '''
        props = CfnLoggerDefinitionVersionProps(
            logger_definition_id=logger_definition_id, loggers=loggers
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
    @jsii.member(jsii_name="loggerDefinitionId")
    def logger_definition_id(self) -> builtins.str:
        '''The ID of the logger definition associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinitionversion.html#cfn-greengrass-loggerdefinitionversion-loggerdefinitionid
        '''
        return typing.cast(builtins.str, jsii.get(self, "loggerDefinitionId"))

    @logger_definition_id.setter
    def logger_definition_id(self, value: builtins.str) -> None:
        jsii.set(self, "loggerDefinitionId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loggers")
    def loggers(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLoggerDefinitionVersion.LoggerProperty", _IResolvable_da3f097b]]]:
        '''The loggers in this version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinitionversion.html#cfn-greengrass-loggerdefinitionversion-loggers
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLoggerDefinitionVersion.LoggerProperty", _IResolvable_da3f097b]]], jsii.get(self, "loggers"))

    @loggers.setter
    def loggers(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLoggerDefinitionVersion.LoggerProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "loggers", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnLoggerDefinitionVersion.LoggerProperty",
        jsii_struct_bases=[],
        name_mapping={
            "component": "component",
            "id": "id",
            "level": "level",
            "type": "type",
            "space": "space",
        },
    )
    class LoggerProperty:
        def __init__(
            self,
            *,
            component: builtins.str,
            id: builtins.str,
            level: builtins.str,
            type: builtins.str,
            space: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''A logger represents logging settings for the AWS IoT Greengrass group, which can be stored in CloudWatch and the local file system of your core device.

            All log entries include a timestamp, log level, and information about the event. For more information, see `Monitoring with AWS IoT Greengrass Logs <https://docs.aws.amazon.com/greengrass/latest/developerguide/greengrass-logs-overview.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, the ``Loggers`` property of the ```AWS::Greengrass::LoggerDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinitionversion.html>`_ resource contains a list of ``Logger`` property types.

            :param component: The source of the log event. Valid values are ``GreengrassSystem`` or ``Lambda`` . When ``GreengrassSystem`` is used, events from Greengrass system components are logged. When ``Lambda`` is used, events from user-defined Lambda functions are logged.
            :param id: A descriptive or arbitrary ID for the logger. This value must be unique within the logger definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .
            :param level: The log-level threshold. Log events below this threshold are filtered out and aren't stored. Valid values are ``DEBUG`` , ``INFO`` (recommended), ``WARN`` , ``ERROR`` , or ``FATAL`` .
            :param type: The storage mechanism for log events. Valid values are ``FileSystem`` or ``AWSCloudWatch`` . When ``AWSCloudWatch`` is used, log events are sent to CloudWatch Logs . When ``FileSystem`` is used, log events are stored on the local file system.
            :param space: The amount of file space (in KB) to use when writing logs to the local file system. This property does not apply for CloudWatch Logs .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinitionversion-logger.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                logger_property = greengrass.CfnLoggerDefinitionVersion.LoggerProperty(
                    component="component",
                    id="id",
                    level="level",
                    type="type",
                
                    # the properties below are optional
                    space=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "component": component,
                "id": id,
                "level": level,
                "type": type,
            }
            if space is not None:
                self._values["space"] = space

        @builtins.property
        def component(self) -> builtins.str:
            '''The source of the log event.

            Valid values are ``GreengrassSystem`` or ``Lambda`` . When ``GreengrassSystem`` is used, events from Greengrass system components are logged. When ``Lambda`` is used, events from user-defined Lambda functions are logged.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinitionversion-logger.html#cfn-greengrass-loggerdefinitionversion-logger-component
            '''
            result = self._values.get("component")
            assert result is not None, "Required property 'component' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def id(self) -> builtins.str:
            '''A descriptive or arbitrary ID for the logger.

            This value must be unique within the logger definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinitionversion-logger.html#cfn-greengrass-loggerdefinitionversion-logger-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def level(self) -> builtins.str:
            '''The log-level threshold.

            Log events below this threshold are filtered out and aren't stored. Valid values are ``DEBUG`` , ``INFO`` (recommended), ``WARN`` , ``ERROR`` , or ``FATAL`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinitionversion-logger.html#cfn-greengrass-loggerdefinitionversion-logger-level
            '''
            result = self._values.get("level")
            assert result is not None, "Required property 'level' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def type(self) -> builtins.str:
            '''The storage mechanism for log events.

            Valid values are ``FileSystem`` or ``AWSCloudWatch`` . When ``AWSCloudWatch`` is used, log events are sent to CloudWatch Logs . When ``FileSystem`` is used, log events are stored on the local file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinitionversion-logger.html#cfn-greengrass-loggerdefinitionversion-logger-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def space(self) -> typing.Optional[jsii.Number]:
            '''The amount of file space (in KB) to use when writing logs to the local file system.

            This property does not apply for CloudWatch Logs .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-loggerdefinitionversion-logger.html#cfn-greengrass-loggerdefinitionversion-logger-space
            '''
            result = self._values.get("space")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoggerProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnLoggerDefinitionVersionProps",
    jsii_struct_bases=[],
    name_mapping={"logger_definition_id": "loggerDefinitionId", "loggers": "loggers"},
)
class CfnLoggerDefinitionVersionProps:
    def __init__(
        self,
        *,
        logger_definition_id: builtins.str,
        loggers: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnLoggerDefinitionVersion.LoggerProperty, _IResolvable_da3f097b]]],
    ) -> None:
        '''Properties for defining a ``CfnLoggerDefinitionVersion``.

        :param logger_definition_id: The ID of the logger definition associated with this version. This value is a GUID.
        :param loggers: The loggers in this version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinitionversion.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            cfn_logger_definition_version_props = greengrass.CfnLoggerDefinitionVersionProps(
                logger_definition_id="loggerDefinitionId",
                loggers=[greengrass.CfnLoggerDefinitionVersion.LoggerProperty(
                    component="component",
                    id="id",
                    level="level",
                    type="type",
            
                    # the properties below are optional
                    space=123
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "logger_definition_id": logger_definition_id,
            "loggers": loggers,
        }

    @builtins.property
    def logger_definition_id(self) -> builtins.str:
        '''The ID of the logger definition associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinitionversion.html#cfn-greengrass-loggerdefinitionversion-loggerdefinitionid
        '''
        result = self._values.get("logger_definition_id")
        assert result is not None, "Required property 'logger_definition_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def loggers(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnLoggerDefinitionVersion.LoggerProperty, _IResolvable_da3f097b]]]:
        '''The loggers in this version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-loggerdefinitionversion.html#cfn-greengrass-loggerdefinitionversion-loggers
        '''
        result = self._values.get("loggers")
        assert result is not None, "Required property 'loggers' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnLoggerDefinitionVersion.LoggerProperty, _IResolvable_da3f097b]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnLoggerDefinitionVersionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnResourceDefinition(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinition",
):
    '''A CloudFormation ``AWS::Greengrass::ResourceDefinition``.

    The ``AWS::Greengrass::ResourceDefinition`` resource represents a resource definition for AWS IoT Greengrass . Resource definitions are used to organize your resource definition versions.

    Resource definitions can reference multiple resource definition versions. All resource definition versions must be associated with a resource definition. Each resource definition version can contain one or more resources. (In AWS CloudFormation , resources are named *resource instances* .)
    .. epigraph::

       When you create a resource definition, you can optionally include an initial resource definition version. To associate a resource definition version later, create an ```AWS::Greengrass::ResourceDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinitionversion.html>`_ resource and specify the ID of this resource definition.

       After you create the resource definition version that contains the resources you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::ResourceDefinition
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinition.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        # tags: Any
        
        cfn_resource_definition = greengrass.CfnResourceDefinition(self, "MyCfnResourceDefinition",
            name="name",
        
            # the properties below are optional
            initial_version=greengrass.CfnResourceDefinition.ResourceDefinitionVersionProperty(
                resources=[greengrass.CfnResourceDefinition.ResourceInstanceProperty(
                    id="id",
                    name="name",
                    resource_data_container=greengrass.CfnResourceDefinition.ResourceDataContainerProperty(
                        local_device_resource_data=greengrass.CfnResourceDefinition.LocalDeviceResourceDataProperty(
                            source_path="sourcePath",
        
                            # the properties below are optional
                            group_owner_setting=greengrass.CfnResourceDefinition.GroupOwnerSettingProperty(
                                auto_add_group_owner=False,
        
                                # the properties below are optional
                                group_owner="groupOwner"
                            )
                        ),
                        local_volume_resource_data=greengrass.CfnResourceDefinition.LocalVolumeResourceDataProperty(
                            destination_path="destinationPath",
                            source_path="sourcePath",
        
                            # the properties below are optional
                            group_owner_setting=greengrass.CfnResourceDefinition.GroupOwnerSettingProperty(
                                auto_add_group_owner=False,
        
                                # the properties below are optional
                                group_owner="groupOwner"
                            )
                        ),
                        s3_machine_learning_model_resource_data=greengrass.CfnResourceDefinition.S3MachineLearningModelResourceDataProperty(
                            destination_path="destinationPath",
                            s3_uri="s3Uri",
        
                            # the properties below are optional
                            owner_setting=greengrass.CfnResourceDefinition.ResourceDownloadOwnerSettingProperty(
                                group_owner="groupOwner",
                                group_permission="groupPermission"
                            )
                        ),
                        sage_maker_machine_learning_model_resource_data=greengrass.CfnResourceDefinition.SageMakerMachineLearningModelResourceDataProperty(
                            destination_path="destinationPath",
                            sage_maker_job_arn="sageMakerJobArn",
        
                            # the properties below are optional
                            owner_setting=greengrass.CfnResourceDefinition.ResourceDownloadOwnerSettingProperty(
                                group_owner="groupOwner",
                                group_permission="groupPermission"
                            )
                        ),
                        secrets_manager_secret_resource_data=greengrass.CfnResourceDefinition.SecretsManagerSecretResourceDataProperty(
                            arn="arn",
        
                            # the properties below are optional
                            additional_staging_labels_to_download=["additionalStagingLabelsToDownload"]
                        )
                    )
                )]
            ),
            tags=tags
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union["CfnResourceDefinition.ResourceDefinitionVersionProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Greengrass::ResourceDefinition``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the resource definition.
        :param initial_version: The resource definition version to include when the resource definition is created. A resource definition version contains a list of ```resource instance`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourceinstance.html>`_ property types. .. epigraph:: To associate a resource definition version after the resource definition is created, create an ```AWS::Greengrass::ResourceDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinitionversion.html>`_ resource and specify the ID of this resource definition.
        :param tags: Application-specific metadata to attach to the resource definition. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }
        '''
        props = CfnResourceDefinitionProps(
            name=name, initial_version=initial_version, tags=tags
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
        '''The Amazon Resource Name (ARN) of the ``ResourceDefinition`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/resources/1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the ``ResourceDefinition`` , such as ``1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLatestVersionArn")
    def attr_latest_version_arn(self) -> builtins.str:
        '''The ARN of the last ``ResourceDefinitionVersion`` that was added to the ``ResourceDefinition`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/resources/1234a5b6-78cd-901e-2fgh-3i45j6k178l9/versions/9876ac30-4bdb-4f9d-95af-b5fdb66be1a2`` .

        :cloudformationAttribute: LatestVersionArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLatestVersionArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the ``ResourceDefinition`` , such as ``MyResourceDefinition`` .

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
        '''Application-specific metadata to attach to the resource definition.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinition.html#cfn-greengrass-resourcedefinition-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the resource definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinition.html#cfn-greengrass-resourcedefinition-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="initialVersion")
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union["CfnResourceDefinition.ResourceDefinitionVersionProperty", _IResolvable_da3f097b]]:
        '''The resource definition version to include when the resource definition is created.

        A resource definition version contains a list of ```resource instance`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourceinstance.html>`_ property types.
        .. epigraph::

           To associate a resource definition version after the resource definition is created, create an ```AWS::Greengrass::ResourceDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinitionversion.html>`_ resource and specify the ID of this resource definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinition.html#cfn-greengrass-resourcedefinition-initialversion
        '''
        return typing.cast(typing.Optional[typing.Union["CfnResourceDefinition.ResourceDefinitionVersionProperty", _IResolvable_da3f097b]], jsii.get(self, "initialVersion"))

    @initial_version.setter
    def initial_version(
        self,
        value: typing.Optional[typing.Union["CfnResourceDefinition.ResourceDefinitionVersionProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "initialVersion", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinition.GroupOwnerSettingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "auto_add_group_owner": "autoAddGroupOwner",
            "group_owner": "groupOwner",
        },
    )
    class GroupOwnerSettingProperty:
        def __init__(
            self,
            *,
            auto_add_group_owner: typing.Union[builtins.bool, _IResolvable_da3f097b],
            group_owner: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Settings that define additional Linux OS group permissions to give to the Lambda function process.

            You can give the permissions of the Linux group that owns the resource or choose another Linux group. These permissions are in addition to the function's ``RunAs`` permissions.

            In an AWS CloudFormation template, ``GroupOwnerSetting`` is a property of the ```LocalDeviceResourceData`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-localdeviceresourcedata.html>`_ and ```LocalVolumeResourceData`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-localvolumeresourcedata.html>`_ property types.

            :param auto_add_group_owner: Indicates whether to give the privileges of the Linux group that owns the resource to the Lambda process. This gives the Lambda process the file access permissions of the Linux group.
            :param group_owner: The name of the Linux group whose privileges you want to add to the Lambda process. This value is ignored if ``AutoAddGroupOwner`` is true.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-groupownersetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                group_owner_setting_property = greengrass.CfnResourceDefinition.GroupOwnerSettingProperty(
                    auto_add_group_owner=False,
                
                    # the properties below are optional
                    group_owner="groupOwner"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "auto_add_group_owner": auto_add_group_owner,
            }
            if group_owner is not None:
                self._values["group_owner"] = group_owner

        @builtins.property
        def auto_add_group_owner(
            self,
        ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Indicates whether to give the privileges of the Linux group that owns the resource to the Lambda process.

            This gives the Lambda process the file access permissions of the Linux group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-groupownersetting.html#cfn-greengrass-resourcedefinition-groupownersetting-autoaddgroupowner
            '''
            result = self._values.get("auto_add_group_owner")
            assert result is not None, "Required property 'auto_add_group_owner' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def group_owner(self) -> typing.Optional[builtins.str]:
            '''The name of the Linux group whose privileges you want to add to the Lambda process.

            This value is ignored if ``AutoAddGroupOwner`` is true.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-groupownersetting.html#cfn-greengrass-resourcedefinition-groupownersetting-groupowner
            '''
            result = self._values.get("group_owner")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GroupOwnerSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinition.LocalDeviceResourceDataProperty",
        jsii_struct_bases=[],
        name_mapping={
            "source_path": "sourcePath",
            "group_owner_setting": "groupOwnerSetting",
        },
    )
    class LocalDeviceResourceDataProperty:
        def __init__(
            self,
            *,
            source_path: builtins.str,
            group_owner_setting: typing.Optional[typing.Union["CfnResourceDefinition.GroupOwnerSettingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Settings for a local device resource, which represents a file under ``/dev`` .

            For more information, see `Access Local Resources with Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-local-resources.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, ``LocalDeviceResourceData`` can be used in the ```ResourceDataContainer`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedatacontainer.html>`_ property type.

            :param source_path: The local absolute path of the device resource. The source path for a device resource can refer only to a character device or block device under ``/dev`` .
            :param group_owner_setting: Settings that define additional Linux OS group permissions to give to the Lambda function process.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-localdeviceresourcedata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                local_device_resource_data_property = greengrass.CfnResourceDefinition.LocalDeviceResourceDataProperty(
                    source_path="sourcePath",
                
                    # the properties below are optional
                    group_owner_setting=greengrass.CfnResourceDefinition.GroupOwnerSettingProperty(
                        auto_add_group_owner=False,
                
                        # the properties below are optional
                        group_owner="groupOwner"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "source_path": source_path,
            }
            if group_owner_setting is not None:
                self._values["group_owner_setting"] = group_owner_setting

        @builtins.property
        def source_path(self) -> builtins.str:
            '''The local absolute path of the device resource.

            The source path for a device resource can refer only to a character device or block device under ``/dev`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-localdeviceresourcedata.html#cfn-greengrass-resourcedefinition-localdeviceresourcedata-sourcepath
            '''
            result = self._values.get("source_path")
            assert result is not None, "Required property 'source_path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def group_owner_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinition.GroupOwnerSettingProperty", _IResolvable_da3f097b]]:
            '''Settings that define additional Linux OS group permissions to give to the Lambda function process.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-localdeviceresourcedata.html#cfn-greengrass-resourcedefinition-localdeviceresourcedata-groupownersetting
            '''
            result = self._values.get("group_owner_setting")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinition.GroupOwnerSettingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LocalDeviceResourceDataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinition.LocalVolumeResourceDataProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destination_path": "destinationPath",
            "source_path": "sourcePath",
            "group_owner_setting": "groupOwnerSetting",
        },
    )
    class LocalVolumeResourceDataProperty:
        def __init__(
            self,
            *,
            destination_path: builtins.str,
            source_path: builtins.str,
            group_owner_setting: typing.Optional[typing.Union["CfnResourceDefinition.GroupOwnerSettingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Settings for a local volume resource, which represents a file or directory on the root file system.

            For more information, see `Access Local Resources with Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-local-resources.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, ``LocalVolumeResourceData`` can be used in the ```ResourceDataContainer`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedatacontainer.html>`_ property type.

            :param destination_path: The absolute local path of the resource in the Lambda environment.
            :param source_path: The local absolute path of the volume resource on the host. The source path for a volume resource type cannot start with ``/sys`` .
            :param group_owner_setting: Settings that define additional Linux OS group permissions to give to the Lambda function process.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-localvolumeresourcedata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                local_volume_resource_data_property = greengrass.CfnResourceDefinition.LocalVolumeResourceDataProperty(
                    destination_path="destinationPath",
                    source_path="sourcePath",
                
                    # the properties below are optional
                    group_owner_setting=greengrass.CfnResourceDefinition.GroupOwnerSettingProperty(
                        auto_add_group_owner=False,
                
                        # the properties below are optional
                        group_owner="groupOwner"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination_path": destination_path,
                "source_path": source_path,
            }
            if group_owner_setting is not None:
                self._values["group_owner_setting"] = group_owner_setting

        @builtins.property
        def destination_path(self) -> builtins.str:
            '''The absolute local path of the resource in the Lambda environment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-localvolumeresourcedata.html#cfn-greengrass-resourcedefinition-localvolumeresourcedata-destinationpath
            '''
            result = self._values.get("destination_path")
            assert result is not None, "Required property 'destination_path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def source_path(self) -> builtins.str:
            '''The local absolute path of the volume resource on the host.

            The source path for a volume resource type cannot start with ``/sys`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-localvolumeresourcedata.html#cfn-greengrass-resourcedefinition-localvolumeresourcedata-sourcepath
            '''
            result = self._values.get("source_path")
            assert result is not None, "Required property 'source_path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def group_owner_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinition.GroupOwnerSettingProperty", _IResolvable_da3f097b]]:
            '''Settings that define additional Linux OS group permissions to give to the Lambda function process.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-localvolumeresourcedata.html#cfn-greengrass-resourcedefinition-localvolumeresourcedata-groupownersetting
            '''
            result = self._values.get("group_owner_setting")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinition.GroupOwnerSettingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LocalVolumeResourceDataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinition.ResourceDataContainerProperty",
        jsii_struct_bases=[],
        name_mapping={
            "local_device_resource_data": "localDeviceResourceData",
            "local_volume_resource_data": "localVolumeResourceData",
            "s3_machine_learning_model_resource_data": "s3MachineLearningModelResourceData",
            "sage_maker_machine_learning_model_resource_data": "sageMakerMachineLearningModelResourceData",
            "secrets_manager_secret_resource_data": "secretsManagerSecretResourceData",
        },
    )
    class ResourceDataContainerProperty:
        def __init__(
            self,
            *,
            local_device_resource_data: typing.Optional[typing.Union["CfnResourceDefinition.LocalDeviceResourceDataProperty", _IResolvable_da3f097b]] = None,
            local_volume_resource_data: typing.Optional[typing.Union["CfnResourceDefinition.LocalVolumeResourceDataProperty", _IResolvable_da3f097b]] = None,
            s3_machine_learning_model_resource_data: typing.Optional[typing.Union["CfnResourceDefinition.S3MachineLearningModelResourceDataProperty", _IResolvable_da3f097b]] = None,
            sage_maker_machine_learning_model_resource_data: typing.Optional[typing.Union["CfnResourceDefinition.SageMakerMachineLearningModelResourceDataProperty", _IResolvable_da3f097b]] = None,
            secrets_manager_secret_resource_data: typing.Optional[typing.Union["CfnResourceDefinition.SecretsManagerSecretResourceDataProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A container for resource data, which defines the resource type.

            The container takes only one of the following supported resource data types: ``LocalDeviceResourceData`` , ``LocalVolumeResourceData`` , ``SageMakerMachineLearningModelResourceData`` , ``S3MachineLearningModelResourceData`` , or ``SecretsManagerSecretResourceData`` .
            .. epigraph::

               Only one resource type can be defined for a ``ResourceDataContainer`` instance.

            In an AWS CloudFormation template, ``ResourceDataContainer`` is a property of the ```ResourceInstance`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourceinstance.html>`_ property type.

            :param local_device_resource_data: Settings for a local device resource.
            :param local_volume_resource_data: Settings for a local volume resource.
            :param s3_machine_learning_model_resource_data: Settings for a machine learning resource stored in Amazon S3 .
            :param sage_maker_machine_learning_model_resource_data: Settings for a machine learning resource saved as an SageMaker training job.
            :param secrets_manager_secret_resource_data: Settings for a secret resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedatacontainer.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                resource_data_container_property = greengrass.CfnResourceDefinition.ResourceDataContainerProperty(
                    local_device_resource_data=greengrass.CfnResourceDefinition.LocalDeviceResourceDataProperty(
                        source_path="sourcePath",
                
                        # the properties below are optional
                        group_owner_setting=greengrass.CfnResourceDefinition.GroupOwnerSettingProperty(
                            auto_add_group_owner=False,
                
                            # the properties below are optional
                            group_owner="groupOwner"
                        )
                    ),
                    local_volume_resource_data=greengrass.CfnResourceDefinition.LocalVolumeResourceDataProperty(
                        destination_path="destinationPath",
                        source_path="sourcePath",
                
                        # the properties below are optional
                        group_owner_setting=greengrass.CfnResourceDefinition.GroupOwnerSettingProperty(
                            auto_add_group_owner=False,
                
                            # the properties below are optional
                            group_owner="groupOwner"
                        )
                    ),
                    s3_machine_learning_model_resource_data=greengrass.CfnResourceDefinition.S3MachineLearningModelResourceDataProperty(
                        destination_path="destinationPath",
                        s3_uri="s3Uri",
                
                        # the properties below are optional
                        owner_setting=greengrass.CfnResourceDefinition.ResourceDownloadOwnerSettingProperty(
                            group_owner="groupOwner",
                            group_permission="groupPermission"
                        )
                    ),
                    sage_maker_machine_learning_model_resource_data=greengrass.CfnResourceDefinition.SageMakerMachineLearningModelResourceDataProperty(
                        destination_path="destinationPath",
                        sage_maker_job_arn="sageMakerJobArn",
                
                        # the properties below are optional
                        owner_setting=greengrass.CfnResourceDefinition.ResourceDownloadOwnerSettingProperty(
                            group_owner="groupOwner",
                            group_permission="groupPermission"
                        )
                    ),
                    secrets_manager_secret_resource_data=greengrass.CfnResourceDefinition.SecretsManagerSecretResourceDataProperty(
                        arn="arn",
                
                        # the properties below are optional
                        additional_staging_labels_to_download=["additionalStagingLabelsToDownload"]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if local_device_resource_data is not None:
                self._values["local_device_resource_data"] = local_device_resource_data
            if local_volume_resource_data is not None:
                self._values["local_volume_resource_data"] = local_volume_resource_data
            if s3_machine_learning_model_resource_data is not None:
                self._values["s3_machine_learning_model_resource_data"] = s3_machine_learning_model_resource_data
            if sage_maker_machine_learning_model_resource_data is not None:
                self._values["sage_maker_machine_learning_model_resource_data"] = sage_maker_machine_learning_model_resource_data
            if secrets_manager_secret_resource_data is not None:
                self._values["secrets_manager_secret_resource_data"] = secrets_manager_secret_resource_data

        @builtins.property
        def local_device_resource_data(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinition.LocalDeviceResourceDataProperty", _IResolvable_da3f097b]]:
            '''Settings for a local device resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedatacontainer.html#cfn-greengrass-resourcedefinition-resourcedatacontainer-localdeviceresourcedata
            '''
            result = self._values.get("local_device_resource_data")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinition.LocalDeviceResourceDataProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def local_volume_resource_data(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinition.LocalVolumeResourceDataProperty", _IResolvable_da3f097b]]:
            '''Settings for a local volume resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedatacontainer.html#cfn-greengrass-resourcedefinition-resourcedatacontainer-localvolumeresourcedata
            '''
            result = self._values.get("local_volume_resource_data")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinition.LocalVolumeResourceDataProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def s3_machine_learning_model_resource_data(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinition.S3MachineLearningModelResourceDataProperty", _IResolvable_da3f097b]]:
            '''Settings for a machine learning resource stored in Amazon S3 .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedatacontainer.html#cfn-greengrass-resourcedefinition-resourcedatacontainer-s3machinelearningmodelresourcedata
            '''
            result = self._values.get("s3_machine_learning_model_resource_data")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinition.S3MachineLearningModelResourceDataProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sage_maker_machine_learning_model_resource_data(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinition.SageMakerMachineLearningModelResourceDataProperty", _IResolvable_da3f097b]]:
            '''Settings for a machine learning resource saved as an SageMaker training job.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedatacontainer.html#cfn-greengrass-resourcedefinition-resourcedatacontainer-sagemakermachinelearningmodelresourcedata
            '''
            result = self._values.get("sage_maker_machine_learning_model_resource_data")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinition.SageMakerMachineLearningModelResourceDataProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def secrets_manager_secret_resource_data(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinition.SecretsManagerSecretResourceDataProperty", _IResolvable_da3f097b]]:
            '''Settings for a secret resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedatacontainer.html#cfn-greengrass-resourcedefinition-resourcedatacontainer-secretsmanagersecretresourcedata
            '''
            result = self._values.get("secrets_manager_secret_resource_data")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinition.SecretsManagerSecretResourceDataProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourceDataContainerProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinition.ResourceDefinitionVersionProperty",
        jsii_struct_bases=[],
        name_mapping={"resources": "resources"},
    )
    class ResourceDefinitionVersionProperty:
        def __init__(
            self,
            *,
            resources: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnResourceDefinition.ResourceInstanceProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A resource definition version contains a list of resources. (In AWS CloudFormation , resources are named *resource instances* .).

            .. epigraph::

               After you create a resource definition version that contains the resources you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

            In an AWS CloudFormation template, ``ResourceDefinitionVersion`` is the property type of the ``InitialVersion`` property in the ```AWS::Greengrass::ResourceDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinition.html>`_ resource.

            :param resources: The resources in this version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedefinitionversion.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                resource_definition_version_property = greengrass.CfnResourceDefinition.ResourceDefinitionVersionProperty(
                    resources=[greengrass.CfnResourceDefinition.ResourceInstanceProperty(
                        id="id",
                        name="name",
                        resource_data_container=greengrass.CfnResourceDefinition.ResourceDataContainerProperty(
                            local_device_resource_data=greengrass.CfnResourceDefinition.LocalDeviceResourceDataProperty(
                                source_path="sourcePath",
                
                                # the properties below are optional
                                group_owner_setting=greengrass.CfnResourceDefinition.GroupOwnerSettingProperty(
                                    auto_add_group_owner=False,
                
                                    # the properties below are optional
                                    group_owner="groupOwner"
                                )
                            ),
                            local_volume_resource_data=greengrass.CfnResourceDefinition.LocalVolumeResourceDataProperty(
                                destination_path="destinationPath",
                                source_path="sourcePath",
                
                                # the properties below are optional
                                group_owner_setting=greengrass.CfnResourceDefinition.GroupOwnerSettingProperty(
                                    auto_add_group_owner=False,
                
                                    # the properties below are optional
                                    group_owner="groupOwner"
                                )
                            ),
                            s3_machine_learning_model_resource_data=greengrass.CfnResourceDefinition.S3MachineLearningModelResourceDataProperty(
                                destination_path="destinationPath",
                                s3_uri="s3Uri",
                
                                # the properties below are optional
                                owner_setting=greengrass.CfnResourceDefinition.ResourceDownloadOwnerSettingProperty(
                                    group_owner="groupOwner",
                                    group_permission="groupPermission"
                                )
                            ),
                            sage_maker_machine_learning_model_resource_data=greengrass.CfnResourceDefinition.SageMakerMachineLearningModelResourceDataProperty(
                                destination_path="destinationPath",
                                sage_maker_job_arn="sageMakerJobArn",
                
                                # the properties below are optional
                                owner_setting=greengrass.CfnResourceDefinition.ResourceDownloadOwnerSettingProperty(
                                    group_owner="groupOwner",
                                    group_permission="groupPermission"
                                )
                            ),
                            secrets_manager_secret_resource_data=greengrass.CfnResourceDefinition.SecretsManagerSecretResourceDataProperty(
                                arn="arn",
                
                                # the properties below are optional
                                additional_staging_labels_to_download=["additionalStagingLabelsToDownload"]
                            )
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "resources": resources,
            }

        @builtins.property
        def resources(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnResourceDefinition.ResourceInstanceProperty", _IResolvable_da3f097b]]]:
            '''The resources in this version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedefinitionversion.html#cfn-greengrass-resourcedefinition-resourcedefinitionversion-resources
            '''
            result = self._values.get("resources")
            assert result is not None, "Required property 'resources' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnResourceDefinition.ResourceInstanceProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourceDefinitionVersionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinition.ResourceDownloadOwnerSettingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "group_owner": "groupOwner",
            "group_permission": "groupPermission",
        },
    )
    class ResourceDownloadOwnerSettingProperty:
        def __init__(
            self,
            *,
            group_owner: builtins.str,
            group_permission: builtins.str,
        ) -> None:
            '''The owner setting for a downloaded machine learning resource.

            For more information, see `Access Machine Learning Resources from Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-ml-resources.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, ``ResourceDownloadOwnerSetting`` is the property type of the ``OwnerSetting`` property for the ```S3MachineLearningModelResourceData`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-s3machinelearningmodelresourcedata.html>`_ and ```SageMakerMachineLearningModelResourceData`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-sagemakermachinelearningmodelresourcedata.html>`_ property types.

            :param group_owner: The group owner of the machine learning resource. This is the group ID (GID) of an existing Linux OS group on the system. The group's permissions are added to the Lambda process.
            :param group_permission: The permissions that the group owner has to the machine learning resource. Valid values are ``rw`` (read-write) or ``ro`` (read-only).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedownloadownersetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                resource_download_owner_setting_property = greengrass.CfnResourceDefinition.ResourceDownloadOwnerSettingProperty(
                    group_owner="groupOwner",
                    group_permission="groupPermission"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "group_owner": group_owner,
                "group_permission": group_permission,
            }

        @builtins.property
        def group_owner(self) -> builtins.str:
            '''The group owner of the machine learning resource.

            This is the group ID (GID) of an existing Linux OS group on the system. The group's permissions are added to the Lambda process.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedownloadownersetting.html#cfn-greengrass-resourcedefinition-resourcedownloadownersetting-groupowner
            '''
            result = self._values.get("group_owner")
            assert result is not None, "Required property 'group_owner' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def group_permission(self) -> builtins.str:
            '''The permissions that the group owner has to the machine learning resource.

            Valid values are ``rw`` (read-write) or ``ro`` (read-only).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedownloadownersetting.html#cfn-greengrass-resourcedefinition-resourcedownloadownersetting-grouppermission
            '''
            result = self._values.get("group_permission")
            assert result is not None, "Required property 'group_permission' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourceDownloadOwnerSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinition.ResourceInstanceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "id": "id",
            "name": "name",
            "resource_data_container": "resourceDataContainer",
        },
    )
    class ResourceInstanceProperty:
        def __init__(
            self,
            *,
            id: builtins.str,
            name: builtins.str,
            resource_data_container: typing.Union["CfnResourceDefinition.ResourceDataContainerProperty", _IResolvable_da3f097b],
        ) -> None:
            '''A local resource, machine learning resource, or secret resource.

            For more information, see `Access Local Resources with Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-local-resources.html>`_ , `Perform Machine Learning Inference <https://docs.aws.amazon.com/greengrass/latest/developerguide/ml-inference.html>`_ , and `Deploy Secrets to the AWS IoT Greengrass Core <https://docs.aws.amazon.com/greengrass/latest/developerguide/secrets.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, the ``Resources`` property of the ```AWS::Greengrass::ResourceDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinition.html>`_ resource contains a list of ``ResourceInstance`` property types.

            :param id: A descriptive or arbitrary ID for the resource. This value must be unique within the resource definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .
            :param name: The descriptive resource name, which is displayed on the AWS IoT Greengrass console. Maximum length 128 characters with pattern [a-zA-Z0-9:_-]+. This must be unique within a Greengrass group.
            :param resource_data_container: A container for resource data. The container takes only one of the following supported resource data types: ``LocalDeviceResourceData`` , ``LocalVolumeResourceData`` , ``SageMakerMachineLearningModelResourceData`` , ``S3MachineLearningModelResourceData`` , or ``SecretsManagerSecretResourceData`` . .. epigraph:: Only one resource type can be defined for a ``ResourceDataContainer`` instance.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourceinstance.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                resource_instance_property = greengrass.CfnResourceDefinition.ResourceInstanceProperty(
                    id="id",
                    name="name",
                    resource_data_container=greengrass.CfnResourceDefinition.ResourceDataContainerProperty(
                        local_device_resource_data=greengrass.CfnResourceDefinition.LocalDeviceResourceDataProperty(
                            source_path="sourcePath",
                
                            # the properties below are optional
                            group_owner_setting=greengrass.CfnResourceDefinition.GroupOwnerSettingProperty(
                                auto_add_group_owner=False,
                
                                # the properties below are optional
                                group_owner="groupOwner"
                            )
                        ),
                        local_volume_resource_data=greengrass.CfnResourceDefinition.LocalVolumeResourceDataProperty(
                            destination_path="destinationPath",
                            source_path="sourcePath",
                
                            # the properties below are optional
                            group_owner_setting=greengrass.CfnResourceDefinition.GroupOwnerSettingProperty(
                                auto_add_group_owner=False,
                
                                # the properties below are optional
                                group_owner="groupOwner"
                            )
                        ),
                        s3_machine_learning_model_resource_data=greengrass.CfnResourceDefinition.S3MachineLearningModelResourceDataProperty(
                            destination_path="destinationPath",
                            s3_uri="s3Uri",
                
                            # the properties below are optional
                            owner_setting=greengrass.CfnResourceDefinition.ResourceDownloadOwnerSettingProperty(
                                group_owner="groupOwner",
                                group_permission="groupPermission"
                            )
                        ),
                        sage_maker_machine_learning_model_resource_data=greengrass.CfnResourceDefinition.SageMakerMachineLearningModelResourceDataProperty(
                            destination_path="destinationPath",
                            sage_maker_job_arn="sageMakerJobArn",
                
                            # the properties below are optional
                            owner_setting=greengrass.CfnResourceDefinition.ResourceDownloadOwnerSettingProperty(
                                group_owner="groupOwner",
                                group_permission="groupPermission"
                            )
                        ),
                        secrets_manager_secret_resource_data=greengrass.CfnResourceDefinition.SecretsManagerSecretResourceDataProperty(
                            arn="arn",
                
                            # the properties below are optional
                            additional_staging_labels_to_download=["additionalStagingLabelsToDownload"]
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "id": id,
                "name": name,
                "resource_data_container": resource_data_container,
            }

        @builtins.property
        def id(self) -> builtins.str:
            '''A descriptive or arbitrary ID for the resource.

            This value must be unique within the resource definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourceinstance.html#cfn-greengrass-resourcedefinition-resourceinstance-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The descriptive resource name, which is displayed on the AWS IoT Greengrass console.

            Maximum length 128 characters with pattern [a-zA-Z0-9:_-]+. This must be unique within a Greengrass group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourceinstance.html#cfn-greengrass-resourcedefinition-resourceinstance-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def resource_data_container(
            self,
        ) -> typing.Union["CfnResourceDefinition.ResourceDataContainerProperty", _IResolvable_da3f097b]:
            '''A container for resource data.

            The container takes only one of the following supported resource data types: ``LocalDeviceResourceData`` , ``LocalVolumeResourceData`` , ``SageMakerMachineLearningModelResourceData`` , ``S3MachineLearningModelResourceData`` , or ``SecretsManagerSecretResourceData`` .
            .. epigraph::

               Only one resource type can be defined for a ``ResourceDataContainer`` instance.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourceinstance.html#cfn-greengrass-resourcedefinition-resourceinstance-resourcedatacontainer
            '''
            result = self._values.get("resource_data_container")
            assert result is not None, "Required property 'resource_data_container' is missing"
            return typing.cast(typing.Union["CfnResourceDefinition.ResourceDataContainerProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourceInstanceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinition.S3MachineLearningModelResourceDataProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destination_path": "destinationPath",
            "s3_uri": "s3Uri",
            "owner_setting": "ownerSetting",
        },
    )
    class S3MachineLearningModelResourceDataProperty:
        def __init__(
            self,
            *,
            destination_path: builtins.str,
            s3_uri: builtins.str,
            owner_setting: typing.Optional[typing.Union["CfnResourceDefinition.ResourceDownloadOwnerSettingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Settings for an Amazon S3 machine learning resource.

            For more information, see `Perform Machine Learning Inference <https://docs.aws.amazon.com/greengrass/latest/developerguide/ml-inference.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, ``S3MachineLearningModelResourceData`` can be used in the ```ResourceDataContainer`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedatacontainer.html>`_ property type.

            :param destination_path: The absolute local path of the resource inside the Lambda environment.
            :param s3_uri: The URI of the source model in an Amazon S3 bucket. The model package must be in ``tar.gz`` or ``.zip`` format.
            :param owner_setting: The owner setting for the downloaded machine learning resource. For more information, see `Access Machine Learning Resources from Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-ml-resources.html>`_ in the *Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-s3machinelearningmodelresourcedata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                s3_machine_learning_model_resource_data_property = greengrass.CfnResourceDefinition.S3MachineLearningModelResourceDataProperty(
                    destination_path="destinationPath",
                    s3_uri="s3Uri",
                
                    # the properties below are optional
                    owner_setting=greengrass.CfnResourceDefinition.ResourceDownloadOwnerSettingProperty(
                        group_owner="groupOwner",
                        group_permission="groupPermission"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination_path": destination_path,
                "s3_uri": s3_uri,
            }
            if owner_setting is not None:
                self._values["owner_setting"] = owner_setting

        @builtins.property
        def destination_path(self) -> builtins.str:
            '''The absolute local path of the resource inside the Lambda environment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-s3machinelearningmodelresourcedata.html#cfn-greengrass-resourcedefinition-s3machinelearningmodelresourcedata-destinationpath
            '''
            result = self._values.get("destination_path")
            assert result is not None, "Required property 'destination_path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_uri(self) -> builtins.str:
            '''The URI of the source model in an Amazon S3 bucket.

            The model package must be in ``tar.gz`` or ``.zip`` format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-s3machinelearningmodelresourcedata.html#cfn-greengrass-resourcedefinition-s3machinelearningmodelresourcedata-s3uri
            '''
            result = self._values.get("s3_uri")
            assert result is not None, "Required property 's3_uri' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def owner_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinition.ResourceDownloadOwnerSettingProperty", _IResolvable_da3f097b]]:
            '''The owner setting for the downloaded machine learning resource.

            For more information, see `Access Machine Learning Resources from Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-ml-resources.html>`_ in the *Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-s3machinelearningmodelresourcedata.html#cfn-greengrass-resourcedefinition-s3machinelearningmodelresourcedata-ownersetting
            '''
            result = self._values.get("owner_setting")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinition.ResourceDownloadOwnerSettingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3MachineLearningModelResourceDataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinition.SageMakerMachineLearningModelResourceDataProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destination_path": "destinationPath",
            "sage_maker_job_arn": "sageMakerJobArn",
            "owner_setting": "ownerSetting",
        },
    )
    class SageMakerMachineLearningModelResourceDataProperty:
        def __init__(
            self,
            *,
            destination_path: builtins.str,
            sage_maker_job_arn: builtins.str,
            owner_setting: typing.Optional[typing.Union["CfnResourceDefinition.ResourceDownloadOwnerSettingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Settings for an Secrets Manager machine learning resource.

            For more information, see `Perform Machine Learning Inference <https://docs.aws.amazon.com/greengrass/latest/developerguide/ml-inference.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, ``SageMakerMachineLearningModelResourceData`` can be used in the ```ResourceDataContainer`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedatacontainer.html>`_ property type.

            :param destination_path: The absolute local path of the resource inside the Lambda environment.
            :param sage_maker_job_arn: The Amazon Resource Name (ARN) of the Amazon SageMaker training job that represents the source model.
            :param owner_setting: The owner setting for the downloaded machine learning resource. For more information, see `Access Machine Learning Resources from Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-ml-resources.html>`_ in the *Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-sagemakermachinelearningmodelresourcedata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                sage_maker_machine_learning_model_resource_data_property = greengrass.CfnResourceDefinition.SageMakerMachineLearningModelResourceDataProperty(
                    destination_path="destinationPath",
                    sage_maker_job_arn="sageMakerJobArn",
                
                    # the properties below are optional
                    owner_setting=greengrass.CfnResourceDefinition.ResourceDownloadOwnerSettingProperty(
                        group_owner="groupOwner",
                        group_permission="groupPermission"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination_path": destination_path,
                "sage_maker_job_arn": sage_maker_job_arn,
            }
            if owner_setting is not None:
                self._values["owner_setting"] = owner_setting

        @builtins.property
        def destination_path(self) -> builtins.str:
            '''The absolute local path of the resource inside the Lambda environment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-sagemakermachinelearningmodelresourcedata.html#cfn-greengrass-resourcedefinition-sagemakermachinelearningmodelresourcedata-destinationpath
            '''
            result = self._values.get("destination_path")
            assert result is not None, "Required property 'destination_path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def sage_maker_job_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the Amazon SageMaker training job that represents the source model.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-sagemakermachinelearningmodelresourcedata.html#cfn-greengrass-resourcedefinition-sagemakermachinelearningmodelresourcedata-sagemakerjobarn
            '''
            result = self._values.get("sage_maker_job_arn")
            assert result is not None, "Required property 'sage_maker_job_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def owner_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinition.ResourceDownloadOwnerSettingProperty", _IResolvable_da3f097b]]:
            '''The owner setting for the downloaded machine learning resource.

            For more information, see `Access Machine Learning Resources from Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-ml-resources.html>`_ in the *Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-sagemakermachinelearningmodelresourcedata.html#cfn-greengrass-resourcedefinition-sagemakermachinelearningmodelresourcedata-ownersetting
            '''
            result = self._values.get("owner_setting")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinition.ResourceDownloadOwnerSettingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SageMakerMachineLearningModelResourceDataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinition.SecretsManagerSecretResourceDataProperty",
        jsii_struct_bases=[],
        name_mapping={
            "arn": "arn",
            "additional_staging_labels_to_download": "additionalStagingLabelsToDownload",
        },
    )
    class SecretsManagerSecretResourceDataProperty:
        def __init__(
            self,
            *,
            arn: builtins.str,
            additional_staging_labels_to_download: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Settings for a secret resource, which references a secret from AWS Secrets Manager .

            AWS IoT Greengrass stores a local, encrypted copy of the secret on the Greengrass core, where it can be securely accessed by connectors and Lambda functions. For more information, see `Deploy Secrets to the AWS IoT Greengrass Core <https://docs.aws.amazon.com/greengrass/latest/developerguide/secrets.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, ``SecretsManagerSecretResourceData`` can be used in the ```ResourceDataContainer`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourcedatacontainer.html>`_ property type.

            :param arn: The Amazon Resource Name (ARN) of the Secrets Manager secret to make available on the core. The value of the secret's latest version (represented by the ``AWSCURRENT`` staging label) is included by default.
            :param additional_staging_labels_to_download: The staging labels whose values you want to make available on the core, in addition to ``AWSCURRENT`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-secretsmanagersecretresourcedata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                secrets_manager_secret_resource_data_property = greengrass.CfnResourceDefinition.SecretsManagerSecretResourceDataProperty(
                    arn="arn",
                
                    # the properties below are optional
                    additional_staging_labels_to_download=["additionalStagingLabelsToDownload"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
            }
            if additional_staging_labels_to_download is not None:
                self._values["additional_staging_labels_to_download"] = additional_staging_labels_to_download

        @builtins.property
        def arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the Secrets Manager secret to make available on the core.

            The value of the secret's latest version (represented by the ``AWSCURRENT`` staging label) is included by default.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-secretsmanagersecretresourcedata.html#cfn-greengrass-resourcedefinition-secretsmanagersecretresourcedata-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def additional_staging_labels_to_download(
            self,
        ) -> typing.Optional[typing.List[builtins.str]]:
            '''The staging labels whose values you want to make available on the core, in addition to ``AWSCURRENT`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-secretsmanagersecretresourcedata.html#cfn-greengrass-resourcedefinition-secretsmanagersecretresourcedata-additionalstaginglabelstodownload
            '''
            result = self._values.get("additional_staging_labels_to_download")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SecretsManagerSecretResourceDataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinitionProps",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "initial_version": "initialVersion", "tags": "tags"},
)
class CfnResourceDefinitionProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union[CfnResourceDefinition.ResourceDefinitionVersionProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnResourceDefinition``.

        :param name: The name of the resource definition.
        :param initial_version: The resource definition version to include when the resource definition is created. A resource definition version contains a list of ```resource instance`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourceinstance.html>`_ property types. .. epigraph:: To associate a resource definition version after the resource definition is created, create an ```AWS::Greengrass::ResourceDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinitionversion.html>`_ resource and specify the ID of this resource definition.
        :param tags: Application-specific metadata to attach to the resource definition. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinition.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            # tags: Any
            
            cfn_resource_definition_props = greengrass.CfnResourceDefinitionProps(
                name="name",
            
                # the properties below are optional
                initial_version=greengrass.CfnResourceDefinition.ResourceDefinitionVersionProperty(
                    resources=[greengrass.CfnResourceDefinition.ResourceInstanceProperty(
                        id="id",
                        name="name",
                        resource_data_container=greengrass.CfnResourceDefinition.ResourceDataContainerProperty(
                            local_device_resource_data=greengrass.CfnResourceDefinition.LocalDeviceResourceDataProperty(
                                source_path="sourcePath",
            
                                # the properties below are optional
                                group_owner_setting=greengrass.CfnResourceDefinition.GroupOwnerSettingProperty(
                                    auto_add_group_owner=False,
            
                                    # the properties below are optional
                                    group_owner="groupOwner"
                                )
                            ),
                            local_volume_resource_data=greengrass.CfnResourceDefinition.LocalVolumeResourceDataProperty(
                                destination_path="destinationPath",
                                source_path="sourcePath",
            
                                # the properties below are optional
                                group_owner_setting=greengrass.CfnResourceDefinition.GroupOwnerSettingProperty(
                                    auto_add_group_owner=False,
            
                                    # the properties below are optional
                                    group_owner="groupOwner"
                                )
                            ),
                            s3_machine_learning_model_resource_data=greengrass.CfnResourceDefinition.S3MachineLearningModelResourceDataProperty(
                                destination_path="destinationPath",
                                s3_uri="s3Uri",
            
                                # the properties below are optional
                                owner_setting=greengrass.CfnResourceDefinition.ResourceDownloadOwnerSettingProperty(
                                    group_owner="groupOwner",
                                    group_permission="groupPermission"
                                )
                            ),
                            sage_maker_machine_learning_model_resource_data=greengrass.CfnResourceDefinition.SageMakerMachineLearningModelResourceDataProperty(
                                destination_path="destinationPath",
                                sage_maker_job_arn="sageMakerJobArn",
            
                                # the properties below are optional
                                owner_setting=greengrass.CfnResourceDefinition.ResourceDownloadOwnerSettingProperty(
                                    group_owner="groupOwner",
                                    group_permission="groupPermission"
                                )
                            ),
                            secrets_manager_secret_resource_data=greengrass.CfnResourceDefinition.SecretsManagerSecretResourceDataProperty(
                                arn="arn",
            
                                # the properties below are optional
                                additional_staging_labels_to_download=["additionalStagingLabelsToDownload"]
                            )
                        )
                    )]
                ),
                tags=tags
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if initial_version is not None:
            self._values["initial_version"] = initial_version
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the resource definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinition.html#cfn-greengrass-resourcedefinition-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union[CfnResourceDefinition.ResourceDefinitionVersionProperty, _IResolvable_da3f097b]]:
        '''The resource definition version to include when the resource definition is created.

        A resource definition version contains a list of ```resource instance`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinition-resourceinstance.html>`_ property types.
        .. epigraph::

           To associate a resource definition version after the resource definition is created, create an ```AWS::Greengrass::ResourceDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinitionversion.html>`_ resource and specify the ID of this resource definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinition.html#cfn-greengrass-resourcedefinition-initialversion
        '''
        result = self._values.get("initial_version")
        return typing.cast(typing.Optional[typing.Union[CfnResourceDefinition.ResourceDefinitionVersionProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''Application-specific metadata to attach to the resource definition.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinition.html#cfn-greengrass-resourcedefinition-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnResourceDefinitionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnResourceDefinitionVersion(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinitionVersion",
):
    '''A CloudFormation ``AWS::Greengrass::ResourceDefinitionVersion``.

    The ``AWS::Greengrass::ResourceDefinitionVersion`` resource represents a resource definition version for AWS IoT Greengrass . A resource definition version contains a list of resources. (In AWS CloudFormation , resources are named *resource instances* .)
    .. epigraph::

       To create a resource definition version, you must specify the ID of the resource definition that you want to associate with the version. For information about creating a resource definition, see ```AWS::Greengrass::ResourceDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinition.html>`_ .

       After you create a resource definition version that contains the resources you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::ResourceDefinitionVersion
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinitionversion.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        cfn_resource_definition_version = greengrass.CfnResourceDefinitionVersion(self, "MyCfnResourceDefinitionVersion",
            resource_definition_id="resourceDefinitionId",
            resources=[greengrass.CfnResourceDefinitionVersion.ResourceInstanceProperty(
                id="id",
                name="name",
                resource_data_container=greengrass.CfnResourceDefinitionVersion.ResourceDataContainerProperty(
                    local_device_resource_data=greengrass.CfnResourceDefinitionVersion.LocalDeviceResourceDataProperty(
                        source_path="sourcePath",
        
                        # the properties below are optional
                        group_owner_setting=greengrass.CfnResourceDefinitionVersion.GroupOwnerSettingProperty(
                            auto_add_group_owner=False,
        
                            # the properties below are optional
                            group_owner="groupOwner"
                        )
                    ),
                    local_volume_resource_data=greengrass.CfnResourceDefinitionVersion.LocalVolumeResourceDataProperty(
                        destination_path="destinationPath",
                        source_path="sourcePath",
        
                        # the properties below are optional
                        group_owner_setting=greengrass.CfnResourceDefinitionVersion.GroupOwnerSettingProperty(
                            auto_add_group_owner=False,
        
                            # the properties below are optional
                            group_owner="groupOwner"
                        )
                    ),
                    s3_machine_learning_model_resource_data=greengrass.CfnResourceDefinitionVersion.S3MachineLearningModelResourceDataProperty(
                        destination_path="destinationPath",
                        s3_uri="s3Uri",
        
                        # the properties below are optional
                        owner_setting=greengrass.CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty(
                            group_owner="groupOwner",
                            group_permission="groupPermission"
                        )
                    ),
                    sage_maker_machine_learning_model_resource_data=greengrass.CfnResourceDefinitionVersion.SageMakerMachineLearningModelResourceDataProperty(
                        destination_path="destinationPath",
                        sage_maker_job_arn="sageMakerJobArn",
        
                        # the properties below are optional
                        owner_setting=greengrass.CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty(
                            group_owner="groupOwner",
                            group_permission="groupPermission"
                        )
                    ),
                    secrets_manager_secret_resource_data=greengrass.CfnResourceDefinitionVersion.SecretsManagerSecretResourceDataProperty(
                        arn="arn",
        
                        # the properties below are optional
                        additional_staging_labels_to_download=["additionalStagingLabelsToDownload"]
                    )
                )
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        resource_definition_id: builtins.str,
        resources: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnResourceDefinitionVersion.ResourceInstanceProperty", _IResolvable_da3f097b]]],
    ) -> None:
        '''Create a new ``AWS::Greengrass::ResourceDefinitionVersion``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param resource_definition_id: The ID of the resource definition associated with this version. This value is a GUID.
        :param resources: The resources in this version.
        '''
        props = CfnResourceDefinitionVersionProps(
            resource_definition_id=resource_definition_id, resources=resources
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
    @jsii.member(jsii_name="resourceDefinitionId")
    def resource_definition_id(self) -> builtins.str:
        '''The ID of the resource definition associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinitionversion.html#cfn-greengrass-resourcedefinitionversion-resourcedefinitionid
        '''
        return typing.cast(builtins.str, jsii.get(self, "resourceDefinitionId"))

    @resource_definition_id.setter
    def resource_definition_id(self, value: builtins.str) -> None:
        jsii.set(self, "resourceDefinitionId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resources")
    def resources(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnResourceDefinitionVersion.ResourceInstanceProperty", _IResolvable_da3f097b]]]:
        '''The resources in this version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinitionversion.html#cfn-greengrass-resourcedefinitionversion-resources
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnResourceDefinitionVersion.ResourceInstanceProperty", _IResolvable_da3f097b]]], jsii.get(self, "resources"))

    @resources.setter
    def resources(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnResourceDefinitionVersion.ResourceInstanceProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "resources", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinitionVersion.GroupOwnerSettingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "auto_add_group_owner": "autoAddGroupOwner",
            "group_owner": "groupOwner",
        },
    )
    class GroupOwnerSettingProperty:
        def __init__(
            self,
            *,
            auto_add_group_owner: typing.Union[builtins.bool, _IResolvable_da3f097b],
            group_owner: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Settings that define additional Linux OS group permissions to give to the Lambda function process.

            You can give the permissions of the Linux group that owns the resource or choose another Linux group. These permissions are in addition to the function's ``RunAs`` permissions.

            In an AWS CloudFormation template, ``GroupOwnerSetting`` is a property of the ```LocalDeviceResourceData`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-localdeviceresourcedata.html>`_ and ```LocalVolumeResourceData`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-localvolumeresourcedata.html>`_ property types.

            :param auto_add_group_owner: Indicates whether to give the privileges of the Linux group that owns the resource to the Lambda process. This gives the Lambda process the file access permissions of the Linux group.
            :param group_owner: The name of the Linux group whose privileges you want to add to the Lambda process. This value is ignored if ``AutoAddGroupOwner`` is true.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-groupownersetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                group_owner_setting_property = greengrass.CfnResourceDefinitionVersion.GroupOwnerSettingProperty(
                    auto_add_group_owner=False,
                
                    # the properties below are optional
                    group_owner="groupOwner"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "auto_add_group_owner": auto_add_group_owner,
            }
            if group_owner is not None:
                self._values["group_owner"] = group_owner

        @builtins.property
        def auto_add_group_owner(
            self,
        ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Indicates whether to give the privileges of the Linux group that owns the resource to the Lambda process.

            This gives the Lambda process the file access permissions of the Linux group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-groupownersetting.html#cfn-greengrass-resourcedefinitionversion-groupownersetting-autoaddgroupowner
            '''
            result = self._values.get("auto_add_group_owner")
            assert result is not None, "Required property 'auto_add_group_owner' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def group_owner(self) -> typing.Optional[builtins.str]:
            '''The name of the Linux group whose privileges you want to add to the Lambda process.

            This value is ignored if ``AutoAddGroupOwner`` is true.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-groupownersetting.html#cfn-greengrass-resourcedefinitionversion-groupownersetting-groupowner
            '''
            result = self._values.get("group_owner")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GroupOwnerSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinitionVersion.LocalDeviceResourceDataProperty",
        jsii_struct_bases=[],
        name_mapping={
            "source_path": "sourcePath",
            "group_owner_setting": "groupOwnerSetting",
        },
    )
    class LocalDeviceResourceDataProperty:
        def __init__(
            self,
            *,
            source_path: builtins.str,
            group_owner_setting: typing.Optional[typing.Union["CfnResourceDefinitionVersion.GroupOwnerSettingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Settings for a local device resource, which represents a file under ``/dev`` .

            For more information, see `Access Local Resources with Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-local-resources.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, ``LocalDeviceResourceData`` can be used in the ```ResourceDataContainer`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourcedatacontainer.html>`_ property type.

            :param source_path: The local absolute path of the device resource. The source path for a device resource can refer only to a character device or block device under ``/dev`` .
            :param group_owner_setting: Settings that define additional Linux OS group permissions to give to the Lambda function process.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-localdeviceresourcedata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                local_device_resource_data_property = greengrass.CfnResourceDefinitionVersion.LocalDeviceResourceDataProperty(
                    source_path="sourcePath",
                
                    # the properties below are optional
                    group_owner_setting=greengrass.CfnResourceDefinitionVersion.GroupOwnerSettingProperty(
                        auto_add_group_owner=False,
                
                        # the properties below are optional
                        group_owner="groupOwner"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "source_path": source_path,
            }
            if group_owner_setting is not None:
                self._values["group_owner_setting"] = group_owner_setting

        @builtins.property
        def source_path(self) -> builtins.str:
            '''The local absolute path of the device resource.

            The source path for a device resource can refer only to a character device or block device under ``/dev`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-localdeviceresourcedata.html#cfn-greengrass-resourcedefinitionversion-localdeviceresourcedata-sourcepath
            '''
            result = self._values.get("source_path")
            assert result is not None, "Required property 'source_path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def group_owner_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinitionVersion.GroupOwnerSettingProperty", _IResolvable_da3f097b]]:
            '''Settings that define additional Linux OS group permissions to give to the Lambda function process.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-localdeviceresourcedata.html#cfn-greengrass-resourcedefinitionversion-localdeviceresourcedata-groupownersetting
            '''
            result = self._values.get("group_owner_setting")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinitionVersion.GroupOwnerSettingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LocalDeviceResourceDataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinitionVersion.LocalVolumeResourceDataProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destination_path": "destinationPath",
            "source_path": "sourcePath",
            "group_owner_setting": "groupOwnerSetting",
        },
    )
    class LocalVolumeResourceDataProperty:
        def __init__(
            self,
            *,
            destination_path: builtins.str,
            source_path: builtins.str,
            group_owner_setting: typing.Optional[typing.Union["CfnResourceDefinitionVersion.GroupOwnerSettingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Settings for a local volume resource, which represents a file or directory on the root file system.

            For more information, see `Access Local Resources with Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-local-resources.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, ``LocalVolumeResourceData`` can be used in the ```ResourceDataContainer`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourcedatacontainer.html>`_ property type.

            :param destination_path: The absolute local path of the resource in the Lambda environment.
            :param source_path: The local absolute path of the volume resource on the host. The source path for a volume resource type cannot start with ``/sys`` .
            :param group_owner_setting: Settings that define additional Linux OS group permissions to give to the Lambda function process.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-localvolumeresourcedata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                local_volume_resource_data_property = greengrass.CfnResourceDefinitionVersion.LocalVolumeResourceDataProperty(
                    destination_path="destinationPath",
                    source_path="sourcePath",
                
                    # the properties below are optional
                    group_owner_setting=greengrass.CfnResourceDefinitionVersion.GroupOwnerSettingProperty(
                        auto_add_group_owner=False,
                
                        # the properties below are optional
                        group_owner="groupOwner"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination_path": destination_path,
                "source_path": source_path,
            }
            if group_owner_setting is not None:
                self._values["group_owner_setting"] = group_owner_setting

        @builtins.property
        def destination_path(self) -> builtins.str:
            '''The absolute local path of the resource in the Lambda environment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-localvolumeresourcedata.html#cfn-greengrass-resourcedefinitionversion-localvolumeresourcedata-destinationpath
            '''
            result = self._values.get("destination_path")
            assert result is not None, "Required property 'destination_path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def source_path(self) -> builtins.str:
            '''The local absolute path of the volume resource on the host.

            The source path for a volume resource type cannot start with ``/sys`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-localvolumeresourcedata.html#cfn-greengrass-resourcedefinitionversion-localvolumeresourcedata-sourcepath
            '''
            result = self._values.get("source_path")
            assert result is not None, "Required property 'source_path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def group_owner_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinitionVersion.GroupOwnerSettingProperty", _IResolvable_da3f097b]]:
            '''Settings that define additional Linux OS group permissions to give to the Lambda function process.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-localvolumeresourcedata.html#cfn-greengrass-resourcedefinitionversion-localvolumeresourcedata-groupownersetting
            '''
            result = self._values.get("group_owner_setting")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinitionVersion.GroupOwnerSettingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LocalVolumeResourceDataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinitionVersion.ResourceDataContainerProperty",
        jsii_struct_bases=[],
        name_mapping={
            "local_device_resource_data": "localDeviceResourceData",
            "local_volume_resource_data": "localVolumeResourceData",
            "s3_machine_learning_model_resource_data": "s3MachineLearningModelResourceData",
            "sage_maker_machine_learning_model_resource_data": "sageMakerMachineLearningModelResourceData",
            "secrets_manager_secret_resource_data": "secretsManagerSecretResourceData",
        },
    )
    class ResourceDataContainerProperty:
        def __init__(
            self,
            *,
            local_device_resource_data: typing.Optional[typing.Union["CfnResourceDefinitionVersion.LocalDeviceResourceDataProperty", _IResolvable_da3f097b]] = None,
            local_volume_resource_data: typing.Optional[typing.Union["CfnResourceDefinitionVersion.LocalVolumeResourceDataProperty", _IResolvable_da3f097b]] = None,
            s3_machine_learning_model_resource_data: typing.Optional[typing.Union["CfnResourceDefinitionVersion.S3MachineLearningModelResourceDataProperty", _IResolvable_da3f097b]] = None,
            sage_maker_machine_learning_model_resource_data: typing.Optional[typing.Union["CfnResourceDefinitionVersion.SageMakerMachineLearningModelResourceDataProperty", _IResolvable_da3f097b]] = None,
            secrets_manager_secret_resource_data: typing.Optional[typing.Union["CfnResourceDefinitionVersion.SecretsManagerSecretResourceDataProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A container for resource data, which defines the resource type.

            The container takes only one of the following supported resource data types: ``LocalDeviceResourceData`` , ``LocalVolumeResourceData`` , ``SageMakerMachineLearningModelResourceData`` , ``S3MachineLearningModelResourceData`` , or ``SecretsManagerSecretResourceData`` .
            .. epigraph::

               Only one resource type can be defined for a ``ResourceDataContainer`` instance.

            In an AWS CloudFormation template, ``ResourceDataContainer`` is a property of the ```ResourceInstance`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourceinstance.html>`_ property type.

            :param local_device_resource_data: Settings for a local device resource.
            :param local_volume_resource_data: Settings for a local volume resource.
            :param s3_machine_learning_model_resource_data: Settings for a machine learning resource stored in Amazon S3 .
            :param sage_maker_machine_learning_model_resource_data: Settings for a machine learning resource saved as an SageMaker training job.
            :param secrets_manager_secret_resource_data: Settings for a secret resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourcedatacontainer.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                resource_data_container_property = greengrass.CfnResourceDefinitionVersion.ResourceDataContainerProperty(
                    local_device_resource_data=greengrass.CfnResourceDefinitionVersion.LocalDeviceResourceDataProperty(
                        source_path="sourcePath",
                
                        # the properties below are optional
                        group_owner_setting=greengrass.CfnResourceDefinitionVersion.GroupOwnerSettingProperty(
                            auto_add_group_owner=False,
                
                            # the properties below are optional
                            group_owner="groupOwner"
                        )
                    ),
                    local_volume_resource_data=greengrass.CfnResourceDefinitionVersion.LocalVolumeResourceDataProperty(
                        destination_path="destinationPath",
                        source_path="sourcePath",
                
                        # the properties below are optional
                        group_owner_setting=greengrass.CfnResourceDefinitionVersion.GroupOwnerSettingProperty(
                            auto_add_group_owner=False,
                
                            # the properties below are optional
                            group_owner="groupOwner"
                        )
                    ),
                    s3_machine_learning_model_resource_data=greengrass.CfnResourceDefinitionVersion.S3MachineLearningModelResourceDataProperty(
                        destination_path="destinationPath",
                        s3_uri="s3Uri",
                
                        # the properties below are optional
                        owner_setting=greengrass.CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty(
                            group_owner="groupOwner",
                            group_permission="groupPermission"
                        )
                    ),
                    sage_maker_machine_learning_model_resource_data=greengrass.CfnResourceDefinitionVersion.SageMakerMachineLearningModelResourceDataProperty(
                        destination_path="destinationPath",
                        sage_maker_job_arn="sageMakerJobArn",
                
                        # the properties below are optional
                        owner_setting=greengrass.CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty(
                            group_owner="groupOwner",
                            group_permission="groupPermission"
                        )
                    ),
                    secrets_manager_secret_resource_data=greengrass.CfnResourceDefinitionVersion.SecretsManagerSecretResourceDataProperty(
                        arn="arn",
                
                        # the properties below are optional
                        additional_staging_labels_to_download=["additionalStagingLabelsToDownload"]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if local_device_resource_data is not None:
                self._values["local_device_resource_data"] = local_device_resource_data
            if local_volume_resource_data is not None:
                self._values["local_volume_resource_data"] = local_volume_resource_data
            if s3_machine_learning_model_resource_data is not None:
                self._values["s3_machine_learning_model_resource_data"] = s3_machine_learning_model_resource_data
            if sage_maker_machine_learning_model_resource_data is not None:
                self._values["sage_maker_machine_learning_model_resource_data"] = sage_maker_machine_learning_model_resource_data
            if secrets_manager_secret_resource_data is not None:
                self._values["secrets_manager_secret_resource_data"] = secrets_manager_secret_resource_data

        @builtins.property
        def local_device_resource_data(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinitionVersion.LocalDeviceResourceDataProperty", _IResolvable_da3f097b]]:
            '''Settings for a local device resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourcedatacontainer.html#cfn-greengrass-resourcedefinitionversion-resourcedatacontainer-localdeviceresourcedata
            '''
            result = self._values.get("local_device_resource_data")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinitionVersion.LocalDeviceResourceDataProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def local_volume_resource_data(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinitionVersion.LocalVolumeResourceDataProperty", _IResolvable_da3f097b]]:
            '''Settings for a local volume resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourcedatacontainer.html#cfn-greengrass-resourcedefinitionversion-resourcedatacontainer-localvolumeresourcedata
            '''
            result = self._values.get("local_volume_resource_data")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinitionVersion.LocalVolumeResourceDataProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def s3_machine_learning_model_resource_data(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinitionVersion.S3MachineLearningModelResourceDataProperty", _IResolvable_da3f097b]]:
            '''Settings for a machine learning resource stored in Amazon S3 .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourcedatacontainer.html#cfn-greengrass-resourcedefinitionversion-resourcedatacontainer-s3machinelearningmodelresourcedata
            '''
            result = self._values.get("s3_machine_learning_model_resource_data")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinitionVersion.S3MachineLearningModelResourceDataProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sage_maker_machine_learning_model_resource_data(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinitionVersion.SageMakerMachineLearningModelResourceDataProperty", _IResolvable_da3f097b]]:
            '''Settings for a machine learning resource saved as an SageMaker training job.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourcedatacontainer.html#cfn-greengrass-resourcedefinitionversion-resourcedatacontainer-sagemakermachinelearningmodelresourcedata
            '''
            result = self._values.get("sage_maker_machine_learning_model_resource_data")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinitionVersion.SageMakerMachineLearningModelResourceDataProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def secrets_manager_secret_resource_data(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinitionVersion.SecretsManagerSecretResourceDataProperty", _IResolvable_da3f097b]]:
            '''Settings for a secret resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourcedatacontainer.html#cfn-greengrass-resourcedefinitionversion-resourcedatacontainer-secretsmanagersecretresourcedata
            '''
            result = self._values.get("secrets_manager_secret_resource_data")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinitionVersion.SecretsManagerSecretResourceDataProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourceDataContainerProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "group_owner": "groupOwner",
            "group_permission": "groupPermission",
        },
    )
    class ResourceDownloadOwnerSettingProperty:
        def __init__(
            self,
            *,
            group_owner: builtins.str,
            group_permission: builtins.str,
        ) -> None:
            '''The owner setting for a downloaded machine learning resource.

            For more information, see `Access Machine Learning Resources from Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-ml-resources.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, ``ResourceDownloadOwnerSetting`` is the property type of the ``OwnerSetting`` property for the ```S3MachineLearningModelResourceData`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-s3machinelearningmodelresourcedata.html>`_ and ```SageMakerMachineLearningModelResourceData`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-sagemakermachinelearningmodelresourcedata.html>`_ property types.

            :param group_owner: The group owner of the machine learning resource. This is the group ID (GID) of an existing Linux OS group on the system. The group's permissions are added to the Lambda process.
            :param group_permission: The permissions that the group owner has to the machine learning resource. Valid values are ``rw`` (read-write) or ``ro`` (read-only).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourcedownloadownersetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                resource_download_owner_setting_property = greengrass.CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty(
                    group_owner="groupOwner",
                    group_permission="groupPermission"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "group_owner": group_owner,
                "group_permission": group_permission,
            }

        @builtins.property
        def group_owner(self) -> builtins.str:
            '''The group owner of the machine learning resource.

            This is the group ID (GID) of an existing Linux OS group on the system. The group's permissions are added to the Lambda process.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourcedownloadownersetting.html#cfn-greengrass-resourcedefinitionversion-resourcedownloadownersetting-groupowner
            '''
            result = self._values.get("group_owner")
            assert result is not None, "Required property 'group_owner' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def group_permission(self) -> builtins.str:
            '''The permissions that the group owner has to the machine learning resource.

            Valid values are ``rw`` (read-write) or ``ro`` (read-only).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourcedownloadownersetting.html#cfn-greengrass-resourcedefinitionversion-resourcedownloadownersetting-grouppermission
            '''
            result = self._values.get("group_permission")
            assert result is not None, "Required property 'group_permission' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourceDownloadOwnerSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinitionVersion.ResourceInstanceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "id": "id",
            "name": "name",
            "resource_data_container": "resourceDataContainer",
        },
    )
    class ResourceInstanceProperty:
        def __init__(
            self,
            *,
            id: builtins.str,
            name: builtins.str,
            resource_data_container: typing.Union["CfnResourceDefinitionVersion.ResourceDataContainerProperty", _IResolvable_da3f097b],
        ) -> None:
            '''A local resource, machine learning resource, or secret resource.

            For more information, see `Access Local Resources with Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-local-resources.html>`_ , `Perform Machine Learning Inference <https://docs.aws.amazon.com/greengrass/latest/developerguide/ml-inference.html>`_ , and `Deploy Secrets to the AWS IoT Greengrass Core <https://docs.aws.amazon.com/greengrass/latest/developerguide/secrets.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, the ``Resources`` property of the ```AWS::Greengrass::ResourceDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinitionversion.html>`_ resource contains a list of ``ResourceInstance`` property types.

            :param id: A descriptive or arbitrary ID for the resource. This value must be unique within the resource definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .
            :param name: The descriptive resource name, which is displayed on the AWS IoT Greengrass console. Maximum length 128 characters with pattern [a-zA-Z0-9:_-]+. This must be unique within a Greengrass group.
            :param resource_data_container: A container for resource data. The container takes only one of the following supported resource data types: ``LocalDeviceResourceData`` , ``LocalVolumeResourceData`` , ``SageMakerMachineLearningModelResourceData`` , ``S3MachineLearningModelResourceData`` , or ``SecretsManagerSecretResourceData`` . .. epigraph:: Only one resource type can be defined for a ``ResourceDataContainer`` instance.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourceinstance.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                resource_instance_property = greengrass.CfnResourceDefinitionVersion.ResourceInstanceProperty(
                    id="id",
                    name="name",
                    resource_data_container=greengrass.CfnResourceDefinitionVersion.ResourceDataContainerProperty(
                        local_device_resource_data=greengrass.CfnResourceDefinitionVersion.LocalDeviceResourceDataProperty(
                            source_path="sourcePath",
                
                            # the properties below are optional
                            group_owner_setting=greengrass.CfnResourceDefinitionVersion.GroupOwnerSettingProperty(
                                auto_add_group_owner=False,
                
                                # the properties below are optional
                                group_owner="groupOwner"
                            )
                        ),
                        local_volume_resource_data=greengrass.CfnResourceDefinitionVersion.LocalVolumeResourceDataProperty(
                            destination_path="destinationPath",
                            source_path="sourcePath",
                
                            # the properties below are optional
                            group_owner_setting=greengrass.CfnResourceDefinitionVersion.GroupOwnerSettingProperty(
                                auto_add_group_owner=False,
                
                                # the properties below are optional
                                group_owner="groupOwner"
                            )
                        ),
                        s3_machine_learning_model_resource_data=greengrass.CfnResourceDefinitionVersion.S3MachineLearningModelResourceDataProperty(
                            destination_path="destinationPath",
                            s3_uri="s3Uri",
                
                            # the properties below are optional
                            owner_setting=greengrass.CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty(
                                group_owner="groupOwner",
                                group_permission="groupPermission"
                            )
                        ),
                        sage_maker_machine_learning_model_resource_data=greengrass.CfnResourceDefinitionVersion.SageMakerMachineLearningModelResourceDataProperty(
                            destination_path="destinationPath",
                            sage_maker_job_arn="sageMakerJobArn",
                
                            # the properties below are optional
                            owner_setting=greengrass.CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty(
                                group_owner="groupOwner",
                                group_permission="groupPermission"
                            )
                        ),
                        secrets_manager_secret_resource_data=greengrass.CfnResourceDefinitionVersion.SecretsManagerSecretResourceDataProperty(
                            arn="arn",
                
                            # the properties below are optional
                            additional_staging_labels_to_download=["additionalStagingLabelsToDownload"]
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "id": id,
                "name": name,
                "resource_data_container": resource_data_container,
            }

        @builtins.property
        def id(self) -> builtins.str:
            '''A descriptive or arbitrary ID for the resource.

            This value must be unique within the resource definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourceinstance.html#cfn-greengrass-resourcedefinitionversion-resourceinstance-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The descriptive resource name, which is displayed on the AWS IoT Greengrass console.

            Maximum length 128 characters with pattern [a-zA-Z0-9:_-]+. This must be unique within a Greengrass group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourceinstance.html#cfn-greengrass-resourcedefinitionversion-resourceinstance-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def resource_data_container(
            self,
        ) -> typing.Union["CfnResourceDefinitionVersion.ResourceDataContainerProperty", _IResolvable_da3f097b]:
            '''A container for resource data.

            The container takes only one of the following supported resource data types: ``LocalDeviceResourceData`` , ``LocalVolumeResourceData`` , ``SageMakerMachineLearningModelResourceData`` , ``S3MachineLearningModelResourceData`` , or ``SecretsManagerSecretResourceData`` .
            .. epigraph::

               Only one resource type can be defined for a ``ResourceDataContainer`` instance.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourceinstance.html#cfn-greengrass-resourcedefinitionversion-resourceinstance-resourcedatacontainer
            '''
            result = self._values.get("resource_data_container")
            assert result is not None, "Required property 'resource_data_container' is missing"
            return typing.cast(typing.Union["CfnResourceDefinitionVersion.ResourceDataContainerProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourceInstanceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinitionVersion.S3MachineLearningModelResourceDataProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destination_path": "destinationPath",
            "s3_uri": "s3Uri",
            "owner_setting": "ownerSetting",
        },
    )
    class S3MachineLearningModelResourceDataProperty:
        def __init__(
            self,
            *,
            destination_path: builtins.str,
            s3_uri: builtins.str,
            owner_setting: typing.Optional[typing.Union["CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Settings for an Amazon S3 machine learning resource.

            For more information, see `Perform Machine Learning Inference <https://docs.aws.amazon.com/greengrass/latest/developerguide/ml-inference.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, ``S3MachineLearningModelResourceData`` can be used in the ```ResourceDataContainer`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourcedatacontainer.html>`_ property type.

            :param destination_path: The absolute local path of the resource inside the Lambda environment.
            :param s3_uri: The URI of the source model in an Amazon S3 bucket. The model package must be in ``tar.gz`` or ``.zip`` format.
            :param owner_setting: The owner setting for the downloaded machine learning resource. For more information, see `Access Machine Learning Resources from Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-ml-resources.html>`_ in the *Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-s3machinelearningmodelresourcedata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                s3_machine_learning_model_resource_data_property = greengrass.CfnResourceDefinitionVersion.S3MachineLearningModelResourceDataProperty(
                    destination_path="destinationPath",
                    s3_uri="s3Uri",
                
                    # the properties below are optional
                    owner_setting=greengrass.CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty(
                        group_owner="groupOwner",
                        group_permission="groupPermission"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination_path": destination_path,
                "s3_uri": s3_uri,
            }
            if owner_setting is not None:
                self._values["owner_setting"] = owner_setting

        @builtins.property
        def destination_path(self) -> builtins.str:
            '''The absolute local path of the resource inside the Lambda environment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-s3machinelearningmodelresourcedata.html#cfn-greengrass-resourcedefinitionversion-s3machinelearningmodelresourcedata-destinationpath
            '''
            result = self._values.get("destination_path")
            assert result is not None, "Required property 'destination_path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_uri(self) -> builtins.str:
            '''The URI of the source model in an Amazon S3 bucket.

            The model package must be in ``tar.gz`` or ``.zip`` format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-s3machinelearningmodelresourcedata.html#cfn-greengrass-resourcedefinitionversion-s3machinelearningmodelresourcedata-s3uri
            '''
            result = self._values.get("s3_uri")
            assert result is not None, "Required property 's3_uri' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def owner_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty", _IResolvable_da3f097b]]:
            '''The owner setting for the downloaded machine learning resource.

            For more information, see `Access Machine Learning Resources from Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-ml-resources.html>`_ in the *Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-s3machinelearningmodelresourcedata.html#cfn-greengrass-resourcedefinitionversion-s3machinelearningmodelresourcedata-ownersetting
            '''
            result = self._values.get("owner_setting")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3MachineLearningModelResourceDataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinitionVersion.SageMakerMachineLearningModelResourceDataProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destination_path": "destinationPath",
            "sage_maker_job_arn": "sageMakerJobArn",
            "owner_setting": "ownerSetting",
        },
    )
    class SageMakerMachineLearningModelResourceDataProperty:
        def __init__(
            self,
            *,
            destination_path: builtins.str,
            sage_maker_job_arn: builtins.str,
            owner_setting: typing.Optional[typing.Union["CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Settings for an Secrets Manager machine learning resource.

            For more information, see `Perform Machine Learning Inference <https://docs.aws.amazon.com/greengrass/latest/developerguide/ml-inference.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, ``SageMakerMachineLearningModelResourceData`` can be used in the ```ResourceDataContainer`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourcedatacontainer.html>`_ property type.

            :param destination_path: The absolute local path of the resource inside the Lambda environment.
            :param sage_maker_job_arn: The Amazon Resource Name (ARN) of the Amazon SageMaker training job that represents the source model.
            :param owner_setting: The owner setting for the downloaded machine learning resource. For more information, see `Access Machine Learning Resources from Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-ml-resources.html>`_ in the *Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-sagemakermachinelearningmodelresourcedata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                sage_maker_machine_learning_model_resource_data_property = greengrass.CfnResourceDefinitionVersion.SageMakerMachineLearningModelResourceDataProperty(
                    destination_path="destinationPath",
                    sage_maker_job_arn="sageMakerJobArn",
                
                    # the properties below are optional
                    owner_setting=greengrass.CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty(
                        group_owner="groupOwner",
                        group_permission="groupPermission"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination_path": destination_path,
                "sage_maker_job_arn": sage_maker_job_arn,
            }
            if owner_setting is not None:
                self._values["owner_setting"] = owner_setting

        @builtins.property
        def destination_path(self) -> builtins.str:
            '''The absolute local path of the resource inside the Lambda environment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-sagemakermachinelearningmodelresourcedata.html#cfn-greengrass-resourcedefinitionversion-sagemakermachinelearningmodelresourcedata-destinationpath
            '''
            result = self._values.get("destination_path")
            assert result is not None, "Required property 'destination_path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def sage_maker_job_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the Amazon SageMaker training job that represents the source model.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-sagemakermachinelearningmodelresourcedata.html#cfn-greengrass-resourcedefinitionversion-sagemakermachinelearningmodelresourcedata-sagemakerjobarn
            '''
            result = self._values.get("sage_maker_job_arn")
            assert result is not None, "Required property 'sage_maker_job_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def owner_setting(
            self,
        ) -> typing.Optional[typing.Union["CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty", _IResolvable_da3f097b]]:
            '''The owner setting for the downloaded machine learning resource.

            For more information, see `Access Machine Learning Resources from Lambda Functions <https://docs.aws.amazon.com/greengrass/latest/developerguide/access-ml-resources.html>`_ in the *Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-sagemakermachinelearningmodelresourcedata.html#cfn-greengrass-resourcedefinitionversion-sagemakermachinelearningmodelresourcedata-ownersetting
            '''
            result = self._values.get("owner_setting")
            return typing.cast(typing.Optional[typing.Union["CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SageMakerMachineLearningModelResourceDataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinitionVersion.SecretsManagerSecretResourceDataProperty",
        jsii_struct_bases=[],
        name_mapping={
            "arn": "arn",
            "additional_staging_labels_to_download": "additionalStagingLabelsToDownload",
        },
    )
    class SecretsManagerSecretResourceDataProperty:
        def __init__(
            self,
            *,
            arn: builtins.str,
            additional_staging_labels_to_download: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Settings for a secret resource, which references a secret from AWS Secrets Manager .

            AWS IoT Greengrass stores a local, encrypted copy of the secret on the Greengrass core, where it can be securely accessed by connectors and Lambda functions. For more information, see `Deploy Secrets to the AWS IoT Greengrass Core <https://docs.aws.amazon.com/greengrass/latest/developerguide/secrets.html>`_ in the *Developer Guide* .

            In an AWS CloudFormation template, ``SecretsManagerSecretResourceData`` can be used in the ```ResourceDataContainer`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-resourcedatacontainer.html>`_ property type.

            :param arn: The Amazon Resource Name (ARN) of the Secrets Manager secret to make available on the core. The value of the secret's latest version (represented by the ``AWSCURRENT`` staging label) is included by default.
            :param additional_staging_labels_to_download: The staging labels whose values you want to make available on the core, in addition to ``AWSCURRENT`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-secretsmanagersecretresourcedata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                secrets_manager_secret_resource_data_property = greengrass.CfnResourceDefinitionVersion.SecretsManagerSecretResourceDataProperty(
                    arn="arn",
                
                    # the properties below are optional
                    additional_staging_labels_to_download=["additionalStagingLabelsToDownload"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
            }
            if additional_staging_labels_to_download is not None:
                self._values["additional_staging_labels_to_download"] = additional_staging_labels_to_download

        @builtins.property
        def arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the Secrets Manager secret to make available on the core.

            The value of the secret's latest version (represented by the ``AWSCURRENT`` staging label) is included by default.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-secretsmanagersecretresourcedata.html#cfn-greengrass-resourcedefinitionversion-secretsmanagersecretresourcedata-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def additional_staging_labels_to_download(
            self,
        ) -> typing.Optional[typing.List[builtins.str]]:
            '''The staging labels whose values you want to make available on the core, in addition to ``AWSCURRENT`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-resourcedefinitionversion-secretsmanagersecretresourcedata.html#cfn-greengrass-resourcedefinitionversion-secretsmanagersecretresourcedata-additionalstaginglabelstodownload
            '''
            result = self._values.get("additional_staging_labels_to_download")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SecretsManagerSecretResourceDataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnResourceDefinitionVersionProps",
    jsii_struct_bases=[],
    name_mapping={
        "resource_definition_id": "resourceDefinitionId",
        "resources": "resources",
    },
)
class CfnResourceDefinitionVersionProps:
    def __init__(
        self,
        *,
        resource_definition_id: builtins.str,
        resources: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnResourceDefinitionVersion.ResourceInstanceProperty, _IResolvable_da3f097b]]],
    ) -> None:
        '''Properties for defining a ``CfnResourceDefinitionVersion``.

        :param resource_definition_id: The ID of the resource definition associated with this version. This value is a GUID.
        :param resources: The resources in this version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinitionversion.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            cfn_resource_definition_version_props = greengrass.CfnResourceDefinitionVersionProps(
                resource_definition_id="resourceDefinitionId",
                resources=[greengrass.CfnResourceDefinitionVersion.ResourceInstanceProperty(
                    id="id",
                    name="name",
                    resource_data_container=greengrass.CfnResourceDefinitionVersion.ResourceDataContainerProperty(
                        local_device_resource_data=greengrass.CfnResourceDefinitionVersion.LocalDeviceResourceDataProperty(
                            source_path="sourcePath",
            
                            # the properties below are optional
                            group_owner_setting=greengrass.CfnResourceDefinitionVersion.GroupOwnerSettingProperty(
                                auto_add_group_owner=False,
            
                                # the properties below are optional
                                group_owner="groupOwner"
                            )
                        ),
                        local_volume_resource_data=greengrass.CfnResourceDefinitionVersion.LocalVolumeResourceDataProperty(
                            destination_path="destinationPath",
                            source_path="sourcePath",
            
                            # the properties below are optional
                            group_owner_setting=greengrass.CfnResourceDefinitionVersion.GroupOwnerSettingProperty(
                                auto_add_group_owner=False,
            
                                # the properties below are optional
                                group_owner="groupOwner"
                            )
                        ),
                        s3_machine_learning_model_resource_data=greengrass.CfnResourceDefinitionVersion.S3MachineLearningModelResourceDataProperty(
                            destination_path="destinationPath",
                            s3_uri="s3Uri",
            
                            # the properties below are optional
                            owner_setting=greengrass.CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty(
                                group_owner="groupOwner",
                                group_permission="groupPermission"
                            )
                        ),
                        sage_maker_machine_learning_model_resource_data=greengrass.CfnResourceDefinitionVersion.SageMakerMachineLearningModelResourceDataProperty(
                            destination_path="destinationPath",
                            sage_maker_job_arn="sageMakerJobArn",
            
                            # the properties below are optional
                            owner_setting=greengrass.CfnResourceDefinitionVersion.ResourceDownloadOwnerSettingProperty(
                                group_owner="groupOwner",
                                group_permission="groupPermission"
                            )
                        ),
                        secrets_manager_secret_resource_data=greengrass.CfnResourceDefinitionVersion.SecretsManagerSecretResourceDataProperty(
                            arn="arn",
            
                            # the properties below are optional
                            additional_staging_labels_to_download=["additionalStagingLabelsToDownload"]
                        )
                    )
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "resource_definition_id": resource_definition_id,
            "resources": resources,
        }

    @builtins.property
    def resource_definition_id(self) -> builtins.str:
        '''The ID of the resource definition associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinitionversion.html#cfn-greengrass-resourcedefinitionversion-resourcedefinitionid
        '''
        result = self._values.get("resource_definition_id")
        assert result is not None, "Required property 'resource_definition_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def resources(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnResourceDefinitionVersion.ResourceInstanceProperty, _IResolvable_da3f097b]]]:
        '''The resources in this version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-resourcedefinitionversion.html#cfn-greengrass-resourcedefinitionversion-resources
        '''
        result = self._values.get("resources")
        assert result is not None, "Required property 'resources' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnResourceDefinitionVersion.ResourceInstanceProperty, _IResolvable_da3f097b]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnResourceDefinitionVersionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSubscriptionDefinition(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnSubscriptionDefinition",
):
    '''A CloudFormation ``AWS::Greengrass::SubscriptionDefinition``.

    The ``AWS::Greengrass::SubscriptionDefinition`` resource represents a subscription definition for AWS IoT Greengrass . Subscription definitions are used to organize your subscription definition versions.

    Subscription definitions can reference multiple subscription definition versions. All subscription definition versions must be associated with a subscription definition. Each subscription definition version can contain one or more subscriptions.
    .. epigraph::

       When you create a subscription definition, you can optionally include an initial subscription definition version. To associate a subscription definition version later, create an ```AWS::Greengrass::SubscriptionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinitionversion.html>`_ resource and specify the ID of this subscription definition.

       After you create the subscription definition version that contains the subscriptions you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::SubscriptionDefinition
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinition.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        # tags: Any
        
        cfn_subscription_definition = greengrass.CfnSubscriptionDefinition(self, "MyCfnSubscriptionDefinition",
            name="name",
        
            # the properties below are optional
            initial_version=greengrass.CfnSubscriptionDefinition.SubscriptionDefinitionVersionProperty(
                subscriptions=[greengrass.CfnSubscriptionDefinition.SubscriptionProperty(
                    id="id",
                    source="source",
                    subject="subject",
                    target="target"
                )]
            ),
            tags=tags
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union["CfnSubscriptionDefinition.SubscriptionDefinitionVersionProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Greengrass::SubscriptionDefinition``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the subscription definition.
        :param initial_version: The subscription definition version to include when the subscription definition is created. A subscription definition version contains a list of ```subscription`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinition-subscription.html>`_ property types. .. epigraph:: To associate a subscription definition version after the subscription definition is created, create an ```AWS::Greengrass::SubscriptionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinitionversion.html>`_ resource and specify the ID of this subscription definition.
        :param tags: Application-specific metadata to attach to the subscription definition. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }
        '''
        props = CfnSubscriptionDefinitionProps(
            name=name, initial_version=initial_version, tags=tags
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
        '''The Amazon Resource Name (ARN) of the ``SubscriptionDefinition`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/subscriptions/1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the ``SubscriptionDefinition`` , such as ``1234a5b6-78cd-901e-2fgh-3i45j6k178l9`` .

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLatestVersionArn")
    def attr_latest_version_arn(self) -> builtins.str:
        '''The ARN of the last ``SubscriptionDefinitionVersion`` that was added to the ``SubscriptionDefinition`` , such as ``arn:aws:greengrass:us-east-1:  :/greengrass/definition/subscriptions/1234a5b6-78cd-901e-2fgh-3i45j6k178l9/versions/9876ac30-4bdb-4f9d-95af-b5fdb66be1a2`` .

        :cloudformationAttribute: LatestVersionArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLatestVersionArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the ``SubscriptionDefinition`` , such as ``MySubscriptionDefinition`` .

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
        '''Application-specific metadata to attach to the subscription definition.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinition.html#cfn-greengrass-subscriptiondefinition-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the subscription definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinition.html#cfn-greengrass-subscriptiondefinition-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="initialVersion")
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union["CfnSubscriptionDefinition.SubscriptionDefinitionVersionProperty", _IResolvable_da3f097b]]:
        '''The subscription definition version to include when the subscription definition is created.

        A subscription definition version contains a list of ```subscription`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinition-subscription.html>`_ property types.
        .. epigraph::

           To associate a subscription definition version after the subscription definition is created, create an ```AWS::Greengrass::SubscriptionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinitionversion.html>`_ resource and specify the ID of this subscription definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinition.html#cfn-greengrass-subscriptiondefinition-initialversion
        '''
        return typing.cast(typing.Optional[typing.Union["CfnSubscriptionDefinition.SubscriptionDefinitionVersionProperty", _IResolvable_da3f097b]], jsii.get(self, "initialVersion"))

    @initial_version.setter
    def initial_version(
        self,
        value: typing.Optional[typing.Union["CfnSubscriptionDefinition.SubscriptionDefinitionVersionProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "initialVersion", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnSubscriptionDefinition.SubscriptionDefinitionVersionProperty",
        jsii_struct_bases=[],
        name_mapping={"subscriptions": "subscriptions"},
    )
    class SubscriptionDefinitionVersionProperty:
        def __init__(
            self,
            *,
            subscriptions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnSubscriptionDefinition.SubscriptionProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A subscription definition version contains a list of `subscriptions <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinition-subscription.html>`_ .

            .. epigraph::

               After you create a subscription definition version that contains the subscriptions you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

            In an AWS CloudFormation template, ``SubscriptionDefinitionVersion`` is the property type of the ``InitialVersion`` property in the ```AWS::Greengrass::SubscriptionDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinition.html>`_ resource.

            :param subscriptions: The subscriptions in this version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinition-subscriptiondefinitionversion.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                subscription_definition_version_property = greengrass.CfnSubscriptionDefinition.SubscriptionDefinitionVersionProperty(
                    subscriptions=[greengrass.CfnSubscriptionDefinition.SubscriptionProperty(
                        id="id",
                        source="source",
                        subject="subject",
                        target="target"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "subscriptions": subscriptions,
            }

        @builtins.property
        def subscriptions(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSubscriptionDefinition.SubscriptionProperty", _IResolvable_da3f097b]]]:
            '''The subscriptions in this version.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinition-subscriptiondefinitionversion.html#cfn-greengrass-subscriptiondefinition-subscriptiondefinitionversion-subscriptions
            '''
            result = self._values.get("subscriptions")
            assert result is not None, "Required property 'subscriptions' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSubscriptionDefinition.SubscriptionProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SubscriptionDefinitionVersionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnSubscriptionDefinition.SubscriptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "id": "id",
            "source": "source",
            "subject": "subject",
            "target": "target",
        },
    )
    class SubscriptionProperty:
        def __init__(
            self,
            *,
            id: builtins.str,
            source: builtins.str,
            subject: builtins.str,
            target: builtins.str,
        ) -> None:
            '''Subscriptions define how MQTT messages can be exchanged between devices, functions, and connectors in the group, and with AWS IoT or the local shadow service.

            A subscription defines a message source, message target, and a topic (or subject) that's used to route messages from the source to the target. A subscription defines the message flow in one direction, from the source to the target. For two-way communication, you must set up two subscriptions, one for each direction.

            In an AWS CloudFormation template, the ``Subscriptions`` property of the ```SubscriptionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinition-subscriptiondefinitionversion.html>`_ property type contains a list of ``Subscription`` property types.

            :param id: A descriptive or arbitrary ID for the subscription. This value must be unique within the subscription definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .
            :param source: The originator of the message. The value can be a thing ARN, the ARN of a Lambda function alias (recommended) or version, a connector ARN, ``cloud`` (which represents the AWS IoT cloud), or ``GGShadowService`` .
            :param subject: The MQTT topic used to route the message.
            :param target: The destination of the message. The value can be a thing ARN, the ARN of a Lambda function alias (recommended) or version, a connector ARN, ``cloud`` (which represents the AWS IoT cloud), or ``GGShadowService`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinition-subscription.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                subscription_property = greengrass.CfnSubscriptionDefinition.SubscriptionProperty(
                    id="id",
                    source="source",
                    subject="subject",
                    target="target"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "id": id,
                "source": source,
                "subject": subject,
                "target": target,
            }

        @builtins.property
        def id(self) -> builtins.str:
            '''A descriptive or arbitrary ID for the subscription.

            This value must be unique within the subscription definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinition-subscription.html#cfn-greengrass-subscriptiondefinition-subscription-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def source(self) -> builtins.str:
            '''The originator of the message.

            The value can be a thing ARN, the ARN of a Lambda function alias (recommended) or version, a connector ARN, ``cloud`` (which represents the AWS IoT cloud), or ``GGShadowService`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinition-subscription.html#cfn-greengrass-subscriptiondefinition-subscription-source
            '''
            result = self._values.get("source")
            assert result is not None, "Required property 'source' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def subject(self) -> builtins.str:
            '''The MQTT topic used to route the message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinition-subscription.html#cfn-greengrass-subscriptiondefinition-subscription-subject
            '''
            result = self._values.get("subject")
            assert result is not None, "Required property 'subject' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def target(self) -> builtins.str:
            '''The destination of the message.

            The value can be a thing ARN, the ARN of a Lambda function alias (recommended) or version, a connector ARN, ``cloud`` (which represents the AWS IoT cloud), or ``GGShadowService`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinition-subscription.html#cfn-greengrass-subscriptiondefinition-subscription-target
            '''
            result = self._values.get("target")
            assert result is not None, "Required property 'target' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SubscriptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnSubscriptionDefinitionProps",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "initial_version": "initialVersion", "tags": "tags"},
)
class CfnSubscriptionDefinitionProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        initial_version: typing.Optional[typing.Union[CfnSubscriptionDefinition.SubscriptionDefinitionVersionProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnSubscriptionDefinition``.

        :param name: The name of the subscription definition.
        :param initial_version: The subscription definition version to include when the subscription definition is created. A subscription definition version contains a list of ```subscription`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinition-subscription.html>`_ property types. .. epigraph:: To associate a subscription definition version after the subscription definition is created, create an ```AWS::Greengrass::SubscriptionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinitionversion.html>`_ resource and specify the ID of this subscription definition.
        :param tags: Application-specific metadata to attach to the subscription definition. You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* . This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates:: "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value" }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinition.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            # tags: Any
            
            cfn_subscription_definition_props = greengrass.CfnSubscriptionDefinitionProps(
                name="name",
            
                # the properties below are optional
                initial_version=greengrass.CfnSubscriptionDefinition.SubscriptionDefinitionVersionProperty(
                    subscriptions=[greengrass.CfnSubscriptionDefinition.SubscriptionProperty(
                        id="id",
                        source="source",
                        subject="subject",
                        target="target"
                    )]
                ),
                tags=tags
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if initial_version is not None:
            self._values["initial_version"] = initial_version
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the subscription definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinition.html#cfn-greengrass-subscriptiondefinition-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def initial_version(
        self,
    ) -> typing.Optional[typing.Union[CfnSubscriptionDefinition.SubscriptionDefinitionVersionProperty, _IResolvable_da3f097b]]:
        '''The subscription definition version to include when the subscription definition is created.

        A subscription definition version contains a list of ```subscription`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinition-subscription.html>`_ property types.
        .. epigraph::

           To associate a subscription definition version after the subscription definition is created, create an ```AWS::Greengrass::SubscriptionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinitionversion.html>`_ resource and specify the ID of this subscription definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinition.html#cfn-greengrass-subscriptiondefinition-initialversion
        '''
        result = self._values.get("initial_version")
        return typing.cast(typing.Optional[typing.Union[CfnSubscriptionDefinition.SubscriptionDefinitionVersionProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''Application-specific metadata to attach to the subscription definition.

        You can use tags in IAM policies to control access to AWS IoT Greengrass resources. You can also use tags to categorize your resources. For more information, see `Tagging Your AWS IoT Greengrass Resources <https://docs.aws.amazon.com/greengrass/latest/developerguide/tagging.html>`_ in the *Developer Guide* .

        This ``Json`` property type is processed as a map of key-value pairs. It uses the following format, which is different from most ``Tags`` implementations in AWS CloudFormation templates::

           "Tags": { "KeyName0": "value", "KeyName1": "value", "KeyName2": "value"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinition.html#cfn-greengrass-subscriptiondefinition-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSubscriptionDefinitionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSubscriptionDefinitionVersion(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_greengrass.CfnSubscriptionDefinitionVersion",
):
    '''A CloudFormation ``AWS::Greengrass::SubscriptionDefinitionVersion``.

    The ``AWS::Greengrass::SubscriptionDefinitionVersion`` resource represents a subscription definition version for AWS IoT Greengrass . A subscription definition version contains a list of subscriptions.
    .. epigraph::

       To create a subscription definition version, you must specify the ID of the subscription definition that you want to associate with the version. For information about creating a subscription definition, see ```AWS::Greengrass::SubscriptionDefinition`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinition.html>`_ .

       After you create a subscription definition version that contains the subscriptions you want to deploy, you must add it to your group version. For more information, see ```AWS::Greengrass::Group`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-group.html>`_ .

    :cloudformationResource: AWS::Greengrass::SubscriptionDefinitionVersion
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinitionversion.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_greengrass as greengrass
        
        cfn_subscription_definition_version = greengrass.CfnSubscriptionDefinitionVersion(self, "MyCfnSubscriptionDefinitionVersion",
            subscription_definition_id="subscriptionDefinitionId",
            subscriptions=[greengrass.CfnSubscriptionDefinitionVersion.SubscriptionProperty(
                id="id",
                source="source",
                subject="subject",
                target="target"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        subscription_definition_id: builtins.str,
        subscriptions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnSubscriptionDefinitionVersion.SubscriptionProperty", _IResolvable_da3f097b]]],
    ) -> None:
        '''Create a new ``AWS::Greengrass::SubscriptionDefinitionVersion``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param subscription_definition_id: The ID of the subscription definition associated with this version. This value is a GUID.
        :param subscriptions: The subscriptions in this version.
        '''
        props = CfnSubscriptionDefinitionVersionProps(
            subscription_definition_id=subscription_definition_id,
            subscriptions=subscriptions,
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
    @jsii.member(jsii_name="subscriptionDefinitionId")
    def subscription_definition_id(self) -> builtins.str:
        '''The ID of the subscription definition associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinitionversion.html#cfn-greengrass-subscriptiondefinitionversion-subscriptiondefinitionid
        '''
        return typing.cast(builtins.str, jsii.get(self, "subscriptionDefinitionId"))

    @subscription_definition_id.setter
    def subscription_definition_id(self, value: builtins.str) -> None:
        jsii.set(self, "subscriptionDefinitionId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subscriptions")
    def subscriptions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSubscriptionDefinitionVersion.SubscriptionProperty", _IResolvable_da3f097b]]]:
        '''The subscriptions in this version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinitionversion.html#cfn-greengrass-subscriptiondefinitionversion-subscriptions
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSubscriptionDefinitionVersion.SubscriptionProperty", _IResolvable_da3f097b]]], jsii.get(self, "subscriptions"))

    @subscriptions.setter
    def subscriptions(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSubscriptionDefinitionVersion.SubscriptionProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "subscriptions", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_greengrass.CfnSubscriptionDefinitionVersion.SubscriptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "id": "id",
            "source": "source",
            "subject": "subject",
            "target": "target",
        },
    )
    class SubscriptionProperty:
        def __init__(
            self,
            *,
            id: builtins.str,
            source: builtins.str,
            subject: builtins.str,
            target: builtins.str,
        ) -> None:
            '''Subscriptions define how MQTT messages can be exchanged between devices, functions, and connectors in the group, and with AWS IoT or the local shadow service.

            A subscription defines a message source, message target, and a topic (or subject) that's used to route messages from the source to the target. A subscription defines the message flow in one direction, from the source to the target. For two-way communication, you must set up two subscriptions, one for each direction.

            In an AWS CloudFormation template, the ``Subscriptions`` property of the ```AWS::Greengrass::SubscriptionDefinitionVersion`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinitionversion.html>`_ resource contains a list of ``Subscription`` property types.

            :param id: A descriptive or arbitrary ID for the subscription. This value must be unique within the subscription definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .
            :param source: The originator of the message. The value can be a thing ARN, the ARN of a Lambda function alias (recommended) or version, a connector ARN, ``cloud`` (which represents the AWS IoT cloud), or ``GGShadowService`` .
            :param subject: The MQTT topic used to route the message.
            :param target: The destination of the message. The value can be a thing ARN, the ARN of a Lambda function alias (recommended) or version, a connector ARN, ``cloud`` (which represents the AWS IoT cloud), or ``GGShadowService`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinitionversion-subscription.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_greengrass as greengrass
                
                subscription_property = greengrass.CfnSubscriptionDefinitionVersion.SubscriptionProperty(
                    id="id",
                    source="source",
                    subject="subject",
                    target="target"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "id": id,
                "source": source,
                "subject": subject,
                "target": target,
            }

        @builtins.property
        def id(self) -> builtins.str:
            '''A descriptive or arbitrary ID for the subscription.

            This value must be unique within the subscription definition version. Maximum length is 128 characters with pattern ``[a-zA-Z0-9:_-]+`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinitionversion-subscription.html#cfn-greengrass-subscriptiondefinitionversion-subscription-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def source(self) -> builtins.str:
            '''The originator of the message.

            The value can be a thing ARN, the ARN of a Lambda function alias (recommended) or version, a connector ARN, ``cloud`` (which represents the AWS IoT cloud), or ``GGShadowService`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinitionversion-subscription.html#cfn-greengrass-subscriptiondefinitionversion-subscription-source
            '''
            result = self._values.get("source")
            assert result is not None, "Required property 'source' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def subject(self) -> builtins.str:
            '''The MQTT topic used to route the message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinitionversion-subscription.html#cfn-greengrass-subscriptiondefinitionversion-subscription-subject
            '''
            result = self._values.get("subject")
            assert result is not None, "Required property 'subject' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def target(self) -> builtins.str:
            '''The destination of the message.

            The value can be a thing ARN, the ARN of a Lambda function alias (recommended) or version, a connector ARN, ``cloud`` (which represents the AWS IoT cloud), or ``GGShadowService`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-greengrass-subscriptiondefinitionversion-subscription.html#cfn-greengrass-subscriptiondefinitionversion-subscription-target
            '''
            result = self._values.get("target")
            assert result is not None, "Required property 'target' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SubscriptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_greengrass.CfnSubscriptionDefinitionVersionProps",
    jsii_struct_bases=[],
    name_mapping={
        "subscription_definition_id": "subscriptionDefinitionId",
        "subscriptions": "subscriptions",
    },
)
class CfnSubscriptionDefinitionVersionProps:
    def __init__(
        self,
        *,
        subscription_definition_id: builtins.str,
        subscriptions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnSubscriptionDefinitionVersion.SubscriptionProperty, _IResolvable_da3f097b]]],
    ) -> None:
        '''Properties for defining a ``CfnSubscriptionDefinitionVersion``.

        :param subscription_definition_id: The ID of the subscription definition associated with this version. This value is a GUID.
        :param subscriptions: The subscriptions in this version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinitionversion.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_greengrass as greengrass
            
            cfn_subscription_definition_version_props = greengrass.CfnSubscriptionDefinitionVersionProps(
                subscription_definition_id="subscriptionDefinitionId",
                subscriptions=[greengrass.CfnSubscriptionDefinitionVersion.SubscriptionProperty(
                    id="id",
                    source="source",
                    subject="subject",
                    target="target"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "subscription_definition_id": subscription_definition_id,
            "subscriptions": subscriptions,
        }

    @builtins.property
    def subscription_definition_id(self) -> builtins.str:
        '''The ID of the subscription definition associated with this version.

        This value is a GUID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinitionversion.html#cfn-greengrass-subscriptiondefinitionversion-subscriptiondefinitionid
        '''
        result = self._values.get("subscription_definition_id")
        assert result is not None, "Required property 'subscription_definition_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def subscriptions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnSubscriptionDefinitionVersion.SubscriptionProperty, _IResolvable_da3f097b]]]:
        '''The subscriptions in this version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-greengrass-subscriptiondefinitionversion.html#cfn-greengrass-subscriptiondefinitionversion-subscriptions
        '''
        result = self._values.get("subscriptions")
        assert result is not None, "Required property 'subscriptions' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnSubscriptionDefinitionVersion.SubscriptionProperty, _IResolvable_da3f097b]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSubscriptionDefinitionVersionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnConnectorDefinition",
    "CfnConnectorDefinitionProps",
    "CfnConnectorDefinitionVersion",
    "CfnConnectorDefinitionVersionProps",
    "CfnCoreDefinition",
    "CfnCoreDefinitionProps",
    "CfnCoreDefinitionVersion",
    "CfnCoreDefinitionVersionProps",
    "CfnDeviceDefinition",
    "CfnDeviceDefinitionProps",
    "CfnDeviceDefinitionVersion",
    "CfnDeviceDefinitionVersionProps",
    "CfnFunctionDefinition",
    "CfnFunctionDefinitionProps",
    "CfnFunctionDefinitionVersion",
    "CfnFunctionDefinitionVersionProps",
    "CfnGroup",
    "CfnGroupProps",
    "CfnGroupVersion",
    "CfnGroupVersionProps",
    "CfnLoggerDefinition",
    "CfnLoggerDefinitionProps",
    "CfnLoggerDefinitionVersion",
    "CfnLoggerDefinitionVersionProps",
    "CfnResourceDefinition",
    "CfnResourceDefinitionProps",
    "CfnResourceDefinitionVersion",
    "CfnResourceDefinitionVersionProps",
    "CfnSubscriptionDefinition",
    "CfnSubscriptionDefinitionProps",
    "CfnSubscriptionDefinitionVersion",
    "CfnSubscriptionDefinitionVersionProps",
]

publication.publish()
