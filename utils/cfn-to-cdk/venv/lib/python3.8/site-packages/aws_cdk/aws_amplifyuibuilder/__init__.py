'''
# AWS::AmplifyUIBuilder Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_amplifyuibuilder as amplifyuibuilder
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-amplifyuibuilder-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::AmplifyUIBuilder](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_AmplifyUIBuilder.html).

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
    jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponent",
):
    '''A CloudFormation ``AWS::AmplifyUIBuilder::Component``.

    The AWS::AmplifyUIBuilder::Component resource specifies a component within an Amplify app. A component is a user interface (UI) element that you can customize. Use ``ComponentChild`` to configure an instance of a ``Component`` . A ``ComponentChild`` instance inherits the configuration of the main ``Component`` .

    :cloudformationResource: AWS::AmplifyUIBuilder::Component
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
        
        # bindings: Any
        # component_child_property_: amplifyuibuilder.CfnComponent.ComponentChildProperty
        # component_property_property_: amplifyuibuilder.CfnComponent.ComponentPropertyProperty
        # events: Any
        # fields: Any
        # overrides: Any
        # predicate_property_: amplifyuibuilder.CfnComponent.PredicateProperty
        # properties: Any
        # variant_values: Any
        
        cfn_component = amplifyuibuilder.CfnComponent(self, "MyCfnComponent",
            binding_properties={
                "binding_properties_key": amplifyuibuilder.CfnComponent.ComponentBindingPropertiesValueProperty(
                    binding_properties=amplifyuibuilder.CfnComponent.ComponentBindingPropertiesValuePropertiesProperty(
                        bucket="bucket",
                        default_value="defaultValue",
                        field="field",
                        key="key",
                        model="model",
                        predicates=[amplifyuibuilder.CfnComponent.PredicateProperty(
                            and=[predicate_property_],
                            field="field",
                            operand="operand",
                            operator="operator",
                            or=[predicate_property_]
                        )],
                        user_attribute="userAttribute"
                    ),
                    default_value="defaultValue",
                    type="type"
                )
            },
            component_type="componentType",
            name="name",
            overrides={
                "overrides_key": overrides
            },
            properties={
                "properties_key": amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                    binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                        property="property",
        
                        # the properties below are optional
                        field="field"
                    ),
                    bindings=bindings,
                    collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                        property="property",
        
                        # the properties below are optional
                        field="field"
                    ),
                    component_name="componentName",
                    concat=[component_property_property_],
                    condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                        else=component_property_property_,
                        field="field",
                        operand="operand",
                        operand_type="operandType",
                        operator="operator",
                        property="property",
                        then=component_property_property_
                    ),
                    configured=False,
                    default_value="defaultValue",
                    event="event",
                    imported_value="importedValue",
                    model="model",
                    property="property",
                    type="type",
                    user_attribute="userAttribute",
                    value="value"
                )
            },
            variants=[amplifyuibuilder.CfnComponent.ComponentVariantProperty(
                overrides=overrides,
                variant_values=variant_values
            )],
        
            # the properties below are optional
            children=[amplifyuibuilder.CfnComponent.ComponentChildProperty(
                component_type="componentType",
                name="name",
                properties=properties,
        
                # the properties below are optional
                children=[component_child_property_],
                events=events
            )],
            collection_properties={
                "collection_properties_key": amplifyuibuilder.CfnComponent.ComponentDataConfigurationProperty(
                    model="model",
        
                    # the properties below are optional
                    identifiers=["identifiers"],
                    predicate=amplifyuibuilder.CfnComponent.PredicateProperty(
                        and=[predicate_property_],
                        field="field",
                        operand="operand",
                        operator="operator",
                        or=[predicate_property_]
                    ),
                    sort=[amplifyuibuilder.CfnComponent.SortPropertyProperty(
                        direction="direction",
                        field="field"
                    )]
                )
            },
            events={
                "events_key": amplifyuibuilder.CfnComponent.ComponentEventProperty(
                    action="action",
                    parameters=amplifyuibuilder.CfnComponent.ActionParametersProperty(
                        anchor=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
        
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
        
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                else=component_property_property_,
                                field="field",
                                operand="operand",
                                operand_type="operandType",
                                operator="operator",
                                property="property",
                                then=component_property_property_
                            ),
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        ),
                        fields=fields,
                        global=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
        
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
        
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                else=component_property_property_,
                                field="field",
                                operand="operand",
                                operand_type="operandType",
                                operator="operator",
                                property="property",
                                then=component_property_property_
                            ),
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        ),
                        id=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
        
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
        
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                else=component_property_property_,
                                field="field",
                                operand="operand",
                                operand_type="operandType",
                                operator="operator",
                                property="property",
                                then=component_property_property_
                            ),
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        ),
                        model="model",
                        state=amplifyuibuilder.CfnComponent.MutationActionSetStateParameterProperty(
                            component_name="componentName",
                            property="property",
                            set=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                                binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
        
                                    # the properties below are optional
                                    field="field"
                                ),
                                bindings=bindings,
                                collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
        
                                    # the properties below are optional
                                    field="field"
                                ),
                                component_name="componentName",
                                concat=[component_property_property_],
                                condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                    else=component_property_property_,
                                    field="field",
                                    operand="operand",
                                    operand_type="operandType",
                                    operator="operator",
                                    property="property",
                                    then=component_property_property_
                                ),
                                configured=False,
                                default_value="defaultValue",
                                event="event",
                                imported_value="importedValue",
                                model="model",
                                property="property",
                                type="type",
                                user_attribute="userAttribute",
                                value="value"
                            )
                        ),
                        target=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
        
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
        
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                else=component_property_property_,
                                field="field",
                                operand="operand",
                                operand_type="operandType",
                                operator="operator",
                                property="property",
                                then=component_property_property_
                            ),
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        ),
                        type=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
        
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
        
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                else=component_property_property_,
                                field="field",
                                operand="operand",
                                operand_type="operandType",
                                operator="operator",
                                property="property",
                                then=component_property_property_
                            ),
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        ),
                        url=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
        
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
        
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                else=component_property_property_,
                                field="field",
                                operand="operand",
                                operand_type="operandType",
                                operator="operator",
                                property="property",
                                then=component_property_property_
                            ),
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        )
                    )
                )
            },
            source_id="sourceId",
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
        binding_properties: typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentBindingPropertiesValueProperty", _IResolvable_da3f097b]]],
        component_type: builtins.str,
        name: builtins.str,
        overrides: typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Any]],
        properties: typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]],
        variants: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnComponent.ComponentVariantProperty", _IResolvable_da3f097b]]],
        children: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnComponent.ComponentChildProperty", _IResolvable_da3f097b]]]] = None,
        collection_properties: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentDataConfigurationProperty", _IResolvable_da3f097b]]]] = None,
        events: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentEventProperty", _IResolvable_da3f097b]]]] = None,
        source_id: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::AmplifyUIBuilder::Component``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param binding_properties: The information to connect a component's properties to data at runtime. You can't specify ``tags`` as a valid property for ``bindingProperties`` .
        :param component_type: The type of the component. This can be an Amplify custom UI component or another custom component.
        :param name: The name of the component.
        :param overrides: Describes the component's properties that can be overriden in a customized instance of the component. You can't specify ``tags`` as a valid property for ``overrides`` .
        :param properties: Describes the component's properties. You can't specify ``tags`` as a valid property for ``properties`` .
        :param variants: A list of the component's variants. A variant is a unique style configuration of a main component.
        :param children: A list of the component's ``ComponentChild`` instances.
        :param collection_properties: The data binding configuration for the component's properties. Use this for a collection component. You can't specify ``tags`` as a valid property for ``collectionProperties`` .
        :param events: ``AWS::AmplifyUIBuilder::Component.Events``.
        :param source_id: The unique ID of the component in its original source system, such as Figma.
        :param tags: One or more key-value pairs to use when tagging the component.
        '''
        props = CfnComponentProps(
            binding_properties=binding_properties,
            component_type=component_type,
            name=name,
            overrides=overrides,
            properties=properties,
            variants=variants,
            children=children,
            collection_properties=collection_properties,
            events=events,
            source_id=source_id,
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
    @jsii.member(jsii_name="attrAppId")
    def attr_app_id(self) -> builtins.str:
        '''The unique ID for the Amplify app.

        :cloudformationAttribute: AppId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAppId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrEnvironmentName")
    def attr_environment_name(self) -> builtins.str:
        '''The name of the backend environment that is a part of the Amplify app.

        :cloudformationAttribute: EnvironmentName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrEnvironmentName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The unique ID of the component.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''One or more key-value pairs to use when tagging the component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bindingProperties")
    def binding_properties(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentBindingPropertiesValueProperty", _IResolvable_da3f097b]]]:
        '''The information to connect a component's properties to data at runtime.

        You can't specify ``tags`` as a valid property for ``bindingProperties`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-bindingproperties
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentBindingPropertiesValueProperty", _IResolvable_da3f097b]]], jsii.get(self, "bindingProperties"))

    @binding_properties.setter
    def binding_properties(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentBindingPropertiesValueProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "bindingProperties", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="componentType")
    def component_type(self) -> builtins.str:
        '''The type of the component.

        This can be an Amplify custom UI component or another custom component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-componenttype
        '''
        return typing.cast(builtins.str, jsii.get(self, "componentType"))

    @component_type.setter
    def component_type(self, value: builtins.str) -> None:
        jsii.set(self, "componentType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="overrides")
    def overrides(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Any]]:
        '''Describes the component's properties that can be overriden in a customized instance of the component.

        You can't specify ``tags`` as a valid property for ``overrides`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-overrides
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Any]], jsii.get(self, "overrides"))

    @overrides.setter
    def overrides(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Any]],
    ) -> None:
        jsii.set(self, "overrides", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="properties")
    def properties(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]]:
        '''Describes the component's properties.

        You can't specify ``tags`` as a valid property for ``properties`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-properties
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]], jsii.get(self, "properties"))

    @properties.setter
    def properties(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "properties", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="variants")
    def variants(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.ComponentVariantProperty", _IResolvable_da3f097b]]]:
        '''A list of the component's variants.

        A variant is a unique style configuration of a main component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-variants
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.ComponentVariantProperty", _IResolvable_da3f097b]]], jsii.get(self, "variants"))

    @variants.setter
    def variants(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.ComponentVariantProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "variants", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="children")
    def children(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.ComponentChildProperty", _IResolvable_da3f097b]]]]:
        '''A list of the component's ``ComponentChild`` instances.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-children
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.ComponentChildProperty", _IResolvable_da3f097b]]]], jsii.get(self, "children"))

    @children.setter
    def children(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.ComponentChildProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "children", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="collectionProperties")
    def collection_properties(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentDataConfigurationProperty", _IResolvable_da3f097b]]]]:
        '''The data binding configuration for the component's properties.

        Use this for a collection component. You can't specify ``tags`` as a valid property for ``collectionProperties`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-collectionproperties
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentDataConfigurationProperty", _IResolvable_da3f097b]]]], jsii.get(self, "collectionProperties"))

    @collection_properties.setter
    def collection_properties(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentDataConfigurationProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "collectionProperties", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="events")
    def events(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentEventProperty", _IResolvable_da3f097b]]]]:
        '''``AWS::AmplifyUIBuilder::Component.Events``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-events
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentEventProperty", _IResolvable_da3f097b]]]], jsii.get(self, "events"))

    @events.setter
    def events(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnComponent.ComponentEventProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "events", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceId")
    def source_id(self) -> typing.Optional[builtins.str]:
        '''The unique ID of the component in its original source system, such as Figma.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-sourceid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "sourceId"))

    @source_id.setter
    def source_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "sourceId", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponent.ActionParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "anchor": "anchor",
            "fields": "fields",
            "global_": "global",
            "id": "id",
            "model": "model",
            "state": "state",
            "target": "target",
            "type": "type",
            "url": "url",
        },
    )
    class ActionParametersProperty:
        def __init__(
            self,
            *,
            anchor: typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]] = None,
            fields: typing.Any = None,
            global_: typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]] = None,
            id: typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]] = None,
            model: typing.Optional[builtins.str] = None,
            state: typing.Optional[typing.Union["CfnComponent.MutationActionSetStateParameterProperty", _IResolvable_da3f097b]] = None,
            target: typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]] = None,
            type: typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]] = None,
            url: typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''
            :param anchor: ``CfnComponent.ActionParametersProperty.Anchor``.
            :param fields: ``CfnComponent.ActionParametersProperty.Fields``.
            :param global_: ``CfnComponent.ActionParametersProperty.Global``.
            :param id: ``CfnComponent.ActionParametersProperty.Id``.
            :param model: ``CfnComponent.ActionParametersProperty.Model``.
            :param state: ``CfnComponent.ActionParametersProperty.State``.
            :param target: ``CfnComponent.ActionParametersProperty.Target``.
            :param type: ``CfnComponent.ActionParametersProperty.Type``.
            :param url: ``CfnComponent.ActionParametersProperty.Url``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-actionparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                # bindings: Any
                # component_property_property_: amplifyuibuilder.CfnComponent.ComponentPropertyProperty
                # fields: Any
                
                action_parameters_property = amplifyuibuilder.CfnComponent.ActionParametersProperty(
                    anchor=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                        binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        bindings=bindings,
                        collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        component_name="componentName",
                        concat=[component_property_property_],
                        condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                            else=component_property_property_,
                            field="field",
                            operand="operand",
                            operand_type="operandType",
                            operator="operator",
                            property="property",
                            then=component_property_property_
                        ),
                        configured=False,
                        default_value="defaultValue",
                        event="event",
                        imported_value="importedValue",
                        model="model",
                        property="property",
                        type="type",
                        user_attribute="userAttribute",
                        value="value"
                    ),
                    fields=fields,
                    global=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                        binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        bindings=bindings,
                        collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        component_name="componentName",
                        concat=[component_property_property_],
                        condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                            else=component_property_property_,
                            field="field",
                            operand="operand",
                            operand_type="operandType",
                            operator="operator",
                            property="property",
                            then=component_property_property_
                        ),
                        configured=False,
                        default_value="defaultValue",
                        event="event",
                        imported_value="importedValue",
                        model="model",
                        property="property",
                        type="type",
                        user_attribute="userAttribute",
                        value="value"
                    ),
                    id=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                        binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        bindings=bindings,
                        collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        component_name="componentName",
                        concat=[component_property_property_],
                        condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                            else=component_property_property_,
                            field="field",
                            operand="operand",
                            operand_type="operandType",
                            operator="operator",
                            property="property",
                            then=component_property_property_
                        ),
                        configured=False,
                        default_value="defaultValue",
                        event="event",
                        imported_value="importedValue",
                        model="model",
                        property="property",
                        type="type",
                        user_attribute="userAttribute",
                        value="value"
                    ),
                    model="model",
                    state=amplifyuibuilder.CfnComponent.MutationActionSetStateParameterProperty(
                        component_name="componentName",
                        property="property",
                        set=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                else=component_property_property_,
                                field="field",
                                operand="operand",
                                operand_type="operandType",
                                operator="operator",
                                property="property",
                                then=component_property_property_
                            ),
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        )
                    ),
                    target=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                        binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        bindings=bindings,
                        collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        component_name="componentName",
                        concat=[component_property_property_],
                        condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                            else=component_property_property_,
                            field="field",
                            operand="operand",
                            operand_type="operandType",
                            operator="operator",
                            property="property",
                            then=component_property_property_
                        ),
                        configured=False,
                        default_value="defaultValue",
                        event="event",
                        imported_value="importedValue",
                        model="model",
                        property="property",
                        type="type",
                        user_attribute="userAttribute",
                        value="value"
                    ),
                    type=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                        binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        bindings=bindings,
                        collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        component_name="componentName",
                        concat=[component_property_property_],
                        condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                            else=component_property_property_,
                            field="field",
                            operand="operand",
                            operand_type="operandType",
                            operator="operator",
                            property="property",
                            then=component_property_property_
                        ),
                        configured=False,
                        default_value="defaultValue",
                        event="event",
                        imported_value="importedValue",
                        model="model",
                        property="property",
                        type="type",
                        user_attribute="userAttribute",
                        value="value"
                    ),
                    url=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                        binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        bindings=bindings,
                        collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        component_name="componentName",
                        concat=[component_property_property_],
                        condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                            else=component_property_property_,
                            field="field",
                            operand="operand",
                            operand_type="operandType",
                            operator="operator",
                            property="property",
                            then=component_property_property_
                        ),
                        configured=False,
                        default_value="defaultValue",
                        event="event",
                        imported_value="importedValue",
                        model="model",
                        property="property",
                        type="type",
                        user_attribute="userAttribute",
                        value="value"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if anchor is not None:
                self._values["anchor"] = anchor
            if fields is not None:
                self._values["fields"] = fields
            if global_ is not None:
                self._values["global_"] = global_
            if id is not None:
                self._values["id"] = id
            if model is not None:
                self._values["model"] = model
            if state is not None:
                self._values["state"] = state
            if target is not None:
                self._values["target"] = target
            if type is not None:
                self._values["type"] = type
            if url is not None:
                self._values["url"] = url

        @builtins.property
        def anchor(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]:
            '''``CfnComponent.ActionParametersProperty.Anchor``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-actionparameters.html#cfn-amplifyuibuilder-component-actionparameters-anchor
            '''
            result = self._values.get("anchor")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def fields(self) -> typing.Any:
            '''``CfnComponent.ActionParametersProperty.Fields``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-actionparameters.html#cfn-amplifyuibuilder-component-actionparameters-fields
            '''
            result = self._values.get("fields")
            return typing.cast(typing.Any, result)

        @builtins.property
        def global_(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]:
            '''``CfnComponent.ActionParametersProperty.Global``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-actionparameters.html#cfn-amplifyuibuilder-component-actionparameters-global
            '''
            result = self._values.get("global_")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def id(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]:
            '''``CfnComponent.ActionParametersProperty.Id``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-actionparameters.html#cfn-amplifyuibuilder-component-actionparameters-id
            '''
            result = self._values.get("id")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def model(self) -> typing.Optional[builtins.str]:
            '''``CfnComponent.ActionParametersProperty.Model``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-actionparameters.html#cfn-amplifyuibuilder-component-actionparameters-model
            '''
            result = self._values.get("model")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def state(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.MutationActionSetStateParameterProperty", _IResolvable_da3f097b]]:
            '''``CfnComponent.ActionParametersProperty.State``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-actionparameters.html#cfn-amplifyuibuilder-component-actionparameters-state
            '''
            result = self._values.get("state")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.MutationActionSetStateParameterProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def target(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]:
            '''``CfnComponent.ActionParametersProperty.Target``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-actionparameters.html#cfn-amplifyuibuilder-component-actionparameters-target
            '''
            result = self._values.get("target")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def type(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]:
            '''``CfnComponent.ActionParametersProperty.Type``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-actionparameters.html#cfn-amplifyuibuilder-component-actionparameters-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def url(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]:
            '''``CfnComponent.ActionParametersProperty.Url``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-actionparameters.html#cfn-amplifyuibuilder-component-actionparameters-url
            '''
            result = self._values.get("url")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ActionParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponent.ComponentBindingPropertiesValuePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket": "bucket",
            "default_value": "defaultValue",
            "field": "field",
            "key": "key",
            "model": "model",
            "predicates": "predicates",
            "user_attribute": "userAttribute",
        },
    )
    class ComponentBindingPropertiesValuePropertiesProperty:
        def __init__(
            self,
            *,
            bucket: typing.Optional[builtins.str] = None,
            default_value: typing.Optional[builtins.str] = None,
            field: typing.Optional[builtins.str] = None,
            key: typing.Optional[builtins.str] = None,
            model: typing.Optional[builtins.str] = None,
            predicates: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnComponent.PredicateProperty", _IResolvable_da3f097b]]]] = None,
            user_attribute: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The ``ComponentBindingPropertiesValueProperties`` property specifies the data binding configuration for a specific property using data stored in AWS .

            For AWS connected properties, you can bind a property to data stored in an Amazon S3 bucket, an Amplify DataStore model or an authenticated user attribute.

            :param bucket: An Amazon S3 bucket.
            :param default_value: The default value to assign to the property.
            :param field: The field to bind the data to.
            :param key: The storage key for an Amazon S3 bucket.
            :param model: An Amplify DataStore model.
            :param predicates: A list of predicates for binding a component's properties to data.
            :param user_attribute: An authenticated user attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentbindingpropertiesvalueproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                # predicate_property_: amplifyuibuilder.CfnComponent.PredicateProperty
                
                component_binding_properties_value_properties_property = amplifyuibuilder.CfnComponent.ComponentBindingPropertiesValuePropertiesProperty(
                    bucket="bucket",
                    default_value="defaultValue",
                    field="field",
                    key="key",
                    model="model",
                    predicates=[amplifyuibuilder.CfnComponent.PredicateProperty(
                        and=[predicate_property_],
                        field="field",
                        operand="operand",
                        operator="operator",
                        or=[predicate_property_]
                    )],
                    user_attribute="userAttribute"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if bucket is not None:
                self._values["bucket"] = bucket
            if default_value is not None:
                self._values["default_value"] = default_value
            if field is not None:
                self._values["field"] = field
            if key is not None:
                self._values["key"] = key
            if model is not None:
                self._values["model"] = model
            if predicates is not None:
                self._values["predicates"] = predicates
            if user_attribute is not None:
                self._values["user_attribute"] = user_attribute

        @builtins.property
        def bucket(self) -> typing.Optional[builtins.str]:
            '''An Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentbindingpropertiesvalueproperties.html#cfn-amplifyuibuilder-component-componentbindingpropertiesvalueproperties-bucket
            '''
            result = self._values.get("bucket")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def default_value(self) -> typing.Optional[builtins.str]:
            '''The default value to assign to the property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentbindingpropertiesvalueproperties.html#cfn-amplifyuibuilder-component-componentbindingpropertiesvalueproperties-defaultvalue
            '''
            result = self._values.get("default_value")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def field(self) -> typing.Optional[builtins.str]:
            '''The field to bind the data to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentbindingpropertiesvalueproperties.html#cfn-amplifyuibuilder-component-componentbindingpropertiesvalueproperties-field
            '''
            result = self._values.get("field")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def key(self) -> typing.Optional[builtins.str]:
            '''The storage key for an Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentbindingpropertiesvalueproperties.html#cfn-amplifyuibuilder-component-componentbindingpropertiesvalueproperties-key
            '''
            result = self._values.get("key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def model(self) -> typing.Optional[builtins.str]:
            '''An Amplify DataStore model.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentbindingpropertiesvalueproperties.html#cfn-amplifyuibuilder-component-componentbindingpropertiesvalueproperties-model
            '''
            result = self._values.get("model")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def predicates(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.PredicateProperty", _IResolvable_da3f097b]]]]:
            '''A list of predicates for binding a component's properties to data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentbindingpropertiesvalueproperties.html#cfn-amplifyuibuilder-component-componentbindingpropertiesvalueproperties-predicates
            '''
            result = self._values.get("predicates")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.PredicateProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def user_attribute(self) -> typing.Optional[builtins.str]:
            '''An authenticated user attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentbindingpropertiesvalueproperties.html#cfn-amplifyuibuilder-component-componentbindingpropertiesvalueproperties-userattribute
            '''
            result = self._values.get("user_attribute")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComponentBindingPropertiesValuePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponent.ComponentBindingPropertiesValueProperty",
        jsii_struct_bases=[],
        name_mapping={
            "binding_properties": "bindingProperties",
            "default_value": "defaultValue",
            "type": "type",
        },
    )
    class ComponentBindingPropertiesValueProperty:
        def __init__(
            self,
            *,
            binding_properties: typing.Optional[typing.Union["CfnComponent.ComponentBindingPropertiesValuePropertiesProperty", _IResolvable_da3f097b]] = None,
            default_value: typing.Optional[builtins.str] = None,
            type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The ``ComponentBindingPropertiesValue`` property specifies the data binding configuration for a component at runtime.

            You can use ``ComponentBindingPropertiesValue`` to add exposed properties to a component to allow different values to be entered when a component is reused in different places in an app.

            :param binding_properties: Describes the properties to customize with data at runtime.
            :param default_value: The default value of the property.
            :param type: The property type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentbindingpropertiesvalue.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                # predicate_property_: amplifyuibuilder.CfnComponent.PredicateProperty
                
                component_binding_properties_value_property = amplifyuibuilder.CfnComponent.ComponentBindingPropertiesValueProperty(
                    binding_properties=amplifyuibuilder.CfnComponent.ComponentBindingPropertiesValuePropertiesProperty(
                        bucket="bucket",
                        default_value="defaultValue",
                        field="field",
                        key="key",
                        model="model",
                        predicates=[amplifyuibuilder.CfnComponent.PredicateProperty(
                            and=[predicate_property_],
                            field="field",
                            operand="operand",
                            operator="operator",
                            or=[predicate_property_]
                        )],
                        user_attribute="userAttribute"
                    ),
                    default_value="defaultValue",
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if binding_properties is not None:
                self._values["binding_properties"] = binding_properties
            if default_value is not None:
                self._values["default_value"] = default_value
            if type is not None:
                self._values["type"] = type

        @builtins.property
        def binding_properties(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.ComponentBindingPropertiesValuePropertiesProperty", _IResolvable_da3f097b]]:
            '''Describes the properties to customize with data at runtime.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentbindingpropertiesvalue.html#cfn-amplifyuibuilder-component-componentbindingpropertiesvalue-bindingproperties
            '''
            result = self._values.get("binding_properties")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.ComponentBindingPropertiesValuePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def default_value(self) -> typing.Optional[builtins.str]:
            '''The default value of the property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentbindingpropertiesvalue.html#cfn-amplifyuibuilder-component-componentbindingpropertiesvalue-defaultvalue
            '''
            result = self._values.get("default_value")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''The property type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentbindingpropertiesvalue.html#cfn-amplifyuibuilder-component-componentbindingpropertiesvalue-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComponentBindingPropertiesValueProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponent.ComponentChildProperty",
        jsii_struct_bases=[],
        name_mapping={
            "component_type": "componentType",
            "name": "name",
            "properties": "properties",
            "children": "children",
            "events": "events",
        },
    )
    class ComponentChildProperty:
        def __init__(
            self,
            *,
            component_type: builtins.str,
            name: builtins.str,
            properties: typing.Any,
            children: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnComponent.ComponentChildProperty", _IResolvable_da3f097b]]]] = None,
            events: typing.Any = None,
        ) -> None:
            '''The ``ComponentChild`` property specifies a nested UI configuration within a parent ``Component`` .

            :param component_type: The type of the child component.
            :param name: The name of the child component.
            :param properties: Describes the properties of the child component. You can't specify ``tags`` as a valid property for ``properties`` .
            :param children: The list of ``ComponentChild`` instances for this component.
            :param events: ``CfnComponent.ComponentChildProperty.Events``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentchild.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                # component_child_property_: amplifyuibuilder.CfnComponent.ComponentChildProperty
                # events: Any
                # properties: Any
                
                component_child_property = amplifyuibuilder.CfnComponent.ComponentChildProperty(
                    component_type="componentType",
                    name="name",
                    properties=properties,
                
                    # the properties below are optional
                    children=[amplifyuibuilder.CfnComponent.ComponentChildProperty(
                        component_type="componentType",
                        name="name",
                        properties=properties,
                
                        # the properties below are optional
                        children=[component_child_property_],
                        events=events
                    )],
                    events=events
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "component_type": component_type,
                "name": name,
                "properties": properties,
            }
            if children is not None:
                self._values["children"] = children
            if events is not None:
                self._values["events"] = events

        @builtins.property
        def component_type(self) -> builtins.str:
            '''The type of the child component.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentchild.html#cfn-amplifyuibuilder-component-componentchild-componenttype
            '''
            result = self._values.get("component_type")
            assert result is not None, "Required property 'component_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the child component.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentchild.html#cfn-amplifyuibuilder-component-componentchild-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def properties(self) -> typing.Any:
            '''Describes the properties of the child component.

            You can't specify ``tags`` as a valid property for ``properties`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentchild.html#cfn-amplifyuibuilder-component-componentchild-properties
            '''
            result = self._values.get("properties")
            assert result is not None, "Required property 'properties' is missing"
            return typing.cast(typing.Any, result)

        @builtins.property
        def children(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.ComponentChildProperty", _IResolvable_da3f097b]]]]:
            '''The list of ``ComponentChild`` instances for this component.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentchild.html#cfn-amplifyuibuilder-component-componentchild-children
            '''
            result = self._values.get("children")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.ComponentChildProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def events(self) -> typing.Any:
            '''``CfnComponent.ComponentChildProperty.Events``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentchild.html#cfn-amplifyuibuilder-component-componentchild-events
            '''
            result = self._values.get("events")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComponentChildProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "else_": "else",
            "field": "field",
            "operand": "operand",
            "operand_type": "operandType",
            "operator": "operator",
            "property": "property",
            "then": "then",
        },
    )
    class ComponentConditionPropertyProperty:
        def __init__(
            self,
            *,
            else_: typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]] = None,
            field: typing.Optional[builtins.str] = None,
            operand: typing.Optional[builtins.str] = None,
            operand_type: typing.Optional[builtins.str] = None,
            operator: typing.Optional[builtins.str] = None,
            property: typing.Optional[builtins.str] = None,
            then: typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The ``ComponentConditionProperty`` property specifies a conditional expression for setting a component property.

            Use ``ComponentConditionProperty`` to set a property to different values conditionally, based on the value of another property.

            :param else_: The value to assign to the property if the condition is not met.
            :param field: The name of a field. Specify this when the property is a data model.
            :param operand: The value of the property to evaluate.
            :param operand_type: ``CfnComponent.ComponentConditionPropertyProperty.OperandType``.
            :param operator: The operator to use to perform the evaluation, such as ``eq`` to represent equals.
            :param property: The name of the conditional property.
            :param then: The value to assign to the property if the condition is met.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentconditionproperty.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                # bindings: Any
                # component_property_property_: amplifyuibuilder.CfnComponent.ComponentPropertyProperty
                
                component_condition_property_property = amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                    else=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                        binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        bindings=bindings,
                        collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        component_name="componentName",
                        concat=[component_property_property_],
                        condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                            else=component_property_property_,
                            field="field",
                            operand="operand",
                            operand_type="operandType",
                            operator="operator",
                            property="property",
                            then=component_property_property_
                        ),
                        configured=False,
                        default_value="defaultValue",
                        event="event",
                        imported_value="importedValue",
                        model="model",
                        property="property",
                        type="type",
                        user_attribute="userAttribute",
                        value="value"
                    ),
                    field="field",
                    operand="operand",
                    operand_type="operandType",
                    operator="operator",
                    property="property",
                    then=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                        binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        bindings=bindings,
                        collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        component_name="componentName",
                        concat=[component_property_property_],
                        condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                            else=component_property_property_,
                            field="field",
                            operand="operand",
                            operand_type="operandType",
                            operator="operator",
                            property="property",
                            then=component_property_property_
                        ),
                        configured=False,
                        default_value="defaultValue",
                        event="event",
                        imported_value="importedValue",
                        model="model",
                        property="property",
                        type="type",
                        user_attribute="userAttribute",
                        value="value"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if else_ is not None:
                self._values["else_"] = else_
            if field is not None:
                self._values["field"] = field
            if operand is not None:
                self._values["operand"] = operand
            if operand_type is not None:
                self._values["operand_type"] = operand_type
            if operator is not None:
                self._values["operator"] = operator
            if property is not None:
                self._values["property"] = property
            if then is not None:
                self._values["then"] = then

        @builtins.property
        def else_(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]:
            '''The value to assign to the property if the condition is not met.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentconditionproperty.html#cfn-amplifyuibuilder-component-componentconditionproperty-else
            '''
            result = self._values.get("else_")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def field(self) -> typing.Optional[builtins.str]:
            '''The name of a field.

            Specify this when the property is a data model.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentconditionproperty.html#cfn-amplifyuibuilder-component-componentconditionproperty-field
            '''
            result = self._values.get("field")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def operand(self) -> typing.Optional[builtins.str]:
            '''The value of the property to evaluate.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentconditionproperty.html#cfn-amplifyuibuilder-component-componentconditionproperty-operand
            '''
            result = self._values.get("operand")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def operand_type(self) -> typing.Optional[builtins.str]:
            '''``CfnComponent.ComponentConditionPropertyProperty.OperandType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentconditionproperty.html#cfn-amplifyuibuilder-component-componentconditionproperty-operandtype
            '''
            result = self._values.get("operand_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def operator(self) -> typing.Optional[builtins.str]:
            '''The operator to use to perform the evaluation, such as ``eq`` to represent equals.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentconditionproperty.html#cfn-amplifyuibuilder-component-componentconditionproperty-operator
            '''
            result = self._values.get("operator")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def property(self) -> typing.Optional[builtins.str]:
            '''The name of the conditional property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentconditionproperty.html#cfn-amplifyuibuilder-component-componentconditionproperty-property
            '''
            result = self._values.get("property")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def then(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]:
            '''The value to assign to the property if the condition is met.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentconditionproperty.html#cfn-amplifyuibuilder-component-componentconditionproperty-then
            '''
            result = self._values.get("then")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComponentConditionPropertyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponent.ComponentDataConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "model": "model",
            "identifiers": "identifiers",
            "predicate": "predicate",
            "sort": "sort",
        },
    )
    class ComponentDataConfigurationProperty:
        def __init__(
            self,
            *,
            model: builtins.str,
            identifiers: typing.Optional[typing.Sequence[builtins.str]] = None,
            predicate: typing.Optional[typing.Union["CfnComponent.PredicateProperty", _IResolvable_da3f097b]] = None,
            sort: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnComponent.SortPropertyProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''The ``ComponentDataConfiguration`` property specifies the configuration for binding a component's properties to data.

            :param model: The name of the data model to use to bind data to a component.
            :param identifiers: A list of IDs to use to bind data to a component. Use this property to bind specifically chosen data, rather than data retrieved from a query.
            :param predicate: Represents the conditional logic to use when binding data to a component. Use this property to retrieve only a subset of the data in a collection.
            :param sort: Describes how to sort the component's properties.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentdataconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                # predicate_property_: amplifyuibuilder.CfnComponent.PredicateProperty
                
                component_data_configuration_property = amplifyuibuilder.CfnComponent.ComponentDataConfigurationProperty(
                    model="model",
                
                    # the properties below are optional
                    identifiers=["identifiers"],
                    predicate=amplifyuibuilder.CfnComponent.PredicateProperty(
                        and=[predicate_property_],
                        field="field",
                        operand="operand",
                        operator="operator",
                        or=[predicate_property_]
                    ),
                    sort=[amplifyuibuilder.CfnComponent.SortPropertyProperty(
                        direction="direction",
                        field="field"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "model": model,
            }
            if identifiers is not None:
                self._values["identifiers"] = identifiers
            if predicate is not None:
                self._values["predicate"] = predicate
            if sort is not None:
                self._values["sort"] = sort

        @builtins.property
        def model(self) -> builtins.str:
            '''The name of the data model to use to bind data to a component.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentdataconfiguration.html#cfn-amplifyuibuilder-component-componentdataconfiguration-model
            '''
            result = self._values.get("model")
            assert result is not None, "Required property 'model' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def identifiers(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of IDs to use to bind data to a component.

            Use this property to bind specifically chosen data, rather than data retrieved from a query.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentdataconfiguration.html#cfn-amplifyuibuilder-component-componentdataconfiguration-identifiers
            '''
            result = self._values.get("identifiers")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def predicate(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.PredicateProperty", _IResolvable_da3f097b]]:
            '''Represents the conditional logic to use when binding data to a component.

            Use this property to retrieve only a subset of the data in a collection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentdataconfiguration.html#cfn-amplifyuibuilder-component-componentdataconfiguration-predicate
            '''
            result = self._values.get("predicate")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.PredicateProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sort(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.SortPropertyProperty", _IResolvable_da3f097b]]]]:
            '''Describes how to sort the component's properties.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentdataconfiguration.html#cfn-amplifyuibuilder-component-componentdataconfiguration-sort
            '''
            result = self._values.get("sort")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.SortPropertyProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComponentDataConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponent.ComponentEventProperty",
        jsii_struct_bases=[],
        name_mapping={"action": "action", "parameters": "parameters"},
    )
    class ComponentEventProperty:
        def __init__(
            self,
            *,
            action: typing.Optional[builtins.str] = None,
            parameters: typing.Optional[typing.Union["CfnComponent.ActionParametersProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''
            :param action: ``CfnComponent.ComponentEventProperty.Action``.
            :param parameters: ``CfnComponent.ComponentEventProperty.Parameters``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentevent.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                # bindings: Any
                # component_property_property_: amplifyuibuilder.CfnComponent.ComponentPropertyProperty
                # fields: Any
                
                component_event_property = amplifyuibuilder.CfnComponent.ComponentEventProperty(
                    action="action",
                    parameters=amplifyuibuilder.CfnComponent.ActionParametersProperty(
                        anchor=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                else=component_property_property_,
                                field="field",
                                operand="operand",
                                operand_type="operandType",
                                operator="operator",
                                property="property",
                                then=component_property_property_
                            ),
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        ),
                        fields=fields,
                        global=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                else=component_property_property_,
                                field="field",
                                operand="operand",
                                operand_type="operandType",
                                operator="operator",
                                property="property",
                                then=component_property_property_
                            ),
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        ),
                        id=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                else=component_property_property_,
                                field="field",
                                operand="operand",
                                operand_type="operandType",
                                operator="operator",
                                property="property",
                                then=component_property_property_
                            ),
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        ),
                        model="model",
                        state=amplifyuibuilder.CfnComponent.MutationActionSetStateParameterProperty(
                            component_name="componentName",
                            property="property",
                            set=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                                binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
                
                                    # the properties below are optional
                                    field="field"
                                ),
                                bindings=bindings,
                                collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
                
                                    # the properties below are optional
                                    field="field"
                                ),
                                component_name="componentName",
                                concat=[component_property_property_],
                                condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                    else=component_property_property_,
                                    field="field",
                                    operand="operand",
                                    operand_type="operandType",
                                    operator="operator",
                                    property="property",
                                    then=component_property_property_
                                ),
                                configured=False,
                                default_value="defaultValue",
                                event="event",
                                imported_value="importedValue",
                                model="model",
                                property="property",
                                type="type",
                                user_attribute="userAttribute",
                                value="value"
                            )
                        ),
                        target=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                else=component_property_property_,
                                field="field",
                                operand="operand",
                                operand_type="operandType",
                                operator="operator",
                                property="property",
                                then=component_property_property_
                            ),
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        ),
                        type=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                else=component_property_property_,
                                field="field",
                                operand="operand",
                                operand_type="operandType",
                                operator="operator",
                                property="property",
                                then=component_property_property_
                            ),
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        ),
                        url=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                else=component_property_property_,
                                field="field",
                                operand="operand",
                                operand_type="operandType",
                                operator="operator",
                                property="property",
                                then=component_property_property_
                            ),
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if action is not None:
                self._values["action"] = action
            if parameters is not None:
                self._values["parameters"] = parameters

        @builtins.property
        def action(self) -> typing.Optional[builtins.str]:
            '''``CfnComponent.ComponentEventProperty.Action``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentevent.html#cfn-amplifyuibuilder-component-componentevent-action
            '''
            result = self._values.get("action")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.ActionParametersProperty", _IResolvable_da3f097b]]:
            '''``CfnComponent.ComponentEventProperty.Parameters``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentevent.html#cfn-amplifyuibuilder-component-componentevent-parameters
            '''
            result = self._values.get("parameters")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.ActionParametersProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComponentEventProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"property": "property", "field": "field"},
    )
    class ComponentPropertyBindingPropertiesProperty:
        def __init__(
            self,
            *,
            property: builtins.str,
            field: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The ``ComponentPropertyBindingProperties`` property specifies a component property to associate with a binding property.

            This enables exposed properties on the top level component to propagate data to the component's property values.

            :param property: The component property to bind to the data field.
            :param field: The data field to bind the property to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentpropertybindingproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                component_property_binding_properties_property = amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                    property="property",
                
                    # the properties below are optional
                    field="field"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "property": property,
            }
            if field is not None:
                self._values["field"] = field

        @builtins.property
        def property(self) -> builtins.str:
            '''The component property to bind to the data field.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentpropertybindingproperties.html#cfn-amplifyuibuilder-component-componentpropertybindingproperties-property
            '''
            result = self._values.get("property")
            assert result is not None, "Required property 'property' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def field(self) -> typing.Optional[builtins.str]:
            '''The data field to bind the property to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentpropertybindingproperties.html#cfn-amplifyuibuilder-component-componentpropertybindingproperties-field
            '''
            result = self._values.get("field")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComponentPropertyBindingPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponent.ComponentPropertyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "binding_properties": "bindingProperties",
            "bindings": "bindings",
            "collection_binding_properties": "collectionBindingProperties",
            "component_name": "componentName",
            "concat": "concat",
            "condition": "condition",
            "configured": "configured",
            "default_value": "defaultValue",
            "event": "event",
            "imported_value": "importedValue",
            "model": "model",
            "property": "property",
            "type": "type",
            "user_attribute": "userAttribute",
            "value": "value",
        },
    )
    class ComponentPropertyProperty:
        def __init__(
            self,
            *,
            binding_properties: typing.Optional[typing.Union["CfnComponent.ComponentPropertyBindingPropertiesProperty", _IResolvable_da3f097b]] = None,
            bindings: typing.Any = None,
            collection_binding_properties: typing.Optional[typing.Union["CfnComponent.ComponentPropertyBindingPropertiesProperty", _IResolvable_da3f097b]] = None,
            component_name: typing.Optional[builtins.str] = None,
            concat: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]]] = None,
            condition: typing.Optional[typing.Union["CfnComponent.ComponentConditionPropertyProperty", _IResolvable_da3f097b]] = None,
            configured: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            default_value: typing.Optional[builtins.str] = None,
            event: typing.Optional[builtins.str] = None,
            imported_value: typing.Optional[builtins.str] = None,
            model: typing.Optional[builtins.str] = None,
            property: typing.Optional[builtins.str] = None,
            type: typing.Optional[builtins.str] = None,
            user_attribute: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The ``ComponentProperty`` property specifies the configuration for all of a component's properties.

            Use ``ComponentProperty`` to specify the values to render or bind by default.

            :param binding_properties: The information to bind the component property to data at runtime.
            :param bindings: The information to bind the component property to form data.
            :param collection_binding_properties: The information to bind the component property to data at runtime. Use this for collection components.
            :param component_name: ``CfnComponent.ComponentPropertyProperty.ComponentName``.
            :param concat: A list of component properties to concatenate to create the value to assign to this component property.
            :param condition: The conditional expression to use to assign a value to the component property.
            :param configured: Specifies whether the user configured the property in Amplify Studio after importing it.
            :param default_value: The default value to assign to the component property.
            :param event: An event that occurs in your app. Use this for workflow data binding.
            :param imported_value: The default value assigned to the property when the component is imported into an app.
            :param model: The data model to use to assign a value to the component property.
            :param property: ``CfnComponent.ComponentPropertyProperty.Property``.
            :param type: The component type.
            :param user_attribute: An authenticated user attribute to use to assign a value to the component property.
            :param value: The value to assign to the component property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                # bindings: Any
                # component_condition_property_property_: amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty
                # component_property_property_: amplifyuibuilder.CfnComponent.ComponentPropertyProperty
                
                component_property_property = amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                    binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                        property="property",
                
                        # the properties below are optional
                        field="field"
                    ),
                    bindings=bindings,
                    collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                        property="property",
                
                        # the properties below are optional
                        field="field"
                    ),
                    component_name="componentName",
                    concat=[amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                        binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        bindings=bindings,
                        collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        component_name="componentName",
                        concat=[component_property_property_],
                        condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                            else=component_property_property_,
                            field="field",
                            operand="operand",
                            operand_type="operandType",
                            operator="operator",
                            property="property",
                            then=component_property_property_
                        ),
                        configured=False,
                        default_value="defaultValue",
                        event="event",
                        imported_value="importedValue",
                        model="model",
                        property="property",
                        type="type",
                        user_attribute="userAttribute",
                        value="value"
                    )],
                    condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                        else=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=component_condition_property_property_,
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        ),
                        field="field",
                        operand="operand",
                        operand_type="operandType",
                        operator="operator",
                        property="property",
                        then=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                            binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            bindings=bindings,
                            collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                property="property",
                
                                # the properties below are optional
                                field="field"
                            ),
                            component_name="componentName",
                            concat=[component_property_property_],
                            condition=component_condition_property_property_,
                            configured=False,
                            default_value="defaultValue",
                            event="event",
                            imported_value="importedValue",
                            model="model",
                            property="property",
                            type="type",
                            user_attribute="userAttribute",
                            value="value"
                        )
                    ),
                    configured=False,
                    default_value="defaultValue",
                    event="event",
                    imported_value="importedValue",
                    model="model",
                    property="property",
                    type="type",
                    user_attribute="userAttribute",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if binding_properties is not None:
                self._values["binding_properties"] = binding_properties
            if bindings is not None:
                self._values["bindings"] = bindings
            if collection_binding_properties is not None:
                self._values["collection_binding_properties"] = collection_binding_properties
            if component_name is not None:
                self._values["component_name"] = component_name
            if concat is not None:
                self._values["concat"] = concat
            if condition is not None:
                self._values["condition"] = condition
            if configured is not None:
                self._values["configured"] = configured
            if default_value is not None:
                self._values["default_value"] = default_value
            if event is not None:
                self._values["event"] = event
            if imported_value is not None:
                self._values["imported_value"] = imported_value
            if model is not None:
                self._values["model"] = model
            if property is not None:
                self._values["property"] = property
            if type is not None:
                self._values["type"] = type
            if user_attribute is not None:
                self._values["user_attribute"] = user_attribute
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def binding_properties(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.ComponentPropertyBindingPropertiesProperty", _IResolvable_da3f097b]]:
            '''The information to bind the component property to data at runtime.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-bindingproperties
            '''
            result = self._values.get("binding_properties")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.ComponentPropertyBindingPropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def bindings(self) -> typing.Any:
            '''The information to bind the component property to form data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-bindings
            '''
            result = self._values.get("bindings")
            return typing.cast(typing.Any, result)

        @builtins.property
        def collection_binding_properties(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.ComponentPropertyBindingPropertiesProperty", _IResolvable_da3f097b]]:
            '''The information to bind the component property to data at runtime.

            Use this for collection components.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-collectionbindingproperties
            '''
            result = self._values.get("collection_binding_properties")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.ComponentPropertyBindingPropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def component_name(self) -> typing.Optional[builtins.str]:
            '''``CfnComponent.ComponentPropertyProperty.ComponentName``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-componentname
            '''
            result = self._values.get("component_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def concat(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]]]:
            '''A list of component properties to concatenate to create the value to assign to this component property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-concat
            '''
            result = self._values.get("concat")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def condition(
            self,
        ) -> typing.Optional[typing.Union["CfnComponent.ComponentConditionPropertyProperty", _IResolvable_da3f097b]]:
            '''The conditional expression to use to assign a value to the component property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-condition
            '''
            result = self._values.get("condition")
            return typing.cast(typing.Optional[typing.Union["CfnComponent.ComponentConditionPropertyProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def configured(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether the user configured the property in Amplify Studio after importing it.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-configured
            '''
            result = self._values.get("configured")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def default_value(self) -> typing.Optional[builtins.str]:
            '''The default value to assign to the component property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-defaultvalue
            '''
            result = self._values.get("default_value")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def event(self) -> typing.Optional[builtins.str]:
            '''An event that occurs in your app.

            Use this for workflow data binding.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-event
            '''
            result = self._values.get("event")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def imported_value(self) -> typing.Optional[builtins.str]:
            '''The default value assigned to the property when the component is imported into an app.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-importedvalue
            '''
            result = self._values.get("imported_value")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def model(self) -> typing.Optional[builtins.str]:
            '''The data model to use to assign a value to the component property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-model
            '''
            result = self._values.get("model")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def property(self) -> typing.Optional[builtins.str]:
            '''``CfnComponent.ComponentPropertyProperty.Property``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-property
            '''
            result = self._values.get("property")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''The component type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def user_attribute(self) -> typing.Optional[builtins.str]:
            '''An authenticated user attribute to use to assign a value to the component property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-userattribute
            '''
            result = self._values.get("user_attribute")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''The value to assign to the component property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentproperty.html#cfn-amplifyuibuilder-component-componentproperty-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComponentPropertyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponent.ComponentVariantProperty",
        jsii_struct_bases=[],
        name_mapping={"overrides": "overrides", "variant_values": "variantValues"},
    )
    class ComponentVariantProperty:
        def __init__(
            self,
            *,
            overrides: typing.Any = None,
            variant_values: typing.Any = None,
        ) -> None:
            '''The ``ComponentVariant`` property specifies the style configuration of a unique variation of a main component.

            :param overrides: The properties of the component variant that can be overriden when customizing an instance of the component. You can't specify ``tags`` as a valid property for ``overrides`` .
            :param variant_values: The combination of variants that comprise this variant.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentvariant.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                # overrides: Any
                # variant_values: Any
                
                component_variant_property = amplifyuibuilder.CfnComponent.ComponentVariantProperty(
                    overrides=overrides,
                    variant_values=variant_values
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if overrides is not None:
                self._values["overrides"] = overrides
            if variant_values is not None:
                self._values["variant_values"] = variant_values

        @builtins.property
        def overrides(self) -> typing.Any:
            '''The properties of the component variant that can be overriden when customizing an instance of the component.

            You can't specify ``tags`` as a valid property for ``overrides`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentvariant.html#cfn-amplifyuibuilder-component-componentvariant-overrides
            '''
            result = self._values.get("overrides")
            return typing.cast(typing.Any, result)

        @builtins.property
        def variant_values(self) -> typing.Any:
            '''The combination of variants that comprise this variant.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-componentvariant.html#cfn-amplifyuibuilder-component-componentvariant-variantvalues
            '''
            result = self._values.get("variant_values")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComponentVariantProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponent.MutationActionSetStateParameterProperty",
        jsii_struct_bases=[],
        name_mapping={
            "component_name": "componentName",
            "property": "property",
            "set": "set",
        },
    )
    class MutationActionSetStateParameterProperty:
        def __init__(
            self,
            *,
            component_name: builtins.str,
            property: builtins.str,
            set: typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b],
        ) -> None:
            '''
            :param component_name: ``CfnComponent.MutationActionSetStateParameterProperty.ComponentName``.
            :param property: ``CfnComponent.MutationActionSetStateParameterProperty.Property``.
            :param set: ``CfnComponent.MutationActionSetStateParameterProperty.Set``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-mutationactionsetstateparameter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                # bindings: Any
                # component_property_property_: amplifyuibuilder.CfnComponent.ComponentPropertyProperty
                
                mutation_action_set_state_parameter_property = amplifyuibuilder.CfnComponent.MutationActionSetStateParameterProperty(
                    component_name="componentName",
                    property="property",
                    set=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                        binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        bindings=bindings,
                        collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
                
                            # the properties below are optional
                            field="field"
                        ),
                        component_name="componentName",
                        concat=[component_property_property_],
                        condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                            else=component_property_property_,
                            field="field",
                            operand="operand",
                            operand_type="operandType",
                            operator="operator",
                            property="property",
                            then=component_property_property_
                        ),
                        configured=False,
                        default_value="defaultValue",
                        event="event",
                        imported_value="importedValue",
                        model="model",
                        property="property",
                        type="type",
                        user_attribute="userAttribute",
                        value="value"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "component_name": component_name,
                "property": property,
                "set": set,
            }

        @builtins.property
        def component_name(self) -> builtins.str:
            '''``CfnComponent.MutationActionSetStateParameterProperty.ComponentName``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-mutationactionsetstateparameter.html#cfn-amplifyuibuilder-component-mutationactionsetstateparameter-componentname
            '''
            result = self._values.get("component_name")
            assert result is not None, "Required property 'component_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def property(self) -> builtins.str:
            '''``CfnComponent.MutationActionSetStateParameterProperty.Property``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-mutationactionsetstateparameter.html#cfn-amplifyuibuilder-component-mutationactionsetstateparameter-property
            '''
            result = self._values.get("property")
            assert result is not None, "Required property 'property' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def set(
            self,
        ) -> typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b]:
            '''``CfnComponent.MutationActionSetStateParameterProperty.Set``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-mutationactionsetstateparameter.html#cfn-amplifyuibuilder-component-mutationactionsetstateparameter-set
            '''
            result = self._values.get("set")
            assert result is not None, "Required property 'set' is missing"
            return typing.cast(typing.Union["CfnComponent.ComponentPropertyProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MutationActionSetStateParameterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponent.PredicateProperty",
        jsii_struct_bases=[],
        name_mapping={
            "and_": "and",
            "field": "field",
            "operand": "operand",
            "operator": "operator",
            "or_": "or",
        },
    )
    class PredicateProperty:
        def __init__(
            self,
            *,
            and_: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnComponent.PredicateProperty", _IResolvable_da3f097b]]]] = None,
            field: typing.Optional[builtins.str] = None,
            operand: typing.Optional[builtins.str] = None,
            operator: typing.Optional[builtins.str] = None,
            or_: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnComponent.PredicateProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''The ``Predicate`` property specifies information for generating Amplify DataStore queries.

            Use ``Predicate`` to retrieve a subset of the data in a collection.

            :param and_: A list of predicates to combine logically.
            :param field: The field to query.
            :param operand: The value to use when performing the evaluation.
            :param operator: The operator to use to perform the evaluation.
            :param or_: A list of predicates to combine logically.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-predicate.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                # predicate_property_: amplifyuibuilder.CfnComponent.PredicateProperty
                
                predicate_property = amplifyuibuilder.CfnComponent.PredicateProperty(
                    and=[amplifyuibuilder.CfnComponent.PredicateProperty(
                        and=[predicate_property_],
                        field="field",
                        operand="operand",
                        operator="operator",
                        or=[predicate_property_]
                    )],
                    field="field",
                    operand="operand",
                    operator="operator",
                    or=[amplifyuibuilder.CfnComponent.PredicateProperty(
                        and=[predicate_property_],
                        field="field",
                        operand="operand",
                        operator="operator",
                        or=[predicate_property_]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if and_ is not None:
                self._values["and_"] = and_
            if field is not None:
                self._values["field"] = field
            if operand is not None:
                self._values["operand"] = operand
            if operator is not None:
                self._values["operator"] = operator
            if or_ is not None:
                self._values["or_"] = or_

        @builtins.property
        def and_(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.PredicateProperty", _IResolvable_da3f097b]]]]:
            '''A list of predicates to combine logically.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-predicate.html#cfn-amplifyuibuilder-component-predicate-and
            '''
            result = self._values.get("and_")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.PredicateProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def field(self) -> typing.Optional[builtins.str]:
            '''The field to query.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-predicate.html#cfn-amplifyuibuilder-component-predicate-field
            '''
            result = self._values.get("field")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def operand(self) -> typing.Optional[builtins.str]:
            '''The value to use when performing the evaluation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-predicate.html#cfn-amplifyuibuilder-component-predicate-operand
            '''
            result = self._values.get("operand")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def operator(self) -> typing.Optional[builtins.str]:
            '''The operator to use to perform the evaluation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-predicate.html#cfn-amplifyuibuilder-component-predicate-operator
            '''
            result = self._values.get("operator")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def or_(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.PredicateProperty", _IResolvable_da3f097b]]]]:
            '''A list of predicates to combine logically.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-predicate.html#cfn-amplifyuibuilder-component-predicate-or
            '''
            result = self._values.get("or_")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComponent.PredicateProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PredicateProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponent.SortPropertyProperty",
        jsii_struct_bases=[],
        name_mapping={"direction": "direction", "field": "field"},
    )
    class SortPropertyProperty:
        def __init__(self, *, direction: builtins.str, field: builtins.str) -> None:
            '''The ``SortProperty`` property specifies how to sort the data that you bind to a component.

            :param direction: The direction of the sort, either ascending or descending.
            :param field: The field to perform the sort on.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-sortproperty.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                sort_property_property = amplifyuibuilder.CfnComponent.SortPropertyProperty(
                    direction="direction",
                    field="field"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "direction": direction,
                "field": field,
            }

        @builtins.property
        def direction(self) -> builtins.str:
            '''The direction of the sort, either ascending or descending.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-sortproperty.html#cfn-amplifyuibuilder-component-sortproperty-direction
            '''
            result = self._values.get("direction")
            assert result is not None, "Required property 'direction' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def field(self) -> builtins.str:
            '''The field to perform the sort on.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-component-sortproperty.html#cfn-amplifyuibuilder-component-sortproperty-field
            '''
            result = self._values.get("field")
            assert result is not None, "Required property 'field' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SortPropertyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnComponentProps",
    jsii_struct_bases=[],
    name_mapping={
        "binding_properties": "bindingProperties",
        "component_type": "componentType",
        "name": "name",
        "overrides": "overrides",
        "properties": "properties",
        "variants": "variants",
        "children": "children",
        "collection_properties": "collectionProperties",
        "events": "events",
        "source_id": "sourceId",
        "tags": "tags",
    },
)
class CfnComponentProps:
    def __init__(
        self,
        *,
        binding_properties: typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnComponent.ComponentBindingPropertiesValueProperty, _IResolvable_da3f097b]]],
        component_type: builtins.str,
        name: builtins.str,
        overrides: typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Any]],
        properties: typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnComponent.ComponentPropertyProperty, _IResolvable_da3f097b]]],
        variants: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnComponent.ComponentVariantProperty, _IResolvable_da3f097b]]],
        children: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnComponent.ComponentChildProperty, _IResolvable_da3f097b]]]] = None,
        collection_properties: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnComponent.ComponentDataConfigurationProperty, _IResolvable_da3f097b]]]] = None,
        events: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnComponent.ComponentEventProperty, _IResolvable_da3f097b]]]] = None,
        source_id: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnComponent``.

        :param binding_properties: The information to connect a component's properties to data at runtime. You can't specify ``tags`` as a valid property for ``bindingProperties`` .
        :param component_type: The type of the component. This can be an Amplify custom UI component or another custom component.
        :param name: The name of the component.
        :param overrides: Describes the component's properties that can be overriden in a customized instance of the component. You can't specify ``tags`` as a valid property for ``overrides`` .
        :param properties: Describes the component's properties. You can't specify ``tags`` as a valid property for ``properties`` .
        :param variants: A list of the component's variants. A variant is a unique style configuration of a main component.
        :param children: A list of the component's ``ComponentChild`` instances.
        :param collection_properties: The data binding configuration for the component's properties. Use this for a collection component. You can't specify ``tags`` as a valid property for ``collectionProperties`` .
        :param events: ``AWS::AmplifyUIBuilder::Component.Events``.
        :param source_id: The unique ID of the component in its original source system, such as Figma.
        :param tags: One or more key-value pairs to use when tagging the component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
            
            # bindings: Any
            # component_child_property_: amplifyuibuilder.CfnComponent.ComponentChildProperty
            # component_property_property_: amplifyuibuilder.CfnComponent.ComponentPropertyProperty
            # events: Any
            # fields: Any
            # overrides: Any
            # predicate_property_: amplifyuibuilder.CfnComponent.PredicateProperty
            # properties: Any
            # variant_values: Any
            
            cfn_component_props = amplifyuibuilder.CfnComponentProps(
                binding_properties={
                    "binding_properties_key": amplifyuibuilder.CfnComponent.ComponentBindingPropertiesValueProperty(
                        binding_properties=amplifyuibuilder.CfnComponent.ComponentBindingPropertiesValuePropertiesProperty(
                            bucket="bucket",
                            default_value="defaultValue",
                            field="field",
                            key="key",
                            model="model",
                            predicates=[amplifyuibuilder.CfnComponent.PredicateProperty(
                                and=[predicate_property_],
                                field="field",
                                operand="operand",
                                operator="operator",
                                or=[predicate_property_]
                            )],
                            user_attribute="userAttribute"
                        ),
                        default_value="defaultValue",
                        type="type"
                    )
                },
                component_type="componentType",
                name="name",
                overrides={
                    "overrides_key": overrides
                },
                properties={
                    "properties_key": amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                        binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
            
                            # the properties below are optional
                            field="field"
                        ),
                        bindings=bindings,
                        collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                            property="property",
            
                            # the properties below are optional
                            field="field"
                        ),
                        component_name="componentName",
                        concat=[component_property_property_],
                        condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                            else=component_property_property_,
                            field="field",
                            operand="operand",
                            operand_type="operandType",
                            operator="operator",
                            property="property",
                            then=component_property_property_
                        ),
                        configured=False,
                        default_value="defaultValue",
                        event="event",
                        imported_value="importedValue",
                        model="model",
                        property="property",
                        type="type",
                        user_attribute="userAttribute",
                        value="value"
                    )
                },
                variants=[amplifyuibuilder.CfnComponent.ComponentVariantProperty(
                    overrides=overrides,
                    variant_values=variant_values
                )],
            
                # the properties below are optional
                children=[amplifyuibuilder.CfnComponent.ComponentChildProperty(
                    component_type="componentType",
                    name="name",
                    properties=properties,
            
                    # the properties below are optional
                    children=[component_child_property_],
                    events=events
                )],
                collection_properties={
                    "collection_properties_key": amplifyuibuilder.CfnComponent.ComponentDataConfigurationProperty(
                        model="model",
            
                        # the properties below are optional
                        identifiers=["identifiers"],
                        predicate=amplifyuibuilder.CfnComponent.PredicateProperty(
                            and=[predicate_property_],
                            field="field",
                            operand="operand",
                            operator="operator",
                            or=[predicate_property_]
                        ),
                        sort=[amplifyuibuilder.CfnComponent.SortPropertyProperty(
                            direction="direction",
                            field="field"
                        )]
                    )
                },
                events={
                    "events_key": amplifyuibuilder.CfnComponent.ComponentEventProperty(
                        action="action",
                        parameters=amplifyuibuilder.CfnComponent.ActionParametersProperty(
                            anchor=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                                binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
            
                                    # the properties below are optional
                                    field="field"
                                ),
                                bindings=bindings,
                                collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
            
                                    # the properties below are optional
                                    field="field"
                                ),
                                component_name="componentName",
                                concat=[component_property_property_],
                                condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                    else=component_property_property_,
                                    field="field",
                                    operand="operand",
                                    operand_type="operandType",
                                    operator="operator",
                                    property="property",
                                    then=component_property_property_
                                ),
                                configured=False,
                                default_value="defaultValue",
                                event="event",
                                imported_value="importedValue",
                                model="model",
                                property="property",
                                type="type",
                                user_attribute="userAttribute",
                                value="value"
                            ),
                            fields=fields,
                            global=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                                binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
            
                                    # the properties below are optional
                                    field="field"
                                ),
                                bindings=bindings,
                                collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
            
                                    # the properties below are optional
                                    field="field"
                                ),
                                component_name="componentName",
                                concat=[component_property_property_],
                                condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                    else=component_property_property_,
                                    field="field",
                                    operand="operand",
                                    operand_type="operandType",
                                    operator="operator",
                                    property="property",
                                    then=component_property_property_
                                ),
                                configured=False,
                                default_value="defaultValue",
                                event="event",
                                imported_value="importedValue",
                                model="model",
                                property="property",
                                type="type",
                                user_attribute="userAttribute",
                                value="value"
                            ),
                            id=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                                binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
            
                                    # the properties below are optional
                                    field="field"
                                ),
                                bindings=bindings,
                                collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
            
                                    # the properties below are optional
                                    field="field"
                                ),
                                component_name="componentName",
                                concat=[component_property_property_],
                                condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                    else=component_property_property_,
                                    field="field",
                                    operand="operand",
                                    operand_type="operandType",
                                    operator="operator",
                                    property="property",
                                    then=component_property_property_
                                ),
                                configured=False,
                                default_value="defaultValue",
                                event="event",
                                imported_value="importedValue",
                                model="model",
                                property="property",
                                type="type",
                                user_attribute="userAttribute",
                                value="value"
                            ),
                            model="model",
                            state=amplifyuibuilder.CfnComponent.MutationActionSetStateParameterProperty(
                                component_name="componentName",
                                property="property",
                                set=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                                    binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                        property="property",
            
                                        # the properties below are optional
                                        field="field"
                                    ),
                                    bindings=bindings,
                                    collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                        property="property",
            
                                        # the properties below are optional
                                        field="field"
                                    ),
                                    component_name="componentName",
                                    concat=[component_property_property_],
                                    condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                        else=component_property_property_,
                                        field="field",
                                        operand="operand",
                                        operand_type="operandType",
                                        operator="operator",
                                        property="property",
                                        then=component_property_property_
                                    ),
                                    configured=False,
                                    default_value="defaultValue",
                                    event="event",
                                    imported_value="importedValue",
                                    model="model",
                                    property="property",
                                    type="type",
                                    user_attribute="userAttribute",
                                    value="value"
                                )
                            ),
                            target=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                                binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
            
                                    # the properties below are optional
                                    field="field"
                                ),
                                bindings=bindings,
                                collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
            
                                    # the properties below are optional
                                    field="field"
                                ),
                                component_name="componentName",
                                concat=[component_property_property_],
                                condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                    else=component_property_property_,
                                    field="field",
                                    operand="operand",
                                    operand_type="operandType",
                                    operator="operator",
                                    property="property",
                                    then=component_property_property_
                                ),
                                configured=False,
                                default_value="defaultValue",
                                event="event",
                                imported_value="importedValue",
                                model="model",
                                property="property",
                                type="type",
                                user_attribute="userAttribute",
                                value="value"
                            ),
                            type=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                                binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
            
                                    # the properties below are optional
                                    field="field"
                                ),
                                bindings=bindings,
                                collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
            
                                    # the properties below are optional
                                    field="field"
                                ),
                                component_name="componentName",
                                concat=[component_property_property_],
                                condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                    else=component_property_property_,
                                    field="field",
                                    operand="operand",
                                    operand_type="operandType",
                                    operator="operator",
                                    property="property",
                                    then=component_property_property_
                                ),
                                configured=False,
                                default_value="defaultValue",
                                event="event",
                                imported_value="importedValue",
                                model="model",
                                property="property",
                                type="type",
                                user_attribute="userAttribute",
                                value="value"
                            ),
                            url=amplifyuibuilder.CfnComponent.ComponentPropertyProperty(
                                binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
            
                                    # the properties below are optional
                                    field="field"
                                ),
                                bindings=bindings,
                                collection_binding_properties=amplifyuibuilder.CfnComponent.ComponentPropertyBindingPropertiesProperty(
                                    property="property",
            
                                    # the properties below are optional
                                    field="field"
                                ),
                                component_name="componentName",
                                concat=[component_property_property_],
                                condition=amplifyuibuilder.CfnComponent.ComponentConditionPropertyProperty(
                                    else=component_property_property_,
                                    field="field",
                                    operand="operand",
                                    operand_type="operandType",
                                    operator="operator",
                                    property="property",
                                    then=component_property_property_
                                ),
                                configured=False,
                                default_value="defaultValue",
                                event="event",
                                imported_value="importedValue",
                                model="model",
                                property="property",
                                type="type",
                                user_attribute="userAttribute",
                                value="value"
                            )
                        )
                    )
                },
                source_id="sourceId",
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "binding_properties": binding_properties,
            "component_type": component_type,
            "name": name,
            "overrides": overrides,
            "properties": properties,
            "variants": variants,
        }
        if children is not None:
            self._values["children"] = children
        if collection_properties is not None:
            self._values["collection_properties"] = collection_properties
        if events is not None:
            self._values["events"] = events
        if source_id is not None:
            self._values["source_id"] = source_id
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def binding_properties(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnComponent.ComponentBindingPropertiesValueProperty, _IResolvable_da3f097b]]]:
        '''The information to connect a component's properties to data at runtime.

        You can't specify ``tags`` as a valid property for ``bindingProperties`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-bindingproperties
        '''
        result = self._values.get("binding_properties")
        assert result is not None, "Required property 'binding_properties' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnComponent.ComponentBindingPropertiesValueProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def component_type(self) -> builtins.str:
        '''The type of the component.

        This can be an Amplify custom UI component or another custom component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-componenttype
        '''
        result = self._values.get("component_type")
        assert result is not None, "Required property 'component_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def overrides(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Any]]:
        '''Describes the component's properties that can be overriden in a customized instance of the component.

        You can't specify ``tags`` as a valid property for ``overrides`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-overrides
        '''
        result = self._values.get("overrides")
        assert result is not None, "Required property 'overrides' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Any]], result)

    @builtins.property
    def properties(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnComponent.ComponentPropertyProperty, _IResolvable_da3f097b]]]:
        '''Describes the component's properties.

        You can't specify ``tags`` as a valid property for ``properties`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-properties
        '''
        result = self._values.get("properties")
        assert result is not None, "Required property 'properties' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnComponent.ComponentPropertyProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def variants(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnComponent.ComponentVariantProperty, _IResolvable_da3f097b]]]:
        '''A list of the component's variants.

        A variant is a unique style configuration of a main component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-variants
        '''
        result = self._values.get("variants")
        assert result is not None, "Required property 'variants' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnComponent.ComponentVariantProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def children(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnComponent.ComponentChildProperty, _IResolvable_da3f097b]]]]:
        '''A list of the component's ``ComponentChild`` instances.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-children
        '''
        result = self._values.get("children")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnComponent.ComponentChildProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def collection_properties(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnComponent.ComponentDataConfigurationProperty, _IResolvable_da3f097b]]]]:
        '''The data binding configuration for the component's properties.

        Use this for a collection component. You can't specify ``tags`` as a valid property for ``collectionProperties`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-collectionproperties
        '''
        result = self._values.get("collection_properties")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnComponent.ComponentDataConfigurationProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def events(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnComponent.ComponentEventProperty, _IResolvable_da3f097b]]]]:
        '''``AWS::AmplifyUIBuilder::Component.Events``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-events
        '''
        result = self._values.get("events")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnComponent.ComponentEventProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def source_id(self) -> typing.Optional[builtins.str]:
        '''The unique ID of the component in its original source system, such as Figma.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-sourceid
        '''
        result = self._values.get("source_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''One or more key-value pairs to use when tagging the component.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-component.html#cfn-amplifyuibuilder-component-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnComponentProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnTheme(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnTheme",
):
    '''A CloudFormation ``AWS::AmplifyUIBuilder::Theme``.

    The AWS::AmplifyUIBuilder::Theme resource specifies a theme within an Amplify app. A theme is a collection of style settings that apply globally to the components associated with the app.

    :cloudformationResource: AWS::AmplifyUIBuilder::Theme
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-theme.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
        
        # theme_values_property_: amplifyuibuilder.CfnTheme.ThemeValuesProperty
        
        cfn_theme = amplifyuibuilder.CfnTheme(self, "MyCfnTheme",
            name="name",
            values=[amplifyuibuilder.CfnTheme.ThemeValuesProperty(
                key="key",
                value=amplifyuibuilder.CfnTheme.ThemeValueProperty(
                    children=[theme_values_property_],
                    value="value"
                )
            )],
        
            # the properties below are optional
            overrides=[amplifyuibuilder.CfnTheme.ThemeValuesProperty(
                key="key",
                value=amplifyuibuilder.CfnTheme.ThemeValueProperty(
                    children=[theme_values_property_],
                    value="value"
                )
            )],
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
        values: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTheme.ThemeValuesProperty", _IResolvable_da3f097b]]],
        overrides: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTheme.ThemeValuesProperty", _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::AmplifyUIBuilder::Theme``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the theme.
        :param values: A list of key-value pairs that defines the properties of the theme.
        :param overrides: Describes the properties that can be overriden to customize a theme.
        :param tags: One or more key-value pairs to use when tagging the theme.
        '''
        props = CfnThemeProps(name=name, values=values, overrides=overrides, tags=tags)

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
    @jsii.member(jsii_name="attrAppId")
    def attr_app_id(self) -> builtins.str:
        '''The unique ID for the Amplify app associated with the theme.

        :cloudformationAttribute: AppId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAppId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCreatedAt")
    def attr_created_at(self) -> builtins.str:
        '''The time that the theme was created.

        :cloudformationAttribute: CreatedAt
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedAt"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrEnvironmentName")
    def attr_environment_name(self) -> builtins.str:
        '''The name of the backend environment that is a part of the Amplify app.

        :cloudformationAttribute: EnvironmentName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrEnvironmentName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID for the theme.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrModifiedAt")
    def attr_modified_at(self) -> builtins.str:
        '''The time that the theme was modified.

        :cloudformationAttribute: ModifiedAt
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrModifiedAt"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''One or more key-value pairs to use when tagging the theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-theme.html#cfn-amplifyuibuilder-theme-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-theme.html#cfn-amplifyuibuilder-theme-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="values")
    def values(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTheme.ThemeValuesProperty", _IResolvable_da3f097b]]]:
        '''A list of key-value pairs that defines the properties of the theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-theme.html#cfn-amplifyuibuilder-theme-values
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTheme.ThemeValuesProperty", _IResolvable_da3f097b]]], jsii.get(self, "values"))

    @values.setter
    def values(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTheme.ThemeValuesProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "values", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="overrides")
    def overrides(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTheme.ThemeValuesProperty", _IResolvable_da3f097b]]]]:
        '''Describes the properties that can be overriden to customize a theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-theme.html#cfn-amplifyuibuilder-theme-overrides
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTheme.ThemeValuesProperty", _IResolvable_da3f097b]]]], jsii.get(self, "overrides"))

    @overrides.setter
    def overrides(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTheme.ThemeValuesProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "overrides", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnTheme.ThemeValueProperty",
        jsii_struct_bases=[],
        name_mapping={"children": "children", "value": "value"},
    )
    class ThemeValueProperty:
        def __init__(
            self,
            *,
            children: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTheme.ThemeValuesProperty", _IResolvable_da3f097b]]]] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The ``ThemeValue`` property specifies the configuration of a theme's properties.

            :param children: A list of key-value pairs that define the theme's properties.
            :param value: The value of a theme property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-theme-themevalue.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                # theme_values_property_: amplifyuibuilder.CfnTheme.ThemeValuesProperty
                
                theme_value_property = amplifyuibuilder.CfnTheme.ThemeValueProperty(
                    children=[amplifyuibuilder.CfnTheme.ThemeValuesProperty(
                        key="key",
                        value=amplifyuibuilder.CfnTheme.ThemeValueProperty(
                            children=[theme_values_property_],
                            value="value"
                        )
                    )],
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if children is not None:
                self._values["children"] = children
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def children(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTheme.ThemeValuesProperty", _IResolvable_da3f097b]]]]:
            '''A list of key-value pairs that define the theme's properties.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-theme-themevalue.html#cfn-amplifyuibuilder-theme-themevalue-children
            '''
            result = self._values.get("children")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTheme.ThemeValuesProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''The value of a theme property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-theme-themevalue.html#cfn-amplifyuibuilder-theme-themevalue-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ThemeValueProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnTheme.ThemeValuesProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class ThemeValuesProperty:
        def __init__(
            self,
            *,
            key: typing.Optional[builtins.str] = None,
            value: typing.Optional[typing.Union["CfnTheme.ThemeValueProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The ``ThemeValues`` property specifies key-value pair that defines a property of a theme.

            :param key: The name of the property.
            :param value: The value of the property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-theme-themevalues.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
                
                # theme_value_property_: amplifyuibuilder.CfnTheme.ThemeValueProperty
                
                theme_values_property = amplifyuibuilder.CfnTheme.ThemeValuesProperty(
                    key="key",
                    value=amplifyuibuilder.CfnTheme.ThemeValueProperty(
                        children=[amplifyuibuilder.CfnTheme.ThemeValuesProperty(
                            key="key",
                            value=theme_value_property_
                        )],
                        value="value"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if key is not None:
                self._values["key"] = key
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def key(self) -> typing.Optional[builtins.str]:
            '''The name of the property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-theme-themevalues.html#cfn-amplifyuibuilder-theme-themevalues-key
            '''
            result = self._values.get("key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(
            self,
        ) -> typing.Optional[typing.Union["CfnTheme.ThemeValueProperty", _IResolvable_da3f097b]]:
            '''The value of the property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplifyuibuilder-theme-themevalues.html#cfn-amplifyuibuilder-theme-themevalues-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[typing.Union["CfnTheme.ThemeValueProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ThemeValuesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_amplifyuibuilder.CfnThemeProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "values": "values",
        "overrides": "overrides",
        "tags": "tags",
    },
)
class CfnThemeProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        values: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnTheme.ThemeValuesProperty, _IResolvable_da3f097b]]],
        overrides: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnTheme.ThemeValuesProperty, _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnTheme``.

        :param name: The name of the theme.
        :param values: A list of key-value pairs that defines the properties of the theme.
        :param overrides: Describes the properties that can be overriden to customize a theme.
        :param tags: One or more key-value pairs to use when tagging the theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-theme.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_amplifyuibuilder as amplifyuibuilder
            
            # theme_values_property_: amplifyuibuilder.CfnTheme.ThemeValuesProperty
            
            cfn_theme_props = amplifyuibuilder.CfnThemeProps(
                name="name",
                values=[amplifyuibuilder.CfnTheme.ThemeValuesProperty(
                    key="key",
                    value=amplifyuibuilder.CfnTheme.ThemeValueProperty(
                        children=[theme_values_property_],
                        value="value"
                    )
                )],
            
                # the properties below are optional
                overrides=[amplifyuibuilder.CfnTheme.ThemeValuesProperty(
                    key="key",
                    value=amplifyuibuilder.CfnTheme.ThemeValueProperty(
                        children=[theme_values_property_],
                        value="value"
                    )
                )],
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
            "values": values,
        }
        if overrides is not None:
            self._values["overrides"] = overrides
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-theme.html#cfn-amplifyuibuilder-theme-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def values(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTheme.ThemeValuesProperty, _IResolvable_da3f097b]]]:
        '''A list of key-value pairs that defines the properties of the theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-theme.html#cfn-amplifyuibuilder-theme-values
        '''
        result = self._values.get("values")
        assert result is not None, "Required property 'values' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTheme.ThemeValuesProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def overrides(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTheme.ThemeValuesProperty, _IResolvable_da3f097b]]]]:
        '''Describes the properties that can be overriden to customize a theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-theme.html#cfn-amplifyuibuilder-theme-overrides
        '''
        result = self._values.get("overrides")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTheme.ThemeValuesProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''One or more key-value pairs to use when tagging the theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplifyuibuilder-theme.html#cfn-amplifyuibuilder-theme-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnThemeProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnComponent",
    "CfnComponentProps",
    "CfnTheme",
    "CfnThemeProps",
]

publication.publish()
