'''
# AWS::QuickSight Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_quicksight as quicksight
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-quicksight-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::QuickSight](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_QuickSight.html).

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
class CfnAnalysis(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_quicksight.CfnAnalysis",
):
    '''A CloudFormation ``AWS::QuickSight::Analysis``.

    Creates an analysis in Amazon QuickSight.

    :cloudformationResource: AWS::QuickSight::Analysis
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_quicksight as quicksight
        
        cfn_analysis = quicksight.CfnAnalysis(self, "MyCfnAnalysis",
            analysis_id="analysisId",
            aws_account_id="awsAccountId",
            source_entity=quicksight.CfnAnalysis.AnalysisSourceEntityProperty(
                source_template=quicksight.CfnAnalysis.AnalysisSourceTemplateProperty(
                    arn="arn",
                    data_set_references=[quicksight.CfnAnalysis.DataSetReferenceProperty(
                        data_set_arn="dataSetArn",
                        data_set_placeholder="dataSetPlaceholder"
                    )]
                )
            ),
        
            # the properties below are optional
            errors=[quicksight.CfnAnalysis.AnalysisErrorProperty(
                message="message",
                type="type"
            )],
            name="name",
            parameters=quicksight.CfnAnalysis.ParametersProperty(
                date_time_parameters=[quicksight.CfnAnalysis.DateTimeParameterProperty(
                    name="name",
                    values=["values"]
                )],
                decimal_parameters=[quicksight.CfnAnalysis.DecimalParameterProperty(
                    name="name",
                    values=[123]
                )],
                integer_parameters=[quicksight.CfnAnalysis.IntegerParameterProperty(
                    name="name",
                    values=[123]
                )],
                string_parameters=[quicksight.CfnAnalysis.StringParameterProperty(
                    name="name",
                    values=["values"]
                )]
            ),
            permissions=[quicksight.CfnAnalysis.ResourcePermissionProperty(
                actions=["actions"],
                principal="principal"
            )],
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            theme_arn="themeArn"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        analysis_id: builtins.str,
        aws_account_id: builtins.str,
        source_entity: typing.Union["CfnAnalysis.AnalysisSourceEntityProperty", _IResolvable_da3f097b],
        errors: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnAnalysis.AnalysisErrorProperty", _IResolvable_da3f097b]]]] = None,
        name: typing.Optional[builtins.str] = None,
        parameters: typing.Optional[typing.Union["CfnAnalysis.ParametersProperty", _IResolvable_da3f097b]] = None,
        permissions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnAnalysis.ResourcePermissionProperty", _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        theme_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::QuickSight::Analysis``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param analysis_id: The ID for the analysis that you're creating. This ID displays in the URL of the analysis.
        :param aws_account_id: The ID of the AWS account where you are creating an analysis.
        :param source_entity: A source entity to use for the analysis that you're creating. This metadata structure contains details that describe a source template and one or more datasets.
        :param errors: ``AWS::QuickSight::Analysis.Errors``.
        :param name: A descriptive name for the analysis that you're creating. This name displays for the analysis in the Amazon QuickSight console.
        :param parameters: The parameter names and override values that you want to use. An analysis can have any parameter type, and some parameters might accept multiple values.
        :param permissions: A structure that describes the principals and the resource-level permissions on an analysis. You can use the ``Permissions`` structure to grant permissions by providing a list of AWS Identity and Access Management (IAM) action information for each principal listed by Amazon Resource Name (ARN). To specify no permissions, omit ``Permissions`` .
        :param tags: Contains a map of the key-value pairs for the resource tag or tags assigned to the analysis.
        :param theme_arn: The ARN for the theme to apply to the analysis that you're creating. To see the theme in the Amazon QuickSight console, make sure that you have access to it.
        '''
        props = CfnAnalysisProps(
            analysis_id=analysis_id,
            aws_account_id=aws_account_id,
            source_entity=source_entity,
            errors=errors,
            name=name,
            parameters=parameters,
            permissions=permissions,
            tags=tags,
            theme_arn=theme_arn,
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
        '''The Amazon Resource Name (ARN) of the analysis.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCreatedTime")
    def attr_created_time(self) -> builtins.str:
        '''
        :cloudformationAttribute: CreatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDataSetArns")
    def attr_data_set_arns(self) -> typing.List[builtins.str]:
        '''The ARNs of the datasets of the analysis.

        :cloudformationAttribute: DataSetArns
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrDataSetArns"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLastUpdatedTime")
    def attr_last_updated_time(self) -> builtins.str:
        '''The time that the analysis was last updated.

        :cloudformationAttribute: LastUpdatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLastUpdatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSheets")
    def attr_sheets(self) -> _IResolvable_da3f097b:
        '''
        :cloudformationAttribute: Sheets
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrSheets"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStatus")
    def attr_status(self) -> builtins.str:
        '''
        :cloudformationAttribute: Status
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Contains a map of the key-value pairs for the resource tag or tags assigned to the analysis.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="analysisId")
    def analysis_id(self) -> builtins.str:
        '''The ID for the analysis that you're creating.

        This ID displays in the URL of the analysis.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-analysisid
        '''
        return typing.cast(builtins.str, jsii.get(self, "analysisId"))

    @analysis_id.setter
    def analysis_id(self, value: builtins.str) -> None:
        jsii.set(self, "analysisId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="awsAccountId")
    def aws_account_id(self) -> builtins.str:
        '''The ID of the AWS account where you are creating an analysis.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-awsaccountid
        '''
        return typing.cast(builtins.str, jsii.get(self, "awsAccountId"))

    @aws_account_id.setter
    def aws_account_id(self, value: builtins.str) -> None:
        jsii.set(self, "awsAccountId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceEntity")
    def source_entity(
        self,
    ) -> typing.Union["CfnAnalysis.AnalysisSourceEntityProperty", _IResolvable_da3f097b]:
        '''A source entity to use for the analysis that you're creating.

        This metadata structure contains details that describe a source template and one or more datasets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-sourceentity
        '''
        return typing.cast(typing.Union["CfnAnalysis.AnalysisSourceEntityProperty", _IResolvable_da3f097b], jsii.get(self, "sourceEntity"))

    @source_entity.setter
    def source_entity(
        self,
        value: typing.Union["CfnAnalysis.AnalysisSourceEntityProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "sourceEntity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="errors")
    def errors(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.AnalysisErrorProperty", _IResolvable_da3f097b]]]]:
        '''``AWS::QuickSight::Analysis.Errors``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-errors
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.AnalysisErrorProperty", _IResolvable_da3f097b]]]], jsii.get(self, "errors"))

    @errors.setter
    def errors(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.AnalysisErrorProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "errors", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''A descriptive name for the analysis that you're creating.

        This name displays for the analysis in the Amazon QuickSight console.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="parameters")
    def parameters(
        self,
    ) -> typing.Optional[typing.Union["CfnAnalysis.ParametersProperty", _IResolvable_da3f097b]]:
        '''The parameter names and override values that you want to use.

        An analysis can have any parameter type, and some parameters might accept multiple values.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-parameters
        '''
        return typing.cast(typing.Optional[typing.Union["CfnAnalysis.ParametersProperty", _IResolvable_da3f097b]], jsii.get(self, "parameters"))

    @parameters.setter
    def parameters(
        self,
        value: typing.Optional[typing.Union["CfnAnalysis.ParametersProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "parameters", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="permissions")
    def permissions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.ResourcePermissionProperty", _IResolvable_da3f097b]]]]:
        '''A structure that describes the principals and the resource-level permissions on an analysis.

        You can use the ``Permissions`` structure to grant permissions by providing a list of AWS Identity and Access Management (IAM) action information for each principal listed by Amazon Resource Name (ARN).

        To specify no permissions, omit ``Permissions`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-permissions
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.ResourcePermissionProperty", _IResolvable_da3f097b]]]], jsii.get(self, "permissions"))

    @permissions.setter
    def permissions(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.ResourcePermissionProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "permissions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="themeArn")
    def theme_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN for the theme to apply to the analysis that you're creating.

        To see the theme in the Amazon QuickSight console, make sure that you have access to it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-themearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "themeArn"))

    @theme_arn.setter
    def theme_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "themeArn", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnAnalysis.AnalysisErrorProperty",
        jsii_struct_bases=[],
        name_mapping={"message": "message", "type": "type"},
    )
    class AnalysisErrorProperty:
        def __init__(
            self,
            *,
            message: typing.Optional[builtins.str] = None,
            type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Analysis error.

            :param message: The message associated with the analysis error.
            :param type: The type of the analysis error.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-analysiserror.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                analysis_error_property = quicksight.CfnAnalysis.AnalysisErrorProperty(
                    message="message",
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if message is not None:
                self._values["message"] = message
            if type is not None:
                self._values["type"] = type

        @builtins.property
        def message(self) -> typing.Optional[builtins.str]:
            '''The message associated with the analysis error.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-analysiserror.html#cfn-quicksight-analysis-analysiserror-message
            '''
            result = self._values.get("message")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''The type of the analysis error.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-analysiserror.html#cfn-quicksight-analysis-analysiserror-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AnalysisErrorProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnAnalysis.AnalysisSourceEntityProperty",
        jsii_struct_bases=[],
        name_mapping={"source_template": "sourceTemplate"},
    )
    class AnalysisSourceEntityProperty:
        def __init__(
            self,
            *,
            source_template: typing.Optional[typing.Union["CfnAnalysis.AnalysisSourceTemplateProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The source entity of an analysis.

            :param source_template: The source template for the source entity of the analysis.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-analysissourceentity.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                analysis_source_entity_property = quicksight.CfnAnalysis.AnalysisSourceEntityProperty(
                    source_template=quicksight.CfnAnalysis.AnalysisSourceTemplateProperty(
                        arn="arn",
                        data_set_references=[quicksight.CfnAnalysis.DataSetReferenceProperty(
                            data_set_arn="dataSetArn",
                            data_set_placeholder="dataSetPlaceholder"
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if source_template is not None:
                self._values["source_template"] = source_template

        @builtins.property
        def source_template(
            self,
        ) -> typing.Optional[typing.Union["CfnAnalysis.AnalysisSourceTemplateProperty", _IResolvable_da3f097b]]:
            '''The source template for the source entity of the analysis.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-analysissourceentity.html#cfn-quicksight-analysis-analysissourceentity-sourcetemplate
            '''
            result = self._values.get("source_template")
            return typing.cast(typing.Optional[typing.Union["CfnAnalysis.AnalysisSourceTemplateProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AnalysisSourceEntityProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnAnalysis.AnalysisSourceTemplateProperty",
        jsii_struct_bases=[],
        name_mapping={"arn": "arn", "data_set_references": "dataSetReferences"},
    )
    class AnalysisSourceTemplateProperty:
        def __init__(
            self,
            *,
            arn: builtins.str,
            data_set_references: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnAnalysis.DataSetReferenceProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''The source template of an analysis.

            :param arn: The Amazon Resource Name (ARN) of the source template of an analysis.
            :param data_set_references: The dataset references of the source template of an analysis.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-analysissourcetemplate.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                analysis_source_template_property = quicksight.CfnAnalysis.AnalysisSourceTemplateProperty(
                    arn="arn",
                    data_set_references=[quicksight.CfnAnalysis.DataSetReferenceProperty(
                        data_set_arn="dataSetArn",
                        data_set_placeholder="dataSetPlaceholder"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
                "data_set_references": data_set_references,
            }

        @builtins.property
        def arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the source template of an analysis.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-analysissourcetemplate.html#cfn-quicksight-analysis-analysissourcetemplate-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def data_set_references(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.DataSetReferenceProperty", _IResolvable_da3f097b]]]:
            '''The dataset references of the source template of an analysis.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-analysissourcetemplate.html#cfn-quicksight-analysis-analysissourcetemplate-datasetreferences
            '''
            result = self._values.get("data_set_references")
            assert result is not None, "Required property 'data_set_references' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.DataSetReferenceProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AnalysisSourceTemplateProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnAnalysis.DataSetReferenceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "data_set_arn": "dataSetArn",
            "data_set_placeholder": "dataSetPlaceholder",
        },
    )
    class DataSetReferenceProperty:
        def __init__(
            self,
            *,
            data_set_arn: builtins.str,
            data_set_placeholder: builtins.str,
        ) -> None:
            '''Dataset reference.

            :param data_set_arn: Dataset Amazon Resource Name (ARN).
            :param data_set_placeholder: Dataset placeholder.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-datasetreference.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                data_set_reference_property = quicksight.CfnAnalysis.DataSetReferenceProperty(
                    data_set_arn="dataSetArn",
                    data_set_placeholder="dataSetPlaceholder"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "data_set_arn": data_set_arn,
                "data_set_placeholder": data_set_placeholder,
            }

        @builtins.property
        def data_set_arn(self) -> builtins.str:
            '''Dataset Amazon Resource Name (ARN).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-datasetreference.html#cfn-quicksight-analysis-datasetreference-datasetarn
            '''
            result = self._values.get("data_set_arn")
            assert result is not None, "Required property 'data_set_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def data_set_placeholder(self) -> builtins.str:
            '''Dataset placeholder.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-datasetreference.html#cfn-quicksight-analysis-datasetreference-datasetplaceholder
            '''
            result = self._values.get("data_set_placeholder")
            assert result is not None, "Required property 'data_set_placeholder' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataSetReferenceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnAnalysis.DateTimeParameterProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "values": "values"},
    )
    class DateTimeParameterProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            values: typing.Sequence[builtins.str],
        ) -> None:
            '''A date-time parameter.

            :param name: A display name for the date-time parameter.
            :param values: The values for the date-time parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-datetimeparameter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                date_time_parameter_property = quicksight.CfnAnalysis.DateTimeParameterProperty(
                    name="name",
                    values=["values"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "values": values,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''A display name for the date-time parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-datetimeparameter.html#cfn-quicksight-analysis-datetimeparameter-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def values(self) -> typing.List[builtins.str]:
            '''The values for the date-time parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-datetimeparameter.html#cfn-quicksight-analysis-datetimeparameter-values
            '''
            result = self._values.get("values")
            assert result is not None, "Required property 'values' is missing"
            return typing.cast(typing.List[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DateTimeParameterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnAnalysis.DecimalParameterProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "values": "values"},
    )
    class DecimalParameterProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            values: typing.Union[_IResolvable_da3f097b, typing.Sequence[jsii.Number]],
        ) -> None:
            '''A decimal parameter.

            :param name: A display name for the decimal parameter.
            :param values: The values for the decimal parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-decimalparameter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                decimal_parameter_property = quicksight.CfnAnalysis.DecimalParameterProperty(
                    name="name",
                    values=[123]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "values": values,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''A display name for the decimal parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-decimalparameter.html#cfn-quicksight-analysis-decimalparameter-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def values(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[jsii.Number]]:
            '''The values for the decimal parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-decimalparameter.html#cfn-quicksight-analysis-decimalparameter-values
            '''
            result = self._values.get("values")
            assert result is not None, "Required property 'values' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[jsii.Number]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DecimalParameterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnAnalysis.IntegerParameterProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "values": "values"},
    )
    class IntegerParameterProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            values: typing.Union[_IResolvable_da3f097b, typing.Sequence[jsii.Number]],
        ) -> None:
            '''An integer parameter.

            :param name: The name of the integer parameter.
            :param values: The values for the integer parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-integerparameter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                integer_parameter_property = quicksight.CfnAnalysis.IntegerParameterProperty(
                    name="name",
                    values=[123]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "values": values,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the integer parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-integerparameter.html#cfn-quicksight-analysis-integerparameter-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def values(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[jsii.Number]]:
            '''The values for the integer parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-integerparameter.html#cfn-quicksight-analysis-integerparameter-values
            '''
            result = self._values.get("values")
            assert result is not None, "Required property 'values' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[jsii.Number]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IntegerParameterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnAnalysis.ParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "date_time_parameters": "dateTimeParameters",
            "decimal_parameters": "decimalParameters",
            "integer_parameters": "integerParameters",
            "string_parameters": "stringParameters",
        },
    )
    class ParametersProperty:
        def __init__(
            self,
            *,
            date_time_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnAnalysis.DateTimeParameterProperty", _IResolvable_da3f097b]]]] = None,
            decimal_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnAnalysis.DecimalParameterProperty", _IResolvable_da3f097b]]]] = None,
            integer_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnAnalysis.IntegerParameterProperty", _IResolvable_da3f097b]]]] = None,
            string_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnAnalysis.StringParameterProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''A list of Amazon QuickSight parameters and the list's override values.

            :param date_time_parameters: The parameters that have a data type of date-time.
            :param decimal_parameters: The parameters that have a data type of decimal.
            :param integer_parameters: The parameters that have a data type of integer.
            :param string_parameters: The parameters that have a data type of string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-parameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                parameters_property = quicksight.CfnAnalysis.ParametersProperty(
                    date_time_parameters=[quicksight.CfnAnalysis.DateTimeParameterProperty(
                        name="name",
                        values=["values"]
                    )],
                    decimal_parameters=[quicksight.CfnAnalysis.DecimalParameterProperty(
                        name="name",
                        values=[123]
                    )],
                    integer_parameters=[quicksight.CfnAnalysis.IntegerParameterProperty(
                        name="name",
                        values=[123]
                    )],
                    string_parameters=[quicksight.CfnAnalysis.StringParameterProperty(
                        name="name",
                        values=["values"]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if date_time_parameters is not None:
                self._values["date_time_parameters"] = date_time_parameters
            if decimal_parameters is not None:
                self._values["decimal_parameters"] = decimal_parameters
            if integer_parameters is not None:
                self._values["integer_parameters"] = integer_parameters
            if string_parameters is not None:
                self._values["string_parameters"] = string_parameters

        @builtins.property
        def date_time_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.DateTimeParameterProperty", _IResolvable_da3f097b]]]]:
            '''The parameters that have a data type of date-time.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-parameters.html#cfn-quicksight-analysis-parameters-datetimeparameters
            '''
            result = self._values.get("date_time_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.DateTimeParameterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def decimal_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.DecimalParameterProperty", _IResolvable_da3f097b]]]]:
            '''The parameters that have a data type of decimal.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-parameters.html#cfn-quicksight-analysis-parameters-decimalparameters
            '''
            result = self._values.get("decimal_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.DecimalParameterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def integer_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.IntegerParameterProperty", _IResolvable_da3f097b]]]]:
            '''The parameters that have a data type of integer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-parameters.html#cfn-quicksight-analysis-parameters-integerparameters
            '''
            result = self._values.get("integer_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.IntegerParameterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def string_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.StringParameterProperty", _IResolvable_da3f097b]]]]:
            '''The parameters that have a data type of string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-parameters.html#cfn-quicksight-analysis-parameters-stringparameters
            '''
            result = self._values.get("string_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAnalysis.StringParameterProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnAnalysis.ResourcePermissionProperty",
        jsii_struct_bases=[],
        name_mapping={"actions": "actions", "principal": "principal"},
    )
    class ResourcePermissionProperty:
        def __init__(
            self,
            *,
            actions: typing.Sequence[builtins.str],
            principal: builtins.str,
        ) -> None:
            '''Permission for the resource.

            :param actions: The IAM action to grant or revoke permissions on.
            :param principal: The Amazon Resource Name (ARN) of the principal. This can be one of the following:. - The ARN of an Amazon QuickSight user or group associated with a data source or dataset. (This is common.) - The ARN of an Amazon QuickSight user, group, or namespace associated with an analysis, dashboard, template, or theme. (This is common.) - The ARN of an AWS account root: This is an IAM ARN rather than a Amazon QuickSight ARN. Use this option only to share resources (templates) across AWS accounts . (This is less common.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-resourcepermission.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                resource_permission_property = quicksight.CfnAnalysis.ResourcePermissionProperty(
                    actions=["actions"],
                    principal="principal"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "actions": actions,
                "principal": principal,
            }

        @builtins.property
        def actions(self) -> typing.List[builtins.str]:
            '''The IAM action to grant or revoke permissions on.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-resourcepermission.html#cfn-quicksight-analysis-resourcepermission-actions
            '''
            result = self._values.get("actions")
            assert result is not None, "Required property 'actions' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def principal(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the principal. This can be one of the following:.

            - The ARN of an Amazon QuickSight user or group associated with a data source or dataset. (This is common.)
            - The ARN of an Amazon QuickSight user, group, or namespace associated with an analysis, dashboard, template, or theme. (This is common.)
            - The ARN of an AWS account root: This is an IAM ARN rather than a Amazon QuickSight ARN. Use this option only to share resources (templates) across AWS accounts . (This is less common.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-resourcepermission.html#cfn-quicksight-analysis-resourcepermission-principal
            '''
            result = self._values.get("principal")
            assert result is not None, "Required property 'principal' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourcePermissionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnAnalysis.SheetProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "sheet_id": "sheetId"},
    )
    class SheetProperty:
        def __init__(
            self,
            *,
            name: typing.Optional[builtins.str] = None,
            sheet_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A *sheet* , which is an object that contains a set of visuals that are viewed together on one page in Amazon QuickSight.

            Every analysis and dashboard contains at least one sheet. Each sheet contains at least one visualization widget, for example a chart, pivot table, or narrative insight. Sheets can be associated with other components, such as controls, filters, and so on.

            :param name: The name of a sheet. This name is displayed on the sheet's tab in the Amazon QuickSight console.
            :param sheet_id: The unique identifier associated with a sheet.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-sheet.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                sheet_property = quicksight.CfnAnalysis.SheetProperty(
                    name="name",
                    sheet_id="sheetId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if name is not None:
                self._values["name"] = name
            if sheet_id is not None:
                self._values["sheet_id"] = sheet_id

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of a sheet.

            This name is displayed on the sheet's tab in the Amazon QuickSight console.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-sheet.html#cfn-quicksight-analysis-sheet-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def sheet_id(self) -> typing.Optional[builtins.str]:
            '''The unique identifier associated with a sheet.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-sheet.html#cfn-quicksight-analysis-sheet-sheetid
            '''
            result = self._values.get("sheet_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SheetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnAnalysis.StringParameterProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "values": "values"},
    )
    class StringParameterProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            values: typing.Sequence[builtins.str],
        ) -> None:
            '''A string parameter.

            :param name: A display name for a string parameter.
            :param values: The values of a string parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-stringparameter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                string_parameter_property = quicksight.CfnAnalysis.StringParameterProperty(
                    name="name",
                    values=["values"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "values": values,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''A display name for a string parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-stringparameter.html#cfn-quicksight-analysis-stringparameter-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def values(self) -> typing.List[builtins.str]:
            '''The values of a string parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-analysis-stringparameter.html#cfn-quicksight-analysis-stringparameter-values
            '''
            result = self._values.get("values")
            assert result is not None, "Required property 'values' is missing"
            return typing.cast(typing.List[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StringParameterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_quicksight.CfnAnalysisProps",
    jsii_struct_bases=[],
    name_mapping={
        "analysis_id": "analysisId",
        "aws_account_id": "awsAccountId",
        "source_entity": "sourceEntity",
        "errors": "errors",
        "name": "name",
        "parameters": "parameters",
        "permissions": "permissions",
        "tags": "tags",
        "theme_arn": "themeArn",
    },
)
class CfnAnalysisProps:
    def __init__(
        self,
        *,
        analysis_id: builtins.str,
        aws_account_id: builtins.str,
        source_entity: typing.Union[CfnAnalysis.AnalysisSourceEntityProperty, _IResolvable_da3f097b],
        errors: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnAnalysis.AnalysisErrorProperty, _IResolvable_da3f097b]]]] = None,
        name: typing.Optional[builtins.str] = None,
        parameters: typing.Optional[typing.Union[CfnAnalysis.ParametersProperty, _IResolvable_da3f097b]] = None,
        permissions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnAnalysis.ResourcePermissionProperty, _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        theme_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnAnalysis``.

        :param analysis_id: The ID for the analysis that you're creating. This ID displays in the URL of the analysis.
        :param aws_account_id: The ID of the AWS account where you are creating an analysis.
        :param source_entity: A source entity to use for the analysis that you're creating. This metadata structure contains details that describe a source template and one or more datasets.
        :param errors: ``AWS::QuickSight::Analysis.Errors``.
        :param name: A descriptive name for the analysis that you're creating. This name displays for the analysis in the Amazon QuickSight console.
        :param parameters: The parameter names and override values that you want to use. An analysis can have any parameter type, and some parameters might accept multiple values.
        :param permissions: A structure that describes the principals and the resource-level permissions on an analysis. You can use the ``Permissions`` structure to grant permissions by providing a list of AWS Identity and Access Management (IAM) action information for each principal listed by Amazon Resource Name (ARN). To specify no permissions, omit ``Permissions`` .
        :param tags: Contains a map of the key-value pairs for the resource tag or tags assigned to the analysis.
        :param theme_arn: The ARN for the theme to apply to the analysis that you're creating. To see the theme in the Amazon QuickSight console, make sure that you have access to it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_quicksight as quicksight
            
            cfn_analysis_props = quicksight.CfnAnalysisProps(
                analysis_id="analysisId",
                aws_account_id="awsAccountId",
                source_entity=quicksight.CfnAnalysis.AnalysisSourceEntityProperty(
                    source_template=quicksight.CfnAnalysis.AnalysisSourceTemplateProperty(
                        arn="arn",
                        data_set_references=[quicksight.CfnAnalysis.DataSetReferenceProperty(
                            data_set_arn="dataSetArn",
                            data_set_placeholder="dataSetPlaceholder"
                        )]
                    )
                ),
            
                # the properties below are optional
                errors=[quicksight.CfnAnalysis.AnalysisErrorProperty(
                    message="message",
                    type="type"
                )],
                name="name",
                parameters=quicksight.CfnAnalysis.ParametersProperty(
                    date_time_parameters=[quicksight.CfnAnalysis.DateTimeParameterProperty(
                        name="name",
                        values=["values"]
                    )],
                    decimal_parameters=[quicksight.CfnAnalysis.DecimalParameterProperty(
                        name="name",
                        values=[123]
                    )],
                    integer_parameters=[quicksight.CfnAnalysis.IntegerParameterProperty(
                        name="name",
                        values=[123]
                    )],
                    string_parameters=[quicksight.CfnAnalysis.StringParameterProperty(
                        name="name",
                        values=["values"]
                    )]
                ),
                permissions=[quicksight.CfnAnalysis.ResourcePermissionProperty(
                    actions=["actions"],
                    principal="principal"
                )],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                theme_arn="themeArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "analysis_id": analysis_id,
            "aws_account_id": aws_account_id,
            "source_entity": source_entity,
        }
        if errors is not None:
            self._values["errors"] = errors
        if name is not None:
            self._values["name"] = name
        if parameters is not None:
            self._values["parameters"] = parameters
        if permissions is not None:
            self._values["permissions"] = permissions
        if tags is not None:
            self._values["tags"] = tags
        if theme_arn is not None:
            self._values["theme_arn"] = theme_arn

    @builtins.property
    def analysis_id(self) -> builtins.str:
        '''The ID for the analysis that you're creating.

        This ID displays in the URL of the analysis.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-analysisid
        '''
        result = self._values.get("analysis_id")
        assert result is not None, "Required property 'analysis_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def aws_account_id(self) -> builtins.str:
        '''The ID of the AWS account where you are creating an analysis.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-awsaccountid
        '''
        result = self._values.get("aws_account_id")
        assert result is not None, "Required property 'aws_account_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def source_entity(
        self,
    ) -> typing.Union[CfnAnalysis.AnalysisSourceEntityProperty, _IResolvable_da3f097b]:
        '''A source entity to use for the analysis that you're creating.

        This metadata structure contains details that describe a source template and one or more datasets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-sourceentity
        '''
        result = self._values.get("source_entity")
        assert result is not None, "Required property 'source_entity' is missing"
        return typing.cast(typing.Union[CfnAnalysis.AnalysisSourceEntityProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def errors(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnAnalysis.AnalysisErrorProperty, _IResolvable_da3f097b]]]]:
        '''``AWS::QuickSight::Analysis.Errors``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-errors
        '''
        result = self._values.get("errors")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnAnalysis.AnalysisErrorProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''A descriptive name for the analysis that you're creating.

        This name displays for the analysis in the Amazon QuickSight console.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def parameters(
        self,
    ) -> typing.Optional[typing.Union[CfnAnalysis.ParametersProperty, _IResolvable_da3f097b]]:
        '''The parameter names and override values that you want to use.

        An analysis can have any parameter type, and some parameters might accept multiple values.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-parameters
        '''
        result = self._values.get("parameters")
        return typing.cast(typing.Optional[typing.Union[CfnAnalysis.ParametersProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def permissions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnAnalysis.ResourcePermissionProperty, _IResolvable_da3f097b]]]]:
        '''A structure that describes the principals and the resource-level permissions on an analysis.

        You can use the ``Permissions`` structure to grant permissions by providing a list of AWS Identity and Access Management (IAM) action information for each principal listed by Amazon Resource Name (ARN).

        To specify no permissions, omit ``Permissions`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-permissions
        '''
        result = self._values.get("permissions")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnAnalysis.ResourcePermissionProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Contains a map of the key-value pairs for the resource tag or tags assigned to the analysis.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def theme_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN for the theme to apply to the analysis that you're creating.

        To see the theme in the Amazon QuickSight console, make sure that you have access to it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-analysis.html#cfn-quicksight-analysis-themearn
        '''
        result = self._values.get("theme_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAnalysisProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDashboard(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboard",
):
    '''A CloudFormation ``AWS::QuickSight::Dashboard``.

    Creates a dashboard from a template. To first create a template, see the ``CreateTemplate`` API operation.

    A dashboard is an entity in Amazon QuickSight that identifies Amazon QuickSight reports, created from analyses. You can share Amazon QuickSight dashboards. With the right permissions, you can create scheduled email reports from them. If you have the correct permissions, you can create a dashboard from a template that exists in a different AWS account .

    :cloudformationResource: AWS::QuickSight::Dashboard
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_quicksight as quicksight
        
        cfn_dashboard = quicksight.CfnDashboard(self, "MyCfnDashboard",
            aws_account_id="awsAccountId",
            dashboard_id="dashboardId",
            source_entity=quicksight.CfnDashboard.DashboardSourceEntityProperty(
                source_template=quicksight.CfnDashboard.DashboardSourceTemplateProperty(
                    arn="arn",
                    data_set_references=[quicksight.CfnDashboard.DataSetReferenceProperty(
                        data_set_arn="dataSetArn",
                        data_set_placeholder="dataSetPlaceholder"
                    )]
                )
            ),
        
            # the properties below are optional
            dashboard_publish_options=quicksight.CfnDashboard.DashboardPublishOptionsProperty(
                ad_hoc_filtering_option=quicksight.CfnDashboard.AdHocFilteringOptionProperty(
                    availability_status="availabilityStatus"
                ),
                export_to_csv_option=quicksight.CfnDashboard.ExportToCSVOptionProperty(
                    availability_status="availabilityStatus"
                ),
                sheet_controls_option=quicksight.CfnDashboard.SheetControlsOptionProperty(
                    visibility_state="visibilityState"
                )
            ),
            name="name",
            parameters=quicksight.CfnDashboard.ParametersProperty(
                date_time_parameters=[quicksight.CfnDashboard.DateTimeParameterProperty(
                    name="name",
                    values=["values"]
                )],
                decimal_parameters=[quicksight.CfnDashboard.DecimalParameterProperty(
                    name="name",
                    values=[123]
                )],
                integer_parameters=[quicksight.CfnDashboard.IntegerParameterProperty(
                    name="name",
                    values=[123]
                )],
                string_parameters=[quicksight.CfnDashboard.StringParameterProperty(
                    name="name",
                    values=["values"]
                )]
            ),
            permissions=[quicksight.CfnDashboard.ResourcePermissionProperty(
                actions=["actions"],
                principal="principal"
            )],
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            theme_arn="themeArn",
            version_description="versionDescription"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        aws_account_id: builtins.str,
        dashboard_id: builtins.str,
        source_entity: typing.Union["CfnDashboard.DashboardSourceEntityProperty", _IResolvable_da3f097b],
        dashboard_publish_options: typing.Optional[typing.Union["CfnDashboard.DashboardPublishOptionsProperty", _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        parameters: typing.Optional[typing.Union["CfnDashboard.ParametersProperty", _IResolvable_da3f097b]] = None,
        permissions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDashboard.ResourcePermissionProperty", _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        theme_arn: typing.Optional[builtins.str] = None,
        version_description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::QuickSight::Dashboard``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param aws_account_id: The ID of the AWS account where you want to create the dashboard.
        :param dashboard_id: The ID for the dashboard, also added to the IAM policy.
        :param source_entity: The entity that you are using as a source when you create the dashboard. In ``SourceEntity`` , you specify the type of object that you want to use. You can only create a dashboard from a template, so you use a ``SourceTemplate`` entity. If you need to create a dashboard from an analysis, first convert the analysis to a template by using the ``CreateTemplate`` API operation. For ``SourceTemplate`` , specify the Amazon Resource Name (ARN) of the source template. The ``SourceTemplate`` ARN can contain any AWS account; and any QuickSight-supported AWS Region . Use the ``DataSetReferences`` entity within ``SourceTemplate`` to list the replacement datasets for the placeholders listed in the original. The schema in each dataset must match its placeholder.
        :param dashboard_publish_options: Options for publishing the dashboard when you create it:. - ``AvailabilityStatus`` for ``AdHocFilteringOption`` - This status can be either ``ENABLED`` or ``DISABLED`` . When this is set to ``DISABLED`` , Amazon QuickSight disables the left filter pane on the published dashboard, which can be used for ad hoc (one-time) filtering. This option is ``ENABLED`` by default. - ``AvailabilityStatus`` for ``ExportToCSVOption`` - This status can be either ``ENABLED`` or ``DISABLED`` . The visual option to export data to .CSV format isn't enabled when this is set to ``DISABLED`` . This option is ``ENABLED`` by default. - ``VisibilityState`` for ``SheetControlsOption`` - This visibility state can be either ``COLLAPSED`` or ``EXPANDED`` . This option is ``COLLAPSED`` by default.
        :param name: The display name of the dashboard.
        :param parameters: The parameters for the creation of the dashboard, which you want to use to override the default settings. A dashboard can have any type of parameters, and some parameters might accept multiple values.
        :param permissions: A structure that contains the permissions of the dashboard. You can use this structure for granting permissions by providing a list of IAM action information for each principal ARN. To specify no permissions, omit the permissions list.
        :param tags: Contains a map of the key-value pairs for the resource tag or tags assigned to the dashboard.
        :param theme_arn: The Amazon Resource Name (ARN) of the theme that is being used for this dashboard. If you add a value for this field, it overrides the value that is used in the source entity. The theme ARN must exist in the same AWS account where you create the dashboard.
        :param version_description: A description for the first version of the dashboard being created.
        '''
        props = CfnDashboardProps(
            aws_account_id=aws_account_id,
            dashboard_id=dashboard_id,
            source_entity=source_entity,
            dashboard_publish_options=dashboard_publish_options,
            name=name,
            parameters=parameters,
            permissions=permissions,
            tags=tags,
            theme_arn=theme_arn,
            version_description=version_description,
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
        '''The Amazon Resource Name (ARN) of the dashboard.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCreatedTime")
    def attr_created_time(self) -> builtins.str:
        '''The time this dashboard version was created.

        :cloudformationAttribute: CreatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLastPublishedTime")
    def attr_last_published_time(self) -> builtins.str:
        '''The time that the dashboard was last published.

        :cloudformationAttribute: LastPublishedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLastPublishedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLastUpdatedTime")
    def attr_last_updated_time(self) -> builtins.str:
        '''The time that the dashboard was last updated.

        :cloudformationAttribute: LastUpdatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLastUpdatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Contains a map of the key-value pairs for the resource tag or tags assigned to the dashboard.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="awsAccountId")
    def aws_account_id(self) -> builtins.str:
        '''The ID of the AWS account where you want to create the dashboard.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-awsaccountid
        '''
        return typing.cast(builtins.str, jsii.get(self, "awsAccountId"))

    @aws_account_id.setter
    def aws_account_id(self, value: builtins.str) -> None:
        jsii.set(self, "awsAccountId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dashboardId")
    def dashboard_id(self) -> builtins.str:
        '''The ID for the dashboard, also added to the IAM policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-dashboardid
        '''
        return typing.cast(builtins.str, jsii.get(self, "dashboardId"))

    @dashboard_id.setter
    def dashboard_id(self, value: builtins.str) -> None:
        jsii.set(self, "dashboardId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceEntity")
    def source_entity(
        self,
    ) -> typing.Union["CfnDashboard.DashboardSourceEntityProperty", _IResolvable_da3f097b]:
        '''The entity that you are using as a source when you create the dashboard.

        In ``SourceEntity`` , you specify the type of object that you want to use. You can only create a dashboard from a template, so you use a ``SourceTemplate`` entity. If you need to create a dashboard from an analysis, first convert the analysis to a template by using the ``CreateTemplate`` API operation. For ``SourceTemplate`` , specify the Amazon Resource Name (ARN) of the source template. The ``SourceTemplate`` ARN can contain any AWS account; and any QuickSight-supported AWS Region .

        Use the ``DataSetReferences`` entity within ``SourceTemplate`` to list the replacement datasets for the placeholders listed in the original. The schema in each dataset must match its placeholder.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-sourceentity
        '''
        return typing.cast(typing.Union["CfnDashboard.DashboardSourceEntityProperty", _IResolvable_da3f097b], jsii.get(self, "sourceEntity"))

    @source_entity.setter
    def source_entity(
        self,
        value: typing.Union["CfnDashboard.DashboardSourceEntityProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "sourceEntity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dashboardPublishOptions")
    def dashboard_publish_options(
        self,
    ) -> typing.Optional[typing.Union["CfnDashboard.DashboardPublishOptionsProperty", _IResolvable_da3f097b]]:
        '''Options for publishing the dashboard when you create it:.

        - ``AvailabilityStatus`` for ``AdHocFilteringOption`` - This status can be either ``ENABLED`` or ``DISABLED`` . When this is set to ``DISABLED`` , Amazon QuickSight disables the left filter pane on the published dashboard, which can be used for ad hoc (one-time) filtering. This option is ``ENABLED`` by default.
        - ``AvailabilityStatus`` for ``ExportToCSVOption`` - This status can be either ``ENABLED`` or ``DISABLED`` . The visual option to export data to .CSV format isn't enabled when this is set to ``DISABLED`` . This option is ``ENABLED`` by default.
        - ``VisibilityState`` for ``SheetControlsOption`` - This visibility state can be either ``COLLAPSED`` or ``EXPANDED`` . This option is ``COLLAPSED`` by default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-dashboardpublishoptions
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDashboard.DashboardPublishOptionsProperty", _IResolvable_da3f097b]], jsii.get(self, "dashboardPublishOptions"))

    @dashboard_publish_options.setter
    def dashboard_publish_options(
        self,
        value: typing.Optional[typing.Union["CfnDashboard.DashboardPublishOptionsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "dashboardPublishOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The display name of the dashboard.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="parameters")
    def parameters(
        self,
    ) -> typing.Optional[typing.Union["CfnDashboard.ParametersProperty", _IResolvable_da3f097b]]:
        '''The parameters for the creation of the dashboard, which you want to use to override the default settings.

        A dashboard can have any type of parameters, and some parameters might accept multiple values.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-parameters
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDashboard.ParametersProperty", _IResolvable_da3f097b]], jsii.get(self, "parameters"))

    @parameters.setter
    def parameters(
        self,
        value: typing.Optional[typing.Union["CfnDashboard.ParametersProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "parameters", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="permissions")
    def permissions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDashboard.ResourcePermissionProperty", _IResolvable_da3f097b]]]]:
        '''A structure that contains the permissions of the dashboard.

        You can use this structure for granting permissions by providing a list of IAM action information for each principal ARN.

        To specify no permissions, omit the permissions list.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-permissions
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDashboard.ResourcePermissionProperty", _IResolvable_da3f097b]]]], jsii.get(self, "permissions"))

    @permissions.setter
    def permissions(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDashboard.ResourcePermissionProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "permissions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="themeArn")
    def theme_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the theme that is being used for this dashboard.

        If you add a value for this field, it overrides the value that is used in the source entity. The theme ARN must exist in the same AWS account where you create the dashboard.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-themearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "themeArn"))

    @theme_arn.setter
    def theme_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "themeArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="versionDescription")
    def version_description(self) -> typing.Optional[builtins.str]:
        '''A description for the first version of the dashboard being created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-versiondescription
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "versionDescription"))

    @version_description.setter
    def version_description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "versionDescription", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboard.AdHocFilteringOptionProperty",
        jsii_struct_bases=[],
        name_mapping={"availability_status": "availabilityStatus"},
    )
    class AdHocFilteringOptionProperty:
        def __init__(
            self,
            *,
            availability_status: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Ad hoc (one-time) filtering option.

            :param availability_status: Availability status.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-adhocfilteringoption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                ad_hoc_filtering_option_property = quicksight.CfnDashboard.AdHocFilteringOptionProperty(
                    availability_status="availabilityStatus"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if availability_status is not None:
                self._values["availability_status"] = availability_status

        @builtins.property
        def availability_status(self) -> typing.Optional[builtins.str]:
            '''Availability status.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-adhocfilteringoption.html#cfn-quicksight-dashboard-adhocfilteringoption-availabilitystatus
            '''
            result = self._values.get("availability_status")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AdHocFilteringOptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboard.DashboardPublishOptionsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "ad_hoc_filtering_option": "adHocFilteringOption",
            "export_to_csv_option": "exportToCsvOption",
            "sheet_controls_option": "sheetControlsOption",
        },
    )
    class DashboardPublishOptionsProperty:
        def __init__(
            self,
            *,
            ad_hoc_filtering_option: typing.Optional[typing.Union["CfnDashboard.AdHocFilteringOptionProperty", _IResolvable_da3f097b]] = None,
            export_to_csv_option: typing.Optional[typing.Union["CfnDashboard.ExportToCSVOptionProperty", _IResolvable_da3f097b]] = None,
            sheet_controls_option: typing.Optional[typing.Union["CfnDashboard.SheetControlsOptionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Dashboard publish options.

            :param ad_hoc_filtering_option: Ad hoc (one-time) filtering option.
            :param export_to_csv_option: Export to .csv option.
            :param sheet_controls_option: Sheet controls option.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-dashboardpublishoptions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                dashboard_publish_options_property = quicksight.CfnDashboard.DashboardPublishOptionsProperty(
                    ad_hoc_filtering_option=quicksight.CfnDashboard.AdHocFilteringOptionProperty(
                        availability_status="availabilityStatus"
                    ),
                    export_to_csv_option=quicksight.CfnDashboard.ExportToCSVOptionProperty(
                        availability_status="availabilityStatus"
                    ),
                    sheet_controls_option=quicksight.CfnDashboard.SheetControlsOptionProperty(
                        visibility_state="visibilityState"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if ad_hoc_filtering_option is not None:
                self._values["ad_hoc_filtering_option"] = ad_hoc_filtering_option
            if export_to_csv_option is not None:
                self._values["export_to_csv_option"] = export_to_csv_option
            if sheet_controls_option is not None:
                self._values["sheet_controls_option"] = sheet_controls_option

        @builtins.property
        def ad_hoc_filtering_option(
            self,
        ) -> typing.Optional[typing.Union["CfnDashboard.AdHocFilteringOptionProperty", _IResolvable_da3f097b]]:
            '''Ad hoc (one-time) filtering option.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-dashboardpublishoptions.html#cfn-quicksight-dashboard-dashboardpublishoptions-adhocfilteringoption
            '''
            result = self._values.get("ad_hoc_filtering_option")
            return typing.cast(typing.Optional[typing.Union["CfnDashboard.AdHocFilteringOptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def export_to_csv_option(
            self,
        ) -> typing.Optional[typing.Union["CfnDashboard.ExportToCSVOptionProperty", _IResolvable_da3f097b]]:
            '''Export to .csv option.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-dashboardpublishoptions.html#cfn-quicksight-dashboard-dashboardpublishoptions-exporttocsvoption
            '''
            result = self._values.get("export_to_csv_option")
            return typing.cast(typing.Optional[typing.Union["CfnDashboard.ExportToCSVOptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sheet_controls_option(
            self,
        ) -> typing.Optional[typing.Union["CfnDashboard.SheetControlsOptionProperty", _IResolvable_da3f097b]]:
            '''Sheet controls option.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-dashboardpublishoptions.html#cfn-quicksight-dashboard-dashboardpublishoptions-sheetcontrolsoption
            '''
            result = self._values.get("sheet_controls_option")
            return typing.cast(typing.Optional[typing.Union["CfnDashboard.SheetControlsOptionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DashboardPublishOptionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboard.DashboardSourceEntityProperty",
        jsii_struct_bases=[],
        name_mapping={"source_template": "sourceTemplate"},
    )
    class DashboardSourceEntityProperty:
        def __init__(
            self,
            *,
            source_template: typing.Optional[typing.Union["CfnDashboard.DashboardSourceTemplateProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Dashboard source entity.

            :param source_template: Source template.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-dashboardsourceentity.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                dashboard_source_entity_property = quicksight.CfnDashboard.DashboardSourceEntityProperty(
                    source_template=quicksight.CfnDashboard.DashboardSourceTemplateProperty(
                        arn="arn",
                        data_set_references=[quicksight.CfnDashboard.DataSetReferenceProperty(
                            data_set_arn="dataSetArn",
                            data_set_placeholder="dataSetPlaceholder"
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if source_template is not None:
                self._values["source_template"] = source_template

        @builtins.property
        def source_template(
            self,
        ) -> typing.Optional[typing.Union["CfnDashboard.DashboardSourceTemplateProperty", _IResolvable_da3f097b]]:
            '''Source template.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-dashboardsourceentity.html#cfn-quicksight-dashboard-dashboardsourceentity-sourcetemplate
            '''
            result = self._values.get("source_template")
            return typing.cast(typing.Optional[typing.Union["CfnDashboard.DashboardSourceTemplateProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DashboardSourceEntityProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboard.DashboardSourceTemplateProperty",
        jsii_struct_bases=[],
        name_mapping={"arn": "arn", "data_set_references": "dataSetReferences"},
    )
    class DashboardSourceTemplateProperty:
        def __init__(
            self,
            *,
            arn: builtins.str,
            data_set_references: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDashboard.DataSetReferenceProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''Dashboard source template.

            :param arn: The Amazon Resource Name (ARN) of the resource.
            :param data_set_references: Dataset references.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-dashboardsourcetemplate.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                dashboard_source_template_property = quicksight.CfnDashboard.DashboardSourceTemplateProperty(
                    arn="arn",
                    data_set_references=[quicksight.CfnDashboard.DataSetReferenceProperty(
                        data_set_arn="dataSetArn",
                        data_set_placeholder="dataSetPlaceholder"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
                "data_set_references": data_set_references,
            }

        @builtins.property
        def arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-dashboardsourcetemplate.html#cfn-quicksight-dashboard-dashboardsourcetemplate-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def data_set_references(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDashboard.DataSetReferenceProperty", _IResolvable_da3f097b]]]:
            '''Dataset references.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-dashboardsourcetemplate.html#cfn-quicksight-dashboard-dashboardsourcetemplate-datasetreferences
            '''
            result = self._values.get("data_set_references")
            assert result is not None, "Required property 'data_set_references' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDashboard.DataSetReferenceProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DashboardSourceTemplateProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboard.DataSetReferenceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "data_set_arn": "dataSetArn",
            "data_set_placeholder": "dataSetPlaceholder",
        },
    )
    class DataSetReferenceProperty:
        def __init__(
            self,
            *,
            data_set_arn: builtins.str,
            data_set_placeholder: builtins.str,
        ) -> None:
            '''Dataset reference.

            :param data_set_arn: Dataset Amazon Resource Name (ARN).
            :param data_set_placeholder: Dataset placeholder.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-datasetreference.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                data_set_reference_property = quicksight.CfnDashboard.DataSetReferenceProperty(
                    data_set_arn="dataSetArn",
                    data_set_placeholder="dataSetPlaceholder"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "data_set_arn": data_set_arn,
                "data_set_placeholder": data_set_placeholder,
            }

        @builtins.property
        def data_set_arn(self) -> builtins.str:
            '''Dataset Amazon Resource Name (ARN).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-datasetreference.html#cfn-quicksight-dashboard-datasetreference-datasetarn
            '''
            result = self._values.get("data_set_arn")
            assert result is not None, "Required property 'data_set_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def data_set_placeholder(self) -> builtins.str:
            '''Dataset placeholder.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-datasetreference.html#cfn-quicksight-dashboard-datasetreference-datasetplaceholder
            '''
            result = self._values.get("data_set_placeholder")
            assert result is not None, "Required property 'data_set_placeholder' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataSetReferenceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboard.DateTimeParameterProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "values": "values"},
    )
    class DateTimeParameterProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            values: typing.Sequence[builtins.str],
        ) -> None:
            '''A date-time parameter.

            :param name: A display name for the date-time parameter.
            :param values: The values for the date-time parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-datetimeparameter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                date_time_parameter_property = quicksight.CfnDashboard.DateTimeParameterProperty(
                    name="name",
                    values=["values"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "values": values,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''A display name for the date-time parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-datetimeparameter.html#cfn-quicksight-dashboard-datetimeparameter-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def values(self) -> typing.List[builtins.str]:
            '''The values for the date-time parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-datetimeparameter.html#cfn-quicksight-dashboard-datetimeparameter-values
            '''
            result = self._values.get("values")
            assert result is not None, "Required property 'values' is missing"
            return typing.cast(typing.List[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DateTimeParameterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboard.DecimalParameterProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "values": "values"},
    )
    class DecimalParameterProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            values: typing.Union[_IResolvable_da3f097b, typing.Sequence[jsii.Number]],
        ) -> None:
            '''A decimal parameter.

            :param name: A display name for the decimal parameter.
            :param values: The values for the decimal parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-decimalparameter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                decimal_parameter_property = quicksight.CfnDashboard.DecimalParameterProperty(
                    name="name",
                    values=[123]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "values": values,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''A display name for the decimal parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-decimalparameter.html#cfn-quicksight-dashboard-decimalparameter-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def values(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[jsii.Number]]:
            '''The values for the decimal parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-decimalparameter.html#cfn-quicksight-dashboard-decimalparameter-values
            '''
            result = self._values.get("values")
            assert result is not None, "Required property 'values' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[jsii.Number]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DecimalParameterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboard.ExportToCSVOptionProperty",
        jsii_struct_bases=[],
        name_mapping={"availability_status": "availabilityStatus"},
    )
    class ExportToCSVOptionProperty:
        def __init__(
            self,
            *,
            availability_status: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Export to .csv option.

            :param availability_status: Availability status.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-exporttocsvoption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                export_to_cSVOption_property = quicksight.CfnDashboard.ExportToCSVOptionProperty(
                    availability_status="availabilityStatus"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if availability_status is not None:
                self._values["availability_status"] = availability_status

        @builtins.property
        def availability_status(self) -> typing.Optional[builtins.str]:
            '''Availability status.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-exporttocsvoption.html#cfn-quicksight-dashboard-exporttocsvoption-availabilitystatus
            '''
            result = self._values.get("availability_status")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ExportToCSVOptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboard.IntegerParameterProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "values": "values"},
    )
    class IntegerParameterProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            values: typing.Union[_IResolvable_da3f097b, typing.Sequence[jsii.Number]],
        ) -> None:
            '''An integer parameter.

            :param name: The name of the integer parameter.
            :param values: The values for the integer parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-integerparameter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                integer_parameter_property = quicksight.CfnDashboard.IntegerParameterProperty(
                    name="name",
                    values=[123]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "values": values,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the integer parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-integerparameter.html#cfn-quicksight-dashboard-integerparameter-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def values(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[jsii.Number]]:
            '''The values for the integer parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-integerparameter.html#cfn-quicksight-dashboard-integerparameter-values
            '''
            result = self._values.get("values")
            assert result is not None, "Required property 'values' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[jsii.Number]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IntegerParameterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboard.ParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "date_time_parameters": "dateTimeParameters",
            "decimal_parameters": "decimalParameters",
            "integer_parameters": "integerParameters",
            "string_parameters": "stringParameters",
        },
    )
    class ParametersProperty:
        def __init__(
            self,
            *,
            date_time_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDashboard.DateTimeParameterProperty", _IResolvable_da3f097b]]]] = None,
            decimal_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDashboard.DecimalParameterProperty", _IResolvable_da3f097b]]]] = None,
            integer_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDashboard.IntegerParameterProperty", _IResolvable_da3f097b]]]] = None,
            string_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDashboard.StringParameterProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''A list of Amazon QuickSight parameters and the list's override values.

            :param date_time_parameters: The parameters that have a data type of date-time.
            :param decimal_parameters: The parameters that have a data type of decimal.
            :param integer_parameters: The parameters that have a data type of integer.
            :param string_parameters: The parameters that have a data type of string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-parameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                parameters_property = quicksight.CfnDashboard.ParametersProperty(
                    date_time_parameters=[quicksight.CfnDashboard.DateTimeParameterProperty(
                        name="name",
                        values=["values"]
                    )],
                    decimal_parameters=[quicksight.CfnDashboard.DecimalParameterProperty(
                        name="name",
                        values=[123]
                    )],
                    integer_parameters=[quicksight.CfnDashboard.IntegerParameterProperty(
                        name="name",
                        values=[123]
                    )],
                    string_parameters=[quicksight.CfnDashboard.StringParameterProperty(
                        name="name",
                        values=["values"]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if date_time_parameters is not None:
                self._values["date_time_parameters"] = date_time_parameters
            if decimal_parameters is not None:
                self._values["decimal_parameters"] = decimal_parameters
            if integer_parameters is not None:
                self._values["integer_parameters"] = integer_parameters
            if string_parameters is not None:
                self._values["string_parameters"] = string_parameters

        @builtins.property
        def date_time_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDashboard.DateTimeParameterProperty", _IResolvable_da3f097b]]]]:
            '''The parameters that have a data type of date-time.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-parameters.html#cfn-quicksight-dashboard-parameters-datetimeparameters
            '''
            result = self._values.get("date_time_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDashboard.DateTimeParameterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def decimal_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDashboard.DecimalParameterProperty", _IResolvable_da3f097b]]]]:
            '''The parameters that have a data type of decimal.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-parameters.html#cfn-quicksight-dashboard-parameters-decimalparameters
            '''
            result = self._values.get("decimal_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDashboard.DecimalParameterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def integer_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDashboard.IntegerParameterProperty", _IResolvable_da3f097b]]]]:
            '''The parameters that have a data type of integer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-parameters.html#cfn-quicksight-dashboard-parameters-integerparameters
            '''
            result = self._values.get("integer_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDashboard.IntegerParameterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def string_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDashboard.StringParameterProperty", _IResolvable_da3f097b]]]]:
            '''The parameters that have a data type of string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-parameters.html#cfn-quicksight-dashboard-parameters-stringparameters
            '''
            result = self._values.get("string_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDashboard.StringParameterProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboard.ResourcePermissionProperty",
        jsii_struct_bases=[],
        name_mapping={"actions": "actions", "principal": "principal"},
    )
    class ResourcePermissionProperty:
        def __init__(
            self,
            *,
            actions: typing.Sequence[builtins.str],
            principal: builtins.str,
        ) -> None:
            '''Permission for the resource.

            :param actions: The IAM action to grant or revoke permissions on.
            :param principal: The Amazon Resource Name (ARN) of the principal. This can be one of the following:. - The ARN of an Amazon QuickSight user or group associated with a data source or dataset. (This is common.) - The ARN of an Amazon QuickSight user, group, or namespace associated with an analysis, dashboard, template, or theme. (This is common.) - The ARN of an AWS account root: This is an IAM ARN rather than a Amazon QuickSight ARN. Use this option only to share resources (templates) across AWS accounts . (This is less common.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-resourcepermission.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                resource_permission_property = quicksight.CfnDashboard.ResourcePermissionProperty(
                    actions=["actions"],
                    principal="principal"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "actions": actions,
                "principal": principal,
            }

        @builtins.property
        def actions(self) -> typing.List[builtins.str]:
            '''The IAM action to grant or revoke permissions on.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-resourcepermission.html#cfn-quicksight-dashboard-resourcepermission-actions
            '''
            result = self._values.get("actions")
            assert result is not None, "Required property 'actions' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def principal(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the principal. This can be one of the following:.

            - The ARN of an Amazon QuickSight user or group associated with a data source or dataset. (This is common.)
            - The ARN of an Amazon QuickSight user, group, or namespace associated with an analysis, dashboard, template, or theme. (This is common.)
            - The ARN of an AWS account root: This is an IAM ARN rather than a Amazon QuickSight ARN. Use this option only to share resources (templates) across AWS accounts . (This is less common.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-resourcepermission.html#cfn-quicksight-dashboard-resourcepermission-principal
            '''
            result = self._values.get("principal")
            assert result is not None, "Required property 'principal' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourcePermissionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboard.SheetControlsOptionProperty",
        jsii_struct_bases=[],
        name_mapping={"visibility_state": "visibilityState"},
    )
    class SheetControlsOptionProperty:
        def __init__(
            self,
            *,
            visibility_state: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Sheet controls option.

            :param visibility_state: Visibility state.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-sheetcontrolsoption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                sheet_controls_option_property = quicksight.CfnDashboard.SheetControlsOptionProperty(
                    visibility_state="visibilityState"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if visibility_state is not None:
                self._values["visibility_state"] = visibility_state

        @builtins.property
        def visibility_state(self) -> typing.Optional[builtins.str]:
            '''Visibility state.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-sheetcontrolsoption.html#cfn-quicksight-dashboard-sheetcontrolsoption-visibilitystate
            '''
            result = self._values.get("visibility_state")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SheetControlsOptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboard.StringParameterProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "values": "values"},
    )
    class StringParameterProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            values: typing.Sequence[builtins.str],
        ) -> None:
            '''A string parameter.

            :param name: A display name for a string parameter.
            :param values: The values of a string parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-stringparameter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                string_parameter_property = quicksight.CfnDashboard.StringParameterProperty(
                    name="name",
                    values=["values"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "values": values,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''A display name for a string parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-stringparameter.html#cfn-quicksight-dashboard-stringparameter-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def values(self) -> typing.List[builtins.str]:
            '''The values of a string parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dashboard-stringparameter.html#cfn-quicksight-dashboard-stringparameter-values
            '''
            result = self._values.get("values")
            assert result is not None, "Required property 'values' is missing"
            return typing.cast(typing.List[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StringParameterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_quicksight.CfnDashboardProps",
    jsii_struct_bases=[],
    name_mapping={
        "aws_account_id": "awsAccountId",
        "dashboard_id": "dashboardId",
        "source_entity": "sourceEntity",
        "dashboard_publish_options": "dashboardPublishOptions",
        "name": "name",
        "parameters": "parameters",
        "permissions": "permissions",
        "tags": "tags",
        "theme_arn": "themeArn",
        "version_description": "versionDescription",
    },
)
class CfnDashboardProps:
    def __init__(
        self,
        *,
        aws_account_id: builtins.str,
        dashboard_id: builtins.str,
        source_entity: typing.Union[CfnDashboard.DashboardSourceEntityProperty, _IResolvable_da3f097b],
        dashboard_publish_options: typing.Optional[typing.Union[CfnDashboard.DashboardPublishOptionsProperty, _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        parameters: typing.Optional[typing.Union[CfnDashboard.ParametersProperty, _IResolvable_da3f097b]] = None,
        permissions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnDashboard.ResourcePermissionProperty, _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        theme_arn: typing.Optional[builtins.str] = None,
        version_description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnDashboard``.

        :param aws_account_id: The ID of the AWS account where you want to create the dashboard.
        :param dashboard_id: The ID for the dashboard, also added to the IAM policy.
        :param source_entity: The entity that you are using as a source when you create the dashboard. In ``SourceEntity`` , you specify the type of object that you want to use. You can only create a dashboard from a template, so you use a ``SourceTemplate`` entity. If you need to create a dashboard from an analysis, first convert the analysis to a template by using the ``CreateTemplate`` API operation. For ``SourceTemplate`` , specify the Amazon Resource Name (ARN) of the source template. The ``SourceTemplate`` ARN can contain any AWS account; and any QuickSight-supported AWS Region . Use the ``DataSetReferences`` entity within ``SourceTemplate`` to list the replacement datasets for the placeholders listed in the original. The schema in each dataset must match its placeholder.
        :param dashboard_publish_options: Options for publishing the dashboard when you create it:. - ``AvailabilityStatus`` for ``AdHocFilteringOption`` - This status can be either ``ENABLED`` or ``DISABLED`` . When this is set to ``DISABLED`` , Amazon QuickSight disables the left filter pane on the published dashboard, which can be used for ad hoc (one-time) filtering. This option is ``ENABLED`` by default. - ``AvailabilityStatus`` for ``ExportToCSVOption`` - This status can be either ``ENABLED`` or ``DISABLED`` . The visual option to export data to .CSV format isn't enabled when this is set to ``DISABLED`` . This option is ``ENABLED`` by default. - ``VisibilityState`` for ``SheetControlsOption`` - This visibility state can be either ``COLLAPSED`` or ``EXPANDED`` . This option is ``COLLAPSED`` by default.
        :param name: The display name of the dashboard.
        :param parameters: The parameters for the creation of the dashboard, which you want to use to override the default settings. A dashboard can have any type of parameters, and some parameters might accept multiple values.
        :param permissions: A structure that contains the permissions of the dashboard. You can use this structure for granting permissions by providing a list of IAM action information for each principal ARN. To specify no permissions, omit the permissions list.
        :param tags: Contains a map of the key-value pairs for the resource tag or tags assigned to the dashboard.
        :param theme_arn: The Amazon Resource Name (ARN) of the theme that is being used for this dashboard. If you add a value for this field, it overrides the value that is used in the source entity. The theme ARN must exist in the same AWS account where you create the dashboard.
        :param version_description: A description for the first version of the dashboard being created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_quicksight as quicksight
            
            cfn_dashboard_props = quicksight.CfnDashboardProps(
                aws_account_id="awsAccountId",
                dashboard_id="dashboardId",
                source_entity=quicksight.CfnDashboard.DashboardSourceEntityProperty(
                    source_template=quicksight.CfnDashboard.DashboardSourceTemplateProperty(
                        arn="arn",
                        data_set_references=[quicksight.CfnDashboard.DataSetReferenceProperty(
                            data_set_arn="dataSetArn",
                            data_set_placeholder="dataSetPlaceholder"
                        )]
                    )
                ),
            
                # the properties below are optional
                dashboard_publish_options=quicksight.CfnDashboard.DashboardPublishOptionsProperty(
                    ad_hoc_filtering_option=quicksight.CfnDashboard.AdHocFilteringOptionProperty(
                        availability_status="availabilityStatus"
                    ),
                    export_to_csv_option=quicksight.CfnDashboard.ExportToCSVOptionProperty(
                        availability_status="availabilityStatus"
                    ),
                    sheet_controls_option=quicksight.CfnDashboard.SheetControlsOptionProperty(
                        visibility_state="visibilityState"
                    )
                ),
                name="name",
                parameters=quicksight.CfnDashboard.ParametersProperty(
                    date_time_parameters=[quicksight.CfnDashboard.DateTimeParameterProperty(
                        name="name",
                        values=["values"]
                    )],
                    decimal_parameters=[quicksight.CfnDashboard.DecimalParameterProperty(
                        name="name",
                        values=[123]
                    )],
                    integer_parameters=[quicksight.CfnDashboard.IntegerParameterProperty(
                        name="name",
                        values=[123]
                    )],
                    string_parameters=[quicksight.CfnDashboard.StringParameterProperty(
                        name="name",
                        values=["values"]
                    )]
                ),
                permissions=[quicksight.CfnDashboard.ResourcePermissionProperty(
                    actions=["actions"],
                    principal="principal"
                )],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                theme_arn="themeArn",
                version_description="versionDescription"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "aws_account_id": aws_account_id,
            "dashboard_id": dashboard_id,
            "source_entity": source_entity,
        }
        if dashboard_publish_options is not None:
            self._values["dashboard_publish_options"] = dashboard_publish_options
        if name is not None:
            self._values["name"] = name
        if parameters is not None:
            self._values["parameters"] = parameters
        if permissions is not None:
            self._values["permissions"] = permissions
        if tags is not None:
            self._values["tags"] = tags
        if theme_arn is not None:
            self._values["theme_arn"] = theme_arn
        if version_description is not None:
            self._values["version_description"] = version_description

    @builtins.property
    def aws_account_id(self) -> builtins.str:
        '''The ID of the AWS account where you want to create the dashboard.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-awsaccountid
        '''
        result = self._values.get("aws_account_id")
        assert result is not None, "Required property 'aws_account_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def dashboard_id(self) -> builtins.str:
        '''The ID for the dashboard, also added to the IAM policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-dashboardid
        '''
        result = self._values.get("dashboard_id")
        assert result is not None, "Required property 'dashboard_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def source_entity(
        self,
    ) -> typing.Union[CfnDashboard.DashboardSourceEntityProperty, _IResolvable_da3f097b]:
        '''The entity that you are using as a source when you create the dashboard.

        In ``SourceEntity`` , you specify the type of object that you want to use. You can only create a dashboard from a template, so you use a ``SourceTemplate`` entity. If you need to create a dashboard from an analysis, first convert the analysis to a template by using the ``CreateTemplate`` API operation. For ``SourceTemplate`` , specify the Amazon Resource Name (ARN) of the source template. The ``SourceTemplate`` ARN can contain any AWS account; and any QuickSight-supported AWS Region .

        Use the ``DataSetReferences`` entity within ``SourceTemplate`` to list the replacement datasets for the placeholders listed in the original. The schema in each dataset must match its placeholder.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-sourceentity
        '''
        result = self._values.get("source_entity")
        assert result is not None, "Required property 'source_entity' is missing"
        return typing.cast(typing.Union[CfnDashboard.DashboardSourceEntityProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def dashboard_publish_options(
        self,
    ) -> typing.Optional[typing.Union[CfnDashboard.DashboardPublishOptionsProperty, _IResolvable_da3f097b]]:
        '''Options for publishing the dashboard when you create it:.

        - ``AvailabilityStatus`` for ``AdHocFilteringOption`` - This status can be either ``ENABLED`` or ``DISABLED`` . When this is set to ``DISABLED`` , Amazon QuickSight disables the left filter pane on the published dashboard, which can be used for ad hoc (one-time) filtering. This option is ``ENABLED`` by default.
        - ``AvailabilityStatus`` for ``ExportToCSVOption`` - This status can be either ``ENABLED`` or ``DISABLED`` . The visual option to export data to .CSV format isn't enabled when this is set to ``DISABLED`` . This option is ``ENABLED`` by default.
        - ``VisibilityState`` for ``SheetControlsOption`` - This visibility state can be either ``COLLAPSED`` or ``EXPANDED`` . This option is ``COLLAPSED`` by default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-dashboardpublishoptions
        '''
        result = self._values.get("dashboard_publish_options")
        return typing.cast(typing.Optional[typing.Union[CfnDashboard.DashboardPublishOptionsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The display name of the dashboard.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def parameters(
        self,
    ) -> typing.Optional[typing.Union[CfnDashboard.ParametersProperty, _IResolvable_da3f097b]]:
        '''The parameters for the creation of the dashboard, which you want to use to override the default settings.

        A dashboard can have any type of parameters, and some parameters might accept multiple values.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-parameters
        '''
        result = self._values.get("parameters")
        return typing.cast(typing.Optional[typing.Union[CfnDashboard.ParametersProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def permissions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDashboard.ResourcePermissionProperty, _IResolvable_da3f097b]]]]:
        '''A structure that contains the permissions of the dashboard.

        You can use this structure for granting permissions by providing a list of IAM action information for each principal ARN.

        To specify no permissions, omit the permissions list.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-permissions
        '''
        result = self._values.get("permissions")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDashboard.ResourcePermissionProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Contains a map of the key-value pairs for the resource tag or tags assigned to the dashboard.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def theme_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the theme that is being used for this dashboard.

        If you add a value for this field, it overrides the value that is used in the source entity. The theme ARN must exist in the same AWS account where you create the dashboard.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-themearn
        '''
        result = self._values.get("theme_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def version_description(self) -> typing.Optional[builtins.str]:
        '''A description for the first version of the dashboard being created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dashboard.html#cfn-quicksight-dashboard-versiondescription
        '''
        result = self._values.get("version_description")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDashboardProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDataSet(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet",
):
    '''A CloudFormation ``AWS::QuickSight::DataSet``.

    Creates a dataset. This operation doesn't support datasets that include uploaded files as a source.

    :cloudformationResource: AWS::QuickSight::DataSet
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_quicksight as quicksight
        
        cfn_data_set = quicksight.CfnDataSet(self, "MyCfnDataSet",
            aws_account_id="awsAccountId",
            column_groups=[quicksight.CfnDataSet.ColumnGroupProperty(
                geo_spatial_column_group=quicksight.CfnDataSet.GeoSpatialColumnGroupProperty(
                    columns=["columns"],
                    name="name",
        
                    # the properties below are optional
                    country_code="countryCode"
                )
            )],
            column_level_permission_rules=[quicksight.CfnDataSet.ColumnLevelPermissionRuleProperty(
                column_names=["columnNames"],
                principals=["principals"]
            )],
            data_set_id="dataSetId",
            field_folders={
                "field_folders_key": quicksight.CfnDataSet.FieldFolderProperty(
                    columns=["columns"],
                    description="description"
                )
            },
            import_mode="importMode",
            ingestion_wait_policy=quicksight.CfnDataSet.IngestionWaitPolicyProperty(
                ingestion_wait_time_in_hours=123,
                wait_for_spice_ingestion=False
            ),
            logical_table_map={
                "logical_table_map_key": quicksight.CfnDataSet.LogicalTableProperty(
                    alias="alias",
                    source=quicksight.CfnDataSet.LogicalTableSourceProperty(
                        join_instruction=quicksight.CfnDataSet.JoinInstructionProperty(
                            left_operand="leftOperand",
                            on_clause="onClause",
                            right_operand="rightOperand",
                            type="type",
        
                            # the properties below are optional
                            left_join_key_properties=quicksight.CfnDataSet.JoinKeyPropertiesProperty(
                                unique_key=False
                            ),
                            right_join_key_properties=quicksight.CfnDataSet.JoinKeyPropertiesProperty(
                                unique_key=False
                            )
                        ),
                        physical_table_id="physicalTableId"
                    ),
        
                    # the properties below are optional
                    data_transforms=[quicksight.CfnDataSet.TransformOperationProperty(
                        cast_column_type_operation=quicksight.CfnDataSet.CastColumnTypeOperationProperty(
                            column_name="columnName",
                            new_column_type="newColumnType",
        
                            # the properties below are optional
                            format="format"
                        ),
                        create_columns_operation=quicksight.CfnDataSet.CreateColumnsOperationProperty(
                            columns=[quicksight.CfnDataSet.CalculatedColumnProperty(
                                column_id="columnId",
                                column_name="columnName",
                                expression="expression"
                            )]
                        ),
                        filter_operation=quicksight.CfnDataSet.FilterOperationProperty(
                            condition_expression="conditionExpression"
                        ),
                        project_operation=quicksight.CfnDataSet.ProjectOperationProperty(
                            projected_columns=["projectedColumns"]
                        ),
                        rename_column_operation=quicksight.CfnDataSet.RenameColumnOperationProperty(
                            column_name="columnName",
                            new_column_name="newColumnName"
                        ),
                        tag_column_operation=quicksight.CfnDataSet.TagColumnOperationProperty(
                            column_name="columnName",
                            tags=[quicksight.CfnDataSet.ColumnTagProperty(
                                column_description=quicksight.CfnDataSet.ColumnDescriptionProperty(
                                    text="text"
                                ),
                                column_geographic_role="columnGeographicRole"
                            )]
                        )
                    )]
                )
            },
            name="name",
            permissions=[quicksight.CfnDataSet.ResourcePermissionProperty(
                actions=["actions"],
                principal="principal"
            )],
            physical_table_map={
                "physical_table_map_key": quicksight.CfnDataSet.PhysicalTableProperty(
                    custom_sql=quicksight.CfnDataSet.CustomSqlProperty(
                        columns=[quicksight.CfnDataSet.InputColumnProperty(
                            name="name",
                            type="type"
                        )],
                        data_source_arn="dataSourceArn",
                        name="name",
                        sql_query="sqlQuery"
                    ),
                    relational_table=quicksight.CfnDataSet.RelationalTableProperty(
                        data_source_arn="dataSourceArn",
                        input_columns=[quicksight.CfnDataSet.InputColumnProperty(
                            name="name",
                            type="type"
                        )],
                        name="name",
        
                        # the properties below are optional
                        catalog="catalog",
                        schema="schema"
                    ),
                    s3_source=quicksight.CfnDataSet.S3SourceProperty(
                        data_source_arn="dataSourceArn",
                        input_columns=[quicksight.CfnDataSet.InputColumnProperty(
                            name="name",
                            type="type"
                        )],
        
                        # the properties below are optional
                        upload_settings=quicksight.CfnDataSet.UploadSettingsProperty(
                            contains_header=False,
                            delimiter="delimiter",
                            format="format",
                            start_from_row=123,
                            text_qualifier="textQualifier"
                        )
                    )
                )
            },
            row_level_permission_data_set=quicksight.CfnDataSet.RowLevelPermissionDataSetProperty(
                arn="arn",
                permission_policy="permissionPolicy",
        
                # the properties below are optional
                format_version="formatVersion",
                namespace="namespace"
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
        aws_account_id: typing.Optional[builtins.str] = None,
        column_groups: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataSet.ColumnGroupProperty", _IResolvable_da3f097b]]]] = None,
        column_level_permission_rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataSet.ColumnLevelPermissionRuleProperty", _IResolvable_da3f097b]]]] = None,
        data_set_id: typing.Optional[builtins.str] = None,
        field_folders: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDataSet.FieldFolderProperty", _IResolvable_da3f097b]]]] = None,
        import_mode: typing.Optional[builtins.str] = None,
        ingestion_wait_policy: typing.Optional[typing.Union["CfnDataSet.IngestionWaitPolicyProperty", _IResolvable_da3f097b]] = None,
        logical_table_map: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDataSet.LogicalTableProperty", _IResolvable_da3f097b]]]] = None,
        name: typing.Optional[builtins.str] = None,
        permissions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataSet.ResourcePermissionProperty", _IResolvable_da3f097b]]]] = None,
        physical_table_map: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDataSet.PhysicalTableProperty", _IResolvable_da3f097b]]]] = None,
        row_level_permission_data_set: typing.Optional[typing.Union["CfnDataSet.RowLevelPermissionDataSetProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::QuickSight::DataSet``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param aws_account_id: The AWS account ID.
        :param column_groups: Groupings of columns that work together in certain Amazon QuickSight features. Currently, only geospatial hierarchy is supported.
        :param column_level_permission_rules: A set of one or more definitions of a ``ColumnLevelPermissionRule`` .
        :param data_set_id: An ID for the dataset that you want to create. This ID is unique per AWS Region for each AWS account.
        :param field_folders: The folder that contains fields and nested subfolders for your dataset.
        :param import_mode: Indicates whether you want to import the data into SPICE.
        :param ingestion_wait_policy: The wait policy to use when creating or updating a Dataset. The default is to wait for SPICE ingestion to finish with timeout of 36 hours.
        :param logical_table_map: Configures the combination and transformation of the data from the physical tables.
        :param name: The display name for the dataset.
        :param permissions: A list of resource permissions on the dataset.
        :param physical_table_map: Declares the physical tables that are available in the underlying data sources.
        :param row_level_permission_data_set: The row-level security configuration for the data that you want to create.
        :param tags: Contains a map of the key-value pairs for the resource tag or tags assigned to the dataset.
        '''
        props = CfnDataSetProps(
            aws_account_id=aws_account_id,
            column_groups=column_groups,
            column_level_permission_rules=column_level_permission_rules,
            data_set_id=data_set_id,
            field_folders=field_folders,
            import_mode=import_mode,
            ingestion_wait_policy=ingestion_wait_policy,
            logical_table_map=logical_table_map,
            name=name,
            permissions=permissions,
            physical_table_map=physical_table_map,
            row_level_permission_data_set=row_level_permission_data_set,
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
        '''The Amazon Resource Name (ARN) of the dataset.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrConsumedSpiceCapacityInBytes")
    def attr_consumed_spice_capacity_in_bytes(self) -> _IResolvable_da3f097b:
        '''
        :cloudformationAttribute: ConsumedSpiceCapacityInBytes
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrConsumedSpiceCapacityInBytes"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCreatedTime")
    def attr_created_time(self) -> builtins.str:
        '''The time this dataset version was created.

        :cloudformationAttribute: CreatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLastUpdatedTime")
    def attr_last_updated_time(self) -> builtins.str:
        '''The time this dataset version was last updated.

        :cloudformationAttribute: LastUpdatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLastUpdatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrOutputColumns")
    def attr_output_columns(self) -> _IResolvable_da3f097b:
        '''
        :cloudformationAttribute: OutputColumns
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrOutputColumns"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Contains a map of the key-value pairs for the resource tag or tags assigned to the dataset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="awsAccountId")
    def aws_account_id(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-awsaccountid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "awsAccountId"))

    @aws_account_id.setter
    def aws_account_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "awsAccountId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="columnGroups")
    def column_groups(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.ColumnGroupProperty", _IResolvable_da3f097b]]]]:
        '''Groupings of columns that work together in certain Amazon QuickSight features.

        Currently, only geospatial hierarchy is supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-columngroups
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.ColumnGroupProperty", _IResolvable_da3f097b]]]], jsii.get(self, "columnGroups"))

    @column_groups.setter
    def column_groups(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.ColumnGroupProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "columnGroups", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="columnLevelPermissionRules")
    def column_level_permission_rules(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.ColumnLevelPermissionRuleProperty", _IResolvable_da3f097b]]]]:
        '''A set of one or more definitions of a ``ColumnLevelPermissionRule`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-columnlevelpermissionrules
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.ColumnLevelPermissionRuleProperty", _IResolvable_da3f097b]]]], jsii.get(self, "columnLevelPermissionRules"))

    @column_level_permission_rules.setter
    def column_level_permission_rules(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.ColumnLevelPermissionRuleProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "columnLevelPermissionRules", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dataSetId")
    def data_set_id(self) -> typing.Optional[builtins.str]:
        '''An ID for the dataset that you want to create.

        This ID is unique per AWS Region for each AWS account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-datasetid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "dataSetId"))

    @data_set_id.setter
    def data_set_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "dataSetId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fieldFolders")
    def field_folders(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDataSet.FieldFolderProperty", _IResolvable_da3f097b]]]]:
        '''The folder that contains fields and nested subfolders for your dataset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-fieldfolders
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDataSet.FieldFolderProperty", _IResolvable_da3f097b]]]], jsii.get(self, "fieldFolders"))

    @field_folders.setter
    def field_folders(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDataSet.FieldFolderProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "fieldFolders", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="importMode")
    def import_mode(self) -> typing.Optional[builtins.str]:
        '''Indicates whether you want to import the data into SPICE.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-importmode
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "importMode"))

    @import_mode.setter
    def import_mode(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "importMode", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ingestionWaitPolicy")
    def ingestion_wait_policy(
        self,
    ) -> typing.Optional[typing.Union["CfnDataSet.IngestionWaitPolicyProperty", _IResolvable_da3f097b]]:
        '''The wait policy to use when creating or updating a Dataset.

        The default is to wait for SPICE ingestion to finish with timeout of 36 hours.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-ingestionwaitpolicy
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDataSet.IngestionWaitPolicyProperty", _IResolvable_da3f097b]], jsii.get(self, "ingestionWaitPolicy"))

    @ingestion_wait_policy.setter
    def ingestion_wait_policy(
        self,
        value: typing.Optional[typing.Union["CfnDataSet.IngestionWaitPolicyProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "ingestionWaitPolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logicalTableMap")
    def logical_table_map(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDataSet.LogicalTableProperty", _IResolvable_da3f097b]]]]:
        '''Configures the combination and transformation of the data from the physical tables.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-logicaltablemap
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDataSet.LogicalTableProperty", _IResolvable_da3f097b]]]], jsii.get(self, "logicalTableMap"))

    @logical_table_map.setter
    def logical_table_map(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDataSet.LogicalTableProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "logicalTableMap", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The display name for the dataset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="permissions")
    def permissions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.ResourcePermissionProperty", _IResolvable_da3f097b]]]]:
        '''A list of resource permissions on the dataset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-permissions
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.ResourcePermissionProperty", _IResolvable_da3f097b]]]], jsii.get(self, "permissions"))

    @permissions.setter
    def permissions(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.ResourcePermissionProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "permissions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="physicalTableMap")
    def physical_table_map(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDataSet.PhysicalTableProperty", _IResolvable_da3f097b]]]]:
        '''Declares the physical tables that are available in the underlying data sources.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-physicaltablemap
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDataSet.PhysicalTableProperty", _IResolvable_da3f097b]]]], jsii.get(self, "physicalTableMap"))

    @physical_table_map.setter
    def physical_table_map(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDataSet.PhysicalTableProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "physicalTableMap", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="rowLevelPermissionDataSet")
    def row_level_permission_data_set(
        self,
    ) -> typing.Optional[typing.Union["CfnDataSet.RowLevelPermissionDataSetProperty", _IResolvable_da3f097b]]:
        '''The row-level security configuration for the data that you want to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-rowlevelpermissiondataset
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDataSet.RowLevelPermissionDataSetProperty", _IResolvable_da3f097b]], jsii.get(self, "rowLevelPermissionDataSet"))

    @row_level_permission_data_set.setter
    def row_level_permission_data_set(
        self,
        value: typing.Optional[typing.Union["CfnDataSet.RowLevelPermissionDataSetProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "rowLevelPermissionDataSet", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.CalculatedColumnProperty",
        jsii_struct_bases=[],
        name_mapping={
            "column_id": "columnId",
            "column_name": "columnName",
            "expression": "expression",
        },
    )
    class CalculatedColumnProperty:
        def __init__(
            self,
            *,
            column_id: builtins.str,
            column_name: builtins.str,
            expression: builtins.str,
        ) -> None:
            '''A calculated column for a dataset.

            :param column_id: A unique ID to identify a calculated column. During a dataset update, if the column ID of a calculated column matches that of an existing calculated column, Amazon QuickSight preserves the existing calculated column.
            :param column_name: Column name.
            :param expression: An expression that defines the calculated column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-calculatedcolumn.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                calculated_column_property = quicksight.CfnDataSet.CalculatedColumnProperty(
                    column_id="columnId",
                    column_name="columnName",
                    expression="expression"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "column_id": column_id,
                "column_name": column_name,
                "expression": expression,
            }

        @builtins.property
        def column_id(self) -> builtins.str:
            '''A unique ID to identify a calculated column.

            During a dataset update, if the column ID of a calculated column matches that of an existing calculated column, Amazon QuickSight preserves the existing calculated column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-calculatedcolumn.html#cfn-quicksight-dataset-calculatedcolumn-columnid
            '''
            result = self._values.get("column_id")
            assert result is not None, "Required property 'column_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def column_name(self) -> builtins.str:
            '''Column name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-calculatedcolumn.html#cfn-quicksight-dataset-calculatedcolumn-columnname
            '''
            result = self._values.get("column_name")
            assert result is not None, "Required property 'column_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def expression(self) -> builtins.str:
            '''An expression that defines the calculated column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-calculatedcolumn.html#cfn-quicksight-dataset-calculatedcolumn-expression
            '''
            result = self._values.get("expression")
            assert result is not None, "Required property 'expression' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CalculatedColumnProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.CastColumnTypeOperationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "column_name": "columnName",
            "new_column_type": "newColumnType",
            "format": "format",
        },
    )
    class CastColumnTypeOperationProperty:
        def __init__(
            self,
            *,
            column_name: builtins.str,
            new_column_type: builtins.str,
            format: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A transform operation that casts a column to a different type.

            :param column_name: Column name.
            :param new_column_type: New column data type.
            :param format: When casting a column from string to datetime type, you can supply a string in a format supported by Amazon QuickSight to denote the source data format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-castcolumntypeoperation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                cast_column_type_operation_property = quicksight.CfnDataSet.CastColumnTypeOperationProperty(
                    column_name="columnName",
                    new_column_type="newColumnType",
                
                    # the properties below are optional
                    format="format"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "column_name": column_name,
                "new_column_type": new_column_type,
            }
            if format is not None:
                self._values["format"] = format

        @builtins.property
        def column_name(self) -> builtins.str:
            '''Column name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-castcolumntypeoperation.html#cfn-quicksight-dataset-castcolumntypeoperation-columnname
            '''
            result = self._values.get("column_name")
            assert result is not None, "Required property 'column_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def new_column_type(self) -> builtins.str:
            '''New column data type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-castcolumntypeoperation.html#cfn-quicksight-dataset-castcolumntypeoperation-newcolumntype
            '''
            result = self._values.get("new_column_type")
            assert result is not None, "Required property 'new_column_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def format(self) -> typing.Optional[builtins.str]:
            '''When casting a column from string to datetime type, you can supply a string in a format supported by Amazon QuickSight to denote the source data format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-castcolumntypeoperation.html#cfn-quicksight-dataset-castcolumntypeoperation-format
            '''
            result = self._values.get("format")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CastColumnTypeOperationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.ColumnDescriptionProperty",
        jsii_struct_bases=[],
        name_mapping={"text": "text"},
    )
    class ColumnDescriptionProperty:
        def __init__(self, *, text: typing.Optional[builtins.str] = None) -> None:
            '''Metadata that contains a description for a column.

            :param text: The text of a description for a column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-columndescription.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                column_description_property = quicksight.CfnDataSet.ColumnDescriptionProperty(
                    text="text"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if text is not None:
                self._values["text"] = text

        @builtins.property
        def text(self) -> typing.Optional[builtins.str]:
            '''The text of a description for a column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-columndescription.html#cfn-quicksight-dataset-columndescription-text
            '''
            result = self._values.get("text")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ColumnDescriptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.ColumnGroupProperty",
        jsii_struct_bases=[],
        name_mapping={"geo_spatial_column_group": "geoSpatialColumnGroup"},
    )
    class ColumnGroupProperty:
        def __init__(
            self,
            *,
            geo_spatial_column_group: typing.Optional[typing.Union["CfnDataSet.GeoSpatialColumnGroupProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Groupings of columns that work together in certain Amazon QuickSight features.

            This is a variant type structure. For this structure to be valid, only one of the attributes can be non-null.

            :param geo_spatial_column_group: Geospatial column group that denotes a hierarchy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-columngroup.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                column_group_property = quicksight.CfnDataSet.ColumnGroupProperty(
                    geo_spatial_column_group=quicksight.CfnDataSet.GeoSpatialColumnGroupProperty(
                        columns=["columns"],
                        name="name",
                
                        # the properties below are optional
                        country_code="countryCode"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if geo_spatial_column_group is not None:
                self._values["geo_spatial_column_group"] = geo_spatial_column_group

        @builtins.property
        def geo_spatial_column_group(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.GeoSpatialColumnGroupProperty", _IResolvable_da3f097b]]:
            '''Geospatial column group that denotes a hierarchy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-columngroup.html#cfn-quicksight-dataset-columngroup-geospatialcolumngroup
            '''
            result = self._values.get("geo_spatial_column_group")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.GeoSpatialColumnGroupProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ColumnGroupProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.ColumnLevelPermissionRuleProperty",
        jsii_struct_bases=[],
        name_mapping={"column_names": "columnNames", "principals": "principals"},
    )
    class ColumnLevelPermissionRuleProperty:
        def __init__(
            self,
            *,
            column_names: typing.Optional[typing.Sequence[builtins.str]] = None,
            principals: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''A rule defined to grant access on one or more restricted columns.

            Each dataset can have multiple rules. To create a restricted column, you add it to one or more rules. Each rule must contain at least one column and at least one user or group. To be able to see a restricted column, a user or group needs to be added to a rule for that column.

            :param column_names: An array of column names.
            :param principals: An array of Amazon Resource Names (ARNs) for Amazon QuickSight users or groups.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-columnlevelpermissionrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                column_level_permission_rule_property = quicksight.CfnDataSet.ColumnLevelPermissionRuleProperty(
                    column_names=["columnNames"],
                    principals=["principals"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if column_names is not None:
                self._values["column_names"] = column_names
            if principals is not None:
                self._values["principals"] = principals

        @builtins.property
        def column_names(self) -> typing.Optional[typing.List[builtins.str]]:
            '''An array of column names.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-columnlevelpermissionrule.html#cfn-quicksight-dataset-columnlevelpermissionrule-columnnames
            '''
            result = self._values.get("column_names")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def principals(self) -> typing.Optional[typing.List[builtins.str]]:
            '''An array of Amazon Resource Names (ARNs) for Amazon QuickSight users or groups.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-columnlevelpermissionrule.html#cfn-quicksight-dataset-columnlevelpermissionrule-principals
            '''
            result = self._values.get("principals")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ColumnLevelPermissionRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.ColumnTagProperty",
        jsii_struct_bases=[],
        name_mapping={
            "column_description": "columnDescription",
            "column_geographic_role": "columnGeographicRole",
        },
    )
    class ColumnTagProperty:
        def __init__(
            self,
            *,
            column_description: typing.Optional[typing.Union["CfnDataSet.ColumnDescriptionProperty", _IResolvable_da3f097b]] = None,
            column_geographic_role: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A tag for a column in a ``[TagColumnOperation](https://docs.aws.amazon.com/quicksight/latest/APIReference/API_TagColumnOperation.html)`` structure. This is a variant type structure. For this structure to be valid, only one of the attributes can be non-null.

            :param column_description: A description for a column.
            :param column_geographic_role: A geospatial role for a column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-columntag.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                column_tag_property = quicksight.CfnDataSet.ColumnTagProperty(
                    column_description=quicksight.CfnDataSet.ColumnDescriptionProperty(
                        text="text"
                    ),
                    column_geographic_role="columnGeographicRole"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if column_description is not None:
                self._values["column_description"] = column_description
            if column_geographic_role is not None:
                self._values["column_geographic_role"] = column_geographic_role

        @builtins.property
        def column_description(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.ColumnDescriptionProperty", _IResolvable_da3f097b]]:
            '''A description for a column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-columntag.html#cfn-quicksight-dataset-columntag-columndescription
            '''
            result = self._values.get("column_description")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.ColumnDescriptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def column_geographic_role(self) -> typing.Optional[builtins.str]:
            '''A geospatial role for a column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-columntag.html#cfn-quicksight-dataset-columntag-columngeographicrole
            '''
            result = self._values.get("column_geographic_role")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ColumnTagProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.CreateColumnsOperationProperty",
        jsii_struct_bases=[],
        name_mapping={"columns": "columns"},
    )
    class CreateColumnsOperationProperty:
        def __init__(
            self,
            *,
            columns: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataSet.CalculatedColumnProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A transform operation that creates calculated columns.

            Columns created in one such operation form a lexical closure.

            :param columns: Calculated columns to create.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-createcolumnsoperation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                create_columns_operation_property = quicksight.CfnDataSet.CreateColumnsOperationProperty(
                    columns=[quicksight.CfnDataSet.CalculatedColumnProperty(
                        column_id="columnId",
                        column_name="columnName",
                        expression="expression"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "columns": columns,
            }

        @builtins.property
        def columns(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.CalculatedColumnProperty", _IResolvable_da3f097b]]]:
            '''Calculated columns to create.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-createcolumnsoperation.html#cfn-quicksight-dataset-createcolumnsoperation-columns
            '''
            result = self._values.get("columns")
            assert result is not None, "Required property 'columns' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.CalculatedColumnProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CreateColumnsOperationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.CustomSqlProperty",
        jsii_struct_bases=[],
        name_mapping={
            "columns": "columns",
            "data_source_arn": "dataSourceArn",
            "name": "name",
            "sql_query": "sqlQuery",
        },
    )
    class CustomSqlProperty:
        def __init__(
            self,
            *,
            columns: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataSet.InputColumnProperty", _IResolvable_da3f097b]]],
            data_source_arn: builtins.str,
            name: builtins.str,
            sql_query: builtins.str,
        ) -> None:
            '''A physical table type built from the results of the custom SQL query.

            :param columns: The column schema from the SQL query result set.
            :param data_source_arn: The Amazon Resource Name (ARN) of the data source.
            :param name: A display name for the SQL query result.
            :param sql_query: The SQL query.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-customsql.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                custom_sql_property = quicksight.CfnDataSet.CustomSqlProperty(
                    columns=[quicksight.CfnDataSet.InputColumnProperty(
                        name="name",
                        type="type"
                    )],
                    data_source_arn="dataSourceArn",
                    name="name",
                    sql_query="sqlQuery"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "columns": columns,
                "data_source_arn": data_source_arn,
                "name": name,
                "sql_query": sql_query,
            }

        @builtins.property
        def columns(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.InputColumnProperty", _IResolvable_da3f097b]]]:
            '''The column schema from the SQL query result set.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-customsql.html#cfn-quicksight-dataset-customsql-columns
            '''
            result = self._values.get("columns")
            assert result is not None, "Required property 'columns' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.InputColumnProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def data_source_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the data source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-customsql.html#cfn-quicksight-dataset-customsql-datasourcearn
            '''
            result = self._values.get("data_source_arn")
            assert result is not None, "Required property 'data_source_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def name(self) -> builtins.str:
            '''A display name for the SQL query result.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-customsql.html#cfn-quicksight-dataset-customsql-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def sql_query(self) -> builtins.str:
            '''The SQL query.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-customsql.html#cfn-quicksight-dataset-customsql-sqlquery
            '''
            result = self._values.get("sql_query")
            assert result is not None, "Required property 'sql_query' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomSqlProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.FieldFolderProperty",
        jsii_struct_bases=[],
        name_mapping={"columns": "columns", "description": "description"},
    )
    class FieldFolderProperty:
        def __init__(
            self,
            *,
            columns: typing.Optional[typing.Sequence[builtins.str]] = None,
            description: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A FieldFolder element is a folder that contains fields and nested subfolders.

            :param columns: A folder has a list of columns. A column can only be in one folder.
            :param description: The description for a field folder.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-fieldfolder.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                field_folder_property = quicksight.CfnDataSet.FieldFolderProperty(
                    columns=["columns"],
                    description="description"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if columns is not None:
                self._values["columns"] = columns
            if description is not None:
                self._values["description"] = description

        @builtins.property
        def columns(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A folder has a list of columns.

            A column can only be in one folder.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-fieldfolder.html#cfn-quicksight-dataset-fieldfolder-columns
            '''
            result = self._values.get("columns")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def description(self) -> typing.Optional[builtins.str]:
            '''The description for a field folder.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-fieldfolder.html#cfn-quicksight-dataset-fieldfolder-description
            '''
            result = self._values.get("description")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FieldFolderProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.FilterOperationProperty",
        jsii_struct_bases=[],
        name_mapping={"condition_expression": "conditionExpression"},
    )
    class FilterOperationProperty:
        def __init__(self, *, condition_expression: builtins.str) -> None:
            '''A transform operation that filters rows based on a condition.

            :param condition_expression: An expression that must evaluate to a Boolean value. Rows for which the expression evaluates to true are kept in the dataset.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-filteroperation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                filter_operation_property = quicksight.CfnDataSet.FilterOperationProperty(
                    condition_expression="conditionExpression"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "condition_expression": condition_expression,
            }

        @builtins.property
        def condition_expression(self) -> builtins.str:
            '''An expression that must evaluate to a Boolean value.

            Rows for which the expression evaluates to true are kept in the dataset.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-filteroperation.html#cfn-quicksight-dataset-filteroperation-conditionexpression
            '''
            result = self._values.get("condition_expression")
            assert result is not None, "Required property 'condition_expression' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FilterOperationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.GeoSpatialColumnGroupProperty",
        jsii_struct_bases=[],
        name_mapping={
            "columns": "columns",
            "name": "name",
            "country_code": "countryCode",
        },
    )
    class GeoSpatialColumnGroupProperty:
        def __init__(
            self,
            *,
            columns: typing.Sequence[builtins.str],
            name: builtins.str,
            country_code: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Geospatial column group that denotes a hierarchy.

            :param columns: Columns in this hierarchy.
            :param name: A display name for the hierarchy.
            :param country_code: Country code.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-geospatialcolumngroup.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                geo_spatial_column_group_property = quicksight.CfnDataSet.GeoSpatialColumnGroupProperty(
                    columns=["columns"],
                    name="name",
                
                    # the properties below are optional
                    country_code="countryCode"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "columns": columns,
                "name": name,
            }
            if country_code is not None:
                self._values["country_code"] = country_code

        @builtins.property
        def columns(self) -> typing.List[builtins.str]:
            '''Columns in this hierarchy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-geospatialcolumngroup.html#cfn-quicksight-dataset-geospatialcolumngroup-columns
            '''
            result = self._values.get("columns")
            assert result is not None, "Required property 'columns' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def name(self) -> builtins.str:
            '''A display name for the hierarchy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-geospatialcolumngroup.html#cfn-quicksight-dataset-geospatialcolumngroup-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def country_code(self) -> typing.Optional[builtins.str]:
            '''Country code.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-geospatialcolumngroup.html#cfn-quicksight-dataset-geospatialcolumngroup-countrycode
            '''
            result = self._values.get("country_code")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GeoSpatialColumnGroupProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.IngestionWaitPolicyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "ingestion_wait_time_in_hours": "ingestionWaitTimeInHours",
            "wait_for_spice_ingestion": "waitForSpiceIngestion",
        },
    )
    class IngestionWaitPolicyProperty:
        def __init__(
            self,
            *,
            ingestion_wait_time_in_hours: typing.Optional[jsii.Number] = None,
            wait_for_spice_ingestion: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The wait policy to use when creating or updating a Dataset.

            The default is to wait for SPICE ingestion to finish with timeout of 36 hours.

            :param ingestion_wait_time_in_hours: The maximum time (in hours) to wait for Ingestion to complete. Default timeout is 36 hours. Applicable only when ``DataSetImportMode`` mode is set to SPICE and ``WaitForSpiceIngestion`` is set to true.
            :param wait_for_spice_ingestion: Wait for SPICE ingestion to finish to mark dataset creation or update as successful. Default (true). Applicable only when ``DataSetImportMode`` mode is set to SPICE.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-ingestionwaitpolicy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                ingestion_wait_policy_property = quicksight.CfnDataSet.IngestionWaitPolicyProperty(
                    ingestion_wait_time_in_hours=123,
                    wait_for_spice_ingestion=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if ingestion_wait_time_in_hours is not None:
                self._values["ingestion_wait_time_in_hours"] = ingestion_wait_time_in_hours
            if wait_for_spice_ingestion is not None:
                self._values["wait_for_spice_ingestion"] = wait_for_spice_ingestion

        @builtins.property
        def ingestion_wait_time_in_hours(self) -> typing.Optional[jsii.Number]:
            '''The maximum time (in hours) to wait for Ingestion to complete.

            Default timeout is 36 hours. Applicable only when ``DataSetImportMode`` mode is set to SPICE and ``WaitForSpiceIngestion`` is set to true.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-ingestionwaitpolicy.html#cfn-quicksight-dataset-ingestionwaitpolicy-ingestionwaittimeinhours
            '''
            result = self._values.get("ingestion_wait_time_in_hours")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def wait_for_spice_ingestion(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Wait for SPICE ingestion to finish to mark dataset creation or update as successful.

            Default (true). Applicable only when ``DataSetImportMode`` mode is set to SPICE.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-ingestionwaitpolicy.html#cfn-quicksight-dataset-ingestionwaitpolicy-waitforspiceingestion
            '''
            result = self._values.get("wait_for_spice_ingestion")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IngestionWaitPolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.InputColumnProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "type": "type"},
    )
    class InputColumnProperty:
        def __init__(self, *, name: builtins.str, type: builtins.str) -> None:
            '''Metadata for a column that is used as the input of a transform operation.

            :param name: The name of this column in the underlying data source.
            :param type: The data type of the column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-inputcolumn.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                input_column_property = quicksight.CfnDataSet.InputColumnProperty(
                    name="name",
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "type": type,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of this column in the underlying data source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-inputcolumn.html#cfn-quicksight-dataset-inputcolumn-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def type(self) -> builtins.str:
            '''The data type of the column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-inputcolumn.html#cfn-quicksight-dataset-inputcolumn-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InputColumnProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.JoinInstructionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "left_operand": "leftOperand",
            "on_clause": "onClause",
            "right_operand": "rightOperand",
            "type": "type",
            "left_join_key_properties": "leftJoinKeyProperties",
            "right_join_key_properties": "rightJoinKeyProperties",
        },
    )
    class JoinInstructionProperty:
        def __init__(
            self,
            *,
            left_operand: builtins.str,
            on_clause: builtins.str,
            right_operand: builtins.str,
            type: builtins.str,
            left_join_key_properties: typing.Optional[typing.Union["CfnDataSet.JoinKeyPropertiesProperty", _IResolvable_da3f097b]] = None,
            right_join_key_properties: typing.Optional[typing.Union["CfnDataSet.JoinKeyPropertiesProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The instructions associated with a join.

            :param left_operand: The operand on the left side of a join.
            :param on_clause: The join instructions provided in the ``ON`` clause of a join.
            :param right_operand: The operand on the right side of a join.
            :param type: The type of join that it is.
            :param left_join_key_properties: Join key properties of the left operand.
            :param right_join_key_properties: Join key properties of the right operand.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-joininstruction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                join_instruction_property = quicksight.CfnDataSet.JoinInstructionProperty(
                    left_operand="leftOperand",
                    on_clause="onClause",
                    right_operand="rightOperand",
                    type="type",
                
                    # the properties below are optional
                    left_join_key_properties=quicksight.CfnDataSet.JoinKeyPropertiesProperty(
                        unique_key=False
                    ),
                    right_join_key_properties=quicksight.CfnDataSet.JoinKeyPropertiesProperty(
                        unique_key=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "left_operand": left_operand,
                "on_clause": on_clause,
                "right_operand": right_operand,
                "type": type,
            }
            if left_join_key_properties is not None:
                self._values["left_join_key_properties"] = left_join_key_properties
            if right_join_key_properties is not None:
                self._values["right_join_key_properties"] = right_join_key_properties

        @builtins.property
        def left_operand(self) -> builtins.str:
            '''The operand on the left side of a join.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-joininstruction.html#cfn-quicksight-dataset-joininstruction-leftoperand
            '''
            result = self._values.get("left_operand")
            assert result is not None, "Required property 'left_operand' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def on_clause(self) -> builtins.str:
            '''The join instructions provided in the ``ON`` clause of a join.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-joininstruction.html#cfn-quicksight-dataset-joininstruction-onclause
            '''
            result = self._values.get("on_clause")
            assert result is not None, "Required property 'on_clause' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def right_operand(self) -> builtins.str:
            '''The operand on the right side of a join.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-joininstruction.html#cfn-quicksight-dataset-joininstruction-rightoperand
            '''
            result = self._values.get("right_operand")
            assert result is not None, "Required property 'right_operand' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def type(self) -> builtins.str:
            '''The type of join that it is.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-joininstruction.html#cfn-quicksight-dataset-joininstruction-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def left_join_key_properties(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.JoinKeyPropertiesProperty", _IResolvable_da3f097b]]:
            '''Join key properties of the left operand.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-joininstruction.html#cfn-quicksight-dataset-joininstruction-leftjoinkeyproperties
            '''
            result = self._values.get("left_join_key_properties")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.JoinKeyPropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def right_join_key_properties(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.JoinKeyPropertiesProperty", _IResolvable_da3f097b]]:
            '''Join key properties of the right operand.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-joininstruction.html#cfn-quicksight-dataset-joininstruction-rightjoinkeyproperties
            '''
            result = self._values.get("right_join_key_properties")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.JoinKeyPropertiesProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "JoinInstructionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.JoinKeyPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"unique_key": "uniqueKey"},
    )
    class JoinKeyPropertiesProperty:
        def __init__(
            self,
            *,
            unique_key: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Properties associated with the columns participating in a join.

            :param unique_key: A value that indicates that a row in a table is uniquely identified by the columns in a join key. This is used by Amazon QuickSight to optimize query performance.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-joinkeyproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                join_key_properties_property = quicksight.CfnDataSet.JoinKeyPropertiesProperty(
                    unique_key=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if unique_key is not None:
                self._values["unique_key"] = unique_key

        @builtins.property
        def unique_key(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''A value that indicates that a row in a table is uniquely identified by the columns in a join key.

            This is used by Amazon QuickSight to optimize query performance.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-joinkeyproperties.html#cfn-quicksight-dataset-joinkeyproperties-uniquekey
            '''
            result = self._values.get("unique_key")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "JoinKeyPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.LogicalTableProperty",
        jsii_struct_bases=[],
        name_mapping={
            "alias": "alias",
            "source": "source",
            "data_transforms": "dataTransforms",
        },
    )
    class LogicalTableProperty:
        def __init__(
            self,
            *,
            alias: builtins.str,
            source: typing.Union["CfnDataSet.LogicalTableSourceProperty", _IResolvable_da3f097b],
            data_transforms: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataSet.TransformOperationProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''A *logical table* is a unit that joins and that data transformations operate on.

            A logical table has a source, which can be either a physical table or result of a join. When a logical table points to a physical table, the logical table acts as a mutable copy of that physical table through transform operations.

            :param alias: A display name for the logical table.
            :param source: Source of this logical table.
            :param data_transforms: Transform operations that act on this logical table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-logicaltable.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                logical_table_property = quicksight.CfnDataSet.LogicalTableProperty(
                    alias="alias",
                    source=quicksight.CfnDataSet.LogicalTableSourceProperty(
                        join_instruction=quicksight.CfnDataSet.JoinInstructionProperty(
                            left_operand="leftOperand",
                            on_clause="onClause",
                            right_operand="rightOperand",
                            type="type",
                
                            # the properties below are optional
                            left_join_key_properties=quicksight.CfnDataSet.JoinKeyPropertiesProperty(
                                unique_key=False
                            ),
                            right_join_key_properties=quicksight.CfnDataSet.JoinKeyPropertiesProperty(
                                unique_key=False
                            )
                        ),
                        physical_table_id="physicalTableId"
                    ),
                
                    # the properties below are optional
                    data_transforms=[quicksight.CfnDataSet.TransformOperationProperty(
                        cast_column_type_operation=quicksight.CfnDataSet.CastColumnTypeOperationProperty(
                            column_name="columnName",
                            new_column_type="newColumnType",
                
                            # the properties below are optional
                            format="format"
                        ),
                        create_columns_operation=quicksight.CfnDataSet.CreateColumnsOperationProperty(
                            columns=[quicksight.CfnDataSet.CalculatedColumnProperty(
                                column_id="columnId",
                                column_name="columnName",
                                expression="expression"
                            )]
                        ),
                        filter_operation=quicksight.CfnDataSet.FilterOperationProperty(
                            condition_expression="conditionExpression"
                        ),
                        project_operation=quicksight.CfnDataSet.ProjectOperationProperty(
                            projected_columns=["projectedColumns"]
                        ),
                        rename_column_operation=quicksight.CfnDataSet.RenameColumnOperationProperty(
                            column_name="columnName",
                            new_column_name="newColumnName"
                        ),
                        tag_column_operation=quicksight.CfnDataSet.TagColumnOperationProperty(
                            column_name="columnName",
                            tags=[quicksight.CfnDataSet.ColumnTagProperty(
                                column_description=quicksight.CfnDataSet.ColumnDescriptionProperty(
                                    text="text"
                                ),
                                column_geographic_role="columnGeographicRole"
                            )]
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "alias": alias,
                "source": source,
            }
            if data_transforms is not None:
                self._values["data_transforms"] = data_transforms

        @builtins.property
        def alias(self) -> builtins.str:
            '''A display name for the logical table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-logicaltable.html#cfn-quicksight-dataset-logicaltable-alias
            '''
            result = self._values.get("alias")
            assert result is not None, "Required property 'alias' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def source(
            self,
        ) -> typing.Union["CfnDataSet.LogicalTableSourceProperty", _IResolvable_da3f097b]:
            '''Source of this logical table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-logicaltable.html#cfn-quicksight-dataset-logicaltable-source
            '''
            result = self._values.get("source")
            assert result is not None, "Required property 'source' is missing"
            return typing.cast(typing.Union["CfnDataSet.LogicalTableSourceProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def data_transforms(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.TransformOperationProperty", _IResolvable_da3f097b]]]]:
            '''Transform operations that act on this logical table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-logicaltable.html#cfn-quicksight-dataset-logicaltable-datatransforms
            '''
            result = self._values.get("data_transforms")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.TransformOperationProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LogicalTableProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.LogicalTableSourceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "join_instruction": "joinInstruction",
            "physical_table_id": "physicalTableId",
        },
    )
    class LogicalTableSourceProperty:
        def __init__(
            self,
            *,
            join_instruction: typing.Optional[typing.Union["CfnDataSet.JoinInstructionProperty", _IResolvable_da3f097b]] = None,
            physical_table_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Information about the source of a logical table.

            This is a variant type structure. For this structure to be valid, only one of the attributes can be non-null.

            :param join_instruction: Specifies the result of a join of two logical tables.
            :param physical_table_id: Physical table ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-logicaltablesource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                logical_table_source_property = quicksight.CfnDataSet.LogicalTableSourceProperty(
                    join_instruction=quicksight.CfnDataSet.JoinInstructionProperty(
                        left_operand="leftOperand",
                        on_clause="onClause",
                        right_operand="rightOperand",
                        type="type",
                
                        # the properties below are optional
                        left_join_key_properties=quicksight.CfnDataSet.JoinKeyPropertiesProperty(
                            unique_key=False
                        ),
                        right_join_key_properties=quicksight.CfnDataSet.JoinKeyPropertiesProperty(
                            unique_key=False
                        )
                    ),
                    physical_table_id="physicalTableId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if join_instruction is not None:
                self._values["join_instruction"] = join_instruction
            if physical_table_id is not None:
                self._values["physical_table_id"] = physical_table_id

        @builtins.property
        def join_instruction(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.JoinInstructionProperty", _IResolvable_da3f097b]]:
            '''Specifies the result of a join of two logical tables.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-logicaltablesource.html#cfn-quicksight-dataset-logicaltablesource-joininstruction
            '''
            result = self._values.get("join_instruction")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.JoinInstructionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def physical_table_id(self) -> typing.Optional[builtins.str]:
            '''Physical table ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-logicaltablesource.html#cfn-quicksight-dataset-logicaltablesource-physicaltableid
            '''
            result = self._values.get("physical_table_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LogicalTableSourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.OutputColumnProperty",
        jsii_struct_bases=[],
        name_mapping={"description": "description", "name": "name", "type": "type"},
    )
    class OutputColumnProperty:
        def __init__(
            self,
            *,
            description: typing.Optional[builtins.str] = None,
            name: typing.Optional[builtins.str] = None,
            type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Output column.

            :param description: A description for a column.
            :param name: A display name for the dataset.
            :param type: Type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-outputcolumn.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                output_column_property = quicksight.CfnDataSet.OutputColumnProperty(
                    description="description",
                    name="name",
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if description is not None:
                self._values["description"] = description
            if name is not None:
                self._values["name"] = name
            if type is not None:
                self._values["type"] = type

        @builtins.property
        def description(self) -> typing.Optional[builtins.str]:
            '''A description for a column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-outputcolumn.html#cfn-quicksight-dataset-outputcolumn-description
            '''
            result = self._values.get("description")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''A display name for the dataset.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-outputcolumn.html#cfn-quicksight-dataset-outputcolumn-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''Type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-outputcolumn.html#cfn-quicksight-dataset-outputcolumn-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OutputColumnProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.PhysicalTableProperty",
        jsii_struct_bases=[],
        name_mapping={
            "custom_sql": "customSql",
            "relational_table": "relationalTable",
            "s3_source": "s3Source",
        },
    )
    class PhysicalTableProperty:
        def __init__(
            self,
            *,
            custom_sql: typing.Optional[typing.Union["CfnDataSet.CustomSqlProperty", _IResolvable_da3f097b]] = None,
            relational_table: typing.Optional[typing.Union["CfnDataSet.RelationalTableProperty", _IResolvable_da3f097b]] = None,
            s3_source: typing.Optional[typing.Union["CfnDataSet.S3SourceProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A view of a data source that contains information about the shape of the data in the underlying source.

            This is a variant type structure. For this structure to be valid, only one of the attributes can be non-null.

            :param custom_sql: A physical table type built from the results of the custom SQL query.
            :param relational_table: A physical table type for relational data sources.
            :param s3_source: A physical table type for as S3 data source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-physicaltable.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                physical_table_property = quicksight.CfnDataSet.PhysicalTableProperty(
                    custom_sql=quicksight.CfnDataSet.CustomSqlProperty(
                        columns=[quicksight.CfnDataSet.InputColumnProperty(
                            name="name",
                            type="type"
                        )],
                        data_source_arn="dataSourceArn",
                        name="name",
                        sql_query="sqlQuery"
                    ),
                    relational_table=quicksight.CfnDataSet.RelationalTableProperty(
                        data_source_arn="dataSourceArn",
                        input_columns=[quicksight.CfnDataSet.InputColumnProperty(
                            name="name",
                            type="type"
                        )],
                        name="name",
                
                        # the properties below are optional
                        catalog="catalog",
                        schema="schema"
                    ),
                    s3_source=quicksight.CfnDataSet.S3SourceProperty(
                        data_source_arn="dataSourceArn",
                        input_columns=[quicksight.CfnDataSet.InputColumnProperty(
                            name="name",
                            type="type"
                        )],
                
                        # the properties below are optional
                        upload_settings=quicksight.CfnDataSet.UploadSettingsProperty(
                            contains_header=False,
                            delimiter="delimiter",
                            format="format",
                            start_from_row=123,
                            text_qualifier="textQualifier"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if custom_sql is not None:
                self._values["custom_sql"] = custom_sql
            if relational_table is not None:
                self._values["relational_table"] = relational_table
            if s3_source is not None:
                self._values["s3_source"] = s3_source

        @builtins.property
        def custom_sql(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.CustomSqlProperty", _IResolvable_da3f097b]]:
            '''A physical table type built from the results of the custom SQL query.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-physicaltable.html#cfn-quicksight-dataset-physicaltable-customsql
            '''
            result = self._values.get("custom_sql")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.CustomSqlProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def relational_table(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.RelationalTableProperty", _IResolvable_da3f097b]]:
            '''A physical table type for relational data sources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-physicaltable.html#cfn-quicksight-dataset-physicaltable-relationaltable
            '''
            result = self._values.get("relational_table")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.RelationalTableProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def s3_source(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.S3SourceProperty", _IResolvable_da3f097b]]:
            '''A physical table type for as S3 data source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-physicaltable.html#cfn-quicksight-dataset-physicaltable-s3source
            '''
            result = self._values.get("s3_source")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.S3SourceProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PhysicalTableProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.ProjectOperationProperty",
        jsii_struct_bases=[],
        name_mapping={"projected_columns": "projectedColumns"},
    )
    class ProjectOperationProperty:
        def __init__(self, *, projected_columns: typing.Sequence[builtins.str]) -> None:
            '''A transform operation that projects columns.

            Operations that come after a projection can only refer to projected columns.

            :param projected_columns: Projected columns.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-projectoperation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                project_operation_property = quicksight.CfnDataSet.ProjectOperationProperty(
                    projected_columns=["projectedColumns"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "projected_columns": projected_columns,
            }

        @builtins.property
        def projected_columns(self) -> typing.List[builtins.str]:
            '''Projected columns.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-projectoperation.html#cfn-quicksight-dataset-projectoperation-projectedcolumns
            '''
            result = self._values.get("projected_columns")
            assert result is not None, "Required property 'projected_columns' is missing"
            return typing.cast(typing.List[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ProjectOperationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.RelationalTableProperty",
        jsii_struct_bases=[],
        name_mapping={
            "data_source_arn": "dataSourceArn",
            "input_columns": "inputColumns",
            "name": "name",
            "catalog": "catalog",
            "schema": "schema",
        },
    )
    class RelationalTableProperty:
        def __init__(
            self,
            *,
            data_source_arn: builtins.str,
            input_columns: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataSet.InputColumnProperty", _IResolvable_da3f097b]]],
            name: builtins.str,
            catalog: typing.Optional[builtins.str] = None,
            schema: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A physical table type for relational data sources.

            :param data_source_arn: The Amazon Resource Name (ARN) for the data source.
            :param input_columns: The column schema of the table.
            :param name: The name of the relational table.
            :param catalog: ``CfnDataSet.RelationalTableProperty.Catalog``.
            :param schema: The schema name. This name applies to certain relational database engines.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-relationaltable.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                relational_table_property = quicksight.CfnDataSet.RelationalTableProperty(
                    data_source_arn="dataSourceArn",
                    input_columns=[quicksight.CfnDataSet.InputColumnProperty(
                        name="name",
                        type="type"
                    )],
                    name="name",
                
                    # the properties below are optional
                    catalog="catalog",
                    schema="schema"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "data_source_arn": data_source_arn,
                "input_columns": input_columns,
                "name": name,
            }
            if catalog is not None:
                self._values["catalog"] = catalog
            if schema is not None:
                self._values["schema"] = schema

        @builtins.property
        def data_source_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) for the data source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-relationaltable.html#cfn-quicksight-dataset-relationaltable-datasourcearn
            '''
            result = self._values.get("data_source_arn")
            assert result is not None, "Required property 'data_source_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def input_columns(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.InputColumnProperty", _IResolvable_da3f097b]]]:
            '''The column schema of the table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-relationaltable.html#cfn-quicksight-dataset-relationaltable-inputcolumns
            '''
            result = self._values.get("input_columns")
            assert result is not None, "Required property 'input_columns' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.InputColumnProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the relational table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-relationaltable.html#cfn-quicksight-dataset-relationaltable-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def catalog(self) -> typing.Optional[builtins.str]:
            '''``CfnDataSet.RelationalTableProperty.Catalog``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-relationaltable.html#cfn-quicksight-dataset-relationaltable-catalog
            '''
            result = self._values.get("catalog")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def schema(self) -> typing.Optional[builtins.str]:
            '''The schema name.

            This name applies to certain relational database engines.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-relationaltable.html#cfn-quicksight-dataset-relationaltable-schema
            '''
            result = self._values.get("schema")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RelationalTableProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.RenameColumnOperationProperty",
        jsii_struct_bases=[],
        name_mapping={"column_name": "columnName", "new_column_name": "newColumnName"},
    )
    class RenameColumnOperationProperty:
        def __init__(
            self,
            *,
            column_name: builtins.str,
            new_column_name: builtins.str,
        ) -> None:
            '''A transform operation that renames a column.

            :param column_name: The name of the column to be renamed.
            :param new_column_name: The new name for the column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-renamecolumnoperation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                rename_column_operation_property = quicksight.CfnDataSet.RenameColumnOperationProperty(
                    column_name="columnName",
                    new_column_name="newColumnName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "column_name": column_name,
                "new_column_name": new_column_name,
            }

        @builtins.property
        def column_name(self) -> builtins.str:
            '''The name of the column to be renamed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-renamecolumnoperation.html#cfn-quicksight-dataset-renamecolumnoperation-columnname
            '''
            result = self._values.get("column_name")
            assert result is not None, "Required property 'column_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def new_column_name(self) -> builtins.str:
            '''The new name for the column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-renamecolumnoperation.html#cfn-quicksight-dataset-renamecolumnoperation-newcolumnname
            '''
            result = self._values.get("new_column_name")
            assert result is not None, "Required property 'new_column_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RenameColumnOperationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.ResourcePermissionProperty",
        jsii_struct_bases=[],
        name_mapping={"actions": "actions", "principal": "principal"},
    )
    class ResourcePermissionProperty:
        def __init__(
            self,
            *,
            actions: typing.Sequence[builtins.str],
            principal: builtins.str,
        ) -> None:
            '''Permission for the resource.

            :param actions: The IAM action to grand or revoke permisions on.
            :param principal: The Amazon Resource Name (ARN) of the principal. This can be one of the following:. - The ARN of an Amazon QuickSight user or group associated with a data source or dataset. (This is common.) - The ARN of an Amazon QuickSight user, group, or namespace associated with an analysis, dashboard, template, or theme. (This is common.) - The ARN of an AWS account root: This is an IAM ARN rather than a Amazon QuickSight ARN. Use this option only to share resources (templates) across AWS accounts . (This is less common.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-resourcepermission.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                resource_permission_property = quicksight.CfnDataSet.ResourcePermissionProperty(
                    actions=["actions"],
                    principal="principal"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "actions": actions,
                "principal": principal,
            }

        @builtins.property
        def actions(self) -> typing.List[builtins.str]:
            '''The IAM action to grand or revoke permisions on.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-resourcepermission.html#cfn-quicksight-dataset-resourcepermission-actions
            '''
            result = self._values.get("actions")
            assert result is not None, "Required property 'actions' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def principal(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the principal. This can be one of the following:.

            - The ARN of an Amazon QuickSight user or group associated with a data source or dataset. (This is common.)
            - The ARN of an Amazon QuickSight user, group, or namespace associated with an analysis, dashboard, template, or theme. (This is common.)
            - The ARN of an AWS account root: This is an IAM ARN rather than a Amazon QuickSight ARN. Use this option only to share resources (templates) across AWS accounts . (This is less common.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-resourcepermission.html#cfn-quicksight-dataset-resourcepermission-principal
            '''
            result = self._values.get("principal")
            assert result is not None, "Required property 'principal' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourcePermissionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.RowLevelPermissionDataSetProperty",
        jsii_struct_bases=[],
        name_mapping={
            "arn": "arn",
            "permission_policy": "permissionPolicy",
            "format_version": "formatVersion",
            "namespace": "namespace",
        },
    )
    class RowLevelPermissionDataSetProperty:
        def __init__(
            self,
            *,
            arn: builtins.str,
            permission_policy: builtins.str,
            format_version: typing.Optional[builtins.str] = None,
            namespace: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Information about a dataset that contains permissions for row-level security (RLS).

            The permissions dataset maps fields to users or groups. For more information, see `Using Row-Level Security (RLS) to Restrict Access to a Dataset <https://docs.aws.amazon.com/quicksight/latest/user/restrict-access-to-a-data-set-using-row-level-security.html>`_ in the *Amazon QuickSight User Guide* .

            The option to deny permissions by setting ``PermissionPolicy`` to ``DENY_ACCESS`` is not supported for new RLS datasets.

            :param arn: The Amazon Resource Name (ARN) of the dataset that contains permissions for RLS.
            :param permission_policy: The type of permissions to use when interpreting the permissions for RLS. ``DENY_ACCESS`` is included for backward compatibility only.
            :param format_version: The user or group rules associated with the dataset that contains permissions for RLS. By default, ``FormatVersion`` is ``VERSION_1`` . When ``FormatVersion`` is ``VERSION_1`` , ``UserName`` and ``GroupName`` are required. When ``FormatVersion`` is ``VERSION_2`` , ``UserARN`` and ``GroupARN`` are required, and ``Namespace`` must not exist.
            :param namespace: The namespace associated with the dataset that contains permissions for RLS.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-rowlevelpermissiondataset.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                row_level_permission_data_set_property = quicksight.CfnDataSet.RowLevelPermissionDataSetProperty(
                    arn="arn",
                    permission_policy="permissionPolicy",
                
                    # the properties below are optional
                    format_version="formatVersion",
                    namespace="namespace"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
                "permission_policy": permission_policy,
            }
            if format_version is not None:
                self._values["format_version"] = format_version
            if namespace is not None:
                self._values["namespace"] = namespace

        @builtins.property
        def arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the dataset that contains permissions for RLS.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-rowlevelpermissiondataset.html#cfn-quicksight-dataset-rowlevelpermissiondataset-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def permission_policy(self) -> builtins.str:
            '''The type of permissions to use when interpreting the permissions for RLS.

            ``DENY_ACCESS`` is included for backward compatibility only.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-rowlevelpermissiondataset.html#cfn-quicksight-dataset-rowlevelpermissiondataset-permissionpolicy
            '''
            result = self._values.get("permission_policy")
            assert result is not None, "Required property 'permission_policy' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def format_version(self) -> typing.Optional[builtins.str]:
            '''The user or group rules associated with the dataset that contains permissions for RLS.

            By default, ``FormatVersion`` is ``VERSION_1`` . When ``FormatVersion`` is ``VERSION_1`` , ``UserName`` and ``GroupName`` are required. When ``FormatVersion`` is ``VERSION_2`` , ``UserARN`` and ``GroupARN`` are required, and ``Namespace`` must not exist.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-rowlevelpermissiondataset.html#cfn-quicksight-dataset-rowlevelpermissiondataset-formatversion
            '''
            result = self._values.get("format_version")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def namespace(self) -> typing.Optional[builtins.str]:
            '''The namespace associated with the dataset that contains permissions for RLS.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-rowlevelpermissiondataset.html#cfn-quicksight-dataset-rowlevelpermissiondataset-namespace
            '''
            result = self._values.get("namespace")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RowLevelPermissionDataSetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.S3SourceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "data_source_arn": "dataSourceArn",
            "input_columns": "inputColumns",
            "upload_settings": "uploadSettings",
        },
    )
    class S3SourceProperty:
        def __init__(
            self,
            *,
            data_source_arn: builtins.str,
            input_columns: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataSet.InputColumnProperty", _IResolvable_da3f097b]]],
            upload_settings: typing.Optional[typing.Union["CfnDataSet.UploadSettingsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A physical table type for an S3 data source.

            :param data_source_arn: The Amazon Resource Name (ARN) for the data source.
            :param input_columns: A physical table type for an S3 data source. .. epigraph:: For files that aren't JSON, only ``STRING`` data types are supported in input columns.
            :param upload_settings: Information about the format for the S3 source file or files.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-s3source.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                s3_source_property = quicksight.CfnDataSet.S3SourceProperty(
                    data_source_arn="dataSourceArn",
                    input_columns=[quicksight.CfnDataSet.InputColumnProperty(
                        name="name",
                        type="type"
                    )],
                
                    # the properties below are optional
                    upload_settings=quicksight.CfnDataSet.UploadSettingsProperty(
                        contains_header=False,
                        delimiter="delimiter",
                        format="format",
                        start_from_row=123,
                        text_qualifier="textQualifier"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "data_source_arn": data_source_arn,
                "input_columns": input_columns,
            }
            if upload_settings is not None:
                self._values["upload_settings"] = upload_settings

        @builtins.property
        def data_source_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) for the data source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-s3source.html#cfn-quicksight-dataset-s3source-datasourcearn
            '''
            result = self._values.get("data_source_arn")
            assert result is not None, "Required property 'data_source_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def input_columns(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.InputColumnProperty", _IResolvable_da3f097b]]]:
            '''A physical table type for an S3 data source.

            .. epigraph::

               For files that aren't JSON, only ``STRING`` data types are supported in input columns.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-s3source.html#cfn-quicksight-dataset-s3source-inputcolumns
            '''
            result = self._values.get("input_columns")
            assert result is not None, "Required property 'input_columns' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSet.InputColumnProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def upload_settings(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.UploadSettingsProperty", _IResolvable_da3f097b]]:
            '''Information about the format for the S3 source file or files.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-s3source.html#cfn-quicksight-dataset-s3source-uploadsettings
            '''
            result = self._values.get("upload_settings")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.UploadSettingsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3SourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.TagColumnOperationProperty",
        jsii_struct_bases=[],
        name_mapping={"column_name": "columnName", "tags": "tags"},
    )
    class TagColumnOperationProperty:
        def __init__(
            self,
            *,
            column_name: builtins.str,
            tags: typing.Sequence["CfnDataSet.ColumnTagProperty"],
        ) -> None:
            '''A transform operation that tags a column with additional information.

            :param column_name: The column that this operation acts on.
            :param tags: The dataset column tag, currently only used for geospatial type tagging. .. epigraph:: This is not tags for the AWS tagging feature.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-tagcolumnoperation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                tag_column_operation_property = quicksight.CfnDataSet.TagColumnOperationProperty(
                    column_name="columnName",
                    tags=[quicksight.CfnDataSet.ColumnTagProperty(
                        column_description=quicksight.CfnDataSet.ColumnDescriptionProperty(
                            text="text"
                        ),
                        column_geographic_role="columnGeographicRole"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "column_name": column_name,
                "tags": tags,
            }

        @builtins.property
        def column_name(self) -> builtins.str:
            '''The column that this operation acts on.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-tagcolumnoperation.html#cfn-quicksight-dataset-tagcolumnoperation-columnname
            '''
            result = self._values.get("column_name")
            assert result is not None, "Required property 'column_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def tags(self) -> typing.List["CfnDataSet.ColumnTagProperty"]:
            '''The dataset column tag, currently only used for geospatial type tagging.

            .. epigraph::

               This is not tags for the AWS tagging feature.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-tagcolumnoperation.html#cfn-quicksight-dataset-tagcolumnoperation-tags
            '''
            result = self._values.get("tags")
            assert result is not None, "Required property 'tags' is missing"
            return typing.cast(typing.List["CfnDataSet.ColumnTagProperty"], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TagColumnOperationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.TransformOperationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cast_column_type_operation": "castColumnTypeOperation",
            "create_columns_operation": "createColumnsOperation",
            "filter_operation": "filterOperation",
            "project_operation": "projectOperation",
            "rename_column_operation": "renameColumnOperation",
            "tag_column_operation": "tagColumnOperation",
        },
    )
    class TransformOperationProperty:
        def __init__(
            self,
            *,
            cast_column_type_operation: typing.Optional[typing.Union["CfnDataSet.CastColumnTypeOperationProperty", _IResolvable_da3f097b]] = None,
            create_columns_operation: typing.Optional[typing.Union["CfnDataSet.CreateColumnsOperationProperty", _IResolvable_da3f097b]] = None,
            filter_operation: typing.Optional[typing.Union["CfnDataSet.FilterOperationProperty", _IResolvable_da3f097b]] = None,
            project_operation: typing.Optional[typing.Union["CfnDataSet.ProjectOperationProperty", _IResolvable_da3f097b]] = None,
            rename_column_operation: typing.Optional[typing.Union["CfnDataSet.RenameColumnOperationProperty", _IResolvable_da3f097b]] = None,
            tag_column_operation: typing.Optional[typing.Union["CfnDataSet.TagColumnOperationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A data transformation on a logical table.

            This is a variant type structure. For this structure to be valid, only one of the attributes can be non-null.

            :param cast_column_type_operation: A transform operation that casts a column to a different type.
            :param create_columns_operation: An operation that creates calculated columns. Columns created in one such operation form a lexical closure.
            :param filter_operation: An operation that filters rows based on some condition.
            :param project_operation: An operation that projects columns. Operations that come after a projection can only refer to projected columns.
            :param rename_column_operation: An operation that renames a column.
            :param tag_column_operation: An operation that tags a column with additional information.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-transformoperation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                transform_operation_property = quicksight.CfnDataSet.TransformOperationProperty(
                    cast_column_type_operation=quicksight.CfnDataSet.CastColumnTypeOperationProperty(
                        column_name="columnName",
                        new_column_type="newColumnType",
                
                        # the properties below are optional
                        format="format"
                    ),
                    create_columns_operation=quicksight.CfnDataSet.CreateColumnsOperationProperty(
                        columns=[quicksight.CfnDataSet.CalculatedColumnProperty(
                            column_id="columnId",
                            column_name="columnName",
                            expression="expression"
                        )]
                    ),
                    filter_operation=quicksight.CfnDataSet.FilterOperationProperty(
                        condition_expression="conditionExpression"
                    ),
                    project_operation=quicksight.CfnDataSet.ProjectOperationProperty(
                        projected_columns=["projectedColumns"]
                    ),
                    rename_column_operation=quicksight.CfnDataSet.RenameColumnOperationProperty(
                        column_name="columnName",
                        new_column_name="newColumnName"
                    ),
                    tag_column_operation=quicksight.CfnDataSet.TagColumnOperationProperty(
                        column_name="columnName",
                        tags=[quicksight.CfnDataSet.ColumnTagProperty(
                            column_description=quicksight.CfnDataSet.ColumnDescriptionProperty(
                                text="text"
                            ),
                            column_geographic_role="columnGeographicRole"
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if cast_column_type_operation is not None:
                self._values["cast_column_type_operation"] = cast_column_type_operation
            if create_columns_operation is not None:
                self._values["create_columns_operation"] = create_columns_operation
            if filter_operation is not None:
                self._values["filter_operation"] = filter_operation
            if project_operation is not None:
                self._values["project_operation"] = project_operation
            if rename_column_operation is not None:
                self._values["rename_column_operation"] = rename_column_operation
            if tag_column_operation is not None:
                self._values["tag_column_operation"] = tag_column_operation

        @builtins.property
        def cast_column_type_operation(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.CastColumnTypeOperationProperty", _IResolvable_da3f097b]]:
            '''A transform operation that casts a column to a different type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-transformoperation.html#cfn-quicksight-dataset-transformoperation-castcolumntypeoperation
            '''
            result = self._values.get("cast_column_type_operation")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.CastColumnTypeOperationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def create_columns_operation(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.CreateColumnsOperationProperty", _IResolvable_da3f097b]]:
            '''An operation that creates calculated columns.

            Columns created in one such operation form a lexical closure.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-transformoperation.html#cfn-quicksight-dataset-transformoperation-createcolumnsoperation
            '''
            result = self._values.get("create_columns_operation")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.CreateColumnsOperationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def filter_operation(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.FilterOperationProperty", _IResolvable_da3f097b]]:
            '''An operation that filters rows based on some condition.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-transformoperation.html#cfn-quicksight-dataset-transformoperation-filteroperation
            '''
            result = self._values.get("filter_operation")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.FilterOperationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def project_operation(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.ProjectOperationProperty", _IResolvable_da3f097b]]:
            '''An operation that projects columns.

            Operations that come after a projection can only refer to projected columns.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-transformoperation.html#cfn-quicksight-dataset-transformoperation-projectoperation
            '''
            result = self._values.get("project_operation")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.ProjectOperationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def rename_column_operation(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.RenameColumnOperationProperty", _IResolvable_da3f097b]]:
            '''An operation that renames a column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-transformoperation.html#cfn-quicksight-dataset-transformoperation-renamecolumnoperation
            '''
            result = self._values.get("rename_column_operation")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.RenameColumnOperationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def tag_column_operation(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSet.TagColumnOperationProperty", _IResolvable_da3f097b]]:
            '''An operation that tags a column with additional information.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-transformoperation.html#cfn-quicksight-dataset-transformoperation-tagcolumnoperation
            '''
            result = self._values.get("tag_column_operation")
            return typing.cast(typing.Optional[typing.Union["CfnDataSet.TagColumnOperationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TransformOperationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSet.UploadSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "contains_header": "containsHeader",
            "delimiter": "delimiter",
            "format": "format",
            "start_from_row": "startFromRow",
            "text_qualifier": "textQualifier",
        },
    )
    class UploadSettingsProperty:
        def __init__(
            self,
            *,
            contains_header: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            delimiter: typing.Optional[builtins.str] = None,
            format: typing.Optional[builtins.str] = None,
            start_from_row: typing.Optional[jsii.Number] = None,
            text_qualifier: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Information about the format for a source file or files.

            :param contains_header: Whether the file has a header row, or the files each have a header row.
            :param delimiter: The delimiter between values in the file.
            :param format: File format.
            :param start_from_row: A row number to start reading data from.
            :param text_qualifier: Text qualifier.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-uploadsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                upload_settings_property = quicksight.CfnDataSet.UploadSettingsProperty(
                    contains_header=False,
                    delimiter="delimiter",
                    format="format",
                    start_from_row=123,
                    text_qualifier="textQualifier"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if contains_header is not None:
                self._values["contains_header"] = contains_header
            if delimiter is not None:
                self._values["delimiter"] = delimiter
            if format is not None:
                self._values["format"] = format
            if start_from_row is not None:
                self._values["start_from_row"] = start_from_row
            if text_qualifier is not None:
                self._values["text_qualifier"] = text_qualifier

        @builtins.property
        def contains_header(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Whether the file has a header row, or the files each have a header row.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-uploadsettings.html#cfn-quicksight-dataset-uploadsettings-containsheader
            '''
            result = self._values.get("contains_header")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def delimiter(self) -> typing.Optional[builtins.str]:
            '''The delimiter between values in the file.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-uploadsettings.html#cfn-quicksight-dataset-uploadsettings-delimiter
            '''
            result = self._values.get("delimiter")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def format(self) -> typing.Optional[builtins.str]:
            '''File format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-uploadsettings.html#cfn-quicksight-dataset-uploadsettings-format
            '''
            result = self._values.get("format")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def start_from_row(self) -> typing.Optional[jsii.Number]:
            '''A row number to start reading data from.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-uploadsettings.html#cfn-quicksight-dataset-uploadsettings-startfromrow
            '''
            result = self._values.get("start_from_row")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def text_qualifier(self) -> typing.Optional[builtins.str]:
            '''Text qualifier.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-dataset-uploadsettings.html#cfn-quicksight-dataset-uploadsettings-textqualifier
            '''
            result = self._values.get("text_qualifier")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "UploadSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSetProps",
    jsii_struct_bases=[],
    name_mapping={
        "aws_account_id": "awsAccountId",
        "column_groups": "columnGroups",
        "column_level_permission_rules": "columnLevelPermissionRules",
        "data_set_id": "dataSetId",
        "field_folders": "fieldFolders",
        "import_mode": "importMode",
        "ingestion_wait_policy": "ingestionWaitPolicy",
        "logical_table_map": "logicalTableMap",
        "name": "name",
        "permissions": "permissions",
        "physical_table_map": "physicalTableMap",
        "row_level_permission_data_set": "rowLevelPermissionDataSet",
        "tags": "tags",
    },
)
class CfnDataSetProps:
    def __init__(
        self,
        *,
        aws_account_id: typing.Optional[builtins.str] = None,
        column_groups: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnDataSet.ColumnGroupProperty, _IResolvable_da3f097b]]]] = None,
        column_level_permission_rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnDataSet.ColumnLevelPermissionRuleProperty, _IResolvable_da3f097b]]]] = None,
        data_set_id: typing.Optional[builtins.str] = None,
        field_folders: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnDataSet.FieldFolderProperty, _IResolvable_da3f097b]]]] = None,
        import_mode: typing.Optional[builtins.str] = None,
        ingestion_wait_policy: typing.Optional[typing.Union[CfnDataSet.IngestionWaitPolicyProperty, _IResolvable_da3f097b]] = None,
        logical_table_map: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnDataSet.LogicalTableProperty, _IResolvable_da3f097b]]]] = None,
        name: typing.Optional[builtins.str] = None,
        permissions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnDataSet.ResourcePermissionProperty, _IResolvable_da3f097b]]]] = None,
        physical_table_map: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnDataSet.PhysicalTableProperty, _IResolvable_da3f097b]]]] = None,
        row_level_permission_data_set: typing.Optional[typing.Union[CfnDataSet.RowLevelPermissionDataSetProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDataSet``.

        :param aws_account_id: The AWS account ID.
        :param column_groups: Groupings of columns that work together in certain Amazon QuickSight features. Currently, only geospatial hierarchy is supported.
        :param column_level_permission_rules: A set of one or more definitions of a ``ColumnLevelPermissionRule`` .
        :param data_set_id: An ID for the dataset that you want to create. This ID is unique per AWS Region for each AWS account.
        :param field_folders: The folder that contains fields and nested subfolders for your dataset.
        :param import_mode: Indicates whether you want to import the data into SPICE.
        :param ingestion_wait_policy: The wait policy to use when creating or updating a Dataset. The default is to wait for SPICE ingestion to finish with timeout of 36 hours.
        :param logical_table_map: Configures the combination and transformation of the data from the physical tables.
        :param name: The display name for the dataset.
        :param permissions: A list of resource permissions on the dataset.
        :param physical_table_map: Declares the physical tables that are available in the underlying data sources.
        :param row_level_permission_data_set: The row-level security configuration for the data that you want to create.
        :param tags: Contains a map of the key-value pairs for the resource tag or tags assigned to the dataset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_quicksight as quicksight
            
            cfn_data_set_props = quicksight.CfnDataSetProps(
                aws_account_id="awsAccountId",
                column_groups=[quicksight.CfnDataSet.ColumnGroupProperty(
                    geo_spatial_column_group=quicksight.CfnDataSet.GeoSpatialColumnGroupProperty(
                        columns=["columns"],
                        name="name",
            
                        # the properties below are optional
                        country_code="countryCode"
                    )
                )],
                column_level_permission_rules=[quicksight.CfnDataSet.ColumnLevelPermissionRuleProperty(
                    column_names=["columnNames"],
                    principals=["principals"]
                )],
                data_set_id="dataSetId",
                field_folders={
                    "field_folders_key": quicksight.CfnDataSet.FieldFolderProperty(
                        columns=["columns"],
                        description="description"
                    )
                },
                import_mode="importMode",
                ingestion_wait_policy=quicksight.CfnDataSet.IngestionWaitPolicyProperty(
                    ingestion_wait_time_in_hours=123,
                    wait_for_spice_ingestion=False
                ),
                logical_table_map={
                    "logical_table_map_key": quicksight.CfnDataSet.LogicalTableProperty(
                        alias="alias",
                        source=quicksight.CfnDataSet.LogicalTableSourceProperty(
                            join_instruction=quicksight.CfnDataSet.JoinInstructionProperty(
                                left_operand="leftOperand",
                                on_clause="onClause",
                                right_operand="rightOperand",
                                type="type",
            
                                # the properties below are optional
                                left_join_key_properties=quicksight.CfnDataSet.JoinKeyPropertiesProperty(
                                    unique_key=False
                                ),
                                right_join_key_properties=quicksight.CfnDataSet.JoinKeyPropertiesProperty(
                                    unique_key=False
                                )
                            ),
                            physical_table_id="physicalTableId"
                        ),
            
                        # the properties below are optional
                        data_transforms=[quicksight.CfnDataSet.TransformOperationProperty(
                            cast_column_type_operation=quicksight.CfnDataSet.CastColumnTypeOperationProperty(
                                column_name="columnName",
                                new_column_type="newColumnType",
            
                                # the properties below are optional
                                format="format"
                            ),
                            create_columns_operation=quicksight.CfnDataSet.CreateColumnsOperationProperty(
                                columns=[quicksight.CfnDataSet.CalculatedColumnProperty(
                                    column_id="columnId",
                                    column_name="columnName",
                                    expression="expression"
                                )]
                            ),
                            filter_operation=quicksight.CfnDataSet.FilterOperationProperty(
                                condition_expression="conditionExpression"
                            ),
                            project_operation=quicksight.CfnDataSet.ProjectOperationProperty(
                                projected_columns=["projectedColumns"]
                            ),
                            rename_column_operation=quicksight.CfnDataSet.RenameColumnOperationProperty(
                                column_name="columnName",
                                new_column_name="newColumnName"
                            ),
                            tag_column_operation=quicksight.CfnDataSet.TagColumnOperationProperty(
                                column_name="columnName",
                                tags=[quicksight.CfnDataSet.ColumnTagProperty(
                                    column_description=quicksight.CfnDataSet.ColumnDescriptionProperty(
                                        text="text"
                                    ),
                                    column_geographic_role="columnGeographicRole"
                                )]
                            )
                        )]
                    )
                },
                name="name",
                permissions=[quicksight.CfnDataSet.ResourcePermissionProperty(
                    actions=["actions"],
                    principal="principal"
                )],
                physical_table_map={
                    "physical_table_map_key": quicksight.CfnDataSet.PhysicalTableProperty(
                        custom_sql=quicksight.CfnDataSet.CustomSqlProperty(
                            columns=[quicksight.CfnDataSet.InputColumnProperty(
                                name="name",
                                type="type"
                            )],
                            data_source_arn="dataSourceArn",
                            name="name",
                            sql_query="sqlQuery"
                        ),
                        relational_table=quicksight.CfnDataSet.RelationalTableProperty(
                            data_source_arn="dataSourceArn",
                            input_columns=[quicksight.CfnDataSet.InputColumnProperty(
                                name="name",
                                type="type"
                            )],
                            name="name",
            
                            # the properties below are optional
                            catalog="catalog",
                            schema="schema"
                        ),
                        s3_source=quicksight.CfnDataSet.S3SourceProperty(
                            data_source_arn="dataSourceArn",
                            input_columns=[quicksight.CfnDataSet.InputColumnProperty(
                                name="name",
                                type="type"
                            )],
            
                            # the properties below are optional
                            upload_settings=quicksight.CfnDataSet.UploadSettingsProperty(
                                contains_header=False,
                                delimiter="delimiter",
                                format="format",
                                start_from_row=123,
                                text_qualifier="textQualifier"
                            )
                        )
                    )
                },
                row_level_permission_data_set=quicksight.CfnDataSet.RowLevelPermissionDataSetProperty(
                    arn="arn",
                    permission_policy="permissionPolicy",
            
                    # the properties below are optional
                    format_version="formatVersion",
                    namespace="namespace"
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if aws_account_id is not None:
            self._values["aws_account_id"] = aws_account_id
        if column_groups is not None:
            self._values["column_groups"] = column_groups
        if column_level_permission_rules is not None:
            self._values["column_level_permission_rules"] = column_level_permission_rules
        if data_set_id is not None:
            self._values["data_set_id"] = data_set_id
        if field_folders is not None:
            self._values["field_folders"] = field_folders
        if import_mode is not None:
            self._values["import_mode"] = import_mode
        if ingestion_wait_policy is not None:
            self._values["ingestion_wait_policy"] = ingestion_wait_policy
        if logical_table_map is not None:
            self._values["logical_table_map"] = logical_table_map
        if name is not None:
            self._values["name"] = name
        if permissions is not None:
            self._values["permissions"] = permissions
        if physical_table_map is not None:
            self._values["physical_table_map"] = physical_table_map
        if row_level_permission_data_set is not None:
            self._values["row_level_permission_data_set"] = row_level_permission_data_set
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def aws_account_id(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-awsaccountid
        '''
        result = self._values.get("aws_account_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def column_groups(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataSet.ColumnGroupProperty, _IResolvable_da3f097b]]]]:
        '''Groupings of columns that work together in certain Amazon QuickSight features.

        Currently, only geospatial hierarchy is supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-columngroups
        '''
        result = self._values.get("column_groups")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataSet.ColumnGroupProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def column_level_permission_rules(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataSet.ColumnLevelPermissionRuleProperty, _IResolvable_da3f097b]]]]:
        '''A set of one or more definitions of a ``ColumnLevelPermissionRule`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-columnlevelpermissionrules
        '''
        result = self._values.get("column_level_permission_rules")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataSet.ColumnLevelPermissionRuleProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def data_set_id(self) -> typing.Optional[builtins.str]:
        '''An ID for the dataset that you want to create.

        This ID is unique per AWS Region for each AWS account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-datasetid
        '''
        result = self._values.get("data_set_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def field_folders(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnDataSet.FieldFolderProperty, _IResolvable_da3f097b]]]]:
        '''The folder that contains fields and nested subfolders for your dataset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-fieldfolders
        '''
        result = self._values.get("field_folders")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnDataSet.FieldFolderProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def import_mode(self) -> typing.Optional[builtins.str]:
        '''Indicates whether you want to import the data into SPICE.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-importmode
        '''
        result = self._values.get("import_mode")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ingestion_wait_policy(
        self,
    ) -> typing.Optional[typing.Union[CfnDataSet.IngestionWaitPolicyProperty, _IResolvable_da3f097b]]:
        '''The wait policy to use when creating or updating a Dataset.

        The default is to wait for SPICE ingestion to finish with timeout of 36 hours.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-ingestionwaitpolicy
        '''
        result = self._values.get("ingestion_wait_policy")
        return typing.cast(typing.Optional[typing.Union[CfnDataSet.IngestionWaitPolicyProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def logical_table_map(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnDataSet.LogicalTableProperty, _IResolvable_da3f097b]]]]:
        '''Configures the combination and transformation of the data from the physical tables.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-logicaltablemap
        '''
        result = self._values.get("logical_table_map")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnDataSet.LogicalTableProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The display name for the dataset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def permissions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataSet.ResourcePermissionProperty, _IResolvable_da3f097b]]]]:
        '''A list of resource permissions on the dataset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-permissions
        '''
        result = self._values.get("permissions")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataSet.ResourcePermissionProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def physical_table_map(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnDataSet.PhysicalTableProperty, _IResolvable_da3f097b]]]]:
        '''Declares the physical tables that are available in the underlying data sources.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-physicaltablemap
        '''
        result = self._values.get("physical_table_map")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnDataSet.PhysicalTableProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def row_level_permission_data_set(
        self,
    ) -> typing.Optional[typing.Union[CfnDataSet.RowLevelPermissionDataSetProperty, _IResolvable_da3f097b]]:
        '''The row-level security configuration for the data that you want to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-rowlevelpermissiondataset
        '''
        result = self._values.get("row_level_permission_data_set")
        return typing.cast(typing.Optional[typing.Union[CfnDataSet.RowLevelPermissionDataSetProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Contains a map of the key-value pairs for the resource tag or tags assigned to the dataset.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-dataset.html#cfn-quicksight-dataset-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDataSetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDataSource(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource",
):
    '''A CloudFormation ``AWS::QuickSight::DataSource``.

    Creates a data source.

    :cloudformationResource: AWS::QuickSight::DataSource
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_quicksight as quicksight
        
        cfn_data_source = quicksight.CfnDataSource(self, "MyCfnDataSource",
            alternate_data_source_parameters=[quicksight.CfnDataSource.DataSourceParametersProperty(
                amazon_elasticsearch_parameters=quicksight.CfnDataSource.AmazonElasticsearchParametersProperty(
                    domain="domain"
                ),
                amazon_open_search_parameters=quicksight.CfnDataSource.AmazonOpenSearchParametersProperty(
                    domain="domain"
                ),
                athena_parameters=quicksight.CfnDataSource.AthenaParametersProperty(
                    work_group="workGroup"
                ),
                aurora_parameters=quicksight.CfnDataSource.AuroraParametersProperty(
                    database="database",
                    host="host",
                    port=123
                ),
                aurora_postgre_sql_parameters=quicksight.CfnDataSource.AuroraPostgreSqlParametersProperty(
                    database="database",
                    host="host",
                    port=123
                ),
                maria_db_parameters=quicksight.CfnDataSource.MariaDbParametersProperty(
                    database="database",
                    host="host",
                    port=123
                ),
                my_sql_parameters=quicksight.CfnDataSource.MySqlParametersProperty(
                    database="database",
                    host="host",
                    port=123
                ),
                oracle_parameters=quicksight.CfnDataSource.OracleParametersProperty(
                    database="database",
                    host="host",
                    port=123
                ),
                postgre_sql_parameters=quicksight.CfnDataSource.PostgreSqlParametersProperty(
                    database="database",
                    host="host",
                    port=123
                ),
                presto_parameters=quicksight.CfnDataSource.PrestoParametersProperty(
                    catalog="catalog",
                    host="host",
                    port=123
                ),
                rds_parameters=quicksight.CfnDataSource.RdsParametersProperty(
                    database="database",
                    instance_id="instanceId"
                ),
                redshift_parameters=quicksight.CfnDataSource.RedshiftParametersProperty(
                    database="database",
        
                    # the properties below are optional
                    cluster_id="clusterId",
                    host="host",
                    port=123
                ),
                s3_parameters=quicksight.CfnDataSource.S3ParametersProperty(
                    manifest_file_location=quicksight.CfnDataSource.ManifestFileLocationProperty(
                        bucket="bucket",
                        key="key"
                    )
                ),
                snowflake_parameters=quicksight.CfnDataSource.SnowflakeParametersProperty(
                    database="database",
                    host="host",
                    warehouse="warehouse"
                ),
                spark_parameters=quicksight.CfnDataSource.SparkParametersProperty(
                    host="host",
                    port=123
                ),
                sql_server_parameters=quicksight.CfnDataSource.SqlServerParametersProperty(
                    database="database",
                    host="host",
                    port=123
                ),
                teradata_parameters=quicksight.CfnDataSource.TeradataParametersProperty(
                    database="database",
                    host="host",
                    port=123
                )
            )],
            aws_account_id="awsAccountId",
            credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
                copy_source_arn="copySourceArn",
                credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                    password="password",
                    username="username",
        
                    # the properties below are optional
                    alternate_data_source_parameters=[quicksight.CfnDataSource.DataSourceParametersProperty(
                        amazon_elasticsearch_parameters=quicksight.CfnDataSource.AmazonElasticsearchParametersProperty(
                            domain="domain"
                        ),
                        amazon_open_search_parameters=quicksight.CfnDataSource.AmazonOpenSearchParametersProperty(
                            domain="domain"
                        ),
                        athena_parameters=quicksight.CfnDataSource.AthenaParametersProperty(
                            work_group="workGroup"
                        ),
                        aurora_parameters=quicksight.CfnDataSource.AuroraParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        ),
                        aurora_postgre_sql_parameters=quicksight.CfnDataSource.AuroraPostgreSqlParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        ),
                        maria_db_parameters=quicksight.CfnDataSource.MariaDbParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        ),
                        my_sql_parameters=quicksight.CfnDataSource.MySqlParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        ),
                        oracle_parameters=quicksight.CfnDataSource.OracleParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        ),
                        postgre_sql_parameters=quicksight.CfnDataSource.PostgreSqlParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        ),
                        presto_parameters=quicksight.CfnDataSource.PrestoParametersProperty(
                            catalog="catalog",
                            host="host",
                            port=123
                        ),
                        rds_parameters=quicksight.CfnDataSource.RdsParametersProperty(
                            database="database",
                            instance_id="instanceId"
                        ),
                        redshift_parameters=quicksight.CfnDataSource.RedshiftParametersProperty(
                            database="database",
        
                            # the properties below are optional
                            cluster_id="clusterId",
                            host="host",
                            port=123
                        ),
                        s3_parameters=quicksight.CfnDataSource.S3ParametersProperty(
                            manifest_file_location=quicksight.CfnDataSource.ManifestFileLocationProperty(
                                bucket="bucket",
                                key="key"
                            )
                        ),
                        snowflake_parameters=quicksight.CfnDataSource.SnowflakeParametersProperty(
                            database="database",
                            host="host",
                            warehouse="warehouse"
                        ),
                        spark_parameters=quicksight.CfnDataSource.SparkParametersProperty(
                            host="host",
                            port=123
                        ),
                        sql_server_parameters=quicksight.CfnDataSource.SqlServerParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        ),
                        teradata_parameters=quicksight.CfnDataSource.TeradataParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        )
                    )]
                )
            ),
            data_source_id="dataSourceId",
            data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
                amazon_elasticsearch_parameters=quicksight.CfnDataSource.AmazonElasticsearchParametersProperty(
                    domain="domain"
                ),
                amazon_open_search_parameters=quicksight.CfnDataSource.AmazonOpenSearchParametersProperty(
                    domain="domain"
                ),
                athena_parameters=quicksight.CfnDataSource.AthenaParametersProperty(
                    work_group="workGroup"
                ),
                aurora_parameters=quicksight.CfnDataSource.AuroraParametersProperty(
                    database="database",
                    host="host",
                    port=123
                ),
                aurora_postgre_sql_parameters=quicksight.CfnDataSource.AuroraPostgreSqlParametersProperty(
                    database="database",
                    host="host",
                    port=123
                ),
                maria_db_parameters=quicksight.CfnDataSource.MariaDbParametersProperty(
                    database="database",
                    host="host",
                    port=123
                ),
                my_sql_parameters=quicksight.CfnDataSource.MySqlParametersProperty(
                    database="database",
                    host="host",
                    port=123
                ),
                oracle_parameters=quicksight.CfnDataSource.OracleParametersProperty(
                    database="database",
                    host="host",
                    port=123
                ),
                postgre_sql_parameters=quicksight.CfnDataSource.PostgreSqlParametersProperty(
                    database="database",
                    host="host",
                    port=123
                ),
                presto_parameters=quicksight.CfnDataSource.PrestoParametersProperty(
                    catalog="catalog",
                    host="host",
                    port=123
                ),
                rds_parameters=quicksight.CfnDataSource.RdsParametersProperty(
                    database="database",
                    instance_id="instanceId"
                ),
                redshift_parameters=quicksight.CfnDataSource.RedshiftParametersProperty(
                    database="database",
        
                    # the properties below are optional
                    cluster_id="clusterId",
                    host="host",
                    port=123
                ),
                s3_parameters=quicksight.CfnDataSource.S3ParametersProperty(
                    manifest_file_location=quicksight.CfnDataSource.ManifestFileLocationProperty(
                        bucket="bucket",
                        key="key"
                    )
                ),
                snowflake_parameters=quicksight.CfnDataSource.SnowflakeParametersProperty(
                    database="database",
                    host="host",
                    warehouse="warehouse"
                ),
                spark_parameters=quicksight.CfnDataSource.SparkParametersProperty(
                    host="host",
                    port=123
                ),
                sql_server_parameters=quicksight.CfnDataSource.SqlServerParametersProperty(
                    database="database",
                    host="host",
                    port=123
                ),
                teradata_parameters=quicksight.CfnDataSource.TeradataParametersProperty(
                    database="database",
                    host="host",
                    port=123
                )
            ),
            error_info=quicksight.CfnDataSource.DataSourceErrorInfoProperty(
                message="message",
                type="type"
            ),
            name="name",
            permissions=[quicksight.CfnDataSource.ResourcePermissionProperty(
                actions=["actions"],
                principal="principal"
            )],
            ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                disable_ssl=False
            ),
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            type="type",
            vpc_connection_properties=quicksight.CfnDataSource.VpcConnectionPropertiesProperty(
                vpc_connection_arn="vpcConnectionArn"
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        alternate_data_source_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataSource.DataSourceParametersProperty", _IResolvable_da3f097b]]]] = None,
        aws_account_id: typing.Optional[builtins.str] = None,
        credentials: typing.Optional[typing.Union["CfnDataSource.DataSourceCredentialsProperty", _IResolvable_da3f097b]] = None,
        data_source_id: typing.Optional[builtins.str] = None,
        data_source_parameters: typing.Optional[typing.Union["CfnDataSource.DataSourceParametersProperty", _IResolvable_da3f097b]] = None,
        error_info: typing.Optional[typing.Union["CfnDataSource.DataSourceErrorInfoProperty", _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        permissions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataSource.ResourcePermissionProperty", _IResolvable_da3f097b]]]] = None,
        ssl_properties: typing.Optional[typing.Union["CfnDataSource.SslPropertiesProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        type: typing.Optional[builtins.str] = None,
        vpc_connection_properties: typing.Optional[typing.Union["CfnDataSource.VpcConnectionPropertiesProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::QuickSight::DataSource``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param alternate_data_source_parameters: A set of alternate data source parameters that you want to share for the credentials stored with this data source. The credentials are applied in tandem with the data source parameters when you copy a data source by using a create or update request. The API operation compares the ``DataSourceParameters`` structure that's in the request with the structures in the ``AlternateDataSourceParameters`` allow list. If the structures are an exact match, the request is allowed to use the credentials from this existing data source. If the ``AlternateDataSourceParameters`` list is null, the ``Credentials`` originally used with this ``DataSourceParameters`` are automatically allowed.
        :param aws_account_id: The AWS account ID.
        :param credentials: The credentials Amazon QuickSight that uses to connect to your underlying source. Currently, only credentials based on user name and password are supported.
        :param data_source_id: An ID for the data source. This ID is unique per AWS Region for each AWS account.
        :param data_source_parameters: The parameters that Amazon QuickSight uses to connect to your underlying source.
        :param error_info: Error information from the last update or the creation of the data source.
        :param name: A display name for the data source.
        :param permissions: A list of resource permissions on the data source.
        :param ssl_properties: Secure Socket Layer (SSL) properties that apply when Amazon QuickSight connects to your underlying source.
        :param tags: Contains a map of the key-value pairs for the resource tag or tags assigned to the data source.
        :param type: The type of the data source. To return a list of all data sources, use ``ListDataSources`` . Use ``AMAZON_ELASTICSEARCH`` for Amazon OpenSearch Service .
        :param vpc_connection_properties: Use this parameter only when you want Amazon QuickSight to use a VPC connection when connecting to your underlying source.
        '''
        props = CfnDataSourceProps(
            alternate_data_source_parameters=alternate_data_source_parameters,
            aws_account_id=aws_account_id,
            credentials=credentials,
            data_source_id=data_source_id,
            data_source_parameters=data_source_parameters,
            error_info=error_info,
            name=name,
            permissions=permissions,
            ssl_properties=ssl_properties,
            tags=tags,
            type=type,
            vpc_connection_properties=vpc_connection_properties,
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
        '''The Amazon Resource Name (ARN) of the dataset.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCreatedTime")
    def attr_created_time(self) -> builtins.str:
        '''The time that this data source was created.

        :cloudformationAttribute: CreatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLastUpdatedTime")
    def attr_last_updated_time(self) -> builtins.str:
        '''The last time that this data source was updated.

        :cloudformationAttribute: LastUpdatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLastUpdatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStatus")
    def attr_status(self) -> builtins.str:
        '''The HTTP status of the request.

        :cloudformationAttribute: Status
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Contains a map of the key-value pairs for the resource tag or tags assigned to the data source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="alternateDataSourceParameters")
    def alternate_data_source_parameters(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSource.DataSourceParametersProperty", _IResolvable_da3f097b]]]]:
        '''A set of alternate data source parameters that you want to share for the credentials stored with this data source.

        The credentials are applied in tandem with the data source parameters when you copy a data source by using a create or update request. The API operation compares the ``DataSourceParameters`` structure that's in the request with the structures in the ``AlternateDataSourceParameters`` allow list. If the structures are an exact match, the request is allowed to use the credentials from this existing data source. If the ``AlternateDataSourceParameters`` list is null, the ``Credentials`` originally used with this ``DataSourceParameters`` are automatically allowed.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-alternatedatasourceparameters
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSource.DataSourceParametersProperty", _IResolvable_da3f097b]]]], jsii.get(self, "alternateDataSourceParameters"))

    @alternate_data_source_parameters.setter
    def alternate_data_source_parameters(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSource.DataSourceParametersProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "alternateDataSourceParameters", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="awsAccountId")
    def aws_account_id(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-awsaccountid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "awsAccountId"))

    @aws_account_id.setter
    def aws_account_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "awsAccountId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="credentials")
    def credentials(
        self,
    ) -> typing.Optional[typing.Union["CfnDataSource.DataSourceCredentialsProperty", _IResolvable_da3f097b]]:
        '''The credentials Amazon QuickSight that uses to connect to your underlying source.

        Currently, only credentials based on user name and password are supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-credentials
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDataSource.DataSourceCredentialsProperty", _IResolvable_da3f097b]], jsii.get(self, "credentials"))

    @credentials.setter
    def credentials(
        self,
        value: typing.Optional[typing.Union["CfnDataSource.DataSourceCredentialsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "credentials", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dataSourceId")
    def data_source_id(self) -> typing.Optional[builtins.str]:
        '''An ID for the data source.

        This ID is unique per AWS Region for each AWS account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-datasourceid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "dataSourceId"))

    @data_source_id.setter
    def data_source_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "dataSourceId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dataSourceParameters")
    def data_source_parameters(
        self,
    ) -> typing.Optional[typing.Union["CfnDataSource.DataSourceParametersProperty", _IResolvable_da3f097b]]:
        '''The parameters that Amazon QuickSight uses to connect to your underlying source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-datasourceparameters
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDataSource.DataSourceParametersProperty", _IResolvable_da3f097b]], jsii.get(self, "dataSourceParameters"))

    @data_source_parameters.setter
    def data_source_parameters(
        self,
        value: typing.Optional[typing.Union["CfnDataSource.DataSourceParametersProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "dataSourceParameters", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="errorInfo")
    def error_info(
        self,
    ) -> typing.Optional[typing.Union["CfnDataSource.DataSourceErrorInfoProperty", _IResolvable_da3f097b]]:
        '''Error information from the last update or the creation of the data source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-errorinfo
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDataSource.DataSourceErrorInfoProperty", _IResolvable_da3f097b]], jsii.get(self, "errorInfo"))

    @error_info.setter
    def error_info(
        self,
        value: typing.Optional[typing.Union["CfnDataSource.DataSourceErrorInfoProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "errorInfo", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''A display name for the data source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="permissions")
    def permissions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSource.ResourcePermissionProperty", _IResolvable_da3f097b]]]]:
        '''A list of resource permissions on the data source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-permissions
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSource.ResourcePermissionProperty", _IResolvable_da3f097b]]]], jsii.get(self, "permissions"))

    @permissions.setter
    def permissions(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSource.ResourcePermissionProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "permissions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sslProperties")
    def ssl_properties(
        self,
    ) -> typing.Optional[typing.Union["CfnDataSource.SslPropertiesProperty", _IResolvable_da3f097b]]:
        '''Secure Socket Layer (SSL) properties that apply when Amazon QuickSight connects to your underlying source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-sslproperties
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDataSource.SslPropertiesProperty", _IResolvable_da3f097b]], jsii.get(self, "sslProperties"))

    @ssl_properties.setter
    def ssl_properties(
        self,
        value: typing.Optional[typing.Union["CfnDataSource.SslPropertiesProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "sslProperties", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> typing.Optional[builtins.str]:
        '''The type of the data source. To return a list of all data sources, use ``ListDataSources`` .

        Use ``AMAZON_ELASTICSEARCH`` for Amazon OpenSearch Service .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-type
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "type"))

    @type.setter
    def type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "type", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcConnectionProperties")
    def vpc_connection_properties(
        self,
    ) -> typing.Optional[typing.Union["CfnDataSource.VpcConnectionPropertiesProperty", _IResolvable_da3f097b]]:
        '''Use this parameter only when you want Amazon QuickSight to use a VPC connection when connecting to your underlying source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-vpcconnectionproperties
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDataSource.VpcConnectionPropertiesProperty", _IResolvable_da3f097b]], jsii.get(self, "vpcConnectionProperties"))

    @vpc_connection_properties.setter
    def vpc_connection_properties(
        self,
        value: typing.Optional[typing.Union["CfnDataSource.VpcConnectionPropertiesProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "vpcConnectionProperties", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.AmazonElasticsearchParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"domain": "domain"},
    )
    class AmazonElasticsearchParametersProperty:
        def __init__(self, *, domain: builtins.str) -> None:
            '''The parameters for OpenSearch .

            :param domain: The OpenSearch domain.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-amazonelasticsearchparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                amazon_elasticsearch_parameters_property = quicksight.CfnDataSource.AmazonElasticsearchParametersProperty(
                    domain="domain"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "domain": domain,
            }

        @builtins.property
        def domain(self) -> builtins.str:
            '''The OpenSearch domain.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-amazonelasticsearchparameters.html#cfn-quicksight-datasource-amazonelasticsearchparameters-domain
            '''
            result = self._values.get("domain")
            assert result is not None, "Required property 'domain' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AmazonElasticsearchParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.AmazonOpenSearchParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"domain": "domain"},
    )
    class AmazonOpenSearchParametersProperty:
        def __init__(self, *, domain: builtins.str) -> None:
            '''The parameters for OpenSearch .

            :param domain: The OpenSearch domain.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-amazonopensearchparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                amazon_open_search_parameters_property = quicksight.CfnDataSource.AmazonOpenSearchParametersProperty(
                    domain="domain"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "domain": domain,
            }

        @builtins.property
        def domain(self) -> builtins.str:
            '''The OpenSearch domain.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-amazonopensearchparameters.html#cfn-quicksight-datasource-amazonopensearchparameters-domain
            '''
            result = self._values.get("domain")
            assert result is not None, "Required property 'domain' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AmazonOpenSearchParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.AthenaParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"work_group": "workGroup"},
    )
    class AthenaParametersProperty:
        def __init__(self, *, work_group: typing.Optional[builtins.str] = None) -> None:
            '''Parameters for Amazon Athena.

            :param work_group: The workgroup that Amazon Athena uses.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-athenaparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                athena_parameters_property = quicksight.CfnDataSource.AthenaParametersProperty(
                    work_group="workGroup"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if work_group is not None:
                self._values["work_group"] = work_group

        @builtins.property
        def work_group(self) -> typing.Optional[builtins.str]:
            '''The workgroup that Amazon Athena uses.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-athenaparameters.html#cfn-quicksight-datasource-athenaparameters-workgroup
            '''
            result = self._values.get("work_group")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AthenaParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.AuroraParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"database": "database", "host": "host", "port": "port"},
    )
    class AuroraParametersProperty:
        def __init__(
            self,
            *,
            database: builtins.str,
            host: builtins.str,
            port: jsii.Number,
        ) -> None:
            '''Parameters for Amazon Aurora.

            :param database: Database.
            :param host: Host.
            :param port: Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-auroraparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                aurora_parameters_property = quicksight.CfnDataSource.AuroraParametersProperty(
                    database="database",
                    host="host",
                    port=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database": database,
                "host": host,
                "port": port,
            }

        @builtins.property
        def database(self) -> builtins.str:
            '''Database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-auroraparameters.html#cfn-quicksight-datasource-auroraparameters-database
            '''
            result = self._values.get("database")
            assert result is not None, "Required property 'database' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def host(self) -> builtins.str:
            '''Host.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-auroraparameters.html#cfn-quicksight-datasource-auroraparameters-host
            '''
            result = self._values.get("host")
            assert result is not None, "Required property 'host' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def port(self) -> jsii.Number:
            '''Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-auroraparameters.html#cfn-quicksight-datasource-auroraparameters-port
            '''
            result = self._values.get("port")
            assert result is not None, "Required property 'port' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AuroraParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.AuroraPostgreSqlParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"database": "database", "host": "host", "port": "port"},
    )
    class AuroraPostgreSqlParametersProperty:
        def __init__(
            self,
            *,
            database: builtins.str,
            host: builtins.str,
            port: jsii.Number,
        ) -> None:
            '''Parameters for Amazon Aurora PostgreSQL-Compatible Edition.

            :param database: The Amazon Aurora PostgreSQL database to connect to.
            :param host: The Amazon Aurora PostgreSQL-Compatible host to connect to.
            :param port: The port that Amazon Aurora PostgreSQL is listening on.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-aurorapostgresqlparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                aurora_postgre_sql_parameters_property = quicksight.CfnDataSource.AuroraPostgreSqlParametersProperty(
                    database="database",
                    host="host",
                    port=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database": database,
                "host": host,
                "port": port,
            }

        @builtins.property
        def database(self) -> builtins.str:
            '''The Amazon Aurora PostgreSQL database to connect to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-aurorapostgresqlparameters.html#cfn-quicksight-datasource-aurorapostgresqlparameters-database
            '''
            result = self._values.get("database")
            assert result is not None, "Required property 'database' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def host(self) -> builtins.str:
            '''The Amazon Aurora PostgreSQL-Compatible host to connect to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-aurorapostgresqlparameters.html#cfn-quicksight-datasource-aurorapostgresqlparameters-host
            '''
            result = self._values.get("host")
            assert result is not None, "Required property 'host' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def port(self) -> jsii.Number:
            '''The port that Amazon Aurora PostgreSQL is listening on.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-aurorapostgresqlparameters.html#cfn-quicksight-datasource-aurorapostgresqlparameters-port
            '''
            result = self._values.get("port")
            assert result is not None, "Required property 'port' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AuroraPostgreSqlParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.CredentialPairProperty",
        jsii_struct_bases=[],
        name_mapping={
            "password": "password",
            "username": "username",
            "alternate_data_source_parameters": "alternateDataSourceParameters",
        },
    )
    class CredentialPairProperty:
        def __init__(
            self,
            *,
            password: builtins.str,
            username: builtins.str,
            alternate_data_source_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataSource.DataSourceParametersProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''The combination of user name and password that are used as credentials.

            :param password: Password.
            :param username: User name.
            :param alternate_data_source_parameters: A set of alternate data source parameters that you want to share for these credentials. The credentials are applied in tandem with the data source parameters when you copy a data source by using a create or update request. The API operation compares the ``DataSourceParameters`` structure that's in the request with the structures in the ``AlternateDataSourceParameters`` allow list. If the structures are an exact match, the request is allowed to use the new data source with the existing credentials. If the ``AlternateDataSourceParameters`` list is null, the ``DataSourceParameters`` originally used with these ``Credentials`` is automatically allowed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-credentialpair.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                credential_pair_property = quicksight.CfnDataSource.CredentialPairProperty(
                    password="password",
                    username="username",
                
                    # the properties below are optional
                    alternate_data_source_parameters=[quicksight.CfnDataSource.DataSourceParametersProperty(
                        amazon_elasticsearch_parameters=quicksight.CfnDataSource.AmazonElasticsearchParametersProperty(
                            domain="domain"
                        ),
                        amazon_open_search_parameters=quicksight.CfnDataSource.AmazonOpenSearchParametersProperty(
                            domain="domain"
                        ),
                        athena_parameters=quicksight.CfnDataSource.AthenaParametersProperty(
                            work_group="workGroup"
                        ),
                        aurora_parameters=quicksight.CfnDataSource.AuroraParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        ),
                        aurora_postgre_sql_parameters=quicksight.CfnDataSource.AuroraPostgreSqlParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        ),
                        maria_db_parameters=quicksight.CfnDataSource.MariaDbParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        ),
                        my_sql_parameters=quicksight.CfnDataSource.MySqlParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        ),
                        oracle_parameters=quicksight.CfnDataSource.OracleParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        ),
                        postgre_sql_parameters=quicksight.CfnDataSource.PostgreSqlParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        ),
                        presto_parameters=quicksight.CfnDataSource.PrestoParametersProperty(
                            catalog="catalog",
                            host="host",
                            port=123
                        ),
                        rds_parameters=quicksight.CfnDataSource.RdsParametersProperty(
                            database="database",
                            instance_id="instanceId"
                        ),
                        redshift_parameters=quicksight.CfnDataSource.RedshiftParametersProperty(
                            database="database",
                
                            # the properties below are optional
                            cluster_id="clusterId",
                            host="host",
                            port=123
                        ),
                        s3_parameters=quicksight.CfnDataSource.S3ParametersProperty(
                            manifest_file_location=quicksight.CfnDataSource.ManifestFileLocationProperty(
                                bucket="bucket",
                                key="key"
                            )
                        ),
                        snowflake_parameters=quicksight.CfnDataSource.SnowflakeParametersProperty(
                            database="database",
                            host="host",
                            warehouse="warehouse"
                        ),
                        spark_parameters=quicksight.CfnDataSource.SparkParametersProperty(
                            host="host",
                            port=123
                        ),
                        sql_server_parameters=quicksight.CfnDataSource.SqlServerParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        ),
                        teradata_parameters=quicksight.CfnDataSource.TeradataParametersProperty(
                            database="database",
                            host="host",
                            port=123
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "password": password,
                "username": username,
            }
            if alternate_data_source_parameters is not None:
                self._values["alternate_data_source_parameters"] = alternate_data_source_parameters

        @builtins.property
        def password(self) -> builtins.str:
            '''Password.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-credentialpair.html#cfn-quicksight-datasource-credentialpair-password
            '''
            result = self._values.get("password")
            assert result is not None, "Required property 'password' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def username(self) -> builtins.str:
            '''User name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-credentialpair.html#cfn-quicksight-datasource-credentialpair-username
            '''
            result = self._values.get("username")
            assert result is not None, "Required property 'username' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def alternate_data_source_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSource.DataSourceParametersProperty", _IResolvable_da3f097b]]]]:
            '''A set of alternate data source parameters that you want to share for these credentials.

            The credentials are applied in tandem with the data source parameters when you copy a data source by using a create or update request. The API operation compares the ``DataSourceParameters`` structure that's in the request with the structures in the ``AlternateDataSourceParameters`` allow list. If the structures are an exact match, the request is allowed to use the new data source with the existing credentials. If the ``AlternateDataSourceParameters`` list is null, the ``DataSourceParameters`` originally used with these ``Credentials`` is automatically allowed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-credentialpair.html#cfn-quicksight-datasource-credentialpair-alternatedatasourceparameters
            '''
            result = self._values.get("alternate_data_source_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataSource.DataSourceParametersProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CredentialPairProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.DataSourceCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "copy_source_arn": "copySourceArn",
            "credential_pair": "credentialPair",
        },
    )
    class DataSourceCredentialsProperty:
        def __init__(
            self,
            *,
            copy_source_arn: typing.Optional[builtins.str] = None,
            credential_pair: typing.Optional[typing.Union["CfnDataSource.CredentialPairProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Data source credentials.

            This is a variant type structure. For this structure to be valid, only one of the attributes can be non-null.

            :param copy_source_arn: The Amazon Resource Name (ARN) of a data source that has the credential pair that you want to use. When ``CopySourceArn`` is not null, the credential pair from the data source in the ARN is used as the credentials for the ``DataSourceCredentials`` structure.
            :param credential_pair: Credential pair. For more information, see ``[CredentialPair](https://docs.aws.amazon.com/quicksight/latest/APIReference/API_CredentialPair.html)`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourcecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                data_source_credentials_property = quicksight.CfnDataSource.DataSourceCredentialsProperty(
                    copy_source_arn="copySourceArn",
                    credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                        password="password",
                        username="username",
                
                        # the properties below are optional
                        alternate_data_source_parameters=[quicksight.CfnDataSource.DataSourceParametersProperty(
                            amazon_elasticsearch_parameters=quicksight.CfnDataSource.AmazonElasticsearchParametersProperty(
                                domain="domain"
                            ),
                            amazon_open_search_parameters=quicksight.CfnDataSource.AmazonOpenSearchParametersProperty(
                                domain="domain"
                            ),
                            athena_parameters=quicksight.CfnDataSource.AthenaParametersProperty(
                                work_group="workGroup"
                            ),
                            aurora_parameters=quicksight.CfnDataSource.AuroraParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            ),
                            aurora_postgre_sql_parameters=quicksight.CfnDataSource.AuroraPostgreSqlParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            ),
                            maria_db_parameters=quicksight.CfnDataSource.MariaDbParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            ),
                            my_sql_parameters=quicksight.CfnDataSource.MySqlParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            ),
                            oracle_parameters=quicksight.CfnDataSource.OracleParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            ),
                            postgre_sql_parameters=quicksight.CfnDataSource.PostgreSqlParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            ),
                            presto_parameters=quicksight.CfnDataSource.PrestoParametersProperty(
                                catalog="catalog",
                                host="host",
                                port=123
                            ),
                            rds_parameters=quicksight.CfnDataSource.RdsParametersProperty(
                                database="database",
                                instance_id="instanceId"
                            ),
                            redshift_parameters=quicksight.CfnDataSource.RedshiftParametersProperty(
                                database="database",
                
                                # the properties below are optional
                                cluster_id="clusterId",
                                host="host",
                                port=123
                            ),
                            s3_parameters=quicksight.CfnDataSource.S3ParametersProperty(
                                manifest_file_location=quicksight.CfnDataSource.ManifestFileLocationProperty(
                                    bucket="bucket",
                                    key="key"
                                )
                            ),
                            snowflake_parameters=quicksight.CfnDataSource.SnowflakeParametersProperty(
                                database="database",
                                host="host",
                                warehouse="warehouse"
                            ),
                            spark_parameters=quicksight.CfnDataSource.SparkParametersProperty(
                                host="host",
                                port=123
                            ),
                            sql_server_parameters=quicksight.CfnDataSource.SqlServerParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            ),
                            teradata_parameters=quicksight.CfnDataSource.TeradataParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            )
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if copy_source_arn is not None:
                self._values["copy_source_arn"] = copy_source_arn
            if credential_pair is not None:
                self._values["credential_pair"] = credential_pair

        @builtins.property
        def copy_source_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of a data source that has the credential pair that you want to use.

            When ``CopySourceArn`` is not null, the credential pair from the data source in the ARN is used as the credentials for the ``DataSourceCredentials`` structure.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourcecredentials.html#cfn-quicksight-datasource-datasourcecredentials-copysourcearn
            '''
            result = self._values.get("copy_source_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def credential_pair(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.CredentialPairProperty", _IResolvable_da3f097b]]:
            '''Credential pair.

            For more information, see ``[CredentialPair](https://docs.aws.amazon.com/quicksight/latest/APIReference/API_CredentialPair.html)`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourcecredentials.html#cfn-quicksight-datasource-datasourcecredentials-credentialpair
            '''
            result = self._values.get("credential_pair")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.CredentialPairProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataSourceCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.DataSourceErrorInfoProperty",
        jsii_struct_bases=[],
        name_mapping={"message": "message", "type": "type"},
    )
    class DataSourceErrorInfoProperty:
        def __init__(
            self,
            *,
            message: typing.Optional[builtins.str] = None,
            type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Error information for the data source creation or update.

            :param message: Error message.
            :param type: Error type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceerrorinfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                data_source_error_info_property = quicksight.CfnDataSource.DataSourceErrorInfoProperty(
                    message="message",
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if message is not None:
                self._values["message"] = message
            if type is not None:
                self._values["type"] = type

        @builtins.property
        def message(self) -> typing.Optional[builtins.str]:
            '''Error message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceerrorinfo.html#cfn-quicksight-datasource-datasourceerrorinfo-message
            '''
            result = self._values.get("message")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''Error type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceerrorinfo.html#cfn-quicksight-datasource-datasourceerrorinfo-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataSourceErrorInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.DataSourceParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "amazon_elasticsearch_parameters": "amazonElasticsearchParameters",
            "amazon_open_search_parameters": "amazonOpenSearchParameters",
            "athena_parameters": "athenaParameters",
            "aurora_parameters": "auroraParameters",
            "aurora_postgre_sql_parameters": "auroraPostgreSqlParameters",
            "maria_db_parameters": "mariaDbParameters",
            "my_sql_parameters": "mySqlParameters",
            "oracle_parameters": "oracleParameters",
            "postgre_sql_parameters": "postgreSqlParameters",
            "presto_parameters": "prestoParameters",
            "rds_parameters": "rdsParameters",
            "redshift_parameters": "redshiftParameters",
            "s3_parameters": "s3Parameters",
            "snowflake_parameters": "snowflakeParameters",
            "spark_parameters": "sparkParameters",
            "sql_server_parameters": "sqlServerParameters",
            "teradata_parameters": "teradataParameters",
        },
    )
    class DataSourceParametersProperty:
        def __init__(
            self,
            *,
            amazon_elasticsearch_parameters: typing.Optional[typing.Union["CfnDataSource.AmazonElasticsearchParametersProperty", _IResolvable_da3f097b]] = None,
            amazon_open_search_parameters: typing.Optional[typing.Union["CfnDataSource.AmazonOpenSearchParametersProperty", _IResolvable_da3f097b]] = None,
            athena_parameters: typing.Optional[typing.Union["CfnDataSource.AthenaParametersProperty", _IResolvable_da3f097b]] = None,
            aurora_parameters: typing.Optional[typing.Union["CfnDataSource.AuroraParametersProperty", _IResolvable_da3f097b]] = None,
            aurora_postgre_sql_parameters: typing.Optional[typing.Union["CfnDataSource.AuroraPostgreSqlParametersProperty", _IResolvable_da3f097b]] = None,
            maria_db_parameters: typing.Optional[typing.Union["CfnDataSource.MariaDbParametersProperty", _IResolvable_da3f097b]] = None,
            my_sql_parameters: typing.Optional[typing.Union["CfnDataSource.MySqlParametersProperty", _IResolvable_da3f097b]] = None,
            oracle_parameters: typing.Optional[typing.Union["CfnDataSource.OracleParametersProperty", _IResolvable_da3f097b]] = None,
            postgre_sql_parameters: typing.Optional[typing.Union["CfnDataSource.PostgreSqlParametersProperty", _IResolvable_da3f097b]] = None,
            presto_parameters: typing.Optional[typing.Union["CfnDataSource.PrestoParametersProperty", _IResolvable_da3f097b]] = None,
            rds_parameters: typing.Optional[typing.Union["CfnDataSource.RdsParametersProperty", _IResolvable_da3f097b]] = None,
            redshift_parameters: typing.Optional[typing.Union["CfnDataSource.RedshiftParametersProperty", _IResolvable_da3f097b]] = None,
            s3_parameters: typing.Optional[typing.Union["CfnDataSource.S3ParametersProperty", _IResolvable_da3f097b]] = None,
            snowflake_parameters: typing.Optional[typing.Union["CfnDataSource.SnowflakeParametersProperty", _IResolvable_da3f097b]] = None,
            spark_parameters: typing.Optional[typing.Union["CfnDataSource.SparkParametersProperty", _IResolvable_da3f097b]] = None,
            sql_server_parameters: typing.Optional[typing.Union["CfnDataSource.SqlServerParametersProperty", _IResolvable_da3f097b]] = None,
            teradata_parameters: typing.Optional[typing.Union["CfnDataSource.TeradataParametersProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The parameters that Amazon QuickSight uses to connect to your underlying data source.

            This is a variant type structure. For this structure to be valid, only one of the attributes can be non-null.

            :param amazon_elasticsearch_parameters: The parameters for OpenSearch .
            :param amazon_open_search_parameters: The parameters for OpenSearch .
            :param athena_parameters: The parameters for Amazon Athena.
            :param aurora_parameters: The parameters for Amazon Aurora MySQL.
            :param aurora_postgre_sql_parameters: The parameters for Amazon Aurora.
            :param maria_db_parameters: The parameters for MariaDB.
            :param my_sql_parameters: The parameters for MySQL.
            :param oracle_parameters: Oracle parameters.
            :param postgre_sql_parameters: The parameters for PostgreSQL.
            :param presto_parameters: The parameters for Presto.
            :param rds_parameters: The parameters for Amazon RDS.
            :param redshift_parameters: The parameters for Amazon Redshift.
            :param s3_parameters: The parameters for S3.
            :param snowflake_parameters: The parameters for Snowflake.
            :param spark_parameters: The parameters for Spark.
            :param sql_server_parameters: The parameters for SQL Server.
            :param teradata_parameters: The parameters for Teradata.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                data_source_parameters_property = quicksight.CfnDataSource.DataSourceParametersProperty(
                    amazon_elasticsearch_parameters=quicksight.CfnDataSource.AmazonElasticsearchParametersProperty(
                        domain="domain"
                    ),
                    amazon_open_search_parameters=quicksight.CfnDataSource.AmazonOpenSearchParametersProperty(
                        domain="domain"
                    ),
                    athena_parameters=quicksight.CfnDataSource.AthenaParametersProperty(
                        work_group="workGroup"
                    ),
                    aurora_parameters=quicksight.CfnDataSource.AuroraParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    aurora_postgre_sql_parameters=quicksight.CfnDataSource.AuroraPostgreSqlParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    maria_db_parameters=quicksight.CfnDataSource.MariaDbParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    my_sql_parameters=quicksight.CfnDataSource.MySqlParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    oracle_parameters=quicksight.CfnDataSource.OracleParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    postgre_sql_parameters=quicksight.CfnDataSource.PostgreSqlParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    presto_parameters=quicksight.CfnDataSource.PrestoParametersProperty(
                        catalog="catalog",
                        host="host",
                        port=123
                    ),
                    rds_parameters=quicksight.CfnDataSource.RdsParametersProperty(
                        database="database",
                        instance_id="instanceId"
                    ),
                    redshift_parameters=quicksight.CfnDataSource.RedshiftParametersProperty(
                        database="database",
                
                        # the properties below are optional
                        cluster_id="clusterId",
                        host="host",
                        port=123
                    ),
                    s3_parameters=quicksight.CfnDataSource.S3ParametersProperty(
                        manifest_file_location=quicksight.CfnDataSource.ManifestFileLocationProperty(
                            bucket="bucket",
                            key="key"
                        )
                    ),
                    snowflake_parameters=quicksight.CfnDataSource.SnowflakeParametersProperty(
                        database="database",
                        host="host",
                        warehouse="warehouse"
                    ),
                    spark_parameters=quicksight.CfnDataSource.SparkParametersProperty(
                        host="host",
                        port=123
                    ),
                    sql_server_parameters=quicksight.CfnDataSource.SqlServerParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    teradata_parameters=quicksight.CfnDataSource.TeradataParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if amazon_elasticsearch_parameters is not None:
                self._values["amazon_elasticsearch_parameters"] = amazon_elasticsearch_parameters
            if amazon_open_search_parameters is not None:
                self._values["amazon_open_search_parameters"] = amazon_open_search_parameters
            if athena_parameters is not None:
                self._values["athena_parameters"] = athena_parameters
            if aurora_parameters is not None:
                self._values["aurora_parameters"] = aurora_parameters
            if aurora_postgre_sql_parameters is not None:
                self._values["aurora_postgre_sql_parameters"] = aurora_postgre_sql_parameters
            if maria_db_parameters is not None:
                self._values["maria_db_parameters"] = maria_db_parameters
            if my_sql_parameters is not None:
                self._values["my_sql_parameters"] = my_sql_parameters
            if oracle_parameters is not None:
                self._values["oracle_parameters"] = oracle_parameters
            if postgre_sql_parameters is not None:
                self._values["postgre_sql_parameters"] = postgre_sql_parameters
            if presto_parameters is not None:
                self._values["presto_parameters"] = presto_parameters
            if rds_parameters is not None:
                self._values["rds_parameters"] = rds_parameters
            if redshift_parameters is not None:
                self._values["redshift_parameters"] = redshift_parameters
            if s3_parameters is not None:
                self._values["s3_parameters"] = s3_parameters
            if snowflake_parameters is not None:
                self._values["snowflake_parameters"] = snowflake_parameters
            if spark_parameters is not None:
                self._values["spark_parameters"] = spark_parameters
            if sql_server_parameters is not None:
                self._values["sql_server_parameters"] = sql_server_parameters
            if teradata_parameters is not None:
                self._values["teradata_parameters"] = teradata_parameters

        @builtins.property
        def amazon_elasticsearch_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.AmazonElasticsearchParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for OpenSearch .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-amazonelasticsearchparameters
            '''
            result = self._values.get("amazon_elasticsearch_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.AmazonElasticsearchParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def amazon_open_search_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.AmazonOpenSearchParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for OpenSearch .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-amazonopensearchparameters
            '''
            result = self._values.get("amazon_open_search_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.AmazonOpenSearchParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def athena_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.AthenaParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for Amazon Athena.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-athenaparameters
            '''
            result = self._values.get("athena_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.AthenaParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def aurora_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.AuroraParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for Amazon Aurora MySQL.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-auroraparameters
            '''
            result = self._values.get("aurora_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.AuroraParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def aurora_postgre_sql_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.AuroraPostgreSqlParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for Amazon Aurora.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-aurorapostgresqlparameters
            '''
            result = self._values.get("aurora_postgre_sql_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.AuroraPostgreSqlParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def maria_db_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.MariaDbParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for MariaDB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-mariadbparameters
            '''
            result = self._values.get("maria_db_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.MariaDbParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def my_sql_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.MySqlParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for MySQL.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-mysqlparameters
            '''
            result = self._values.get("my_sql_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.MySqlParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def oracle_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.OracleParametersProperty", _IResolvable_da3f097b]]:
            '''Oracle parameters.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-oracleparameters
            '''
            result = self._values.get("oracle_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.OracleParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def postgre_sql_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.PostgreSqlParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for PostgreSQL.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-postgresqlparameters
            '''
            result = self._values.get("postgre_sql_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.PostgreSqlParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def presto_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.PrestoParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for Presto.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-prestoparameters
            '''
            result = self._values.get("presto_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.PrestoParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def rds_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.RdsParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for Amazon RDS.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-rdsparameters
            '''
            result = self._values.get("rds_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.RdsParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def redshift_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.RedshiftParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for Amazon Redshift.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-redshiftparameters
            '''
            result = self._values.get("redshift_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.RedshiftParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def s3_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.S3ParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for S3.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-s3parameters
            '''
            result = self._values.get("s3_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.S3ParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def snowflake_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.SnowflakeParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for Snowflake.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-snowflakeparameters
            '''
            result = self._values.get("snowflake_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.SnowflakeParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def spark_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.SparkParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for Spark.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-sparkparameters
            '''
            result = self._values.get("spark_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.SparkParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sql_server_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.SqlServerParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for SQL Server.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-sqlserverparameters
            '''
            result = self._values.get("sql_server_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.SqlServerParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def teradata_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnDataSource.TeradataParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for Teradata.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-datasourceparameters.html#cfn-quicksight-datasource-datasourceparameters-teradataparameters
            '''
            result = self._values.get("teradata_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnDataSource.TeradataParametersProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataSourceParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.ManifestFileLocationProperty",
        jsii_struct_bases=[],
        name_mapping={"bucket": "bucket", "key": "key"},
    )
    class ManifestFileLocationProperty:
        def __init__(self, *, bucket: builtins.str, key: builtins.str) -> None:
            '''Amazon S3 manifest file location.

            :param bucket: Amazon S3 bucket.
            :param key: Amazon S3 key that identifies an object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-manifestfilelocation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                manifest_file_location_property = quicksight.CfnDataSource.ManifestFileLocationProperty(
                    bucket="bucket",
                    key="key"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket": bucket,
                "key": key,
            }

        @builtins.property
        def bucket(self) -> builtins.str:
            '''Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-manifestfilelocation.html#cfn-quicksight-datasource-manifestfilelocation-bucket
            '''
            result = self._values.get("bucket")
            assert result is not None, "Required property 'bucket' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def key(self) -> builtins.str:
            '''Amazon S3 key that identifies an object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-manifestfilelocation.html#cfn-quicksight-datasource-manifestfilelocation-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ManifestFileLocationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.MariaDbParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"database": "database", "host": "host", "port": "port"},
    )
    class MariaDbParametersProperty:
        def __init__(
            self,
            *,
            database: builtins.str,
            host: builtins.str,
            port: jsii.Number,
        ) -> None:
            '''The parameters for MariaDB.

            :param database: Database.
            :param host: Host.
            :param port: Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-mariadbparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                maria_db_parameters_property = quicksight.CfnDataSource.MariaDbParametersProperty(
                    database="database",
                    host="host",
                    port=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database": database,
                "host": host,
                "port": port,
            }

        @builtins.property
        def database(self) -> builtins.str:
            '''Database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-mariadbparameters.html#cfn-quicksight-datasource-mariadbparameters-database
            '''
            result = self._values.get("database")
            assert result is not None, "Required property 'database' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def host(self) -> builtins.str:
            '''Host.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-mariadbparameters.html#cfn-quicksight-datasource-mariadbparameters-host
            '''
            result = self._values.get("host")
            assert result is not None, "Required property 'host' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def port(self) -> jsii.Number:
            '''Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-mariadbparameters.html#cfn-quicksight-datasource-mariadbparameters-port
            '''
            result = self._values.get("port")
            assert result is not None, "Required property 'port' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MariaDbParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.MySqlParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"database": "database", "host": "host", "port": "port"},
    )
    class MySqlParametersProperty:
        def __init__(
            self,
            *,
            database: builtins.str,
            host: builtins.str,
            port: jsii.Number,
        ) -> None:
            '''The parameters for MySQL.

            :param database: Database.
            :param host: Host.
            :param port: Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-mysqlparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                my_sql_parameters_property = quicksight.CfnDataSource.MySqlParametersProperty(
                    database="database",
                    host="host",
                    port=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database": database,
                "host": host,
                "port": port,
            }

        @builtins.property
        def database(self) -> builtins.str:
            '''Database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-mysqlparameters.html#cfn-quicksight-datasource-mysqlparameters-database
            '''
            result = self._values.get("database")
            assert result is not None, "Required property 'database' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def host(self) -> builtins.str:
            '''Host.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-mysqlparameters.html#cfn-quicksight-datasource-mysqlparameters-host
            '''
            result = self._values.get("host")
            assert result is not None, "Required property 'host' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def port(self) -> jsii.Number:
            '''Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-mysqlparameters.html#cfn-quicksight-datasource-mysqlparameters-port
            '''
            result = self._values.get("port")
            assert result is not None, "Required property 'port' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MySqlParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.OracleParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"database": "database", "host": "host", "port": "port"},
    )
    class OracleParametersProperty:
        def __init__(
            self,
            *,
            database: builtins.str,
            host: builtins.str,
            port: jsii.Number,
        ) -> None:
            '''Oracle parameters.

            :param database: Database.
            :param host: Host.
            :param port: Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-oracleparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                oracle_parameters_property = quicksight.CfnDataSource.OracleParametersProperty(
                    database="database",
                    host="host",
                    port=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database": database,
                "host": host,
                "port": port,
            }

        @builtins.property
        def database(self) -> builtins.str:
            '''Database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-oracleparameters.html#cfn-quicksight-datasource-oracleparameters-database
            '''
            result = self._values.get("database")
            assert result is not None, "Required property 'database' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def host(self) -> builtins.str:
            '''Host.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-oracleparameters.html#cfn-quicksight-datasource-oracleparameters-host
            '''
            result = self._values.get("host")
            assert result is not None, "Required property 'host' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def port(self) -> jsii.Number:
            '''Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-oracleparameters.html#cfn-quicksight-datasource-oracleparameters-port
            '''
            result = self._values.get("port")
            assert result is not None, "Required property 'port' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OracleParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.PostgreSqlParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"database": "database", "host": "host", "port": "port"},
    )
    class PostgreSqlParametersProperty:
        def __init__(
            self,
            *,
            database: builtins.str,
            host: builtins.str,
            port: jsii.Number,
        ) -> None:
            '''The parameters for PostgreSQL.

            :param database: Database.
            :param host: Host.
            :param port: Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-postgresqlparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                postgre_sql_parameters_property = quicksight.CfnDataSource.PostgreSqlParametersProperty(
                    database="database",
                    host="host",
                    port=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database": database,
                "host": host,
                "port": port,
            }

        @builtins.property
        def database(self) -> builtins.str:
            '''Database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-postgresqlparameters.html#cfn-quicksight-datasource-postgresqlparameters-database
            '''
            result = self._values.get("database")
            assert result is not None, "Required property 'database' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def host(self) -> builtins.str:
            '''Host.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-postgresqlparameters.html#cfn-quicksight-datasource-postgresqlparameters-host
            '''
            result = self._values.get("host")
            assert result is not None, "Required property 'host' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def port(self) -> jsii.Number:
            '''Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-postgresqlparameters.html#cfn-quicksight-datasource-postgresqlparameters-port
            '''
            result = self._values.get("port")
            assert result is not None, "Required property 'port' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PostgreSqlParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.PrestoParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"catalog": "catalog", "host": "host", "port": "port"},
    )
    class PrestoParametersProperty:
        def __init__(
            self,
            *,
            catalog: builtins.str,
            host: builtins.str,
            port: jsii.Number,
        ) -> None:
            '''The parameters for Presto.

            :param catalog: Catalog.
            :param host: Host.
            :param port: Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-prestoparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                presto_parameters_property = quicksight.CfnDataSource.PrestoParametersProperty(
                    catalog="catalog",
                    host="host",
                    port=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "catalog": catalog,
                "host": host,
                "port": port,
            }

        @builtins.property
        def catalog(self) -> builtins.str:
            '''Catalog.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-prestoparameters.html#cfn-quicksight-datasource-prestoparameters-catalog
            '''
            result = self._values.get("catalog")
            assert result is not None, "Required property 'catalog' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def host(self) -> builtins.str:
            '''Host.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-prestoparameters.html#cfn-quicksight-datasource-prestoparameters-host
            '''
            result = self._values.get("host")
            assert result is not None, "Required property 'host' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def port(self) -> jsii.Number:
            '''Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-prestoparameters.html#cfn-quicksight-datasource-prestoparameters-port
            '''
            result = self._values.get("port")
            assert result is not None, "Required property 'port' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PrestoParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.RdsParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"database": "database", "instance_id": "instanceId"},
    )
    class RdsParametersProperty:
        def __init__(
            self,
            *,
            database: builtins.str,
            instance_id: builtins.str,
        ) -> None:
            '''The parameters for Amazon RDS.

            :param database: Database.
            :param instance_id: Instance ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-rdsparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                rds_parameters_property = quicksight.CfnDataSource.RdsParametersProperty(
                    database="database",
                    instance_id="instanceId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database": database,
                "instance_id": instance_id,
            }

        @builtins.property
        def database(self) -> builtins.str:
            '''Database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-rdsparameters.html#cfn-quicksight-datasource-rdsparameters-database
            '''
            result = self._values.get("database")
            assert result is not None, "Required property 'database' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def instance_id(self) -> builtins.str:
            '''Instance ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-rdsparameters.html#cfn-quicksight-datasource-rdsparameters-instanceid
            '''
            result = self._values.get("instance_id")
            assert result is not None, "Required property 'instance_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RdsParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.RedshiftParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "database": "database",
            "cluster_id": "clusterId",
            "host": "host",
            "port": "port",
        },
    )
    class RedshiftParametersProperty:
        def __init__(
            self,
            *,
            database: builtins.str,
            cluster_id: typing.Optional[builtins.str] = None,
            host: typing.Optional[builtins.str] = None,
            port: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The parameters for Amazon Redshift.

            The ``ClusterId`` field can be blank if ``Host`` and ``Port`` are both set. The ``Host`` and ``Port`` fields can be blank if the ``ClusterId`` field is set.

            :param database: Database.
            :param cluster_id: Cluster ID. This field can be blank if the ``Host`` and ``Port`` are provided.
            :param host: Host. This field can be blank if ``ClusterId`` is provided.
            :param port: Port. This field can be blank if the ``ClusterId`` is provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-redshiftparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                redshift_parameters_property = quicksight.CfnDataSource.RedshiftParametersProperty(
                    database="database",
                
                    # the properties below are optional
                    cluster_id="clusterId",
                    host="host",
                    port=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database": database,
            }
            if cluster_id is not None:
                self._values["cluster_id"] = cluster_id
            if host is not None:
                self._values["host"] = host
            if port is not None:
                self._values["port"] = port

        @builtins.property
        def database(self) -> builtins.str:
            '''Database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-redshiftparameters.html#cfn-quicksight-datasource-redshiftparameters-database
            '''
            result = self._values.get("database")
            assert result is not None, "Required property 'database' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def cluster_id(self) -> typing.Optional[builtins.str]:
            '''Cluster ID.

            This field can be blank if the ``Host`` and ``Port`` are provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-redshiftparameters.html#cfn-quicksight-datasource-redshiftparameters-clusterid
            '''
            result = self._values.get("cluster_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def host(self) -> typing.Optional[builtins.str]:
            '''Host.

            This field can be blank if ``ClusterId`` is provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-redshiftparameters.html#cfn-quicksight-datasource-redshiftparameters-host
            '''
            result = self._values.get("host")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def port(self) -> typing.Optional[jsii.Number]:
            '''Port.

            This field can be blank if the ``ClusterId`` is provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-redshiftparameters.html#cfn-quicksight-datasource-redshiftparameters-port
            '''
            result = self._values.get("port")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RedshiftParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.ResourcePermissionProperty",
        jsii_struct_bases=[],
        name_mapping={"actions": "actions", "principal": "principal"},
    )
    class ResourcePermissionProperty:
        def __init__(
            self,
            *,
            actions: typing.Sequence[builtins.str],
            principal: builtins.str,
        ) -> None:
            '''Permission for the resource.

            :param actions: The IAM action to grant or revoke permissions on.
            :param principal: The Amazon Resource Name (ARN) of the principal. This can be one of the following:. - The ARN of an Amazon QuickSight user or group associated with a data source or dataset. (This is common.) - The ARN of an Amazon QuickSight user, group, or namespace associated with an analysis, dashboard, template, or theme. (This is common.) - The ARN of an AWS account root: This is an IAM ARN rather than a Amazon QuickSight ARN. Use this option only to share resources (templates) across AWS accounts . (This is less common.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-resourcepermission.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                resource_permission_property = quicksight.CfnDataSource.ResourcePermissionProperty(
                    actions=["actions"],
                    principal="principal"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "actions": actions,
                "principal": principal,
            }

        @builtins.property
        def actions(self) -> typing.List[builtins.str]:
            '''The IAM action to grant or revoke permissions on.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-resourcepermission.html#cfn-quicksight-datasource-resourcepermission-actions
            '''
            result = self._values.get("actions")
            assert result is not None, "Required property 'actions' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def principal(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the principal. This can be one of the following:.

            - The ARN of an Amazon QuickSight user or group associated with a data source or dataset. (This is common.)
            - The ARN of an Amazon QuickSight user, group, or namespace associated with an analysis, dashboard, template, or theme. (This is common.)
            - The ARN of an AWS account root: This is an IAM ARN rather than a Amazon QuickSight ARN. Use this option only to share resources (templates) across AWS accounts . (This is less common.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-resourcepermission.html#cfn-quicksight-datasource-resourcepermission-principal
            '''
            result = self._values.get("principal")
            assert result is not None, "Required property 'principal' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourcePermissionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.S3ParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"manifest_file_location": "manifestFileLocation"},
    )
    class S3ParametersProperty:
        def __init__(
            self,
            *,
            manifest_file_location: typing.Union["CfnDataSource.ManifestFileLocationProperty", _IResolvable_da3f097b],
        ) -> None:
            '''The parameters for S3.

            :param manifest_file_location: Location of the Amazon S3 manifest file. This is NULL if the manifest file was uploaded into Amazon QuickSight.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-s3parameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                s3_parameters_property = quicksight.CfnDataSource.S3ParametersProperty(
                    manifest_file_location=quicksight.CfnDataSource.ManifestFileLocationProperty(
                        bucket="bucket",
                        key="key"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "manifest_file_location": manifest_file_location,
            }

        @builtins.property
        def manifest_file_location(
            self,
        ) -> typing.Union["CfnDataSource.ManifestFileLocationProperty", _IResolvable_da3f097b]:
            '''Location of the Amazon S3 manifest file.

            This is NULL if the manifest file was uploaded into Amazon QuickSight.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-s3parameters.html#cfn-quicksight-datasource-s3parameters-manifestfilelocation
            '''
            result = self._values.get("manifest_file_location")
            assert result is not None, "Required property 'manifest_file_location' is missing"
            return typing.cast(typing.Union["CfnDataSource.ManifestFileLocationProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3ParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.SnowflakeParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "database": "database",
            "host": "host",
            "warehouse": "warehouse",
        },
    )
    class SnowflakeParametersProperty:
        def __init__(
            self,
            *,
            database: builtins.str,
            host: builtins.str,
            warehouse: builtins.str,
        ) -> None:
            '''The parameters for Snowflake.

            :param database: Database.
            :param host: Host.
            :param warehouse: Warehouse.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-snowflakeparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                snowflake_parameters_property = quicksight.CfnDataSource.SnowflakeParametersProperty(
                    database="database",
                    host="host",
                    warehouse="warehouse"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database": database,
                "host": host,
                "warehouse": warehouse,
            }

        @builtins.property
        def database(self) -> builtins.str:
            '''Database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-snowflakeparameters.html#cfn-quicksight-datasource-snowflakeparameters-database
            '''
            result = self._values.get("database")
            assert result is not None, "Required property 'database' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def host(self) -> builtins.str:
            '''Host.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-snowflakeparameters.html#cfn-quicksight-datasource-snowflakeparameters-host
            '''
            result = self._values.get("host")
            assert result is not None, "Required property 'host' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def warehouse(self) -> builtins.str:
            '''Warehouse.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-snowflakeparameters.html#cfn-quicksight-datasource-snowflakeparameters-warehouse
            '''
            result = self._values.get("warehouse")
            assert result is not None, "Required property 'warehouse' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SnowflakeParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.SparkParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"host": "host", "port": "port"},
    )
    class SparkParametersProperty:
        def __init__(self, *, host: builtins.str, port: jsii.Number) -> None:
            '''The parameters for Spark.

            :param host: Host.
            :param port: Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-sparkparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                spark_parameters_property = quicksight.CfnDataSource.SparkParametersProperty(
                    host="host",
                    port=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "host": host,
                "port": port,
            }

        @builtins.property
        def host(self) -> builtins.str:
            '''Host.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-sparkparameters.html#cfn-quicksight-datasource-sparkparameters-host
            '''
            result = self._values.get("host")
            assert result is not None, "Required property 'host' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def port(self) -> jsii.Number:
            '''Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-sparkparameters.html#cfn-quicksight-datasource-sparkparameters-port
            '''
            result = self._values.get("port")
            assert result is not None, "Required property 'port' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SparkParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.SqlServerParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"database": "database", "host": "host", "port": "port"},
    )
    class SqlServerParametersProperty:
        def __init__(
            self,
            *,
            database: builtins.str,
            host: builtins.str,
            port: jsii.Number,
        ) -> None:
            '''The parameters for SQL Server.

            :param database: Database.
            :param host: Host.
            :param port: Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-sqlserverparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                sql_server_parameters_property = quicksight.CfnDataSource.SqlServerParametersProperty(
                    database="database",
                    host="host",
                    port=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database": database,
                "host": host,
                "port": port,
            }

        @builtins.property
        def database(self) -> builtins.str:
            '''Database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-sqlserverparameters.html#cfn-quicksight-datasource-sqlserverparameters-database
            '''
            result = self._values.get("database")
            assert result is not None, "Required property 'database' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def host(self) -> builtins.str:
            '''Host.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-sqlserverparameters.html#cfn-quicksight-datasource-sqlserverparameters-host
            '''
            result = self._values.get("host")
            assert result is not None, "Required property 'host' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def port(self) -> jsii.Number:
            '''Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-sqlserverparameters.html#cfn-quicksight-datasource-sqlserverparameters-port
            '''
            result = self._values.get("port")
            assert result is not None, "Required property 'port' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SqlServerParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.SslPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"disable_ssl": "disableSsl"},
    )
    class SslPropertiesProperty:
        def __init__(
            self,
            *,
            disable_ssl: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Secure Socket Layer (SSL) properties that apply when Amazon QuickSight connects to your underlying data source.

            :param disable_ssl: A Boolean option to control whether SSL should be disabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-sslproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                ssl_properties_property = quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if disable_ssl is not None:
                self._values["disable_ssl"] = disable_ssl

        @builtins.property
        def disable_ssl(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''A Boolean option to control whether SSL should be disabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-sslproperties.html#cfn-quicksight-datasource-sslproperties-disablessl
            '''
            result = self._values.get("disable_ssl")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SslPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.TeradataParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"database": "database", "host": "host", "port": "port"},
    )
    class TeradataParametersProperty:
        def __init__(
            self,
            *,
            database: builtins.str,
            host: builtins.str,
            port: jsii.Number,
        ) -> None:
            '''The parameters for Teradata.

            :param database: Database.
            :param host: Host.
            :param port: Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-teradataparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                teradata_parameters_property = quicksight.CfnDataSource.TeradataParametersProperty(
                    database="database",
                    host="host",
                    port=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database": database,
                "host": host,
                "port": port,
            }

        @builtins.property
        def database(self) -> builtins.str:
            '''Database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-teradataparameters.html#cfn-quicksight-datasource-teradataparameters-database
            '''
            result = self._values.get("database")
            assert result is not None, "Required property 'database' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def host(self) -> builtins.str:
            '''Host.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-teradataparameters.html#cfn-quicksight-datasource-teradataparameters-host
            '''
            result = self._values.get("host")
            assert result is not None, "Required property 'host' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def port(self) -> jsii.Number:
            '''Port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-teradataparameters.html#cfn-quicksight-datasource-teradataparameters-port
            '''
            result = self._values.get("port")
            assert result is not None, "Required property 'port' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TeradataParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSource.VpcConnectionPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"vpc_connection_arn": "vpcConnectionArn"},
    )
    class VpcConnectionPropertiesProperty:
        def __init__(self, *, vpc_connection_arn: builtins.str) -> None:
            '''VPC connection properties.

            :param vpc_connection_arn: The Amazon Resource Name (ARN) for the VPC connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-vpcconnectionproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                vpc_connection_properties_property = quicksight.CfnDataSource.VpcConnectionPropertiesProperty(
                    vpc_connection_arn="vpcConnectionArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "vpc_connection_arn": vpc_connection_arn,
            }

        @builtins.property
        def vpc_connection_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) for the VPC connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-datasource-vpcconnectionproperties.html#cfn-quicksight-datasource-vpcconnectionproperties-vpcconnectionarn
            '''
            result = self._values.get("vpc_connection_arn")
            assert result is not None, "Required property 'vpc_connection_arn' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VpcConnectionPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_quicksight.CfnDataSourceProps",
    jsii_struct_bases=[],
    name_mapping={
        "alternate_data_source_parameters": "alternateDataSourceParameters",
        "aws_account_id": "awsAccountId",
        "credentials": "credentials",
        "data_source_id": "dataSourceId",
        "data_source_parameters": "dataSourceParameters",
        "error_info": "errorInfo",
        "name": "name",
        "permissions": "permissions",
        "ssl_properties": "sslProperties",
        "tags": "tags",
        "type": "type",
        "vpc_connection_properties": "vpcConnectionProperties",
    },
)
class CfnDataSourceProps:
    def __init__(
        self,
        *,
        alternate_data_source_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnDataSource.DataSourceParametersProperty, _IResolvable_da3f097b]]]] = None,
        aws_account_id: typing.Optional[builtins.str] = None,
        credentials: typing.Optional[typing.Union[CfnDataSource.DataSourceCredentialsProperty, _IResolvable_da3f097b]] = None,
        data_source_id: typing.Optional[builtins.str] = None,
        data_source_parameters: typing.Optional[typing.Union[CfnDataSource.DataSourceParametersProperty, _IResolvable_da3f097b]] = None,
        error_info: typing.Optional[typing.Union[CfnDataSource.DataSourceErrorInfoProperty, _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        permissions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnDataSource.ResourcePermissionProperty, _IResolvable_da3f097b]]]] = None,
        ssl_properties: typing.Optional[typing.Union[CfnDataSource.SslPropertiesProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        type: typing.Optional[builtins.str] = None,
        vpc_connection_properties: typing.Optional[typing.Union[CfnDataSource.VpcConnectionPropertiesProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDataSource``.

        :param alternate_data_source_parameters: A set of alternate data source parameters that you want to share for the credentials stored with this data source. The credentials are applied in tandem with the data source parameters when you copy a data source by using a create or update request. The API operation compares the ``DataSourceParameters`` structure that's in the request with the structures in the ``AlternateDataSourceParameters`` allow list. If the structures are an exact match, the request is allowed to use the credentials from this existing data source. If the ``AlternateDataSourceParameters`` list is null, the ``Credentials`` originally used with this ``DataSourceParameters`` are automatically allowed.
        :param aws_account_id: The AWS account ID.
        :param credentials: The credentials Amazon QuickSight that uses to connect to your underlying source. Currently, only credentials based on user name and password are supported.
        :param data_source_id: An ID for the data source. This ID is unique per AWS Region for each AWS account.
        :param data_source_parameters: The parameters that Amazon QuickSight uses to connect to your underlying source.
        :param error_info: Error information from the last update or the creation of the data source.
        :param name: A display name for the data source.
        :param permissions: A list of resource permissions on the data source.
        :param ssl_properties: Secure Socket Layer (SSL) properties that apply when Amazon QuickSight connects to your underlying source.
        :param tags: Contains a map of the key-value pairs for the resource tag or tags assigned to the data source.
        :param type: The type of the data source. To return a list of all data sources, use ``ListDataSources`` . Use ``AMAZON_ELASTICSEARCH`` for Amazon OpenSearch Service .
        :param vpc_connection_properties: Use this parameter only when you want Amazon QuickSight to use a VPC connection when connecting to your underlying source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_quicksight as quicksight
            
            cfn_data_source_props = quicksight.CfnDataSourceProps(
                alternate_data_source_parameters=[quicksight.CfnDataSource.DataSourceParametersProperty(
                    amazon_elasticsearch_parameters=quicksight.CfnDataSource.AmazonElasticsearchParametersProperty(
                        domain="domain"
                    ),
                    amazon_open_search_parameters=quicksight.CfnDataSource.AmazonOpenSearchParametersProperty(
                        domain="domain"
                    ),
                    athena_parameters=quicksight.CfnDataSource.AthenaParametersProperty(
                        work_group="workGroup"
                    ),
                    aurora_parameters=quicksight.CfnDataSource.AuroraParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    aurora_postgre_sql_parameters=quicksight.CfnDataSource.AuroraPostgreSqlParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    maria_db_parameters=quicksight.CfnDataSource.MariaDbParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    my_sql_parameters=quicksight.CfnDataSource.MySqlParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    oracle_parameters=quicksight.CfnDataSource.OracleParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    postgre_sql_parameters=quicksight.CfnDataSource.PostgreSqlParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    presto_parameters=quicksight.CfnDataSource.PrestoParametersProperty(
                        catalog="catalog",
                        host="host",
                        port=123
                    ),
                    rds_parameters=quicksight.CfnDataSource.RdsParametersProperty(
                        database="database",
                        instance_id="instanceId"
                    ),
                    redshift_parameters=quicksight.CfnDataSource.RedshiftParametersProperty(
                        database="database",
            
                        # the properties below are optional
                        cluster_id="clusterId",
                        host="host",
                        port=123
                    ),
                    s3_parameters=quicksight.CfnDataSource.S3ParametersProperty(
                        manifest_file_location=quicksight.CfnDataSource.ManifestFileLocationProperty(
                            bucket="bucket",
                            key="key"
                        )
                    ),
                    snowflake_parameters=quicksight.CfnDataSource.SnowflakeParametersProperty(
                        database="database",
                        host="host",
                        warehouse="warehouse"
                    ),
                    spark_parameters=quicksight.CfnDataSource.SparkParametersProperty(
                        host="host",
                        port=123
                    ),
                    sql_server_parameters=quicksight.CfnDataSource.SqlServerParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    teradata_parameters=quicksight.CfnDataSource.TeradataParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    )
                )],
                aws_account_id="awsAccountId",
                credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
                    copy_source_arn="copySourceArn",
                    credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                        password="password",
                        username="username",
            
                        # the properties below are optional
                        alternate_data_source_parameters=[quicksight.CfnDataSource.DataSourceParametersProperty(
                            amazon_elasticsearch_parameters=quicksight.CfnDataSource.AmazonElasticsearchParametersProperty(
                                domain="domain"
                            ),
                            amazon_open_search_parameters=quicksight.CfnDataSource.AmazonOpenSearchParametersProperty(
                                domain="domain"
                            ),
                            athena_parameters=quicksight.CfnDataSource.AthenaParametersProperty(
                                work_group="workGroup"
                            ),
                            aurora_parameters=quicksight.CfnDataSource.AuroraParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            ),
                            aurora_postgre_sql_parameters=quicksight.CfnDataSource.AuroraPostgreSqlParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            ),
                            maria_db_parameters=quicksight.CfnDataSource.MariaDbParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            ),
                            my_sql_parameters=quicksight.CfnDataSource.MySqlParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            ),
                            oracle_parameters=quicksight.CfnDataSource.OracleParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            ),
                            postgre_sql_parameters=quicksight.CfnDataSource.PostgreSqlParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            ),
                            presto_parameters=quicksight.CfnDataSource.PrestoParametersProperty(
                                catalog="catalog",
                                host="host",
                                port=123
                            ),
                            rds_parameters=quicksight.CfnDataSource.RdsParametersProperty(
                                database="database",
                                instance_id="instanceId"
                            ),
                            redshift_parameters=quicksight.CfnDataSource.RedshiftParametersProperty(
                                database="database",
            
                                # the properties below are optional
                                cluster_id="clusterId",
                                host="host",
                                port=123
                            ),
                            s3_parameters=quicksight.CfnDataSource.S3ParametersProperty(
                                manifest_file_location=quicksight.CfnDataSource.ManifestFileLocationProperty(
                                    bucket="bucket",
                                    key="key"
                                )
                            ),
                            snowflake_parameters=quicksight.CfnDataSource.SnowflakeParametersProperty(
                                database="database",
                                host="host",
                                warehouse="warehouse"
                            ),
                            spark_parameters=quicksight.CfnDataSource.SparkParametersProperty(
                                host="host",
                                port=123
                            ),
                            sql_server_parameters=quicksight.CfnDataSource.SqlServerParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            ),
                            teradata_parameters=quicksight.CfnDataSource.TeradataParametersProperty(
                                database="database",
                                host="host",
                                port=123
                            )
                        )]
                    )
                ),
                data_source_id="dataSourceId",
                data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
                    amazon_elasticsearch_parameters=quicksight.CfnDataSource.AmazonElasticsearchParametersProperty(
                        domain="domain"
                    ),
                    amazon_open_search_parameters=quicksight.CfnDataSource.AmazonOpenSearchParametersProperty(
                        domain="domain"
                    ),
                    athena_parameters=quicksight.CfnDataSource.AthenaParametersProperty(
                        work_group="workGroup"
                    ),
                    aurora_parameters=quicksight.CfnDataSource.AuroraParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    aurora_postgre_sql_parameters=quicksight.CfnDataSource.AuroraPostgreSqlParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    maria_db_parameters=quicksight.CfnDataSource.MariaDbParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    my_sql_parameters=quicksight.CfnDataSource.MySqlParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    oracle_parameters=quicksight.CfnDataSource.OracleParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    postgre_sql_parameters=quicksight.CfnDataSource.PostgreSqlParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    presto_parameters=quicksight.CfnDataSource.PrestoParametersProperty(
                        catalog="catalog",
                        host="host",
                        port=123
                    ),
                    rds_parameters=quicksight.CfnDataSource.RdsParametersProperty(
                        database="database",
                        instance_id="instanceId"
                    ),
                    redshift_parameters=quicksight.CfnDataSource.RedshiftParametersProperty(
                        database="database",
            
                        # the properties below are optional
                        cluster_id="clusterId",
                        host="host",
                        port=123
                    ),
                    s3_parameters=quicksight.CfnDataSource.S3ParametersProperty(
                        manifest_file_location=quicksight.CfnDataSource.ManifestFileLocationProperty(
                            bucket="bucket",
                            key="key"
                        )
                    ),
                    snowflake_parameters=quicksight.CfnDataSource.SnowflakeParametersProperty(
                        database="database",
                        host="host",
                        warehouse="warehouse"
                    ),
                    spark_parameters=quicksight.CfnDataSource.SparkParametersProperty(
                        host="host",
                        port=123
                    ),
                    sql_server_parameters=quicksight.CfnDataSource.SqlServerParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    ),
                    teradata_parameters=quicksight.CfnDataSource.TeradataParametersProperty(
                        database="database",
                        host="host",
                        port=123
                    )
                ),
                error_info=quicksight.CfnDataSource.DataSourceErrorInfoProperty(
                    message="message",
                    type="type"
                ),
                name="name",
                permissions=[quicksight.CfnDataSource.ResourcePermissionProperty(
                    actions=["actions"],
                    principal="principal"
                )],
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                type="type",
                vpc_connection_properties=quicksight.CfnDataSource.VpcConnectionPropertiesProperty(
                    vpc_connection_arn="vpcConnectionArn"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if alternate_data_source_parameters is not None:
            self._values["alternate_data_source_parameters"] = alternate_data_source_parameters
        if aws_account_id is not None:
            self._values["aws_account_id"] = aws_account_id
        if credentials is not None:
            self._values["credentials"] = credentials
        if data_source_id is not None:
            self._values["data_source_id"] = data_source_id
        if data_source_parameters is not None:
            self._values["data_source_parameters"] = data_source_parameters
        if error_info is not None:
            self._values["error_info"] = error_info
        if name is not None:
            self._values["name"] = name
        if permissions is not None:
            self._values["permissions"] = permissions
        if ssl_properties is not None:
            self._values["ssl_properties"] = ssl_properties
        if tags is not None:
            self._values["tags"] = tags
        if type is not None:
            self._values["type"] = type
        if vpc_connection_properties is not None:
            self._values["vpc_connection_properties"] = vpc_connection_properties

    @builtins.property
    def alternate_data_source_parameters(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataSource.DataSourceParametersProperty, _IResolvable_da3f097b]]]]:
        '''A set of alternate data source parameters that you want to share for the credentials stored with this data source.

        The credentials are applied in tandem with the data source parameters when you copy a data source by using a create or update request. The API operation compares the ``DataSourceParameters`` structure that's in the request with the structures in the ``AlternateDataSourceParameters`` allow list. If the structures are an exact match, the request is allowed to use the credentials from this existing data source. If the ``AlternateDataSourceParameters`` list is null, the ``Credentials`` originally used with this ``DataSourceParameters`` are automatically allowed.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-alternatedatasourceparameters
        '''
        result = self._values.get("alternate_data_source_parameters")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataSource.DataSourceParametersProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def aws_account_id(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-awsaccountid
        '''
        result = self._values.get("aws_account_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def credentials(
        self,
    ) -> typing.Optional[typing.Union[CfnDataSource.DataSourceCredentialsProperty, _IResolvable_da3f097b]]:
        '''The credentials Amazon QuickSight that uses to connect to your underlying source.

        Currently, only credentials based on user name and password are supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-credentials
        '''
        result = self._values.get("credentials")
        return typing.cast(typing.Optional[typing.Union[CfnDataSource.DataSourceCredentialsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def data_source_id(self) -> typing.Optional[builtins.str]:
        '''An ID for the data source.

        This ID is unique per AWS Region for each AWS account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-datasourceid
        '''
        result = self._values.get("data_source_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def data_source_parameters(
        self,
    ) -> typing.Optional[typing.Union[CfnDataSource.DataSourceParametersProperty, _IResolvable_da3f097b]]:
        '''The parameters that Amazon QuickSight uses to connect to your underlying source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-datasourceparameters
        '''
        result = self._values.get("data_source_parameters")
        return typing.cast(typing.Optional[typing.Union[CfnDataSource.DataSourceParametersProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def error_info(
        self,
    ) -> typing.Optional[typing.Union[CfnDataSource.DataSourceErrorInfoProperty, _IResolvable_da3f097b]]:
        '''Error information from the last update or the creation of the data source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-errorinfo
        '''
        result = self._values.get("error_info")
        return typing.cast(typing.Optional[typing.Union[CfnDataSource.DataSourceErrorInfoProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''A display name for the data source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def permissions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataSource.ResourcePermissionProperty, _IResolvable_da3f097b]]]]:
        '''A list of resource permissions on the data source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-permissions
        '''
        result = self._values.get("permissions")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataSource.ResourcePermissionProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def ssl_properties(
        self,
    ) -> typing.Optional[typing.Union[CfnDataSource.SslPropertiesProperty, _IResolvable_da3f097b]]:
        '''Secure Socket Layer (SSL) properties that apply when Amazon QuickSight connects to your underlying source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-sslproperties
        '''
        result = self._values.get("ssl_properties")
        return typing.cast(typing.Optional[typing.Union[CfnDataSource.SslPropertiesProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Contains a map of the key-value pairs for the resource tag or tags assigned to the data source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def type(self) -> typing.Optional[builtins.str]:
        '''The type of the data source. To return a list of all data sources, use ``ListDataSources`` .

        Use ``AMAZON_ELASTICSEARCH`` for Amazon OpenSearch Service .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-type
        '''
        result = self._values.get("type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def vpc_connection_properties(
        self,
    ) -> typing.Optional[typing.Union[CfnDataSource.VpcConnectionPropertiesProperty, _IResolvable_da3f097b]]:
        '''Use this parameter only when you want Amazon QuickSight to use a VPC connection when connecting to your underlying source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-datasource.html#cfn-quicksight-datasource-vpcconnectionproperties
        '''
        result = self._values.get("vpc_connection_properties")
        return typing.cast(typing.Optional[typing.Union[CfnDataSource.VpcConnectionPropertiesProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDataSourceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnTemplate(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_quicksight.CfnTemplate",
):
    '''A CloudFormation ``AWS::QuickSight::Template``.

    Creates a template from an existing Amazon QuickSight analysis or template. You can use the resulting template to create a dashboard.

    A *template* is an entity in Amazon QuickSight that encapsulates the metadata required to create an analysis and that you can use to create s dashboard. A template adds a layer of abstraction by using placeholders to replace the dataset associated with the analysis. You can use templates to create dashboards by replacing dataset placeholders with datasets that follow the same schema that was used to create the source analysis and template.

    :cloudformationResource: AWS::QuickSight::Template
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_quicksight as quicksight
        
        cfn_template = quicksight.CfnTemplate(self, "MyCfnTemplate",
            aws_account_id="awsAccountId",
            source_entity=quicksight.CfnTemplate.TemplateSourceEntityProperty(
                source_analysis=quicksight.CfnTemplate.TemplateSourceAnalysisProperty(
                    arn="arn",
                    data_set_references=[quicksight.CfnTemplate.DataSetReferenceProperty(
                        data_set_arn="dataSetArn",
                        data_set_placeholder="dataSetPlaceholder"
                    )]
                ),
                source_template=quicksight.CfnTemplate.TemplateSourceTemplateProperty(
                    arn="arn"
                )
            ),
            template_id="templateId",
        
            # the properties below are optional
            name="name",
            permissions=[quicksight.CfnTemplate.ResourcePermissionProperty(
                actions=["actions"],
                principal="principal"
            )],
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            version_description="versionDescription"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        aws_account_id: builtins.str,
        source_entity: typing.Union["CfnTemplate.TemplateSourceEntityProperty", _IResolvable_da3f097b],
        template_id: builtins.str,
        name: typing.Optional[builtins.str] = None,
        permissions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTemplate.ResourcePermissionProperty", _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        version_description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::QuickSight::Template``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param aws_account_id: The ID for the AWS account that the group is in. You use the ID for the AWS account that contains your Amazon QuickSight account.
        :param source_entity: The entity that you are using as a source when you create the template. In ``SourceEntity`` , you specify the type of object you're using as source: ``SourceTemplate`` for a template or ``SourceAnalysis`` for an analysis. Both of these require an Amazon Resource Name (ARN). For ``SourceTemplate`` , specify the ARN of the source template. For ``SourceAnalysis`` , specify the ARN of the source analysis. The ``SourceTemplate`` ARN can contain any AWS account and any Amazon QuickSight-supported AWS Region . Use the ``DataSetReferences`` entity within ``SourceTemplate`` or ``SourceAnalysis`` to list the replacement datasets for the placeholders listed in the original. The schema in each dataset must match its placeholder.
        :param template_id: An ID for the template that you want to create. This template is unique per AWS Region ; in each AWS account.
        :param name: A display name for the template.
        :param permissions: A list of resource permissions to be set on the template.
        :param tags: Contains a map of the key-value pairs for the resource tag or tags assigned to the resource.
        :param version_description: A description of the current template version being created. This API operation creates the first version of the template. Every time ``UpdateTemplate`` is called, a new version is created. Each version of the template maintains a description of the version in the ``VersionDescription`` field.
        '''
        props = CfnTemplateProps(
            aws_account_id=aws_account_id,
            source_entity=source_entity,
            template_id=template_id,
            name=name,
            permissions=permissions,
            tags=tags,
            version_description=version_description,
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
        '''The Amazon Resource Name (ARN) of the template.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCreatedTime")
    def attr_created_time(self) -> builtins.str:
        '''The time this template was created.

        :cloudformationAttribute: CreatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLastUpdatedTime")
    def attr_last_updated_time(self) -> builtins.str:
        '''The time this template was last updated.

        :cloudformationAttribute: LastUpdatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLastUpdatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Contains a map of the key-value pairs for the resource tag or tags assigned to the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html#cfn-quicksight-template-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="awsAccountId")
    def aws_account_id(self) -> builtins.str:
        '''The ID for the AWS account that the group is in.

        You use the ID for the AWS account that contains your Amazon QuickSight account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html#cfn-quicksight-template-awsaccountid
        '''
        return typing.cast(builtins.str, jsii.get(self, "awsAccountId"))

    @aws_account_id.setter
    def aws_account_id(self, value: builtins.str) -> None:
        jsii.set(self, "awsAccountId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceEntity")
    def source_entity(
        self,
    ) -> typing.Union["CfnTemplate.TemplateSourceEntityProperty", _IResolvable_da3f097b]:
        '''The entity that you are using as a source when you create the template.

        In ``SourceEntity`` , you specify the type of object you're using as source: ``SourceTemplate`` for a template or ``SourceAnalysis`` for an analysis. Both of these require an Amazon Resource Name (ARN). For ``SourceTemplate`` , specify the ARN of the source template. For ``SourceAnalysis`` , specify the ARN of the source analysis. The ``SourceTemplate`` ARN can contain any AWS account and any Amazon QuickSight-supported AWS Region .

        Use the ``DataSetReferences`` entity within ``SourceTemplate`` or ``SourceAnalysis`` to list the replacement datasets for the placeholders listed in the original. The schema in each dataset must match its placeholder.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html#cfn-quicksight-template-sourceentity
        '''
        return typing.cast(typing.Union["CfnTemplate.TemplateSourceEntityProperty", _IResolvable_da3f097b], jsii.get(self, "sourceEntity"))

    @source_entity.setter
    def source_entity(
        self,
        value: typing.Union["CfnTemplate.TemplateSourceEntityProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "sourceEntity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="templateId")
    def template_id(self) -> builtins.str:
        '''An ID for the template that you want to create.

        This template is unique per AWS Region ; in each AWS account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html#cfn-quicksight-template-templateid
        '''
        return typing.cast(builtins.str, jsii.get(self, "templateId"))

    @template_id.setter
    def template_id(self, value: builtins.str) -> None:
        jsii.set(self, "templateId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''A display name for the template.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html#cfn-quicksight-template-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="permissions")
    def permissions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTemplate.ResourcePermissionProperty", _IResolvable_da3f097b]]]]:
        '''A list of resource permissions to be set on the template.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html#cfn-quicksight-template-permissions
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTemplate.ResourcePermissionProperty", _IResolvable_da3f097b]]]], jsii.get(self, "permissions"))

    @permissions.setter
    def permissions(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTemplate.ResourcePermissionProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "permissions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="versionDescription")
    def version_description(self) -> typing.Optional[builtins.str]:
        '''A description of the current template version being created.

        This API operation creates the first version of the template. Every time ``UpdateTemplate`` is called, a new version is created. Each version of the template maintains a description of the version in the ``VersionDescription`` field.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html#cfn-quicksight-template-versiondescription
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "versionDescription"))

    @version_description.setter
    def version_description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "versionDescription", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTemplate.DataSetReferenceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "data_set_arn": "dataSetArn",
            "data_set_placeholder": "dataSetPlaceholder",
        },
    )
    class DataSetReferenceProperty:
        def __init__(
            self,
            *,
            data_set_arn: builtins.str,
            data_set_placeholder: builtins.str,
        ) -> None:
            '''Dataset reference.

            :param data_set_arn: Dataset Amazon Resource Name (ARN).
            :param data_set_placeholder: Dataset placeholder.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-template-datasetreference.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                data_set_reference_property = quicksight.CfnTemplate.DataSetReferenceProperty(
                    data_set_arn="dataSetArn",
                    data_set_placeholder="dataSetPlaceholder"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "data_set_arn": data_set_arn,
                "data_set_placeholder": data_set_placeholder,
            }

        @builtins.property
        def data_set_arn(self) -> builtins.str:
            '''Dataset Amazon Resource Name (ARN).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-template-datasetreference.html#cfn-quicksight-template-datasetreference-datasetarn
            '''
            result = self._values.get("data_set_arn")
            assert result is not None, "Required property 'data_set_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def data_set_placeholder(self) -> builtins.str:
            '''Dataset placeholder.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-template-datasetreference.html#cfn-quicksight-template-datasetreference-datasetplaceholder
            '''
            result = self._values.get("data_set_placeholder")
            assert result is not None, "Required property 'data_set_placeholder' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataSetReferenceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTemplate.ResourcePermissionProperty",
        jsii_struct_bases=[],
        name_mapping={"actions": "actions", "principal": "principal"},
    )
    class ResourcePermissionProperty:
        def __init__(
            self,
            *,
            actions: typing.Sequence[builtins.str],
            principal: builtins.str,
        ) -> None:
            '''Permission for the resource.

            :param actions: The IAM action to grant or revoke permissions on.
            :param principal: The Amazon Resource Name (ARN) of the principal. This can be one of the following:. - The ARN of an Amazon QuickSight user or group associated with a data source or dataset. (This is common.) - The ARN of an Amazon QuickSight user, group, or namespace associated with an analysis, dashboard, template, or theme. (This is common.) - The ARN of an AWS account root: This is an IAM ARN rather than a Amazon QuickSight ARN. Use this option only to share resources (templates) across AWS accounts . (This is less common.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-template-resourcepermission.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                resource_permission_property = quicksight.CfnTemplate.ResourcePermissionProperty(
                    actions=["actions"],
                    principal="principal"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "actions": actions,
                "principal": principal,
            }

        @builtins.property
        def actions(self) -> typing.List[builtins.str]:
            '''The IAM action to grant or revoke permissions on.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-template-resourcepermission.html#cfn-quicksight-template-resourcepermission-actions
            '''
            result = self._values.get("actions")
            assert result is not None, "Required property 'actions' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def principal(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the principal. This can be one of the following:.

            - The ARN of an Amazon QuickSight user or group associated with a data source or dataset. (This is common.)
            - The ARN of an Amazon QuickSight user, group, or namespace associated with an analysis, dashboard, template, or theme. (This is common.)
            - The ARN of an AWS account root: This is an IAM ARN rather than a Amazon QuickSight ARN. Use this option only to share resources (templates) across AWS accounts . (This is less common.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-template-resourcepermission.html#cfn-quicksight-template-resourcepermission-principal
            '''
            result = self._values.get("principal")
            assert result is not None, "Required property 'principal' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourcePermissionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTemplate.TemplateSourceAnalysisProperty",
        jsii_struct_bases=[],
        name_mapping={"arn": "arn", "data_set_references": "dataSetReferences"},
    )
    class TemplateSourceAnalysisProperty:
        def __init__(
            self,
            *,
            arn: builtins.str,
            data_set_references: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTemplate.DataSetReferenceProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''The source analysis of the template.

            :param arn: The Amazon Resource Name (ARN) of the resource.
            :param data_set_references: A structure containing information about the dataset references used as placeholders in the template.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-template-templatesourceanalysis.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                template_source_analysis_property = quicksight.CfnTemplate.TemplateSourceAnalysisProperty(
                    arn="arn",
                    data_set_references=[quicksight.CfnTemplate.DataSetReferenceProperty(
                        data_set_arn="dataSetArn",
                        data_set_placeholder="dataSetPlaceholder"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
                "data_set_references": data_set_references,
            }

        @builtins.property
        def arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-template-templatesourceanalysis.html#cfn-quicksight-template-templatesourceanalysis-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def data_set_references(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTemplate.DataSetReferenceProperty", _IResolvable_da3f097b]]]:
            '''A structure containing information about the dataset references used as placeholders in the template.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-template-templatesourceanalysis.html#cfn-quicksight-template-templatesourceanalysis-datasetreferences
            '''
            result = self._values.get("data_set_references")
            assert result is not None, "Required property 'data_set_references' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTemplate.DataSetReferenceProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TemplateSourceAnalysisProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTemplate.TemplateSourceEntityProperty",
        jsii_struct_bases=[],
        name_mapping={
            "source_analysis": "sourceAnalysis",
            "source_template": "sourceTemplate",
        },
    )
    class TemplateSourceEntityProperty:
        def __init__(
            self,
            *,
            source_analysis: typing.Optional[typing.Union["CfnTemplate.TemplateSourceAnalysisProperty", _IResolvable_da3f097b]] = None,
            source_template: typing.Optional[typing.Union["CfnTemplate.TemplateSourceTemplateProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The source entity of the template.

            :param source_analysis: The source analysis, if it is based on an analysis.
            :param source_template: The source template, if it is based on an template.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-template-templatesourceentity.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                template_source_entity_property = quicksight.CfnTemplate.TemplateSourceEntityProperty(
                    source_analysis=quicksight.CfnTemplate.TemplateSourceAnalysisProperty(
                        arn="arn",
                        data_set_references=[quicksight.CfnTemplate.DataSetReferenceProperty(
                            data_set_arn="dataSetArn",
                            data_set_placeholder="dataSetPlaceholder"
                        )]
                    ),
                    source_template=quicksight.CfnTemplate.TemplateSourceTemplateProperty(
                        arn="arn"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if source_analysis is not None:
                self._values["source_analysis"] = source_analysis
            if source_template is not None:
                self._values["source_template"] = source_template

        @builtins.property
        def source_analysis(
            self,
        ) -> typing.Optional[typing.Union["CfnTemplate.TemplateSourceAnalysisProperty", _IResolvable_da3f097b]]:
            '''The source analysis, if it is based on an analysis.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-template-templatesourceentity.html#cfn-quicksight-template-templatesourceentity-sourceanalysis
            '''
            result = self._values.get("source_analysis")
            return typing.cast(typing.Optional[typing.Union["CfnTemplate.TemplateSourceAnalysisProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def source_template(
            self,
        ) -> typing.Optional[typing.Union["CfnTemplate.TemplateSourceTemplateProperty", _IResolvable_da3f097b]]:
            '''The source template, if it is based on an template.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-template-templatesourceentity.html#cfn-quicksight-template-templatesourceentity-sourcetemplate
            '''
            result = self._values.get("source_template")
            return typing.cast(typing.Optional[typing.Union["CfnTemplate.TemplateSourceTemplateProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TemplateSourceEntityProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTemplate.TemplateSourceTemplateProperty",
        jsii_struct_bases=[],
        name_mapping={"arn": "arn"},
    )
    class TemplateSourceTemplateProperty:
        def __init__(self, *, arn: builtins.str) -> None:
            '''The source template of the template.

            :param arn: The Amazon Resource Name (ARN) of the resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-template-templatesourcetemplate.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                template_source_template_property = quicksight.CfnTemplate.TemplateSourceTemplateProperty(
                    arn="arn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
            }

        @builtins.property
        def arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-template-templatesourcetemplate.html#cfn-quicksight-template-templatesourcetemplate-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TemplateSourceTemplateProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_quicksight.CfnTemplateProps",
    jsii_struct_bases=[],
    name_mapping={
        "aws_account_id": "awsAccountId",
        "source_entity": "sourceEntity",
        "template_id": "templateId",
        "name": "name",
        "permissions": "permissions",
        "tags": "tags",
        "version_description": "versionDescription",
    },
)
class CfnTemplateProps:
    def __init__(
        self,
        *,
        aws_account_id: builtins.str,
        source_entity: typing.Union[CfnTemplate.TemplateSourceEntityProperty, _IResolvable_da3f097b],
        template_id: builtins.str,
        name: typing.Optional[builtins.str] = None,
        permissions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnTemplate.ResourcePermissionProperty, _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        version_description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnTemplate``.

        :param aws_account_id: The ID for the AWS account that the group is in. You use the ID for the AWS account that contains your Amazon QuickSight account.
        :param source_entity: The entity that you are using as a source when you create the template. In ``SourceEntity`` , you specify the type of object you're using as source: ``SourceTemplate`` for a template or ``SourceAnalysis`` for an analysis. Both of these require an Amazon Resource Name (ARN). For ``SourceTemplate`` , specify the ARN of the source template. For ``SourceAnalysis`` , specify the ARN of the source analysis. The ``SourceTemplate`` ARN can contain any AWS account and any Amazon QuickSight-supported AWS Region . Use the ``DataSetReferences`` entity within ``SourceTemplate`` or ``SourceAnalysis`` to list the replacement datasets for the placeholders listed in the original. The schema in each dataset must match its placeholder.
        :param template_id: An ID for the template that you want to create. This template is unique per AWS Region ; in each AWS account.
        :param name: A display name for the template.
        :param permissions: A list of resource permissions to be set on the template.
        :param tags: Contains a map of the key-value pairs for the resource tag or tags assigned to the resource.
        :param version_description: A description of the current template version being created. This API operation creates the first version of the template. Every time ``UpdateTemplate`` is called, a new version is created. Each version of the template maintains a description of the version in the ``VersionDescription`` field.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_quicksight as quicksight
            
            cfn_template_props = quicksight.CfnTemplateProps(
                aws_account_id="awsAccountId",
                source_entity=quicksight.CfnTemplate.TemplateSourceEntityProperty(
                    source_analysis=quicksight.CfnTemplate.TemplateSourceAnalysisProperty(
                        arn="arn",
                        data_set_references=[quicksight.CfnTemplate.DataSetReferenceProperty(
                            data_set_arn="dataSetArn",
                            data_set_placeholder="dataSetPlaceholder"
                        )]
                    ),
                    source_template=quicksight.CfnTemplate.TemplateSourceTemplateProperty(
                        arn="arn"
                    )
                ),
                template_id="templateId",
            
                # the properties below are optional
                name="name",
                permissions=[quicksight.CfnTemplate.ResourcePermissionProperty(
                    actions=["actions"],
                    principal="principal"
                )],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                version_description="versionDescription"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "aws_account_id": aws_account_id,
            "source_entity": source_entity,
            "template_id": template_id,
        }
        if name is not None:
            self._values["name"] = name
        if permissions is not None:
            self._values["permissions"] = permissions
        if tags is not None:
            self._values["tags"] = tags
        if version_description is not None:
            self._values["version_description"] = version_description

    @builtins.property
    def aws_account_id(self) -> builtins.str:
        '''The ID for the AWS account that the group is in.

        You use the ID for the AWS account that contains your Amazon QuickSight account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html#cfn-quicksight-template-awsaccountid
        '''
        result = self._values.get("aws_account_id")
        assert result is not None, "Required property 'aws_account_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def source_entity(
        self,
    ) -> typing.Union[CfnTemplate.TemplateSourceEntityProperty, _IResolvable_da3f097b]:
        '''The entity that you are using as a source when you create the template.

        In ``SourceEntity`` , you specify the type of object you're using as source: ``SourceTemplate`` for a template or ``SourceAnalysis`` for an analysis. Both of these require an Amazon Resource Name (ARN). For ``SourceTemplate`` , specify the ARN of the source template. For ``SourceAnalysis`` , specify the ARN of the source analysis. The ``SourceTemplate`` ARN can contain any AWS account and any Amazon QuickSight-supported AWS Region .

        Use the ``DataSetReferences`` entity within ``SourceTemplate`` or ``SourceAnalysis`` to list the replacement datasets for the placeholders listed in the original. The schema in each dataset must match its placeholder.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html#cfn-quicksight-template-sourceentity
        '''
        result = self._values.get("source_entity")
        assert result is not None, "Required property 'source_entity' is missing"
        return typing.cast(typing.Union[CfnTemplate.TemplateSourceEntityProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def template_id(self) -> builtins.str:
        '''An ID for the template that you want to create.

        This template is unique per AWS Region ; in each AWS account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html#cfn-quicksight-template-templateid
        '''
        result = self._values.get("template_id")
        assert result is not None, "Required property 'template_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''A display name for the template.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html#cfn-quicksight-template-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def permissions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTemplate.ResourcePermissionProperty, _IResolvable_da3f097b]]]]:
        '''A list of resource permissions to be set on the template.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html#cfn-quicksight-template-permissions
        '''
        result = self._values.get("permissions")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTemplate.ResourcePermissionProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Contains a map of the key-value pairs for the resource tag or tags assigned to the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html#cfn-quicksight-template-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def version_description(self) -> typing.Optional[builtins.str]:
        '''A description of the current template version being created.

        This API operation creates the first version of the template. Every time ``UpdateTemplate`` is called, a new version is created. Each version of the template maintains a description of the version in the ``VersionDescription`` field.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-template.html#cfn-quicksight-template-versiondescription
        '''
        result = self._values.get("version_description")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnTemplateProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnTheme(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_quicksight.CfnTheme",
):
    '''A CloudFormation ``AWS::QuickSight::Theme``.

    Creates a theme.

    A *theme* is set of configuration options for color and layout. Themes apply to analyses and dashboards. For more information, see `Using Themes in Amazon QuickSight <https://docs.aws.amazon.com/quicksight/latest/user/themes-in-quicksight.html>`_ in the *Amazon QuickSight User Guide* .

    :cloudformationResource: AWS::QuickSight::Theme
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_quicksight as quicksight
        
        cfn_theme = quicksight.CfnTheme(self, "MyCfnTheme",
            aws_account_id="awsAccountId",
            theme_id="themeId",
        
            # the properties below are optional
            base_theme_id="baseThemeId",
            configuration=quicksight.CfnTheme.ThemeConfigurationProperty(
                data_color_palette=quicksight.CfnTheme.DataColorPaletteProperty(
                    colors=["colors"],
                    empty_fill_color="emptyFillColor",
                    min_max_gradient=["minMaxGradient"]
                ),
                sheet=quicksight.CfnTheme.SheetStyleProperty(
                    tile=quicksight.CfnTheme.TileStyleProperty(
                        border=quicksight.CfnTheme.BorderStyleProperty(
                            show=False
                        )
                    ),
                    tile_layout=quicksight.CfnTheme.TileLayoutStyleProperty(
                        gutter=quicksight.CfnTheme.GutterStyleProperty(
                            show=False
                        ),
                        margin=quicksight.CfnTheme.MarginStyleProperty(
                            show=False
                        )
                    )
                ),
                typography=quicksight.CfnTheme.TypographyProperty(
                    font_families=[quicksight.CfnTheme.FontProperty(
                        font_family="fontFamily"
                    )]
                ),
                ui_color_palette=quicksight.CfnTheme.UIColorPaletteProperty(
                    accent="accent",
                    accent_foreground="accentForeground",
                    danger="danger",
                    danger_foreground="dangerForeground",
                    dimension="dimension",
                    dimension_foreground="dimensionForeground",
                    measure="measure",
                    measure_foreground="measureForeground",
                    primary_background="primaryBackground",
                    primary_foreground="primaryForeground",
                    secondary_background="secondaryBackground",
                    secondary_foreground="secondaryForeground",
                    success="success",
                    success_foreground="successForeground",
                    warning="warning",
                    warning_foreground="warningForeground"
                )
            ),
            name="name",
            permissions=[quicksight.CfnTheme.ResourcePermissionProperty(
                actions=["actions"],
                principal="principal"
            )],
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            version_description="versionDescription"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        aws_account_id: builtins.str,
        theme_id: builtins.str,
        base_theme_id: typing.Optional[builtins.str] = None,
        configuration: typing.Optional[typing.Union["CfnTheme.ThemeConfigurationProperty", _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        permissions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTheme.ResourcePermissionProperty", _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        version_description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::QuickSight::Theme``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param aws_account_id: The ID of the AWS account where you want to store the new theme.
        :param theme_id: An ID for the theme that you want to create. The theme ID is unique per AWS Region in each AWS account.
        :param base_theme_id: The ID of the theme that a custom theme will inherit from. All themes inherit from one of the starting themes defined by Amazon QuickSight. For a list of the starting themes, use ``ListThemes`` or choose *Themes* from within an analysis.
        :param configuration: The theme configuration, which contains the theme display properties.
        :param name: A display name for the theme.
        :param permissions: A valid grouping of resource permissions to apply to the new theme.
        :param tags: A map of the key-value pairs for the resource tag or tags that you want to add to the resource.
        :param version_description: A description of the first version of the theme that you're creating. Every time ``UpdateTheme`` is called, a new version is created. Each version of the theme has a description of the version in the ``VersionDescription`` field.
        '''
        props = CfnThemeProps(
            aws_account_id=aws_account_id,
            theme_id=theme_id,
            base_theme_id=base_theme_id,
            configuration=configuration,
            name=name,
            permissions=permissions,
            tags=tags,
            version_description=version_description,
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
        '''The Amazon Resource Name (ARN) of the theme.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCreatedTime")
    def attr_created_time(self) -> builtins.str:
        '''The time the theme was created.

        :cloudformationAttribute: CreatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLastUpdatedTime")
    def attr_last_updated_time(self) -> builtins.str:
        '''The time the theme was last updated.

        :cloudformationAttribute: LastUpdatedTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLastUpdatedTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrType")
    def attr_type(self) -> builtins.str:
        '''Theme type.

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
        '''A map of the key-value pairs for the resource tag or tags that you want to add to the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="awsAccountId")
    def aws_account_id(self) -> builtins.str:
        '''The ID of the AWS account where you want to store the new theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-awsaccountid
        '''
        return typing.cast(builtins.str, jsii.get(self, "awsAccountId"))

    @aws_account_id.setter
    def aws_account_id(self, value: builtins.str) -> None:
        jsii.set(self, "awsAccountId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="themeId")
    def theme_id(self) -> builtins.str:
        '''An ID for the theme that you want to create.

        The theme ID is unique per AWS Region in each AWS account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-themeid
        '''
        return typing.cast(builtins.str, jsii.get(self, "themeId"))

    @theme_id.setter
    def theme_id(self, value: builtins.str) -> None:
        jsii.set(self, "themeId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="baseThemeId")
    def base_theme_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the theme that a custom theme will inherit from.

        All themes inherit from one of the starting themes defined by Amazon QuickSight. For a list of the starting themes, use ``ListThemes`` or choose *Themes* from within an analysis.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-basethemeid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "baseThemeId"))

    @base_theme_id.setter
    def base_theme_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "baseThemeId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="configuration")
    def configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnTheme.ThemeConfigurationProperty", _IResolvable_da3f097b]]:
        '''The theme configuration, which contains the theme display properties.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-configuration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnTheme.ThemeConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "configuration"))

    @configuration.setter
    def configuration(
        self,
        value: typing.Optional[typing.Union["CfnTheme.ThemeConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "configuration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''A display name for the theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="permissions")
    def permissions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTheme.ResourcePermissionProperty", _IResolvable_da3f097b]]]]:
        '''A valid grouping of resource permissions to apply to the new theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-permissions
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTheme.ResourcePermissionProperty", _IResolvable_da3f097b]]]], jsii.get(self, "permissions"))

    @permissions.setter
    def permissions(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTheme.ResourcePermissionProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "permissions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="versionDescription")
    def version_description(self) -> typing.Optional[builtins.str]:
        '''A description of the first version of the theme that you're creating.

        Every time ``UpdateTheme`` is called, a new version is created. Each version of the theme has a description of the version in the ``VersionDescription`` field.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-versiondescription
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "versionDescription"))

    @version_description.setter
    def version_description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "versionDescription", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTheme.BorderStyleProperty",
        jsii_struct_bases=[],
        name_mapping={"show": "show"},
    )
    class BorderStyleProperty:
        def __init__(
            self,
            *,
            show: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The display options for tile borders for visuals.

            :param show: The option to enable display of borders for visuals.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-borderstyle.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                border_style_property = quicksight.CfnTheme.BorderStyleProperty(
                    show=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if show is not None:
                self._values["show"] = show

        @builtins.property
        def show(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The option to enable display of borders for visuals.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-borderstyle.html#cfn-quicksight-theme-borderstyle-show
            '''
            result = self._values.get("show")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BorderStyleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTheme.DataColorPaletteProperty",
        jsii_struct_bases=[],
        name_mapping={
            "colors": "colors",
            "empty_fill_color": "emptyFillColor",
            "min_max_gradient": "minMaxGradient",
        },
    )
    class DataColorPaletteProperty:
        def __init__(
            self,
            *,
            colors: typing.Optional[typing.Sequence[builtins.str]] = None,
            empty_fill_color: typing.Optional[builtins.str] = None,
            min_max_gradient: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''The theme colors that are used for data colors in charts.

            The colors description is a hexadecimal color code that consists of six alphanumerical characters, prefixed with ``#`` , for example #37BFF5.

            :param colors: The hexadecimal codes for the colors.
            :param empty_fill_color: The hexadecimal code of a color that applies to charts where a lack of data is highlighted.
            :param min_max_gradient: The minimum and maximum hexadecimal codes that describe a color gradient.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-datacolorpalette.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                data_color_palette_property = quicksight.CfnTheme.DataColorPaletteProperty(
                    colors=["colors"],
                    empty_fill_color="emptyFillColor",
                    min_max_gradient=["minMaxGradient"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if colors is not None:
                self._values["colors"] = colors
            if empty_fill_color is not None:
                self._values["empty_fill_color"] = empty_fill_color
            if min_max_gradient is not None:
                self._values["min_max_gradient"] = min_max_gradient

        @builtins.property
        def colors(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The hexadecimal codes for the colors.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-datacolorpalette.html#cfn-quicksight-theme-datacolorpalette-colors
            '''
            result = self._values.get("colors")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def empty_fill_color(self) -> typing.Optional[builtins.str]:
            '''The hexadecimal code of a color that applies to charts where a lack of data is highlighted.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-datacolorpalette.html#cfn-quicksight-theme-datacolorpalette-emptyfillcolor
            '''
            result = self._values.get("empty_fill_color")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def min_max_gradient(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The minimum and maximum hexadecimal codes that describe a color gradient.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-datacolorpalette.html#cfn-quicksight-theme-datacolorpalette-minmaxgradient
            '''
            result = self._values.get("min_max_gradient")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataColorPaletteProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTheme.FontProperty",
        jsii_struct_bases=[],
        name_mapping={"font_family": "fontFamily"},
    )
    class FontProperty:
        def __init__(
            self,
            *,
            font_family: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param font_family: ``CfnTheme.FontProperty.FontFamily``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-font.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                font_property = quicksight.CfnTheme.FontProperty(
                    font_family="fontFamily"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if font_family is not None:
                self._values["font_family"] = font_family

        @builtins.property
        def font_family(self) -> typing.Optional[builtins.str]:
            '''``CfnTheme.FontProperty.FontFamily``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-font.html#cfn-quicksight-theme-font-fontfamily
            '''
            result = self._values.get("font_family")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FontProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTheme.GutterStyleProperty",
        jsii_struct_bases=[],
        name_mapping={"show": "show"},
    )
    class GutterStyleProperty:
        def __init__(
            self,
            *,
            show: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The display options for gutter spacing between tiles on a sheet.

            :param show: This Boolean value controls whether to display a gutter space between sheet tiles.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-gutterstyle.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                gutter_style_property = quicksight.CfnTheme.GutterStyleProperty(
                    show=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if show is not None:
                self._values["show"] = show

        @builtins.property
        def show(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''This Boolean value controls whether to display a gutter space between sheet tiles.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-gutterstyle.html#cfn-quicksight-theme-gutterstyle-show
            '''
            result = self._values.get("show")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GutterStyleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTheme.MarginStyleProperty",
        jsii_struct_bases=[],
        name_mapping={"show": "show"},
    )
    class MarginStyleProperty:
        def __init__(
            self,
            *,
            show: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The display options for margins around the outside edge of sheets.

            :param show: This Boolean value controls whether to display sheet margins.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-marginstyle.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                margin_style_property = quicksight.CfnTheme.MarginStyleProperty(
                    show=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if show is not None:
                self._values["show"] = show

        @builtins.property
        def show(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''This Boolean value controls whether to display sheet margins.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-marginstyle.html#cfn-quicksight-theme-marginstyle-show
            '''
            result = self._values.get("show")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MarginStyleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTheme.ResourcePermissionProperty",
        jsii_struct_bases=[],
        name_mapping={"actions": "actions", "principal": "principal"},
    )
    class ResourcePermissionProperty:
        def __init__(
            self,
            *,
            actions: typing.Sequence[builtins.str],
            principal: builtins.str,
        ) -> None:
            '''Permission for the resource.

            :param actions: The IAM action to grant or revoke permissions on.
            :param principal: The Amazon Resource Name (ARN) of the principal. This can be one of the following:. - The ARN of an Amazon QuickSight user or group associated with a data source or dataset. (This is common.) - The ARN of an Amazon QuickSight user, group, or namespace associated with an analysis, dashboard, template, or theme. (This is common.) - The ARN of an AWS account root: This is an IAM ARN rather than a Amazon QuickSight ARN. Use this option only to share resources (templates) across AWS accounts . (This is less common.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-resourcepermission.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                resource_permission_property = quicksight.CfnTheme.ResourcePermissionProperty(
                    actions=["actions"],
                    principal="principal"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "actions": actions,
                "principal": principal,
            }

        @builtins.property
        def actions(self) -> typing.List[builtins.str]:
            '''The IAM action to grant or revoke permissions on.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-resourcepermission.html#cfn-quicksight-theme-resourcepermission-actions
            '''
            result = self._values.get("actions")
            assert result is not None, "Required property 'actions' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def principal(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the principal. This can be one of the following:.

            - The ARN of an Amazon QuickSight user or group associated with a data source or dataset. (This is common.)
            - The ARN of an Amazon QuickSight user, group, or namespace associated with an analysis, dashboard, template, or theme. (This is common.)
            - The ARN of an AWS account root: This is an IAM ARN rather than a Amazon QuickSight ARN. Use this option only to share resources (templates) across AWS accounts . (This is less common.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-resourcepermission.html#cfn-quicksight-theme-resourcepermission-principal
            '''
            result = self._values.get("principal")
            assert result is not None, "Required property 'principal' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourcePermissionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTheme.SheetStyleProperty",
        jsii_struct_bases=[],
        name_mapping={"tile": "tile", "tile_layout": "tileLayout"},
    )
    class SheetStyleProperty:
        def __init__(
            self,
            *,
            tile: typing.Optional[typing.Union["CfnTheme.TileStyleProperty", _IResolvable_da3f097b]] = None,
            tile_layout: typing.Optional[typing.Union["CfnTheme.TileLayoutStyleProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The theme display options for sheets.

            :param tile: The display options for tiles.
            :param tile_layout: The layout options for tiles.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-sheetstyle.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                sheet_style_property = quicksight.CfnTheme.SheetStyleProperty(
                    tile=quicksight.CfnTheme.TileStyleProperty(
                        border=quicksight.CfnTheme.BorderStyleProperty(
                            show=False
                        )
                    ),
                    tile_layout=quicksight.CfnTheme.TileLayoutStyleProperty(
                        gutter=quicksight.CfnTheme.GutterStyleProperty(
                            show=False
                        ),
                        margin=quicksight.CfnTheme.MarginStyleProperty(
                            show=False
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if tile is not None:
                self._values["tile"] = tile
            if tile_layout is not None:
                self._values["tile_layout"] = tile_layout

        @builtins.property
        def tile(
            self,
        ) -> typing.Optional[typing.Union["CfnTheme.TileStyleProperty", _IResolvable_da3f097b]]:
            '''The display options for tiles.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-sheetstyle.html#cfn-quicksight-theme-sheetstyle-tile
            '''
            result = self._values.get("tile")
            return typing.cast(typing.Optional[typing.Union["CfnTheme.TileStyleProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def tile_layout(
            self,
        ) -> typing.Optional[typing.Union["CfnTheme.TileLayoutStyleProperty", _IResolvable_da3f097b]]:
            '''The layout options for tiles.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-sheetstyle.html#cfn-quicksight-theme-sheetstyle-tilelayout
            '''
            result = self._values.get("tile_layout")
            return typing.cast(typing.Optional[typing.Union["CfnTheme.TileLayoutStyleProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SheetStyleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTheme.ThemeConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "data_color_palette": "dataColorPalette",
            "sheet": "sheet",
            "typography": "typography",
            "ui_color_palette": "uiColorPalette",
        },
    )
    class ThemeConfigurationProperty:
        def __init__(
            self,
            *,
            data_color_palette: typing.Optional[typing.Union["CfnTheme.DataColorPaletteProperty", _IResolvable_da3f097b]] = None,
            sheet: typing.Optional[typing.Union["CfnTheme.SheetStyleProperty", _IResolvable_da3f097b]] = None,
            typography: typing.Optional[typing.Union["CfnTheme.TypographyProperty", _IResolvable_da3f097b]] = None,
            ui_color_palette: typing.Optional[typing.Union["CfnTheme.UIColorPaletteProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The theme configuration.

            This configuration contains all of the display properties for a theme.

            :param data_color_palette: Color properties that apply to chart data colors.
            :param sheet: Display options related to sheets.
            :param typography: ``CfnTheme.ThemeConfigurationProperty.Typography``.
            :param ui_color_palette: Color properties that apply to the UI and to charts, excluding the colors that apply to data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-themeconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                theme_configuration_property = quicksight.CfnTheme.ThemeConfigurationProperty(
                    data_color_palette=quicksight.CfnTheme.DataColorPaletteProperty(
                        colors=["colors"],
                        empty_fill_color="emptyFillColor",
                        min_max_gradient=["minMaxGradient"]
                    ),
                    sheet=quicksight.CfnTheme.SheetStyleProperty(
                        tile=quicksight.CfnTheme.TileStyleProperty(
                            border=quicksight.CfnTheme.BorderStyleProperty(
                                show=False
                            )
                        ),
                        tile_layout=quicksight.CfnTheme.TileLayoutStyleProperty(
                            gutter=quicksight.CfnTheme.GutterStyleProperty(
                                show=False
                            ),
                            margin=quicksight.CfnTheme.MarginStyleProperty(
                                show=False
                            )
                        )
                    ),
                    typography=quicksight.CfnTheme.TypographyProperty(
                        font_families=[quicksight.CfnTheme.FontProperty(
                            font_family="fontFamily"
                        )]
                    ),
                    ui_color_palette=quicksight.CfnTheme.UIColorPaletteProperty(
                        accent="accent",
                        accent_foreground="accentForeground",
                        danger="danger",
                        danger_foreground="dangerForeground",
                        dimension="dimension",
                        dimension_foreground="dimensionForeground",
                        measure="measure",
                        measure_foreground="measureForeground",
                        primary_background="primaryBackground",
                        primary_foreground="primaryForeground",
                        secondary_background="secondaryBackground",
                        secondary_foreground="secondaryForeground",
                        success="success",
                        success_foreground="successForeground",
                        warning="warning",
                        warning_foreground="warningForeground"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if data_color_palette is not None:
                self._values["data_color_palette"] = data_color_palette
            if sheet is not None:
                self._values["sheet"] = sheet
            if typography is not None:
                self._values["typography"] = typography
            if ui_color_palette is not None:
                self._values["ui_color_palette"] = ui_color_palette

        @builtins.property
        def data_color_palette(
            self,
        ) -> typing.Optional[typing.Union["CfnTheme.DataColorPaletteProperty", _IResolvable_da3f097b]]:
            '''Color properties that apply to chart data colors.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-themeconfiguration.html#cfn-quicksight-theme-themeconfiguration-datacolorpalette
            '''
            result = self._values.get("data_color_palette")
            return typing.cast(typing.Optional[typing.Union["CfnTheme.DataColorPaletteProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sheet(
            self,
        ) -> typing.Optional[typing.Union["CfnTheme.SheetStyleProperty", _IResolvable_da3f097b]]:
            '''Display options related to sheets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-themeconfiguration.html#cfn-quicksight-theme-themeconfiguration-sheet
            '''
            result = self._values.get("sheet")
            return typing.cast(typing.Optional[typing.Union["CfnTheme.SheetStyleProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def typography(
            self,
        ) -> typing.Optional[typing.Union["CfnTheme.TypographyProperty", _IResolvable_da3f097b]]:
            '''``CfnTheme.ThemeConfigurationProperty.Typography``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-themeconfiguration.html#cfn-quicksight-theme-themeconfiguration-typography
            '''
            result = self._values.get("typography")
            return typing.cast(typing.Optional[typing.Union["CfnTheme.TypographyProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def ui_color_palette(
            self,
        ) -> typing.Optional[typing.Union["CfnTheme.UIColorPaletteProperty", _IResolvable_da3f097b]]:
            '''Color properties that apply to the UI and to charts, excluding the colors that apply to data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-themeconfiguration.html#cfn-quicksight-theme-themeconfiguration-uicolorpalette
            '''
            result = self._values.get("ui_color_palette")
            return typing.cast(typing.Optional[typing.Union["CfnTheme.UIColorPaletteProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ThemeConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTheme.TileLayoutStyleProperty",
        jsii_struct_bases=[],
        name_mapping={"gutter": "gutter", "margin": "margin"},
    )
    class TileLayoutStyleProperty:
        def __init__(
            self,
            *,
            gutter: typing.Optional[typing.Union["CfnTheme.GutterStyleProperty", _IResolvable_da3f097b]] = None,
            margin: typing.Optional[typing.Union["CfnTheme.MarginStyleProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The display options for the layout of tiles on a sheet.

            :param gutter: The gutter settings that apply between tiles.
            :param margin: The margin settings that apply around the outside edge of sheets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-tilelayoutstyle.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                tile_layout_style_property = quicksight.CfnTheme.TileLayoutStyleProperty(
                    gutter=quicksight.CfnTheme.GutterStyleProperty(
                        show=False
                    ),
                    margin=quicksight.CfnTheme.MarginStyleProperty(
                        show=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if gutter is not None:
                self._values["gutter"] = gutter
            if margin is not None:
                self._values["margin"] = margin

        @builtins.property
        def gutter(
            self,
        ) -> typing.Optional[typing.Union["CfnTheme.GutterStyleProperty", _IResolvable_da3f097b]]:
            '''The gutter settings that apply between tiles.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-tilelayoutstyle.html#cfn-quicksight-theme-tilelayoutstyle-gutter
            '''
            result = self._values.get("gutter")
            return typing.cast(typing.Optional[typing.Union["CfnTheme.GutterStyleProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def margin(
            self,
        ) -> typing.Optional[typing.Union["CfnTheme.MarginStyleProperty", _IResolvable_da3f097b]]:
            '''The margin settings that apply around the outside edge of sheets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-tilelayoutstyle.html#cfn-quicksight-theme-tilelayoutstyle-margin
            '''
            result = self._values.get("margin")
            return typing.cast(typing.Optional[typing.Union["CfnTheme.MarginStyleProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TileLayoutStyleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTheme.TileStyleProperty",
        jsii_struct_bases=[],
        name_mapping={"border": "border"},
    )
    class TileStyleProperty:
        def __init__(
            self,
            *,
            border: typing.Optional[typing.Union["CfnTheme.BorderStyleProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Display options related to tiles on a sheet.

            :param border: The border around a tile.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-tilestyle.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                tile_style_property = quicksight.CfnTheme.TileStyleProperty(
                    border=quicksight.CfnTheme.BorderStyleProperty(
                        show=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if border is not None:
                self._values["border"] = border

        @builtins.property
        def border(
            self,
        ) -> typing.Optional[typing.Union["CfnTheme.BorderStyleProperty", _IResolvable_da3f097b]]:
            '''The border around a tile.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-tilestyle.html#cfn-quicksight-theme-tilestyle-border
            '''
            result = self._values.get("border")
            return typing.cast(typing.Optional[typing.Union["CfnTheme.BorderStyleProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TileStyleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTheme.TypographyProperty",
        jsii_struct_bases=[],
        name_mapping={"font_families": "fontFamilies"},
    )
    class TypographyProperty:
        def __init__(
            self,
            *,
            font_families: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTheme.FontProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''
            :param font_families: ``CfnTheme.TypographyProperty.FontFamilies``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-typography.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                typography_property = quicksight.CfnTheme.TypographyProperty(
                    font_families=[quicksight.CfnTheme.FontProperty(
                        font_family="fontFamily"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if font_families is not None:
                self._values["font_families"] = font_families

        @builtins.property
        def font_families(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTheme.FontProperty", _IResolvable_da3f097b]]]]:
            '''``CfnTheme.TypographyProperty.FontFamilies``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-typography.html#cfn-quicksight-theme-typography-fontfamilies
            '''
            result = self._values.get("font_families")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTheme.FontProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TypographyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_quicksight.CfnTheme.UIColorPaletteProperty",
        jsii_struct_bases=[],
        name_mapping={
            "accent": "accent",
            "accent_foreground": "accentForeground",
            "danger": "danger",
            "danger_foreground": "dangerForeground",
            "dimension": "dimension",
            "dimension_foreground": "dimensionForeground",
            "measure": "measure",
            "measure_foreground": "measureForeground",
            "primary_background": "primaryBackground",
            "primary_foreground": "primaryForeground",
            "secondary_background": "secondaryBackground",
            "secondary_foreground": "secondaryForeground",
            "success": "success",
            "success_foreground": "successForeground",
            "warning": "warning",
            "warning_foreground": "warningForeground",
        },
    )
    class UIColorPaletteProperty:
        def __init__(
            self,
            *,
            accent: typing.Optional[builtins.str] = None,
            accent_foreground: typing.Optional[builtins.str] = None,
            danger: typing.Optional[builtins.str] = None,
            danger_foreground: typing.Optional[builtins.str] = None,
            dimension: typing.Optional[builtins.str] = None,
            dimension_foreground: typing.Optional[builtins.str] = None,
            measure: typing.Optional[builtins.str] = None,
            measure_foreground: typing.Optional[builtins.str] = None,
            primary_background: typing.Optional[builtins.str] = None,
            primary_foreground: typing.Optional[builtins.str] = None,
            secondary_background: typing.Optional[builtins.str] = None,
            secondary_foreground: typing.Optional[builtins.str] = None,
            success: typing.Optional[builtins.str] = None,
            success_foreground: typing.Optional[builtins.str] = None,
            warning: typing.Optional[builtins.str] = None,
            warning_foreground: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The theme colors that apply to UI and to charts, excluding data colors.

            The colors description is a hexadecimal color code that consists of six alphanumerical characters, prefixed with ``#`` , for example #37BFF5. For more information, see `Using Themes in Amazon QuickSight <https://docs.aws.amazon.com/quicksight/latest/user/themes-in-quicksight.html>`_ in the *Amazon QuickSight User Guide.*

            :param accent: This color is that applies to selected states and buttons.
            :param accent_foreground: The foreground color that applies to any text or other elements that appear over the accent color.
            :param danger: The color that applies to error messages.
            :param danger_foreground: The foreground color that applies to any text or other elements that appear over the error color.
            :param dimension: The color that applies to the names of fields that are identified as dimensions.
            :param dimension_foreground: The foreground color that applies to any text or other elements that appear over the dimension color.
            :param measure: The color that applies to the names of fields that are identified as measures.
            :param measure_foreground: The foreground color that applies to any text or other elements that appear over the measure color.
            :param primary_background: The background color that applies to visuals and other high emphasis UI.
            :param primary_foreground: The color of text and other foreground elements that appear over the primary background regions, such as grid lines, borders, table banding, icons, and so on.
            :param secondary_background: The background color that applies to the sheet background and sheet controls.
            :param secondary_foreground: The foreground color that applies to any sheet title, sheet control text, or UI that appears over the secondary background.
            :param success: The color that applies to success messages, for example the check mark for a successful download.
            :param success_foreground: The foreground color that applies to any text or other elements that appear over the success color.
            :param warning: This color that applies to warning and informational messages.
            :param warning_foreground: The foreground color that applies to any text or other elements that appear over the warning color.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_quicksight as quicksight
                
                u_iColor_palette_property = quicksight.CfnTheme.UIColorPaletteProperty(
                    accent="accent",
                    accent_foreground="accentForeground",
                    danger="danger",
                    danger_foreground="dangerForeground",
                    dimension="dimension",
                    dimension_foreground="dimensionForeground",
                    measure="measure",
                    measure_foreground="measureForeground",
                    primary_background="primaryBackground",
                    primary_foreground="primaryForeground",
                    secondary_background="secondaryBackground",
                    secondary_foreground="secondaryForeground",
                    success="success",
                    success_foreground="successForeground",
                    warning="warning",
                    warning_foreground="warningForeground"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if accent is not None:
                self._values["accent"] = accent
            if accent_foreground is not None:
                self._values["accent_foreground"] = accent_foreground
            if danger is not None:
                self._values["danger"] = danger
            if danger_foreground is not None:
                self._values["danger_foreground"] = danger_foreground
            if dimension is not None:
                self._values["dimension"] = dimension
            if dimension_foreground is not None:
                self._values["dimension_foreground"] = dimension_foreground
            if measure is not None:
                self._values["measure"] = measure
            if measure_foreground is not None:
                self._values["measure_foreground"] = measure_foreground
            if primary_background is not None:
                self._values["primary_background"] = primary_background
            if primary_foreground is not None:
                self._values["primary_foreground"] = primary_foreground
            if secondary_background is not None:
                self._values["secondary_background"] = secondary_background
            if secondary_foreground is not None:
                self._values["secondary_foreground"] = secondary_foreground
            if success is not None:
                self._values["success"] = success
            if success_foreground is not None:
                self._values["success_foreground"] = success_foreground
            if warning is not None:
                self._values["warning"] = warning
            if warning_foreground is not None:
                self._values["warning_foreground"] = warning_foreground

        @builtins.property
        def accent(self) -> typing.Optional[builtins.str]:
            '''This color is that applies to selected states and buttons.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-accent
            '''
            result = self._values.get("accent")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def accent_foreground(self) -> typing.Optional[builtins.str]:
            '''The foreground color that applies to any text or other elements that appear over the accent color.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-accentforeground
            '''
            result = self._values.get("accent_foreground")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def danger(self) -> typing.Optional[builtins.str]:
            '''The color that applies to error messages.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-danger
            '''
            result = self._values.get("danger")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def danger_foreground(self) -> typing.Optional[builtins.str]:
            '''The foreground color that applies to any text or other elements that appear over the error color.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-dangerforeground
            '''
            result = self._values.get("danger_foreground")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def dimension(self) -> typing.Optional[builtins.str]:
            '''The color that applies to the names of fields that are identified as dimensions.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-dimension
            '''
            result = self._values.get("dimension")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def dimension_foreground(self) -> typing.Optional[builtins.str]:
            '''The foreground color that applies to any text or other elements that appear over the dimension color.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-dimensionforeground
            '''
            result = self._values.get("dimension_foreground")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def measure(self) -> typing.Optional[builtins.str]:
            '''The color that applies to the names of fields that are identified as measures.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-measure
            '''
            result = self._values.get("measure")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def measure_foreground(self) -> typing.Optional[builtins.str]:
            '''The foreground color that applies to any text or other elements that appear over the measure color.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-measureforeground
            '''
            result = self._values.get("measure_foreground")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def primary_background(self) -> typing.Optional[builtins.str]:
            '''The background color that applies to visuals and other high emphasis UI.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-primarybackground
            '''
            result = self._values.get("primary_background")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def primary_foreground(self) -> typing.Optional[builtins.str]:
            '''The color of text and other foreground elements that appear over the primary background regions, such as grid lines, borders, table banding, icons, and so on.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-primaryforeground
            '''
            result = self._values.get("primary_foreground")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secondary_background(self) -> typing.Optional[builtins.str]:
            '''The background color that applies to the sheet background and sheet controls.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-secondarybackground
            '''
            result = self._values.get("secondary_background")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secondary_foreground(self) -> typing.Optional[builtins.str]:
            '''The foreground color that applies to any sheet title, sheet control text, or UI that appears over the secondary background.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-secondaryforeground
            '''
            result = self._values.get("secondary_foreground")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def success(self) -> typing.Optional[builtins.str]:
            '''The color that applies to success messages, for example the check mark for a successful download.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-success
            '''
            result = self._values.get("success")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def success_foreground(self) -> typing.Optional[builtins.str]:
            '''The foreground color that applies to any text or other elements that appear over the success color.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-successforeground
            '''
            result = self._values.get("success_foreground")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def warning(self) -> typing.Optional[builtins.str]:
            '''This color that applies to warning and informational messages.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-warning
            '''
            result = self._values.get("warning")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def warning_foreground(self) -> typing.Optional[builtins.str]:
            '''The foreground color that applies to any text or other elements that appear over the warning color.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-quicksight-theme-uicolorpalette.html#cfn-quicksight-theme-uicolorpalette-warningforeground
            '''
            result = self._values.get("warning_foreground")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "UIColorPaletteProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_quicksight.CfnThemeProps",
    jsii_struct_bases=[],
    name_mapping={
        "aws_account_id": "awsAccountId",
        "theme_id": "themeId",
        "base_theme_id": "baseThemeId",
        "configuration": "configuration",
        "name": "name",
        "permissions": "permissions",
        "tags": "tags",
        "version_description": "versionDescription",
    },
)
class CfnThemeProps:
    def __init__(
        self,
        *,
        aws_account_id: builtins.str,
        theme_id: builtins.str,
        base_theme_id: typing.Optional[builtins.str] = None,
        configuration: typing.Optional[typing.Union[CfnTheme.ThemeConfigurationProperty, _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        permissions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnTheme.ResourcePermissionProperty, _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        version_description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnTheme``.

        :param aws_account_id: The ID of the AWS account where you want to store the new theme.
        :param theme_id: An ID for the theme that you want to create. The theme ID is unique per AWS Region in each AWS account.
        :param base_theme_id: The ID of the theme that a custom theme will inherit from. All themes inherit from one of the starting themes defined by Amazon QuickSight. For a list of the starting themes, use ``ListThemes`` or choose *Themes* from within an analysis.
        :param configuration: The theme configuration, which contains the theme display properties.
        :param name: A display name for the theme.
        :param permissions: A valid grouping of resource permissions to apply to the new theme.
        :param tags: A map of the key-value pairs for the resource tag or tags that you want to add to the resource.
        :param version_description: A description of the first version of the theme that you're creating. Every time ``UpdateTheme`` is called, a new version is created. Each version of the theme has a description of the version in the ``VersionDescription`` field.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_quicksight as quicksight
            
            cfn_theme_props = quicksight.CfnThemeProps(
                aws_account_id="awsAccountId",
                theme_id="themeId",
            
                # the properties below are optional
                base_theme_id="baseThemeId",
                configuration=quicksight.CfnTheme.ThemeConfigurationProperty(
                    data_color_palette=quicksight.CfnTheme.DataColorPaletteProperty(
                        colors=["colors"],
                        empty_fill_color="emptyFillColor",
                        min_max_gradient=["minMaxGradient"]
                    ),
                    sheet=quicksight.CfnTheme.SheetStyleProperty(
                        tile=quicksight.CfnTheme.TileStyleProperty(
                            border=quicksight.CfnTheme.BorderStyleProperty(
                                show=False
                            )
                        ),
                        tile_layout=quicksight.CfnTheme.TileLayoutStyleProperty(
                            gutter=quicksight.CfnTheme.GutterStyleProperty(
                                show=False
                            ),
                            margin=quicksight.CfnTheme.MarginStyleProperty(
                                show=False
                            )
                        )
                    ),
                    typography=quicksight.CfnTheme.TypographyProperty(
                        font_families=[quicksight.CfnTheme.FontProperty(
                            font_family="fontFamily"
                        )]
                    ),
                    ui_color_palette=quicksight.CfnTheme.UIColorPaletteProperty(
                        accent="accent",
                        accent_foreground="accentForeground",
                        danger="danger",
                        danger_foreground="dangerForeground",
                        dimension="dimension",
                        dimension_foreground="dimensionForeground",
                        measure="measure",
                        measure_foreground="measureForeground",
                        primary_background="primaryBackground",
                        primary_foreground="primaryForeground",
                        secondary_background="secondaryBackground",
                        secondary_foreground="secondaryForeground",
                        success="success",
                        success_foreground="successForeground",
                        warning="warning",
                        warning_foreground="warningForeground"
                    )
                ),
                name="name",
                permissions=[quicksight.CfnTheme.ResourcePermissionProperty(
                    actions=["actions"],
                    principal="principal"
                )],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                version_description="versionDescription"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "aws_account_id": aws_account_id,
            "theme_id": theme_id,
        }
        if base_theme_id is not None:
            self._values["base_theme_id"] = base_theme_id
        if configuration is not None:
            self._values["configuration"] = configuration
        if name is not None:
            self._values["name"] = name
        if permissions is not None:
            self._values["permissions"] = permissions
        if tags is not None:
            self._values["tags"] = tags
        if version_description is not None:
            self._values["version_description"] = version_description

    @builtins.property
    def aws_account_id(self) -> builtins.str:
        '''The ID of the AWS account where you want to store the new theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-awsaccountid
        '''
        result = self._values.get("aws_account_id")
        assert result is not None, "Required property 'aws_account_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def theme_id(self) -> builtins.str:
        '''An ID for the theme that you want to create.

        The theme ID is unique per AWS Region in each AWS account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-themeid
        '''
        result = self._values.get("theme_id")
        assert result is not None, "Required property 'theme_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def base_theme_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the theme that a custom theme will inherit from.

        All themes inherit from one of the starting themes defined by Amazon QuickSight. For a list of the starting themes, use ``ListThemes`` or choose *Themes* from within an analysis.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-basethemeid
        '''
        result = self._values.get("base_theme_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnTheme.ThemeConfigurationProperty, _IResolvable_da3f097b]]:
        '''The theme configuration, which contains the theme display properties.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-configuration
        '''
        result = self._values.get("configuration")
        return typing.cast(typing.Optional[typing.Union[CfnTheme.ThemeConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''A display name for the theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def permissions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTheme.ResourcePermissionProperty, _IResolvable_da3f097b]]]]:
        '''A valid grouping of resource permissions to apply to the new theme.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-permissions
        '''
        result = self._values.get("permissions")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTheme.ResourcePermissionProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A map of the key-value pairs for the resource tag or tags that you want to add to the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def version_description(self) -> typing.Optional[builtins.str]:
        '''A description of the first version of the theme that you're creating.

        Every time ``UpdateTheme`` is called, a new version is created. Each version of the theme has a description of the version in the ``VersionDescription`` field.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-quicksight-theme.html#cfn-quicksight-theme-versiondescription
        '''
        result = self._values.get("version_description")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnThemeProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnAnalysis",
    "CfnAnalysisProps",
    "CfnDashboard",
    "CfnDashboardProps",
    "CfnDataSet",
    "CfnDataSetProps",
    "CfnDataSource",
    "CfnDataSourceProps",
    "CfnTemplate",
    "CfnTemplateProps",
    "CfnTheme",
    "CfnThemeProps",
]

publication.publish()
